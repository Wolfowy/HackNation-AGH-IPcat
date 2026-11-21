using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Npgsql;
using WebScan.Contracts;
using WebScan.Server.Kernel.Messaging;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Kernel.Telemetry;
using WebScan.Server.Modules.Scanning.Events;
using WebScan.Server.Modules.Scanning.Persistence;
using WebScan.Server.Modules.Scanning.Planning;
using Wolverine.EntityFrameworkCore;

namespace WebScan.Server.Modules.Scanning.Jobs;

public enum JobCallStatus { Ok, NotFound, Conflict, Invalid }

public sealed record JobCallResult<T>(JobCallStatus Status, T? Value = default, string? Error = null)
{
    public static JobCallResult<T> Ok(T value) => new(JobCallStatus.Ok, value);
    public static JobCallResult<T> NotFound(string error) => new(JobCallStatus.NotFound, default, error);
    public static JobCallResult<T> Conflict(string error) => new(JobCallStatus.Conflict, default, error);
    public static JobCallResult<T> Invalid(string error) => new(JobCallStatus.Invalid, default, error);
}

/// <summary>
/// The persistent job queue: claim (FOR UPDATE SKIP LOCKED), leases, idempotent results, completion, failures and retries.
/// Every terminal transition publishes <see cref="ScanJobFinished"/> through the EF Core outbox in the same transaction.
/// One state transition per DI scope: a failed outbox save must not leak queued envelopes into a later save.
/// </summary>
public sealed class JobQueue(
    IDbContextOutbox<ScanningDbContext> outbox, IAgentDirectory agents, ScanLimitsStore limitsStore,
    IOptions<PlannerOptions> plannerOptions, IScanEventPublisher events, TimeProvider time, ILogger<JobQueue> logger)
{
    private const long ClaimLockKey = 0x5745425343414E; // "WEBSCAN": serializes claims so caps are accounted exactly
    private const double PerformanceAlpha = 0.3;
    private ScanningDbContext Db => outbox.DbContext;

    public async Task<JobClaimResponse> ClaimAsync(string agentId, JobClaimRequest request, CancellationToken ct = default)
    {
        var empty = new JobClaimResponse { Assignments = [] };
        var agent = await agents.GetAsync(agentId, ct);
        if (agent is null || agent.Status != AgentStatus.Active || request.MaxJobs <= 0) return empty;
        var capabilities = agent.ApprovedTools.SelectMany(t => t.Capabilities).Select(c => c.ToLowerInvariant()).Distinct().ToArray();
        var zones = agent.AuthorizedZones.Select(z => z.ToLowerInvariant()).ToArray();
        if (capabilities.Length == 0 || zones.Length == 0) return empty;

        var options = plannerOptions.Value;
        var limits = await limitsStore.GetAsync(ct);
        var networks = agent.AuthorizedNetworkIds.ToArray();
        var maxJobs = Math.Min(request.MaxJobs, agent.Limits.MaxConcurrentJobs);
        var now = time.GetUtcNow();
        var assignments = new List<JobAssignment>();

        await using (var tx = await Db.Database.BeginTransactionAsync(ct))
        {
            await Db.Database.ExecuteSqlAsync($"SELECT pg_advisory_xact_lock({ClaimLockKey})", ct);
            var running = await Db.Jobs.AsNoTracking().Where(j => j.Status == JobStatus.Leased)
                .Select(j => new RunningJob(j.AgentId!, j.InterfaceName ?? "", j.Zone, j.SubnetKey, j.ScanRunId, j.StepId, j.AssignedRatePerSecond ?? 0))
                .ToListAsync(ct);
            // shortcut: only the top candidates (by priority/age) are scored; if they are all unreachable for this agent it
            // gets nothing this poll even if a later job fits. Upgrade to reachability pre-filtering in SQL if that shows up.
            var limit = Math.Min(200, maxJobs * 20);
            var candidates = await Db.Jobs.FromSql($"""
                SELECT j.*, j.xmin FROM scanning.scan_jobs j
                WHERE j.status = 'Queued' AND NOT j.cancel_requested
                  AND (j.next_attempt_at IS NULL OR j.next_attempt_at <= {now})
                  AND (j.not_after IS NULL OR j.not_after > {now})
                  AND lower(j.zone) = ANY({zones}) AND j.capability = ANY({capabilities})
                  AND (cardinality({networks}) = 0 OR j.network_id = ANY({networks}))
                ORDER BY j.priority DESC, j.created_at
                LIMIT {limit}
                FOR UPDATE SKIP LOCKED
                """).ToListAsync(ct);
            var performance = await Db.Performance.AsNoTracking()
                .Select(p => new PerformanceSample(p.AgentId, p.InterfaceName, p.ToolId, p.AvgTargetsPerSecond)).ToListAsync(ct);

            var decisions = ClaimSelector.Select(agent, AgentReach.Build(agent, options.AllowDefaultRoute),
                candidates.Select(ToCandidate).ToList(), running, limits, performance, options, request.Interfaces, maxJobs, now);

            var byId = candidates.ToDictionary(c => c.Id);
            foreach (var decision in decisions)
            {
                var job = byId[decision.JobId];
                job.Status = JobStatus.Leased;
                job.AgentId = agentId;
                job.InterfaceName = decision.InterfaceName;
                job.ToolId = decision.ToolId;
                job.AssignedRatePerSecond = decision.RatePerSecond;
                job.LeaseId = Guid.NewGuid();
                job.LeaseExpiresAt = now.AddSeconds(limits.LeaseDurationSeconds);
                job.Attempt++;
                job.StartedAt = now;
                job.NextAttemptAt = null;
                job.QueueReason = null;
                job.ProgressPercent = null;
                var original = Payload(job);
                var payload = original with
                {
                    InterfaceName = decision.InterfaceName,
                    Tool = original.Tool with { ToolId = decision.ToolId },
                    Limits = original.Limits with { RatePerSecond = decision.RatePerSecond },
                };
                job.PayloadJson = JsonSerializer.Serialize(payload, ContractJson.Options);
                assignments.Add(new JobAssignment
                {
                    Job = payload,
                    Lease = new JobLease
                    {
                        LeaseId = job.LeaseId.Value, ExpiresAt = job.LeaseExpiresAt.Value, Attempt = job.Attempt, MaxAttempts = job.MaxAttempts,
                        HeartbeatIntervalSeconds = Math.Max(5, limits.LeaseDurationSeconds / 4),
                    },
                });
            }
            await Db.SaveChangesAsync(ct);
            await tx.CommitAsync(ct);
        }

        foreach (var a in assignments)
            await events.PublishAsync(time, ScanExecutionEventType.JobAssigned, a.Job.ScanRunId,
                $"Assigned to {agentId}/{a.Job.InterfaceName} ({a.Job.Tool.ToolId}, {a.Job.Limits.RatePerSecond}/s, attempt {a.Lease.Attempt})",
                a.Job.WorkflowRunId, a.Job.WorkflowStepId, a.Job.JobId, agentId, ct: ct);
        return new JobClaimResponse { Assignments = assignments, NextPollSeconds = assignments.Count > 0 ? 1 : 5 };
    }

    public async Task<JobCallResult<JobHeartbeatResponse>> HeartbeatAsync(string agentId, Guid jobId, JobHeartbeatRequest request, CancellationToken ct = default)
    {
        var limits = await limitsStore.GetAsync(ct);
        var expires = time.GetUtcNow().AddSeconds(limits.LeaseDurationSeconds);
        var progress = request.Progress;
        double? percent = progress is null ? null : Math.Clamp(progress.Percent, 0, 100);
        var message = progress?.Message is { } m ? Truncate(SensitiveDataMasker.MaskTokens(m), 500) : null;

        var updated = await Db.Jobs
            .Where(j => j.Id == jobId && j.Status == JobStatus.Leased && j.LeaseId == request.LeaseId && j.AgentId == agentId)
            .ExecuteUpdateAsync(s =>
            {
                s.SetProperty(j => j.LeaseExpiresAt, expires);
                if (progress is not null) s.SetProperty(j => j.ProgressPercent, percent).SetProperty(j => j.ProgressMessage, message);
            }, ct);
        if (updated == 0) return await RejectAsync<JobHeartbeatResponse>(jobId, ct);

        var job = await Db.Jobs.AsNoTracking().Where(j => j.Id == jobId)
            .Select(j => new { j.CancelRequested, j.ScanRunId, j.WorkflowRunId, j.StepId }).FirstAsync(ct);
        if (progress is not null)
            await events.PublishAsync(time, ScanExecutionEventType.JobProgress, job.ScanRunId, message, job.WorkflowRunId, job.StepId, jobId, agentId, percent, ct: ct);
        return JobCallResult<JobHeartbeatResponse>.Ok(new JobHeartbeatResponse { LeaseExpiresAt = expires, CancelRequested = job.CancelRequested });
    }

    public async Task<JobCallResult<ResultBatchAck>> SubmitResultsAsync(string agentId, Guid jobId, ScanResultBatch batch, CancellationToken ct = default)
    {
        if (batch.JobId != jobId) return JobCallResult<ResultBatchAck>.Invalid("jobId in the body does not match the route.");
        if (batch.Observations is null || batch.Observations.Count > ScanResultBatch.MaxObservations)
            return JobCallResult<ResultBatchAck>.Invalid($"A batch must carry 0–{ScanResultBatch.MaxObservations} observations.");
        if (batch.Sequence < 0) return JobCallResult<ResultBatchAck>.Invalid("sequence must be >= 0.");

        var job = await Db.Jobs.AsNoTracking().FirstOrDefaultAsync(j => j.Id == jobId, ct);
        if (job is null) return JobCallResult<ResultBatchAck>.NotFound("Unknown job.");
        var duplicate = await FindDuplicateAsync(batch.BatchId, jobId, ct);
        if (duplicate is not null) return duplicate;
        if (!HoldsLease(job, agentId, batch.LeaseId)) return JobCallResult<ResultBatchAck>.Conflict("Stale lease or job not leased by this agent.");

        var guard = new ObservationGuard(Payload(job));
        var accepted = new List<DiscoveryObservation>(batch.Observations.Count);
        foreach (var o in batch.Observations)
            if (o is not null && guard.InScope(o)) accepted.Add(ObservationGuard.Mask(o));
        var dropped = batch.Observations.Count - accepted.Count;
        if (dropped > 0)
            logger.LogWarning("Job {JobId} batch {BatchId}: dropped {Count} observations outside the job's targets (agent {AgentId})", jobId, batch.BatchId, dropped, agentId);

        var stored = batch with { Observations = accepted };
        Db.ResultBatches.Add(new ResultBatchRecord
        {
            BatchId = batch.BatchId, JobId = jobId, ScanRunId = job.ScanRunId, StepId = job.StepId, LeaseId = batch.LeaseId, Sequence = batch.Sequence,
            ObservationCount = accepted.Count, ReceivedAt = time.GetUtcNow(), PayloadJson = JsonSerializer.Serialize(accepted, ContractJson.Options),
        });
        await outbox.PublishAsync(new ScanResultBatchReceived(new IngestContext
        {
            ScanRunId = job.ScanRunId, JobId = jobId, WorkflowStepId = job.StepId, Operation = job.Operation, AgentId = agentId,
            InterfaceName = job.InterfaceName, Zone = job.Zone, NetworkIds = [job.NetworkId],
        }, stored));
        try
        {
            await outbox.SaveChangesAndFlushMessagesAsync(ct);
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            await ResetAsync(ct); // concurrent upload of the same batch won the insert
            var duplicateAck = await FindDuplicateAsync(batch.BatchId, jobId, ct);
            if (duplicateAck is not null) return duplicateAck;
            throw;
        }

        if (batch.Progress is { } p)
            await Db.Jobs.Where(j => j.Id == jobId && j.LeaseId == batch.LeaseId && j.Status == JobStatus.Leased)
                .ExecuteUpdateAsync(s => s.SetProperty(j => j.ProgressPercent, Math.Clamp(p.Percent, 0, 100)), ct);
        await events.PublishAsync(time, ScanExecutionEventType.ResultsReceived, job.ScanRunId,
            $"Batch {batch.Sequence}: {accepted.Count} observations" + (dropped > 0 ? $" ({dropped} out of scope dropped)" : ""),
            job.WorkflowRunId, job.StepId, jobId, agentId, ct: ct);
        return JobCallResult<ResultBatchAck>.Ok(new ResultBatchAck { BatchId = batch.BatchId, Accepted = true, ObservationsAccepted = accepted.Count });
    }

    public async Task<JobCallResult<bool>> CompleteAsync(string agentId, Guid jobId, JobCompletionRequest request, CancellationToken ct = default)
    {
        if (request.TotalBatches < 0 || request.Coverage is null || request.ToolRun is null)
            return JobCallResult<bool>.Invalid("totalBatches, coverage and toolRun are required.");
        var job = await Db.Jobs.FirstOrDefaultAsync(j => j.Id == jobId, ct);
        if (job is null) return JobCallResult<bool>.NotFound("Unknown job.");
        if (!HoldsLease(job, agentId, request.LeaseId)) return JobCallResult<bool>.Conflict("Stale lease or job not leased by this agent.");
        var missing = await MissingBatchesAsync(jobId, request.LeaseId, request.TotalBatches, ct);
        if (missing is not null) return JobCallResult<bool>.Conflict(missing);

        var now = time.GetUtcNow();
        job.Status = JobStatus.Completed;
        job.FinishedAt = now;
        job.DurationMs = request.ToolRun.DurationMs > 0 ? request.ToolRun.DurationMs : (long)(now - (job.StartedAt ?? now)).TotalMilliseconds;
        job.ToolVersion = request.ToolRun.ToolVersion;
        job.CoverageJson = JsonSerializer.Serialize(request.Coverage, ContractJson.Options);
        job.ProgressPercent = 100;
        job.LeaseExpiresAt = null;
        job.Error = null;
        if (!await SaveTransitionAsync(job, ct)) return JobCallResult<bool>.Conflict("The job changed concurrently (lease expired or cancelled).");

        await RecordPerformanceAsync(job, now, ct);
        var seconds = job.DurationMs.Value / 1000.0;
        WebScanTelemetry.JobDuration.Record(seconds, Tag("operation", job.Operation), Tag("tool", job.ToolId), Tag("status", job.Status));
        WebScanTelemetry.IpsScanned.Add(job.TargetCount, Tag("agent", agentId), Tag("interface", job.InterfaceName), Tag("tool", job.ToolId), Tag("operation", job.Operation));
        if (seconds > 0) WebScanTelemetry.InterfaceThroughput.Record(job.TargetCount / seconds, Tag("agent", agentId), Tag("interface", job.InterfaceName));
        await events.PublishAsync(time, ScanExecutionEventType.JobCompleted, job.ScanRunId,
            request.Coverage.Complete ? "Completed" : $"Completed with {request.Coverage.UncoveredTargets.Count} uncovered targets",
            job.WorkflowRunId, job.StepId, job.Id, agentId, 100, ct: ct);
        return JobCallResult<bool>.Ok(true);
    }

    public async Task<JobCallResult<bool>> FailAsync(string agentId, Guid jobId, JobFailureRequest request, CancellationToken ct = default)
    {
        if (!Enum.IsDefined(request.Reason) || request.TotalBatches < 0) return JobCallResult<bool>.Invalid("Invalid failure reason or totalBatches.");
        var job = await Db.Jobs.FirstOrDefaultAsync(j => j.Id == jobId, ct);
        if (job is null) return JobCallResult<bool>.NotFound("Unknown job.");
        if (!HoldsLease(job, agentId, request.LeaseId)) return JobCallResult<bool>.Conflict("Stale lease or job not leased by this agent.");
        var missing = await MissingBatchesAsync(jobId, request.LeaseId, request.TotalBatches, ct);
        if (missing is not null) return JobCallResult<bool>.Conflict(missing);

        var now = time.GetUtcNow();
        if (request.Coverage is not null) job.CoverageJson = JsonSerializer.Serialize(request.Coverage, ContractJson.Options);
        job.DurationMs = request.ToolRun?.DurationMs ?? (long)(now - (job.StartedAt ?? now)).TotalMilliseconds;
        job.ToolVersion = request.ToolRun?.ToolVersion ?? job.ToolVersion;
        job.FailureReason = request.Reason;
        job.Error = Truncate($"{request.Reason}: {SensitiveDataMasker.MaskTokens(request.Message ?? "")}".TrimEnd(' ', ':'), 2000);
        job.LastAgentId = agentId;

        var cancelled = job.CancelRequested || request.Reason is JobFailureReason.Cancelled or JobFailureReason.WindowExpired || job.NotAfter <= now;
        var retry = !cancelled && request.Retryable && request.Reason != JobFailureReason.InvalidJob && job.Attempt < job.MaxAttempts;
        if (retry) Requeue(job, now.AddSeconds(Backoff(job)));
        else MarkTerminal(job, cancelled ? JobStatus.Cancelled : JobStatus.Failed, now);

        if (!await SaveTransitionAsync(job, ct)) return JobCallResult<bool>.Conflict("The job changed concurrently (lease expired or cancelled).");

        if (request.Reason == JobFailureReason.Timeout) WebScanTelemetry.JobTimeouts.Add(1, Tag("operation", job.Operation), Tag("tool", job.ToolId));
        if (job.Status == JobStatus.Failed) WebScanTelemetry.JobFailures.Add(1, Tag("operation", job.Operation), Tag("tool", job.ToolId));
        WebScanTelemetry.JobDuration.Record(job.DurationMs.Value / 1000.0, Tag("operation", job.Operation), Tag("tool", job.ToolId), Tag("status", job.Status));
        var type = job.Status switch
        {
            JobStatus.Queued => ScanExecutionEventType.JobRetryScheduled,
            JobStatus.Cancelled => ScanExecutionEventType.JobCancelled,
            _ => ScanExecutionEventType.JobFailed,
        };
        await events.PublishAsync(time, type, job.ScanRunId,
            retry ? $"{job.Error}; retry {job.Attempt + 1}/{job.MaxAttempts} at {job.NextAttemptAt:O}" : job.Error,
            job.WorkflowRunId, job.StepId, job.Id, agentId, ct: ct);
        return JobCallResult<bool>.Ok(true);
    }

    /// <summary>Lease lost (expired, timed out, agent offline): back to the queue for any eligible perspective, or ended.</summary>
    public async Task<bool> ReleaseLeaseAsync(Guid jobId, Guid leaseId, string reason, bool timedOut, CancellationToken ct = default)
    {
        var job = await Db.Jobs.FirstOrDefaultAsync(j => j.Id == jobId && j.LeaseId == leaseId && j.Status == JobStatus.Leased, ct);
        if (job is null) return false;
        var now = time.GetUtcNow();
        var agentId = job.AgentId;
        job.LastAgentId = agentId;
        job.Error = reason;
        job.FailureReason = timedOut ? JobFailureReason.Timeout : null;
        if (job.CancelRequested || job.NotAfter <= now) MarkTerminal(job, JobStatus.Cancelled, now);
        else if (job.Attempt >= job.MaxAttempts) MarkTerminal(job, JobStatus.Failed, now);
        else Requeue(job, now);
        if (!await SaveTransitionAsync(job, ct)) return false;

        if (timedOut) WebScanTelemetry.JobTimeouts.Add(1, Tag("operation", job.Operation), Tag("tool", job.ToolId));
        if (job.Status == JobStatus.Failed) WebScanTelemetry.JobFailures.Add(1, Tag("operation", job.Operation), Tag("tool", job.ToolId));
        await events.PublishAsync(time, ScanExecutionEventType.JobLeaseExpired, job.ScanRunId,
            job.Status == JobStatus.Queued ? $"{reason}; requeued for another perspective" : $"{reason}; job {job.Status}",
            job.WorkflowRunId, job.StepId, job.Id, agentId, ct: ct);
        return true;
    }

    /// <summary>UI cancel: queued jobs end immediately, leased jobs get <c>CancelRequested</c> (agent stops and reports).</summary>
    public async Task<JobCallResult<bool>> CancelAsync(Guid jobId, CancellationToken ct = default)
    {
        var job = await Db.Jobs.FirstOrDefaultAsync(j => j.Id == jobId, ct);
        if (job is null) return JobCallResult<bool>.NotFound("Unknown job.");
        if (job.IsTerminal) return JobCallResult<bool>.Conflict($"Job is already {job.Status}.");
        job.CancelRequested = true;
        if (job.Status == JobStatus.Queued) { job.Error = "Cancelled by user"; MarkTerminal(job, JobStatus.Cancelled, time.GetUtcNow()); }
        if (!await SaveTransitionAsync(job, ct)) return JobCallResult<bool>.Conflict("The job changed concurrently; try again.");
        await events.PublishAsync(time, ScanExecutionEventType.JobCancelled, job.ScanRunId,
            job.Status == JobStatus.Cancelled ? "Cancelled by user" : "Cancellation requested; waiting for the agent",
            job.WorkflowRunId, job.StepId, job.Id, job.AgentId, ct: ct);
        return JobCallResult<bool>.Ok(true);
    }

    /// <summary>UI retry of a failed/cancelled job while its run is still active.</summary>
    public async Task<JobCallResult<bool>> RetryAsync(Guid jobId, CancellationToken ct = default)
    {
        var job = await Db.Jobs.FirstOrDefaultAsync(j => j.Id == jobId, ct);
        if (job is null) return JobCallResult<bool>.NotFound("Unknown job.");
        if (job.Status is not (JobStatus.Failed or JobStatus.Cancelled)) return JobCallResult<bool>.Conflict($"Only failed or cancelled jobs can be retried (job is {job.Status}).");
        var runStatus = await Db.ScanRuns.Where(r => r.Id == job.ScanRunId).Select(r => r.Status).FirstAsync(ct);
        if (runStatus.IsTerminal()) return JobCallResult<bool>.Conflict($"The scan run is already {runStatus}.");
        job.Attempt = 0;
        job.CancelRequested = false;
        job.FinishedAt = null;
        job.FailureReason = null;
        job.Error = null;
        Requeue(job, null);
        await Db.SaveChangesAsync(ct);
        await events.PublishAsync(time, ScanExecutionEventType.JobQueued, job.ScanRunId, "Retry requested by user", job.WorkflowRunId, job.StepId, job.Id, ct: ct);
        return JobCallResult<bool>.Ok(true);
    }

    // ---- helpers ----

    private static bool HoldsLease(ScanJobRecord job, string agentId, Guid leaseId) =>
        job.Status == JobStatus.Leased && job.LeaseId == leaseId && job.AgentId == agentId;

    private async Task<JobCallResult<T>> RejectAsync<T>(Guid jobId, CancellationToken ct) =>
        await Db.Jobs.AnyAsync(j => j.Id == jobId, ct)
            ? JobCallResult<T>.Conflict("Stale lease or job not leased by this agent.")
            : JobCallResult<T>.NotFound("Unknown job.");

    private async Task<JobCallResult<ResultBatchAck>?> FindDuplicateAsync(Guid batchId, Guid jobId, CancellationToken ct)
    {
        var existing = await Db.ResultBatches.AsNoTracking().Where(b => b.BatchId == batchId)
            .Select(b => new { b.JobId, b.ObservationCount }).FirstOrDefaultAsync(ct);
        if (existing is null) return null;
        return existing.JobId == jobId
            ? JobCallResult<ResultBatchAck>.Ok(new ResultBatchAck { BatchId = batchId, Accepted = true, Duplicate = true, ObservationsAccepted = existing.ObservationCount })
            : JobCallResult<ResultBatchAck>.Invalid("batchId was already used for another job.");
    }

    private async Task<string?> MissingBatchesAsync(Guid jobId, Guid leaseId, int expected, CancellationToken ct)
    {
        var received = await Db.ResultBatches.CountAsync(b => b.JobId == jobId && b.LeaseId == leaseId, ct);
        return received < expected ? $"Received {received} of {expected} result batches for this lease; re-send the missing batches." : null;
    }

    /// <summary>Saves the job; terminal states publish <see cref="ScanJobFinished"/> atomically. False on a concurrent change.</summary>
    private async Task<bool> SaveTransitionAsync(ScanJobRecord job, CancellationToken ct)
    {
        if (job.IsTerminal)
            await outbox.PublishAsync(new ScanJobFinished(job.Id, job.ScanRunId, job.WorkflowRunId, job.StepId, job.Status.ToString()));
        try
        {
            await outbox.SaveChangesAndFlushMessagesAsync(ct);
            return true;
        }
        catch (DbUpdateConcurrencyException)
        {
            logger.LogInformation("Job {JobId} changed concurrently; transition to {Status} discarded", job.Id, job.Status);
            await ResetAsync(ct);
            return false;
        }
    }

    /// <summary>After a failed outbox save: roll back the transaction the outbox opened and forget pending changes.</summary>
    private async Task ResetAsync(CancellationToken ct)
    {
        if (Db.Database.CurrentTransaction is not null) await Db.Database.RollbackTransactionAsync(ct);
        Db.ChangeTracker.Clear();
    }

    private static void Requeue(ScanJobRecord job, DateTimeOffset? notBefore)
    {
        job.Status = JobStatus.Queued;
        job.NextAttemptAt = notBefore;
        job.AgentId = null;
        job.InterfaceName = null;
        job.ToolId = null;
        job.LeaseId = null;
        job.LeaseExpiresAt = null;
        job.AssignedRatePerSecond = null;
        job.ProgressPercent = null;
    }

    private static void MarkTerminal(ScanJobRecord job, JobStatus status, DateTimeOffset now)
    {
        job.Status = status;
        job.FinishedAt = now;
        job.LeaseExpiresAt = null;
    }

    private static int Backoff(ScanJobRecord job) =>
        (int)Math.Min(3600, job.BackoffSeconds * Math.Pow(2, Math.Max(0, job.Attempt - 1)));

    private async Task RecordPerformanceAsync(ScanJobRecord job, DateTimeOffset now, CancellationToken ct)
    {
        var seconds = Math.Max(0.001, job.DurationMs!.Value / 1000.0);
        var tps = job.TargetCount / seconds;
        await Db.Database.ExecuteSqlAsync($"""
            INSERT INTO scanning.job_performance (agent_id, interface_name, tool_id, jobs_completed, avg_duration_ms, avg_targets_per_second, updated_at)
            VALUES ({job.AgentId}, {job.InterfaceName ?? ""}, {job.ToolId ?? ""}, 1, {(double)job.DurationMs.Value}, {tps}, {now})
            ON CONFLICT (agent_id, interface_name, tool_id) DO UPDATE SET
              jobs_completed = job_performance.jobs_completed + 1,
              avg_duration_ms = job_performance.avg_duration_ms * {1 - PerformanceAlpha} + EXCLUDED.avg_duration_ms * {PerformanceAlpha},
              avg_targets_per_second = job_performance.avg_targets_per_second * {1 - PerformanceAlpha} + EXCLUDED.avg_targets_per_second * {PerformanceAlpha},
              updated_at = EXCLUDED.updated_at
            """, ct);
    }

    private static ClaimCandidate ToCandidate(ScanJobRecord j) =>
        new(j.Id, j.ScanRunId, j.StepId, j.Priority, j.CreatedAt,
            new JobRequirement(j.Zone, j.NetworkId, j.Capability, j.PreferredToolId, j.ReachTargets),
            j.SubnetKey, j.RequestedRatePerSecond, j.StepMaxConcurrency, j.LastAgentId);

    private static ScanJob Payload(ScanJobRecord job) =>
        JsonSerializer.Deserialize<ScanJob>(job.PayloadJson, ContractJson.Options) ?? throw new InvalidOperationException($"Job {job.Id} has no payload.");

    private static KeyValuePair<string, object?> Tag(string key, object? value) => new(key, value?.ToString());

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max];
}
