using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using WebScan.Contracts;
using WebScan.Server.Kernel.Messaging;
using WebScan.Server.Kernel.Networking;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Modules.Scanning.Events;
using WebScan.Server.Modules.Scanning.Persistence;
using WebScan.Server.Modules.Scanning.Planning;
using Wolverine.EntityFrameworkCore;

namespace WebScan.Server.Modules.Scanning.Runs;

public sealed record StepJobCounts(int Total, int Queued, int Leased, int Completed, int Failed, int Cancelled)
{
    public static readonly StepJobCounts None = new(0, 0, 0, 0, 0, 0);
    public int Active => Queued + Leased;
}

/// <summary>Scan run lifecycle and run-level queries used by the workflow engine and the scans API.</summary>
public sealed class ScanRunStore(IDbContextOutbox<ScanningDbContext> outbox, IScanEventPublisher events, TimeProvider time)
{
    private ScanningDbContext Db => outbox.DbContext;

    public Task<ScanRun?> GetAsync(Guid runId, CancellationToken ct = default) =>
        Db.ScanRuns.AsNoTracking().FirstOrDefaultAsync(r => r.Id == runId, ct);

    public Task<ScanRun?> FindByScheduleAsync(Guid scheduleId, DateTimeOffset fireTime, CancellationToken ct = default) =>
        Db.ScanRuns.AsNoTracking().FirstOrDefaultAsync(r => r.ScheduleId == scheduleId && r.ScheduledFireTime == fireTime, ct);

    /// <summary>Creates the run; a concurrent duplicate (same schedule fire) returns the existing run instead.</summary>
    public async Task<(ScanRun Run, bool Created)> CreateAsync(ScanRun run, CancellationToken ct = default)
    {
        Db.ScanRuns.Add(run);
        try
        {
            await Db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation }
                                            && run.ScheduleId is { } scheduleId && run.ScheduledFireTime is { } fire)
        {
            Db.ChangeTracker.Clear();
            var existing = await FindByScheduleAsync(scheduleId, fire, ct);
            if (existing is null) throw;
            return (existing, false);
        }
        await events.PublishAsync(time, ScanExecutionEventType.RunCreated, run.Id, $"Run '{run.Name}' created ({run.TriggeredBy})", ct: ct);
        return (run, true);
    }

    public async Task<IReadOnlyList<Guid>> ActiveRunIdsAsync(CancellationToken ct = default) =>
        await Db.ScanRuns.AsNoTracking().Where(r => r.Status == ScanRunStatus.Pending || r.Status == ScanRunStatus.Running)
            .OrderBy(r => r.CreatedAt).Select(r => r.Id).ToListAsync(ct);

    public async Task MarkRunningAsync(Guid runId, Guid workflowRunId, CancellationToken ct = default)
    {
        var now = time.GetUtcNow();
        var updated = await Db.ScanRuns.Where(r => r.Id == runId && r.Status == ScanRunStatus.Pending)
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.Status, ScanRunStatus.Running).SetProperty(r => r.StartedAt, now), ct);
        if (updated > 0) await events.PublishAsync(time, ScanExecutionEventType.RunStarted, runId, "Run started", workflowRunId, ct: ct);
    }

    public async Task<IReadOnlyDictionary<string, StepJobCounts>> StepJobCountsAsync(Guid runId, CancellationToken ct = default)
    {
        var rows = await Db.Jobs.AsNoTracking().Where(j => j.ScanRunId == runId)
            .GroupBy(j => new { j.StepId, j.Status }).Select(g => new { g.Key.StepId, g.Key.Status, Count = g.Count() }).ToListAsync(ct);
        return rows.GroupBy(r => r.StepId).ToDictionary(g => g.Key, g =>
        {
            int C(JobStatus s) => g.Where(r => r.Status == s).Sum(r => r.Count);
            return new StepJobCounts(g.Sum(r => r.Count), C(JobStatus.Queued), C(JobStatus.Leased), C(JobStatus.Completed), C(JobStatus.Failed), C(JobStatus.Cancelled));
        });
    }

    public Task<int> LeasedJobCountAsync(Guid runId, CancellationToken ct = default) =>
        Db.Jobs.CountAsync(j => j.ScanRunId == runId && j.Status == JobStatus.Leased, ct);

    /// <summary>Accepted observations of the given steps (deduplicated by observation id).</summary>
    public async Task<IReadOnlyList<DiscoveryObservation>> ObservationsAsync(Guid runId, IReadOnlyCollection<string> stepIds, CancellationToken ct = default)
    {
        var payloads = await Db.ResultBatches.AsNoTracking().Where(b => b.ScanRunId == runId && stepIds.Contains(b.StepId))
            .OrderBy(b => b.ReceivedAt).ThenBy(b => b.Sequence).Select(b => b.PayloadJson).ToListAsync(ct);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var result = new List<DiscoveryObservation>();
        foreach (var json in payloads)
            foreach (var o in JsonSerializer.Deserialize<List<DiscoveryObservation>>(json, ContractJson.Options) ?? [])
                if (seen.Add(o.ObservationId)) result.Add(o);
        return result;
    }

    /// <summary>Coverage from job coverage reports: targets of jobs minus what the agents reported as not covered.</summary>
    public async Task<RunCoverage> CoverageAsync(Guid runId, bool complete, CancellationToken ct = default)
    {
        var jobs = await Db.Jobs.AsNoTracking()
            .Where(j => j.ScanRunId == runId && j.Operation != ScanOperation.ExecuteSignatures && (j.Status == JobStatus.Completed || j.CoverageJson != null))
            .Select(j => new { j.Operation, j.Status, j.PayloadJson, j.CoverageJson }).ToListAsync(ct);

        var hosts = new IpRangeSet();
        var hostnames = new SortedSet<string>(StringComparer.Ordinal);
        var endpoints = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var j in jobs)
        {
            var coverage = j.CoverageJson is null ? null : JsonSerializer.Deserialize<JobCoverage>(j.CoverageJson, ContractJson.Options);
            if (coverage is null && j.Status != JobStatus.Completed) continue;
            var uncovered = coverage is { Complete: false } ? coverage.UncoveredTargets.ToHashSet(StringComparer.OrdinalIgnoreCase) : [];
            var targets = JsonSerializer.Deserialize<ScanJob>(j.PayloadJson, ContractJson.Options)!.Targets;

            var ranges = new List<IpRange>();
            foreach (var h in targets.Hosts)
            {
                if (IpRangeSet.TryParseRange(h, out var r)) ranges.Add(r);
                else if (!uncovered.Contains(h)) hostnames.Add(TargetPlanner.NormalizeHostname(h));
            }
            var uncoveredRanges = uncovered.Select(u => IpRangeSet.TryParseRange(u, out var r) ? r : (IpRange?)null).OfType<IpRange>();
            hosts = hosts.Union(IpRangeSet.FromRanges(ranges).Subtract(IpRangeSet.FromRanges(uncoveredRanges)));
            foreach (var key in targets.Endpoints.Select(e => $"{e.Address}:{e.Port}").Where(k => !uncovered.Contains(k)))
                endpoints.Add(key);
        }

        var executed = await Db.Jobs.AsNoTracking().Where(j => j.ScanRunId == runId && j.Status == JobStatus.Completed)
            .Select(j => j.Operation).Distinct().ToListAsync(ct);
        return new RunCoverage
        {
            CoveredHosts = [.. hosts.ToCidrs(), .. hostnames], CoveredEndpoints = [.. endpoints], Complete = complete,
            OperationsExecuted = executed.OrderBy(o => o).ToList(),
        };
    }

    public Task<bool> HasFailedJobsAsync(Guid runId, CancellationToken ct = default) =>
        Db.Jobs.AnyAsync(j => j.ScanRunId == runId && (j.Status == JobStatus.Failed || j.Status == JobStatus.Cancelled), ct);

    /// <summary>Cancels queued jobs and asks agents to stop leased ones (heartbeat returns <c>CancelRequested</c>).</summary>
    public async Task<(int Cancelled, int Signalled)> CancelJobsAsync(Guid runId, string reason, string? stepId = null, CancellationToken ct = default)
    {
        var now = time.GetUtcNow();
        var queued = Db.Jobs.Where(j => j.ScanRunId == runId && j.Status == JobStatus.Queued && (stepId == null || j.StepId == stepId));
        var cancelled = await queued.ExecuteUpdateAsync(s => s
            .SetProperty(j => j.Status, JobStatus.Cancelled).SetProperty(j => j.CancelRequested, true)
            .SetProperty(j => j.FinishedAt, now).SetProperty(j => j.Error, reason), ct);
        var signalled = await Db.Jobs.Where(j => j.ScanRunId == runId && j.Status == JobStatus.Leased && !j.CancelRequested && (stepId == null || j.StepId == stepId))
            .ExecuteUpdateAsync(s => s.SetProperty(j => j.CancelRequested, true), ct);
        if (cancelled + signalled > 0)
            await events.PublishAsync(time, ScanExecutionEventType.JobCancelled, runId,
                $"{reason}: {cancelled} queued jobs cancelled, {signalled} running jobs asked to stop", stepId: stepId, ct: ct);
        return (cancelled, signalled);
    }

    /// <summary>Moves the run to a terminal status and publishes <see cref="ScanRunFinished"/> atomically. False if already terminal.</summary>
    public async Task<bool> FinishAsync(Guid runId, ScanRunStatus status, bool coverageComplete, string? message, CancellationToken ct = default)
    {
        var now = time.GetUtcNow();
        await using var tx = await Db.Database.BeginTransactionAsync(ct);
        var updated = await Db.ScanRuns.Where(r => r.Id == runId && (r.Status == ScanRunStatus.Pending || r.Status == ScanRunStatus.Running))
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.Status, status).SetProperty(r => r.FinishedAt, now)
                .SetProperty(r => r.CoverageComplete, coverageComplete).SetProperty(r => r.Message, message), ct);
        if (updated == 0) return false;
        await outbox.PublishAsync(new ScanRunFinished(runId, status.ToString(), coverageComplete));
        await outbox.SaveChangesAndFlushMessagesAsync(ct); // commits the transaction above together with the envelope

        var type = status switch
        {
            ScanRunStatus.Completed => ScanExecutionEventType.RunCompleted,
            ScanRunStatus.PartiallyCompleted => ScanExecutionEventType.RunPartiallyCompleted,
            ScanRunStatus.Cancelled => ScanExecutionEventType.RunCancelled,
            ScanRunStatus.WindowExpired => ScanExecutionEventType.RunWindowExpired,
            _ => ScanExecutionEventType.RunFailed,
        };
        await events.PublishAsync(time, type, runId, message ?? status.ToString(),
            data: new Dictionary<string, string> { ["coverageComplete"] = coverageComplete ? "true" : "false" }, ct: ct);
        return true;
    }
}
