using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WebScan.Agent.Communication;
using WebScan.Agent.Storage;
using WebScan.Agent.Tools.Abstractions;
using WebScan.Contracts;

namespace WebScan.Agent.Execution;

/// <summary>
/// Lifecycle of claimed jobs: validation, concurrency limits (agent slots, per-tool <c>maxConcurrency</c>, per-interface),
/// tool execution with timeout/window/cancel handling, batched buffered results, job heartbeats, coverage and the final
/// complete/fail report (sent by <see cref="ResultUploader"/> after all batches were acknowledged).
/// </summary>
public sealed class JobExecutor(
    JobValidator validator,
    ToolExecutor toolExecutor,
    AgentApiClient api,
    ResultBuffer buffer,
    ResultUploader uploader,
    IOptionsMonitor<AgentOptions> options,
    TimeProvider time,
    ILogger<JobExecutor> logger)
{
    private readonly ConcurrentDictionary<Guid, RunningJob> _running = new();
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _toolSlots = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _interfaceSlots = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource _lifetime = new();

    /// <summary>Set whenever a job finishes (claim loop wake-up).</summary>
    public AsyncSignal SlotFreed { get; } = new();

    public int FreeSlots => Math.Max(0, options.CurrentValue.MaxConcurrentJobs - _running.Count);
    public IReadOnlyList<Guid> ActiveJobIds => [.. _running.Keys];

    public IReadOnlyDictionary<string, int> RunningJobsPerInterface =>
        _running.Values.Where(j => j.Job.InterfaceName is not null).GroupBy(j => j.Job.InterfaceName!).ToDictionary(g => g.Key, g => g.Count());

    /// <summary>Interfaces below the per-interface limit, or null when every interface has capacity.</summary>
    public IReadOnlyList<string>? InterfacesWithCapacity(IEnumerable<string> interfaces)
    {
        var limit = PerInterfaceLimit;
        if (limit >= options.CurrentValue.MaxConcurrentJobs) return null;
        var running = RunningJobsPerInterface;
        return [.. interfaces.Where(i => running.GetValueOrDefault(i) < limit)];
    }

    public bool TryStart(JobAssignment assignment)
    {
        if (FreeSlots == 0 || _lifetime.IsCancellationRequested) return false;
        var job = new RunningJob(assignment);
        if (!_running.TryAdd(assignment.Job.JobId, job)) return false;
        job.Task = Task.Run(() => RunAsync(job));
        return true;
    }

    public void Cancel(Guid jobId, JobFailureReason reason)
    {
        if (_running.TryGetValue(jobId, out var job)) job.Cancel(reason);
    }

    /// <summary>Cancels running jobs (AgentShutdown, retryable) and waits until their results are reported or <paramref name="flushDeadline"/> fires.</summary>
    public async Task StopAsync(CancellationToken flushDeadline)
    {
        foreach (var job in _running.Values) job.Cancel(JobFailureReason.AgentShutdown);
        using var _ = flushDeadline.Register(() => _lifetime.Cancel());
        await Task.WhenAll(_running.Values.Select(j => j.Task ?? Task.CompletedTask));
        await _lifetime.CancelAsync();
    }

    private async Task RunAsync(RunningJob running)
    {
        var job = running.Job;
        var lease = running.Assignment.Lease;
        using var heartbeatStop = new CancellationTokenSource();
        ResultBatcher? batcher = null;
        var heartbeat = Task.CompletedTask;
        try
        {
            buffer.StartJob(job.JobId, lease.LeaseId);
            heartbeat = HeartbeatLoopAsync(running, () => batcher?.Progress(), heartbeatStop.Token);

            var validation = validator.Validate(job);
            if (!validation.IsValid)
            {
                logger.LogWarning("Job {JobId} rejected: {Reason} {Error}", job.JobId, validation.Reason, validation.Error);
                Finish(job.JobId, FinalKind.Fail, new JobFailureRequest
                {
                    LeaseId = lease.LeaseId, Reason = validation.Reason, Message = validation.Error, Retryable = validation.Retryable,
                    TotalBatches = 0, Coverage = new JobCoverage { Complete = false, UncoveredTargets = [.. Targets.CoverageKeys(job.Targets)] },
                });
            }
            else
            {
                batcher = new ResultBatcher(job, lease.LeaseId, buffer, uploader.Signal, options.CurrentValue.ResultBatchMaxObservations,
                    TimeSpan.FromSeconds(Math.Max(1, options.CurrentValue.ResultBatchFlushSeconds)), time);
                await ExecuteAsync(running, validation.Job!, batcher);
            }

            // Keep the lease alive (heartbeats) until the final report is acknowledged.
            await uploader.WaitForJobAsync(job.JobId, _lifetime.Token);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Job {JobId} failed unexpectedly.", job.JobId);
        }
        finally
        {
            await heartbeatStop.CancelAsync();
            await heartbeat;
            if (batcher is not null) await batcher.DisposeAsync();
            _running.TryRemove(job.JobId, out _);
            running.Dispose();
            SlotFreed.Set();
        }
    }

    private async Task ExecuteAsync(RunningJob running, ValidatedJob validated, ResultBatcher batcher)
    {
        var job = running.Job;
        var lease = running.Assignment.Lease;
        ToolExecutionResult? result = null;
        Exception? error = null;
        var started = time.GetTimestamp();
        using var timeoutCts = new CancellationTokenSource(validated.Timeout, time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(running.Token, timeoutCts.Token);

        var toolSlot = _toolSlots.GetOrAdd(validated.Tool.Id, _ => new SemaphoreSlim(validated.Tool.Manifest.MaxConcurrency));
        var interfaceSlot = job.InterfaceName is { } nic ? _interfaceSlots.GetOrAdd(nic, _ => new SemaphoreSlim(PerInterfaceLimit)) : null;
        var acquired = new List<SemaphoreSlim>();
        try
        {
            await toolSlot.WaitAsync(linked.Token);
            acquired.Add(toolSlot);
            if (interfaceSlot is not null) { await interfaceSlot.WaitAsync(linked.Token); acquired.Add(interfaceSlot); }
            result = await toolExecutor.RunAsync(validated, batcher, linked.Token);
        }
        catch (OperationCanceledException) when (linked.IsCancellationRequested) { }
        catch (Exception ex)
        {
            error = ex;
            logger.LogError(ex, "Job {JobId}: tool execution failed.", job.JobId);
        }
        finally
        {
            foreach (var slot in acquired) slot.Release();
        }

        await batcher.CompleteAsync();
        if (running.Stale || !batcher.Accepted)
        {
            logger.LogWarning("Job {JobId}: lease is stale; results dropped.", job.JobId);
            uploader.DropJob(job.JobId);
            return;
        }
        if (timeoutCts.IsCancellationRequested) running.Cancel(validated.TimeoutIsWindowEnd ? JobFailureReason.WindowExpired : JobFailureReason.Timeout);

        var toolRun = new ToolRunInfo
        {
            ToolId = validated.Tool.Id,
            ToolVersion = validated.Tool.Version,
            ExitCode = result?.ExitCode,
            DurationMs = (long)(result?.Duration ?? time.GetElapsedTime(started)).TotalMilliseconds,
            StderrTail = Tail(result?.StderrTail),
        };
        var complete = error is null && running.CancelReason is null && result?.ExitCode == 0;
        var coverage = complete ? new JobCoverage { Complete = true } : new JobCoverage { Complete = false, UncoveredTargets = batcher.UncoveredTargets() };

        if (complete)
        {
            logger.LogInformation("Job {JobId} completed: {Observations} observation(s) in {Batches} batch(es).", job.JobId, batcher.ObservationCount, batcher.TotalBatches);
            Finish(job.JobId, FinalKind.Complete, new JobCompletionRequest { LeaseId = lease.LeaseId, TotalBatches = batcher.TotalBatches, Coverage = coverage, ToolRun = toolRun });
            return;
        }

        var reason = running.CancelReason ?? (error is not null ? JobFailureReason.Internal : JobFailureReason.ToolError);
        var message = reason switch
        {
            JobFailureReason.ToolError => $"Tool exited with code {result?.ExitCode}.",
            JobFailureReason.Internal => Tail(SensitiveDataMasker.MaskTokens(error?.Message ?? "")),
            _ => $"Job stopped: {reason}.",
        };
        logger.LogWarning("Job {JobId} failed ({Reason}): {Message} {Uncovered} target(s) uncovered.", job.JobId, reason, message, coverage.UncoveredTargets.Count);
        Finish(job.JobId, FinalKind.Fail, new JobFailureRequest
        {
            LeaseId = lease.LeaseId, Reason = reason, Message = message,
            Retryable = reason is not (JobFailureReason.Cancelled or JobFailureReason.WindowExpired or JobFailureReason.InvalidJob),
            TotalBatches = batcher.TotalBatches, Coverage = coverage, ToolRun = toolRun,
        });
    }

    private void Finish<T>(Guid jobId, FinalKind kind, T request)
    {
        buffer.SetFinal(jobId, kind, JsonSerializer.Serialize(request, ContractJson.Options));
        uploader.Signal();
    }

    private async Task HeartbeatLoopAsync(RunningJob running, Func<JobProgress?> progress, CancellationToken stop)
    {
        var interval = TimeSpan.FromSeconds(Math.Max(1, running.Assignment.Lease.HeartbeatIntervalSeconds));
        var jobId = running.Job.JobId;
        try
        {
            while (true)
            {
                await Task.Delay(interval, time, stop);
                try
                {
                    var response = await api.JobHeartbeatAsync(jobId, new JobHeartbeatRequest { LeaseId = running.Assignment.Lease.LeaseId, Progress = progress() }, stop);
                    if (response.CancelRequested)
                    {
                        logger.LogInformation("Job {JobId}: cancellation requested by the server.", jobId);
                        running.Cancel(JobFailureReason.Cancelled);
                    }
                }
                catch (AgentApiException ex) when (ex.IsStaleJob)
                {
                    logger.LogWarning("Job {JobId}: heartbeat rejected ({Status}); aborting and dropping results.", jobId, (int)ex.StatusCode);
                    running.Stale = true;
                    running.Cancel(JobFailureReason.Cancelled);
                    uploader.DropJob(jobId);
                    return;
                }
                catch (Exception ex) when (ex is not OperationCanceledException || !stop.IsCancellationRequested)
                {
                    logger.LogDebug(ex, "Job {JobId}: heartbeat failed; retrying at the next interval.", jobId);
                }
            }
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
    }

    private int PerInterfaceLimit => Math.Max(1, options.CurrentValue.MaxConcurrentJobsPerInterface ?? options.CurrentValue.MaxConcurrentJobs);

    private static string? Tail(string? text) => text is null || text.Length <= 4096 ? text : text[^4096..];

    private sealed class RunningJob(JobAssignment assignment) : IDisposable
    {
        private readonly CancellationTokenSource _cts = new();
        private int _reason = -1;

        public JobAssignment Assignment { get; } = assignment;
        public ScanJob Job => Assignment.Job;
        public CancellationToken Token => _cts.Token;
        public Task? Task { get; set; }
        public volatile bool Stale;

        /// <summary>First reason wins (e.g. a timeout after a server cancel stays "Cancelled").</summary>
        public JobFailureReason? CancelReason => Volatile.Read(ref _reason) is var r and >= 0 ? (JobFailureReason)r : null;

        public void Cancel(JobFailureReason reason)
        {
            if (Interlocked.CompareExchange(ref _reason, (int)reason, -1) == -1)
                try { _cts.Cancel(); } catch (ObjectDisposedException) { }
        }

        public void Dispose() => _cts.Dispose();
    }
}
