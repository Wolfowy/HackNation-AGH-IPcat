using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WebScan.Agent.Execution;
using WebScan.Agent.Storage;
using WebScan.Contracts;

namespace WebScan.Agent.Communication;

/// <summary>
/// Drains the local buffer: result batches in order, then each job's final complete/fail call once all its batches are
/// acknowledged. Retries transient failures with backoff indefinitely (server outages); 409/404 drop the job's data.
/// </summary>
public sealed class ResultUploader(
    ResultBuffer buffer,
    AgentApiClient api,
    AgentState state,
    IOptionsMonitor<AgentOptions> options,
    TimeProvider time,
    ILogger<ResultUploader> logger)
{
    private readonly AsyncSignal _signal = new();
    private readonly ConcurrentDictionary<Guid, TaskCompletionSource> _waiters = new();

    public void Signal() => _signal.Set();

    /// <summary>Completes when the job's final call was acknowledged or its data dropped (or <paramref name="ct"/> fires).</summary>
    public async Task WaitForJobAsync(Guid jobId, CancellationToken ct)
    {
        var tcs = _waiters.GetOrAdd(jobId, _ => new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously));
        if (!buffer.HasJob(jobId)) Release(jobId);
        try { await tcs.Task.WaitAsync(ct); }
        catch (OperationCanceledException) { } // data stays buffered and is sent after restart
    }

    /// <summary>Stale lease: drop all buffered data of the job.</summary>
    public void DropJob(Guid jobId)
    {
        buffer.RemoveJob(jobId);
        Release(jobId);
    }

    /// <summary>Jobs interrupted by a crash/kill of a previous process are reported as failed (AgentShutdown, retryable).</summary>
    public void RecoverInterruptedJobs()
    {
        foreach (var (jobId, leaseId, batchCount) in buffer.InterruptedJobs())
        {
            logger.LogWarning("Job {JobId} was interrupted by an agent restart; reporting it as failed.", jobId);
            buffer.SetFinal(jobId, FinalKind.Fail, JsonSerializer.Serialize(new JobFailureRequest
            {
                LeaseId = leaseId, Reason = JobFailureReason.AgentShutdown, Message = "Agent restarted while the job was running.",
                Retryable = true, TotalBatches = batchCount, Coverage = new JobCoverage { Complete = false },
            }, ContractJson.Options));
        }
    }

    public async Task RunAsync(CancellationToken ct)
    {
        var backoff = MinBackoff;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (await DrainOnceAsync(ct)) backoff = MinBackoff;
                else
                {
                    await Task.Delay(backoff, time, ct);
                    backoff = TimeSpan.FromTicks(Math.Min(backoff.Ticks * 2, MaxBackoff.Ticks));
                    continue;
                }
                await _signal.WaitAsync(TimeSpan.FromSeconds(5), ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
            catch (Exception ex)
            {
                // e.g. local disk full / SQLite I/O error: never let the upload loop die silently; results stay buffered.
                logger.LogWarning(ex, "Result upload loop failed: {Error}; retrying in {Delay}.", ex.Message, backoff);
                try { await Task.Delay(backoff, time, ct); } catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
                backoff = TimeSpan.FromTicks(Math.Min(backoff.Ticks * 2, MaxBackoff.Ticks));
            }
        }
    }

    /// <summary>One pass over the buffer; false when a transient failure stopped it (caller backs off).</summary>
    public async Task<bool> DrainOnceAsync(CancellationToken ct)
    {
        var dropped = new HashSet<Guid>();
        while (true)
        {
            var batches = buffer.PendingBatches(50);
            if (batches.Count == 0) break;
            foreach (var batch in batches.Where(b => !dropped.Contains(b.JobId)))
            {
                try
                {
                    await api.SendResultsAsync(batch.JobId, batch.GzipPayload, ct);
                    buffer.DeleteBatch(batch.BatchId);
                }
                catch (AgentApiException ex) when (ex.IsStaleJob)
                {
                    logger.LogWarning("Results of job {JobId} rejected ({Status}): lease is stale; dropping its buffered results.", batch.JobId, (int)ex.StatusCode);
                    DropJob(batch.JobId);
                    dropped.Add(batch.JobId);
                }
                catch (Exception ex) when (IsTransient(ex, ct))
                {
                    buffer.IncrementAttempts(batch.BatchId);
                    logger.LogWarning("Uploading batch {BatchId} of job {JobId} failed (attempt {Attempt}): {Error}", batch.BatchId, batch.JobId, batch.Attempts + 1, ex.Message);
                    return false;
                }
                catch (AgentApiException ex)
                {
                    // Permanent rejection (e.g. 422): retrying would block every later batch forever.
                    logger.LogError("Batch {BatchId} of job {JobId} permanently rejected: {Error}; discarded.", batch.BatchId, batch.JobId, ex.Message);
                    buffer.DeleteBatch(batch.BatchId);
                }
            }
        }

        foreach (var final in buffer.PendingFinals())
        {
            try
            {
                await api.SendFinalAsync(final.JobId, final.Kind, final.Payload, ct);
                logger.LogInformation("Job {JobId} reported as {Kind}.", final.JobId, final.Kind);
                DropJob(final.JobId);
            }
            catch (AgentApiException ex) when (ex.IsStaleJob)
            {
                logger.LogWarning("Final {Kind} of job {JobId} rejected ({Status}): lease is stale.", final.Kind, final.JobId, (int)ex.StatusCode);
                DropJob(final.JobId);
            }
            catch (Exception ex) when (IsTransient(ex, ct))
            {
                logger.LogWarning("Reporting job {JobId} as {Kind} failed: {Error}", final.JobId, final.Kind, ex.Message);
                return false;
            }
            catch (AgentApiException ex)
            {
                logger.LogError("Final {Kind} of job {JobId} permanently rejected: {Error}", final.Kind, final.JobId, ex.Message);
                DropJob(final.JobId);
            }
        }
        return true;
    }

    private bool IsTransient(Exception ex, CancellationToken ct)
    {
        if (ex is AgentApiException api)
        {
            if (api.StatusCode == HttpStatusCode.Unauthorized) state.RequestReRegistration();
            // 401/403 are retried too: credentials get renewed by re-registration, or an admin re-enables the agent.
            return !api.IsPermanent || api.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden;
        }
        return ex is HttpRequestException or IOException || (ex is OperationCanceledException && !ct.IsCancellationRequested);
    }

    private void Release(Guid jobId)
    {
        if (_waiters.TryRemove(jobId, out var tcs)) tcs.TrySetResult();
    }

    private TimeSpan MinBackoff => TimeSpan.FromSeconds(Math.Max(0.01, options.CurrentValue.ErrorBackoffSeconds));
    private static readonly TimeSpan MaxBackoff = TimeSpan.FromSeconds(60);
}
