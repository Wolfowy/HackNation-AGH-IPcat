using System.Net;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WebScan.Agent.Execution;
using WebScan.Agent.Inventory;
using WebScan.Agent.Storage;
using WebScan.Agent.Tools;
using WebScan.Contracts;

namespace WebScan.Agent.Communication;

/// <summary>
/// Agent main loop: probe tools → register (enrollment on first start) → heartbeat, claim and upload loops.
/// Shutdown: stop claiming, cancel running jobs (AgentShutdown, retryable) and flush the buffer within <c>Agent:ShutdownFlushSeconds</c>.
/// </summary>
public sealed class AgentWorker(
    ToolRegistry tools,
    AgentRegistrar registrar,
    AgentState state,
    AgentApiClient api,
    JobExecutor executor,
    ResultUploader uploader,
    ResultBuffer buffer,
    NetworkInventory inventory,
    CredentialStore credentials,
    IOptionsMonitor<AgentOptions> options,
    TimeProvider time,
    ILogger<AgentWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await tools.InitializeAsync(stoppingToken);
            uploader.RecoverInterruptedJobs();
            await RegisterUntilSuccessAsync(stoppingToken);
            await Task.WhenAll(uploader.RunAsync(stoppingToken), HeartbeatLoopAsync(stoppingToken), ClaimLoopAsync(stoppingToken));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }

        await ShutdownAsync();
    }

    private async Task ShutdownAsync()
    {
        logger.LogInformation("Agent stopping: cancelling {Count} running job(s) and flushing results.", executor.ActiveJobIds.Count);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(Math.Max(1, options.CurrentValue.ShutdownFlushSeconds)), time);
        var drain = state.IsRegistered ? uploader.RunAsync(deadline.Token) : Task.CompletedTask;
        await executor.StopAsync(deadline.Token);
        try { await uploader.DrainOnceAsync(deadline.Token); }
        catch (Exception ex) when (ex is OperationCanceledException or HttpRequestException or AgentApiException) { }
        await deadline.CancelAsync();
        await drain;
        var left = buffer.PendingBatchCount();
        if (left > 0) logger.LogWarning("{Count} result batch(es) remain buffered and will be sent on the next start.", left);
    }

    private async Task RegisterUntilSuccessAsync(CancellationToken ct)
    {
        var backoff = MinBackoff;
        while (true)
        {
            try
            {
                if (await registrar.RegisterAsync(ct)) return;
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                logger.LogWarning("Registration failed: {Error}", ex.Message);
            }
            await Task.Delay(backoff, time, ct);
            backoff = Next(backoff);
        }
    }

    private async Task HeartbeatLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromSeconds(state.HeartbeatIntervalSeconds), time, ct);
            try
            {
                if (state.ConsumeReRegistration() || await registrar.InventoryChangedAsync(ct)) await registrar.RegisterAsync(ct);

                var (cpu, memory) = inventory.SampleLoad();
                var response = await api.HeartbeatAsync(new AgentHeartbeat
                {
                    AgentId = credentials.Current?.AgentId ?? AgentPaths.DefaultAgentId(options.CurrentValue),
                    Timestamp = time.GetUtcNow(),
                    Load = new AgentLoad
                    {
                        CpuPercent = cpu, MemoryUsedMb = memory, RunningJobs = executor.ActiveJobIds.Count,
                        BufferedBatches = buffer.PendingBatchCount(), RunningJobsPerInterface = executor.RunningJobsPerInterface,
                    },
                    ActiveJobIds = executor.ActiveJobIds,
                    InventoryHash = state.RegisteredInventoryHash,
                }, ct);

                if (state.Status != response.Status) logger.LogInformation("Agent status is now {Status}.", response.Status);
                state.Status = response.Status;
                foreach (var jobId in response.CancelJobIds) executor.Cancel(jobId, JobFailureReason.Cancelled);
                if (response.RotateCredentials) await registrar.RotateCredentialsAsync(ct);
                if (response.ReRegisterRequired) await registrar.RegisterAsync(ct);
            }
            catch (AgentApiException ex) when (ex.StatusCode == HttpStatusCode.Unauthorized)
            {
                logger.LogWarning("Heartbeat rejected (401); re-registering.");
                state.RequestReRegistration();
            }
            catch (AgentApiException ex) when (ex.StatusCode == HttpStatusCode.Forbidden)
            {
                logger.LogWarning("Agent is disabled or blocked by the server; not claiming jobs.");
                state.Status = AgentStatus.Disabled;
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                logger.LogWarning("Heartbeat failed: {Error}", ex.Message);
            }
        }
    }

    private async Task ClaimLoopAsync(CancellationToken ct)
    {
        var backoff = MinBackoff;
        while (!ct.IsCancellationRequested)
        {
            var poll = TimeSpan.FromSeconds(state.JobPollIntervalSeconds);
            if (!state.CanClaim) { await Task.Delay(poll, time, ct); continue; }

            var free = executor.FreeSlots;
            if (free == 0) { await executor.SlotFreed.WaitAsync(poll, ct); continue; }
            try
            {
                var response = await api.ClaimAsync(new JobClaimRequest
                {
                    MaxJobs = free,
                    Interfaces = executor.InterfacesWithCapacity(inventory.GetInterfaces().Select(i => i.Name)),
                }, ct);
                backoff = MinBackoff;
                foreach (var assignment in response.Assignments)
                {
                    if (executor.TryStart(assignment))
                        logger.LogInformation("Claimed job {JobId} ({Operation}, lease attempt {Attempt}).", assignment.Job.JobId, assignment.Job.Operation, assignment.Lease.Attempt);
                    else
                        logger.LogWarning("Could not start claimed job {JobId}; the lease will expire on the server.", assignment.Job.JobId);
                }
                if (response.Assignments.Count == 0)
                    await executor.SlotFreed.WaitAsync(TimeSpan.FromSeconds(Math.Max(1, response.NextPollSeconds)), ct);
            }
            catch (AgentApiException ex) when (ex.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                if (ex.StatusCode == HttpStatusCode.Unauthorized) state.RequestReRegistration();
                else state.Status = AgentStatus.Disabled;
                await Task.Delay(poll, time, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                logger.LogWarning("Claiming jobs failed: {Error}", ex.Message);
                await Task.Delay(backoff, time, ct);
                backoff = Next(backoff);
            }
        }
    }

    private TimeSpan MinBackoff => TimeSpan.FromSeconds(Math.Max(0.01, options.CurrentValue.ErrorBackoffSeconds));
    private static TimeSpan Next(TimeSpan backoff) => TimeSpan.FromTicks(Math.Min(backoff.Ticks * 2, TimeSpan.FromSeconds(60).Ticks));
}
