using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WebScan.Server.Kernel.Messaging;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Modules.Scanning.Persistence;
using WebScan.Server.Modules.Scanning.Planning;

namespace WebScan.Server.Modules.Scanning.Jobs;

/// <summary>Releases lost leases (expired, timed out, agent offline) so other perspectives can take the jobs.</summary>
public sealed class LeaseSweeper(
    IServiceScopeFactory scopes, IOptions<ScanningOptions> options, IOptions<PlannerOptions> plannerOptions, TimeProvider time, ILogger<LeaseSweeper> logger)
{
    private long _queuedJobs;

    /// <summary>Cached number of queued jobs (gauge <c>webscan.queue.length</c>), refreshed on every sweep.</summary>
    public long QueuedJobs => Interlocked.Read(ref _queuedJobs);

    public async Task<int> SweepOnceAsync(CancellationToken ct = default)
    {
        List<(Guid Id, Guid LeaseId, bool TimedOut)> lost;
        await using (var scope = scopes.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ScanningDbContext>();
            var now = time.GetUtcNow();
            var grace = options.Value.TimeoutGraceSeconds;
            var leased = await db.Jobs.AsNoTracking().Where(j => j.Status == JobStatus.Leased)
                .Select(j => new { j.Id, j.LeaseId, j.LeaseExpiresAt, j.StartedAt, j.TimeoutSeconds }).ToListAsync(ct);
            lost = leased
                .Where(j => j.LeaseExpiresAt < now || j.StartedAt?.AddSeconds(j.TimeoutSeconds + grace) < now)
                .Select(j => (j.Id, j.LeaseId!.Value, TimedOut: !(j.LeaseExpiresAt < now))).ToList();
            Interlocked.Exchange(ref _queuedJobs, await db.Jobs.LongCountAsync(j => j.Status == JobStatus.Queued, ct));
        }

        var released = 0;
        foreach (var (id, leaseId, timedOut) in lost)
            if (await ReleaseAsync(id, leaseId, timedOut ? "Job exceeded its timeout" : "Lease expired (no job heartbeat)", timedOut, ct)) released++;
        await CancelUnassignableAsync(ct);
        return released;
    }

    /// <summary>
    /// Jobs queued longer than <see cref="ScanLimits.UnassignedJobTimeoutSeconds"/> with no online agent eligible for them
    /// (zone, network restriction, approved tool, reachability) are cancelled so the scan finishes with the agents available.
    /// Jobs that only wait for a busy eligible agent keep waiting.
    /// </summary>
    public async Task<int> CancelUnassignableAsync(CancellationToken ct = default)
    {
        List<(Guid Id, string Reason)> doomed = [];
        await using (var scope = scopes.CreateAsyncScope())
        {
            var limits = await scope.ServiceProvider.GetRequiredService<ScanLimitsStore>().GetAsync(ct);
            if (limits.UnassignedJobTimeoutSeconds <= 0) return 0;
            var cutoff = time.GetUtcNow().AddSeconds(-limits.UnassignedJobTimeoutSeconds);
            var db = scope.ServiceProvider.GetRequiredService<ScanningDbContext>();
            // Wait period restarts when a job was requeued after running (StartedAt).
            var stale = await db.Jobs.AsNoTracking()
                .Where(j => j.Status == JobStatus.Queued && !j.CancelRequested && (j.StartedAt ?? j.CreatedAt) < cutoff)
                .ToListAsync(ct);
            if (stale.Count == 0) return 0;

            var planner = plannerOptions.Value;
            var agents = scope.ServiceProvider.GetRequiredService<IAgentDirectory>();
            var online = (await agents.GetActiveAgentsAsync(ct)).Where(a => a.IsOnline)
                .Select(a => (Agent: a, Reach: AgentReach.Build(a, planner.AllowDefaultRoute))).ToList();
            var minutes = limits.UnassignedJobTimeoutSeconds / 60.0;
            foreach (var job in stale)
            {
                var requirement = JobQueue.RequirementOf(job);
                var results = online.Select(o => Eligibility.Evaluate(o.Agent, o.Reach, requirement, planner)).ToList();
                if (results.Any(r => r.IsEligible)) continue;
                var why = results.Select(r => r.Reason).FirstOrDefault(r => r is not null) ?? "no online agent";
                doomed.Add((job.Id, $"No eligible agent within {minutes:0.#} min ({why}); targets skipped and reported as not covered"));
            }
        }

        var cancelled = 0;
        foreach (var (id, reason) in doomed)
        {
            await using var scope = scopes.CreateAsyncScope(); // one scope per transition (outbox rule)
            if (await scope.ServiceProvider.GetRequiredService<JobQueue>().CancelUnassignableAsync(id, reason, ct)) cancelled++;
        }
        if (cancelled > 0) logger.LogWarning("Cancelled {Count} queued jobs that no online agent can take", cancelled);
        return cancelled;
    }

    /// <summary>Immediately releases every lease of an agent that went offline.</summary>
    public async Task<int> ReleaseAgentAsync(string agentId, CancellationToken ct = default)
    {
        List<(Guid Id, Guid LeaseId)> leases;
        await using (var scope = scopes.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ScanningDbContext>();
            leases = (await db.Jobs.AsNoTracking().Where(j => j.Status == JobStatus.Leased && j.AgentId == agentId)
                .Select(j => new { j.Id, j.LeaseId }).ToListAsync(ct)).Select(j => (j.Id, j.LeaseId!.Value)).ToList();
        }
        var released = 0;
        foreach (var (id, leaseId) in leases)
            if (await ReleaseAsync(id, leaseId, $"Agent {agentId} went offline", false, ct)) released++;
        if (released > 0) logger.LogInformation("Released {Count} leases of offline agent {AgentId}", released, agentId);
        return released;
    }

    private async Task<bool> ReleaseAsync(Guid jobId, Guid leaseId, string reason, bool timedOut, CancellationToken ct)
    {
        // One scope per transition (outbox rule, see JobQueue).
        await using var scope = scopes.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<JobQueue>().ReleaseLeaseAsync(jobId, leaseId, reason, timedOut, ct);
    }
}

public sealed class LeaseSweeperService(LeaseSweeper sweeper, IOptions<ScanningOptions> options, ILogger<LeaseSweeperService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Value.SweeperEnabled) return;
        var interval = TimeSpan.FromSeconds(Math.Max(1, options.Value.SweepIntervalSeconds));
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await sweeper.SweepOnceAsync(stoppingToken); }
            catch (Exception ex) when (ex is not OperationCanceledException) { logger.LogError(ex, "Lease sweep failed"); }
            try { await Task.Delay(interval, stoppingToken); } catch (OperationCanceledException) { break; }
        }
    }
}

/// <summary>Wolverine handler: an agent stopped heartbeating, its jobs go back to the queue right away.</summary>
public static class AgentWentOfflineHandler
{
    public static Task Handle(AgentWentOffline message, LeaseSweeper sweeper, CancellationToken ct) => sweeper.ReleaseAgentAsync(message.AgentId, ct);
}
