using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WebScan.Contracts;
using WebScan.Server.Kernel.Messaging;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Kernel.Telemetry;
using WebScan.Server.Modules.Agents.Persistence;
using Wolverine.EntityFrameworkCore;

namespace WebScan.Server.Modules.Agents;

/// <summary><see cref="IAgentDirectory"/> for the planner: only approved + enabled tools, effective (min) limits.</summary>
internal sealed class AgentDirectory(AgentsDbContext db, IOptions<AgentsOptions> options, TimeProvider time) : IAgentDirectory
{
    public async Task<IReadOnlyList<AgentSnapshot>> GetActiveAgentsAsync(CancellationToken ct = default)
    {
        var agents = await db.Agents.AsNoTracking().Where(a => a.Status == AgentStatus.Active).OrderBy(a => a.AgentId).ToListAsync(ct);
        var usable = await AgentAdminEndpoints.UsableToolIdsAsync(db, ct);
        var now = time.GetUtcNow();
        return agents.Select(a => ToSnapshot(a, usable, now)).ToList();
    }

    public async Task<AgentSnapshot?> GetAsync(string agentId, CancellationToken ct = default)
    {
        var agent = await db.Agents.AsNoTracking().SingleOrDefaultAsync(a => a.AgentId == agentId, ct);
        return agent is null ? null : ToSnapshot(agent, await AgentAdminEndpoints.UsableToolIdsAsync(db, ct), time.GetUtcNow());
    }

    private AgentSnapshot ToSnapshot(Agent a, HashSet<string> usableTools, DateTimeOffset now) => new()
    {
        AgentId = a.AgentId,
        Status = a.Status,
        IsOnline = a.IsOnlineAt(now, options.Value.HeartbeatTimeout),
        LastHeartbeatAt = a.LastHeartbeatAt,
        ApprovedTools = a.Inventory.Tools.Where(t => usableTools.Contains(t.Id)).ToList(),
        Interfaces = a.Inventory.Interfaces,
        Routes = a.Inventory.Routes,
        ConnectedFrom = a.Inventory.ConnectedFrom,
        RawSockets = a.Inventory.RawSockets,
        AuthorizedZones = a.AuthorizedZones,
        AuthorizedNetworkIds = a.AuthorizedNetworkIds,
        Limits = a.EffectiveLimits,
        Load = a.Load,
    };
}

/// <summary>
/// Marks agents whose heartbeat is older than <c>Agents:HeartbeatTimeoutSeconds</c> offline (once) and publishes
/// <see cref="AgentWentOffline"/> through the Wolverine outbox, atomically with the flag change.
/// </summary>
internal sealed class AgentOfflineDetector(IServiceScopeFactory scopes, IOptions<AgentsOptions> options, TimeProvider time,
    ILoggerFactory loggers) : BackgroundService
{
    private readonly ILogger _logger = loggers.CreateLogger<AgentOfflineDetector>();
    private volatile int _activeAgents;

    public int ActiveAgents => _activeAgents;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        WebScanTelemetry.SetActiveAgentsProvider(() => _activeAgents);
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(Math.Max(1, options.Value.OfflineCheckIntervalSeconds)), time);
        do
        {
            try
            {
                await CheckAsync(stoppingToken);
            }
            catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
            {
                _logger.LogError(ex, "Agent offline check failed");
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    /// <summary>One detection pass; returns the ids of agents marked offline.</summary>
    public async Task<IReadOnlyList<string>> CheckAsync(CancellationToken ct)
    {
        await using var scope = scopes.CreateAsyncScope();
        var outbox = scope.ServiceProvider.GetRequiredService<IDbContextOutbox<AgentsDbContext>>();
        var db = outbox.DbContext;
        var now = time.GetUtcNow();
        var cutoff = now - options.Value.HeartbeatTimeout;

        var stale = await db.Agents.Where(a => a.IsOnline && (a.LastHeartbeatAt == null || a.LastHeartbeatAt < cutoff)).ToListAsync(ct);
        foreach (var agent in stale)
        {
            agent.IsOnline = false;
            await outbox.PublishAsync(new AgentWentOffline(agent.AgentId, agent.LastHeartbeatAt ?? agent.RegisteredAt));
        }
        if (stale.Count > 0)
        {
            await outbox.SaveChangesAndFlushMessagesAsync(ct);
            foreach (var agent in stale)
            {
                _logger.LogWarning("Agent {AgentId} went offline (last heartbeat {LastHeartbeatAt})", agent.AgentId, agent.LastHeartbeatAt);
                await AgentEvents.PublishAsync(scope.ServiceProvider, loggers, ScanExecutionEventType.AgentOffline, agent.AgentId, now,
                    "Agent stopped sending heartbeats.", ct);
            }
        }

        _activeAgents = await db.Agents.CountAsync(a => a.IsOnline && a.Status == AgentStatus.Active, ct);
        return stale.Select(a => a.AgentId).ToList();
    }
}

/// <summary>Seeds or refreshes the enrollment token from <c>Agents:BootstrapEnrollmentToken</c> (compose / dev convenience).</summary>
internal sealed class BootstrapEnrollmentTokenInitializer(IServiceScopeFactory scopes, IOptions<AgentsOptions> options, TimeProvider time,
    ILogger<BootstrapEnrollmentTokenInitializer> logger) : IHostedService
{
    internal static readonly Guid TokenId = new("0b5e7a1e-0000-4000-8000-00000000b007");

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var settings = options.Value;
        if (string.IsNullOrWhiteSpace(settings.BootstrapEnrollmentToken)) return;
        if (settings.BootstrapEnrollmentToken.Length < 16)
            throw new InvalidOperationException("Agents:BootstrapEnrollmentToken must be at least 16 characters long.");

        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AgentsDbContext>();
        var now = time.GetUtcNow();
        var token = await db.EnrollmentTokens.SingleOrDefaultAsync(t => t.Id == TokenId, cancellationToken);
        if (token is null)
        {
            token = new EnrollmentToken { Id = TokenId, Name = "bootstrap (configuration)", CreatedBy = "configuration", CreatedAt = now };
            db.EnrollmentTokens.Add(token);
        }
        token.TokenHash = AgentSecrets.Hash(settings.BootstrapEnrollmentToken);
        token.ExpiresAt = now.AddDays(365);
        token.MaxUses = int.MaxValue;
        token.Revoked = false;
        token.AutoApprove = settings.BootstrapEnrollmentAutoApprove;
        token.Zones = settings.BootstrapEnrollmentZones.ToList();
        await db.SaveChangesAsync(cancellationToken);
        logger.LogInformation("Bootstrap enrollment token refreshed (autoApprove={AutoApprove}, zones={Zones})",
            token.AutoApprove, string.Join(",", token.Zones));
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
