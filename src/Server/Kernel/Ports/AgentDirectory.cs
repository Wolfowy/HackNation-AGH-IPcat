using WebScan.Contracts;

namespace WebScan.Server.Kernel.Ports;

/// <summary>Read model of registered agents. Implemented by the Agents module; consumed by the TaskPlanner.</summary>
public interface IAgentDirectory
{
    /// <summary>Agents with Status=Active (online or not; check <see cref="AgentSnapshot.IsOnline"/>).</summary>
    Task<IReadOnlyList<AgentSnapshot>> GetActiveAgentsAsync(CancellationToken ct = default);

    Task<AgentSnapshot?> GetAsync(string agentId, CancellationToken ct = default);
}

public sealed record AgentSnapshot
{
    public required string AgentId { get; init; }
    public required AgentStatus Status { get; init; }

    /// <summary>Heartbeat received within the configured timeout.</summary>
    public required bool IsOnline { get; init; }

    public DateTimeOffset? LastHeartbeatAt { get; init; }

    /// <summary>Only tools approved and enabled by an administrator.</summary>
    public required IReadOnlyList<ToolDescriptor> ApprovedTools { get; init; }

    public required IReadOnlyList<NetworkInterfaceInfo> Interfaces { get; init; }
    public required IReadOnlyList<RouteInfo> Routes { get; init; }

    /// <summary>Zones the administrator authorized this agent to scan (authoritative).</summary>
    public required IReadOnlyList<string> AuthorizedZones { get; init; }

    /// <summary>Optional restriction to specific networks; empty = every network in <see cref="AuthorizedZones"/>.</summary>
    public IReadOnlyList<Guid> AuthorizedNetworkIds { get; init; } = [];

    /// <summary>Effective limits (agent-reported, possibly lowered by admin override).</summary>
    public required AgentLimits Limits { get; init; }

    public AgentLoad? Load { get; init; }
}
