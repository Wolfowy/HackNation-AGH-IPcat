namespace WebScan.Contracts;

/// <summary>
/// Sent by an agent on startup (and whenever its tools/interfaces change) to <c>POST /api/agents/register</c>.
/// First registration authenticates with an enrollment token (header <c>X-Enrollment-Token</c>);
/// later registrations authenticate with the agent credential (<c>Authorization: Agent {agentId}:{secret}</c>).
/// </summary>
public sealed record AgentRegistration
{
    /// <summary>Stable agent id chosen/persisted by the agent. Pattern: <see cref="AgentIdPattern"/>.</summary>
    public required string AgentId { get; init; }

    public required string Hostname { get; init; }

    /// <summary>"linux" / "windows" / "osx".</summary>
    public required string OsPlatform { get; init; }

    public required string OsDescription { get; init; }
    public required string AgentVersion { get; init; }

    /// <summary>Tools discovered from the agent's tool manifests and verified to be runnable.</summary>
    public required IReadOnlyList<ToolDescriptor> Tools { get; init; }

    public required IReadOnlyList<NetworkInterfaceInfo> Interfaces { get; init; }
    public IReadOnlyList<RouteInfo> Routes { get; init; } = [];

    /// <summary>Zones the agent claims to sit in (informational; the server's zone assignment is authoritative).</summary>
    public IReadOnlyList<string> DeclaredZones { get; init; } = [];

    public required AgentResources Resources { get; init; }
    public required AgentLimits Limits { get; init; }

    /// <summary>
    /// Whether the agent's scanning tools can use raw sockets (SYN scans, ICMP/ARP discovery): root, CAP_NET_RAW or tools with file
    /// capabilities. Null = unknown (treated as capable, e.g. older agents).
    /// </summary>
    public bool? RawSockets { get; init; }

    public const string AgentIdPattern = "^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,63}$";
}

/// <summary>A scanning tool available on the agent, described by its manifest.</summary>
public sealed record ToolDescriptor
{
    /// <summary>Manifest id, e.g. "nmap", "naabu", "httpx", "nuclei", or any custom id.</summary>
    public required string Id { get; init; }

    public required string Version { get; init; }

    /// <summary>Capabilities provided, e.g. ["host-discovery","service-detection"]. Open set, see <see cref="ToolCapabilities"/>.</summary>
    public required IReadOnlyList<string> Capabilities { get; init; }

    /// <summary>Operation parameters this tool understands (subset of <see cref="OperationCatalog"/> parameters).</summary>
    public IReadOnlyList<string> SupportedParameters { get; init; } = [];

    /// <summary>Output parser id used by the agent (informational).</summary>
    public string? Parser { get; init; }

    /// <summary>SHA-256 of the tool manifest; changes when the agent-side definition changes.</summary>
    public string? ManifestSha256 { get; init; }

    /// <summary>Max concurrent executions of this tool on the agent.</summary>
    public int MaxConcurrency { get; init; } = 1;
}

public sealed record NetworkInterfaceInfo
{
    public required string Name { get; init; }
    public string? Description { get; init; }
    public string? MacAddress { get; init; }
    public bool IsUp { get; init; } = true;

    /// <summary>Assigned addresses with prefix, e.g. "10.0.1.15/24", "fe80::1/64".</summary>
    public required IReadOnlyList<string> Addresses { get; init; }

    /// <summary>Link speed in Mbit/s if known.</summary>
    public long? SpeedMbps { get; init; }
}

public sealed record RouteInfo
{
    /// <summary>Destination CIDR, e.g. "10.20.0.0/16" or "0.0.0.0/0".</summary>
    public required string Destination { get; init; }

    public string? Gateway { get; init; }
    public required string InterfaceName { get; init; }
    public int Metric { get; init; }
}

public sealed record AgentResources
{
    public required int CpuCores { get; init; }
    public required long MemoryTotalMb { get; init; }
}

public sealed record AgentLimits
{
    public required int MaxConcurrentJobs { get; init; }

    /// <summary>Agent-wide upper bound for packets/requests per second across all jobs.</summary>
    public required int MaxRatePerSecond { get; init; }
}

public enum AgentStatus
{
    PendingApproval,
    Active,
    Disabled,
    Blocked,
}

public sealed record AgentRegistrationResponse
{
    public required string AgentId { get; init; }
    public required AgentStatus Status { get; init; }

    /// <summary>Returned only on first enrollment or credential rotation. The agent must persist it securely.</summary>
    public string? AgentSecret { get; init; }

    public DateTimeOffset? SecretExpiresAt { get; init; }
    public required int HeartbeatIntervalSeconds { get; init; }
    public required int JobPollIntervalSeconds { get; init; }

    /// <summary>Tool ids the server has not approved yet (agent may log them; they will not receive jobs).</summary>
    public IReadOnlyList<string> UnapprovedTools { get; init; } = [];
}

/// <summary><c>POST /api/agents/heartbeat</c>.</summary>
public sealed record AgentHeartbeat
{
    public required string AgentId { get; init; }
    public required DateTimeOffset Timestamp { get; init; }
    public required AgentLoad Load { get; init; }
    public IReadOnlyList<Guid> ActiveJobIds { get; init; } = [];

    /// <summary>Hash of tools+interfaces; when it differs from the registered one the server asks for re-registration.</summary>
    public string? InventoryHash { get; init; }
}

public sealed record AgentLoad
{
    public double CpuPercent { get; init; }
    public long MemoryUsedMb { get; init; }
    public int RunningJobs { get; init; }

    /// <summary>Results waiting in the local buffer (not yet acknowledged by the server).</summary>
    public int BufferedBatches { get; init; }

    public IReadOnlyDictionary<string, int> RunningJobsPerInterface { get; init; } = new Dictionary<string, int>();
}

public sealed record AgentHeartbeatResponse
{
    public required AgentStatus Status { get; init; }
    public bool ReRegisterRequired { get; init; }

    /// <summary>Server asks the agent to call <c>POST /api/agents/credentials/rotate</c>.</summary>
    public bool RotateCredentials { get; init; }

    /// <summary>Jobs the agent must stop immediately.</summary>
    public IReadOnlyList<Guid> CancelJobIds { get; init; } = [];

    public required DateTimeOffset ServerTime { get; init; }
}

/// <summary>Response of <c>POST /api/agents/credentials/rotate</c>. The previous secret stays valid for a grace period.</summary>
public sealed record AgentCredentialRotationResponse
{
    public required string AgentSecret { get; init; }
    public required DateTimeOffset PreviousSecretValidUntil { get; init; }
    public DateTimeOffset? SecretExpiresAt { get; init; }
}
