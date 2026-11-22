namespace WebScan.Contracts;

/// <summary>
/// Unit of work executed by one agent, through one tool, from one perspective (agent + interface),
/// against one batch of targets. Created by the server TaskPlanner; delivered to agents via
/// <c>POST /api/agents/jobs/claim</c> wrapped in a <see cref="JobAssignment"/>.
/// </summary>
public sealed record ScanJob
{
    public required Guid JobId { get; init; }
    public required Guid ScanRunId { get; init; }
    public Guid? WorkflowRunId { get; init; }
    public string? WorkflowStepId { get; init; }

    public required ScanOperation Operation { get; init; }
    public required ToolSelection Tool { get; init; }

    /// <summary>Exact set of targets to scan. Already minus exclusions; the agent must not scan anything else.</summary>
    public required JobTargets Targets { get; init; }

    /// <summary>
    /// Authorized scope (CIDRs / hostnames) the targets were derived from. The agent rejects the job
    /// if any target falls outside it (defence in depth against a compromised or buggy planner).
    /// </summary>
    public required IReadOnlyList<string> AuthorizedScope { get; init; }

    /// <summary>
    /// Ports the scope policy allows ("22,80,443,8000-8100"); null = every port. The agent rejects the job if an endpoint port or
    /// a port parameter in effect (<see cref="PortScope.ParametersInEffect"/>) falls outside it, or a port parameter is "top-N".
    /// </summary>
    public string? AuthorizedPorts { get; init; }

    /// <summary>Operation parameters, validated against <see cref="OperationCatalog"/> (string values only).</summary>
    public IReadOnlyDictionary<string, string> Parameters { get; init; } = new Dictionary<string, string>();

    public required JobLimits Limits { get; init; }

    /// <summary>Network interface (perspective) to scan from; null = OS default route.</summary>
    public string? InterfaceName { get; init; }

    public int Priority { get; init; }

    /// <summary>End of the allowed scan window. The agent must stop tool processes at this instant.</summary>
    public DateTimeOffset? NotAfter { get; init; }

    /// <summary>Approved signatures snapshot for <see cref="ScanOperation.ExecuteSignatures"/>.</summary>
    public SignatureBundle? Signatures { get; init; }
}

/// <summary>Which tool should run the job. Tools are selected by capability; ids are optional preferences.</summary>
public sealed record ToolSelection
{
    /// <summary>Capability the tool must provide (e.g. <see cref="ToolCapabilities.PortScan"/>).</summary>
    public required string Capability { get; init; }

    /// <summary>Tool id chosen by the planner among the agent's approved tools (e.g. "naabu"). Agent uses it if present.</summary>
    public string? ToolId { get; init; }
}

public sealed record JobTargets
{
    /// <summary>IP addresses, CIDR blocks or hostnames (for <see cref="TargetKind.Hosts"/> operations).</summary>
    public IReadOnlyList<string> Hosts { get; init; } = [];

    /// <summary>Concrete endpoints (for <see cref="TargetKind.Endpoints"/> operations).</summary>
    public IReadOnlyList<ScanEndpoint> Endpoints { get; init; } = [];

    /// <summary>Number of individual addresses/endpoints covered (for progress and throughput metrics).</summary>
    public long Count { get; init; }
}

public sealed record ScanEndpoint
{
    public required string Address { get; init; }
    public required int Port { get; init; }
    public TransportProtocol Transport { get; init; } = TransportProtocol.Tcp;

    /// <summary>
    /// Virtual host / SNI name if known. When set, tools connect by this name (URL host, SNI, Host header) instead of
    /// <see cref="Address"/>, so it must itself be inside the authorized scope.
    /// </summary>
    public string? Hostname { get; init; }

    /// <summary>"http" / "https" when known from service detection.</summary>
    public string? Scheme { get; init; }
}

public enum TransportProtocol
{
    Tcp,
    Udp,
}

public sealed record JobLimits
{
    /// <summary>Upper bound for packets/requests per second (min of step, schedule, agent, interface and global limits).</summary>
    public required int RatePerSecond { get; init; }

    /// <summary>Tool-level parallelism (threads / concurrent hosts).</summary>
    public int MaxParallelism { get; init; } = 25;

    /// <summary>Hard timeout for the whole job; the agent kills the tool process when it elapses.</summary>
    public required int TimeoutSeconds { get; init; }
}

/// <summary>Snapshot of approved signatures delivered inline with the job. The agent verifies <see cref="Sha256"/>.</summary>
public sealed record SignatureBundle
{
    /// <summary>Hex SHA-256 over the concatenation of (Id, Version, Content) of every signature in order.</summary>
    public required string Sha256 { get; init; }

    public required IReadOnlyList<SignatureContent> Items { get; init; }
}

public sealed record SignatureContent
{
    public required string Id { get; init; }
    public required int Version { get; init; }

    /// <summary>"nuclei-yaml" for active detection templates.</summary>
    public required string Format { get; init; }

    public required string Content { get; init; }
}

/// <summary>A job handed to an agent together with its lease.</summary>
public sealed record JobAssignment
{
    public required ScanJob Job { get; init; }
    public required JobLease Lease { get; init; }
}

/// <summary>
/// Exclusive, time-limited right to execute a job. Every agent call about the job carries <see cref="LeaseId"/>;
/// the server rejects calls with a stale lease (HTTP 409) so a re-assigned job never produces duplicate results.
/// </summary>
public sealed record JobLease
{
    public required Guid LeaseId { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>1-based attempt number.</summary>
    public required int Attempt { get; init; }

    public required int MaxAttempts { get; init; }

    /// <summary>How often the agent should call the job heartbeat endpoint to extend the lease.</summary>
    public required int HeartbeatIntervalSeconds { get; init; }
}
