namespace WebScan.Server.Kernel.Ports;

/// <summary>
/// Authorized scan scope. Implemented by the Networks module (networks, ranges, exclusions, global scope policy).
/// Only targets inside the administrator-defined scope policy can ever be scanned.
/// </summary>
public interface INetworkScopeService
{
    /// <summary>Resolves networks into normalized segments (include entries minus nothing; exclusions listed separately).</summary>
    Task<ResolvedScope> ResolveAsync(IReadOnlyCollection<Guid> networkIds, CancellationToken ct = default);

    /// <summary>True if the IP/CIDR/range/hostname lies completely inside the global scope policy and outside global exclusions.</summary>
    Task<bool> IsAuthorizedAsync(string target, CancellationToken ct = default);
}

public sealed record ResolvedScope
{
    public required IReadOnlyList<ScopeSegment> Segments { get; init; }

    /// <summary>Global exclusions (scope policy) that apply to every segment.</summary>
    public IReadOnlyList<string> GlobalExclusions { get; init; } = [];

    /// <summary>Scope policy port allowlist ("80", "8000-8100"); empty = every port.</summary>
    public IReadOnlyList<string> AllowedPorts { get; init; } = [];

    /// <summary>Scope policy port denylist; wins over <see cref="AllowedPorts"/>.</summary>
    public IReadOnlyList<string> ExcludedPorts { get; init; } = [];
}

public sealed record ScopeSegment
{
    public required Guid NetworkId { get; init; }
    public required string NetworkName { get; init; }

    /// <summary>Zone used for agent eligibility and per-zone limits.</summary>
    public required string Zone { get; init; }

    /// <summary>Normalized entries: IP, CIDR, "a-b" range or hostname.</summary>
    public required IReadOnlyList<string> Include { get; init; }

    /// <summary>Network-level exclusions (IP/CIDR/range/hostname).</summary>
    public IReadOnlyList<string> Exclude { get; init; } = [];

    /// <summary>Optional per-network rate cap (packets/s).</summary>
    public int? MaxRatePerSecond { get; init; }
}
