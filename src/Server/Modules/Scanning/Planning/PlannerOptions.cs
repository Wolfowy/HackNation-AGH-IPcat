using WebScan.Contracts;

namespace WebScan.Server.Modules.Scanning.Planning;

/// <summary>Configuration section <c>Planner</c>.</summary>
public sealed class PlannerOptions
{
    public const string Section = "Planner";

    /// <summary>IPv6 segments with more addresses than this are rejected (no exhaustive IPv6 sweeps).</summary>
    public long MaxIpv6SegmentAddresses { get; set; } = 65_536;

    /// <summary>Whether a default route (0.0.0.0/0, ::/0) makes an interface eligible for any target.</summary>
    public bool AllowDefaultRoute { get; set; } = true;

    /// <summary>Operation name → capability override (<c>Planner:OperationCapabilities:ScanPorts = port-scan</c>).</summary>
    public Dictionary<string, string> OperationCapabilities { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Capability → ordered preferred tool ids (<c>Planner:ToolPreference:port-scan:0 = naabu</c>).</summary>
    public Dictionary<string, List<string>> ToolPreference { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public string CapabilityFor(ScanOperation operation) =>
        OperationCapabilities.TryGetValue(operation.ToString(), out var c) && !string.IsNullOrWhiteSpace(c)
            ? c.Trim()
            : OperationCatalog.Get(operation).RequiredCapability
              ?? throw new InvalidOperationException($"Operation {operation} does not run on agents.");

    /// <summary>Effective operation → capability mapping for agent-plane operations (served by <c>GET /api/operations</c>).</summary>
    public IReadOnlyDictionary<string, string> EffectiveCapabilityMapping() =>
        OperationCatalog.All.Values.Where(d => d.Plane == OperationPlane.Agent)
            .ToDictionary(d => d.Operation.ToString(), d => CapabilityFor(d.Operation));
}

/// <summary>Configuration section <c>Scanning</c> (background services).</summary>
public sealed class ScanningOptions
{
    public const string Section = "Scanning";
    public bool SweeperEnabled { get; set; } = true;
    public int SweepIntervalSeconds { get; set; } = 15;

    /// <summary>Extra time after a job's timeout before the server gives up on a leased job that still heartbeats.</summary>
    public int TimeoutGraceSeconds { get; set; } = 120;
}

public sealed class PlanningException(string message) : Exception(message);
