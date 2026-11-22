namespace WebScan.Contracts;

/// <summary>
/// Closed set of approved workflow operations. Workflows can only reference these;
/// nothing in a workflow definition is ever executed as code or shell.
/// </summary>
public enum ScanOperation
{
    DiscoverHosts,
    ScanPorts,
    DetectService,
    HttpProbe,
    TlsProbe,
    ExecuteSignatures,
    EvaluateCondition,
    PersistObservations,
    ComparePreviousScan,
    PublishFinding,

    /// <summary>
    /// Re-probes hosts/endpoints that were known before but not observed in the current run (inside its coverage), in
    /// rounds with a delay, through the existing host-discovery and port-scan capabilities. Unstable hosts are always re-checked.
    /// </summary>
    RecheckMissing,
}

/// <summary>Where an operation runs.</summary>
public enum OperationPlane
{
    /// <summary>Executed by a Scanner Agent through a tool that provides <see cref="OperationDescriptor.RequiredCapability"/>.</summary>
    Agent,

    /// <summary>Executed inside the Central Server (no network traffic to targets).</summary>
    Server,
}

/// <summary>
/// Well-known tool capability identifiers. Capabilities are open strings, not an enum:
/// an agent may report any capability its tool manifests declare, and the server maps
/// operations to capabilities through configuration (defaults in <see cref="OperationCatalog"/>).
/// </summary>
public static class ToolCapabilities
{
    public const string HostDiscovery = "host-discovery";
    public const string PortScan = "port-scan";
    public const string ServiceDetection = "service-detection";
    public const string HttpProbe = "http-probe";
    public const string TlsProbe = "tls-probe";
    public const string SignatureScan = "signature-scan";
    public const string DnsResolve = "dns-resolve";

    /// <summary>Capability ids: lowercase letters, digits, '-', '.', max 64 chars.</summary>
    public const string Pattern = "^[a-z0-9][a-z0-9.-]{0,63}$";
}

/// <summary>Type of an operation/tool parameter. Values always travel as strings and are validated against the type.</summary>
public enum ParameterType
{
    /// <summary>Integer within [Min, Max].</summary>
    Integer,

    /// <summary>"true" / "false".</summary>
    Boolean,

    /// <summary>One of <see cref="ParameterDescriptor.AllowedValues"/>.</summary>
    Enum,

    /// <summary>Port specification: "80", "1-1024", "22,80,443,8000-8100", or "top-100" / "top-1000".</summary>
    PortSpec,

    /// <summary>Comma separated list; every item must match <see cref="ParameterDescriptor.Pattern"/> or be in <see cref="ParameterDescriptor.AllowedValues"/>.</summary>
    StringList,

    /// <summary>Free string constrained by <see cref="ParameterDescriptor.Pattern"/> (required for this type).</summary>
    String,
}

public sealed record ParameterDescriptor
{
    public required string Name { get; init; }
    public required ParameterType Type { get; init; }
    public string? Description { get; init; }
    public string? Default { get; init; }
    public bool Required { get; init; }
    public long? Min { get; init; }
    public long? Max { get; init; }
    public IReadOnlyList<string>? AllowedValues { get; init; }

    /// <summary>Anchored regex for String/StringList items (for PortSpec an extra restriction on top of the port syntax).</summary>
    public string? Pattern { get; init; }

    /// <summary>Values that need raw sockets on the agent (root, CAP_NET_RAW): only agents reporting that capability get such jobs.</summary>
    public IReadOnlyList<string>? PrivilegedValues { get; init; }
}

public sealed record OperationDescriptor
{
    public required ScanOperation Operation { get; init; }
    public required OperationPlane Plane { get; init; }

    /// <summary>Default capability required from an agent tool (Agent plane only). Server may override via configuration.</summary>
    public string? RequiredCapability { get; init; }

    /// <summary>Whether the operation consumes host targets (IPs/CIDRs/hostnames) or endpoints (host:port).</summary>
    public required TargetKind InputKind { get; init; }

    public required IReadOnlyList<ParameterDescriptor> Parameters { get; init; }
}

public enum TargetKind
{
    None,
    Hosts,
    Endpoints,
}

/// <summary>
/// Single source of truth for operation semantics and parameter schemas.
/// Used by server validation, agent validation and the admin UI (served via GET /api/operations).
/// </summary>
public static class OperationCatalog
{
    private const string PortSpecHelp = "e.g. 80,443,8000-8100 or top-100 / top-1000";

    private static readonly ParameterDescriptor Rate = new()
    {
        Name = "rate", Type = ParameterType.Integer, Min = 1, Max = 100_000, Default = "500",
        Description = "Max packets/requests per second for this job (further capped by agent and global limits).",
    };

    private static readonly ParameterDescriptor Retries = new()
    {
        Name = "retries", Type = ParameterType.Integer, Min = 0, Max = 5, Default = "1",
    };

    public static readonly IReadOnlyDictionary<ScanOperation, OperationDescriptor> All =
        new Dictionary<ScanOperation, OperationDescriptor>
        {
            [ScanOperation.DiscoverHosts] = new()
            {
                Operation = ScanOperation.DiscoverHosts, Plane = OperationPlane.Agent,
                RequiredCapability = ToolCapabilities.HostDiscovery, InputKind = TargetKind.Hosts,
                Parameters =
                [
                    new() { Name = "method", Type = ParameterType.Enum, AllowedValues = ["default", "icmp", "tcp-syn", "tcp-ack", "arp", "none"], Default = "default",
                            PrivilegedValues = ["icmp", "tcp-ack", "arp"],
                            Description = "Probe technique: default/tcp-syn = TCP SYN ping to probePorts, tcp-ack = TCP ACK ping to probePorts, icmp = ICMP echo only, " +
                                          "arp = ARP only (same L2 segment), none = treat every target as up (useful behind ICMP filtering). icmp, tcp-ack and arp need raw sockets." },
                    new() { Name = "probePorts", Type = ParameterType.PortSpec, Default = "22,80,443,3389,8080", Pattern = "^[0-9][0-9,-]*$",
                            Description = "Ports used by the TCP ping methods (default, tcp-syn, tcp-ack), e.g. 22,80,443 or 8000-8100 (no top-N)." },
                    Rate, Retries,
                ],
            },
            [ScanOperation.ScanPorts] = new()
            {
                Operation = ScanOperation.ScanPorts, Plane = OperationPlane.Agent,
                RequiredCapability = ToolCapabilities.PortScan, InputKind = TargetKind.Hosts,
                Parameters =
                [
                    new() { Name = "ports", Type = ParameterType.PortSpec, Default = "top-100", Required = true, Description = PortSpecHelp },
                    new() { Name = "scanType", Type = ParameterType.Enum, AllowedValues = ["connect", "syn"], Default = "connect", PrivilegedValues = ["syn"],
                            Description = "connect = full TCP handshake (no privileges); syn = half-open scan, needs raw sockets." },
                    Rate, Retries,
                ],
            },
            [ScanOperation.DetectService] = new()
            {
                Operation = ScanOperation.DetectService, Plane = OperationPlane.Agent,
                RequiredCapability = ToolCapabilities.ServiceDetection, InputKind = TargetKind.Endpoints,
                Parameters =
                [
                    new() { Name = "versionIntensity", Type = ParameterType.Integer, Min = 0, Max = 9, Default = "5" },
                    new() { Name = "grabBanner", Type = ParameterType.Boolean, Default = "true" },
                    Rate,
                ],
            },
            [ScanOperation.HttpProbe] = new()
            {
                Operation = ScanOperation.HttpProbe, Plane = OperationPlane.Agent,
                RequiredCapability = ToolCapabilities.HttpProbe, InputKind = TargetKind.Endpoints,
                Parameters =
                [
                    new() { Name = "followRedirects", Type = ParameterType.Boolean, Default = "true" },
                    new() { Name = "maxRedirects", Type = ParameterType.Integer, Min = 0, Max = 10, Default = "3" },
                    new() { Name = "techDetect", Type = ParameterType.Boolean, Default = "true" },
                    new() { Name = "faviconHash", Type = ParameterType.Boolean, Default = "true" },
                    new() { Name = "paths", Type = ParameterType.StringList, Default = "/", Pattern = "^/[A-Za-z0-9._~/-]{0,200}$",
                            Description = "Relative paths to request on every endpoint." },
                    Rate,
                ],
            },
            [ScanOperation.TlsProbe] = new()
            {
                Operation = ScanOperation.TlsProbe, Plane = OperationPlane.Agent,
                RequiredCapability = ToolCapabilities.TlsProbe, InputKind = TargetKind.Endpoints,
                Parameters = [Rate],
            },
            [ScanOperation.ExecuteSignatures] = new()
            {
                Operation = ScanOperation.ExecuteSignatures, Plane = OperationPlane.Agent,
                RequiredCapability = ToolCapabilities.SignatureScan, InputKind = TargetKind.Endpoints,
                Parameters =
                [
                    new() { Name = "signatureTags", Type = ParameterType.StringList, Pattern = "^[a-z0-9_-]{1,40}$",
                            Description = "Only approved signatures carrying one of these tags. Empty = all approved active signatures." },
                    new() { Name = "signatureIds", Type = ParameterType.StringList, Pattern = "^[A-Za-z0-9_.-]{1,100}$" },
                    new() { Name = "severities", Type = ParameterType.StringList, AllowedValues = ["info", "low", "medium", "high", "critical"], Default = "info,low" },
                    Rate,
                ],
            },
            [ScanOperation.RecheckMissing] = new()
            {
                // Targets are computed server-side from the previous asset state; jobs run as DiscoverHosts / ScanPorts.
                Operation = ScanOperation.RecheckMissing, Plane = OperationPlane.Agent,
                RequiredCapability = ToolCapabilities.PortScan, InputKind = TargetKind.None,
                Parameters =
                [
                    new() { Name = "attempts", Type = ParameterType.Integer, Min = 1, Max = 5, Default = "2",
                            Description = "Re-check rounds; each round probes only what is still missing." },
                    new() { Name = "delaySeconds", Type = ParameterType.Integer, Min = 0, Max = 3600, Default = "30",
                            Description = "Wait between rounds (lets briefly unreachable hosts come back)." },
                    Rate,
                ],
            },
            [ScanOperation.EvaluateCondition] = new()
            {
                Operation = ScanOperation.EvaluateCondition, Plane = OperationPlane.Server, InputKind = TargetKind.None,
                Parameters = [],
            },
            [ScanOperation.PersistObservations] = new()
            {
                Operation = ScanOperation.PersistObservations, Plane = OperationPlane.Server, InputKind = TargetKind.None,
                Parameters = [],
            },
            [ScanOperation.ComparePreviousScan] = new()
            {
                Operation = ScanOperation.ComparePreviousScan, Plane = OperationPlane.Server, InputKind = TargetKind.None,
                Parameters =
                [
                    new() { Name = "missingThreshold", Type = ParameterType.Integer, Min = 1, Max = 20, Default = "3",
                            Description = "Consecutive complete scans without the service before it is reported as gone." },
                ],
            },
            [ScanOperation.PublishFinding] = new()
            {
                Operation = ScanOperation.PublishFinding, Plane = OperationPlane.Server, InputKind = TargetKind.None,
                Parameters =
                [
                    new() { Name = "destination", Type = ParameterType.Enum, AllowedValues = ["internal", "defectdojo"], Default = "internal" },
                    new() { Name = "minSeverity", Type = ParameterType.Enum, AllowedValues = ["info", "low", "medium", "high", "critical"], Default = "medium" },
                ],
            },
        };

    public static OperationDescriptor Get(ScanOperation operation) => All[operation];

    /// <summary>Whether the (validated) parameter values select a technique that needs raw sockets on the agent.</summary>
    public static bool NeedsRawSockets(ScanOperation operation, IReadOnlyDictionary<string, string> values) =>
        Get(operation).Parameters.Any(p => p.PrivilegedValues is { } privileged && values.TryGetValue(p.Name, out var v)
            && privileged.Contains(v, StringComparer.OrdinalIgnoreCase));
}
