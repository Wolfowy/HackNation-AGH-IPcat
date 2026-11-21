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

    /// <summary>Anchored regex for String/StringList items.</summary>
    public string? Pattern { get; init; }
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
                            Description = "Probe technique. 'none' treats every target as up (useful behind ICMP filtering)." },
                    new() { Name = "probePorts", Type = ParameterType.PortSpec, Default = "22,80,443,3389,8080", Description = "Ports used for TCP discovery probes. " + PortSpecHelp },
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
                    new() { Name = "scanType", Type = ParameterType.Enum, AllowedValues = ["connect", "syn"], Default = "connect" },
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
}
