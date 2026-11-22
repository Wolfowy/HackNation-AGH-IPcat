using WebScan.Contracts;
using WebScan.Server.Kernel.Discovery;

namespace WebScan.Server.Modules.Discovery.Domain;

public enum HostStatus
{
    Unknown,
    Active,

    /// <summary>Missed by at least one covering scan, but fewer than the "gone" threshold.</summary>
    Unreachable,
    Gone,
}

public enum ServiceState
{
    Open,
    Gone,
}

public enum FindingStatus
{
    Open,
    Resolved,
}

/// <summary>User verdict on a finding, independent of the detection lifecycle (<see cref="FindingStatus"/>).</summary>
public enum FindingTriage
{
    None,
    Confirmed,
    FalsePositive,
    AcceptedRisk,
}

/// <summary>Append-only raw observation (masked, as received) plus normalized lookup columns.</summary>
public sealed class ObservationRecord
{
    public long Id { get; set; }
    public Guid ScanRunId { get; set; }
    public Guid JobId { get; set; }
    public Guid BatchId { get; set; }
    public required string ObservationId { get; set; }
    public required string AgentId { get; set; }
    public string? InterfaceName { get; set; }

    /// <summary>Zone of the scanned network ("" = default zone); with <see cref="Address"/> it identifies the host.</summary>
    public string Zone { get; set; } = "";

    public string? WorkflowStepId { get; set; }
    public ScanOperation Operation { get; set; }
    public ObservationKind Kind { get; set; }

    /// <summary>Canonical address (see <c>Normalizer.CanonicalAddress</c>).</summary>
    public required string Address { get; set; }

    public int? Port { get; set; }
    public TransportProtocol? Transport { get; set; }
    public DateTimeOffset ObservedAt { get; set; }
    public DateTimeOffset ReceivedAt { get; set; }

    /// <summary><see cref="DiscoveryObservation"/> JSON (wire format); encrypted at rest, so never query inside it in SQL.</summary>
    public required string Payload { get; set; }
}

/// <summary>Idempotency record per result batch.</summary>
public sealed class ProcessedBatch
{
    public Guid BatchId { get; set; }
    public Guid JobId { get; set; }
    public Guid ScanRunId { get; set; }
    public int Sequence { get; set; }
    public int ObservationsReceived { get; set; }
    public int ObservationsAccepted { get; set; }
    public DateTimeOffset ProcessedAt { get; set; }
}

/// <summary>Coverage stored by PersistObservations and consumed (once) by ComparePreviousScan.</summary>
public sealed class RunProcessing
{
    public Guid ScanRunId { get; set; }
    public bool CoverageComplete { get; set; }
    public List<string> CoveredHosts { get; set; } = [];
    public List<string> CoveredEndpoints { get; set; } = [];

    /// <summary>JSON {zone: {hosts: [...], endpoints: [...]}}; null = the flat lists cover all zones.</summary>
    public string? CoverageByZone { get; set; }

    public List<string> OperationsExecuted { get; set; } = [];
    public DateTimeOffset? PersistedAt { get; set; }
    public DateTimeOffset? ComparedAt { get; set; }
    public int? ChangesDetected { get; set; }

    /// <summary>JSON object {changeType: count} of the comparison.</summary>
    public string? ChangesByType { get; set; }
}

/// <summary>Current state of a machine, identified by (<see cref="Zone"/>, <see cref="Address"/>): the same IP in two zones is two hosts.</summary>
public sealed class Host
{
    public Guid Id { get; set; }
    public required string Address { get; set; }
    public List<string> Hostnames { get; set; } = [];
    public HostStatus Status { get; set; }
    public bool Unstable { get; set; }

    /// <summary>Zone of the scanned network; "" = default zone.</summary>
    public string Zone { get; set; } = "";

    /// <summary>Latest MAC (AA:BB:CC:DD:EE:FF) — attribute only, never identity (randomized MACs, only visible on the same L2 segment).</summary>
    public string? MacAddress { get; set; }

    public string? MacVendor { get; set; }
    public string? OsGuess { get; set; }
    public DateTimeOffset FirstSeenAt { get; set; }
    public DateTimeOffset LastSeenAt { get; set; }
    public DateTimeOffset? LastScannedAt { get; set; }
    public Guid FirstSeenRunId { get; set; }
    public Guid LastSeenRunId { get; set; }
    public int ConsecutiveMisses { get; set; }

    /// <summary>Total up↔down transitions observed by covering scans.</summary>
    public int StateChangeCount { get; set; }

    /// <summary>Last covering outcomes, oldest first: 'U' seen, 'D' missed (max <see cref="StateHistoryLength"/>).</summary>
    public string StateHistory { get; set; } = "";

    /// <summary>Covering outcomes per UTC hour of day (index = hour, 24 entries once compared): times seen.</summary>
    public List<int> HourlySeen { get; set; } = [];

    /// <summary>Covering outcomes per UTC hour of day: times missed (with <see cref="HourlySeen"/> = time-of-day availability).</summary>
    public List<int> HourlyMissed { get; set; } = [];

    /// <summary>Null until the host took part in a comparison (→ the next comparison reports it as new).</summary>
    public DateTimeOffset? ComparedAt { get; set; }

    public const int StateHistoryLength = 10;
}

public sealed class Service
{
    public Guid Id { get; set; }
    public Guid HostId { get; set; }

    /// <summary>Zone of the host (denormalized like <see cref="Address"/>).</summary>
    public string Zone { get; set; } = "";

    public required string Address { get; set; }
    public int Port { get; set; }
    public TransportProtocol Transport { get; set; }
    public ServiceState State { get; set; }

    public string? ServiceName { get; set; }
    public string? Product { get; set; }
    public string? Version { get; set; }
    public string? ExtraInfo { get; set; }
    public string? Banner { get; set; }
    public string? Tunnel { get; set; }
    public List<string> Cpe { get; set; } = [];
    public double? Confidence { get; set; }
    public string? ConfidenceMethod { get; set; }

    /// <summary>Run whose observations produced the current service attributes.</summary>
    public Guid? AttributesRunId { get; set; }

    public string? HttpUrl { get; set; }
    public int? HttpStatusCode { get; set; }
    public string? HttpTitle { get; set; }
    public string? HttpWebServer { get; set; }
    public DateTimeOffset? HttpObservedAt { get; set; }

    /// <summary>Latest <see cref="Contracts.HttpDetails"/> as JSON (headers masked, cookies without values).</summary>
    public string? HttpDetailsJson { get; set; }

    public string? CurrentCertFingerprint { get; set; }
    public DateTimeOffset? TlsObservedAt { get; set; }

    /// <summary>Device classification from recog fingerprints, e.g. "IP Camera", "Printer", "Router".</summary>
    public string? DeviceType { get; set; }

    public string? DeviceVendor { get; set; }
    public string? DeviceProduct { get; set; }

    /// <summary>Interesting headers, cookies, pages... of the latest run that fingerprinted the service (<see cref="FingerprintRunId"/>).</summary>
    public List<ServiceArtifact> Artifacts { get; set; } = [];

    public Guid? FingerprintRunId { get; set; }

    /// <summary>Responses of this endpoint differ consistently by hour of day.</summary>
    public bool TimeOfDayVariance { get; set; }

    public DateTimeOffset FirstSeenAt { get; set; }
    public DateTimeOffset LastSeenAt { get; set; }
    public Guid FirstSeenRunId { get; set; }
    public Guid LastSeenRunId { get; set; }
    public int ConsecutiveMisses { get; set; }

    // Baseline as of the last comparison (live attributes above may already be newer).
    public DateTimeOffset? ComparedAt { get; set; }
    public string? ComparedServiceName { get; set; }
    public string? ComparedSummary { get; set; }
    public string? ComparedCertFingerprint { get; set; }
}

/// <summary>Interesting HTTP artifact of a service (see <c>HttpArtifacts</c>).</summary>
public sealed class ServiceArtifact
{
    /// <summary>"header", "cookie", "page", "favicon" or "cert".</summary>
    public required string Kind { get; set; }

    public required string Name { get; set; }

    /// <summary>Short, masked and truncated value.</summary>
    public string? Value { get; set; }

    public required string Reason { get; set; }

    /// <summary>e.g. "tech-hint", "version-leak", "internal-ip-leak", "debug", "insecure-cookie", "login-page".</summary>
    public List<string> Tags { get; set; } = [];

    /// <summary>"info" or "low".</summary>
    public string Severity { get; set; } = "info";
}

public sealed class TechnologyEvidence
{
    public required string Method { get; set; }
    public double Score { get; set; }
}

public sealed class Technology
{
    public Guid Id { get; set; }
    public Guid HostId { get; set; }
    public Guid? ServiceId { get; set; }
    public required string Address { get; set; }

    /// <summary>Null for host-level technologies (e.g. OS).</summary>
    public int? Port { get; set; }

    public required string Name { get; set; }

    /// <summary>Lowercase canonical name (uniqueness key).</summary>
    public required string NameKey { get; set; }

    public string? Version { get; set; }
    public double VersionScore { get; set; }
    public string? Category { get; set; }
    public double Confidence { get; set; }
    public required string ConfidenceMethod { get; set; }

    /// <summary>Best score per confidence method within the last run that saw the technology.</summary>
    public List<TechnologyEvidence> Evidence { get; set; } = [];

    /// <summary>Tool ids / rule ids ("rule-id@v2") that reported the technology.</summary>
    public List<string> Sources { get; set; } = [];

    public DateTimeOffset FirstSeenAt { get; set; }
    public DateTimeOffset LastSeenAt { get; set; }
    public Guid LastSeenRunId { get; set; }
    public DateTimeOffset? ComparedAt { get; set; }
    public string? ComparedVersion { get; set; }
}

public sealed class Certificate
{
    public Guid Id { get; set; }
    public Guid HostId { get; set; }
    public Guid ServiceId { get; set; }
    public required string Address { get; set; }
    public int Port { get; set; }
    public required string FingerprintSha256 { get; set; }
    public string? SubjectCommonName { get; set; }
    public List<string> SubjectAlternativeNames { get; set; } = [];
    public string? Issuer { get; set; }
    public DateTimeOffset? NotBefore { get; set; }
    public DateTimeOffset? NotAfter { get; set; }
    public string? SerialNumber { get; set; }
    public bool? SelfSigned { get; set; }
    public string? TlsVersion { get; set; }
    public DateTimeOffset FirstSeenAt { get; set; }
    public DateTimeOffset LastSeenAt { get; set; }
}

/// <summary>Distinct material HTTP response of an endpoint path within one hour-of-day bucket (UTC).</summary>
public sealed class HttpSnapshot
{
    public Guid Id { get; set; }
    public Guid HostId { get; set; }
    public Guid ServiceId { get; set; }

    /// <summary>Path and query of the requested URL.</summary>
    public required string Path { get; set; }

    public int HourBucket { get; set; }

    /// <summary>SHA-256 over the material fields (status, title, server, favicon hash).</summary>
    public required string Fingerprint { get; set; }

    public int? StatusCode { get; set; }
    public string? Title { get; set; }
    public string? WebServer { get; set; }
    public string? BodySha256 { get; set; }
    public string? FaviconHash { get; set; }
    public int ObservationCount { get; set; }
    public DateTimeOffset FirstSeenAt { get; set; }
    public DateTimeOffset LastSeenAt { get; set; }
    public Guid FirstScanRunId { get; set; }
    public Guid LastScanRunId { get; set; }
}

public sealed class ExternalRefEntry
{
    public required string System { get; set; }
    public required string ExternalId { get; set; }
    public string? ContentHash { get; set; }
    public DateTimeOffset? ExportedAt { get; set; }
}

/// <summary>Signature result (Nuclei detection or classification rule) on a host/endpoint — a "finding".</summary>
public sealed class SignatureMatch
{
    public const string ClassificationSource = "classification-rule";

    /// <summary>High-signal HTTP artifact (debug header, internal IP leak, login/admin page) raised as an info/low finding.</summary>
    public const string ArtifactSource = "artifact";

    public Guid Id { get; set; }
    public Guid HostId { get; set; }
    public Guid? ServiceId { get; set; }

    /// <summary>Zone of the host (denormalized like <see cref="Address"/>).</summary>
    public string Zone { get; set; } = "";

    public required string Address { get; set; }
    public string? Hostname { get; set; }
    public int? Port { get; set; }
    public TransportProtocol? Transport { get; set; }
    public required string SignatureId { get; set; }
    public int? SignatureVersion { get; set; }
    public required string Name { get; set; }
    public required string Severity { get; set; }

    /// <summary>Tool id that executed the signature, or <see cref="ClassificationSource"/>.</summary>
    public required string Source { get; set; }

    public string? MatcherName { get; set; }
    public string? MatchedUrl { get; set; }
    public string? Evidence { get; set; }
    public List<string> Tags { get; set; } = [];
    public string? ClassificationTag { get; set; }
    public double ConfidenceScore { get; set; }
    public required string ConfidenceMethod { get; set; }

    /// <summary>Detection time of the latest match.</summary>
    public DateTimeOffset MatchedAt { get; set; }

    public DateTimeOffset FirstSeenAt { get; set; }
    public DateTimeOffset LastSeenAt { get; set; }
    public Guid LastSeenRunId { get; set; }
    public FindingStatus Status { get; set; }
    public int ConsecutiveMisses { get; set; }
    public DateTimeOffset? ResolvedAt { get; set; }
    public DateTimeOffset? PublishedAt { get; set; }
    public List<ExternalRefEntry> ExternalRefs { get; set; } = [];

    // User triage: never written by ingestion or change detection, so it survives re-detection of the same finding.
    public FindingTriage Triage { get; set; }

    /// <summary>User-set severity; <see cref="EffectiveSeverity"/> = override ?? detected <see cref="Severity"/>.</summary>
    public string? SeverityOverride { get; set; }

    public string? Notes { get; set; }
    public List<string> UserTags { get; set; } = [];
    public string? TriagedBy { get; set; }
    public DateTimeOffset? TriagedAt { get; set; }

    public string EffectiveSeverity => SeverityOverride ?? Severity;
}

public sealed class ChangeEvent
{
    public Guid Id { get; set; }
    public DateTimeOffset DetectedAt { get; set; }
    public Guid ScanRunId { get; set; }
    public AssetChangeType Type { get; set; }
    public Guid? HostId { get; set; }
    public string Zone { get; set; } = "";
    public required string Address { get; set; }
    public int? Port { get; set; }
    public required string Summary { get; set; }
    public string? Before { get; set; }
    public string? After { get; set; }
    public required string Severity { get; set; }

    /// <summary>Change rules ("id@vN") that raised the severity.</summary>
    public List<string> RaisedBy { get; set; } = [];
}

/// <summary>User-maintained context per (zone, address). Never touched by scans; joined to hosts by (zone, address).</summary>
public sealed class AssetAnnotation
{
    public string Zone { get; set; } = "";
    public required string Address { get; set; }
    public string? Description { get; set; }
    public string? Classification { get; set; }
    public string? BusinessState { get; set; }
    public string? Owner { get; set; }
    public List<string> Tags { get; set; } = [];
    public DateTimeOffset UpdatedAt { get; set; }
    public string? UpdatedBy { get; set; }
}

/// <summary>User-maintained context per endpoint (zone, address, port, transport). Never touched by scans; joined to services by that key.</summary>
public sealed class ServiceAnnotation
{
    public string Zone { get; set; } = "";
    public required string Address { get; set; }
    public int Port { get; set; }
    public TransportProtocol Transport { get; set; }
    public string? Notes { get; set; }
    public List<string> Tags { get; set; } = [];

    /// <summary>low | medium | high | critical.</summary>
    public string? Criticality { get; set; }

    public string? Owner { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public string? UpdatedBy { get; set; }
}

/// <summary>Every saved revision of an annotation.</summary>
public sealed class AssetAnnotationRevision
{
    public long Id { get; set; }
    public string Zone { get; set; } = "";
    public required string Address { get; set; }
    public string? Description { get; set; }
    public string? Classification { get; set; }
    public string? BusinessState { get; set; }
    public string? Owner { get; set; }
    public List<string> Tags { get; set; } = [];
    public DateTimeOffset ChangedAt { get; set; }
    public string? ChangedBy { get; set; }

    /// <summary>"api" or "import".</summary>
    public required string Source { get; set; }
}
