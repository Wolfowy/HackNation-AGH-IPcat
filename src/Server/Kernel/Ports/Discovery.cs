using WebScan.Contracts;

namespace WebScan.Server.Kernel.Ports;

/// <summary>Context of a result batch accepted by the Scanning module.</summary>
public sealed record IngestContext
{
    public required Guid ScanRunId { get; init; }
    public required Guid JobId { get; init; }
    public string? WorkflowStepId { get; init; }
    public required ScanOperation Operation { get; init; }
    public required string AgentId { get; init; }
    public string? InterfaceName { get; init; }

    /// <summary>Zone of the network the job targets belong to.</summary>
    public string? Zone { get; init; }

    public IReadOnlyList<Guid> NetworkIds { get; init; } = [];
}

/// <summary>
/// Normalizes and persists observations (Discovery module). Idempotent per <see cref="ScanResultBatch.BatchId"/>.
/// Normally invoked by a Wolverine handler for <c>ScanResultBatchReceived</c>.
/// </summary>
public interface IObservationSink
{
    Task IngestAsync(IngestContext context, ScanResultBatch batch, CancellationToken ct = default);
}

/// <summary>Coverage of a whole scan run: what was scanned completely, from which perspective.</summary>
public sealed record RunCoverage
{
    /// <summary>Host entries (IP/CIDR) whose jobs completed with full coverage.</summary>
    public required IReadOnlyList<string> CoveredHosts { get; init; }

    /// <summary>Endpoints ("addr:port") whose jobs completed with full coverage.</summary>
    public IReadOnlyList<string> CoveredEndpoints { get; init; } = [];

    /// <summary>True when the run finished without window expiry, cancellation or failed jobs.</summary>
    public required bool Complete { get; init; }

    /// <summary>Operations that were executed (e.g. ScanPorts) — absence of a port is meaningful only if ScanPorts ran.</summary>
    public required IReadOnlyList<ScanOperation> OperationsExecuted { get; init; }
}

/// <summary>Server-side workflow operations implemented by the Discovery/Analytics modules.</summary>
public interface IDiscoveryRunProcessor
{
    /// <summary>PersistObservations: waits for pending ingestion of the run, applies interpretation rules, updates current asset state.</summary>
    Task<PersistRunResult> PersistRunAsync(Guid scanRunId, RunCoverage coverage, CancellationToken ct = default);

    /// <summary>ComparePreviousScan: diffs against history, emits change events (new/changed/gone/reappeared).</summary>
    Task<CompareRunResult> CompareWithPreviousAsync(Guid scanRunId, int missingThreshold, CancellationToken ct = default);
}

public sealed record PersistRunResult(int HostsUpdated, int ServicesUpdated, int ObservationsTotal);

public sealed record CompareRunResult(int ChangesDetected, IReadOnlyDictionary<string, int> ChangesByType);

/// <summary>PublishFinding: exports selected findings (Integrations module). Never exports plain open ports as vulnerabilities.</summary>
public interface IFindingPublisher
{
    Task<PublishFindingsResult> PublishAsync(Guid scanRunId, string destination, string minSeverity, CancellationToken ct = default);
}

public sealed record PublishFindingsResult(int Published, int Skipped);

/// <summary>Approved active-detection signatures (Signatures module).</summary>
public interface ISignatureCatalog
{
    /// <summary>Builds the bundle of approved, active signatures filtered by ids/tags/severities. Empty bundle if none match.</summary>
    Task<SignatureBundle> GetApprovedBundleAsync(IReadOnlyCollection<string> signatureIds, IReadOnlyCollection<string> tags,
        IReadOnlyCollection<string> severities, CancellationToken ct = default);
}
