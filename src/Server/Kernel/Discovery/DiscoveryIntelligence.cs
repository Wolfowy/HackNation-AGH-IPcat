using WebScan.Contracts;

namespace WebScan.Server.Kernel.Discovery;

// Ports between the stream-D modules (Signatures → Discovery, Discovery → Analytics/Integrations).
// Added by stream D; consumers depend only on these, never on another module's DbContext.

/// <summary>Types of asset change events emitted by ComparePreviousScan.</summary>
public enum AssetChangeType
{
    NewHost,
    HostReappeared,
    HostGone,
    NewPort,
    PortGone,
    NewService,
    ServiceChanged,
    TechnologyChanged,
    TlsCertificateChanged,
    HttpResponseChanged,
    TimeOfDayVariance,
}

/// <summary>Severity scale shared by signatures, findings and change events ("info" &lt; "low" &lt; ... &lt; "critical").</summary>
public static class Severities
{
    public static readonly IReadOnlyList<string> All = ["info", "low", "medium", "high", "critical"];

    /// <summary>0 (info) … 4 (critical); unknown values rank as info.</summary>
    public static int Rank(string? severity) => Math.Max(0, IndexOf(severity));

    public static bool IsValid(string? severity) => IndexOf(severity) >= 0;

    public static string Max(string a, string b) => Rank(a) >= Rank(b) ? a : b;

    private static int IndexOf(string? severity)
    {
        for (var i = 0; i < All.Count; i++)
            if (string.Equals(All[i], severity?.Trim(), StringComparison.OrdinalIgnoreCase)) return i;
        return -1;
    }
}

/// <summary>Approved interpretation (classification) and historical (change) rules. Implemented by the Signatures module.</summary>
public interface IInterpretationRuleProvider
{
    Task<IReadOnlyList<ClassificationRule>> GetApprovedClassificationRulesAsync(CancellationToken ct = default);
    Task<IReadOnlyList<ChangeRule>> GetApprovedChangeRulesAsync(CancellationToken ct = default);

    /// <summary>Currently approved version per signature id (unknown/unapproved ids are absent). Used to complete agent results without a version.</summary>
    Task<IReadOnlyDictionary<string, int>> GetApprovedVersionsAsync(IReadOnlyCollection<string> signatureIds, CancellationToken ct = default);
}

/// <summary>"When an observation satisfies <see cref="When"/>, conclude <see cref="Outcome"/>."</summary>
public sealed record ClassificationRule(string SignatureId, int Version, string Name, ConditionExpression When, ClassificationOutcome Outcome);

/// <param name="TechnologyVersionField">Optional observation field (from <see cref="ConditionFields"/>) whose value becomes the technology version.</param>
/// <param name="Confidence">0–1 score of this interpretation.</param>
public sealed record ClassificationOutcome(
    string? TechnologyName,
    string? TechnologyVersion,
    string? TechnologyVersionField,
    string? TechnologyCategory,
    string? ClassificationTag,
    double Confidence);

/// <summary>Raises the severity of change events of <see cref="ChangeTypes"/> matching <see cref="When"/> (fields: address, port, transport, service.*, technology.*).</summary>
public sealed record ChangeRule(string SignatureId, int Version, string Name, IReadOnlyList<AssetChangeType> ChangeTypes, ConditionExpression? When, string Severity);

/// <summary>Read access to the append-only observation store (Discovery module).</summary>
public interface IObservationReader
{
    /// <summary>All observations of a scan run, already normalized (canonical addresses, service and technology names).</summary>
    IAsyncEnumerable<DiscoveryObservation> ReadRunObservationsAsync(Guid scanRunId, CancellationToken ct = default);
}

/// <summary>Signature-match findings (Discovery module) for publishing/export (Integrations module).</summary>
public interface IFindingStore
{
    Task<IReadOnlyList<FindingRecord>> GetByIdsAsync(IReadOnlyCollection<Guid> findingIds, CancellationToken ct = default);

    /// <summary>Open findings (re)observed in the given scan run.</summary>
    Task<IReadOnlyList<FindingRecord>> GetRunFindingsAsync(Guid scanRunId, CancellationToken ct = default);

    /// <summary>Stores (or replaces) the external reference of a finding in <paramref name="system"/>.</summary>
    Task SetExternalRefAsync(Guid findingId, FindingExternalRef externalRef, CancellationToken ct = default);

    /// <summary>Marks findings as published internally; returns how many were newly marked.</summary>
    Task<int> MarkPublishedAsync(IReadOnlyCollection<Guid> findingIds, CancellationToken ct = default);
}

public sealed record FindingRecord
{
    public required Guid Id { get; init; }
    public required string SignatureId { get; init; }
    public int? SignatureVersion { get; init; }
    public required string Name { get; init; }
    public required string Severity { get; init; }
    public required string Address { get; init; }
    public string? Hostname { get; init; }
    public int? Port { get; init; }
    public string? Transport { get; init; }
    public required DateTimeOffset MatchedAt { get; init; }
    public required DateTimeOffset FirstSeenAt { get; init; }
    public string? MatchedUrl { get; init; }
    public string? Evidence { get; init; }

    /// <summary>Tool id ("nuclei", ...) or "classification-rule".</summary>
    public required string Source { get; init; }

    public required double ConfidenceScore { get; init; }
    public required string ConfidenceMethod { get; init; }
    public required string Status { get; init; }
    public IReadOnlyList<string> Tags { get; init; } = [];
    public DateTimeOffset? PublishedAt { get; init; }
    public IReadOnlyList<FindingExternalRef> ExternalRefs { get; init; } = [];
}

/// <param name="ContentHash">Hash of the exported content; re-export is skipped while it is unchanged.</param>
public sealed record FindingExternalRef(string System, string ExternalId, string? ContentHash = null, DateTimeOffset? ExportedAt = null);
