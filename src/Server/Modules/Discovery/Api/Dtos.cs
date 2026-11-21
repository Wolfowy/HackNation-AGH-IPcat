using WebScan.Contracts;
using WebScan.Server.Kernel.Discovery;
using WebScan.Server.Modules.Discovery.Domain;

namespace WebScan.Server.Modules.Discovery.Api;

public sealed record PagedResult<T>(IReadOnlyList<T> Items, int Total, int Page, int PageSize);

public sealed record DashboardSummaryDto(int HostsTotal, int HostsActive, int ServicesTotal, int ChangesLast24h, int FindingsOpen, DateTimeOffset? LastScanAt);

public sealed record AnnotationDto(string? Description, string? Classification, string? BusinessState, string? Owner, IReadOnlyList<string> Tags);

public sealed record HostListItemDto(
    Guid Id, string Address, IReadOnlyList<string> Hostnames, HostStatus Status, bool Unstable, DateTimeOffset FirstSeenAt,
    DateTimeOffset LastSeenAt, DateTimeOffset? LastScannedAt, int OpenPortCount, IReadOnlyList<string> Technologies, string? Zone,
    AnnotationDto? Annotation, IReadOnlyList<string> Classifications);

public sealed record HostDetailDto(
    Guid Id, string Address, IReadOnlyList<string> Hostnames, HostStatus Status, bool Unstable, DateTimeOffset FirstSeenAt,
    DateTimeOffset LastSeenAt, DateTimeOffset? LastScannedAt, int OpenPortCount, string? Zone, AnnotationDto? Annotation,
    IReadOnlyList<string> Classifications, string? MacAddress, string? MacVendor, string? OsGuess, int ConsecutiveMisses, int StateChangeCount,
    IReadOnlyList<ServiceDto> Services, IReadOnlyList<TechnologyDto> Technologies, IReadOnlyList<CertificateDto> Certificates,
    IReadOnlyList<FindingDto> Findings, IReadOnlyList<ChangeDto> RecentChanges);

public sealed record HttpInfoDto(string Url, int? StatusCode, string? Title, string? WebServer);

public sealed record TlsInfoDto(string? SubjectCommonName, string? Issuer, DateTimeOffset? NotAfter, string FingerprintSha256);

public sealed record ServiceDto(
    Guid Id, Guid HostId, string Address, int Port, TransportProtocol Transport, ServiceState State, string? ServiceName, string? Product,
    string? Version, string? Banner, IReadOnlyList<string> Cpe, HttpInfoDto? Http, TlsInfoDto? Tls, IReadOnlyList<string> Technologies,
    double? Confidence, string? ConfidenceMethod, bool TimeOfDayVariance, DateTimeOffset FirstSeenAt, DateTimeOffset LastSeenAt);

public sealed record TechnologyDto(
    Guid Id, string Name, string? Version, string? Category, int? Port, double Confidence, string ConfidenceMethod,
    IReadOnlyList<string> Sources, DateTimeOffset FirstSeenAt, DateTimeOffset LastSeenAt);

public sealed record TechnologySummaryDto(string Name, string? Version, string? Category, int HostCount, int ServiceCount, double Confidence);

public sealed record CertificateDto(
    Guid Id, int Port, string FingerprintSha256, string? SubjectCommonName, IReadOnlyList<string> SubjectAlternativeNames, string? Issuer,
    DateTimeOffset? NotBefore, DateTimeOffset? NotAfter, bool? SelfSigned, string? TlsVersion, DateTimeOffset FirstSeenAt, DateTimeOffset LastSeenAt);

public sealed record ExternalRefDto(string System, string ExternalId);

public sealed record FindingDto(
    Guid Id, string SignatureId, int? SignatureVersion, string Name, string Severity, Guid HostId, string Address, int? Port,
    DateTimeOffset MatchedAt, string? Evidence, FindingStatus Status, DateTimeOffset FirstSeenAt, DateTimeOffset LastSeenAt,
    IReadOnlyList<ExternalRefDto> ExternalRefs, string Source, double Confidence, string ConfidenceMethod, string? MatchedUrl,
    string? ClassificationTag, IReadOnlyList<string> Tags);

public sealed record ChangeDto(
    Guid Id, DateTimeOffset DetectedAt, Guid ScanRunId, AssetChangeType Type, Guid? HostId, string Address, int? Port, string Summary,
    string? Before, string? After, string Severity);

public sealed record ObservationDto(
    long Id, Guid ScanRunId, Guid JobId, Guid BatchId, string AgentId, string? InterfaceName, string? Zone, DateTimeOffset ReceivedAt,
    DiscoveryObservation Observation);

public sealed record AnnotationRequest(string? Description, string? Classification, string? BusinessState, string? Owner, IReadOnlyList<string>? Tags);

public sealed record AssetImportRow(string? Address, string? Description, string? Classification, string? BusinessState, string? Owner, IReadOnlyList<string>? Tags);

public sealed record ImportResult(int Imported, int Updated, IReadOnlyList<string> Errors);

internal static class DtoMapping
{
    public static AnnotationDto? ToDto(this AssetAnnotation? a) =>
        a is null ? null : new AnnotationDto(a.Description, a.Classification, a.BusinessState, a.Owner, a.Tags);

    public static ChangeDto ToDto(this ChangeEvent c) =>
        new(c.Id, c.DetectedAt, c.ScanRunId, c.Type, c.HostId, c.Address, c.Port, c.Summary, c.Before, c.After, c.Severity);

    public static FindingDto ToDto(this SignatureMatch m) =>
        new(m.Id, m.SignatureId, m.SignatureVersion, m.Name, m.Severity, m.HostId, m.Address, m.Port, m.MatchedAt, m.Evidence, m.Status,
            m.FirstSeenAt, m.LastSeenAt, m.ExternalRefs.Select(r => new ExternalRefDto(r.System, r.ExternalId)).ToList(), m.Source,
            m.ConfidenceScore, m.ConfidenceMethod, m.MatchedUrl, m.ClassificationTag, m.Tags);

    public static TechnologyDto ToDto(this Technology t) =>
        new(t.Id, t.Name, t.Version, t.Category, t.Port, t.Confidence, t.ConfidenceMethod, t.Sources, t.FirstSeenAt, t.LastSeenAt);

    public static CertificateDto ToDto(this Certificate c) =>
        new(c.Id, c.Port, c.FingerprintSha256, c.SubjectCommonName, c.SubjectAlternativeNames, c.Issuer, c.NotBefore, c.NotAfter, c.SelfSigned,
            c.TlsVersion, c.FirstSeenAt, c.LastSeenAt);
}
