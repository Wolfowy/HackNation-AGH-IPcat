using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WebScan.Contracts;
using WebScan.Server.Kernel.Discovery;
using WebScan.Server.Modules.Discovery.Domain;
using WebScan.Server.Modules.Discovery.Normalization;
using WebScan.Server.Modules.Discovery.Persistence;

namespace WebScan.Server.Modules.Discovery;

internal sealed class ObservationReader(DiscoveryDbContext db) : IObservationReader
{
    public async IAsyncEnumerable<DiscoveryObservation> ReadRunObservationsAsync(Guid scanRunId, [EnumeratorCancellation] CancellationToken ct = default)
    {
        var payloads = db.Observations.AsNoTracking().Where(o => o.ScanRunId == scanRunId).OrderBy(o => o.Id).Select(o => o.Payload).AsAsyncEnumerable();
        await foreach (var payload in payloads.WithCancellation(ct))
            if (JsonSerializer.Deserialize<DiscoveryObservation>(payload, ContractJson.Options) is { } raw && Normalizer.Normalize(raw) is { } o)
                yield return o;
    }
}

internal sealed class FindingStore(DiscoveryDbContext db, TimeProvider time) : IFindingStore
{
    public async Task<IReadOnlyList<FindingRecord>> GetByIdsAsync(IReadOnlyCollection<Guid> findingIds, CancellationToken ct = default) =>
        (await db.SignatureMatches.AsNoTracking().Where(m => findingIds.Contains(m.Id)).ToListAsync(ct)).Select(ToRecord).ToList();

    public async Task<IReadOnlyList<FindingRecord>> GetRunFindingsAsync(Guid scanRunId, CancellationToken ct = default) =>
        (await db.SignatureMatches.AsNoTracking().Where(m => m.LastSeenRunId == scanRunId && m.Status == FindingStatus.Open)
            .OrderBy(m => m.Id).ToListAsync(ct)).Select(ToRecord).ToList();

    public async Task SetExternalRefAsync(Guid findingId, FindingExternalRef externalRef, CancellationToken ct = default)
    {
        var match = await db.SignatureMatches.FirstOrDefaultAsync(m => m.Id == findingId, ct)
                    ?? throw new KeyNotFoundException($"Finding {findingId} not found.");
        match.ExternalRefs =
        [
            .. match.ExternalRefs.Where(r => r.System != externalRef.System).Select(r => new ExternalRefEntry
                { System = r.System, ExternalId = r.ExternalId, ContentHash = r.ContentHash, ExportedAt = r.ExportedAt }),
            new ExternalRefEntry
            {
                System = externalRef.System, ExternalId = externalRef.ExternalId, ContentHash = externalRef.ContentHash,
                ExportedAt = externalRef.ExportedAt ?? time.GetUtcNow(),
            },
        ];
        await db.SaveChangesAsync(ct);
    }

    public async Task<int> MarkPublishedAsync(IReadOnlyCollection<Guid> findingIds, CancellationToken ct = default) =>
        await db.SignatureMatches.Where(m => findingIds.Contains(m.Id) && m.PublishedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(m => m.PublishedAt, time.GetUtcNow()), ct);

    private static FindingRecord ToRecord(SignatureMatch m) => new()
    {
        Id = m.Id, SignatureId = m.SignatureId, SignatureVersion = m.SignatureVersion, Name = m.Name, Severity = m.Severity, Address = m.Address,
        Hostname = m.Hostname, Port = m.Port, Transport = m.Transport?.ToString().ToLowerInvariant(), MatchedAt = m.MatchedAt,
        FirstSeenAt = m.FirstSeenAt, MatchedUrl = m.MatchedUrl, Evidence = m.Evidence, Source = m.Source, ConfidenceScore = m.ConfidenceScore,
        ConfidenceMethod = m.ConfidenceMethod, Status = m.Status.ToString(), Tags = m.Tags, PublishedAt = m.PublishedAt,
        ExternalRefs = m.ExternalRefs.Select(r => new FindingExternalRef(r.System, r.ExternalId, r.ContentHash, r.ExportedAt)).ToList(),
    };
}
