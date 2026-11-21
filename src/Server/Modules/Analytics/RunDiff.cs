using WebScan.Contracts;
using WebScan.Server.Kernel.Discovery;

namespace WebScan.Server.Modules.Analytics;

/// <param name="Kind">"endpoint" or "technology".</param>
/// <param name="Key">"{kind}|{zone}|{address}|{port}|…" — the zone is part of the asset identity.</param>
/// <param name="Before">Service summary (endpoint) or version (technology) in the baseline run.</param>
public sealed record DiffItem(string Kind, string Key, string Zone, string Address, int? Port, string? Transport, string? Name, string? Before, string? After);

public sealed record RunDiffDto(Guid ScanRunId, Guid BaselineRunId, IReadOnlyList<DiffItem> Added, IReadOnlyList<DiffItem> Removed, IReadOnlyList<DiffItem> Changed);

/// <summary>
/// Diff of two runs computed from their raw (normalized) observations: open endpoints with their best service identification,
/// and technologies with versions. "Changed" requires a value on both sides, so a run that skipped service detection does not
/// report every endpoint as changed.
/// </summary>
public static class RunDiff
{
    private static readonly HashSet<ObservationKind> EndpointKinds =
    [
        ObservationKind.PortOpen, ObservationKind.Service, ObservationKind.HttpResponse, ObservationKind.TlsCertificate,
        ObservationKind.Technology, ObservationKind.SignatureMatch,
    ];

    private sealed record Fact(string Kind, string Key, string Zone, string Address, int? Port, string? Transport, string? Name, string? Value, int Rank);

    public static async Task<RunDiffDto> ComputeAsync(Guid runId, Guid baselineId, IAsyncEnumerable<RunObservation> run,
        IAsyncEnumerable<RunObservation> baseline, CancellationToken ct)
    {
        var current = await FactsAsync(run, ct);
        var previous = await FactsAsync(baseline, ct);
        var added = current.Values.Where(f => !previous.ContainsKey(f.Key)).Select(f => Item(f, null, f.Value));
        var removed = previous.Values.Where(f => !current.ContainsKey(f.Key)).Select(f => Item(f, f.Value, null));
        var changed = current.Values
            .Where(f => previous.TryGetValue(f.Key, out var p) && !string.IsNullOrEmpty(p.Value) && !string.IsNullOrEmpty(f.Value) && p.Value != f.Value)
            .Select(f => Item(f, previous[f.Key].Value, f.Value));
        return new RunDiffDto(runId, baselineId, Sorted(added), Sorted(removed), Sorted(changed));
    }

    private static async Task<Dictionary<string, Fact>> FactsAsync(IAsyncEnumerable<RunObservation> observations, CancellationToken ct)
    {
        var facts = new Dictionary<string, Fact>(StringComparer.Ordinal);
        await foreach (var (zone, o) in observations.WithCancellation(ct))
        {
            if (o.Port is not { } port || !EndpointKinds.Contains(o.Kind)) continue;
            var transport = (o.Transport ?? TransportProtocol.Tcp).ToString().ToLowerInvariant();

            var (summary, rank) = o.Service is { } s
                ? (string.Join(' ', new[] { s.Name, s.Product, s.Version }.Where(x => !string.IsNullOrEmpty(x))),
                    s.Version is not null ? 3 : s.Product is not null ? 2 : 1)
                : (null, 0);
            Keep(facts, new Fact("endpoint", $"endpoint|{zone}|{o.Address}|{port}|{transport}", zone, o.Address, port, transport, o.Service?.Name, summary, rank));

            if (o.Technology is { } t)
                Keep(facts, new Fact("technology", $"technology|{zone}|{o.Address}|{port}|{t.Name.ToLowerInvariant()}", zone, o.Address, port, transport, t.Name,
                    t.Version, t.Version is null ? 0 : 1));
        }
        return facts;
    }

    /// <summary>Keeps the most specific value per key (version beats product beats name); ties keep the first.</summary>
    private static void Keep(Dictionary<string, Fact> facts, Fact fact)
    {
        if (!facts.TryGetValue(fact.Key, out var existing) || fact.Rank > existing.Rank) facts[fact.Key] = fact;
    }

    private static DiffItem Item(Fact f, string? before, string? after) => new(f.Kind, f.Key, f.Zone, f.Address, f.Port, f.Transport, f.Name, before, after);

    private static List<DiffItem> Sorted(IEnumerable<DiffItem> items) => items.OrderBy(i => i.Key, StringComparer.Ordinal).ToList();
}
