using System.Net;
using System.Text.Json;
using WebScan.Contracts;
using WebScan.Server.Kernel.Networking;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Modules.Discovery.Domain;
using WebScan.Server.Modules.Discovery.Normalization;

namespace WebScan.Server.Modules.Discovery.Processing;

/// <summary>
/// What a run verifiably scanned. Absence of evidence counts as a "miss" only for targets inside the coverage of a
/// complete run that executed the relevant operation. Coverage is zone-qualified: a host is covered only by entries of its
/// own zone (the same IP in another zone is another machine); runs without zone information cover all zones.
/// </summary>
internal sealed class CoverageSet
{
    private sealed record Scope(IpRangeSet Ranges, HashSet<string> Hostnames, HashSet<string> Endpoints)
    {
        public bool CoversHost(string address) => IPAddress.TryParse(address, out var ip) ? Ranges.Contains(ip) : Hostnames.Contains(address);
    }

    /// <summary>Stored shape of <see cref="RunProcessing.CoverageByZone"/>.</summary>
    private sealed record ZoneEntries(List<string> Hosts, List<string> Endpoints);

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly Scope? _all;
    private readonly Dictionary<string, Scope> _byZone;
    private readonly HashSet<ScanOperation> _operations;

    private CoverageSet(bool complete, Scope? all, Dictionary<string, Scope> byZone, HashSet<ScanOperation> operations)
    {
        Complete = complete;
        _all = all;
        _byZone = byZone;
        _operations = operations;
    }

    public bool Complete { get; }

    public static CoverageSet None { get; } = new(false, null, [], []);

    public static CoverageSet From(RunProcessing run)
    {
        var operations = run.OperationsExecuted.Select(o => Enum.TryParse<ScanOperation>(o, out var op) ? op : (ScanOperation?)null)
            .OfType<ScanOperation>().ToHashSet();
        var zones = run.CoverageByZone is { } json ? JsonSerializer.Deserialize<Dictionary<string, ZoneEntries>>(json, Json) : null;
        return zones is null
            ? new CoverageSet(run.CoverageComplete, Parse(run.CoveredHosts, run.CoveredEndpoints), [], operations)
            : new CoverageSet(run.CoverageComplete, null,
                zones.ToDictionary(z => z.Key, z => Parse(z.Value.Hosts, z.Value.Endpoints), StringComparer.Ordinal), operations);
    }

    /// <summary>JSON for <see cref="RunProcessing.CoverageByZone"/>; null when the coverage carries no zone information.</summary>
    public static string? SerializeZones(RunCoverage coverage)
    {
        if (coverage.CoveredHostsByZone is null && coverage.CoveredEndpointsByZone is null) return null;
        var zones = new Dictionary<string, ZoneEntries>(StringComparer.Ordinal);
        ZoneEntries Entry(string raw)
        {
            var zone = Normalizer.CanonicalZone(raw);
            return zones.TryGetValue(zone, out var e) ? e : zones[zone] = new ZoneEntries([], []);
        }
        foreach (var (zone, hosts) in coverage.CoveredHostsByZone ?? new Dictionary<string, IReadOnlyList<string>>()) Entry(zone).Hosts.AddRange(hosts);
        foreach (var (zone, endpoints) in coverage.CoveredEndpointsByZone ?? new Dictionary<string, IReadOnlyList<string>>())
            Entry(zone).Endpoints.AddRange(endpoints);
        return JsonSerializer.Serialize(zones, Json);
    }

    private static Scope Parse(IEnumerable<string> hosts, IEnumerable<string> endpoints)
    {
        var ranges = new List<IpRange>();
        var hostnames = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in hosts)
        {
            if (IpRangeSet.TryParseRange(entry, out var range)) ranges.Add(range);
            else if (Normalizer.CanonicalHostname(entry) is { } name) hostnames.Add(name);
        }
        return new Scope(IpRangeSet.FromRanges(ranges), hostnames, endpoints.Select(NormalizeEndpoint).OfType<string>().ToHashSet(StringComparer.Ordinal));
    }

    private Scope? ScopeOf(string zone) => _all ?? _byZone.GetValueOrDefault(zone);

    public bool Executed(ScanOperation operation) => _operations.Contains(operation);

    public bool CoversHost(string zone, string address) => ScopeOf(zone)?.CoversHost(address) == true;

    public bool CoversEndpoint(string zone, string address, int port) =>
        ScopeOf(zone) is { } scope && (scope.CoversHost(address) || scope.Endpoints.Contains($"{address}:{port}"));

    /// <summary>A missing host/port in this run is meaningful evidence.</summary>
    public bool CanCountMiss(string zone, string address, ScanOperation operation) => Complete && Executed(operation) && CoversHost(zone, address);

    /// <summary>"addr:port" / "[v6]:port" → canonical "addr:port".</summary>
    private static string? NormalizeEndpoint(string entry)
    {
        var colon = entry.LastIndexOf(':');
        if (colon <= 0 || !int.TryParse(entry[(colon + 1)..], out var port)) return null;
        return Normalizer.CanonicalAddress(entry[..colon]) is { } address ? $"{address}:{port}" : null;
    }
}
