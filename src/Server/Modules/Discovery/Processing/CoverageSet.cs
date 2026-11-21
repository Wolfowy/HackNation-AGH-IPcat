using System.Net;
using WebScan.Contracts;
using WebScan.Server.Kernel.Networking;
using WebScan.Server.Modules.Discovery.Domain;
using WebScan.Server.Modules.Discovery.Normalization;

namespace WebScan.Server.Modules.Discovery.Processing;

/// <summary>
/// What a run verifiably scanned. Absence of evidence counts as a "miss" only for targets inside the coverage of a
/// complete run that executed the relevant operation.
/// </summary>
internal sealed class CoverageSet
{
    private readonly IpRangeSet _ranges;
    private readonly HashSet<string> _hostnames;
    private readonly HashSet<string> _endpoints;
    private readonly HashSet<ScanOperation> _operations;

    private CoverageSet(bool complete, IpRangeSet ranges, HashSet<string> hostnames, HashSet<string> endpoints, HashSet<ScanOperation> operations)
    {
        Complete = complete;
        _ranges = ranges;
        _hostnames = hostnames;
        _endpoints = endpoints;
        _operations = operations;
    }

    public bool Complete { get; }

    public static CoverageSet None { get; } = new(false, new IpRangeSet(), [], [], []);

    public static CoverageSet From(RunProcessing run)
    {
        var ranges = new List<IpRange>();
        var hostnames = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in run.CoveredHosts)
        {
            if (IpRangeSet.TryParseRange(entry, out var range)) ranges.Add(range);
            else if (Normalizer.CanonicalHostname(entry) is { } name) hostnames.Add(name);
        }

        var endpoints = run.CoveredEndpoints.Select(NormalizeEndpoint).OfType<string>().ToHashSet(StringComparer.Ordinal);
        var operations = run.OperationsExecuted.Select(o => Enum.TryParse<ScanOperation>(o, out var op) ? op : (ScanOperation?)null)
            .OfType<ScanOperation>().ToHashSet();
        return new CoverageSet(run.CoverageComplete, IpRangeSet.FromRanges(ranges), hostnames, endpoints, operations);
    }

    public bool Executed(ScanOperation operation) => _operations.Contains(operation);

    public bool CoversHost(string address) =>
        IPAddress.TryParse(address, out var ip) ? _ranges.Contains(ip) : _hostnames.Contains(address);

    public bool CoversEndpoint(string address, int port) => CoversHost(address) || _endpoints.Contains($"{address}:{port}");

    /// <summary>A missing host/port in this run is meaningful evidence.</summary>
    public bool CanCountMiss(string address, ScanOperation operation) => Complete && Executed(operation) && CoversHost(address);

    /// <summary>"addr:port" / "[v6]:port" → canonical "addr:port".</summary>
    private static string? NormalizeEndpoint(string entry)
    {
        var colon = entry.LastIndexOf(':');
        if (colon <= 0 || !int.TryParse(entry[(colon + 1)..], out var port)) return null;
        return Normalizer.CanonicalAddress(entry[..colon]) is { } address ? $"{address}:{port}" : null;
    }
}
