using System.Net;
using WebScan.Contracts;
using WebScan.Server.Kernel.Networking;
using WebScan.Server.Modules.Scanning.Planning;

namespace WebScan.Server.Modules.Scanning.Jobs;

/// <summary>Server-side defence in depth for result batches: only observations about the job's own targets, re-masked.</summary>
public sealed class ObservationGuard
{
    private readonly IpRangeSet _addresses;
    private readonly HashSet<string> _hostnames = new(StringComparer.Ordinal);

    public ObservationGuard(ScanJob job)
    {
        var ranges = new List<IpRange>();
        foreach (var entry in job.Targets.Hosts.Concat(job.Targets.Endpoints.Select(e => e.Address)))
        {
            if (IpRangeSet.TryParseRange(entry, out var r)) ranges.Add(r);
            else _hostnames.Add(TargetPlanner.NormalizeHostname(entry));
        }
        foreach (var ep in job.Targets.Endpoints.Where(e => e.Hostname is not null))
            _hostnames.Add(TargetPlanner.NormalizeHostname(ep.Hostname!));
        _addresses = IpRangeSet.FromRanges(ranges);
    }

    public bool InScope(DiscoveryObservation o)
    {
        if (string.IsNullOrWhiteSpace(o.Address)) return false;
        if (IPAddress.TryParse(o.Address, out var ip) && _addresses.Contains(ip)) return true;
        // A hostname target may be reported with its resolved address; the hostname is what was authorized.
        return _hostnames.Contains(TargetPlanner.NormalizeHostname(o.Address))
               || (o.Hostname is not null && _hostnames.Contains(TargetPlanner.NormalizeHostname(o.Hostname)));
    }

    public static DiscoveryObservation Mask(DiscoveryObservation o) => o with
    {
        Http = o.Http is null ? null : o.Http with
        {
            Url = SensitiveDataMasker.MaskTokens(o.Http.Url),
            FinalUrl = o.Http.FinalUrl is null ? null : SensitiveDataMasker.MaskTokens(o.Http.FinalUrl),
            Headers = SensitiveDataMasker.MaskHeaders(o.Http.Headers ?? new Dictionary<string, string>()),
            RedirectChain = (o.Http.RedirectChain ?? []).Select(SensitiveDataMasker.MaskTokens).ToList(),
        },
        Service = o.Service is null ? null : o.Service with { Banner = o.Service.Banner is null ? null : SensitiveDataMasker.MaskTokens(o.Service.Banner) },
        Signature = o.Signature is null ? null : o.Signature with
        {
            Evidence = o.Signature.Evidence is null ? null : SensitiveDataMasker.MaskTokens(o.Signature.Evidence),
            MatchedAt = o.Signature.MatchedAt is null ? null : SensitiveDataMasker.MaskTokens(o.Signature.MatchedAt),
            ExtractedResults = (o.Signature.ExtractedResults ?? []).Select(SensitiveDataMasker.MaskTokens).ToList(),
        },
        Attributes = o.Attributes?.ToDictionary(a => a.Key, a => SensitiveDataMasker.MaskTokens(a.Value)),
    };
}
