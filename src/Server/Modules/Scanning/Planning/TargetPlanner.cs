using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using WebScan.Contracts;
using WebScan.Server.Kernel.Networking;
using WebScan.Server.Kernel.Ports;

namespace WebScan.Server.Modules.Scanning.Planning;

/// <summary>Authorized targets of one network segment: includes minus network and global exclusions.</summary>
public sealed record SegmentTargets(
    Guid NetworkId, string NetworkName, string Zone, int? MaxRatePerSecond,
    IpRangeSet Addresses, IReadOnlyList<string> Hostnames, IReadOnlyList<string> AuthorizedScope)
{
    public bool ContainsHost(string host) =>
        IPAddress.TryParse(host, out var ip) ? Addresses.Contains(ip) : Hostnames.Contains(TargetPlanner.NormalizeHostname(host));
}

public sealed record PlannedBatch(
    Guid NetworkId, string Zone, int? NetworkRateCap,
    IReadOnlyList<string> Hosts, IReadOnlyList<ScanEndpoint> Endpoints, long Count,
    string TargetKey, string Summary, IReadOnlyList<string> ReachTargets, IReadOnlyList<string> AuthorizedScope, string? SubnetKey);

/// <param name="OutOfScope">Requested targets dropped because they are outside the resolved authorized scope.</param>
public sealed record TargetPlan(IReadOnlyList<PlannedBatch> Batches, int OutOfScope);

/// <summary>
/// Pure, deterministic target planning: scope resolution (exclusions, de-overlapping of segments) and batching.
/// Nothing outside the resolved scope ever ends up in a batch.
/// </summary>
public static class TargetPlanner
{
    public const int MinBatchSize = 64;
    public const int MaxBatchSize = 1024;

    /// <summary>Clamps to 64–1024 and rounds down to a power of two.</summary>
    public static int NormalizeBatchSize(int? requested, int fallback)
    {
        var size = Math.Clamp(requested ?? fallback, MinBatchSize, MaxBatchSize);
        return 1 << (31 - int.LeadingZeroCount(size));
    }

    /// <summary>Every size <see cref="NormalizeBatchSize"/> can return.</summary>
    public static readonly int[] BatchSizes = [64, 128, 256, 512, 1024];

    /// <summary>
    /// Batch size of a step: the workflow's explicit size wins; otherwise measured per-job throughput × target job duration
    /// (64–1024, power of two); without measurements the configured default.
    /// </summary>
    public static (int Size, string Reason) ChooseBatchSize(int? explicitSize, int defaultSize, int targetJobSeconds, double? targetsPerSecond)
    {
        if (explicitSize is not null)
        {
            var size = NormalizeBatchSize(explicitSize, defaultSize);
            return (size, $"batch size {size} (set by the workflow)");
        }
        if (targetsPerSecond is not > 0)
        {
            var size = NormalizeBatchSize(null, defaultSize);
            return (size, $"batch size {size} (default, no throughput measured yet)");
        }
        var adaptive = NormalizeBatchSize((int)Math.Min(MaxBatchSize, targetsPerSecond.Value * targetJobSeconds), defaultSize);
        return (adaptive, string.Create(System.Globalization.CultureInfo.InvariantCulture,
            $"batch size {adaptive} (measured {targetsPerSecond.Value:0.##} targets/s per job, {targetJobSeconds}s target job duration)"));
    }

    /// <summary>
    /// Duration range of one step: best case = all jobs in parallel at the fastest measured agent's rate (never faster than
    /// one packet per target at the rate cap); worst case = waves of full batches at the slowest agent's rate.
    /// Null without measurements or without anyone to run the jobs.
    /// </summary>
    public static (double MinSeconds, double MaxSeconds)? EstimateDuration(long targets, int jobs, int batchSize,
        IReadOnlyCollection<double> agentTargetsPerSecond, int concurrency, long? rateCap)
    {
        if (targets <= 0 || jobs <= 0) return (0, 0);
        var rates = agentTargetsPerSecond.Where(r => r > 0).ToList();
        if (rates.Count == 0 || concurrency < 1) return null;
        var parallel = Math.Min(concurrency, jobs);
        var min = targets / (rates.Max() * parallel);
        if (rateCap is > 0) min = Math.Max(min, targets / (double)rateCap.Value);
        var max = Math.Ceiling(jobs / (double)parallel) * Math.Min(batchSize, targets) / rates.Min();
        return (Math.Round(min), Math.Round(Math.Max(min, max)));
    }

    public static string NormalizeHostname(string host) => host.Trim().TrimEnd('.').ToLowerInvariant();

    /// <summary>
    /// Resolves segments into address sets. Segments are processed in order and an address already claimed by an earlier
    /// segment is not repeated, so overlapping networks never produce duplicate work.
    /// </summary>
    public static IReadOnlyList<SegmentTargets> ResolveTargets(ResolvedScope scope, long maxIpv6SegmentAddresses)
    {
        var (globalIps, globalHosts) = SplitEntries(scope.GlobalExclusions);
        var claimed = new IpRangeSet();
        var claimedHosts = new HashSet<string>(StringComparer.Ordinal);
        var result = new List<SegmentTargets>();

        foreach (var segment in scope.Segments)
        {
            var (includeIps, includeHosts) = SplitEntries(segment.Include);
            var (excludeIps, excludeHosts) = SplitEntries(segment.Exclude);
            var included = IpRangeSet.Parse(includeIps);
            var addresses = included.Subtract(IpRangeSet.Parse(excludeIps)).Subtract(IpRangeSet.Parse(globalIps));

            var v6 = IpRangeSet.FromRanges(addresses.Ranges.Where(r => r.Family == AddressFamily.InterNetworkV6)).Count;
            if (v6 > (UInt128)maxIpv6SegmentAddresses)
                throw new PlanningException(
                    $"Network '{segment.NetworkName}' contains an IPv6 segment of {v6} addresses; the limit is {maxIpv6SegmentAddresses} (Planner:MaxIpv6SegmentAddresses).");

            addresses = addresses.Subtract(claimed);
            claimed = claimed.Union(addresses);

            var hostnames = includeHosts
                .Where(h => !h.StartsWith("*.", StringComparison.Ordinal)) // wildcards describe scope, they are not scannable targets
                .Where(h => !IsExcludedHostname(h, excludeHosts) && !IsExcludedHostname(h, globalHosts))
                .Where(claimedHosts.Add)
                .ToList();

            result.Add(new SegmentTargets(segment.NetworkId, segment.NetworkName, segment.Zone, segment.MaxRatePerSecond,
                addresses, hostnames, [.. included.ToCidrs(), .. includeHosts]));
        }
        return result;
    }

    /// <summary>
    /// Host batches for every segment. <paramref name="restrictTo"/> (e.g. hosts found by a previous step) is intersected
    /// with the scope; entries outside it are counted in <see cref="TargetPlan.OutOfScope"/>.
    /// </summary>
    public static TargetPlan PlanHosts(IReadOnlyList<SegmentTargets> segments, int batchSize, int subnetPrefixLength,
        IReadOnlyCollection<string>? restrictTo = null)
    {
        IpRangeSet? restrictIps = null;
        HashSet<string>? restrictHosts = null;
        var outOfScope = 0;
        if (restrictTo is not null)
        {
            var (ips, hosts) = SplitEntries(restrictTo);
            restrictIps = IpRangeSet.Parse(ips);
            restrictHosts = hosts.ToHashSet(StringComparer.Ordinal);
            var allScope = segments.Aggregate(new IpRangeSet(), (acc, s) => acc.Union(s.Addresses));
            outOfScope = (int)Math.Min(int.MaxValue, ToLong(restrictIps.Subtract(allScope).Count))
                         + restrictHosts.Count(h => !segments.Any(s => s.Hostnames.Contains(h)));
        }

        var batches = new List<PlannedBatch>();
        foreach (var segment in segments)
        {
            var addresses = restrictIps is null ? segment.Addresses : Intersect(segment.Addresses, restrictIps);
            foreach (var hosts in addresses.SplitIntoBatches(batchSize))
                batches.Add(HostBatch(segment, hosts, hosts.Sum(h => ToLong(ParseRange(h).Count)), subnetPrefixLength));

            var hostnames = restrictHosts is null ? segment.Hostnames : segment.Hostnames.Where(restrictHosts.Contains).ToList();
            foreach (var chunk in hostnames.Chunk(batchSize))
                batches.Add(HostBatch(segment, chunk, chunk.Length, subnetPrefixLength));
        }
        return new TargetPlan(batches, outOfScope);
    }

    /// <summary>Endpoint batches: endpoints grouped by host (a host's endpoints stay together unless they exceed the batch size).</summary>
    public static TargetPlan PlanEndpoints(IReadOnlyList<SegmentTargets> segments, IEnumerable<ScanEndpoint> endpoints, int batchSize, int subnetPrefixLength)
    {
        var bySegment = segments.ToDictionary(s => s.NetworkId, _ => new List<ScanEndpoint>());
        var outOfScope = 0;
        foreach (var ep in endpoints.DistinctBy(e => (e.Address.ToLowerInvariant(), e.Port, e.Transport)))
        {
            var segment = segments.FirstOrDefault(s => s.ContainsHost(ep.Address));
            if (segment is null) { outOfScope++; continue; }
            bySegment[segment.NetworkId].Add(ep);
        }

        var batches = new List<PlannedBatch>();
        foreach (var segment in segments)
        {
            var current = new List<ScanEndpoint>();
            foreach (var host in bySegment[segment.NetworkId].GroupBy(e => e.Address.ToLowerInvariant()).OrderBy(g => SortKey(g.Key)))
            {
                var hostEndpoints = host.OrderBy(e => e.Port).ThenBy(e => e.Transport).ToList();
                if (current.Count > 0 && current.Count + hostEndpoints.Count > batchSize) { batches.Add(EndpointBatch(segment, current, subnetPrefixLength)); current = []; }
                foreach (var ep in hostEndpoints)
                {
                    if (current.Count == batchSize) { batches.Add(EndpointBatch(segment, current, subnetPrefixLength)); current = []; }
                    current.Add(ep);
                }
            }
            if (current.Count > 0) batches.Add(EndpointBatch(segment, current, subnetPrefixLength));
        }
        return new TargetPlan(batches, outOfScope);
    }

    /// <summary>Linear-time intersection of two normalized sets (IpRangeSet.Intersect is quadratic for large sparse sets).</summary>
    public static IpRangeSet Intersect(IpRangeSet a, IpRangeSet b)
    {
        var result = new List<IpRange>();
        int i = 0, j = 0;
        while (i < a.Ranges.Count && j < b.Ranges.Count)
        {
            var (x, y) = (a.Ranges[i], b.Ranges[j]);
            if (x.Family != y.Family) { if (x.Family < y.Family) i++; else j++; continue; }
            var start = UInt128.Max(x.Start, y.Start);
            var end = UInt128.Min(x.End, y.End);
            if (start <= end) result.Add(new IpRange(x.Family, start, end));
            if (x.End < y.End) i++; else j++;
        }
        return IpRangeSet.FromRanges(result);
    }

    public static string Hash(IEnumerable<string> parts) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', parts))))[..32];

    private static PlannedBatch HostBatch(SegmentTargets s, IReadOnlyList<string> hosts, long count, int subnetPrefix) =>
        new(s.NetworkId, s.Zone, s.MaxRatePerSecond, hosts, [], count, Hash(hosts),
            hosts.Count == 1 ? hosts[0] : $"{hosts[0]} +{hosts.Count - 1}", hosts, s.AuthorizedScope, SubnetKey(hosts[0], subnetPrefix));

    private static PlannedBatch EndpointBatch(SegmentTargets s, List<ScanEndpoint> endpoints, int subnetPrefix)
    {
        var addresses = endpoints.Select(e => e.Address).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var first = $"{endpoints[0].Address}:{endpoints[0].Port}";
        return new(s.NetworkId, s.Zone, s.MaxRatePerSecond, [], endpoints, endpoints.Count,
            Hash(endpoints.Select(e => $"{e.Address.ToLowerInvariant()}|{e.Port}|{e.Transport}")),
            endpoints.Count == 1 ? first : $"{first} +{endpoints.Count - 1}", addresses, s.AuthorizedScope, SubnetKey(addresses[0], subnetPrefix));
    }

    /// <summary>"10.1.0.0/16" for IPv4 (configured prefix) or the /64 for IPv6; null for hostnames.</summary>
    public static string? SubnetKey(string hostEntry, int ipv4PrefixLength)
    {
        if (!IpRangeSet.TryParseRange(hostEntry, out var r)) return null;
        var prefix = r.Family == AddressFamily.InterNetwork ? Math.Clamp(ipv4PrefixLength, 0, 32) : 64;
        var hostBits = r.Bits - prefix;
        var mask = hostBits == 128 ? UInt128.MaxValue : (UInt128.One << hostBits) - 1;
        return $"{IpRangeSet.ToAddress(r.Family, r.Start & ~mask)}/{prefix}";
    }

    private static (List<string> Ips, List<string> Hostnames) SplitEntries(IEnumerable<string> entries)
    {
        var ips = new List<string>();
        var hosts = new List<string>();
        foreach (var raw in entries)
        {
            switch (IpRangeSet.Classify(raw))
            {
                case TargetEntryKind.Address or TargetEntryKind.Cidr or TargetEntryKind.Range: ips.Add(raw.Trim()); break;
                case TargetEntryKind.Hostname: hosts.Add(NormalizeHostname(raw)); break;
            }
        }
        return (ips, hosts);
    }

    private static bool IsExcludedHostname(string host, IEnumerable<string> exclusions) =>
        exclusions.Any(x => x == host || (x.StartsWith("*.", StringComparison.Ordinal) && host.EndsWith(x[1..], StringComparison.Ordinal)));

    private static IpRange ParseRange(string entry) =>
        IpRangeSet.TryParseRange(entry, out var r) ? r : throw new FormatException($"'{entry}' is not an address.");

    private static long ToLong(UInt128 v) => v > long.MaxValue ? long.MaxValue : (long)v;

    private static (int, UInt128, string) SortKey(string host) =>
        IPAddress.TryParse(host, out var ip) ? ((int)ip.AddressFamily, IpRangeSet.ToUInt128(ip), "") : (int.MaxValue, 0, host);
}
