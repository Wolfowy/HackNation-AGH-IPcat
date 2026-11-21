using WebScan.Server.Infrastructure.Http;
using WebScan.Server.Kernel.Networking;

namespace WebScan.Server.Modules.Networks;

/// <summary>
/// Scope policy evaluation. IP entries are compared as address sets; hostnames match an allowed domain exactly
/// or a <c>*.domain</c> entry (subdomains only). An empty policy authorizes nothing.
/// </summary>
internal sealed class ScopeRules
{
    public const int MaxEntries = 10_000;

    private readonly IpRangeSet _allowedIps;
    private readonly IpRangeSet _effectiveIps;
    private readonly IReadOnlyList<string> _allowedHosts;
    private readonly IReadOnlyList<string> _excludedHosts;

    private ScopeRules(IEnumerable<string> allowed, IEnumerable<string> excluded)
    {
        var (allowedIps, allowedHosts) = Split(allowed);
        var (excludedIps, excludedHosts) = Split(excluded);
        _allowedIps = IpRangeSet.Parse(allowedIps);
        _effectiveIps = _allowedIps.Subtract(IpRangeSet.Parse(excludedIps));
        _allowedHosts = allowedHosts;
        _excludedHosts = excludedHosts;
    }

    /// <summary>Builds rules from validated policy entries (invalid entries are ignored).</summary>
    public static ScopeRules Create(IEnumerable<string> allowed, IEnumerable<string> excluded) => new(allowed, excluded);

    /// <summary>Network ranges must lie inside the allowed set (global exclusions are subtracted later, at resolve time).</summary>
    public bool Covers(string entry) => Classify(entry) switch
    {
        TargetEntryKind.Address or TargetEntryKind.Cidr or TargetEntryKind.Range => _allowedIps.IsSupersetOf(IpRangeSet.Parse([entry])),
        TargetEntryKind.Hostname => MatchesAny(_allowedHosts, entry),
        _ => false,
    };

    /// <summary>Inside the allowed set and outside the global exclusions.</summary>
    public bool IsAuthorized(string target) => Classify(target) switch
    {
        TargetEntryKind.Address or TargetEntryKind.Cidr or TargetEntryKind.Range => _effectiveIps.IsSupersetOf(IpRangeSet.Parse([target])),
        TargetEntryKind.Hostname => !IsWildcard(target) && MatchesAny(_allowedHosts, target) && !MatchesAny(_excludedHosts, target),
        _ => false,
    };

    /// <summary>Keeps covered entries as they are, clips partially covered IP entries to the policy, drops the rest.</summary>
    public IReadOnlyList<string> Restrict(IEnumerable<string> entries)
    {
        var result = new List<string>();
        foreach (var entry in entries)
        {
            if (Covers(entry)) result.Add(entry);
            else if (Classify(entry) is TargetEntryKind.Address or TargetEntryKind.Cidr or TargetEntryKind.Range)
                result.AddRange(IpRangeSet.Parse([entry]).Intersect(_allowedIps).ToCidrs());
        }
        return result;
    }

    /// <summary>Addresses in the ranges minus exclusions, plus hostname entries; saturates at <see cref="long.MaxValue"/>.</summary>
    public static long CountAddresses(IEnumerable<string> ranges, IEnumerable<string> exclusions)
    {
        var (rangeIps, rangeHosts) = Split(ranges);
        var (excludedIps, excludedHosts) = Split(exclusions);
        var count = IpRangeSet.Parse(rangeIps).Subtract(IpRangeSet.Parse(excludedIps)).Count;
        var hosts = rangeHosts.Count(h => !MatchesAny(excludedHosts, h));
        return count >= (UInt128)(long.MaxValue - hosts) ? long.MaxValue : (long)count + hosts;
    }

    /// <summary>Validates IP/CIDR/range/hostname entries; <c>*.domain</c> patterns only where <paramref name="allowWildcards"/>.</summary>
    public static void ValidateEntries(ValidationErrors errors, string field, IReadOnlyList<string>? entries, bool allowWildcards, bool required)
    {
        if (entries is null || entries.Count == 0)
        {
            if (required) errors.Add(field, "At least one entry is required.");
            return;
        }
        if (entries.Count > MaxEntries) errors.Add(field, $"Max {MaxEntries} entries.");
        foreach (var entry in entries)
        {
            if (Classify(entry) == TargetEntryKind.Invalid)
                errors.Add(field, $"'{entry}' is not an IP address, CIDR, range or hostname.");
            else if (!allowWildcards && IsWildcard(entry))
                errors.Add(field, $"'{entry}': wildcard hostnames are only allowed in the scope policy.");
        }
    }

    /// <summary>Trimmed entries; hostnames lower-cased without a trailing dot.</summary>
    public static List<string> Normalize(IEnumerable<string>? entries) =>
        (entries ?? []).Select(e => e.Trim()).Select(e => Classify(e) == TargetEntryKind.Hostname ? NormalizeHost(e) : e)
            .Where(e => e.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    private static TargetEntryKind Classify(string? entry) => IpRangeSet.Classify(entry);

    private static bool IsWildcard(string entry) => entry.TrimStart().StartsWith("*.", StringComparison.Ordinal);

    private static string NormalizeHost(string host) => host.Trim().TrimEnd('.').ToLowerInvariant();

    private static bool MatchesAny(IEnumerable<string> patterns, string host)
    {
        host = NormalizeHost(host);
        return patterns.Any(p => p.StartsWith("*.", StringComparison.Ordinal)
            ? host.EndsWith(p[1..], StringComparison.Ordinal) && host.Length > p.Length - 1
            : host == p);
    }

    private static (List<string> Ips, List<string> Hosts) Split(IEnumerable<string> entries)
    {
        var ips = new List<string>();
        var hosts = new List<string>();
        foreach (var entry in entries)
        {
            switch (Classify(entry))
            {
                case TargetEntryKind.Address or TargetEntryKind.Cidr or TargetEntryKind.Range: ips.Add(entry); break;
                case TargetEntryKind.Hostname: hosts.Add(NormalizeHost(entry)); break;
            }
        }
        return (ips, hosts);
    }
}
