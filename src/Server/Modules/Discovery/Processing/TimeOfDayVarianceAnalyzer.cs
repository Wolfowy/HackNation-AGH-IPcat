namespace WebScan.Server.Modules.Discovery.Processing;

/// <summary>Observations of one material response of an endpoint path within one hour-of-day bucket.</summary>
public sealed record HourlyResponse(int HourBucket, string Fingerprint, int Count, string Description, DateTimeOffset FirstSeenAt, DateTimeOffset LastSeenAt);

public sealed record HourlyPattern(int HourBucket, string Fingerprint, string Description);

public sealed record TimeOfDayVarianceResult(bool HasVariance, IReadOnlyList<HourlyPattern> Pattern)
{
    /// <summary>"00-07h UTC: 503 'Maintenance'; 08-17h UTC: 200 'App'" (contiguous buckets with the same response merged).</summary>
    public string Describe()
    {
        var parts = new List<string>();
        for (var i = 0; i < Pattern.Count; i++)
        {
            var start = Pattern[i];
            var end = start;
            while (i + 1 < Pattern.Count && Pattern[i + 1].Fingerprint == start.Fingerprint && Pattern[i + 1].HourBucket == end.HourBucket + 1)
                end = Pattern[++i];
            var hours = start.HourBucket == end.HourBucket ? $"{start.HourBucket:00}h" : $"{start.HourBucket:00}-{end.HourBucket:00}h";
            parts.Add($"{hours} UTC: {start.Description}");
        }
        return string.Join("; ", parts);
    }
}

/// <summary>
/// Detects endpoints whose responses differ materially, but consistently, by hour of day (e.g. maintenance pages at night).
/// Variance = at least <c>minObservations</c> observations, and two "consistent" hour buckets (≥ 2 observations, dominant
/// response ≥ <c>minDominance</c> of the bucket) with different dominant responses that were seen during overlapping periods
/// (overlap rules out a permanent change that merely happened between scans at different hours).
/// </summary>
public static class TimeOfDayVarianceAnalyzer
{
    public static TimeOfDayVarianceResult Analyze(IEnumerable<HourlyResponse> responses, int minObservations, double minDominance = 0.75)
    {
        var list = responses.ToList();
        if (list.Sum(r => r.Count) < minObservations) return new(false, []);

        var consistent = list.GroupBy(r => r.HourBucket)
            .Select(g =>
            {
                var total = g.Sum(r => r.Count);
                var top = g.OrderByDescending(r => r.Count).ThenBy(r => r.Fingerprint, StringComparer.Ordinal).First();
                return (Top: top, Total: total, Share: (double)top.Count / total);
            })
            .Where(b => b.Total >= 2 && b.Share >= minDominance)
            .Select(b => b.Top)
            .OrderBy(r => r.HourBucket)
            .ToList();

        var variance = consistent.Any(a => consistent.Any(b =>
            a.Fingerprint != b.Fingerprint && a.FirstSeenAt <= b.LastSeenAt && b.FirstSeenAt <= a.LastSeenAt));
        return new(variance, consistent.Select(r => new HourlyPattern(r.HourBucket, r.Fingerprint, r.Description)).ToList());
    }
}
