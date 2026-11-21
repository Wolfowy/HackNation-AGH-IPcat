using WebScan.Contracts;

namespace WebScan.Server.Modules.Discovery.Normalization;

/// <summary>
/// Deterministic confidence model.
/// <list type="bullet">
/// <item>Each piece of evidence has a method and a score: the tool's own <see cref="Confidence"/> when reported, otherwise the
/// base score of the method: signature-match 0.9, version-probe 0.8, banner-match 0.7, tool-reported 0.6, port-heuristic 0.3.</item>
/// <item>Per method only the best score counts (repeating the same kind of evidence adds nothing).</item>
/// <item>Methods are treated as independent: <c>score = 1 − Π(1 − best_m)</c> (noisy-OR), rounded to 3 decimals.</item>
/// <item><c>method</c> = the contributing methods, ordinal-sorted, joined with "+" (e.g. "signature-match+version-probe").</item>
/// </list>
/// </summary>
public static class ConfidenceModel
{
    public const string ToolReported = "tool-reported";
    public const string BannerMatch = "banner-match";
    public const string VersionProbe = "version-probe";
    public const string SignatureMatch = "signature-match";
    public const string PortHeuristic = "port-heuristic";

    private static readonly Dictionary<string, double> BaseScores = new(StringComparer.Ordinal)
    {
        [SignatureMatch] = 0.9, [VersionProbe] = 0.8, [BannerMatch] = 0.7, [ToolReported] = 0.6, [PortHeuristic] = 0.3,
    };

    public static double BaseScore(string method) => BaseScores.GetValueOrDefault(method, 0.5);

    public static (double Score, string Method) Combine(IEnumerable<(string Method, double Score)> evidence)
    {
        var best = evidence
            .GroupBy(e => e.Method.Trim().ToLowerInvariant())
            .Select(g => (Method: g.Key, Score: Math.Clamp(g.Max(e => e.Score), 0, 1)))
            .OrderBy(e => e.Method, StringComparer.Ordinal)
            .ToList();
        if (best.Count == 0) return (0, "none");
        var miss = best.Aggregate(1.0, (acc, e) => acc * (1 - e.Score));
        return (Math.Round(1 - miss, 3), string.Join('+', best.Select(e => e.Method)));
    }

    /// <summary>Evidence carried by a service observation: version string → version-probe, product/banner → banner-match, name only → port-heuristic.</summary>
    public static (string Method, double Score) ForService(DiscoveryObservation o)
    {
        if (o.Confidence is { } c) return (c.Method.Trim().ToLowerInvariant(), Math.Clamp(c.Score, 0, 1));
        var method = o.Service?.Version is not null ? VersionProbe
            : o.Service?.Product is not null || o.Service?.Banner is not null ? BannerMatch
            : PortHeuristic;
        return (method, BaseScore(method));
    }

    public static (string Method, double Score) ForObservation(DiscoveryObservation o, string defaultMethod) =>
        o.Confidence is { } c ? (c.Method.Trim().ToLowerInvariant(), Math.Clamp(c.Score, 0, 1)) : (defaultMethod, BaseScore(defaultMethod));
}
