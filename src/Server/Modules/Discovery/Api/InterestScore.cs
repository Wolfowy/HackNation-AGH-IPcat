using System.Linq.Expressions;
using WebScan.Server.Modules.Discovery.Domain;

namespace WebScan.Server.Modules.Discovery.Api;

/// <summary>One reason that makes an asset worth a look, with its weight.</summary>
public sealed record InterestSignal(int Points, string Reason);

/// <summary>Analytical priority 0–100 and the reasons behind it (highest weight first).</summary>
public sealed record InterestScore(int Score, IReadOnlyList<string> Reasons)
{
    public static readonly InterestScore None = new(0, []);
}

/// <summary>Everything the interest score looks at for one service (or, with <see cref="Port"/> 0, a host without services).</summary>
public sealed record InterestInput
{
    public int Port { get; init; }
    public string? ServiceName { get; init; }
    public bool Http { get; init; }

    /// <summary>Counted findings (see <see cref="InterestScorer.CountsFinding"/>) that are detections, not classifications.</summary>
    public IReadOnlyList<(string Severity, string Name)> Findings { get; init; } = [];

    /// <summary>Classification tags of open classification results (e.g. admin-panel).</summary>
    public IReadOnlyList<string> Classifications { get; init; } = [];

    /// <summary>Detected technologies with a version, e.g. "nginx 1.18.0".</summary>
    public IReadOnlyList<string> VersionedTechnologies { get; init; } = [];

    public bool NewInLastRun { get; init; }
    public DateTimeOffset FirstSeenAt { get; init; }
    public bool? SelfSigned { get; init; }
    public DateTimeOffset? CertNotAfter { get; init; }
    public bool HostUnstable { get; init; }
    public bool TimeOfDayVariance { get; init; }

    /// <summary>
    /// Hook for other analyzers (e.g. HTTP artifacts: interesting headers/cookies, device classification): their signals are
    /// added as given. Fill it where the input is built (<c>AssetQueries.InterestInputsAsync</c>).
    /// </summary>
    public IReadOnlyList<InterestSignal> Extra { get; init; } = [];
}

/// <summary>Pure, explainable "interestingness" score: weighted signals, capped at 100.</summary>
public static class InterestScorer
{
    /// <summary>
    /// The one place that decides whether a finding counts for scores and the dashboard: open only.
    /// Extend here when findings get a triage state (e.g. exclude false positives).
    /// </summary>
    public static readonly Expression<Func<SignatureMatch, bool>> CountsFinding = m => m.Status == FindingStatus.Open;

    private static readonly Dictionary<string, int> SeverityPoints = new(StringComparer.OrdinalIgnoreCase)
    {
        ["critical"] = 45, ["high"] = 35, ["medium"] = 20, ["low"] = 10, ["info"] = 4,
    };

    /// <summary>Remote administration / database / cleartext ports; the value is the weight.</summary>
    private static readonly Dictionary<int, (string Name, int Points)> SensitivePorts = new()
    {
        [21] = ("FTP", 12), [22] = ("SSH", 8), [23] = ("Telnet", 20), [139] = ("NetBIOS", 12), [161] = ("SNMP", 12), [445] = ("SMB", 15),
        [623] = ("IPMI", 20), [1433] = ("MSSQL", 15), [1521] = ("Oracle DB", 15), [2375] = ("Docker API", 25), [2379] = ("etcd", 20),
        [3306] = ("MySQL", 15), [3389] = ("RDP", 15), [5432] = ("PostgreSQL", 15), [5900] = ("VNC", 15), [5985] = ("WinRM", 15),
        [5986] = ("WinRM", 15), [6379] = ("Redis", 20), [8291] = ("MikroTik Winbox", 15), [9200] = ("Elasticsearch", 20),
        [10250] = ("Kubelet", 20), [11211] = ("Memcached", 20), [27017] = ("MongoDB", 20),
    };

    private static readonly int[] StandardHttpPorts = [80, 443, 8080, 8443];

    public static InterestScore Score(InterestInput input, DateTimeOffset now)
    {
        var signals = new List<InterestSignal>();

        if (input.Findings.Count > 0)
        {
            var top = input.Findings.MaxBy(f => SeverityPoints.GetValueOrDefault(f.Severity));
            var more = input.Findings.Count > 1 ? $" (+{input.Findings.Count - 1} more)" : "";
            signals.Add(new(SeverityPoints.GetValueOrDefault(top.Severity) + Math.Min(10, 3 * (input.Findings.Count - 1)),
                $"Open {top.Severity.ToLowerInvariant()} finding: {top.Name}{more}"));
        }

        foreach (var tag in input.Classifications.Distinct(StringComparer.OrdinalIgnoreCase))
            signals.Add(Classification(tag));

        if (input.NewInLastRun) signals.Add(new(15, "New in the last scan"));
        else if (now - input.FirstSeenAt < TimeSpan.FromDays(7)) signals.Add(new(8, $"First seen {(int)(now - input.FirstSeenAt).TotalDays} day(s) ago"));

        if (input.VersionedTechnologies.Count > 0)
            signals.Add(new(Math.Min(15, 5 * input.VersionedTechnologies.Count), $"Version disclosed: {string.Join(", ", input.VersionedTechnologies.Take(3))}"));

        if (input.Port > 0 && SensitivePorts.TryGetValue(input.Port, out var sensitive))
            signals.Add(new(sensitive.Points, $"{sensitive.Name} exposed on port {input.Port}"));
        if (input.Port > 0 && input.Http && !StandardHttpPorts.Contains(input.Port))
            signals.Add(new(10, $"Web interface on non-standard port {input.Port}"));

        if (input.CertNotAfter is { } notAfter)
        {
            if (notAfter < now) signals.Add(new(15, $"TLS certificate expired on {notAfter:yyyy-MM-dd}"));
            else if (notAfter - now < TimeSpan.FromDays(30)) signals.Add(new(8, $"TLS certificate expires in {(int)(notAfter - now).TotalDays} day(s)"));
        }
        if (input.SelfSigned == true) signals.Add(new(8, "Self-signed TLS certificate"));

        if (input.HostUnstable) signals.Add(new(5, "Host is unstable (flapping up/down)"));
        if (input.TimeOfDayVariance) signals.Add(new(10, "Responds differently by time of day"));

        signals.AddRange(input.Extra.Where(s => s.Points > 0));
        var ordered = signals.OrderByDescending(s => s.Points).ToList();
        return new InterestScore(Math.Clamp(ordered.Sum(s => s.Points), 0, 100), ordered.Select(s => s.Reason).ToList());
    }

    private static InterestSignal Classification(string tag)
    {
        var t = tag.ToLowerInvariant();
        if (t.Contains("admin") || t.Contains("management")) return new(25, $"Classified as {tag}");
        if (t.Contains("staging") || t.Contains("dev") || t.Contains("test")) return new(15, $"Classified as {tag} (non-production)");
        string[] devices = ["iot", "camera", "printer", "router", "scada", "plc", "nas"];
        return devices.Any(t.Contains) ? new(15, $"Classified as {tag} (device)") : new(8, $"Classified as {tag}");
    }
}
