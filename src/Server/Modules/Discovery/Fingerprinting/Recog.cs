using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace WebScan.Server.Modules.Discovery.Fingerprinting;

/// <summary>Self-test sample of a fingerprint: the text and the params it must yield.</summary>
internal sealed record RecogExample(string Text, IReadOnlyDictionary<string, string> Expected);

/// <summary>Result of the first matching fingerprint: params such as service.product, hw.device, os.version.</summary>
internal sealed record RecogMatch(string Description, IReadOnlyDictionary<string, string> Params)
{
    public string? this[string name] => Params.GetValueOrDefault(name);
}

/// <summary>One recog fingerprint: params with position 0 are constants, position n takes capture group n.</summary>
internal sealed partial record RecogFingerprint(string MatchKey, Regex Pattern, string Description,
    IReadOnlyList<(int Position, string Name, string? Value)> Params, IReadOnlyList<RecogExample> Examples)
{
    public RecogMatch? Match(string text)
    {
        System.Text.RegularExpressions.Match m;
        try { m = Pattern.Match(text); }
        catch (RegexMatchTimeoutException) { return null; }
        if (!m.Success) return null;

        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (position, name, value) in Params)
        {
            var v = position == 0 ? value : position < m.Groups.Count && m.Groups[position].Success ? m.Groups[position].Value.Trim() : null;
            if (!string.IsNullOrEmpty(v)) values[name] = v;
        }
        // Constants may reference captured params, e.g. "cpe:/a:microsoft:iis:{service.version}".
        foreach (var key in values.Keys.ToList())
            values[key] = Reference().Replace(values[key], r => values.GetValueOrDefault(r.Groups[1].Value, "-"));
        return new RecogMatch(Description, values);
    }

    [GeneratedRegex(@"\{([a-z0-9_.]+)\}")]
    private static partial Regex Reference();
}

/// <summary>
/// Rapid7 recog fingerprints (BSD-2-Clause, vendored XML under Fingerprinting/Recog, pinned version in docs/TOOLS.md), matched on the
/// server against already collected banners, headers, titles, favicon hashes and certificate DNs: no extra traffic to targets.
/// Recog patterns are Ruby regexes: <c>^</c>/<c>$</c> always match at line breaks, REG_MULTILINE / REG_DOT_NEWLINE mean "dot matches newline".
/// </summary>
internal sealed partial class RecogDatabase
{
    public const string HttpServer = "http_header.server";
    public const string HttpCookie = "http_header.cookie";
    public const string HttpWwwAuth = "http_header.wwwauth";
    public const string HtmlTitle = "html_title";
    public const string FaviconMd5 = "favicon.md5";
    public const string SshBanner = "ssh.banner";
    public const string FtpBanner = "ftp.banner";
    public const string X509Subject = "x509.subject";
    public const string X509Issuer = "x509.issuer";

    private static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(100);
    private static readonly Lazy<RecogDatabase> Embedded = new(LoadEmbedded);

    private readonly Dictionary<string, List<RecogFingerprint>> _byKey;

    private RecogDatabase(Dictionary<string, List<RecogFingerprint>> byKey, int skipped)
    {
        _byKey = byKey;
        Skipped = skipped;
    }

    public static RecogDatabase Default => Embedded.Value;

    public IEnumerable<RecogFingerprint> Fingerprints => _byKey.Values.SelectMany(f => f);

    /// <summary>Fingerprints whose pattern .NET could not compile.</summary>
    public int Skipped { get; }

    /// <summary>First fingerprint of the set <paramref name="matchKey"/> that matches (recog semantics), or null.</summary>
    public RecogMatch? Match(string matchKey, string? text)
    {
        if (string.IsNullOrWhiteSpace(text) || !_byKey.TryGetValue(matchKey, out var set)) return null;
        foreach (var fingerprint in set)
            if (fingerprint.Match(text) is { } match) return match;
        return null;
    }

    private static RecogDatabase LoadEmbedded()
    {
        var assembly = typeof(RecogDatabase).Assembly;
        var byKey = new Dictionary<string, List<RecogFingerprint>>(StringComparer.Ordinal);
        var skipped = 0;
        foreach (var resource in assembly.GetManifestResourceNames().Where(n => n.Contains(".Recog.") && n.EndsWith(".xml", StringComparison.Ordinal)).Order())
        {
            using var stream = assembly.GetManifestResourceStream(resource)!;
            var root = XDocument.Load(stream).Root!;
            var key = (string?)root.Attribute("matches") ?? Path.GetFileNameWithoutExtension(resource);
            var list = byKey.TryGetValue(key, out var existing) ? existing : byKey[key] = [];
            foreach (var element in root.Elements("fingerprint"))
            {
                if (Parse(key, element) is { } fingerprint) list.Add(fingerprint);
                else skipped++;
            }
        }
        return new RecogDatabase(byKey, skipped);
    }

    private static RecogFingerprint? Parse(string key, XElement element)
    {
        var flags = ((string?)element.Attribute("flags") ?? "").Split(',', StringSplitOptions.TrimEntries);
        var options = RegexOptions.Multiline | RegexOptions.CultureInvariant;
        if (flags.Contains("REG_ICASE")) options |= RegexOptions.IgnoreCase;
        if (flags.Contains("REG_MULTILINE") || flags.Contains("REG_DOT_NEWLINE")) options |= RegexOptions.Singleline;
        Regex pattern;
        // Ruby accepts "\_" for a literal underscore, .NET rejects the escape.
        try { pattern = new Regex(UnderscoreEscape().Replace((string)element.Attribute("pattern")!, "$1_"), options, MatchTimeout); }
        catch (ArgumentException) { return null; }

        var parameters = element.Elements("param")
            .Select(p => ((int?)p.Attribute("pos") ?? 0, (string)p.Attribute("name")!, (string?)p.Attribute("value")))
            .Where(p => p.Item2 is not null).ToList();
        var examples = element.Elements("example").Select(e => new RecogExample(
            (string?)e.Attribute("_encoding") == "base64" ? Encoding.UTF8.GetString(Convert.FromBase64String(e.Value.Trim())) : e.Value,
            e.Attributes().Where(a => !a.Name.LocalName.StartsWith('_')).ToDictionary(a => a.Name.LocalName, a => a.Value))).ToList();
        var description = Regex.Replace(element.Element("description")?.Value ?? "", @"\s+", " ").Trim();
        return new RecogFingerprint(key, pattern, description, parameters, examples);
    }

    [GeneratedRegex(@"(?<!\\)((?:\\\\)*)\\_")]
    private static partial Regex UnderscoreEscape();
}
