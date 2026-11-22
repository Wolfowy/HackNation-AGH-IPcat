using System.Net;
using System.Text.RegularExpressions;
using WebScan.Contracts;
using WebScan.Server.Modules.Discovery.Domain;

namespace WebScan.Server.Modules.Discovery.Fingerprinting;

/// <summary>
/// Built-in catalog of interesting HTTP artifacts (headers, cookies, pages) found in an already collected response: technology hints,
/// version and internal IP leaks, debug headers, weak session cookies, login/admin pages. Pure function, no traffic.
/// </summary>
internal static partial class HttpArtifacts
{
    public const int MaxValueLength = 200;

    /// <summary>
    /// Tags that are also raised as findings (source "artifact"): tag → finding name. Everything else stays an artifact only; admin pages
    /// too, the built-in "admin-panel" classification rule already reports them.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> FindingTags = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["debug"] = "Debug mode exposed",
        ["internal-ip-leak"] = "Internal IP address disclosed",
        ["login-page"] = "Login page exposed",
    };

    private sealed record HeaderRule(string Name, string Reason, string[] Tags, string Severity = "info", Func<string, bool>? When = null);

    /// <summary>Header names match case-insensitively; a trailing '*' matches a prefix.</summary>
    private static readonly HeaderRule[] HeaderRules =
    [
        new("x-powered-by", "Discloses the application framework", ["tech-hint"]),
        new("server", "Discloses the web server version", ["version-leak"], When: v => Version().IsMatch(v)),
        new("x-aspnet-version", "Discloses the ASP.NET version", ["version-leak"]),
        new("x-aspnetmvc-version", "Discloses the ASP.NET MVC version", ["version-leak"]),
        new("x-generator", "Discloses the CMS / site generator", ["tech-hint"]),
        new("x-drupal-*", "Drupal header", ["tech-hint"]),
        new("x-debug-token", "Symfony profiler token: debug mode is enabled", ["debug"], "low"),
        new("x-debug-token-link", "Symfony profiler link: debug mode is enabled", ["debug"], "low"),
        new("x-backend-server", "Discloses the backend server behind the proxy", ["tech-hint"]),
        new("x-upstream*", "Discloses the upstream server behind the proxy", ["tech-hint"]),
        new("via", "Discloses intermediate proxies", ["tech-hint"]),
        new("access-control-allow-origin", "CORS policy allows any origin", ["permissive-cors"], "low", v => v.Trim() is "*" or "null"),
    ];

    /// <summary>Well-known session cookie names → technology they reveal.</summary>
    private static readonly (Regex Name, string Technology)[] CookieRules =
    [
        (new Regex("^BIGipServer", RegexOptions.IgnoreCase), "F5 BIG-IP load balancer"),
        (new Regex("^PHPSESSID$", RegexOptions.IgnoreCase), "PHP"),
        (new Regex("^JSESSIONID$", RegexOptions.IgnoreCase), "Java servlet container"),
        (new Regex("^ASP\\.NET_SessionId$", RegexOptions.IgnoreCase), "ASP.NET"),
        (new Regex("^laravel_session$"), "Laravel"),
        (new Regex("^ci_session$"), "CodeIgniter"),
        (new Regex("^(wordpress_|wp-settings-)"), "WordPress"),
        (new Regex("^(csrftoken|sessionid)$"), "Django"),
        (new Regex("^_[a-z0-9_]+_session$"), "Ruby on Rails"),
        (new Regex("^connect\\.sid$"), "Express (Node.js)"),
        (new Regex("^S?SESS[0-9a-f]{32}$"), "Drupal"),
    ];

    public static List<ServiceArtifact> Detect(HttpDetails http, string address)
    {
        var found = new List<ServiceArtifact>();
        var https = http.Scheme == "https";

        foreach (var (name, value) in http.Headers)
        {
            var header = name.ToLowerInvariant();
            foreach (var rule in HeaderRules.Where(r => Matches(r.Name, header) && (r.When?.Invoke(value) ?? true)))
            {
                var tags = rule.Tags.Contains("tech-hint") && Version().IsMatch(value) ? [.. rule.Tags, "version-leak"] : rule.Tags;
                Add(found, "header", header, value, rule.Reason, tags, rule.Severity);
            }
            if (InternalAddress(value, address) is { } leaked)
                Add(found, "header", header, value, $"Discloses internal address {leaked}", ["internal-ip-leak"], "low");
        }
        if (https && !http.Headers.Keys.Any(k => k.Equals("strict-transport-security", StringComparison.OrdinalIgnoreCase)))
            Add(found, "header", "strict-transport-security", null, "HSTS header missing on HTTPS", ["missing-hsts"], "info");

        foreach (var cookie in http.Cookies)
        {
            if (CookieRules.FirstOrDefault(r => r.Name.IsMatch(cookie.Name)).Technology is { } technology)
                Add(found, "cookie", cookie.Name, cookie.DecodedValue, $"Cookie reveals {technology}", ["tech-hint"], "info");
            if (cookie.DecodedValue is not null && InternalAddress(cookie.DecodedValue, address) is { } member)
                Add(found, "cookie", cookie.Name, cookie.DecodedValue, $"Load balancer cookie discloses internal pool member {member}", ["internal-ip-leak"], "low");
            if (IsSessionCookie(cookie.Name))
            {
                var missing = new[] { https && !cookie.Secure ? "Secure" : null, cookie.HttpOnly ? null : "HttpOnly" }.OfType<string>().ToList();
                if (missing.Count > 0)
                    Add(found, "cookie", cookie.Name, null, $"Session cookie without {string.Join(" and ", missing)} flag", ["insecure-cookie"], "low");
            }
        }

        var path = Uri.TryCreate(http.FinalUrl ?? http.Url, UriKind.Absolute, out var uri) ? uri.AbsolutePath : "";
        if (http.PageType == "login" || (http.Title is { } t && LoginTitle().IsMatch(t)))
            Add(found, "page", "login", http.Title, http.PageType == "login" ? "Login page (page classification)" : "Login page (title)", ["login-page"], "info");
        if ((http.Title is { } title && AdminTitle().IsMatch(title)) || AdminPath().IsMatch(path))
            Add(found, "page", "admin", http.Title ?? path, "Administrative interface", ["admin-page"], "info");
        if (Header(http, "www-authenticate") is { } challenge)
            Add(found, "page", "http-auth", challenge, "Requires HTTP authentication", ["login-page"], "info");
        return found;
    }

    /// <summary>Adds the artifact or merges it into the one with the same kind and name (reasons and tags united, highest severity).</summary>
    public static void Add(List<ServiceArtifact> artifacts, string kind, string name, string? value, string reason, IEnumerable<string> tags, string severity)
    {
        var existing = artifacts.FirstOrDefault(a => a.Kind == kind && a.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (existing is null)
        {
            artifacts.Add(new ServiceArtifact { Kind = kind, Name = name, Value = Truncate(value), Reason = reason, Tags = [.. tags.Distinct()], Severity = severity });
            return;
        }
        existing.Value ??= Truncate(value);
        if (!existing.Reason.Contains(reason, StringComparison.Ordinal)) existing.Reason = $"{existing.Reason}; {reason}";
        existing.Tags = [.. existing.Tags.Union(tags)];
        if (severity == "low") existing.Severity = "low";
    }

    public static string? Header(HttpDetails http, string name) =>
        http.Headers.FirstOrDefault(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value is { Length: > 0 } v ? v : null;

    private static bool Matches(string pattern, string header) =>
        pattern.EndsWith('*') ? header.StartsWith(pattern[..^1], StringComparison.Ordinal) : header == pattern;

    /// <summary>Session cookies (not CSRF tokens) should carry HttpOnly and, over HTTPS, Secure.</summary>
    private static bool IsSessionCookie(string name) =>
        SessionName().IsMatch(name) && !name.Contains("csrf", StringComparison.OrdinalIgnoreCase) && !name.Contains("xsrf", StringComparison.OrdinalIgnoreCase);

    /// <summary>First private IPv4 address in <paramref name="text"/> other than the scanned address itself.</summary>
    private static string? InternalAddress(string text, string address)
    {
        foreach (Match m in Ipv4().Matches(text))
        {
            if (!IPAddress.TryParse(m.Value, out var ip) || m.Value == address) continue;
            var b = ip.GetAddressBytes();
            if (b[0] == 10 || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168)) return m.Value;
        }
        return null;
    }

    private static string? Truncate(string? value) =>
        value is null ? null : value.Length > MaxValueLength ? value[..MaxValueLength] + "…" : value;

    [GeneratedRegex(@"\d+\.\d+")]
    private static partial Regex Version();

    [GeneratedRegex(@"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")]
    private static partial Regex Ipv4();

    [GeneratedRegex(@"sess|sid$|^sid|auth|token|jwt", RegexOptions.IgnoreCase)]
    private static partial Regex SessionName();

    [GeneratedRegex(@"\b(log\s?in|sign\s?in|log\s?on|anmelden|authentication required)\b", RegexOptions.IgnoreCase)]
    private static partial Regex LoginTitle();

    [GeneratedRegex(@"\b(admin\w*|dashboard|control panel|management console|webmin|phpmyadmin|cpanel)\b", RegexOptions.IgnoreCase)]
    private static partial Regex AdminTitle();

    [GeneratedRegex(@"^/(admin|administrator|wp-admin|phpmyadmin|manager/html)(/|$)", RegexOptions.IgnoreCase)]
    private static partial Regex AdminPath();
}
