using System.Net;
using System.Text.RegularExpressions;
using WebScan.Contracts;
using WebScan.Server.Kernel.Discovery;

namespace WebScan.Server.Modules.Discovery.Normalization;

/// <summary>
/// Server-side canonicalization so facts reported by different tools merge: addresses, hostnames,
/// service names and technology names. Also re-applies secret masking (defence in depth).
/// </summary>
public static partial class Normalizer
{
    private static readonly Dictionary<string, string> ServiceAliases = new(StringComparer.Ordinal)
    {
        ["www"] = "http", ["www-http"] = "http", ["http-alt"] = "http", ["http-proxy"] = "http", ["httpd"] = "http",
        ["http-mgmt"] = "http", ["https-alt"] = "https", ["http-ssl"] = "https", ["ssl/http"] = "https", ["ssl/https"] = "https",
        ["ssl/http-alt"] = "https", ["ms-wbt-server"] = "rdp", ["domain"] = "dns", ["microsoft-ds"] = "smb", ["postgres"] = "postgresql",
        ["ssl/imap"] = "imaps", ["ssl/pop3"] = "pop3s", ["ssl/smtp"] = "smtps", ["mongod"] = "mongodb",
    };

    private static readonly Dictionary<string, (string Name, string Category)> TechnologyAliases = BuildTechnologyAliases();

    [GeneratedRegex(@"^\d{1,3}(\.\d{1,3}){3}$")]
    private static partial Regex DottedQuad();

    [GeneratedRegex(@"\s+")]
    private static partial Regex Whitespace();

    /// <summary>Canonical IP text (IPv4-mapped → IPv4, compressed lowercase IPv6, decimal octets) or a canonical hostname.</summary>
    public static string? CanonicalAddress(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var s = raw.Trim();
        if (s.StartsWith('[') && s.EndsWith(']')) s = s[1..^1];

        if (DottedQuad().IsMatch(s))
        {
            // Parsed by hand: IPAddress.Parse would read "010.0.0.1" as octal.
            var parts = s.Split('.');
            var bytes = new byte[4];
            for (var i = 0; i < 4; i++)
                if (!byte.TryParse(parts[i], out bytes[i])) return null;
            return new IPAddress(bytes).ToString();
        }

        if (s.Contains(':') && IPAddress.TryParse(s, out var ip))
        {
            ip = new IPAddress(ip.GetAddressBytes()); // drops %scope
            return (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString();
        }

        return CanonicalHostname(s);
    }

    /// <summary>Lowercase, trimmed, without trailing dot; null when empty or not a plausible DNS name.</summary>
    public static string? CanonicalHostname(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var s = raw.Trim().TrimEnd('.').ToLowerInvariant();
        if (s.Length == 0 || s.Length > 253 || s.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_' or '*'))) return null;
        return s;
    }

    /// <summary>Canonical service name: lowercase, aliases resolved, TLS-wrapped http → https, empty → "unknown".</summary>
    public static string CanonicalServiceName(string? name, string? tunnel = null)
    {
        var n = (name ?? "").Trim().ToLowerInvariant().TrimEnd('?');
        if (n.Length == 0) return "unknown";
        if (ServiceAliases.TryGetValue(n, out var alias)) n = alias;
        else if (n.StartsWith("ssl/") || n.StartsWith("tls/"))
        {
            n = CanonicalServiceName(n[4..]);
            if (n == "http") n = "https";
        }
        if (n == "http" && string.Equals(tunnel, "ssl", StringComparison.OrdinalIgnoreCase)) n = "https";
        return n;
    }

    /// <summary>Canonical technology name/version/category; splits "Nginx:1.19.0" style names. Key = lowercase name.</summary>
    public static (string Name, string? Version, string? Category, string Key) CanonicalTechnology(string name, string? version, string? category)
    {
        var n = Whitespace().Replace(name.Trim(), " ");
        var v = string.IsNullOrWhiteSpace(version) ? null : version.Trim();
        var colon = n.LastIndexOf(':');
        if (v is null && colon > 0 && colon < n.Length - 1 && char.IsDigit(n[colon + 1]))
        {
            v = n[(colon + 1)..].Trim();
            n = n[..colon].Trim();
        }

        var c = string.IsNullOrWhiteSpace(category) ? null : category.Trim().ToLowerInvariant();
        if (TechnologyAliases.TryGetValue(n.ToLowerInvariant(), out var known))
        {
            n = known.Name;
            c ??= known.Category;
        }
        return (n, v, c, n.ToLowerInvariant());
    }

    public static string CanonicalSeverity(string? severity)
    {
        var s = (severity ?? "").Trim().ToLowerInvariant();
        return Severities.IsValid(s) ? s : "info";
    }

    /// <summary>Re-masks secrets in free-text fields (banner, headers, evidence, attributes).</summary>
    public static DiscoveryObservation Mask(DiscoveryObservation o) => o with
    {
        Service = o.Service is null ? null : o.Service with { Banner = MaskText(o.Service.Banner, 1024) },
        Http = o.Http is null ? null : o.Http with { Headers = SensitiveDataMasker.MaskHeaders(o.Http.Headers) },
        Signature = o.Signature is null ? null : o.Signature with
        {
            Evidence = MaskText(o.Signature.Evidence, 2048),
            ExtractedResults = o.Signature.ExtractedResults.Select(r => SensitiveDataMasker.MaskTokens(r)).ToList(),
        },
        Attributes = o.Attributes?.ToDictionary(a => a.Key, a => SensitiveDataMasker.MaskTokens(a.Value)),
    };

    /// <summary>Canonical copy of the observation, or null when it has no usable address / invalid port.</summary>
    public static DiscoveryObservation? Normalize(DiscoveryObservation o)
    {
        var address = CanonicalAddress(o.Address);
        if (address is null || o.Port is < 0 or > 65535) return null;
        TransportProtocol? transport = o.Port is null ? null : o.Transport ?? TransportProtocol.Tcp;

        return o with
        {
            Address = address,
            Hostname = CanonicalHostname(o.Hostname),
            Transport = transport,
            Host = o.Host is null ? null : o.Host with
            {
                Status = o.Host.Status.Trim().ToLowerInvariant(),
                Hostnames = o.Host.Hostnames.Select(CanonicalHostname).OfType<string>().Distinct().ToList(),
            },
            PortState = o.PortState is null ? null : o.PortState with { State = o.PortState.State.Trim().ToLowerInvariant() },
            Service = o.Service is null ? null : o.Service with
            {
                Name = CanonicalServiceName(o.Service.Name, o.Service.Tunnel),
                Product = Clean(o.Service.Product),
                Version = Clean(o.Service.Version),
            },
            Http = o.Http is null ? null : o.Http with { Scheme = o.Http.Scheme.Trim().ToLowerInvariant(), Title = Clean(o.Http.Title), WebServer = Clean(o.Http.WebServer) },
            Technology = o.Technology is null ? null : CanonicalTechnologyDetails(o.Technology),
            Signature = o.Signature is null ? null : o.Signature with { Severity = CanonicalSeverity(o.Signature.Severity) },
            Tls = o.Tls is null ? null : o.Tls with { FingerprintSha256 = o.Tls.FingerprintSha256?.Replace(":", "").Trim().ToLowerInvariant() },
            Dns = o.Dns is null ? null : o.Dns with { Name = CanonicalHostname(o.Dns.Name) ?? o.Dns.Name, RecordType = o.Dns.RecordType.Trim().ToUpperInvariant() },
        };
    }

    private static TechnologyDetails CanonicalTechnologyDetails(TechnologyDetails t)
    {
        var (name, version, category, _) = CanonicalTechnology(t.Name, t.Version, t.Category);
        return t with { Name = name, Version = version, Category = category };
    }

    private static string? Clean(string? s) => string.IsNullOrWhiteSpace(s) ? null : Whitespace().Replace(s.Trim(), " ");

    private static string? MaskText(string? s, int max)
    {
        if (string.IsNullOrEmpty(s)) return s;
        var masked = SensitiveDataMasker.MaskTokens(s);
        return masked.Length > max ? masked[..max] : masked;
    }

    private static Dictionary<string, (string, string)> BuildTechnologyAliases()
    {
        var map = new Dictionary<string, (string, string)>(StringComparer.Ordinal);
        void Add(string name, string category, params string[] aliases)
        {
            map[name.ToLowerInvariant()] = (name, category);
            foreach (var a in aliases) map[a] = (name, category);
        }

        Add("nginx", "web-server");
        Add("OpenResty", "web-server");
        Add("Apache HTTP Server", "web-server", "apache", "apache httpd", "httpd", "apache2");
        Add("Apache Tomcat", "web-server", "tomcat", "apache-coyote", "apache tomcat/coyote jsp engine");
        Add("Microsoft IIS", "web-server", "iis", "microsoft-iis", "microsoft iis httpd");
        Add("lighttpd", "web-server");
        Add("Caddy", "web-server");
        Add("OpenSSH", "remote-access");
        Add("WordPress", "cms");
        Add("Drupal", "cms");
        Add("Joomla", "cms");
        Add("PHP", "language");
        Add("Node.js", "language", "nodejs", "node");
        Add("jQuery", "javascript-library");
        Add("Bootstrap", "ui-framework");
        Add("React", "javascript-framework");
        Add("Express", "framework");
        Add("ASP.NET", "framework", "microsoft asp.net");
        Add("MySQL", "database");
        Add("PostgreSQL", "database", "postgresql db");
        Add("Redis", "database", "redis key-value store");
        Add("MongoDB", "database");
        Add("Cloudflare", "cdn");
        return map;
    }
}
