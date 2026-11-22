namespace WebScan.Contracts;

/// <summary>
/// Tool-independent, normalized fact observed during a scan. Every tool parser on the agent maps its native
/// output (Nmap XML, naabu/httpx/nuclei JSONL, generic JSONL...) into these records. Exactly the section that
/// matches <see cref="Kind"/> is populated (plus optional <see cref="Attributes"/>).
/// </summary>
public sealed record DiscoveryObservation
{
    /// <summary>
    /// Deterministic id: lowercase hex SHA-256 (first 32 chars) of JobId|Kind|Address|Port|Transport|kind-specific key.
    /// Lets the server deduplicate observations re-sent in retried batches. Use <see cref="ObservationIds.Compute"/>.
    /// </summary>
    public required string ObservationId { get; init; }

    public required ObservationKind Kind { get; init; }

    /// <summary>Normalized IP address (or hostname when it could not be resolved).</summary>
    public required string Address { get; init; }

    public string? Hostname { get; init; }
    public int? Port { get; init; }
    public TransportProtocol? Transport { get; init; }
    public required DateTimeOffset ObservedAt { get; init; }
    public required ObservationSource Source { get; init; }

    public HostDetails? Host { get; init; }
    public PortDetails? PortState { get; init; }
    public ServiceDetails? Service { get; init; }
    public HttpDetails? Http { get; init; }
    public TlsDetails? Tls { get; init; }
    public TechnologyDetails? Technology { get; init; }
    public SignatureMatchDetails? Signature { get; init; }
    public DnsDetails? Dns { get; init; }

    public Confidence? Confidence { get; init; }

    /// <summary>Extra key/values (e.g. from generic tools). Values must already be masked for secrets.</summary>
    public IReadOnlyDictionary<string, string>? Attributes { get; init; }
}

public enum ObservationKind
{
    HostUp,
    HostDown,
    PortOpen,
    PortClosed,
    Service,
    HttpResponse,
    TlsCertificate,
    Technology,
    SignatureMatch,
    DnsRecord,
    Generic,
}

public sealed record ObservationSource
{
    public required string ToolId { get; init; }
    public string? ToolVersion { get; init; }
    public required string AgentId { get; init; }
    public string? InterfaceName { get; init; }
    public required Guid JobId { get; init; }
}

public sealed record HostDetails
{
    /// <summary>"up" / "down".</summary>
    public required string Status { get; init; }

    /// <summary>Tool reason, e.g. "echo-reply", "syn-ack", "arp-response", "no-response".</summary>
    public string? Reason { get; init; }

    public double? LatencyMs { get; init; }
    public string? MacAddress { get; init; }
    public string? MacVendor { get; init; }
    public string? OsGuess { get; init; }
    public IReadOnlyList<string> Hostnames { get; init; } = [];
}

public sealed record PortDetails
{
    /// <summary>"open" / "closed" / "filtered" / "open|filtered".</summary>
    public required string State { get; init; }

    public string? Reason { get; init; }
}

public sealed record ServiceDetails
{
    /// <summary>Normalized service name, e.g. "http", "https", "ssh", "mysql", "unknown".</summary>
    public required string Name { get; init; }

    public string? Product { get; init; }
    public string? Version { get; init; }
    public string? ExtraInfo { get; init; }

    /// <summary>Raw banner (truncated to 1024 chars, secrets masked).</summary>
    public string? Banner { get; init; }

    /// <summary>"ssl" when wrapped in TLS.</summary>
    public string? Tunnel { get; init; }

    public IReadOnlyList<string> Cpe { get; init; } = [];
}

public sealed record HttpDetails
{
    public required string Url { get; init; }
    public required string Scheme { get; init; }
    public int? StatusCode { get; init; }
    public string? Title { get; init; }
    public string? WebServer { get; init; }
    public string? ContentType { get; init; }
    public long? ContentLength { get; init; }

    /// <summary>Response headers; cookie values and tokens are masked (see <see cref="SensitiveDataMasker"/>).</summary>
    public IReadOnlyDictionary<string, string> Headers { get; init; } = new Dictionary<string, string>();

    /// <summary>Names only, never values.</summary>
    public IReadOnlyList<string> CookieNames { get; init; } = [];

    /// <summary>Parsed <c>Set-Cookie</c> headers: name and attributes, never values (see <see cref="HttpCookies"/>).</summary>
    public IReadOnlyList<HttpCookie> Cookies { get; init; } = [];

    /// <summary>Requested URL, intermediate <c>Location</c> and final URL (when the response redirected).</summary>
    public IReadOnlyList<string> RedirectChain { get; init; } = [];

    /// <summary>Status codes of the followed redirect chain, e.g. [301, 200].</summary>
    public IReadOnlyList<int> RedirectStatusCodes { get; init; } = [];

    public string? FinalUrl { get; init; }

    /// <summary>Shodan-style mmh3 hash of the favicon (as string).</summary>
    public string? FaviconHash { get; init; }

    /// <summary>Lowercase hex MD5 of the favicon (matches Rapid7 recog favicon fingerprints).</summary>
    public string? FaviconMd5 { get; init; }

    /// <summary>Page classification of the probe tool (httpx <c>-kb</c>), e.g. "login", "error", "parked".</summary>
    public string? PageType { get; init; }

    /// <summary>CDN/WAF in front of the endpoint (httpx <c>-cdn</c>), e.g. "cloudflare".</summary>
    public string? Cdn { get; init; }

    /// <summary>"cdn", "waf" or "cloud".</summary>
    public string? CdnType { get; init; }

    /// <summary>SHA-256 of the response body (for change detection without storing bodies).</summary>
    public string? BodySha256 { get; init; }

    /// <summary>Technologies reported by the probe tool (also emitted as separate Technology observations).</summary>
    public IReadOnlyList<string> Technologies { get; init; } = [];
}

/// <summary>One <c>Set-Cookie</c> header without its value.</summary>
public sealed record HttpCookie
{
    public required string Name { get; init; }
    public bool Secure { get; init; }
    public bool HttpOnly { get; init; }

    /// <summary>"Strict" / "Lax" / "None" as sent; null when absent.</summary>
    public string? SameSite { get; init; }

    public string? Domain { get; init; }
    public string? Path { get; init; }

    /// <summary>
    /// Non-secret information decoded from the value before it was dropped, e.g. the internal "10.1.1.100:8080" pool member of an
    /// F5 BIG-IP persistence cookie.
    /// </summary>
    public string? DecodedValue { get; init; }
}

public sealed record TlsDetails
{
    public string? SubjectCommonName { get; init; }

    /// <summary>Full subject DN, e.g. "CN=printer.local, O=Example".</summary>
    public string? SubjectDn { get; init; }

    public IReadOnlyList<string> SubjectAlternativeNames { get; init; } = [];
    public string? Issuer { get; init; }
    public DateTimeOffset? NotBefore { get; init; }
    public DateTimeOffset? NotAfter { get; init; }
    public string? SerialNumber { get; init; }

    /// <summary>Lowercase hex SHA-256 of the DER certificate; primary key for certificate change detection.</summary>
    public string? FingerprintSha256 { get; init; }

    public string? TlsVersion { get; init; }
    public string? Cipher { get; init; }
    public bool? SelfSigned { get; init; }
}

public sealed record TechnologyDetails
{
    public required string Name { get; init; }
    public string? Version { get; init; }

    /// <summary>e.g. "cms", "web-server", "framework", "language", "network-device".</summary>
    public string? Category { get; init; }
}

public sealed record SignatureMatchDetails
{
    /// <summary>Signature (template) id.</summary>
    public required string SignatureId { get; init; }

    public int? SignatureVersion { get; init; }
    public required string Name { get; init; }

    /// <summary>"info" / "low" / "medium" / "high" / "critical".</summary>
    public required string Severity { get; init; }

    public string? MatcherName { get; init; }
    public string? MatchedAt { get; init; }
    public IReadOnlyList<string> ExtractedResults { get; init; } = [];
    public IReadOnlyList<string> Tags { get; init; } = [];

    /// <summary>Short, masked evidence (e.g. matched response fragment), max 2048 chars.</summary>
    public string? Evidence { get; init; }
}

public sealed record DnsDetails
{
    public required string Name { get; init; }

    /// <summary>"A", "AAAA", "CNAME", "PTR", "MX", "TXT", ...</summary>
    public required string RecordType { get; init; }

    public IReadOnlyList<string> Values { get; init; } = [];
}

public sealed record Confidence
{
    /// <summary>0.0 – 1.0.</summary>
    public required double Score { get; init; }

    /// <summary>How the score was derived, e.g. "tool-reported", "banner-match", "version-probe", "signature-match", "port-heuristic".</summary>
    public required string Method { get; init; }
}

public static class ObservationIds
{
    public static string Compute(Guid jobId, ObservationKind kind, string address, int? port, TransportProtocol? transport, string? discriminator = null)
    {
        var input = $"{jobId:N}|{kind}|{address.ToLowerInvariant()}|{port}|{transport}|{discriminator}";
        var hash = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(input));
        return Convert.ToHexStringLower(hash)[..32];
    }
}
