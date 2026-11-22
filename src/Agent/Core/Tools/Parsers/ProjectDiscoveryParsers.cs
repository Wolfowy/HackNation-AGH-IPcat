using System.Runtime.CompilerServices;
using System.Text.Json;
using WebScan.Agent.Tools.Abstractions;
using WebScan.Contracts;

namespace WebScan.Agent.Tools.Parsers;

/// <summary><c>naabu -json</c>: one open port per line (<c>ip</c>, <c>host</c>, <c>port</c>, <c>protocol</c>, <c>tls</c>).</summary>
public sealed class NaabuJsonlParser : IToolOutputParser
{
    public string Id => "naabu-jsonl";

    public async IAsyncEnumerable<DiscoveryObservation> ParseAsync(Stream output, ParseContext context, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (var line in Jsonl.ReadAsync(output, cancellationToken))
        {
            var host = line.Str("host");
            var address = line.Str("ip") ?? host;
            if (address is null || line.Get("port").AsInt() is not { } port) continue;
            var transport = line.Str("protocol") == "udp" ? TransportProtocol.Udp : TransportProtocol.Tcp;
            yield return context.NewObservation(ObservationKind.PortOpen, address, port, transport, observedAt: line.Get("timestamp").AsDate()) with
            {
                Hostname = host is not null && host != address ? host : null,
                PortState = new PortDetails { State = "open", Reason = transport == TransportProtocol.Tcp ? "syn-ack" : null },
                Attributes = line.Get("tls").AsBool() is true ? new Dictionary<string, string> { ["tls"] = "true" } : null,
            };
        }
    }
}

/// <summary>
/// <c>httpx -json</c>: HttpResponse per URL (headers masked, cookies without values, body hash, favicon mmh3/md5, redirects, page type,
/// CDN/WAF), plus
/// Technology observations for <c>tech</c> entries and a TlsCertificate observation for the <c>tls</c> block.
/// </summary>
public sealed class HttpxJsonlParser : IToolOutputParser
{
    public string Id => "httpx-jsonl";

    public async IAsyncEnumerable<DiscoveryObservation> ParseAsync(Stream output, ParseContext context, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (var line in Jsonl.ReadAsync(output, cancellationToken))
        {
            if (line.Get("failed").AsBool() is true) continue;
            var url = line.Str("url");
            if (url is null) continue;
            var (urlHost, urlPort) = Jsonl.HostPort(url);
            var host = line.Str("host");
            var address = line.Str("host_ip") ?? (Jsonl.IsIp(host) ? host : null) ?? line.Get("a").AsList().FirstOrDefault() ?? urlHost;
            if (address is null) continue;
            var hostname = host is not null && !Jsonl.IsIp(host) ? host : urlHost is not null && !Jsonl.IsIp(urlHost) ? urlHost : null;
            var port = line.Get("port").AsInt() ?? urlPort;
            var observedAt = line.Get("timestamp").AsDate();

            var headers = Headers(line.Get("header"));
            var cookies = HttpCookies.Parse(headers.GetValueOrDefault("set-cookie"));
            var tech = line.Get("tech").AsList();
            var finalUrl = line.Str("final_url");
            yield return context.NewObservation(ObservationKind.HttpResponse, address, port, TransportProtocol.Tcp, url, observedAt) with
            {
                Hostname = hostname,
                Http = new HttpDetails
                {
                    Url = url,
                    Scheme = line.Str("scheme") ?? new Uri(url).Scheme,
                    StatusCode = line.Get("status_code").AsInt(),
                    Title = line.Str("title"),
                    WebServer = line.Str("webserver"),
                    ContentType = line.Str("content_type"),
                    ContentLength = line.Get("content_length").AsLong(),
                    Headers = SensitiveDataMasker.MaskHeaders(headers),
                    CookieNames = [.. cookies.Select(c => c.Name).Distinct(StringComparer.Ordinal)],
                    Cookies = cookies,
                    RedirectChain = RedirectChain(url, line.Str("location"), finalUrl),
                    RedirectStatusCodes = [.. line.Get("chain_status_codes").AsList().Select(c => int.TryParse(c, out var code) ? code : 0).Where(c => c > 0)],
                    FinalUrl = finalUrl,
                    FaviconHash = line.Str("favicon"),
                    FaviconMd5 = line.Str("favicon_md5")?.ToLowerInvariant(),
                    PageType = line.Str("knowledgebase.PageType")?.ToLowerInvariant(),
                    Cdn = line.Str("cdn_name"),
                    CdnType = line.Str("cdn_type"),
                    BodySha256 = line.Str("hash.body_sha256"),
                    Technologies = tech,
                },
            };

            foreach (var entry in tech)
            {
                var colon = entry.IndexOf(':');
                var name = colon > 0 ? entry[..colon] : entry;
                yield return context.NewObservation(ObservationKind.Technology, address, port, TransportProtocol.Tcp, name.ToLowerInvariant(), observedAt) with
                {
                    Hostname = hostname,
                    Technology = new TechnologyDetails { Name = name, Version = colon > 0 ? entry[(colon + 1)..] : null },
                    Confidence = new Confidence { Score = 0.8, Method = "tool-reported" },
                };
            }

            if (line.Get("tls") is { } tls && Tls(tls) is { } details)
                yield return context.NewObservation(ObservationKind.TlsCertificate, address, port, TransportProtocol.Tcp, details.FingerprintSha256, observedAt) with
                {
                    Hostname = hostname,
                    Tls = details,
                };
        }
    }

    /// <summary>Maps the TLS block shared by httpx and tlsx (<c>subject_cn</c>, <c>fingerprint_hash.sha256</c>, ...).</summary>
    internal static TlsDetails? Tls(JsonElement tls)
    {
        if (tls.Get("probe_status").AsBool() is false) return null;
        var fingerprint = tls.Str("fingerprint_hash.sha256");
        if (fingerprint is null && tls.Str("subject_cn") is null) return null;
        return new TlsDetails
        {
            SubjectCommonName = tls.Str("subject_cn"),
            SubjectDn = tls.Str("subject_dn"),
            SubjectAlternativeNames = tls.Get("subject_an").AsList(),
            Issuer = tls.Str("issuer_dn"),
            NotBefore = tls.Get("not_before").AsDate(),
            NotAfter = tls.Get("not_after").AsDate(),
            SerialNumber = tls.Str("serial"),
            FingerprintSha256 = fingerprint?.ToLowerInvariant(),
            TlsVersion = tls.Str("tls_version"),
            Cipher = tls.Str("cipher"),
            SelfSigned = tls.Get("self_signed").AsBool(),
        };
    }

    /// <summary>httpx reports header names in snake_case; convert to the usual dashed form so masking rules apply.</summary>
    private static Dictionary<string, string> Headers(JsonElement? header)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (header is not { ValueKind: JsonValueKind.Object } obj) return result;
        foreach (var p in obj.EnumerateObject())
            if (p.Value.AsString() is { } value) result[p.Name.Replace('_', '-')] = value;
        return result;
    }

    /// <summary>Requested URL, the (resolved) <c>Location</c> it pointed to and the final URL; empty when nothing redirected.</summary>
    private static IReadOnlyList<string> RedirectChain(string url, string? location, string? finalUrl)
    {
        var next = location is not null && Uri.TryCreate(url, UriKind.Absolute, out var requested) && Uri.TryCreate(requested, location, out var resolved)
            ? resolved.ToString()
            : location;
        List<string> chain = [url, .. new[] { next, finalUrl }.OfType<string>()];
        return chain.Distinct(StringComparer.Ordinal).ToList() is { Count: > 1 } distinct ? distinct : [];
    }
}

/// <summary><c>nuclei -jsonl</c>: SignatureMatch per result; evidence = masked, truncated raw response (or extracted results).</summary>
public sealed class NucleiJsonlParser : IToolOutputParser
{
    public string Id => "nuclei-jsonl";

    public async IAsyncEnumerable<DiscoveryObservation> ParseAsync(Stream output, ParseContext context, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (var line in Jsonl.ReadAsync(output, cancellationToken))
        {
            var templateId = line.Str("template-id");
            if (templateId is null || line.Get("matcher-status").AsBool() is false) continue;
            var matchedAt = line.Str("matched-at") ?? line.Str("url");
            var (urlHost, urlPort) = Jsonl.HostPort(matchedAt ?? line.Str("host"));
            var host = line.Str("host");
            var hostOnly = Jsonl.HostPort(host).Host ?? host;
            var address = line.Str("ip") ?? (Jsonl.IsIp(hostOnly) ? hostOnly : null) ?? urlHost;
            if (address is null) continue;
            var port = line.Get("port").AsInt() ?? urlPort;
            var matcher = line.Str("matcher-name");
            var extracted = line.Get("extracted-results").AsList();

            yield return context.NewObservation(ObservationKind.SignatureMatch, address, port, TransportProtocol.Tcp, $"{templateId}|{matcher}|{matchedAt}", line.Get("timestamp").AsDate()) with
            {
                Hostname = hostOnly is not null && !Jsonl.IsIp(hostOnly) ? hostOnly : null,
                Signature = new SignatureMatchDetails
                {
                    SignatureId = templateId,
                    SignatureVersion = context.Job.Signatures?.Items.FirstOrDefault(i => i.Id == templateId)?.Version,
                    Name = line.Str("info.name") ?? templateId,
                    Severity = line.Str("info.severity")?.ToLowerInvariant() ?? "info",
                    MatcherName = matcher,
                    MatchedAt = matchedAt,
                    ExtractedResults = [.. extracted.Select(e => ParseContext.MaskText(e, ParseContext.MaxEvidenceLength)!)],
                    Tags = line.Get("info.tags").AsList(),
                    Evidence = ParseContext.MaskHttpMessage(line.Str("response"), ParseContext.MaxEvidenceLength)
                               ?? (extracted.Count > 0 ? ParseContext.MaskText(string.Join("\n", extracted), ParseContext.MaxEvidenceLength) : null),
                },
                Confidence = new Confidence { Score = 0.9, Method = "signature-match" },
            };
        }
    }
}
