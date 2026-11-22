using System.Runtime.CompilerServices;
using System.Text.Json;
using WebScan.Agent.Tools.Abstractions;
using WebScan.Contracts;

namespace WebScan.Agent.Tools.Parsers;

/// <summary>
/// Declarative JSONL mapping so new JSON-emitting tools need only a manifest. <c>parserOptions</c>:
/// <code>
/// { "kind": "TlsCertificate",                       // ObservationKind
///   "fields": { "address": "ip", "port": "port", "tls.subjectCommonName": "subject_cn", ... },  // target field → dotted JSON path
///   "attributes": { "name": "dotted.path" },         // extra masked key/values
///   "requireFields": ["tls.fingerprintSha256"],      // lines missing these are skipped
///   "discriminator": "tls.fingerprintSha256",        // target field that makes the observation id unique
///   "transport": "tcp" }
/// </code>
/// Supported target fields: <see cref="Fields"/>. Only the section matching <c>kind</c> is populated.
/// </summary>
public sealed class GenericJsonlParser : IToolOutputParser
{
    public string Id => "generic-jsonl";

    public static readonly IReadOnlySet<string> Fields = new HashSet<string>(StringComparer.Ordinal)
    {
        "address", "hostname", "port", "transport",
        "host.status", "host.reason", "host.macAddress", "host.osGuess",
        "port.state", "port.reason",
        "service.name", "service.product", "service.version", "service.extraInfo", "service.banner", "service.tunnel", "service.cpe",
        "http.url", "http.scheme", "http.statusCode", "http.title", "http.webServer", "http.contentType", "http.contentLength",
        "http.finalUrl", "http.faviconHash", "http.bodySha256", "http.technologies",
        "tls.subjectCommonName", "tls.subjectAlternativeNames", "tls.issuer", "tls.notBefore", "tls.notAfter", "tls.serialNumber",
        "tls.fingerprintSha256", "tls.tlsVersion", "tls.cipher", "tls.selfSigned",
        "technology.name", "technology.version", "technology.category",
        "signature.signatureId", "signature.name", "signature.severity", "signature.matcherName", "signature.matchedAt",
        "signature.extractedResults", "signature.tags", "signature.evidence",
        "dns.name", "dns.recordType", "dns.values",
    };

    private sealed record Options
    {
        public ObservationKind Kind { get; init; } = ObservationKind.Generic;
        public Dictionary<string, string> Fields { get; init; } = [];
        public Dictionary<string, string> Attributes { get; init; } = [];
        public List<string> RequireFields { get; init; } = [];
        public string? Discriminator { get; init; }
        public TransportProtocol Transport { get; init; } = TransportProtocol.Tcp;
    }

    public IReadOnlyList<string> ValidateOptions(JsonElement? options)
    {
        if (options is null) return ["parserOptions are required (kind, fields)."];
        Options o;
        try { o = options.Value.Deserialize<Options>(ToolManifestJson.Options) ?? new Options(); }
        catch (JsonException ex) { return [ex.Message]; }

        var errors = new List<string>();
        if (!o.Fields.ContainsKey("address")) errors.Add("fields.address is required.");
        errors.AddRange(o.Fields.Keys.Where(k => !Fields.Contains(k)).Select(k => $"unknown target field '{k}'."));
        errors.AddRange(o.Fields.Where(kv => string.IsNullOrWhiteSpace(kv.Value)).Select(kv => $"field '{kv.Key}' has no JSON path."));
        errors.AddRange(o.RequireFields.Where(f => !o.Fields.ContainsKey(f)).Select(f => $"requireFields '{f}' is not mapped."));
        if (o.Discriminator is not null && !o.Fields.ContainsKey(o.Discriminator)) errors.Add($"discriminator '{o.Discriminator}' is not mapped.");
        if (o.Attributes.Keys.Any(string.IsNullOrWhiteSpace)) errors.Add("attribute names must not be empty.");
        return errors;
    }

    public async IAsyncEnumerable<DiscoveryObservation> ParseAsync(Stream output, ParseContext context, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var o = context.ParserOptions?.Deserialize<Options>(ToolManifestJson.Options) ?? throw new InvalidOperationException("generic-jsonl requires parserOptions.");
        await foreach (var line in Jsonl.ReadAsync(output, cancellationToken))
        {
            var values = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            foreach (var (field, path) in o.Fields)
                if (line.Get(path) is { } v) values[field] = v;
            if (o.RequireFields.Any(f => !values.ContainsKey(f))) continue;

            string? S(string f) => values.TryGetValue(f, out var v) ? v.AsString() : null;
            JsonElement? E(string f) => values.TryGetValue(f, out var v) ? v : null;

            var address = S("address");
            if (address is null) continue;
            var transport = S("transport") is { } t ? (t.Equals("udp", StringComparison.OrdinalIgnoreCase) ? TransportProtocol.Udp : TransportProtocol.Tcp) : o.Transport;
            var port = E("port").AsInt();
            var discriminator = o.Discriminator is null ? null : S(o.Discriminator);

            var attributes = o.Attributes
                .Select(kv => (kv.Key, Value: line.Get(kv.Value)?.AsString()))
                .Where(a => a.Value is not null)
                .ToDictionary(a => a.Key, a => ParseContext.MaskText(a.Value, ParseContext.MaxEvidenceLength)!);

            var observation = context.NewObservation(o.Kind, address, port, port is null ? null : transport, discriminator) with
            {
                Hostname = S("hostname"),
                Attributes = attributes.Count > 0 ? attributes : null,
            };

            yield return o.Kind switch
            {
                ObservationKind.HostUp or ObservationKind.HostDown => observation with
                {
                    Host = new HostDetails
                    {
                        Status = S("host.status") ?? (o.Kind == ObservationKind.HostUp ? "up" : "down"),
                        Reason = S("host.reason"), MacAddress = S("host.macAddress"), OsGuess = S("host.osGuess"),
                    },
                },
                ObservationKind.PortOpen or ObservationKind.PortClosed => observation with
                {
                    PortState = new PortDetails { State = S("port.state") ?? (o.Kind == ObservationKind.PortOpen ? "open" : "closed"), Reason = S("port.reason") },
                },
                ObservationKind.Service => observation with
                {
                    Service = new ServiceDetails
                    {
                        Name = S("service.name") ?? "unknown", Product = S("service.product"), Version = S("service.version"),
                        ExtraInfo = S("service.extraInfo"), Banner = ParseContext.MaskText(S("service.banner"), ParseContext.MaxBannerLength),
                        Tunnel = S("service.tunnel"), Cpe = E("service.cpe").AsList(),
                    },
                },
                ObservationKind.HttpResponse => observation with
                {
                    Http = new HttpDetails
                    {
                        Url = S("http.url") ?? $"{S("http.scheme") ?? "http"}://{HostPart(address)}{(port is null ? "" : $":{port}")}/",
                        Scheme = S("http.scheme") ?? "http", StatusCode = E("http.statusCode").AsInt(), Title = S("http.title"),
                        WebServer = S("http.webServer"), ContentType = S("http.contentType"), ContentLength = E("http.contentLength").AsLong(),
                        FinalUrl = S("http.finalUrl"), FaviconHash = S("http.faviconHash"), BodySha256 = S("http.bodySha256"),
                        Technologies = E("http.technologies").AsList(),
                    },
                },
                ObservationKind.TlsCertificate => observation with
                {
                    Tls = new TlsDetails
                    {
                        SubjectCommonName = S("tls.subjectCommonName"), SubjectAlternativeNames = E("tls.subjectAlternativeNames").AsList(),
                        Issuer = S("tls.issuer"), NotBefore = E("tls.notBefore").AsDate(), NotAfter = E("tls.notAfter").AsDate(),
                        SerialNumber = S("tls.serialNumber"), FingerprintSha256 = S("tls.fingerprintSha256")?.ToLowerInvariant(),
                        TlsVersion = S("tls.tlsVersion"), Cipher = S("tls.cipher"), SelfSigned = E("tls.selfSigned").AsBool(),
                    },
                },
                ObservationKind.Technology => observation with
                {
                    Technology = new TechnologyDetails { Name = S("technology.name") ?? "unknown", Version = S("technology.version"), Category = S("technology.category") },
                    Confidence = new Confidence { Score = 0.7, Method = "tool-reported" },
                },
                ObservationKind.SignatureMatch => observation with
                {
                    Signature = new SignatureMatchDetails
                    {
                        SignatureId = S("signature.signatureId") ?? "unknown", Name = S("signature.name") ?? S("signature.signatureId") ?? "unknown",
                        Severity = S("signature.severity")?.ToLowerInvariant() ?? "info", MatcherName = S("signature.matcherName"),
                        MatchedAt = S("signature.matchedAt"), ExtractedResults = E("signature.extractedResults").AsList(), Tags = E("signature.tags").AsList(),
                        Evidence = ParseContext.MaskText(S("signature.evidence"), ParseContext.MaxEvidenceLength),
                    },
                },
                ObservationKind.DnsRecord => observation with
                {
                    Dns = new DnsDetails { Name = S("dns.name") ?? address, RecordType = S("dns.recordType") ?? "A", Values = E("dns.values").AsList() },
                },
                _ => observation,
            };
        }
    }

    private static string HostPart(string address) =>
        System.Net.IPAddress.TryParse(address, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? $"[{address}]" : address;
}
