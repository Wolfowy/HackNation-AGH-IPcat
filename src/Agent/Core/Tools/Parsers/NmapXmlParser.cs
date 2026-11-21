using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;
using WebScan.Agent.Tools.Abstractions;
using WebScan.Contracts;

namespace WebScan.Agent.Tools.Parsers;

/// <summary>
/// Nmap XML (<c>-oX</c>), streamed host by host so truncated output (killed scan) still yields the complete hosts.
/// Emits HostUp/HostDown, PortOpen/PortClosed, Service (only when probed: version match, TLS tunnel or banner; with CPEs) and
/// TlsCertificate from the <c>ssl-cert</c> script (details from its PEM). Raw service fingerprints are never copied.
/// </summary>
public sealed class NmapXmlParser : IToolOutputParser
{
    public string Id => "nmap-xml";

    private static readonly Dictionary<string, string> ServiceAliases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["http-alt"] = "http", ["http-proxy"] = "http", ["https-alt"] = "https", ["ssl/http"] = "https",
    };

    public async IAsyncEnumerable<DiscoveryObservation> ParseAsync(Stream output, ParseContext context, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var settings = new XmlReaderSettings { Async = true, DtdProcessing = DtdProcessing.Ignore, XmlResolver = null, IgnoreComments = true };
        using var reader = XmlReader.Create(output, settings);
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            XElement? host;
            try
            {
                host = await NextHostAsync(reader, cancellationToken);
            }
            catch (XmlException) { yield break; } // truncated document: keep what was parsed
            if (host is null) yield break;
            foreach (var observation in ParseHost(host, context)) yield return observation;
        }
    }

    private static async Task<XElement?> NextHostAsync(XmlReader reader, CancellationToken ct)
    {
        while (await reader.ReadAsync())
        {
            if (reader is { NodeType: XmlNodeType.Element, Name: "host" })
                return (XElement)await XNode.ReadFromAsync(reader, ct);
        }
        return null;
    }

    private static IEnumerable<DiscoveryObservation> ParseHost(XElement host, ParseContext context)
    {
        var addresses = host.Elements("address").ToList();
        var address = addresses.FirstOrDefault(a => (string?)a.Attribute("addrtype") is "ipv4" or "ipv6")?.Attribute("addr")?.Value;
        if (address is null) yield break;
        var mac = addresses.FirstOrDefault(a => (string?)a.Attribute("addrtype") == "mac");
        var hostnames = host.Element("hostnames")?.Elements("hostname").Select(h => (string?)h.Attribute("name")).OfType<string>().Distinct().ToList() ?? [];
        var hostname = hostnames.FirstOrDefault();
        var observedAt = (long?)host.Attribute("endtime") is { } end and > 0 ? DateTimeOffset.FromUnixTimeSeconds(end) : (DateTimeOffset?)null;

        var status = host.Element("status");
        var state = (string?)status?.Attribute("state");
        var reason = (string?)status?.Attribute("reason");
        var ports = host.Element("ports")?.Elements("port").ToList() ?? [];
        var anyOpen = ports.Any(p => (string?)p.Element("state")?.Attribute("state") == "open");

        // "user-set" (-Pn) is an assumption, not evidence: report the host up only when a port proved it.
        if (state == "up" && (reason != "user-set" || anyOpen))
        {
            yield return context.NewObservation(ObservationKind.HostUp, address, observedAt: observedAt) with
            {
                Hostname = hostname,
                Host = new HostDetails
                {
                    Status = "up",
                    Reason = reason == "user-set" ? "open-port" : reason,
                    LatencyMs = (double?)host.Element("times")?.Attribute("srtt") is { } srtt ? Math.Round(srtt / 1000.0, 3) : null,
                    MacAddress = (string?)mac?.Attribute("addr"),
                    MacVendor = (string?)mac?.Attribute("vendor"),
                    OsGuess = (string?)host.Element("os")?.Elements("osmatch").FirstOrDefault()?.Attribute("name"),
                    Hostnames = hostnames,
                },
            };
        }
        else if (state == "down")
        {
            yield return context.NewObservation(ObservationKind.HostDown, address, observedAt: observedAt) with
            {
                Hostname = hostname,
                Host = new HostDetails { Status = "down", Reason = reason, Hostnames = hostnames },
            };
        }

        foreach (var port in ports)
        {
            if (!int.TryParse((string?)port.Attribute("portid"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var portId)) continue;
            var transport = (string?)port.Attribute("protocol") == "udp" ? TransportProtocol.Udp : TransportProtocol.Tcp;
            var portState = (string?)port.Element("state")?.Attribute("state");
            var portReason = (string?)port.Element("state")?.Attribute("reason");
            if (portState is not ("open" or "closed")) continue;

            yield return context.NewObservation(portState == "open" ? ObservationKind.PortOpen : ObservationKind.PortClosed, address, portId, transport, observedAt: observedAt) with
            {
                Hostname = hostname,
                PortState = new PortDetails { State = portState, Reason = portReason },
            };
            if (portState != "open") continue;

            var scripts = port.Elements("script").ToList();
            if (Service(port, scripts) is { } service)
            {
                var conf = (int?)port.Element("service")?.Attribute("conf");
                yield return context.NewObservation(ObservationKind.Service, address, portId, transport, observedAt: observedAt) with
                {
                    Hostname = hostname,
                    Service = service,
                    Confidence = conf is { } c ? new Confidence { Score = Math.Clamp(c / 10.0, 0, 1), Method = "version-probe" } : null,
                    Attributes = (string?)port.Element("service")?.Attribute("name") is { } raw && raw != service.Name
                        ? new Dictionary<string, string> { ["nmap.service"] = raw }
                        : null,
                };
            }

            if (scripts.FirstOrDefault(s => (string?)s.Attribute("id") == "ssl-cert") is { } sslCert && Certificate(sslCert) is { } tls)
                yield return context.NewObservation(ObservationKind.TlsCertificate, address, portId, transport, tls.FingerprintSha256, observedAt) with
                {
                    Hostname = hostname,
                    Tls = tls,
                };
        }
    }

    private static ServiceDetails? Service(XElement port, List<XElement> scripts)
    {
        var svc = port.Element("service");
        var banner = (string?)scripts.FirstOrDefault(s => (string?)s.Attribute("id") == "banner")?.Attribute("output");
        var probed = (string?)svc?.Attribute("method") == "probed";
        var tunnel = (string?)svc?.Attribute("tunnel"); // only set when -sV actually negotiated TLS
        if (!probed && tunnel is null && banner is null) return null; // port-table guesses are not service detection

        var name = (string?)svc?.Attribute("name") ?? "unknown";
        if (ServiceAliases.TryGetValue(name, out var alias)) name = alias;
        if (tunnel == "ssl" && name == "http") name = "https";

        return new ServiceDetails
        {
            Name = name,
            Product = (string?)svc?.Attribute("product"),
            Version = (string?)svc?.Attribute("version"),
            ExtraInfo = (string?)svc?.Attribute("extrainfo"),
            Banner = ParseContext.MaskText(banner, ParseContext.MaxBannerLength),
            Tunnel = tunnel,
            Cpe = svc?.Elements("cpe").Select(c => c.Value).ToList() ?? [],
        };
    }

    private static TlsDetails? Certificate(XElement script)
    {
        var pem = script.Elements("elem").FirstOrDefault(e => (string?)e.Attribute("key") == "pem")?.Value;
        if (pem is not null)
        {
            try
            {
                using var cert = X509Certificate2.CreateFromPem(pem);
                var san = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
                return new TlsDetails
                {
                    SubjectCommonName = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false),
                    SubjectAlternativeNames = san is null ? [] : [.. san.EnumerateDnsNames(), .. san.EnumerateIPAddresses().Select(ip => ip.ToString())],
                    Issuer = cert.Issuer,
                    NotBefore = cert.NotBefore.ToUniversalTime(),
                    NotAfter = cert.NotAfter.ToUniversalTime(),
                    SerialNumber = cert.SerialNumber,
                    FingerprintSha256 = cert.GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant(),
                    SelfSigned = cert.SubjectName.RawData.AsSpan().SequenceEqual(cert.IssuerName.RawData),
                };
            }
            catch (CryptographicException) { }
        }

        // Fallback without PEM: subject/issuer/validity tables only (no fingerprint).
        var tables = script.Elements("table").ToDictionary(t => (string?)t.Attribute("key") ?? "", StringComparer.Ordinal);
        string? Elem(string table, string key) => tables.GetValueOrDefault(table)?.Elements("elem").FirstOrDefault(e => (string?)e.Attribute("key") == key)?.Value;
        var cn = Elem("subject", "commonName");
        if (cn is null) return null;
        return new TlsDetails
        {
            SubjectCommonName = cn,
            Issuer = Elem("issuer", "commonName"),
            NotBefore = ParseNmapDate(Elem("validity", "notBefore")),
            NotAfter = ParseNmapDate(Elem("validity", "notAfter")),
        };
    }

    private static DateTimeOffset? ParseNmapDate(string? value) =>
        DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var d) ? d : null;
}
