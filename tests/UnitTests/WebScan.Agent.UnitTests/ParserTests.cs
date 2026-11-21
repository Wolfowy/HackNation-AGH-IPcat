using System.Text;
using System.Text.Json;
using WebScan.Agent.Tools.Abstractions;
using WebScan.Agent.Tools.Parsers;
using WebScan.Contracts;

namespace WebScan.Agent.UnitTests;

/// <summary>Parsers against real tool output captured from the TestLab (see tests/TestLab/README.md).</summary>
public class ParserTests
{
    private const string LabCertFingerprint = "26cd6e61c79bd9e08104ada6910cca0b703a4101ff85113a60d437f0a4ed4edf";

    [Fact]
    public async Task Nmap_host_discovery_reports_up_hosts()
    {
        var observations = await Parsing.ParseFixtureAsync(new NmapXmlParser(), "nmap-host-discovery.xml");

        Assert.All(observations, o => Assert.Equal(ObservationKind.HostUp, o.Kind));
        Assert.Equal(["172.30.0.1", "172.30.0.10", "172.30.0.11", "172.30.0.12", "172.30.0.13", "172.30.0.14", "172.30.0.2"],
            observations.Select(o => o.Address).Order(StringComparer.Ordinal));
        var web = observations.Single(o => o.Address == "172.30.0.10");
        Assert.Equal("conn-refused", web.Host!.Reason);
        Assert.NotNull(web.Host.LatencyMs);
        Assert.All(observations, o => Assert.Equal(32, o.ObservationId.Length));
    }

    [Fact]
    public async Task Nmap_arp_discovery_maps_mac_address_and_vendor()
    {
        var observations = await Parsing.ParseFixtureAsync(new NmapXmlParser(), "nmap-host-discovery-arp.xml");

        var web = observations.Single(o => o.Address == "172.30.0.10").Host!;
        Assert.Equal(("arp-response", "02:42:AC:1E:00:0A", "Docker"), (web.Reason, web.MacAddress, web.MacVendor));
        var self = observations.Single(o => o.Address == "172.30.0.2").Host!; // own interface: no MAC element
        Assert.Equal(((string?)null, (string?)null), (self.MacAddress, self.MacVendor));
    }

    [Fact]
    public async Task Nmap_port_scan_reports_open_ports_and_hosts_proven_up()
    {
        var observations = await Parsing.ParseFixtureAsync(new NmapXmlParser(), "nmap-port-scan.xml");

        var open = observations.Where(o => o.Kind == ObservationKind.PortOpen).Select(o => $"{o.Address}:{o.Port}").Order().ToList();
        Assert.Equal(["172.30.0.10:80", "172.30.0.11:80", "172.30.0.12:8080", "172.30.0.12:8443", "172.30.0.13:80", "172.30.0.14:2323"], open);
        Assert.All(observations.Where(o => o.Kind == ObservationKind.PortOpen), o => Assert.Equal(TransportProtocol.Tcp, o.Transport));
        // -Pn ("user-set") hosts are reported up only because an open port proves it.
        Assert.All(observations.Where(o => o.Kind == ObservationKind.HostUp), o => Assert.Equal("open-port", o.Host!.Reason));
        Assert.DoesNotContain(observations, o => o.Kind == ObservationKind.Service); // port-table guesses are not service detection
    }

    [Fact]
    public async Task Nmap_service_detection_maps_product_version_cpe_and_banner_without_raw_fingerprints()
    {
        var observations = await Parsing.ParseFixtureAsync(new NmapXmlParser(), "nmap-service-detection.xml");
        var services = observations.Where(o => o.Kind == ObservationKind.Service).ToDictionary(o => $"{o.Address}:{o.Port}");

        var nginx = services["172.30.0.10:80"].Service!;
        Assert.Equal(("http", "nginx", "1.27.5"), (nginx.Name, nginx.Product, nginx.Version));
        Assert.Contains("cpe:/a:igor_sysoev:nginx:1.27.5", nginx.Cpe);
        Assert.Equal("(Unix)", services["172.30.0.11:80"].Service!.ExtraInfo);
        Assert.Equal("WEBSCAN-TESTLAB-BANNER v1.0", services["172.30.0.14:2323"].Service!.Banner);

        var json = JsonSerializer.Serialize(observations, ContractJson.Options);
        Assert.DoesNotContain("testlab_session=", json); // servicefp / fingerprint-strings carry raw Set-Cookie values
        Assert.DoesNotContain("SF-Port", json);
    }

    [Fact]
    public async Task Nmap_ssl_cert_becomes_tls_certificate_with_fingerprint_from_pem()
    {
        var observations = await Parsing.ParseFixtureAsync(new NmapXmlParser(), "nmap-tls.xml");
        var tls = observations.Single(o => o.Kind == ObservationKind.TlsCertificate);

        Assert.Equal(("172.30.0.12", 8443), (tls.Address, tls.Port!.Value));
        Assert.Equal("testlab-webapp.local", tls.Tls!.SubjectCommonName);
        Assert.Equal(LabCertFingerprint, tls.Tls.FingerprintSha256); // same certificate as seen by tlsx and httpx
        Assert.Contains("localhost", tls.Tls.SubjectAlternativeNames);
        Assert.Contains("172.30.0.12", tls.Tls.SubjectAlternativeNames);
        Assert.True(tls.Tls.SelfSigned);
        Assert.True(tls.Tls.NotAfter > tls.Tls.NotBefore);
        // Unrecognized Kestrel fingerprint, but -sV negotiated TLS: reported as https with low confidence.
        var service = observations.Single(o => o.Kind == ObservationKind.Service);
        Assert.Equal(("https", "ssl", 0.3), (service.Service!.Name, service.Service.Tunnel, service.Confidence!.Score));
    }

    [Fact]
    public async Task Nmap_truncated_output_keeps_complete_hosts()
    {
        var xml = await File.ReadAllTextAsync(TestPaths.Fixture("nmap-port-scan.xml"));
        var cut = xml[..xml.IndexOf("172.30.0.12", StringComparison.Ordinal)]; // killed mid-scan
        var observations = await Parsing.ParseAsync(new NmapXmlParser(), new MemoryStream(Encoding.UTF8.GetBytes(cut)));

        Assert.Contains(observations, o => o.Address == "172.30.0.10" && o.Kind == ObservationKind.PortOpen);
        Assert.DoesNotContain(observations, o => o.Address == "172.30.0.12");
    }

    [Fact]
    public async Task Naabu_jsonl_reports_open_ports()
    {
        var observations = await Parsing.ParseFixtureAsync(new NaabuJsonlParser(), "naabu.jsonl");

        Assert.Equal(6, observations.Count);
        Assert.All(observations, o => Assert.Equal((ObservationKind.PortOpen, "open"), (o.Kind, o.PortState!.State)));
        Assert.Contains(observations, o => o.Address == "172.30.0.14" && o.Port == 2323);
        Assert.Equal(6, observations.Select(o => o.ObservationId).Distinct().Count());
    }

    [Fact]
    public async Task Httpx_jsonl_maps_responses_technologies_tls_and_masks_cookies()
    {
        var observations = await Parsing.ParseFixtureAsync(new HttpxJsonlParser(), "httpx.jsonl");
        var responses = observations.Where(o => o.Kind == ObservationKind.HttpResponse).ToDictionary(o => o.Http!.Url);

        Assert.Equal(10, responses.Count);
        var nginx = responses["http://172.30.0.10:80/"];
        Assert.Equal((200, "Welcome to nginx!", "nginx/1.27.5", 80), (nginx.Http!.StatusCode!.Value, nginx.Http.Title, nginx.Http.WebServer, nginx.Port!.Value));
        Assert.Equal("fb47468a2cd3953c7131431991afcc6a2703f14640520102eea0a685a7e8d6de", nginx.Http.BodySha256);
        Assert.Equal("nginx/1.27.5", nginx.Http.Headers["server"]);

        var admin = responses["http://172.30.0.13:80/"];
        Assert.Equal(("WebScan TestLab Admin Panel", "894267619"), (admin.Http!.Title, admin.Http.FaviconHash));

        var redirected = responses.Values.Single(o => o.Http!.Url == "http://172.30.0.12:8080/old" || o.Http.FinalUrl == "http://172.30.0.12:8080/");
        Assert.Equal("http://172.30.0.12:8080/", redirected.Http!.FinalUrl);

        var withCookie = responses.Values.First(o => o.Http!.CookieNames.Count > 0);
        Assert.Contains("testlab_session", withCookie.Http!.CookieNames);
        Assert.StartsWith("testlab_session=***", withCookie.Http.Headers["set-cookie"]);
        Assert.DoesNotContain("testlab_session=3E2D", JsonSerializer.Serialize(observations, ContractJson.Options));

        Assert.Contains(observations, o => o.Kind == ObservationKind.Technology && o.Technology!.Name == "Nginx" && o.Technology.Version == "1.27.5");
        var tls = observations.Where(o => o.Kind == ObservationKind.TlsCertificate).ToList();
        Assert.NotEmpty(tls);
        Assert.All(tls, t => Assert.Equal((LabCertFingerprint, "tls13", 8443), (t.Tls!.FingerprintSha256, t.Tls.TlsVersion, t.Port!.Value)));
    }

    [Fact]
    public async Task Nuclei_jsonl_maps_signature_match_with_bundle_version_and_masked_evidence()
    {
        var job = Jobs.Endpoints(ScanOperation.ExecuteSignatures, ToolCapabilities.SignatureScan,
            [new ScanEndpoint { Address = "172.30.0.13", Port = 80 }], ["172.30.0.0/24"]) with
        {
            Signatures = new SignatureBundle { Sha256 = "x", Items = [new SignatureContent { Id = "webscan-testlab-admin-panel", Version = 4, Format = "nuclei-yaml", Content = "" }] },
        };
        var observations = await Parsing.ParseFixtureAsync(new NucleiJsonlParser(), "nuclei.jsonl", Parsing.Context(job));
        var match = Assert.Single(observations);

        Assert.Equal((ObservationKind.SignatureMatch, "172.30.0.13", 80), (match.Kind, match.Address, match.Port!.Value));
        var s = match.Signature!;
        Assert.Equal(("webscan-testlab-admin-panel", 4, "info", "admin-panel-title"), (s.SignatureId, s.SignatureVersion!.Value, s.Severity, s.MatcherName));
        Assert.Equal("WebScan TestLab Admin Panel", s.Name);
        Assert.Equal(["WebScan TestLab Admin Panel"], s.ExtractedResults);
        Assert.Contains("webscan-testlab", s.Tags);
        Assert.Equal("http://172.30.0.13:80/", s.MatchedAt);
        Assert.NotNull(s.Evidence);
        Assert.True(s.Evidence!.Length <= ParseContext.MaxEvidenceLength);
    }

    [Fact]
    public async Task Generic_jsonl_maps_tlsx_output_with_the_shipped_manifest_mapping()
    {
        var manifest = JsonSerializer.Deserialize<ToolManifest>(await File.ReadAllTextAsync(Path.Combine(TestPaths.ShippedManifests, "tlsx.json")), ToolManifestJson.Options)!;
        var options = manifest.Capabilities["tls-probe"].ParserOptions;
        Assert.Empty(new GenericJsonlParser().ValidateOptions(options));

        var observations = await Parsing.ParseFixtureAsync(new GenericJsonlParser(), "tlsx.jsonl", Parsing.Context(options: options));
        var tls = Assert.Single(observations);

        Assert.Equal((ObservationKind.TlsCertificate, "172.30.0.12", 8443), (tls.Kind, tls.Address, tls.Port!.Value));
        Assert.Equal(LabCertFingerprint, tls.Tls!.FingerprintSha256);
        Assert.Equal(("testlab-webapp.local", "tls13", true), (tls.Tls.SubjectCommonName, tls.Tls.TlsVersion, tls.Tls.SelfSigned!.Value));
        Assert.Equal(["testlab-webapp.local", "localhost"], tls.Tls.SubjectAlternativeNames);
        Assert.Equal(new DateTimeOffset(2027, 11, 21, 18, 56, 2, TimeSpan.Zero), tls.Tls.NotAfter);
        Assert.Equal("WebScan TestLab", tls.Attributes!["tlsx.subjectOrg"]);
    }

    [Fact]
    public void Generic_jsonl_rejects_invalid_mappings()
    {
        var errors = new GenericJsonlParser().ValidateOptions(JsonDocument.Parse("""{ "kind": "Service", "fields": { "port": "p", "service.nope": "x" }, "discriminator": "zzz" }""").RootElement);

        Assert.Contains(errors, e => e.Contains("fields.address"));
        Assert.Contains(errors, e => e.Contains("service.nope"));
        Assert.Contains(errors, e => e.Contains("discriminator"));
    }

    [Fact]
    public async Task Generic_jsonl_skips_truncated_lines_and_masks_attributes()
    {
        var options = JsonDocument.Parse("""{ "kind": "Service", "fields": { "address": "ip", "port": "port", "service.name": "svc" }, "attributes": { "note": "meta.note" } }""").RootElement;
        var input = """
            {"ip":"10.0.0.1","port":"22","svc":"ssh","meta":{"note":"password=hunter2"}}
            {"ip":"10.0.0.2","port":80,"svc":"ht
            """;
        var observations = await Parsing.ParseAsync(new GenericJsonlParser(), new MemoryStream(Encoding.UTF8.GetBytes(input)), Parsing.Context(options: options));

        var service = Assert.Single(observations);
        Assert.Equal(("10.0.0.1", 22, "ssh"), (service.Address, service.Port!.Value, service.Service!.Name));
        Assert.DoesNotContain("hunter2", service.Attributes!["note"]);
    }
}
