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
    public async Task Nmap_version_scan_reports_unidentified_ports_as_unknown_services()
    {
        const string xml = """
            <nmaprun><host><status state="up" reason="syn-ack"/><address addr="172.30.0.9" addrtype="ipv4"/><ports>
            <port protocol="tcp" portid="3000"><state state="open"/><service name="ppp" method="table" conf="3"/></port>
            <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6" method="probed" conf="10"/></port>
            </ports></host></nmaprun>
            """;
        var job = Jobs.Endpoints(ScanOperation.DetectService, ToolCapabilities.ServiceDetection,
            [new ScanEndpoint { Address = "172.30.0.9", Port = 3000 }, new ScanEndpoint { Address = "172.30.0.9", Port = 22 }], ["172.30.0.0/24"]);
        var services = (await Parsing.ParseAsync(new NmapXmlParser(), new MemoryStream(Encoding.UTF8.GetBytes(xml)), Parsing.Context(job)))
            .Where(o => o.Kind == ObservationKind.Service).ToDictionary(o => o.Port!.Value, o => o.Service!);
        Assert.Equal(("unknown", null), (services[3000].Name, services[3000].Product)); // the guessed "ppp" is not trusted
        Assert.Equal(("ssh", "OpenSSH"), (services[22].Name, services[22].Product));
    }

    [Fact]
    public async Task Masscan_xml_without_host_status_reports_hosts_and_open_ports()
    {
        const string xml = """
            <?xml version="1.0"?>
            <!-- masscan v1.3 scan -->
            <nmaprun scanner="masscan" start="1763790000" version="1.0-BETA" xmloutputversion="1.03">
            <scaninfo type="syn" protocol="tcp" />
            <host endtime="1763790001"><address addr="172.24.0.4" addrtype="ipv4"/><ports><port protocol="tcp" portid="5672"><state state="open" reason="syn-ack" reason_ttl="64"/></port></ports></host>
            <host endtime="1763790002"><address addr="172.24.0.4" addrtype="ipv4"/><ports><port protocol="tcp" portid="15672"><state state="open" reason="syn-ack" reason_ttl="64"/></port></ports></host>
            <runstats><finished time="1763790010" timestr="2026-11-22 06:00:10" elapsed="10" /><hosts up="1" down="0" total="1" /></runstats>
            </nmaprun>
            """;
        var observations = await Parsing.ParseAsync(new NmapXmlParser(), new MemoryStream(Encoding.UTF8.GetBytes(xml)));
        Assert.Equal([5672, 15672], observations.Where(o => o.Kind == ObservationKind.PortOpen).Select(o => o.Port!.Value).Order());
        Assert.All(observations.Where(o => o.Kind == ObservationKind.HostUp), o => Assert.Equal(("172.24.0.4", "open-port"), (o.Address, o.Host!.Reason)));
        Assert.DoesNotContain(observations, o => o.Kind == ObservationKind.Service);
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
    public async Task Nerva_jsonl_maps_services_to_the_planned_endpoints_without_headers()
    {
        var job = Jobs.Endpoints(ScanOperation.DetectService, ToolCapabilities.ServiceDetection,
        [
            new ScanEndpoint { Address = "172.30.0.10", Port = 80 }, new ScanEndpoint { Address = "203.0.113.7", Port = 443, Hostname = "app.example.com" },
            new ScanEndpoint { Address = "172.30.0.11", Port = 22 }, new ScanEndpoint { Address = "172.30.0.12", Port = 3389 },
            new ScanEndpoint { Address = "198.51.100.9", Port = 8080, Hostname = "legacy.example.com" }, new ScanEndpoint { Address = "172.30.0.14", Port = 6379 },
        ], ["172.30.0.0/24", "app.example.com", "legacy.example.com"]);
        var observations = await Parsing.ParseFixtureAsync(new NervaJsonlParser(), "nerva.jsonl", Parsing.Context(job));
        var services = observations.Where(o => o.Kind == ObservationKind.Service).ToDictionary(o => o.Port!.Value);

        Assert.Equal([22, 80, 443, 3389, 6379, 8080], services.Keys.Order()); // the cut-off last line is skipped
        var nginx = services[80].Service!;
        Assert.Equal(("http", "Nginx", "1.27.5", null), (nginx.Name, nginx.Product, nginx.Version, nginx.Tunnel));
        Assert.Equal(["cpe:2.3:a:f5:nginx:1.27.5:*:*:*:*:*:*:*"], nginx.Cpe);

        var vhost = services[443];
        Assert.Equal(("203.0.113.7", "app.example.com", "https", "ssl", "Grafana", "10.2.3"),
            (vhost.Address, vhost.Hostname, vhost.Service!.Name, vhost.Service.Tunnel, vhost.Service.Product, vhost.Service.Version));
        Assert.Equal("Grafana", vhost.Attributes!["nerva.title"]);

        Assert.Equal(("OpenSSH_9.6p1", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"), (services[22].Service!.Version, services[22].Service!.Banner));
        Assert.Equal("DC01", services[3389].Attributes!["nerva.netbios_computer_name"]);
        Assert.Equal("198.51.100.9", services[8080].Address); // nerva reports 0.0.0.0 for late-resolved names: the planned address wins
        Assert.Equal("true", services[6379].Attributes!["nerva.anonymousAccess"]);

        Assert.Equal(["Go", "Grafana", "Nginx"], observations.Where(o => o.Kind == ObservationKind.Technology).Select(o => o.Technology!.Name).Order());
        Assert.DoesNotContain("abc123secretvalue", JsonSerializer.Serialize(observations, ContractJson.Options));
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
        Assert.Equal("4f5778ef80f10c13694a518b204a625b", admin.Http.FaviconMd5);

        var redirected = responses.Values.Single(o => o.Http!.Url == "http://172.30.0.12:8080/old" || o.Http.FinalUrl == "http://172.30.0.12:8080/");
        Assert.Equal("http://172.30.0.12:8080/", redirected.Http!.FinalUrl);
        Assert.Equal(["http://172.30.0.12:8080/old", "http://172.30.0.12:8080/"], redirected.Http.RedirectChain);
        Assert.Equal([302, 200], redirected.Http.RedirectStatusCodes);
        Assert.Empty(nginx.Http.RedirectChain);

        var withCookie = responses.Values.First(o => o.Http!.CookieNames.Count > 0);
        Assert.Contains("testlab_session", withCookie.Http!.CookieNames);
        Assert.Equal(new HttpCookie { Name = "testlab_session", HttpOnly = true, Path = "/" }, Assert.Single(withCookie.Http.Cookies));
        Assert.StartsWith("testlab_session=***", withCookie.Http.Headers["set-cookie"]);
        Assert.DoesNotContain("testlab_session=3E2D", JsonSerializer.Serialize(observations, ContractJson.Options));

        Assert.Contains(observations, o => o.Kind == ObservationKind.Technology && o.Technology!.Name == "Nginx" && o.Technology.Version == "1.27.5");
        var tls = observations.Where(o => o.Kind == ObservationKind.TlsCertificate).ToList();
        Assert.NotEmpty(tls);
        Assert.All(tls, t => Assert.Equal((LabCertFingerprint, "tls13", 8443), (t.Tls!.FingerprintSha256, t.Tls.TlsVersion, t.Port!.Value)));
    }

    [Fact]
    public async Task Httpx_jsonl_maps_cookie_flags_page_type_cdn_favicon_md5_and_redirects_without_cookie_values()
    {
        var observations = await Parsing.ParseFixtureAsync(new HttpxJsonlParser(), "httpx-extras.jsonl");
        var responses = observations.Where(o => o.Kind == ObservationKind.HttpResponse).ToDictionary(o => o.Http!.Url, o => o.Http!);

        var camera = responses["https://172.30.0.20:443/"];
        Assert.Equal(("login", "cloudflare", "waf"), (camera.PageType, camera.Cdn, camera.CdnType));
        Assert.Equal(("999357577", "842c79ab11f38323fc554afbea5c990a"), (camera.FaviconHash, camera.FaviconMd5));
        Assert.Equal(["https://172.30.0.20:443/", "https://172.30.0.20/doc/page/login.asp"], camera.RedirectChain);
        Assert.Equal([302, 200], camera.RedirectStatusCodes);
        Assert.Equal("a1b2c3", camera.Headers["x-debug-token"]);

        Assert.Equal(["BIGipServerpool_cam", "language", "WebSession_0a1b2c"], camera.CookieNames);
        Assert.Equal(
        [
            new HttpCookie { Name = "BIGipServerpool_cam", HttpOnly = true, Path = "/", DecodedValue = "10.1.1.100:8080" },
            new HttpCookie { Name = "language", Path = "/" },
            new HttpCookie { Name = "WebSession_0a1b2c", HttpOnly = true, SameSite = "Strict", Path = "/" },
        ], camera.Cookies);
        var json = JsonSerializer.Serialize(observations, ContractJson.Options);
        Assert.DoesNotContain("7f3e9d8c2b1a4d5e", json);
        Assert.DoesNotContain("1677787402", json);

        var plain = responses["http://172.30.0.20:80/"];
        Assert.Equal((301, "other"), (plain.StatusCode, plain.PageType));
        Assert.Equal(["http://172.30.0.20:80/", "https://172.30.0.20/"], plain.RedirectChain);
        Assert.Empty(plain.Cookies);

        var tls = Assert.Single(observations, o => o.Kind == ObservationKind.TlsCertificate);
        Assert.Equal("CN=172.30.0.20, OU=Camera, O=Example Cameras", tls.Tls!.SubjectDn);
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
