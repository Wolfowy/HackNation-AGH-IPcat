using WebScan.Contracts;
using WebScan.Server.Modules.Discovery.Fingerprinting;

namespace WebScan.Discovery.UnitTests;

public class RecogTests
{
    private static readonly RecogDatabase Recog = RecogDatabase.Default;

    [Fact]
    public void Vendored_fingerprints_compile_and_match_their_own_examples()
    {
        var fingerprints = Recog.Fingerprints.ToList();
        Assert.True(fingerprints.Count > 2000, $"only {fingerprints.Count} fingerprints loaded");
        Assert.Equal(0, Recog.Skipped);

        // Recog's own self-test: every example matches its fingerprint and yields the params it declares.
        var failures = new List<string>();
        foreach (var fp in fingerprints)
        foreach (var example in fp.Examples)
        {
            var match = fp.Match(example.Text);
            if (match is null) failures.Add($"{fp.MatchKey} '{fp.Description}': no match for '{example.Text}'");
            else
                failures.AddRange(example.Expected.Where(e => match[e.Key] != e.Value.Trim()) // captures are trimmed
                    .Select(e => $"{fp.MatchKey} '{fp.Description}': {e.Key}={match[e.Key]} expected {e.Value}"));
        }
        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    [Theory]
    [InlineData(RecogDatabase.HttpServer, "Apache/2.4.41 (Ubuntu)", "service.product", "HTTPD")]
    [InlineData(RecogDatabase.HttpServer, "Microsoft-IIS/10.0", "service.version", "10.0")]
    [InlineData(RecogDatabase.HttpCookie, "PHPSESSID=", "service.product", "PHP")]
    [InlineData(RecogDatabase.FaviconMd5, "842c79ab11f38323fc554afbea5c990a", "hw.device", "IP Camera")]
    [InlineData(RecogDatabase.SshBanner, "OpenSSH_8.9p1 Ubuntu-3ubuntu0.1", "os.vendor", "Ubuntu")]
    [InlineData(RecogDatabase.X509Subject, "CN=Kubernetes Ingress Controller Fake Certificate,O=Acme Co", "service.product", "NGINX Ingress Controller")]
    public void First_matching_fingerprint_yields_params(string key, string text, string param, string expected) =>
        Assert.Equal(expected, Recog.Match(key, text)?[param]);

    [Fact]
    public void Unknown_text_and_sets_match_nothing()
    {
        Assert.Null(Recog.Match(RecogDatabase.HttpServer, "definitely-not-a-known-server/0"));
        Assert.Null(Recog.Match("no.such.set", "Apache"));
        Assert.Null(Recog.Match(RecogDatabase.HttpServer, null));
    }
}

public class ServiceFingerprinterTests
{
    private static HttpDetails Http(Dictionary<string, string> headers, string scheme = "http", string? title = null, string? faviconMd5 = null,
        IReadOnlyList<HttpCookie>? cookies = null, string? pageType = null) => new()
    {
        Url = $"{scheme}://10.0.0.5/", Scheme = scheme, StatusCode = 200, Title = title, FaviconMd5 = faviconMd5, PageType = pageType,
        Headers = new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase), Cookies = cookies ?? [],
    };

    [Fact]
    public void Http_fingerprint_yields_recog_technologies_device_and_favicon_artifact()
    {
        var result = ServiceFingerprinter.Http(Http(new() { ["server"] = "Microsoft-IIS/10.0" }, faviconMd5: "842c79ab11f38323fc554afbea5c990a"), "10.0.0.5");

        Assert.Contains(result.Technologies, t => t is { Name: "Microsoft IIS", Version: "10.0" });
        Assert.Equal(new DeviceClassification("IP Camera", "D-Link", "DCS-932"), result.Device);
        var favicon = Assert.Single(result.Artifacts, a => a.Kind == "favicon");
        Assert.Contains("D-Link Network Camera", favicon.Reason);
    }

    [Fact]
    public void Ssh_banner_is_matched_without_protocol_prefix_and_sets_os()
    {
        var result = ServiceFingerprinter.Banner(new ServiceDetails { Name = "ssh", Banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n" });
        Assert.Contains(result.Technologies, t => t.Name == "OpenBSD OpenSSH" && t.Version == "8.9p1");
        Assert.NotNull(result.OsGuess);
        Assert.Empty(ServiceFingerprinter.Banner(new ServiceDetails { Name = "http", Banner = "SSH-2.0-OpenSSH_8.9p1" }).Technologies);
    }

    [Fact]
    public void Default_device_certificate_becomes_cert_artifact_but_a_public_ca_does_not()
    {
        var device = ServiceFingerprinter.Tls(new TlsDetails { SubjectDn = "CN=Kubernetes Ingress Controller Fake Certificate, O=Acme Co" });
        Assert.Contains(device.Technologies, t => t.Name == "Kubernetes NGINX Ingress Controller");
        Assert.Single(device.Artifacts, a => a is { Kind: "cert", Name: "subject" });

        var publicCa = ServiceFingerprinter.Tls(new TlsDetails { Issuer = "CN=R3, O=Let's Encrypt, C=US" });
        Assert.True(publicCa.IsEmpty);
    }
}

public class HttpArtifactTests
{
    private static HttpDetails Http(Dictionary<string, string> headers, string scheme = "http", string? title = null, string? setCookie = null,
        string? pageType = null, string path = "/") => new()
    {
        Url = $"{scheme}://10.0.0.5{path}", Scheme = scheme, Title = title, PageType = pageType,
        Headers = new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase), Cookies = HttpCookies.Parse(setCookie),
    };

    [Fact]
    public void Flags_interesting_headers_with_reasons_and_tags()
    {
        var artifacts = HttpArtifacts.Detect(Http(new()
        {
            ["Server"] = "nginx/1.27.5", ["X-Powered-By"] = "PHP/8.1.2", ["X-AspNet-Version"] = "4.0.30319", ["X-Debug-Token"] = "a1b2c3",
            ["X-Backend-Server"] = "app01.internal:8080 (10.20.30.40)", ["Access-Control-Allow-Origin"] = "*", ["Date"] = "Sun, 22 Nov 2026 10:00:00 GMT",
        }), "10.0.0.5");
        var byName = artifacts.ToDictionary(a => a.Name);

        Assert.Equal(["version-leak"], byName["server"].Tags);
        Assert.Equal(["tech-hint", "version-leak"], byName["x-powered-by"].Tags);
        Assert.Contains("version-leak", byName["x-aspnet-version"].Tags);
        Assert.Equal(["debug"], byName["x-debug-token"].Tags);
        Assert.Equal("low", byName["x-debug-token"].Severity);
        Assert.Contains("internal-ip-leak", byName["x-backend-server"].Tags);
        Assert.Contains("10.20.30.40", byName["x-backend-server"].Reason);
        Assert.Equal(["permissive-cors"], byName["access-control-allow-origin"].Tags);
        Assert.DoesNotContain("date", byName.Keys);
        Assert.DoesNotContain("strict-transport-security", byName.Keys); // plain http
    }

    [Fact]
    public void Server_without_version_and_the_scanned_address_itself_are_not_artifacts()
    {
        var artifacts = HttpArtifacts.Detect(Http(new() { ["Server"] = "Kestrel", ["Location"] = "http://10.0.0.5/login" }), "10.0.0.5");
        Assert.Empty(artifacts);
    }

    [Fact]
    public void Https_without_hsts_and_weak_session_cookies_are_flagged()
    {
        var artifacts = HttpArtifacts.Detect(Http(new(), "https",
            setCookie: "PHPSESSID=abc; path=/, csrftoken=x; Path=/; Secure, sid=1; Expires=Wed, 19-May-21 01:11:11 GMT; Secure; HttpOnly"), "10.0.0.5");
        var byName = artifacts.ToDictionary(a => a.Name);

        Assert.Equal(["missing-hsts"], byName["strict-transport-security"].Tags);
        var php = byName["PHPSESSID"];
        Assert.Equal(["tech-hint", "insecure-cookie"], php.Tags);
        Assert.Contains("Cookie reveals PHP", php.Reason);
        Assert.Contains("without Secure and HttpOnly flag", php.Reason);
        Assert.Equal("low", php.Severity);
        Assert.Equal(["tech-hint"], byName["csrftoken"].Tags); // Django hint, but CSRF tokens need no HttpOnly
        Assert.DoesNotContain("sid", byName.Keys);
    }

    [Fact]
    public void Bigip_cookie_reveals_the_load_balancer_and_its_internal_pool_member()
    {
        var artifacts = HttpArtifacts.Detect(Http(new(), setCookie: "BIGipServerpool_web=1677787402.36895.0000; path=/; Httponly"), "203.0.113.7");
        var cookie = Assert.Single(artifacts);
        Assert.Equal(("cookie", "BIGipServerpool_web", "10.1.1.100:8080", "low"), (cookie.Kind, cookie.Name, cookie.Value, cookie.Severity));
        Assert.Equal(["tech-hint", "internal-ip-leak"], cookie.Tags);
    }

    [Fact]
    public void Login_and_admin_pages_from_page_type_title_path_and_http_auth()
    {
        Assert.Contains(HttpArtifacts.Detect(Http(new(), pageType: "login"), "10.0.0.5"), a => a is { Kind: "page", Name: "login" });
        Assert.Contains(HttpArtifacts.Detect(Http(new(), title: "Sign in to Grafana"), "10.0.0.5"), a => a.Tags.Contains("login-page"));
        Assert.Contains(HttpArtifacts.Detect(Http(new(), title: "WebScan TestLab Admin Panel"), "10.0.0.5"), a => a.Tags.Contains("admin-page"));
        Assert.Contains(HttpArtifacts.Detect(Http(new(), path: "/phpmyadmin/"), "10.0.0.5"), a => a.Tags.Contains("admin-page"));
        var auth = Assert.Single(HttpArtifacts.Detect(Http(new() { ["WWW-Authenticate"] = "Basic realm=\"Router\"" }), "10.0.0.5"));
        Assert.Equal(("http-auth", "Basic realm=\"Router\""), (auth.Name, auth.Value));
        Assert.Empty(HttpArtifacts.Detect(Http(new(), title: "Welcome to nginx!"), "10.0.0.5"));
    }
}
