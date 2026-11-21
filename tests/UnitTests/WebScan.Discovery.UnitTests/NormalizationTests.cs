using WebScan.Contracts;
using WebScan.Server.Modules.Discovery.Normalization;

namespace WebScan.Discovery.UnitTests;

public class NormalizationTests
{
    [Theory]
    [InlineData("10.0.0.1", "10.0.0.1")]
    [InlineData(" 010.000.000.001 ", "10.0.0.1")] // decimal, not octal
    [InlineData("::ffff:192.168.1.5", "192.168.1.5")] // IPv4-mapped → IPv4
    [InlineData("2001:DB8:0:0:0:0:0:1", "2001:db8::1")]
    [InlineData("[fe80::1%eth0]", "fe80::1")]
    [InlineData("WWW.Example.COM.", "www.example.com")]
    [InlineData("", null)]
    [InlineData("not a host", null)]
    [InlineData("300.1.1.1", null)]
    public void Canonical_addresses(string input, string? expected) => Assert.Equal(expected, Normalizer.CanonicalAddress(input));

    [Theory]
    [InlineData("aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF")]
    [InlineData("AA-BB-CC-DD-EE-0F", "AA:BB:CC:DD:EE:0F")]
    [InlineData("aabb.ccdd.eeff", "AA:BB:CC:DD:EE:FF")]
    [InlineData(" 0011223344ff ", "00:11:22:33:44:FF")]
    [InlineData("00:11:22:33:44", null)]
    [InlineData("zz:11:22:33:44:55", null)]
    [InlineData("", null)]
    public void Canonical_mac_addresses(string input, string? expected) => Assert.Equal(expected, Normalizer.CanonicalMac(input));

    [Theory]
    [InlineData("www", null, "http")]
    [InlineData("http-alt", null, "http")]
    [InlineData("HTTP-Proxy", null, "http")]
    [InlineData("ssl/http", null, "https")]
    [InlineData("http", "ssl", "https")]
    [InlineData("ssl/imap", null, "imaps")]
    [InlineData("ms-wbt-server", null, "rdp")]
    [InlineData("http?", null, "http")]
    [InlineData("ssh", null, "ssh")]
    [InlineData("", null, "unknown")]
    public void Canonical_service_names(string input, string? tunnel, string expected) =>
        Assert.Equal(expected, Normalizer.CanonicalServiceName(input, tunnel));

    [Theory]
    [InlineData("Nginx", null, "nginx", null, "web-server")]
    [InlineData("Nginx:1.19.0", null, "nginx", "1.19.0", "web-server")]
    [InlineData("Apache httpd", "2.4.41", "Apache HTTP Server", "2.4.41", "web-server")]
    [InlineData("microsoft-iis", "10.0", "Microsoft IIS", "10.0", "web-server")]
    [InlineData("wordpress", " 6.4 ", "WordPress", "6.4", "cms")]
    [InlineData("  Some   Custom App ", null, "Some Custom App", null, null)]
    public void Canonical_technology_names(string name, string? version, string expectedName, string? expectedVersion, string? expectedCategory)
    {
        var (n, v, c, key) = Normalizer.CanonicalTechnology(name, version, null);
        Assert.Equal(expectedName, n);
        Assert.Equal(expectedVersion, v);
        Assert.Equal(expectedCategory, c);
        Assert.Equal(expectedName.ToLowerInvariant(), key);
    }

    [Fact]
    public void Normalize_observation_canonicalizes_and_masks()
    {
        var o = new DiscoveryObservation
        {
            ObservationId = "x", Kind = ObservationKind.Service, Address = "::ffff:10.1.1.1", Port = 443, Hostname = "Host.LAN.",
            ObservedAt = DateTimeOffset.UnixEpoch, Source = new ObservationSource { ToolId = "nmap", AgentId = "a", JobId = Guid.NewGuid() },
            Service = new ServiceDetails { Name = "ssl/http", Product = " nginx ", Banner = "Authorization: Bearer abcdefghijklmnop" },
        };

        var n = Normalizer.Normalize(Normalizer.Mask(o))!;

        Assert.Equal("10.1.1.1", n.Address);
        Assert.Equal("host.lan", n.Hostname);
        Assert.Equal(TransportProtocol.Tcp, n.Transport);
        Assert.Equal("https", n.Service!.Name);
        Assert.Equal("nginx", n.Service.Product);
        Assert.DoesNotContain("abcdefghijklmnop", n.Service.Banner);
    }

    [Fact]
    public void Normalize_rejects_invalid_address_or_port()
    {
        var o = new DiscoveryObservation
        {
            ObservationId = "x", Kind = ObservationKind.PortOpen, Address = "10.0.0.1", Port = 70000, ObservedAt = DateTimeOffset.UnixEpoch,
            Source = new ObservationSource { ToolId = "naabu", AgentId = "a", JobId = Guid.NewGuid() },
        };
        Assert.Null(Normalizer.Normalize(o));
        Assert.Null(Normalizer.Normalize(o with { Port = 80, Address = "bad address" }));
    }
}

public class ConfidenceModelTests
{
    [Fact]
    public void Single_method_uses_its_score()
    {
        Assert.Equal((0.6, "tool-reported"), ConfidenceModel.Combine([("tool-reported", 0.6)]));
    }

    [Fact]
    public void Independent_methods_combine_with_noisy_or_and_sorted_method_names()
    {
        var (score, method) = ConfidenceModel.Combine([("version-probe", 0.8), ("tool-reported", 0.6), ("signature-match", 0.9)]);
        Assert.Equal(0.992, score); // 1 - 0.2 * 0.4 * 0.1
        Assert.Equal("signature-match+tool-reported+version-probe", method);
    }

    [Fact]
    public void Repeated_evidence_of_the_same_method_does_not_inflate_the_score()
    {
        Assert.Equal((0.7, "banner-match"), ConfidenceModel.Combine([("banner-match", 0.5), ("banner-match", 0.7), ("BANNER-MATCH", 0.6)]));
    }

    [Fact]
    public void Service_evidence_method_depends_on_what_was_identified()
    {
        DiscoveryObservation Obs(ServiceDetails s, Confidence? c = null) => new()
        {
            ObservationId = "x", Kind = ObservationKind.Service, Address = "10.0.0.1", Port = 22, ObservedAt = DateTimeOffset.UnixEpoch,
            Source = new ObservationSource { ToolId = "nmap", AgentId = "a", JobId = Guid.Empty }, Service = s, Confidence = c,
        };

        Assert.Equal(("version-probe", 0.8), ConfidenceModel.ForService(Obs(new ServiceDetails { Name = "ssh", Product = "OpenSSH", Version = "9.6" })));
        Assert.Equal(("banner-match", 0.7), ConfidenceModel.ForService(Obs(new ServiceDetails { Name = "ssh", Product = "OpenSSH" })));
        Assert.Equal(("port-heuristic", 0.3), ConfidenceModel.ForService(Obs(new ServiceDetails { Name = "ssh" })));
        Assert.Equal(("tool-reported", 0.95), ConfidenceModel.ForService(Obs(new ServiceDetails { Name = "ssh" }, new Confidence { Score = 0.95, Method = "Tool-Reported" })));
    }
}
