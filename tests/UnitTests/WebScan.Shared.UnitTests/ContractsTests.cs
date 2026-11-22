using System.Text.Json;
using WebScan.Contracts;

namespace WebScan.Shared.UnitTests;

public class ContractsTests
{
    [Fact]
    public void Validator_applies_defaults_and_rejects_unknown_parameters()
    {
        var schema = OperationCatalog.Get(ScanOperation.ScanPorts).Parameters;
        var ok = ParameterValidator.Validate(schema, new Dictionary<string, string> { ["ports"] = "22,80,8000-8100" });
        Assert.True(ok.IsValid);
        Assert.Equal("connect", ok.Values["scanType"]);

        var bad = ParameterValidator.Validate(schema, new Dictionary<string, string> { ["ports"] = "80;id", ["extraArgs"] = "--script=x" });
        Assert.False(bad.IsValid);
        Assert.Contains(bad.Errors, e => e.Contains("extraArgs"));
        Assert.Contains(bad.Errors, e => e.Contains("ports"));
    }

    [Theory]
    [InlineData("top-100", true)]
    [InlineData("1-65535", true)]
    [InlineData("0", false)]
    [InlineData("80-20", false)]
    [InlineData("80,-p", false)]
    public void PortSpec(string spec, bool valid) => Assert.Equal(valid, ParameterValidator.IsValidPortSpec(spec));

    [Fact]
    public void Probe_ports_take_explicit_ports_only_and_privileged_techniques_are_flagged()
    {
        var discover = OperationCatalog.Get(ScanOperation.DiscoverHosts).Parameters;
        Assert.True(ParameterValidator.Validate(discover, new Dictionary<string, string> { ["probePorts"] = "22,80,8000-8100" }).IsValid);
        Assert.Contains(ParameterValidator.Validate(discover, new Dictionary<string, string> { ["probePorts"] = "top-100" }).Errors, e => e.Contains("probePorts"));

        Assert.True(OperationCatalog.NeedsRawSockets(ScanOperation.ScanPorts, new Dictionary<string, string> { ["scanType"] = "syn" }));
        Assert.False(OperationCatalog.NeedsRawSockets(ScanOperation.ScanPorts, new Dictionary<string, string> { ["scanType"] = "connect" }));
        Assert.True(OperationCatalog.NeedsRawSockets(ScanOperation.DiscoverHosts, new Dictionary<string, string> { ["method"] = "arp" }));
        Assert.False(OperationCatalog.NeedsRawSockets(ScanOperation.DiscoverHosts, new Dictionary<string, string> { ["method"] = "default" }));
    }

    [Fact]
    public void Masker_hides_cookie_values_and_tokens()
    {
        Assert.Equal("sid=***; Path=/; HttpOnly", SensitiveDataMasker.MaskHeader("Set-Cookie", "sid=abc123; Path=/; HttpOnly"));
        Assert.Equal("***", SensitiveDataMasker.MaskHeader("Authorization", "Bearer abc.def.ghi"));
        Assert.DoesNotContain("hunter2", SensitiveDataMasker.MaskTokens("login password=hunter2 ok"));
        Assert.Equal("nginx", SensitiveDataMasker.MaskHeader("Server", "nginx"));
    }

    [Fact]
    public void Set_cookie_parser_splits_joined_headers_and_keeps_only_names_and_flags()
    {
        // httpx joins repeated Set-Cookie headers with ", "; the comma of an Expires date is not a separator.
        var cookies = HttpCookies.Parse("sid=abc; Expires=Wed, 19-May-21 01:11:11 GMT; Path=/; Secure; HttpOnly; SameSite=lax, " +
                                        "theme=dark; Domain=.example.com, BIGipServerweb_pool=1677787402.36895.0000; path=/");

        Assert.Equal(["sid", "theme", "BIGipServerweb_pool"], cookies.Select(c => c.Name));
        Assert.Equal(new HttpCookie { Name = "sid", Secure = true, HttpOnly = true, SameSite = "Lax", Path = "/" }, cookies[0]);
        Assert.Equal((false, false, ".example.com"), (cookies[1].Secure, cookies[1].HttpOnly, cookies[1].Domain));
        Assert.Equal("10.1.1.100:8080", cookies[2].DecodedValue);
        Assert.Equal("sid", HttpCookies.Parse(SensitiveDataMasker.MaskHeader("Set-Cookie", "sid=abc; HttpOnly"))[0].Name);
        Assert.Empty(HttpCookies.Parse(null));
    }

    [Theory]
    [InlineData("1677787402.36895.0000", "10.1.1.100:8080")]
    [InlineData("rd5o00000000000000000000ffffc0000201o80", "192.0.2.1:80")]
    [InlineData("vi20010112000000000000000000000030.20480", "[2001:112::30]:80")]
    [InlineData("!Zm9vYmFyZW5jcnlwdGVk", null)]
    [InlineData("***", null)]
    public void Bigip_persistence_cookie_decodes_to_the_internal_pool_member(string value, string? expected) =>
        Assert.Equal(expected, HttpCookies.DecodeBigIp(value));

    [Fact]
    public void Contracts_round_trip_with_string_enums()
    {
        var obs = new DiscoveryObservation
        {
            ObservationId = ObservationIds.Compute(Guid.NewGuid(), ObservationKind.PortOpen, "10.0.0.1", 80, TransportProtocol.Tcp),
            Kind = ObservationKind.PortOpen, Address = "10.0.0.1", Port = 80, Transport = TransportProtocol.Tcp,
            ObservedAt = DateTimeOffset.UtcNow,
            Source = new ObservationSource { ToolId = "naabu", AgentId = "agent-1", JobId = Guid.NewGuid() },
            PortState = new PortDetails { State = "open" },
        };
        var json = JsonSerializer.Serialize(obs, ContractJson.Options);
        Assert.Contains("\"kind\":\"PortOpen\"", json);
        var back = JsonSerializer.Deserialize<DiscoveryObservation>(json, ContractJson.Options)!;
        Assert.Equal(obs.ObservationId, back.ObservationId);
        Assert.Equal(32, obs.ObservationId.Length);
    }
}
