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
