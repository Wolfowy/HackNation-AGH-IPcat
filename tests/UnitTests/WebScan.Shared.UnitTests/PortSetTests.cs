using WebScan.Contracts;

namespace WebScan.Shared.UnitTests;

public class PortSetTests
{
    [Fact]
    public void Parses_merges_intersects_and_subtracts()
    {
        Assert.True(PortSet.TryParse("443, 80,81-90,85-100,22", out var set));
        Assert.Equal("22,80-100,443", set.ToString());
        Assert.Equal(23, set.Count);
        Assert.True(set.Contains(95) && !set.Contains(101));

        Assert.True(PortSet.TryParse("1-1000", out var range));
        Assert.Equal("22,80-100,443", set.Intersect(range).ToString());
        Assert.Equal("1-21,23-79,101-442,444-1000", range.Except(set).ToString());
        Assert.True(range.ContainsAll(set));
        Assert.False(set.ContainsAll(range));
        Assert.True(PortSet.All.IsAll && PortSet.All.Except(PortSet.All).IsEmpty);
    }

    [Theory]
    [InlineData("top-100")]
    [InlineData("")]
    [InlineData("0")]
    [InlineData("65536")]
    [InlineData("90-80")]
    [InlineData("80;id")]
    [InlineData("1-2-3")]
    public void Rejects_specs_that_cannot_be_checked(string spec) => Assert.False(PortSet.TryParse(spec, out _));

    [Fact]
    public void Effective_policy_ports_are_allowlist_minus_denylist()
    {
        Assert.True(PortScope.Effective([], []).IsAll);
        Assert.Equal("1-22,24-65535", PortScope.Effective([], ["23"]).ToString());
        Assert.Equal("80,8000-8079,8081-8100", PortScope.Effective(["80", "8000-8100"], ["8080", "bogus"]).ToString());
    }

    [Fact]
    public void Nmap_top_ports_follow_frequency_order()
    {
        Assert.Equal("21-23,80,443", NmapTopPorts.Top(5)!.ToString());
        Assert.Equal(100, NmapTopPorts.Top(100)!.Count);
        Assert.Equal(1000, NmapTopPorts.Top(1000)!.Count);
        Assert.Null(NmapTopPorts.Top(1001));
    }

    [Fact]
    public void Probe_ports_count_only_for_tcp_ping_methods()
    {
        string[] InEffect(ScanOperation op, Dictionary<string, string> values) => [.. PortScope.ParametersInEffect(op, values)];

        Assert.Equal(["ports"], InEffect(ScanOperation.ScanPorts, new() { ["ports"] = "80", ["scanType"] = "connect" }));
        Assert.Equal(["probePorts"], InEffect(ScanOperation.DiscoverHosts, new() { ["method"] = "tcp-ack", ["probePorts"] = "80" }));
        Assert.Empty(InEffect(ScanOperation.DiscoverHosts, new() { ["method"] = "icmp", ["probePorts"] = "80" }));
        Assert.Empty(InEffect(ScanOperation.HttpProbe, new() { ["rate"] = "10" }));
    }
}
