using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WebScan.Contracts;
using WebScan.Discovery.UnitTests.Infrastructure;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Discovery.Api;
using WebScan.Server.Modules.Discovery.Domain;

namespace WebScan.Discovery.UnitTests;

[Collection(DbCollection.Name)]
public class TopologyTests(TestApp app) : IAsyncLifetime
{
    private static readonly JsonSerializerOptions Json = ContractJson.Options;
    private readonly Scenario _s = new(app);

    public Task InitializeAsync() => app.ResetAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<TopologyDto> GetAsync(string query = "") =>
        (await app.Client(Roles.Viewer).GetFromJsonAsync<TopologyDto>("/api/topology" + query, Json))!;

    [Theory]
    [InlineData(null, HttpStatusCode.Unauthorized)]
    [InlineData(Roles.Viewer, HttpStatusCode.OK)]
    public async Task Topology_requires_read_role(string? role, HttpStatusCode expected) =>
        Assert.Equal(expected, (await app.Client(role).GetAsync("/api/topology")).StatusCode);

    [Theory]
    [InlineData("10.1.2.3", "10.1.2.0/24")]
    [InlineData("2001:db8:1:2:3::4", "2001:db8:1:2::/64")]
    [InlineData("web.example.com", "other")]
    public void Subnet_is_ipv4_24_or_ipv6_64(string address, string expected) => Assert.Equal(expected, Topology.SubnetOf(address));

    [Theory]
    [InlineData("10.0.0.1", 80, "http", null, null, false, "http://10.0.0.1:80/")]
    [InlineData("10.0.0.1", 80, "http", null, "http://10.0.0.1/login", false, "http://10.0.0.1/login")]
    [InlineData("10.0.0.1", 8443, "https-alt", null, null, false, "https://10.0.0.1:8443/")]
    [InlineData("10.0.0.1", 993, "imap", "ssl", null, false, "https://10.0.0.1:993/")]
    [InlineData("10.0.0.1", 9443, null, null, null, true, "https://10.0.0.1:9443/")]
    [InlineData("10.0.0.1", 22, "ssh", null, null, false, null)]
    [InlineData("fe80::1", 8080, "http-proxy", null, null, false, "http://[fe80::1]:8080/")]
    public void Service_url_prefers_http_probe_then_tls_then_http_like_names(string address, int port, string? name, string? tunnel, string? httpUrl,
        bool cert, string? expected) =>
        Assert.Equal(expected, Topology.ServiceUrl(address, port, name, tunnel, httpUrl, cert));

    [Fact]
    public async Task Groups_hosts_into_ipv4_24_and_ipv6_64_subnets()
    {
        await _s.RunAsync(Scenario.Coverage(["10.5.0.0/16"]), 3, _s.HostUp("10.5.1.7"), _s.HostUp("10.5.1.9"), _s.HostUp("10.5.2.3"),
            _s.HostUp("2001:db8::1"), _s.HostUp("2001:db8::2:1"), _s.HostUp("2001:db8:0:1::5"));

        var topology = await GetAsync();
        Assert.Equal([("10.5.1.0/24", 2), ("10.5.2.0/24", 1), ("2001:db8:0:1::/64", 1), ("2001:db8::/64", 2)],
            topology.Subnets.Select(s => (s.Cidr, s.HostCount)));
        Assert.All(topology.Subnets, s => Assert.Equal(("lab", $"lab|{s.Cidr}"), (s.Zone, s.Id)));
        Assert.Equal("lab|2001:db8::/64", topology.Hosts.Single(h => h.Address == "2001:db8::2:1").Subnet);
        Assert.False(topology.Truncated);
    }

    [Fact]
    public async Task ObservedBy_lists_distinct_agent_interfaces_and_perspectives()
    {
        var coverage = Scenario.Coverage(["10.6.0.0/24"]);
        await _s.RunAsync(coverage, 3, _s.HostUp("10.6.0.1"), _s.Port("10.6.0.1", 22));
        _s.NextRun().Perspective = ("agent-2", "ens18", "lab");
        await _s.RunAsync(coverage, 3, _s.HostUp("10.6.0.1"), _s.HostUp("10.6.0.2"));
        _s.NextRun(); // same perspective again: repeated raw observations must not duplicate entries
        await _s.RunAsync(coverage, 3, _s.HostUp("10.6.0.2"));

        var topology = await GetAsync();
        var observedBy = topology.Hosts.ToDictionary(h => h.Address, h => h.ObservedBy.Select(o => (o.AgentId, o.InterfaceName)).ToList());
        Assert.Equal([("agent-1", "eth0"), ("agent-2", "ens18")], observedBy["10.6.0.1"]);
        Assert.Equal([("agent-2", "ens18")], observedBy["10.6.0.2"]);
        Assert.Equal([("agent-1", "eth0", "lab"), ("agent-2", "ens18", "lab")],
            topology.Perspectives.Select(p => (p.AgentId, p.InterfaceName, p.Zone)));
    }

    [Fact]
    public async Task Same_ip_in_two_zones_is_two_hosts_in_per_zone_subnets_with_zone_scoped_perspectives()
    {
        _s.Perspective = ("agent-waw", "eth0", "dc-warsaw");
        await _s.RunAsync(Scenario.ZoneCoverage("dc-warsaw", "10.0.0.0/24"), 3, _s.HostUpWithMac("10.0.0.5", "02:42:ac:1e:00:0a", "Docker"));
        _s.NextRun().Perspective = ("agent-lab", "wg0", "lab");
        await _s.RunAsync(Scenario.ZoneCoverage("lab", "10.0.0.0/24"), 3, _s.HostUp("10.0.0.5"), _s.HostUp("10.0.0.6"));

        var topology = await GetAsync();
        Assert.Equal([("dc-warsaw|10.0.0.0/24", "10.0.0.0/24", "dc-warsaw", 1), ("lab|10.0.0.0/24", "10.0.0.0/24", "lab", 2)],
            topology.Subnets.Select(s => (s.Id, s.Cidr, s.Zone, s.HostCount)));
        var same = topology.Hosts.Where(h => h.Address == "10.0.0.5").ToList();
        Assert.Equal(2, same.Select(h => h.Id).Distinct().Count());
        // Each machine is observed only by the perspective of its own zone, so perspective edges never cross zones.
        Assert.Equal([("dc-warsaw|10.0.0.0/24", "agent-waw"), ("lab|10.0.0.0/24", "agent-lab")],
            same.Select(h => (h.Subnet, Assert.Single(h.ObservedBy).AgentId)));
        Assert.Equal(("02:42:AC:1E:00:0A", "Docker"), (same[0].MacAddress, same[0].MacVendor));
        Assert.Null(same[1].MacAddress);
        Assert.Equal([("10.0.0.5", "dc-warsaw")], (await GetAsync("?zone=dc-warsaw")).Hosts.Select(h => (h.Address, h.Zone)));
    }

    [Fact]
    public async Task Excludes_gone_services_keeps_gone_hosts_and_derives_urls()
    {
        const string a = "10.7.0.1", v6 = "2001:db8::10";
        var imap = _s.Service(a, 993, "imap");
        imap = imap with { Service = imap.Service! with { Tunnel = "ssl" } };
        await _s.RunAsync(Scenario.Coverage(["10.7.0.0/24"]), 3,
            _s.HostUp(a), _s.Port(a, 22), _s.Service(a, 22, "ssh", "OpenSSH", "9.6"),
            _s.Port(a, 80), _s.Http(a, 80, 200, "Portal", "nginx"),
            _s.Port(a, 443), _s.Service(a, 443, "https"),
            _s.Port(a, 8443), _s.Tls(a, 8443, "ab01", "panel.example"),
            _s.Port(a, 993), imap,
            _s.Port(a, 3306),
            _s.HostUp("10.7.0.2"),
            _s.HostUp(v6), _s.Port(v6, 8080), _s.Service(v6, 8080, "http-proxy"));
        await _s.QueryAsync(async db =>
        {
            await db.Services.Where(s => s.Port == 3306).ExecuteUpdateAsync(u => u.SetProperty(s => s.State, ServiceState.Gone));
            return await db.Hosts.Where(h => h.Address == "10.7.0.2").ExecuteUpdateAsync(u => u.SetProperty(h => h.Status, HostStatus.Gone));
        });

        var topology = await GetAsync();
        var host = topology.Hosts.Single(h => h.Address == a);
        Assert.Equal(5, host.OpenPortCount);
        Assert.Equal(
        [
            (22, (string?)null, false, false), (80, "http://10.7.0.1:80/", true, false), (443, "https://10.7.0.1:443/", true, true),
            (993, "https://10.7.0.1:993/", false, true), (8443, "https://10.7.0.1:8443/", false, true),
        ], host.Services.Select(s => (s.Port, s.Url, s.IsWeb, s.Tls)));
        Assert.Equal(("OpenSSH", "9.6"), (host.Services[0].Product, host.Services[0].Version));
        Assert.Equal("http://[2001:db8::10]:8080/", topology.Hosts.Single(h => h.Address == v6).Services.Single().Url);
        Assert.Equal(HostStatus.Gone, topology.Hosts.Single(h => h.Address == "10.7.0.2").Status);

        // The services list and host detail expose the same derived url.
        var services = await app.Client(Roles.Viewer).GetFromJsonAsync<PagedResult<ServiceDto>>("/api/assets/services?port=8443", Json);
        Assert.Equal("https://10.7.0.1:8443/", Assert.Single(services!.Items).Url);
        var detail = await app.Client(Roles.Viewer).GetFromJsonAsync<HostDetailDto>($"/api/assets/hosts/{host.Id}", Json);
        Assert.Null(detail!.Services.Single(s => s.Port == 22).Url);
        Assert.Equal("https://10.7.0.1:993/", detail.Services.Single(s => s.Port == 993).Url);
    }

    [Fact]
    public async Task Filters_by_zone_search_and_network()
    {
        await _s.IngestAsync(_s.HostUp("10.8.0.1"));
        _s.Perspective = ("agent-dmz", "eth1", "dmz");
        await _s.RunAsync(Scenario.Coverage(["10.8.0.0/16"]), 3, _s.HostUp("10.8.1.1", "web.example.com"));
        var network = Guid.NewGuid();
        app.NetworkScope.Networks[network] = ["10.8.1.0/24"];
        app.NetworkScope.Zones[network] = "dmz";
        var labNetwork = Guid.NewGuid(); // same range in another zone: other machines
        app.NetworkScope.Networks[labNetwork] = ["10.8.1.0/24"];

        string[] Addresses(TopologyDto t) => [.. t.Hosts.Select(h => h.Address)];
        Assert.Equal(["10.8.1.1"], Addresses(await GetAsync("?zone=dmz")));
        Assert.Equal(["10.8.0.1"], Addresses(await GetAsync("?search=10.8.0")));
        Assert.Equal(["10.8.1.1"], Addresses(await GetAsync("?search=WEB.example")));
        Assert.Equal(["10.8.1.1"], Addresses(await GetAsync($"?networkId={network}")));
        Assert.Empty((await GetAsync($"?networkId={Guid.NewGuid()}")).Hosts);
        Assert.Empty((await GetAsync($"?networkId={labNetwork}")).Hosts);
        Assert.Equal([("agent-dmz", "eth1")], (await GetAsync("?zone=dmz")).Perspectives.Select(p => (p.AgentId, p.InterfaceName)));
    }
}
