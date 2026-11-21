using WebScan.Contracts;
using WebScan.Scheduling.UnitTests.Support;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Modules.Scanning.Planning;

namespace WebScan.Scheduling.UnitTests;

public sealed class EligibilityTests
{
    private static readonly Guid Network = Guid.NewGuid();
    private static readonly PlannerOptions Options = new();

    private static JobRequirement Job(string[] targets, string zone = "dc1", string capability = ToolCapabilities.PortScan, string? tool = null) =>
        new(zone, Network, capability, tool, targets);

    private static EligibilityResult Evaluate(AgentSnapshot agent, JobRequirement job, PlannerOptions? options = null) =>
        Eligibility.Evaluate(agent, AgentReach.Build(agent, (options ?? Options).AllowDefaultRoute), job, options ?? Options);

    [Fact]
    public void Agent_must_be_authorized_for_the_zone_and_restricted_network()
    {
        var agent = Agents.Simple("a1", "dc1", "10.0.0.5/16");
        Assert.True(Evaluate(agent, Job(["10.0.1.0/24"])).IsEligible);
        Assert.Contains("zone", Evaluate(agent, Job(["10.0.1.0/24"], zone: "dmz")).Reason);
        var restricted = agent with { AuthorizedNetworkIds = [Guid.NewGuid()] };
        Assert.Contains("restricted", Evaluate(restricted, Job(["10.0.1.0/24"])).Reason);
        Assert.False(Evaluate(agent with { Status = AgentStatus.Disabled }, Job(["10.0.1.0/24"])).IsEligible);
    }

    [Fact]
    public void Only_approved_tools_with_the_capability_count()
    {
        var agent = Agents.Simple("a1", "dc1", "10.0.0.5/16", tools: [Agents.Httpx]);
        var result = Evaluate(agent, Job(["10.0.1.0/24"]));
        Assert.False(result.IsEligible);
        Assert.Contains("port-scan", result.Reason);
    }

    [Fact]
    public void Tool_choice_prefers_step_tool_then_configured_preference_then_id_order()
    {
        var agent = Agents.Simple("a1", "dc1", "10.0.0.5/16");
        Assert.Equal("naabu", Eligibility.SelectTool(agent, ToolCapabilities.PortScan, "naabu", Options));
        Assert.Equal("naabu", Eligibility.SelectTool(agent, ToolCapabilities.PortScan, null, Options)); // "naabu" < "nmap"
        var preferNmap = new PlannerOptions { ToolPreference = new(StringComparer.OrdinalIgnoreCase) { [ToolCapabilities.PortScan] = ["masscan", "nmap"] } };
        Assert.Equal("nmap", Eligibility.SelectTool(agent, ToolCapabilities.PortScan, null, preferNmap));
        Assert.Equal("nmap", Eligibility.SelectTool(agent, ToolCapabilities.PortScan, "unknown-tool", preferNmap));
    }

    [Fact]
    public void Operation_capability_can_be_overridden_by_configuration()
    {
        var options = new PlannerOptions { OperationCapabilities = new(StringComparer.OrdinalIgnoreCase) { ["ScanPorts"] = "fast-port-scan" } };
        Assert.Equal("fast-port-scan", options.CapabilityFor(ScanOperation.ScanPorts));
        Assert.Equal(ToolCapabilities.HttpProbe, options.CapabilityFor(ScanOperation.HttpProbe));
        Assert.Equal("fast-port-scan", options.EffectiveCapabilityMapping()["ScanPorts"]);
        Assert.Throws<InvalidOperationException>(() => options.CapabilityFor(ScanOperation.PersistObservations));
    }

    [Fact]
    public void Reachability_by_interface_subnet_or_route()
    {
        var agent = Agents.Create("a1", ["dc1"], new() { ["eth0"] = ["10.0.0.5/24"], ["eth1"] = ["192.168.1.2/24"] },
            routes: [Agents.Route("10.20.0.0/16", "eth1")]);

        Assert.Equal(["eth0"], Evaluate(agent, Job(["10.0.0.0/25"])).Options.Select(o => o.InterfaceName));
        Assert.Equal(["eth1"], Evaluate(agent, Job(["10.20.5.0/24"])).Options.Select(o => o.InterfaceName));
        Assert.False(Evaluate(agent, Job(["10.0.0.0/23"])).IsEligible); // half of it is not reachable
        Assert.False(Evaluate(agent, Job(["172.16.0.0/24"])).IsEligible);
    }

    [Fact]
    public void Default_route_counts_only_when_allowed_and_is_needed_for_hostnames()
    {
        var agent = Agents.Create("a1", ["dc1"], new() { ["eth0"] = ["10.0.0.5/24"] }, routes: [Agents.Route("0.0.0.0/0", "eth0")]);

        Assert.True(Evaluate(agent, Job(["172.16.0.0/24"])).IsEligible);
        Assert.True(Evaluate(agent, Job(["app.example.com"])).IsEligible);
        var noDefault = new PlannerOptions { AllowDefaultRoute = false };
        Assert.False(Evaluate(agent, Job(["172.16.0.0/24"]), noDefault).IsEligible);
        Assert.False(Evaluate(agent, Job(["app.example.com"]), noDefault).IsEligible);
        Assert.False(Evaluate(agent, Job(["2001:db8::/120"])).IsEligible); // IPv4 default route does not cover IPv6
    }

    [Fact]
    public void Down_interfaces_are_ignored_and_every_reaching_interface_is_a_perspective()
    {
        var agent = Agents.Create("a1", ["dc1"], new() { ["eth0"] = ["10.0.0.5/16"], ["eth1"] = ["10.0.0.6/16"], ["eth2"] = ["10.0.0.7/16"] });
        agent = agent with { Interfaces = agent.Interfaces.Select(i => i.Name == "eth2" ? i with { IsUp = false } : i).ToList() };
        Assert.Equal(["eth0", "eth1"], Evaluate(agent, Job(["10.0.3.0/24"])).Options.Select(o => o.InterfaceName));
    }
}
