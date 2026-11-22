using WebScan.Contracts;
using WebScan.Scheduling.UnitTests.Support;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Modules.Scanning.Planning;

namespace WebScan.Scheduling.UnitTests;

public sealed class ClaimSelectorTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
    private static readonly Guid Run = Guid.NewGuid();
    private static readonly Guid Network = Guid.NewGuid();
    private static readonly PlannerOptions Options = new();
    private static readonly ScanLimits Limits = new() { MaxConcurrentJobsPerInterface = 4, MaxConcurrentJobsPerZone = 100, MaxConcurrentJobsPerSubnet = 100, MaxRatePerSecondGlobal = 100_000 };

    private static ClaimCandidate Candidate(string target = "10.0.1.0/24", int priority = 50, int ageMinutes = 0, string step = "s", string? lastAgent = null,
        int rate = 500, int stepConcurrency = 50, string zone = "dc1", string? subnet = "10.0.0.0/16", Guid? network = null) =>
        new(Guid.NewGuid(), Run, step, priority, Now.AddMinutes(-ageMinutes), new JobRequirement(zone, network ?? Network, ToolCapabilities.PortScan, null, [target]),
            subnet, rate, stepConcurrency, lastAgent);

    private static RunningJob Running(string agent = "other", string nic = "eth0", string zone = "dc1", string? subnet = "10.0.0.0/16", string step = "s", int rate = 500) =>
        new(agent, nic, zone, subnet, Run, step, rate);

    private static IReadOnlyList<ClaimDecision> Select(AgentSnapshot agent, IReadOnlyList<ClaimCandidate> candidates, IReadOnlyCollection<RunningJob>? running = null,
        ScanLimits? limits = null, IReadOnlyCollection<PerformanceSample>? performance = null, int maxJobs = 10, IReadOnlyCollection<string>? interfaces = null,
        IReadOnlyDictionary<(Guid, Guid), string>? pinned = null) =>
        ClaimSelector.Select(agent, AgentReach.Build(agent, true), candidates, running ?? [], limits ?? Limits, performance ?? [], Options, interfaces, maxJobs, Now, pinned);

    private static AgentSnapshot TwoNics(int maxJobs = 10, int maxRate = 10_000) =>
        Agents.Create("a1", ["dc1"], new() { ["eth0"] = ["10.0.0.5/16"], ["eth1"] = ["10.0.0.6/16"] }, maxJobs: maxJobs, maxRate: maxRate);

    [Fact]
    public void Default_route_agent_leaves_a_subnet_to_the_agent_attached_to_it_while_that_agent_is_online()
    {
        // Same zone (one address space): the gateway agent could reach 10.0.1.0/24 through its default route, the local agent sits in it.
        var gateway = Agents.Create("gw", ["dc1"], new() { ["eth0"] = ["192.168.0.5/24"] }, [new RouteInfo { Destination = "0.0.0.0/0", Gateway = "192.168.0.1", InterfaceName = "eth0" }]);
        var local = Agents.Simple("local", "dc1", "10.0.1.20/24");
        var job = Candidate(target: "10.0.1.0/24");
        IReadOnlyList<ClaimDecision> Claim(params AgentSnapshot[] peers) =>
            ClaimSelector.Select(gateway, AgentReach.Build(gateway, true), [job], [], Limits, [], Options, null, 10, Now, null,
                peers.Select(p => (p, AgentReach.Build(p, true))).ToList());

        Assert.Empty(Claim(local));
        Assert.Single(Claim(local with { IsOnline = false })); // the local agent is gone: the scan goes on through the router
        Assert.Single(Claim(local with { ApprovedTools = [Agents.Httpx] })); // it cannot run the step itself
        Assert.Single(Claim()); // no peers known (e.g. simulator): previous behaviour

        // The attached agent itself is never held back.
        Assert.Single(ClaimSelector.Select(local, AgentReach.Build(local, true), [job], [], Limits, [], Options, null, 10, Now, null,
            [(gateway, AgentReach.Build(gateway, true))]));
    }

    [Fact]
    public void Agent_concurrency_counts_running_jobs()
    {
        var agent = Agents.Simple("a1", "dc1", "10.0.0.5/16", maxJobs: 3);
        var decisions = Select(agent, [Candidate(), Candidate(), Candidate()], [Running(agent: "a1")]);
        Assert.Equal(2, decisions.Count);
    }

    [Fact]
    public void Interface_cap_spills_over_to_another_interface_and_both_run_in_parallel()
    {
        // Different networks of the run may use different interfaces of the same agent in parallel.
        var limits = Limits with { MaxConcurrentJobsPerInterface = 2 };
        var networks = Enumerable.Range(0, 6).Select(_ => Guid.NewGuid()).ToList();
        var decisions = Select(TwoNics(), networks.Select(n => Candidate(network: n)).ToList(), limits: limits);
        Assert.Equal(4, decisions.Count);
        Assert.Equal(2, decisions.Count(d => d.InterfaceName == "eth0"));
        Assert.Equal(2, decisions.Count(d => d.InterfaceName == "eth1"));
    }

    [Fact]
    public void One_interface_per_run_and_network_across_jobs_and_claims()
    {
        var limits = Limits with { MaxConcurrentJobsPerInterface = 2 };
        var first = Select(TwoNics(), Enumerable.Range(0, 4).Select(_ => Candidate()).ToList(), limits: limits);
        Assert.Equal(2, first.Count); // the pinned interface is full: remaining jobs wait instead of switching perspective
        Assert.Single(first.Select(d => d.InterfaceName).Distinct());

        // A later claim (e.g. the next workflow step) honours the interface already used for this run/network,
        // even when the other interface looks better (free capacity, measured throughput).
        var pinned = new Dictionary<(Guid, Guid), string> { [(Run, Network)] = "eth1" };
        var performance = new[] { new PerformanceSample("a1", "eth0", "naabu", 1000), new PerformanceSample("a1", "eth1", "naabu", 1) };
        var later = Select(TwoNics(), [Candidate(step: "ports"), Candidate(step: "ports")], [Running(agent: "a1", nic: "eth1")],
            limits: Limits, performance: performance, pinned: pinned);
        Assert.All(later, d => Assert.Equal("eth1", d.InterfaceName));
        Assert.Equal(2, later.Count);
    }

    [Fact]
    public void Pin_is_ignored_when_the_pinned_interface_cannot_reach_the_targets()
    {
        var agent = Agents.Create("a1", ["dc1"], new() { ["eth0"] = ["10.0.0.5/16"], ["eth1"] = ["10.9.0.5/16"] });
        var pinned = new Dictionary<(Guid, Guid), string> { [(Run, Network)] = "eth1" };
        var decision = Assert.Single(Select(agent, [Candidate(target: "10.0.1.0/24")], pinned: pinned));
        Assert.Equal("eth0", decision.InterfaceName);
    }

    [Fact]
    public void Zone_subnet_and_step_caps_are_enforced()
    {
        var agent = TwoNics();
        Assert.Single(Select(agent, [Candidate(), Candidate()], [Running(), Running()], Limits with { MaxConcurrentJobsPerZone = 3 }));
        Assert.Single(Select(agent, [Candidate(), Candidate(subnet: "10.1.0.0/16")], [Running()], Limits with { MaxConcurrentJobsPerSubnet = 1 }));
        Assert.Equal(2, Select(agent, [Candidate(stepConcurrency: 2), Candidate(stepConcurrency: 2), Candidate(stepConcurrency: 2)]).Count);
    }

    [Fact]
    public void Higher_priority_then_longer_waiting_jobs_go_first()
    {
        var agent = TwoNics(maxJobs: 1);
        var low = Candidate(priority: 10, ageMinutes: 50);
        var high = Candidate(priority: 90);
        Assert.Equal(high.JobId, Select(agent, [low, high]).Single().JobId);

        var young = Candidate(ageMinutes: 1);
        var old = Candidate(ageMinutes: 30);
        Assert.Equal(old.JobId, Select(agent, [young, old]).Single().JobId);
    }

    [Fact]
    public void Faster_interface_is_chosen_by_measured_throughput()
    {
        var performance = new[]
        {
            new PerformanceSample("a1", "eth0", "naabu", 100), new PerformanceSample("a1", "eth1", "naabu", 900), new PerformanceSample("b", "eth0", "naabu", 500),
        };
        Assert.Equal("eth1", Select(TwoNics(), [Candidate()], performance: performance).Single().InterfaceName);
    }

    [Fact]
    public void A_job_lost_by_this_agent_is_preferred_by_others()
    {
        var agent = TwoNics(maxJobs: 1);
        var lostHere = Candidate(lastAgent: "a1", ageMinutes: 10);
        var fresh = Candidate();
        Assert.Equal(fresh.JobId, Select(agent, [lostHere, fresh]).Single().JobId);
        Assert.Equal(lostHere.JobId, Select(agent, [lostHere]).Single().JobId); // still runnable when nobody else is there
    }

    [Fact]
    public void Rate_is_the_minimum_of_requested_agent_cap_and_global_share()
    {
        Assert.Equal(300, Select(TwoNics(maxRate: 10_000), [Candidate(rate: 300)]).Single().RatePerSecond);
        Assert.Equal(200, Select(TwoNics(maxRate: 200), [Candidate(rate: 300)]).Single().RatePerSecond);
        // Global 1000, 3 running at 300 each: share = min(1000/4, 1000-900) = 100.
        var decision = Select(TwoNics(), [Candidate(rate: 500)], [Running(rate: 300), Running(rate: 300), Running(rate: 300)], Limits with { MaxRatePerSecondGlobal = 1000 });
        Assert.Equal(100, decision.Single().RatePerSecond);
        Assert.Empty(Select(TwoNics(), [Candidate()], [Running(rate: 1000)], Limits with { MaxRatePerSecondGlobal = 1000 }));
    }

    [Fact]
    public void Ineligible_jobs_and_unrequested_interfaces_are_skipped()
    {
        var agent = TwoNics();
        Assert.Empty(Select(agent, [Candidate(target: "172.16.0.0/24"), Candidate(zone: "dmz")]));
        Assert.All(Select(agent, [Candidate(), Candidate()], interfaces: ["eth1"]), d => Assert.Equal("eth1", d.InterfaceName));
    }
}
