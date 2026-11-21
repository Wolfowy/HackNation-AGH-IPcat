using System.Diagnostics;
using WebScan.Contracts;
using WebScan.Scheduling.UnitTests.Support;
using WebScan.Server.Kernel.Networking;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Modules.Scanning.Planning;
using Xunit.Abstractions;

namespace WebScan.Scheduling.UnitTests;

/// <summary>Load/perf test: a /16 with exclusions across 20 simulated agents, claim/complete loop with synthetic results.</summary>
public sealed class PlannerSimulationTests(ITestOutputHelper output)
{
    private sealed class SimJob(PlannedBatch batch, ClaimCandidate candidate)
    {
        public PlannedBatch Batch { get; } = batch;
        public ClaimCandidate Candidate { get; set; } = candidate;
        public string? Agent { get; set; }
        public string? Interface { get; set; }
        public int Rate { get; set; }
        public int FinishesAtTick { get; set; }
        public bool Done { get; set; }
        public List<(string Agent, string Interface)> Perspectives { get; } = [];
    }

    [Fact]
    public void Slash16_across_20_agents_is_fully_covered_without_overlap_and_within_caps()
    {
        var dc1 = new ScopeSegment { NetworkId = Guid.NewGuid(), NetworkName = "dc1", Zone = "dc1", Include = ["10.20.0.0/17"], Exclude = ["10.20.5.0/24"] };
        var dc2 = new ScopeSegment { NetworkId = Guid.NewGuid(), NetworkName = "dc2", Zone = "dc2", Include = ["10.20.128.0/17"], Exclude = ["10.20.200.17"] };
        var scope = new ResolvedScope { Segments = [dc1, dc2], GlobalExclusions = ["10.20.255.0/24", "10.20.64.0-10.20.64.99"] };

        var planning = Stopwatch.StartNew();
        var segments = TargetPlanner.ResolveTargets(scope, 65_536);
        var plan = TargetPlanner.PlanHosts(segments, 64, 16);
        planning.Stop();

        var expected = IpRangeSet.Parse(["10.20.0.0/16"]).Subtract(IpRangeSet.Parse(["10.20.5.0/24", "10.20.200.17", "10.20.255.0/24", "10.20.64.0-10.20.64.99"]));
        Assert.Equal((ulong)expected.Count, (ulong)plan.Batches.Sum(b => b.Count));
        Assert.True(planning.Elapsed < TimeSpan.FromSeconds(3), $"planning took {planning.Elapsed}");

        var agents = CreateAgents();
        var reaches = agents.ToDictionary(a => a.AgentId, a => AgentReach.Build(a, true));
        var limits = new ScanLimits { MaxConcurrentJobsPerZone = 40, MaxConcurrentJobsPerInterface = 2, MaxConcurrentJobsPerSubnet = 1000, SubnetPrefixLength = 16, MaxRatePerSecondGlobal = 30_000 };
        var options = new PlannerOptions();
        var start = new DateTimeOffset(2026, 11, 21, 0, 0, 0, TimeSpan.Zero);
        var jobs = plan.Batches.Select((b, i) => new SimJob(b, new ClaimCandidate(Guid.NewGuid(), Guid.Empty, "ports", 50, start.AddMilliseconds(i),
            new JobRequirement(b.Zone, b.NetworkId, ToolCapabilities.PortScan, null, b.ReachTargets), b.SubnetKey, 2000, 1000, null))).ToList();
        var byId = jobs.ToDictionary(j => j.Candidate.JobId);
        var random = new Random(42);
        var offlineAgent = agents[3].AgentId;
        var maxObserved = new Dictionary<string, int>();

        var simulation = Stopwatch.StartNew();
        var tick = 0;
        var wentOffline = false;
        for (; jobs.Any(j => !j.Done) && tick < 2000; tick++)
        {
            foreach (var job in jobs.Where(j => j.Agent is not null && !j.Done && j.FinishesAtTick <= tick)) job.Done = true;
            if (!wentOffline && tick >= 3 && jobs.Any(j => j.Agent == offlineAgent && !j.Done))
            {
                // Agent goes offline: its leases return to the queue (attempt + 1) and it never claims again.
                wentOffline = true;
                foreach (var job in jobs.Where(j => j.Agent == offlineAgent && !j.Done))
                {
                    job.Candidate = job.Candidate with { LastAgentId = offlineAgent };
                    (job.Agent, job.Interface) = (null, null);
                }
            }

            foreach (var agent in agents.Where(a => a.AgentId != offlineAgent || !wentOffline).OrderBy(_ => random.Next()))
            {
                var running = jobs.Where(j => j.Agent is not null && !j.Done)
                    .Select(j => new RunningJob(j.Agent!, j.Interface!, j.Batch.Zone, j.Batch.SubnetKey, Guid.Empty, "ports", j.Rate)).ToList();
                var candidates = jobs.Where(j => j.Agent is null && agent.AuthorizedZones.Contains(j.Batch.Zone))
                    .Select(j => j.Candidate).OrderBy(c => c.QueuedAt).Take(200).ToList();
                var decisions = ClaimSelector.Select(agent, reaches[agent.AgentId], candidates, running, limits, [], options, null, 4, start.AddSeconds(tick));
                foreach (var d in decisions)
                {
                    var job = byId[d.JobId];
                    Assert.True(Eligibility.Evaluate(agent, reaches[agent.AgentId], job.Candidate.Requirement, options).Options
                        .Any(o => o.InterfaceName == d.InterfaceName), "assigned to an ineligible perspective");
                    (job.Agent, job.Interface, job.Rate, job.FinishesAtTick) = (agent.AgentId, d.InterfaceName, d.RatePerSecond, tick + 1 + random.Next(3));
                    job.Perspectives.Add((agent.AgentId, d.InterfaceName));
                }
                AssertCaps(jobs, agents, limits, maxObserved);
            }
        }
        simulation.Stop();

        Assert.All(jobs, j => Assert.True(j.Done));
        var completed = jobs.Select(j => IpRangeSet.Parse(j.Batch.Hosts)).Aggregate(new IpRangeSet(), (acc, s) => acc.Union(s));
        Assert.Equal(expected.ToString(), completed.ToString()); // full coverage, nothing outside the scope
        Assert.Equal((ulong)completed.Count, (ulong)jobs.Sum(j => j.Batch.Count)); // zero overlap
        Assert.All(jobs, j => Assert.Equal(j.Perspectives.Count, j.Perspectives.Distinct().Count())); // never twice from one perspective
        Assert.DoesNotContain(jobs, j => j.Agent is "dc1-unreachable-1" or "dc1-unreachable-2");
        Assert.True(wentOffline);
        Assert.Contains(jobs, j => j.Candidate.LastAgentId == offlineAgent && j.Agent != offlineAgent); // reassigned
        Assert.Contains(jobs, j => j.Agent!.StartsWith("dc2-", StringComparison.Ordinal));

        output.WriteLine($"Planned {plan.Batches.Count} batches / {expected.Count} addresses in {planning.Elapsed.TotalMilliseconds:0} ms; " +
                         $"simulated {tick} ticks, 20 agents in {simulation.Elapsed.TotalMilliseconds:0} ms; " +
                         $"peak concurrency per zone: {string.Join(", ", maxObserved.Where(kv => kv.Key.StartsWith("zone:")).Select(kv => $"{kv.Key[5..]}={kv.Value}"))}; " +
                         $"jobs per agent: {string.Join(", ", jobs.GroupBy(j => j.Agent).OrderBy(g => g.Key).Select(g => $"{g.Key}={g.Count()}"))}");
    }

    private static void AssertCaps(List<SimJob> jobs, IReadOnlyList<AgentSnapshot> agents, ScanLimits limits, Dictionary<string, int> maxObserved)
    {
        var active = jobs.Where(j => j.Agent is not null && !j.Done).ToList();
        foreach (var g in active.GroupBy(j => j.Agent!))
            Assert.True(g.Count() <= agents.First(a => a.AgentId == g.Key).Limits.MaxConcurrentJobs, $"agent cap exceeded for {g.Key}");
        foreach (var g in active.GroupBy(j => (j.Agent, j.Interface)))
            Assert.True(g.Count() <= limits.MaxConcurrentJobsPerInterface, $"interface cap exceeded for {g.Key}");
        foreach (var g in active.GroupBy(j => j.Batch.Zone))
        {
            Assert.True(g.Count() <= limits.MaxConcurrentJobsPerZone, $"zone cap exceeded for {g.Key}");
            maxObserved[$"zone:{g.Key}"] = Math.Max(maxObserved.GetValueOrDefault($"zone:{g.Key}"), g.Count());
        }
        Assert.True(active.Sum(j => (long)j.Rate) <= limits.MaxRatePerSecondGlobal, "global rate budget exceeded");
    }

    /// <summary>20 agents: mixed zones, single/dual interfaces, subnet, route and default-route reachability, two that reach nothing.</summary>
    private static List<AgentSnapshot> CreateAgents()
    {
        var agents = new List<AgentSnapshot>();
        for (var i = 1; i <= 6; i++)
            agents.Add(Agents.Create($"dc1-subnet-{i}", ["dc1"], new() { ["eth0"] = [$"10.20.{i}.10/17"] }, maxJobs: 4));
        for (var i = 1; i <= 4; i++)
            agents.Add(Agents.Create($"dc1-route-{i}", ["dc1"], new() { ["eth0"] = [$"192.168.{i}.2/24"], ["eth1"] = [$"172.16.{i}.2/24"] },
                routes: [Agents.Route("10.20.0.0/18", "eth0"), Agents.Route("10.20.64.0/18", "eth1")], maxJobs: 4));
        for (var i = 1; i <= 5; i++)
            agents.Add(Agents.Create($"dc2-dual-{i}", ["dc2"], new() { ["eth0"] = [$"10.20.{128 + i}.10/17"], ["eth1"] = [$"10.20.{128 + i}.11/17"] }, maxJobs: 4));
        for (var i = 1; i <= 3; i++)
            agents.Add(Agents.Create($"both-default-{i}", ["dc1", "dc2"], new() { ["eth0"] = [$"192.168.100.{i}/24"] },
                routes: [Agents.Route("0.0.0.0/0", "eth0")], maxJobs: 2, maxRate: 1500));
        for (var i = 1; i <= 2; i++)
            agents.Add(Agents.Create($"dc1-unreachable-{i}", ["dc1"], new() { ["eth0"] = [$"192.168.200.{i}/24"] }, maxJobs: 4));
        return agents;
    }
}
