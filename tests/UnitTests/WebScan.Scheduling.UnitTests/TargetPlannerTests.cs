using WebScan.Contracts;
using WebScan.Server.Kernel.Networking;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Modules.Scanning.Planning;

namespace WebScan.Scheduling.UnitTests;

public sealed class TargetPlannerTests
{
    private static ScopeSegment Segment(string zone, string[] include, string[]? exclude = null) =>
        new() { NetworkId = Guid.NewGuid(), NetworkName = zone, Zone = zone, Include = include, Exclude = exclude ?? [] };

    private static IReadOnlyList<SegmentTargets> Resolve(params ScopeSegment[] segments) =>
        TargetPlanner.ResolveTargets(new ResolvedScope { Segments = segments }, 65_536);

    private static IpRangeSet Covered(TargetPlan plan) => IpRangeSet.Parse(plan.Batches.SelectMany(b => b.Hosts).Where(h => IpRangeSet.Classify(h) != TargetEntryKind.Hostname));

    [Theory]
    [InlineData(null, 256)]
    [InlineData(30, 64)]
    [InlineData(2000, 1024)]
    [InlineData(300, 256)]
    [InlineData(512, 512)]
    public void Batch_size_is_clamped_and_rounded_to_a_power_of_two(int? requested, int expected) =>
        Assert.Equal(expected, TargetPlanner.NormalizeBatchSize(requested, 256));

    [Theory]
    [InlineData(null, null, 256, "default")]  // no measurements: configured default
    [InlineData(null, 1.0, 256, "measured")]  // 1 t/s × 300 s = 300 → 256
    [InlineData(null, 0.1, 64, "measured")]   // 30 → clamped to 64
    [InlineData(null, 50.0, 1024, "measured")] // 15000 → clamped to 1024
    [InlineData(128, 50.0, 128, "workflow")]  // explicit workflow batchSize wins over measurements
    public void Adaptive_batch_size_aims_at_the_target_job_duration(int? explicitSize, double? tps, int expected, string reason)
    {
        var (size, why) = TargetPlanner.ChooseBatchSize(explicitSize, 256, 300, tps);
        Assert.Equal(expected, size);
        Assert.Contains(reason, why);
        Assert.Contains(expected.ToString(System.Globalization.CultureInfo.InvariantCulture), why);
    }

    [Fact]
    public void Duration_range_uses_parallelism_measured_rates_and_rate_cap()
    {
        // 4096 targets in 16 jobs of 256, 4 parallel slots, agents at 1 and 2 targets/s per job.
        var (min, max) = TargetPlanner.EstimateDuration(4096, 16, 256, [1.0, 2.0], 4, rateCap: null)!.Value;
        Assert.Equal(512, min);   // 4096 / (2 t/s × 4)
        Assert.Equal(1024, max);  // 4 waves × 256 targets at 1 t/s
        Assert.Equal(4096, TargetPlanner.EstimateDuration(4096, 16, 256, [1.0, 2.0], 4, rateCap: 1)!.Value.MinSeconds); // ≥ 1 packet per target
        Assert.Null(TargetPlanner.EstimateDuration(4096, 16, 256, [], 4, null));    // nothing measured
        Assert.Null(TargetPlanner.EstimateDuration(4096, 16, 256, [1.0], 0, null)); // nobody to run the jobs
        Assert.Equal((0d, 0d), TargetPlanner.EstimateDuration(0, 0, 256, [1.0], 4, null));
    }

    [Fact]
    public void Batches_are_cidr_aligned_non_overlapping_and_cover_the_scope()
    {
        var plan = TargetPlanner.PlanHosts(Resolve(Segment("dc", ["10.0.0.0/22"])), 256, 16);

        Assert.Equal(["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"], plan.Batches.SelectMany(b => b.Hosts));
        Assert.All(plan.Batches, b => Assert.Equal(256, b.Count));
        Assert.Equal(4, plan.Batches.Select(b => b.TargetKey).Distinct().Count());
        Assert.All(plan.Batches, b => Assert.Equal("10.0.0.0/16", b.SubnetKey));
    }

    [Fact]
    public void Network_and_global_exclusions_never_reach_a_batch()
    {
        var segments = TargetPlanner.ResolveTargets(new ResolvedScope
        {
            Segments = [Segment("dc", ["10.0.0.0/22"], ["10.0.0.128/25"])],
            GlobalExclusions = ["10.0.1.5", "10.0.3.0-10.0.3.9"],
        }, 65_536);
        var plan = TargetPlanner.PlanHosts(segments, 256, 16);

        var covered = Covered(plan);
        Assert.Equal((UInt128)(1024 - 128 - 1 - 10), covered.Count);
        Assert.Equal(covered.Count, (UInt128)plan.Batches.Sum(b => b.Count));
        Assert.False(covered.Overlaps(IpRangeSet.Parse(["10.0.0.128/25", "10.0.1.5", "10.0.3.0-10.0.3.9"])));
        Assert.All(plan.Batches, b => Assert.True(b.Count <= 256));
    }

    [Fact]
    public void Overlapping_networks_do_not_scan_an_address_twice()
    {
        var a = Segment("a", ["10.0.0.0/24"]);
        var b = Segment("b", ["10.0.0.0/23"]);
        var plan = TargetPlanner.PlanHosts(Resolve(a, b), 256, 16);

        Assert.Equal(["10.0.0.0/24"], plan.Batches.Where(x => x.NetworkId == a.NetworkId).SelectMany(x => x.Hosts));
        Assert.Equal(["10.0.1.0/24"], plan.Batches.Where(x => x.NetworkId == b.NetworkId).SelectMany(x => x.Hosts));
    }

    [Fact]
    public void Hostnames_are_separate_targets_and_excluded_hostnames_are_removed()
    {
        var segments = TargetPlanner.ResolveTargets(new ResolvedScope
        {
            Segments = [Segment("web", ["app.example.com", "Admin.Example.com", "old.example.com", "*.example.com", "10.1.0.0/30"], ["old.example.com"])],
            GlobalExclusions = ["*.example.com.internal", "admin.example.com"],
        }, 65_536);
        var plan = TargetPlanner.PlanHosts(segments, 64, 16);

        var hostnameBatch = Assert.Single(plan.Batches, b => b.Hosts.Contains("app.example.com"));
        Assert.Equal(["app.example.com"], hostnameBatch.Hosts);
        Assert.Null(hostnameBatch.SubnetKey);
        Assert.Contains("*.example.com", hostnameBatch.AuthorizedScope);
        Assert.Contains(plan.Batches, b => b.Hosts.SequenceEqual(["10.1.0.0/30"]));
    }

    [Fact]
    public void Oversized_ipv6_segments_are_rejected_and_small_ones_planned()
    {
        var error = Assert.Throws<PlanningException>(() => Resolve(Segment("v6", ["2001:db8::/64"])));
        Assert.Contains("Planner:MaxIpv6SegmentAddresses", error.Message);

        var plan = TargetPlanner.PlanHosts(Resolve(Segment("v6", ["2001:db8::/120"])), 64, 16);
        Assert.Equal(4, plan.Batches.Count);
        Assert.Equal("2001:db8::/64", plan.Batches[0].SubnetKey);
    }

    [Fact]
    public void Hosts_from_earlier_steps_are_restricted_to_the_scope()
    {
        var segments = Resolve(Segment("dc", ["10.0.0.0/24"], ["10.0.0.200"]));
        var plan = TargetPlanner.PlanHosts(segments, 256, 16, ["10.0.0.1", "10.0.0.2", "10.0.0.200", "192.168.1.1", "evil.example.org"]);

        Assert.Equal(3, plan.OutOfScope);
        var batch = Assert.Single(plan.Batches);
        Assert.Equal(2, batch.Count);
        Assert.Equal(IpRangeSet.Parse(["10.0.0.1", "10.0.0.2"]).ToCidrs(), batch.Hosts);
    }

    [Fact]
    public void Endpoints_are_grouped_by_host_within_the_batch_size_and_outside_scope_dropped()
    {
        var segments = Resolve(Segment("dc", ["10.0.0.0/24"]));
        var endpoints = new List<ScanEndpoint>();
        for (var host = 1; host <= 30; host++)
            for (var port = 1; port <= 3; port++)
                endpoints.Add(new ScanEndpoint { Address = $"10.0.0.{host}", Port = 8000 + port });
        endpoints.AddRange(Enumerable.Range(1, 70).Select(p => new ScanEndpoint { Address = "10.0.0.99", Port = p }));
        endpoints.Add(new ScanEndpoint { Address = "172.16.0.1", Port = 80 });
        endpoints.Add(new ScanEndpoint { Address = "10.0.0.1", Port = 8001 }); // duplicate

        var plan = TargetPlanner.PlanEndpoints(segments, endpoints, 64, 16);

        Assert.Equal(1, plan.OutOfScope);
        Assert.Equal(160, plan.Batches.Sum(b => b.Count));
        Assert.All(plan.Batches, b => Assert.True(b.Endpoints.Count <= 64));
        // A host with few endpoints never straddles two batches.
        foreach (var host in Enumerable.Range(1, 30).Select(h => $"10.0.0.{h}"))
            Assert.Single(plan.Batches, b => b.Endpoints.Any(e => e.Address == host));
        Assert.Equal(2, plan.Batches.Count(b => b.Endpoints.Any(e => e.Address == "10.0.0.99")));
    }

    [Fact]
    public void Linear_intersection_matches_the_reference_implementation()
    {
        var random = new Random(7);
        for (var round = 0; round < 50; round++)
        {
            IpRangeSet RandomSet() => IpRangeSet.Parse(Enumerable.Range(0, 20).Select(_ =>
            {
                var start = random.Next(0, 4000);
                return $"{IpRangeSet.ToAddress(System.Net.Sockets.AddressFamily.InterNetwork, (UInt128)(0x0A000000 + start))}-{IpRangeSet.ToAddress(System.Net.Sockets.AddressFamily.InterNetwork, (UInt128)(0x0A000000 + start + random.Next(0, 300)))}";
            }));
            var (a, b) = (RandomSet(), RandomSet());
            Assert.Equal(a.Intersect(b).ToString(), TargetPlanner.Intersect(a, b).ToString());
        }
    }
}
