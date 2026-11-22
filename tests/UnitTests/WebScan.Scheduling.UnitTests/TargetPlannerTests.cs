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
    public void Virtual_host_endpoints_are_planned_by_name_and_bare_duplicates_dropped()
    {
        var segments = Resolve(Segment("web", ["10.0.0.0/24", "app.example.com", "api.example.com"]));
        var endpoints = new List<ScanEndpoint>
        {
            // Domain target: resolved address outside the scope, the name inside.
            new() { Address = "203.0.113.7", Port = 443, Hostname = "App.Example.com." },
            new() { Address = "203.0.113.7", Port = 443, Hostname = "api.example.com" },
            new() { Address = "203.0.113.7", Port = 443, Scheme = "https" }, // bare duplicate of the named ones: not out of scope, its scheme is kept
            // In-scope address with a known name: probed by name only.
            new() { Address = "10.0.0.5", Port = 80, Scheme = "http" },
            new() { Address = "10.0.0.5", Port = 80, Hostname = "app.example.com" },
            // Name outside the scope (e.g. reverse DNS): stripped, the address is probed.
            new() { Address = "10.0.0.6", Port = 8080, Hostname = "ptr.isp.example.net" },
            new() { Address = "198.51.100.1", Port = 80, Hostname = "evil.example.org" }, // neither in scope
        };

        var plan = TargetPlanner.PlanEndpoints(segments, endpoints, 64, 16);
        var planned = plan.Batches.SelectMany(b => b.Endpoints).Select(e => $"{e.Hostname ?? "-"}@{e.Address}:{e.Port}/{e.Scheme ?? "-"}").Order();

        Assert.Equal(["-@10.0.0.6:8080/-", "api.example.com@203.0.113.7:443/https", "app.example.com@10.0.0.5:80/http", "app.example.com@203.0.113.7:443/https"], planned);
        Assert.Equal(1, plan.OutOfScope);
    }

    [Fact]
    public void Endpoints_outside_the_scope_policy_ports_are_dropped()
    {
        var segments = Resolve(Segment("dc", ["10.0.0.0/24"]));
        ScanEndpoint[] endpoints = [new() { Address = "10.0.0.1", Port = 22 }, new() { Address = "10.0.0.1", Port = 443 }, new() { Address = "10.0.0.2", Port = 8080 }];
        PortSet.TryParse("80,443,8000-8100", out var ports);

        var plan = TargetPlanner.PlanEndpoints(segments, endpoints, 64, 16, ports);

        Assert.Equal(["10.0.0.1:443", "10.0.0.2:8080"], plan.Batches.SelectMany(b => b.Endpoints).Select(e => $"{e.Address}:{e.Port}"));
        Assert.Equal(1, plan.OutOfScope);
    }

    [Fact]
    public void Resolved_addresses_of_domain_targets_are_aliases_not_out_of_scope()
    {
        var segments = Resolve(Segment("web", ["10.0.0.0/24", "app.example.com"]));
        string[] hosts = ["203.0.113.7", "app.example.com", "10.0.0.5", "ptr.isp.example.net", "192.168.1.1"];
        var aliases = new[] { ("203.0.113.7", "app.example.com"), ("app.example.com", "203.0.113.7"), ("10.0.0.5", "ptr.isp.example.net"), ("ptr.isp.example.net", "10.0.0.5") }
            .ToLookup(p => p.Item1, p => p.Item2);

        var plan = TargetPlanner.PlanHosts(segments, 256, 16, hosts, aliases);

        Assert.Equal(["10.0.0.5", "app.example.com"], plan.Batches.SelectMany(b => b.Hosts).Order());
        Assert.Equal(1, plan.OutOfScope); // only 192.168.1.1
        Assert.Equal(3, TargetPlanner.PlanHosts(segments, 256, 16, hosts).OutOfScope);
    }

    [Theory]
    [InlineData("top-100", "80,443", "80,443")]
    [InlineData("top-5", "1-1000", "21-23,80,443")] // nmap's top 5 ∩ allowlist
    [InlineData("1-100", "22,80,443,8080", "22,80")]
    [InlineData("top-5000", "22,8080", "22,8080")] // beyond the embedded top-1000: the allowlist itself
    public void Port_parameters_are_clipped_to_the_allowlist(string requested, string allowlist, string expected)
    {
        PortSet.TryParse(allowlist, out var allowed);
        var clipped = TargetPlanner.ClipPorts(ScanOperation.ScanPorts, new Dictionary<string, string> { ["ports"] = requested, ["scanType"] = "connect" }, allowed, hasAllowlist: true);
        Assert.Equal(expected, clipped["ports"]);
        Assert.Equal("connect", clipped["scanType"]);
    }

    [Fact]
    public void Port_clipping_fails_closed()
    {
        var excludedOnly = PortScope.Effective([], ["23"]);
        Assert.Equal("1-1000", TargetPlanner.ClipPorts(ScanOperation.ScanPorts, new Dictionary<string, string> { ["ports"] = "1-1000" }, PortSet.All, false)["ports"]);
        Assert.DoesNotContain("23", TargetPlanner.ClipPorts(ScanOperation.ScanPorts, new Dictionary<string, string> { ["ports"] = "top-100" }, excludedOnly, false)["ports"].Split(','));
        Assert.Throws<PlanningException>(() => TargetPlanner.ClipPorts(ScanOperation.ScanPorts, new Dictionary<string, string> { ["ports"] = "top-5000" }, excludedOnly, false));

        PortSet.TryParse("8443", out var only8443);
        var discovery = new Dictionary<string, string> { ["method"] = "default", ["probePorts"] = "22,80,443" };
        Assert.Contains("no port allowed", Assert.Throws<PlanningException>(() => TargetPlanner.ClipPorts(ScanOperation.DiscoverHosts, discovery, only8443, true)).Message);
        Assert.Equal("22,80,443", TargetPlanner.ClipPorts(ScanOperation.DiscoverHosts, new Dictionary<string, string>(discovery) { ["method"] = "icmp" }, only8443, true)["probePorts"]);
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
