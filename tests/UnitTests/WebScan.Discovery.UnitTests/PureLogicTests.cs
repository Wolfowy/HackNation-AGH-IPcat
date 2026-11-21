using WebScan.Contracts;
using WebScan.Server.Kernel.Discovery;
using WebScan.Server.Modules.Analytics;
using WebScan.Server.Modules.Discovery.Api;
using WebScan.Server.Modules.Discovery.Processing;

namespace WebScan.Discovery.UnitTests;

public class CsvTests
{
    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("a,b", "\"a,b\"")]
    [InlineData("say \"hi\"", "\"say \"\"hi\"\"\"")]
    [InlineData("line1\nline2", "\"line1\nline2\"")]
    [InlineData("=HYPERLINK(\"http://x\")", "\"'=HYPERLINK(\"\"http://x\"\")\"")]
    [InlineData("+1", "'+1")]
    [InlineData("-cmd", "'-cmd")]
    [InlineData("@SUM(A1)", "'@SUM(A1)")]
    [InlineData(null, "")]
    public void Escapes_per_rfc4180_with_injection_guard(string? input, string expected) => Assert.Equal(expected, Csv.Escape(input));

    [Fact]
    public void Write_uses_crlf_and_parse_round_trips()
    {
        var csv = Csv.Write(["address", "description"], [["10.0.0.1", "web, \"main\"\nsecond line"], ["10.0.0.2", null]]);
        Assert.Equal("address,description\r\n10.0.0.1,\"web, \"\"main\"\"\nsecond line\"\r\n10.0.0.2,\r\n", csv);

        var rows = Csv.Parse(csv);
        Assert.Equal(3, rows.Count);
        Assert.Equal(["10.0.0.1", "web, \"main\"\nsecond line"], rows[1]);
        Assert.Equal(["10.0.0.2", ""], rows[2]);
    }
}

public class TimeOfDayVarianceAnalyzerTests
{
    private static readonly DateTimeOffset Day1 = new(2026, 11, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Detects_consistent_responses_that_differ_by_hour()
    {
        HourlyResponse[] responses =
        [
            new(3, "maint", 4, "503 'Maintenance'", Day1.AddHours(3), Day1.AddDays(3).AddHours(3)),
            new(14, "app", 4, "200 'App'", Day1.AddHours(14), Day1.AddDays(3).AddHours(14)),
            new(14, "maint", 1, "503 'Maintenance'", Day1.AddDays(2).AddHours(14), Day1.AddDays(2).AddHours(14)),
        ];
        var result = TimeOfDayVarianceAnalyzer.Analyze(responses, minObservations: 6);
        Assert.True(result.HasVariance);
        Assert.Equal("03h UTC: 503 'Maintenance'; 14h UTC: 200 'App'", result.Describe());
    }

    [Fact]
    public void Needs_enough_observations()
    {
        HourlyResponse[] responses =
        [
            new(3, "maint", 2, "503", Day1, Day1.AddDays(1)),
            new(14, "app", 2, "200", Day1, Day1.AddDays(1)),
        ];
        Assert.False(TimeOfDayVarianceAnalyzer.Analyze(responses, minObservations: 6).HasVariance);
        Assert.True(TimeOfDayVarianceAnalyzer.Analyze(responses, minObservations: 4).HasVariance);
    }

    [Fact]
    public void Inconsistent_buckets_are_not_variance()
    {
        HourlyResponse[] responses =
        [
            new(3, "a", 3, "200 A", Day1, Day1.AddDays(5)),
            new(3, "b", 3, "200 B", Day1, Day1.AddDays(5)),
            new(14, "a", 3, "200 A", Day1, Day1.AddDays(5)),
        ];
        Assert.False(TimeOfDayVarianceAnalyzer.Analyze(responses, minObservations: 6).HasVariance);
    }

    [Fact]
    public void A_permanent_change_between_scans_at_different_hours_is_not_variance()
    {
        HourlyResponse[] responses =
        [
            new(8, "old", 5, "200 Old", Day1, Day1.AddDays(5)),
            new(20, "new", 5, "200 New", Day1.AddDays(6), Day1.AddDays(10)),
        ];
        Assert.False(TimeOfDayVarianceAnalyzer.Analyze(responses, minObservations: 6).HasVariance);
    }
}

public class RunDiffTests
{
    private static DiscoveryObservation Obs(ObservationKind kind, string address, int port, ServiceDetails? service = null, TechnologyDetails? tech = null) => new()
    {
        ObservationId = Guid.NewGuid().ToString("N"), Kind = kind, Address = address, Port = port, Transport = TransportProtocol.Tcp,
        ObservedAt = DateTimeOffset.UnixEpoch, Source = new ObservationSource { ToolId = "t", AgentId = "a", JobId = Guid.Empty },
        Service = service, Technology = tech,
    };

    [Fact]
    public async Task Reports_added_removed_and_changed_endpoints_and_technologies()
    {
        DiscoveryObservation[] baseline =
        [
            Obs(ObservationKind.Service, "10.0.0.1", 80, new ServiceDetails { Name = "http", Product = "nginx", Version = "1.18.0" }),
            Obs(ObservationKind.PortOpen, "10.0.0.1", 22),
            Obs(ObservationKind.Technology, "10.0.0.1", 80, tech: new TechnologyDetails { Name = "PHP", Version = "7.4" }),
            Obs(ObservationKind.PortOpen, "10.0.0.2", 443),
        ];
        DiscoveryObservation[] current =
        [
            Obs(ObservationKind.PortOpen, "10.0.0.1", 80),
            Obs(ObservationKind.Service, "10.0.0.1", 80, new ServiceDetails { Name = "http", Product = "nginx", Version = "1.20.1" }),
            Obs(ObservationKind.Service, "10.0.0.1", 22, new ServiceDetails { Name = "ssh" }), // baseline had no identification → not "changed"
            Obs(ObservationKind.Technology, "10.0.0.1", 80, tech: new TechnologyDetails { Name = "PHP", Version = "8.2" }),
            Obs(ObservationKind.PortOpen, "10.0.0.3", 3389),
        ];

        var diff = await RunDiff.ComputeAsync(Guid.NewGuid(), Guid.NewGuid(), Zoned("lab", current), Zoned("lab", baseline), default);

        Assert.Equal(["endpoint|lab|10.0.0.3|3389|tcp"], diff.Added.Select(i => i.Key));
        Assert.Equal(["endpoint|lab|10.0.0.2|443|tcp"], diff.Removed.Select(i => i.Key));
        Assert.Equal(["endpoint|lab|10.0.0.1|80|tcp", "technology|lab|10.0.0.1|80|php"], diff.Changed.Select(i => i.Key));
        Assert.Equal(("http nginx 1.18.0", "http nginx 1.20.1"), (diff.Changed[0].Before, diff.Changed[0].After));
        Assert.Equal(("7.4", "8.2"), (diff.Changed[1].Before, diff.Changed[1].After));
    }

    [Fact]
    public async Task Same_endpoint_in_another_zone_is_a_different_asset()
    {
        DiscoveryObservation[] port = [Obs(ObservationKind.PortOpen, "10.0.0.5", 22)];
        var diff = await RunDiff.ComputeAsync(Guid.NewGuid(), Guid.NewGuid(), Zoned("lab", port), Zoned("dc-warsaw", port), default);

        Assert.Equal(("endpoint|lab|10.0.0.5|22|tcp", "lab"), (Assert.Single(diff.Added).Key, diff.Added[0].Zone));
        Assert.Equal("endpoint|dc-warsaw|10.0.0.5|22|tcp", Assert.Single(diff.Removed).Key);
    }

    private static IAsyncEnumerable<RunObservation> Zoned(string zone, DiscoveryObservation[] observations) =>
        observations.Select(o => new RunObservation(zone, o)).ToAsyncEnumerable();
}
