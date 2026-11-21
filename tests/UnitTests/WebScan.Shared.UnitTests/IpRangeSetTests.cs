using System.Net;
using WebScan.Server.Kernel.Networking;

namespace WebScan.Shared.UnitTests;

public class IpRangeSetTests
{
    [Theory]
    [InlineData("10.0.0.1", TargetEntryKind.Address)]
    [InlineData("10.0.0.0/24", TargetEntryKind.Cidr)]
    [InlineData("10.0.0.5-10.0.0.20", TargetEntryKind.Range)]
    [InlineData("2001:db8::/120", TargetEntryKind.Cidr)]
    [InlineData("app.example.com", TargetEntryKind.Hostname)]
    [InlineData("10.0.0.0/33", TargetEntryKind.Invalid)]
    [InlineData("rm -rf /", TargetEntryKind.Invalid)]
    [InlineData("10.0.0.9-10.0.0.1", TargetEntryKind.Invalid)]
    public void Classify(string entry, TargetEntryKind expected) => Assert.Equal(expected, IpRangeSet.Classify(entry));

    [Fact]
    public void Cidr_is_normalized_to_network_address()
    {
        var set = IpRangeSet.Parse(["10.0.0.77/24"]);
        Assert.Equal(["10.0.0.0/24"], set.ToCidrs());
        Assert.Equal((UInt128)256, set.Count);
    }

    [Fact]
    public void Union_merges_adjacent_ranges()
    {
        var set = IpRangeSet.Parse(["10.0.0.0/25", "10.0.0.128/25", "10.0.0.5"]);
        Assert.Equal(["10.0.0.0/24"], set.ToCidrs());
    }

    [Fact]
    public void Subtract_exclusions_produces_exact_cidr_cover()
    {
        var set = IpRangeSet.Parse(["192.168.1.0/24"]).Subtract(IpRangeSet.Parse(["192.168.1.0", "192.168.1.128/25"]));
        Assert.Equal((UInt128)127, set.Count);
        Assert.False(set.Contains(IPAddress.Parse("192.168.1.0")));
        Assert.True(set.Contains(IPAddress.Parse("192.168.1.1")));
        Assert.False(set.Contains(IPAddress.Parse("192.168.1.200")));
        Assert.Equal(["192.168.1.1", "192.168.1.2/31", "192.168.1.4/30", "192.168.1.8/29", "192.168.1.16/28", "192.168.1.32/27", "192.168.1.64/26"], set.ToCidrs());
    }

    [Fact]
    public void Split_large_range_into_non_overlapping_batches_covering_everything()
    {
        var set = IpRangeSet.Parse(["10.10.0.0/18"]).Subtract(IpRangeSet.Parse(["10.10.3.0/24", "10.10.7.7"]));
        var batches = set.SplitIntoBatches(256).ToList();

        Assert.All(batches, b => Assert.True(IpRangeSet.Parse(b).Count <= 256));
        var union = batches.Aggregate(new IpRangeSet(), (acc, b) => acc.Union(IpRangeSet.Parse(b)));
        Assert.Equal(set.Count, union.Count);
        Assert.True(union.IsSupersetOf(set) && set.IsSupersetOf(union));
        UInt128 sum = 0;
        foreach (var b in batches) sum += IpRangeSet.Parse(b).Count;
        Assert.Equal(set.Count, sum); // no overlap
    }

    [Fact]
    public void Split_rounds_batch_size_down_to_power_of_two()
    {
        var batches = IpRangeSet.Parse(["10.0.0.0/24"]).SplitIntoBatches(100).ToList();
        Assert.Equal(4, batches.Count);
        Assert.Equal(["10.0.0.0/26"], batches[0]);
    }

    [Fact]
    public void Superset_and_ipv6()
    {
        var policy = IpRangeSet.Parse(["10.0.0.0/8", "2001:db8::/32"]);
        Assert.True(policy.IsSupersetOf(IpRangeSet.Parse(["10.1.2.0/24", "2001:db8:1::/64"])));
        Assert.False(policy.IsSupersetOf(IpRangeSet.Parse(["11.0.0.0/24"])));
    }
}
