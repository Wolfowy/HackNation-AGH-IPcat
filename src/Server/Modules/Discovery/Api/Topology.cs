using System.Net;
using System.Net.Sockets;
using WebScan.Server.Kernel.Networking;
using WebScan.Server.Kernel.Ports;

namespace WebScan.Server.Modules.Discovery.Api;

/// <summary>Pure helpers of the topology read model: subnet grouping, clickable service URLs, network membership.</summary>
internal static class Topology
{
    public const int MaxHosts = 5000;

    /// <summary>Group of hosts known only by a DNS name (no IP address).</summary>
    public const string OtherSubnet = "other";

    /// <summary>IPv4 /24 or IPv6 /64 of a canonical address; <see cref="OtherSubnet"/> for hostnames.</summary>
    public static string SubnetOf(string address)
    {
        if (IpRangeSet.Classify(address) != TargetEntryKind.Address || !IPAddress.TryParse(address, out var ip)) return OtherSubnet;
        ip = IpRangeSet.Normalize(ip);
        var bytes = ip.GetAddressBytes();
        var prefix = ip.AddressFamily == AddressFamily.InterNetwork ? 24 : 64;
        Array.Clear(bytes, prefix / 8, bytes.Length - prefix / 8);
        return $"{new IPAddress(bytes)}/{prefix}";
    }

    /// <summary>Subnet node id: subnets are per zone (identical ranges in two zones are different networks).</summary>
    public static string SubnetId(string zone, string cidr) => $"{zone}|{cidr}";

    public static bool IsWebName(string? serviceName) => serviceName is not null && serviceName.StartsWith("http", StringComparison.Ordinal);

    public static bool IsTls(string? serviceName, string? tunnel, bool certificateSeen) =>
        certificateSeen || string.Equals(tunnel, "ssl", StringComparison.OrdinalIgnoreCase)
        || (serviceName is not null && serviceName.StartsWith("https", StringComparison.Ordinal));

    /// <summary>
    /// Best clickable URL of an endpoint: the probed HTTP URL when known; otherwise https for TLS endpoints, http for http-like
    /// service names, null for anything else (e.g. ssh).
    /// </summary>
    public static string? ServiceUrl(string address, int port, string? serviceName, string? tunnel, string? httpUrl, bool certificateSeen)
    {
        if (!string.IsNullOrWhiteSpace(httpUrl)) return httpUrl;
        var tls = IsTls(serviceName, tunnel, certificateSeen);
        if (!tls && !IsWebName(serviceName)) return null;
        var host = address.Contains(':') ? $"[{address}]" : address;
        return $"{(tls ? "https" : "http")}://{host}:{port}/";
    }

    /// <summary>
    /// Membership test for the ranges (IP/CIDR/range) and hostnames of resolved networks. Exclusions are ignored: they restrict
    /// scanning, not which discovered hosts belong to the network.
    /// </summary>
    public static Func<string, IReadOnlyList<string>, bool> NetworkMatcher(ResolvedScope scope)
    {
        var entries = scope.Segments.SelectMany(s => s.Include).ToList();
        var ranges = IpRangeSet.FromRanges(entries.Select(e => IpRangeSet.TryParseRange(e, out var r) ? r : (IpRange?)null).OfType<IpRange>());
        var names = entries.Where(e => IpRangeSet.Classify(e) == TargetEntryKind.Hostname).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return (address, hostnames) =>
            (IPAddress.TryParse(address, out var ip) && ranges.Contains(ip)) || names.Contains(address) || hostnames.Any(names.Contains);
    }
}
