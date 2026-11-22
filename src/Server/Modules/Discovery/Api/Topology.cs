using System.Globalization;
using System.Net;
using System.Net.Sockets;
using WebScan.Server.Kernel.Networking;
using WebScan.Server.Kernel.Ports;

namespace WebScan.Server.Modules.Discovery.Api;

public enum MacKind { Ignored, Universal, LocallyAdministered, VirtualRouter }

/// <summary>Current host interface carrying a MAC (input of <see cref="Topology.InferDevices"/>).</summary>
internal sealed record MacInterface(Guid HostId, string Zone, string Address, string MacAddress, string? MacVendor);

/// <param name="SharedMac">Hosts whose MAC is on several IPs of their own zone (aliases or proxy-ARP).</param>
internal sealed record DeviceInference(IReadOnlyList<NetworkDeviceDto> Devices, IReadOnlySet<Guid> SharedMac)
{
    public IReadOnlyDictionary<Guid, NetworkDeviceDto> ByHost { get; } =
        Devices.SelectMany(d => d.Interfaces, (d, i) => (i.HostId, d)).ToDictionary(x => x.HostId, x => x.d);
}

/// <summary>Pure helpers of the topology read model: subnet grouping, clickable service URLs, network membership, device inference.</summary>
internal static class Topology
{
    /// <summary>Shared virtual-router MACs: VRRP (IPv4) <c>00:00:5E:00:01:{vrid}</c>, HSRP v1 <c>00:00:0C:07:AC:{group}</c>.</summary>
    public const string VrrpMacPrefix = "00:00:5E:00:01:", HsrpMacPrefix = "00:00:0C:07:AC:";

    public static MacKind ClassifyMac(string? mac)
    {
        if (mac is not { Length: 17 } || !byte.TryParse(mac.AsSpan(0, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var first))
            return MacKind.Ignored;
        if (mac.StartsWith(VrrpMacPrefix, StringComparison.OrdinalIgnoreCase) || mac.StartsWith(HsrpMacPrefix, StringComparison.OrdinalIgnoreCase))
            return MacKind.VirtualRouter;
        // Multicast bit (broadcast included) and all-zero never identify one interface.
        if ((first & 1) != 0 || mac == "00:00:00:00:00:00") return MacKind.Ignored;
        return (first & 2) != 0 ? MacKind.LocallyAdministered : MacKind.Universal;
    }

    /// <summary>
    /// Zones are separate address spaces, so one MAC on hosts of two or more zones is one physical device (router, L3 switch, firewall,
    /// multi-homed box) with an interface in each; virtual-router MACs are devices on their own. Locally administered MACs (Docker/VM
    /// <c>02:…</c>) repeat by accident → confidence "low". A MAC on several IPs of one zone only marks those hosts as shared-MAC.
    /// </summary>
    public static DeviceInference InferDevices(IEnumerable<MacInterface> interfaces)
    {
        var groups = interfaces.Select(i => (Interface: i, Kind: ClassifyMac(i.MacAddress))).Where(x => x.Kind != MacKind.Ignored)
            .GroupBy(x => x.Interface.MacAddress.ToUpperInvariant()).ToList();
        var devices = groups.Where(g => g.First().Kind == MacKind.VirtualRouter || g.Select(x => x.Interface.Zone).Distinct().Count() > 1)
            .Select(g => new NetworkDeviceDto(g.Key, g.Key, g.Select(x => x.Interface.MacVendor).FirstOrDefault(v => v is not null),
                g.First().Kind == MacKind.LocallyAdministered ? "low" : "high",
                g.Select(x => x.Interface.Zone).Distinct().Order(StringComparer.Ordinal).ToList(),
                g.Select(x => new DeviceInterfaceDto(x.Interface.HostId, x.Interface.Zone, x.Interface.Address))
                    .OrderBy(i => i.Zone, StringComparer.Ordinal).ThenBy(i => i.Address, StringComparer.Ordinal).ToList()))
            .OrderBy(d => d.Id, StringComparer.Ordinal).ToList();
        var shared = groups.SelectMany(g => g.GroupBy(x => x.Interface.Zone).Where(z => z.Count() > 1)).SelectMany(z => z.Select(x => x.Interface.HostId))
            .ToHashSet();
        return new DeviceInference(devices, shared);
    }

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
