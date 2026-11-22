using System.Net;
using System.Net.Sockets;
using WebScan.Server.Kernel.Networking;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Modules.Networks.Persistence;

namespace WebScan.Server.Modules.Networks;

/// <summary>One agent interface (or gateway route) that sees a subnet.</summary>
public sealed record AgentSubnetSourceDto(string AgentId, string InterfaceName, string Address, bool Online, string? Gateway);

/// <summary>
/// A subnet an agent is attached to (<c>interface</c>) or routes to through a gateway (<c>route</c>), proposed as a network.
/// <c>ProposedRanges</c> = the part inside the scope policy not yet covered by networks of the zone (what "create" would add).
/// </summary>
public sealed record AgentSubnetDto(
    string Cidr, string Source, string? Zone, IReadOnlyList<string> CandidateZones, long AddressCount,
    IReadOnlyList<AgentSubnetSourceDto> SeenBy, string Scope, IReadOnlyList<string> ProposedRanges,
    IReadOnlyList<string> ExistingNetworks, bool Management, bool Large);

/// <summary>Derives network proposals from the subnets of the agents' interfaces and their gateway routes.</summary>
internal static class AgentSubnets
{
    /// <summary>IPv4 subnets above this many addresses are flagged <c>Large</c> (not preselected).</summary>
    public const long LargeThreshold = 65_536;

    /// <summary>Above this a subnet is not proposed at all (IPv6 /64s, /0-/7 routes): the planner would reject or never finish it.</summary>
    private static readonly UInt128 MaxIpv6Addresses = 65_536;
    private static readonly UInt128 MaxIpv4Addresses = 1 << 24;

    // Loopback, link-local and multicast never make sense as scan targets.
    private static readonly IpRangeSet Ignored = IpRangeSet.Parse(["127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "::1/128", "fe80::/10", "ff00::/8"]);

    private sealed record Seen(IpRange Range, string Source, AgentSnapshot Agent, AgentSubnetSourceDto Dto, bool Management);

    public static IReadOnlyList<AgentSubnetDto> Suggest(IEnumerable<AgentSnapshot> agents, IReadOnlyList<Network> networks, ScopeRules rules)
    {
        var seen = new List<Seen>();
        foreach (var agent in agents.Where(a => a.AuthorizedZones.Count > 0))
        {
            var connected = new List<(IpRange Range, NetworkInterfaceInfoView Nic)>();
            foreach (var nic in agent.Interfaces.Where(i => i.IsUp))
                foreach (var address in nic.Addresses)
                    if (Usable(address, out var range)) connected.Add((range, new NetworkInterfaceInfoView(nic.Name, address)));

            // Management link: the subnet the agent reaches the server through, when the agent has other subnets to scan.
            var from = IPAddress.TryParse(agent.ConnectedFrom, out var ip) ? IpRangeSet.Normalize(ip) : null;
            var distinctSubnets = connected.Select(c => c.Range).Distinct().Count();
            foreach (var (range, nic) in connected)
            {
                var management = from is not null && distinctSubnets > 1 && IpRangeSet.FromRanges([range]).Contains(from);
                seen.Add(new Seen(range, "interface", agent, new AgentSubnetSourceDto(agent.AgentId, nic.Name, nic.Address, agent.IsOnline, null), management));
            }

            var own = IpRangeSet.FromRanges(connected.Select(c => c.Range));
            foreach (var route in agent.Routes.Where(r => !string.IsNullOrWhiteSpace(r.Gateway) && !IsUnspecified(r.Gateway!)))
            {
                if (!Usable(route.Destination, out var range) || own.Contains(range)) continue;
                seen.Add(new Seen(range, "route", agent,
                    new AgentSubnetSourceDto(agent.AgentId, route.InterfaceName, route.Destination, agent.IsOnline, route.Gateway), false));
            }
        }

        var ipNetworks = networks.Select(n => (Network: n, Ips: IpRangeSet.Parse(n.Ranges.Where(r => IpRangeSet.TryParseRange(r, out _))))).ToList();
        var result = new List<(IpRange Range, AgentSubnetDto Dto)>();
        foreach (var group in seen.GroupBy(s => (s.Range, Zones: ZoneKey(s.Agent))))
        {
            var range = group.Key.Range;
            var zones = group.First().Agent.AuthorizedZones.Order(StringComparer.OrdinalIgnoreCase).ToList();
            var cidr = IpRangeSet.FromRanges([range]).ToCidrs().Single();
            var subnet = IpRangeSet.FromRanges([range]);

            var inScope = IpRangeSet.Parse(rules.Restrict([cidr]));
            var scope = rules.Covers(cidr) ? "full" : inScope.IsEmpty ? "none" : "partial";
            var existing = ipNetworks.Where(n => zones.Contains(n.Network.Zone, StringComparer.OrdinalIgnoreCase) && n.Ips.Overlaps(subnet)).ToList();
            var proposed = existing.Aggregate(inScope, (rest, n) => rest.Subtract(n.Ips));

            // Seen through an interface by anyone = directly attached; the route entries then only add perspectives.
            var source = group.Any(s => s.Source == "interface") ? "interface" : "route";
            var count = (long)range.Count;
            result.Add((range, new AgentSubnetDto(
                cidr, source, zones.Count == 1 ? zones[0] : null, zones, count,
                group.Select(s => s.Dto).DistinctBy(d => (d.AgentId, d.InterfaceName, d.Address)).OrderBy(d => d.AgentId, StringComparer.Ordinal).ToList(),
                scope, proposed.ToCidrs().ToList(), existing.Select(n => n.Network.Name).Order(StringComparer.Ordinal).ToList(),
                Management: group.Where(s => s.Source == "interface").All(s => s.Management) && source == "interface",
                Large: range.Family == AddressFamily.InterNetwork && count > LargeThreshold)));
        }

        return result
            .OrderBy(r => r.Dto.Source == "interface" ? 0 : 1)
            .ThenBy(r => r.Dto.Zone ?? string.Join(",", r.Dto.CandidateZones), StringComparer.OrdinalIgnoreCase)
            .ThenBy(r => r.Range.Family).ThenBy(r => r.Range.Start).ThenBy(r => r.Range.End)
            .Select(r => r.Dto).ToList();
    }

    private readonly record struct NetworkInterfaceInfoView(string Name, string Address);

    private static string ZoneKey(AgentSnapshot agent) =>
        string.Join(",", agent.AuthorizedZones.Select(z => z.ToLowerInvariant()).Order(StringComparer.Ordinal));

    private static bool IsUnspecified(string gateway) =>
        IPAddress.TryParse(gateway, out var g) && (g.Equals(IPAddress.Any) || g.Equals(IPAddress.IPv6Any));

    /// <summary>Address/prefix or route destination to its subnet, unless ignored, a single address or too large to scan.</summary>
    private static bool Usable(string cidr, out IpRange range)
    {
        if (!IpRangeSet.TryParseRange(cidr, out range) || !cidr.Contains('/')) return false;
        if (Ignored.Overlaps(IpRangeSet.FromRanges([range])) || range.Count == 1) return false;
        return range.Family == AddressFamily.InterNetwork ? range.Count <= MaxIpv4Addresses : range.Count <= MaxIpv6Addresses;
    }
}
