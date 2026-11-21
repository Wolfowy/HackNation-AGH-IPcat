using System.Net.Sockets;
using WebScan.Contracts;
using WebScan.Server.Kernel.Networking;
using WebScan.Server.Kernel.Ports;

namespace WebScan.Server.Modules.Scanning.Planning;

/// <summary>What a job needs from a perspective.</summary>
public sealed record JobRequirement(string Zone, Guid NetworkId, string Capability, string? PreferredToolId, IReadOnlyList<string> ReachTargets);

public sealed record PerspectiveOption(string InterfaceName, string ToolId);

public sealed record EligibilityResult(IReadOnlyList<PerspectiveOption> Options, string? Reason)
{
    public bool IsEligible => Options.Count > 0;
}

/// <summary>Per-interface reachability of one agent: interface subnets plus routes (default route only if allowed).</summary>
public sealed class AgentReach
{
    private readonly List<(string Name, IpRangeSet Reach, bool DefaultV4, bool DefaultV6)> _interfaces = [];

    public static AgentReach Build(AgentSnapshot agent, bool allowDefaultRoute)
    {
        var reach = new AgentReach();
        foreach (var nic in agent.Interfaces.Where(i => i.IsUp).OrderBy(i => i.Name, StringComparer.Ordinal))
        {
            var ranges = new List<IpRange>();
            bool v4 = false, v6 = false;
            foreach (var cidr in nic.Addresses)
                if (IpRangeSet.TryParseRange(cidr, out var r)) ranges.Add(r);
            foreach (var route in agent.Routes.Where(r => string.Equals(r.InterfaceName, nic.Name, StringComparison.Ordinal)))
            {
                if (!IpRangeSet.TryParseRange(route.Destination, out var r)) continue;
                var isDefault = r.Start == 0 && (r.Family == AddressFamily.InterNetwork ? r.End == uint.MaxValue : r.End == UInt128.MaxValue);
                if (!isDefault) ranges.Add(r);
                else if (allowDefaultRoute) { if (r.Family == AddressFamily.InterNetwork) v4 = true; else v6 = true; }
            }
            reach._interfaces.Add((nic.Name, IpRangeSet.FromRanges(ranges), v4, v6));
        }
        return reach;
    }

    /// <summary>Interfaces through which every target is reachable (hostnames need a default route).</summary>
    public IReadOnlyList<string> InterfacesReaching(IReadOnlyList<string> targets)
    {
        var ranges = new List<IpRange>();
        var hasHostnames = false;
        foreach (var t in targets)
        {
            if (IpRangeSet.TryParseRange(t, out var r)) ranges.Add(r);
            else hasHostnames = true;
        }
        var ips = IpRangeSet.FromRanges(ranges);

        var result = new List<string>();
        foreach (var (name, reach, v4, v6) in _interfaces)
        {
            if (hasHostnames && !v4 && !v6) continue;
            var rest = ips.Subtract(reach);
            if (rest.Ranges.All(r => r.Family == AddressFamily.InterNetwork ? v4 : v6)) result.Add(name);
        }
        return result;
    }
}

/// <summary>Pure eligibility rules: zone/network authorization, approved tool with capability, reachability.</summary>
public static class Eligibility
{
    public static EligibilityResult Evaluate(AgentSnapshot agent, AgentReach reach, JobRequirement job, PlannerOptions options)
    {
        if (agent.Status != AgentStatus.Active) return new([], $"agent {agent.AgentId} is {agent.Status}");
        if (!agent.AuthorizedZones.Contains(job.Zone, StringComparer.OrdinalIgnoreCase))
            return new([], $"agent {agent.AgentId} is not authorized for zone '{job.Zone}'");
        if (agent.AuthorizedNetworkIds.Count > 0 && !agent.AuthorizedNetworkIds.Contains(job.NetworkId))
            return new([], $"agent {agent.AgentId} is restricted to other networks");

        var tool = SelectTool(agent, job.Capability, job.PreferredToolId, options);
        if (tool is null) return new([], $"agent {agent.AgentId} has no approved tool with capability '{job.Capability}'");

        var interfaces = reach.InterfacesReaching(job.ReachTargets);
        if (interfaces.Count == 0) return new([], $"agent {agent.AgentId} has no interface or route reaching the targets");

        return new(interfaces.Select(i => new PerspectiveOption(i, tool)).ToList(), null);
    }

    /// <summary>Step tool if the agent has it, else first of <c>Planner:ToolPreference:{capability}</c>, else any (by id).</summary>
    public static string? SelectTool(AgentSnapshot agent, string capability, string? preferredToolId, PlannerOptions options)
    {
        var tools = agent.ApprovedTools
            .Where(t => t.Capabilities.Contains(capability, StringComparer.OrdinalIgnoreCase))
            .Select(t => t.Id).OrderBy(id => id, StringComparer.Ordinal).ToList();
        if (tools.Count == 0) return null;
        if (preferredToolId is not null && tools.Contains(preferredToolId, StringComparer.OrdinalIgnoreCase))
            return tools.First(t => t.Equals(preferredToolId, StringComparison.OrdinalIgnoreCase));
        if (options.ToolPreference.TryGetValue(capability, out var preferred))
            foreach (var id in preferred)
                if (tools.Contains(id, StringComparer.OrdinalIgnoreCase)) return tools.First(t => t.Equals(id, StringComparison.OrdinalIgnoreCase));
        return tools[0];
    }
}
