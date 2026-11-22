using System.Net.Sockets;
using WebScan.Contracts;
using WebScan.Server.Kernel.Networking;
using WebScan.Server.Kernel.Ports;

namespace WebScan.Server.Modules.Scanning.Planning;

/// <summary>What a job needs from a perspective.</summary>
/// <param name="RequiredParameters">Parameters set explicitly in the step: the tool must support them (not silently ignore them).</param>
/// <param name="NeedsRawSockets">A selected technique (e.g. SYN scan) needs raw sockets on the agent.</param>
public sealed record JobRequirement(string Zone, Guid NetworkId, string Capability, string? PreferredToolId, IReadOnlyList<string> ReachTargets,
    IReadOnlyList<string>? RequiredParameters = null, bool NeedsRawSockets = false);

public sealed record PerspectiveOption(string InterfaceName, string ToolId);

/// <param name="Direct">Targets reached through an interface subnet or a specific route, not only via a default route.</param>
public sealed record EligibilityResult(IReadOnlyList<PerspectiveOption> Options, string? Reason, bool Direct = false)
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

    /// <summary>
    /// Interfaces through which every target is reachable (hostnames need a default route). Longest-prefix semantics:
    /// when an interface reaches the targets through its own subnet or a specific route, the OS sends the traffic there,
    /// so interfaces that would only reach them via a default route are not offered (binding a tool to them would fail).
    /// </summary>
    public IReadOnlyList<string> InterfacesReaching(IReadOnlyList<string> targets) => Reaching(targets).Interfaces;

    /// <summary><see cref="InterfacesReaching"/> plus whether they reach the targets directly (subnet or specific route).</summary>
    public (IReadOnlyList<string> Interfaces, bool Direct) Reaching(IReadOnlyList<string> targets)
    {
        var ranges = new List<IpRange>();
        var hasHostnames = false;
        foreach (var t in targets)
        {
            if (IpRangeSet.TryParseRange(t, out var r)) ranges.Add(r);
            else hasHostnames = true;
        }
        var ips = IpRangeSet.FromRanges(ranges);

        var specific = new List<string>();
        var viaDefault = new List<string>();
        foreach (var (name, reach, v4, v6) in _interfaces)
        {
            if (hasHostnames && !v4 && !v6) continue;
            var rest = ips.Subtract(reach);
            if (rest.IsEmpty && !hasHostnames) specific.Add(name);
            else if (rest.Ranges.All(r => r.Family == AddressFamily.InterNetwork ? v4 : v6)) viaDefault.Add(name);
        }
        return specific.Count > 0 ? (specific, true) : (viaDefault, false);
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

        if (job.NeedsRawSockets && agent.RawSockets == false)
            return new([], $"agent {agent.AgentId} has no raw-socket privileges (needed for the selected scan technique)");

        var tool = SelectTool(agent, job.Capability, job.PreferredToolId, options, job.RequiredParameters, job.ReachTargets);
        if (tool is null)
        {
            var anyTool = SelectTool(agent, job.Capability, job.PreferredToolId, options) is not null;
            return new([], anyTool
                ? $"agent {agent.AgentId} has no approved '{job.Capability}' tool supporting parameter(s) {string.Join(", ", job.RequiredParameters!)}"
                : $"agent {agent.AgentId} has no approved tool with capability '{job.Capability}'");
        }

        var (interfaces, direct) = reach.Reaching(job.ReachTargets);
        if (interfaces.Count == 0) return new([], $"agent {agent.AgentId} has no interface or route reaching the targets");

        return new(interfaces.Select(i => new PerspectiveOption(i, tool)).ToList(), null, direct);
    }

    /// <summary>
    /// Whether another online agent can take the job directly (attached to the targets' subnet or with a specific route to it).
    /// Such agents win over agents that would only reach the targets through a default route: they see the subnet first-hand
    /// (ARP, MAC addresses, no router in between), so the scan stays "wide with local agents".
    /// </summary>
    public static bool DirectPeerExists(string agentId, IEnumerable<(AgentSnapshot Agent, AgentReach Reach)> peers, JobRequirement job, PlannerOptions options) =>
        peers.Any(p => p.Agent.AgentId != agentId && p.Agent.IsOnline && Evaluate(p.Agent, p.Reach, job, options) is { IsEligible: true, Direct: true });

    /// <summary>
    /// Step tool if the agent has it, else first of <c>Planner:ToolPreference:{capability}</c>, else any (by id) — among the tools
    /// that support every required parameter (a tool would otherwise run without them, silently changing the step).
    /// </summary>
    // shortcut: SupportedParameters is per tool, not per capability; split it in the contract if two capabilities of one tool diverge.
    public static string? SelectTool(AgentSnapshot agent, string capability, string? preferredToolId, PlannerOptions options,
        IReadOnlyCollection<string>? requiredParameters = null, IReadOnlyList<string>? targets = null)
    {
        // A pinned tool the agent cannot run here (no raw sockets, host names it cannot resolve) falls back to another tool.
        var hasHostnames = targets?.Any(t => !IpRangeSet.TryParseRange(t, out _)) == true;
        var tools = agent.ApprovedTools
            .Where(t => t.Capabilities.Contains(capability, StringComparer.OrdinalIgnoreCase))
            .Where(t => !(t.RequiresRawSockets && agent.RawSockets == false) && !(hasHostnames && !t.AcceptsHostnames))
            .Where(t => requiredParameters is null || requiredParameters.All(p => t.SupportedParameters.Contains(p, StringComparer.Ordinal)))
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
