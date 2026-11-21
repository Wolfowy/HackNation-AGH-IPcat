using WebScan.Server.Kernel.Ports;

namespace WebScan.Server.Modules.Scanning.Planning;

/// <summary>Global planner limits (<c>GET|PUT /api/scan-limits</c>).</summary>
public sealed record ScanLimits
{
    public int DefaultBatchSize { get; init; } = 256;
    public int LeaseDurationSeconds { get; init; } = 120;
    public int MaxAttempts { get; init; } = 3;
    public int MaxConcurrentJobsPerZone { get; init; } = 100;
    public int MaxConcurrentJobsPerInterface { get; init; } = 4;
    public int MaxConcurrentJobsPerSubnet { get; init; } = 8;
    public int SubnetPrefixLength { get; init; } = 16;
    public int MaxRatePerSecondGlobal { get; init; } = 50_000;

    /// <summary>Validation errors keyed by camelCase field name (empty = valid).</summary>
    public Dictionary<string, string[]> Validate()
    {
        var errors = new Dictionary<string, string[]>();
        void Check(int value, int min, int max, string name) { if (value < min || value > max) errors[name] = [$"{name} must be between {min} and {max}."]; }
        Check(DefaultBatchSize, TargetPlanner.MinBatchSize, TargetPlanner.MaxBatchSize, "defaultBatchSize");
        Check(LeaseDurationSeconds, 30, 3600, "leaseDurationSeconds");
        Check(MaxAttempts, 1, 10, "maxAttempts");
        Check(MaxConcurrentJobsPerZone, 1, 100_000, "maxConcurrentJobsPerZone");
        Check(MaxConcurrentJobsPerInterface, 1, 1000, "maxConcurrentJobsPerInterface");
        Check(MaxConcurrentJobsPerSubnet, 1, 100_000, "maxConcurrentJobsPerSubnet");
        Check(SubnetPrefixLength, 8, 32, "subnetPrefixLength");
        Check(MaxRatePerSecondGlobal, 1, 100_000_000, "maxRatePerSecondGlobal");
        return errors;
    }
}

public sealed record ClaimCandidate(
    Guid JobId, Guid ScanRunId, string StepId, int Priority, DateTimeOffset QueuedAt, JobRequirement Requirement,
    string? SubnetKey, int RequestedRatePerSecond, int StepMaxConcurrency, string? LastAgentId);

/// <summary>A currently leased job (for cap accounting).</summary>
public sealed record RunningJob(string AgentId, string InterfaceName, string Zone, string? SubnetKey, Guid ScanRunId, string StepId, int RatePerSecond);

public sealed record PerformanceSample(string AgentId, string InterfaceName, string ToolId, double TargetsPerSecond);

public sealed record ClaimDecision(Guid JobId, string InterfaceName, string ToolId, int RatePerSecond, double Score);

/// <summary>
/// Pure claim decision for one agent: eligibility, weighted score (priority, wait time, measured throughput, free capacity)
/// and caps (agent, interface, zone, subnet, step concurrency, global rate budget). Used by the DB-backed claim and the simulator.
/// </summary>
public static class ClaimSelector
{
    private const double PriorityWeight = 10;
    private const double MaxWaitMinutes = 60;
    private const double ThroughputWeight = 10;
    private const double FreeCapacityWeight = 5;
    private const double RetryOnSameAgentPenalty = 20;

    public static IReadOnlyList<ClaimDecision> Select(
        AgentSnapshot agent, AgentReach reach, IReadOnlyList<ClaimCandidate> candidates, IReadOnlyCollection<RunningJob> running,
        ScanLimits limits, IReadOnlyCollection<PerformanceSample> performance, PlannerOptions options,
        IReadOnlyCollection<string>? allowedInterfaces, int maxJobs, DateTimeOffset now,
        IReadOnlyDictionary<(Guid ScanRunId, Guid NetworkId), string>? pinnedInterfaces = null)
    {
        // One perspective per run and network: once this agent scanned part of a run's network through an interface,
        // every later job of that run/network (all workflow steps) uses the same interface, so results stay comparable.
        var pins = pinnedInterfaces is null
            ? new Dictionary<(Guid, Guid), string>()
            : new Dictionary<(Guid, Guid), string>(pinnedInterfaces);

        var byAgent = running.Count(r => r.AgentId == agent.AgentId);
        var byInterface = running.Where(r => r.AgentId == agent.AgentId).GroupBy(r => r.InterfaceName).ToDictionary(g => g.Key, g => g.Count());
        var byZone = running.GroupBy(r => r.Zone, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);
        var bySubnet = running.Where(r => r.SubnetKey is not null).GroupBy(r => r.SubnetKey!).ToDictionary(g => g.Key, g => g.Count());
        var byStep = running.GroupBy(r => (r.ScanRunId, r.StepId)).ToDictionary(g => g.Key, g => g.Count());
        var globalRate = running.Sum(r => (long)r.RatePerSecond);
        var globalCount = running.Count;

        var freeSlots = Math.Min(maxJobs, agent.Limits.MaxConcurrentJobs - byAgent);
        if (freeSlots <= 0) return [];

        var referenceTps = performance.GroupBy(p => p.ToolId).ToDictionary(g => g.Key, g => g.Average(p => p.TargetsPerSecond));
        var ownTps = performance.Where(p => p.AgentId == agent.AgentId).ToDictionary(p => (p.InterfaceName, p.ToolId), p => p.TargetsPerSecond);

        double PerspectiveScore(ClaimCandidate c, PerspectiveOption o)
        {
            var throughput = ThroughputWeight / 2; // unknown perspective: neutral
            if (ownTps.TryGetValue((o.InterfaceName, o.ToolId), out var tps) && referenceTps.TryGetValue(o.ToolId, out var reference) && tps + reference > 0)
                throughput = ThroughputWeight * tps / (tps + reference);
            var used = byInterface.GetValueOrDefault(o.InterfaceName);
            var free = FreeCapacityWeight * (1 - (double)used / limits.MaxConcurrentJobsPerInterface);
            var penalty = c.LastAgentId == agent.AgentId ? RetryOnSameAgentPenalty : 0;
            return throughput + free - penalty;
        }

        var scored = new List<(ClaimCandidate Candidate, IReadOnlyList<PerspectiveOption> Options, double Score)>();
        foreach (var c in candidates)
        {
            var eligibility = Eligibility.Evaluate(agent, reach, c.Requirement, options);
            var opts = eligibility.Options.Where(o => allowedInterfaces is null || allowedInterfaces.Contains(o.InterfaceName)).ToList();
            if (opts.Count == 0) continue;
            var jobScore = PriorityWeight * c.Priority + Math.Clamp((now - c.QueuedAt).TotalMinutes, 0, MaxWaitMinutes);
            scored.Add((c, opts, jobScore + opts.Max(o => PerspectiveScore(c, o))));
        }

        var decisions = new List<ClaimDecision>();
        foreach (var (c, opts, score) in scored.OrderByDescending(s => s.Score).ThenBy(s => s.Candidate.QueuedAt).ThenBy(s => s.Candidate.JobId))
        {
            if (decisions.Count >= freeSlots) break;
            var step = (c.ScanRunId, c.StepId);
            if (byStep.GetValueOrDefault(step) >= c.StepMaxConcurrency) continue;
            if (byZone.GetValueOrDefault(c.Requirement.Zone) >= limits.MaxConcurrentJobsPerZone) continue;
            if (c.SubnetKey is not null && bySubnet.GetValueOrDefault(c.SubnetKey) >= limits.MaxConcurrentJobsPerSubnet) continue;

            var pinKey = (c.ScanRunId, c.Requirement.NetworkId);
            var pinnedOpts = pins.TryGetValue(pinKey, out var pinned) && opts.Any(o => o.InterfaceName == pinned)
                ? opts.Where(o => o.InterfaceName == pinned).ToList()
                : opts;
            // A pinned interface at its cap means "wait", never "switch perspective".
            var option = pinnedOpts.Where(o => byInterface.GetValueOrDefault(o.InterfaceName) < limits.MaxConcurrentJobsPerInterface)
                .OrderByDescending(o => PerspectiveScore(c, o)).ThenBy(o => o.InterfaceName, StringComparer.Ordinal).FirstOrDefault();
            if (option is null) continue;
            pins.TryAdd(pinKey, option.InterfaceName);

            // The global budget is shared: a new job gets at most an equal share and never more than what is left.
            // shortcut: rates are fixed at lease time (the job heartbeat contract cannot lower them later); rebalance on heartbeat if the contract grows a rate field.
            var globalShare = Math.Min(limits.MaxRatePerSecondGlobal / (globalCount + 1), limits.MaxRatePerSecondGlobal - globalRate);
            var rate = (int)Math.Min(Math.Min(c.RequestedRatePerSecond, agent.Limits.MaxRatePerSecond), globalShare);
            if (rate < 1) break;

            decisions.Add(new ClaimDecision(c.JobId, option.InterfaceName, option.ToolId, rate, score));
            byInterface[option.InterfaceName] = byInterface.GetValueOrDefault(option.InterfaceName) + 1;
            byZone[c.Requirement.Zone] = byZone.GetValueOrDefault(c.Requirement.Zone) + 1;
            if (c.SubnetKey is not null) bySubnet[c.SubnetKey] = bySubnet.GetValueOrDefault(c.SubnetKey) + 1;
            byStep[step] = byStep.GetValueOrDefault(step) + 1;
            globalRate += rate;
            globalCount++;
        }
        return decisions;
    }
}
