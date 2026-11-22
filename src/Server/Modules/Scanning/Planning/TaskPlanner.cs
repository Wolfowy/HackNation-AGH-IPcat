using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WebScan.Contracts;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Modules.Scanning.Events;
using WebScan.Server.Modules.Scanning.Persistence;

namespace WebScan.Server.Modules.Scanning.Planning;

/// <summary>One agent step of a scan run to be turned into queued jobs.</summary>
public sealed record AgentStepSpec
{
    public required Guid ScanRunId { get; init; }
    public Guid? WorkflowRunId { get; init; }
    public required string StepId { get; init; }
    public required ScanOperation Operation { get; init; }
    public required IReadOnlyList<Guid> NetworkIds { get; init; }

    /// <summary>Validated parameters (defaults applied).</summary>
    public IReadOnlyDictionary<string, string> Parameters { get; init; } = new Dictionary<string, string>();

    public string? PreferredToolId { get; init; }

    /// <summary>Parameters the step sets explicitly (the chosen tool must support them).</summary>
    public IReadOnlyList<string> RequiredParameters { get; init; } = [];

    public int Priority { get; init; }
    public int? RunRateCap { get; init; }
    public DateTimeOffset? NotAfter { get; init; }
    public int TimeoutSeconds { get; init; } = 3600;
    public int MaxConcurrency { get; init; } = 50;
    public int MaxAttempts { get; init; } = 3;
    public int BackoffSeconds { get; init; } = 30;
    public int? BatchSize { get; init; }
    public SignatureBundle? Signatures { get; init; }

    /// <summary>Host targets found by earlier steps; null (with <see cref="Endpoints"/> null) = the whole run scope.</summary>
    public IReadOnlyCollection<string>? Hosts { get; init; }

    /// <summary>Address ↔ hostname pairs among <see cref="Hosts"/> (see <see cref="TargetPlanner.PlanHosts"/>).</summary>
    public ILookup<string, string>? HostAliases { get; init; }

    /// <summary>Endpoint targets for endpoint operations.</summary>
    public IReadOnlyCollection<ScanEndpoint>? Endpoints { get; init; }

    /// <summary>Mixed into the dedup key so one step can queue the same targets again (e.g. RecheckMissing rounds).</summary>
    public string? TargetKeySalt { get; init; }
}

public sealed record PlanResult(int JobsCreated, int JobsExisting, long TargetCount, int OutOfScope, int Unassignable, string? UnassignableReason)
{
    public int JobsTotal => JobsCreated + JobsExisting;
    public int BatchSize { get; init; }

    /// <summary>Why this batch size (workflow setting, measured throughput or default), shown in the step message.</summary>
    public string BatchReason { get; init; } = "";

    /// <summary>Measured per-job targets/s of the agents that could run the step (agent id to rate).</summary>
    public IReadOnlyDictionary<string, double> Throughput { get; init; } = new Dictionary<string, double>();

    /// <summary>Online agents eligible for at least one batch.</summary>
    public IReadOnlyCollection<string> EligibleAgentIds { get; init; } = [];
}

/// <summary>Dry-run plan of one step with a duration range (seconds; null without throughput measurements).</summary>
public sealed record StepEstimate(
    string StepId, ScanOperation Operation, long Targets, int Jobs, int BatchSize, string BatchReason, int EligibleAgents,
    double? TargetsPerSecond, double? EstimatedSecondsMin, double? EstimatedSecondsMax, int Unassignable, string? UnassignableReason);

/// <summary>DB-backed planner: resolves the authorized scope, batches it and queues deduplicated jobs.</summary>
public sealed class TaskPlanner(
    ScanningDbContext db, INetworkScopeService scope, IAgentDirectory agents, ScanLimitsStore limitsStore,
    IOptions<PlannerOptions> plannerOptions, IScanEventPublisher events, TimeProvider time, ILogger<TaskPlanner> logger)
{
    private readonly PlannerOptions _options = plannerOptions.Value;

    /// <summary>Scope of the networks with the planner's own re-check against the global scope policy.</summary>
    public async Task<IReadOnlyList<SegmentTargets>> ResolveScopeAsync(IReadOnlyCollection<Guid> networkIds, CancellationToken ct = default) =>
        (await ResolveAsync(networkIds, ct)).Segments;

    private async Task<(IReadOnlyList<SegmentTargets> Segments, ResolvedScope Resolved)> ResolveAsync(IReadOnlyCollection<Guid> networkIds, CancellationToken ct)
    {
        var resolved = await scope.ResolveAsync(networkIds, ct);
        var segments = new List<ScopeSegment>();
        foreach (var segment in resolved.Segments.Where(s => networkIds.Contains(s.NetworkId)))
        {
            var allowed = new List<string>();
            foreach (var entry in segment.Include)
            {
                if (await scope.IsAuthorizedAsync(entry, ct)) allowed.Add(entry);
                else logger.LogWarning("Planner dropped {Entry} of network {Network}: outside the global scope policy", entry, segment.NetworkName);
            }
            segments.Add(segment with { Include = allowed });
        }
        return (TargetPlanner.ResolveTargets(resolved with { Segments = segments }, _options.MaxIpv6SegmentAddresses), resolved);
    }

    public Task<PlanResult> PlanAsync(AgentStepSpec spec, CancellationToken ct = default) => PlanCoreAsync(spec, dryRun: false, ct);

    /// <summary>Dry run of <see cref="PlanAsync"/> (nothing is queued) plus a duration range from measured throughput.</summary>
    public async Task<StepEstimate> EstimateAsync(AgentStepSpec spec, CancellationToken ct = default)
    {
        var plan = await PlanCoreAsync(spec, dryRun: true, ct);
        var limits = await limitsStore.GetAsync(ct);
        var slots = (await agents.GetActiveAgentsAsync(ct)).Where(a => plan.EligibleAgentIds.Contains(a.AgentId)).Sum(a => a.Limits.MaxConcurrentJobs);
        var parallel = Math.Min(plan.JobsCreated, Math.Min(slots, Math.Min(spec.MaxConcurrency, limits.MaxConcurrentJobsPerZone)));
        // shortcut: per-network rate caps are ignored here (they only lower the best case further); add them if estimates prove too optimistic.
        var rateCap = Math.Min(limits.MaxRatePerSecondGlobal, (long)Math.Max(1, parallel) * Math.Min(StepRate(spec), spec.RunRateCap ?? int.MaxValue));
        var rates = plan.Throughput.Where(t => plan.EligibleAgentIds.Contains(t.Key)).Select(t => t.Value).ToList();
        var duration = TargetPlanner.EstimateDuration(plan.TargetCount, plan.JobsCreated, plan.BatchSize, rates, parallel, rateCap);
        return new StepEstimate(spec.StepId, spec.Operation, plan.TargetCount, plan.JobsCreated, plan.BatchSize, plan.BatchReason,
            plan.EligibleAgentIds.Count, rates.Count > 0 ? Math.Round(rates.Average(), 2) : null, duration?.MinSeconds, duration?.MaxSeconds,
            plan.Unassignable, plan.UnassignableReason);
    }

    private static int StepRate(AgentStepSpec spec) =>
        spec.Parameters.TryGetValue("rate", out var r) && int.TryParse(r, CultureInfo.InvariantCulture, out var rate) ? rate : int.MaxValue;

    private async Task<PlanResult> PlanCoreAsync(AgentStepSpec spec, bool dryRun, CancellationToken ct)
    {
        var limits = await limitsStore.GetAsync(ct);
        var (segments, resolved) = await ResolveAsync(spec.NetworkIds, ct);

        // Scope policy ports: port parameters and endpoints are clipped here, and the agent re-checks AuthorizedPorts.
        var ports = PortScope.Effective(resolved.AllowedPorts, resolved.ExcludedPorts);
        if (ports.IsEmpty) throw new PlanningException("The scope policy's port rules exclude every port; nothing can be scanned.");
        var parameters = TargetPlanner.ClipPorts(spec.Operation, spec.Parameters, ports, resolved.AllowedPorts.Count > 0);
        foreach (var (name, value) in parameters.Where(p => spec.Parameters[p.Key] != p.Value))
            logger.LogInformation("Run {RunId} step {StepId}: {Parameter} clipped to the scope policy's ports: {Value}", spec.ScanRunId, spec.StepId, name, value);

        var capability = _options.CapabilityFor(spec.Operation);
        var needsRawSockets = OperationCatalog.NeedsRawSockets(spec.Operation, parameters);
        var stepRate = StepRate(spec);
        var onlineAgents = (await agents.GetActiveAgentsAsync(ct))
            .Where(a => a.IsOnline && a.Status == AgentStatus.Active)
            .Select(a => (Agent: a, Reach: AgentReach.Build(a, _options.AllowDefaultRoute))).ToList();
        var existing = dryRun
            ? []
            : (await db.Jobs.Where(j => j.ScanRunId == spec.ScanRunId && j.StepId == spec.StepId).Select(j => j.TargetKey).ToListAsync(ct)).ToHashSet();

        var throughput = await MeasuredThroughputAsync(spec, capability, segments, onlineAgents.Select(a => a.Agent), ct);
        var (batchSize, batchReason) = TargetPlanner.ChooseBatchSize(spec.BatchSize, limits.DefaultBatchSize, limits.TargetJobSeconds,
            throughput.Count > 0 ? throughput.Values.Average() : null);
        TargetPlan Plan(int size) => OperationCatalog.Get(spec.Operation).InputKind == TargetKind.Endpoints
            ? TargetPlanner.PlanEndpoints(segments, spec.Endpoints ?? [], size, limits.SubnetPrefixLength, ports.IsAll ? null : ports)
            : TargetPlanner.PlanHosts(segments, size, limits.SubnetPrefixLength, spec.Hosts, spec.HostAliases);
        var plan = Plan(batchSize);

        // Re-planned step (retry): keep the size its queued jobs were cut with, so their TargetKeys still dedupe even if
        // the measured throughput (and with it the adaptive size) changed in between.
        int Matches(TargetPlan p) => p.Batches.Count(b => existing.Contains(b.TargetKey));
        if (existing.Count > 0 && Matches(plan) < existing.Count)
        {
            var kept = TargetPlanner.BatchSizes.Select(size => (Size: size, Plan: Plan(size))).MaxBy(x => Matches(x.Plan));
            if (Matches(kept.Plan) > Matches(plan)) (batchSize, plan, batchReason) = (kept.Size, kept.Plan, $"batch size {kept.Size} (kept from the step's earlier jobs)");
        }
        if (plan.OutOfScope > 0)
            logger.LogWarning("Run {RunId} step {StepId}: {Count} targets outside the authorized scope were dropped", spec.ScanRunId, spec.StepId, plan.OutOfScope);

        var now = time.GetUtcNow();
        int created = 0, skipped = 0, unassignable = 0;
        string? unassignableReason = null;
        long targets = 0;
        var eligibleAgents = new HashSet<string>(StringComparer.Ordinal);
        foreach (var batch in plan.Batches)
        {
            targets += batch.Count;
            var targetKey = spec.TargetKeySalt is null ? batch.TargetKey : TargetPlanner.Hash([batch.TargetKey, spec.TargetKeySalt]);
            if (!existing.Add(targetKey)) { skipped++; continue; }

            var requirement = new JobRequirement(batch.Zone, batch.NetworkId, capability, spec.PreferredToolId, batch.ReachTargets,
                spec.RequiredParameters, needsRawSockets);
            var eligible = new List<(string AgentId, bool Direct)>();
            string? reason = onlineAgents.Count == 0 ? "no online agents" : null;
            foreach (var (agent, reach) in onlineAgents)
            {
                var eligibility = Eligibility.Evaluate(agent, reach, requirement, _options);
                if (eligibility.IsEligible) eligible.Add((agent.AgentId, eligibility.Direct));
                else reason ??= eligibility.Reason;
            }
            // Same rule as the claim: directly attached agents first, default-route agents only when none is online.
            var eligibleIds = (eligible.Any(e => e.Direct) ? eligible.Where(e => e.Direct) : eligible).Select(e => e.AgentId).ToList();
            if (eligible.Count == 0) { unassignable++; unassignableReason ??= reason; }
            eligibleAgents.UnionWith(eligibleIds);
            created++;
            if (dryRun) continue;

            var requested = Math.Min(stepRate, Math.Min(spec.RunRateCap ?? int.MaxValue, batch.NetworkRateCap ?? int.MaxValue));
            var jobId = Guid.NewGuid();
            var payload = new ScanJob
            {
                JobId = jobId, ScanRunId = spec.ScanRunId, WorkflowRunId = spec.WorkflowRunId, WorkflowStepId = spec.StepId,
                Operation = spec.Operation, Tool = new ToolSelection { Capability = capability, ToolId = spec.PreferredToolId },
                Targets = new JobTargets { Hosts = batch.Hosts, Endpoints = batch.Endpoints, Count = batch.Count },
                AuthorizedScope = batch.AuthorizedScope, AuthorizedPorts = ports.IsAll ? null : ports.ToString(), Parameters = parameters,
                Limits = new JobLimits { RatePerSecond = requested, TimeoutSeconds = spec.TimeoutSeconds },
                Priority = spec.Priority, NotAfter = spec.NotAfter, Signatures = spec.Signatures,
            };
            db.Jobs.Add(new ScanJobRecord
            {
                Id = jobId, ScanRunId = spec.ScanRunId, WorkflowRunId = spec.WorkflowRunId, StepId = spec.StepId, Operation = spec.Operation,
                Status = JobStatus.Queued, TargetKey = targetKey, TargetSummary = batch.Summary, TargetCount = batch.Count,
                ReachTargets = [.. batch.ReachTargets], Capability = capability, PreferredToolId = spec.PreferredToolId,
                RequiredParameters = [.. spec.RequiredParameters], NeedsRawSockets = needsRawSockets,
                Zone = batch.Zone, NetworkId = batch.NetworkId, SubnetKey = batch.SubnetKey, Priority = spec.Priority,
                RequestedRatePerSecond = requested, StepMaxConcurrency = spec.MaxConcurrency, TimeoutSeconds = spec.TimeoutSeconds,
                NotAfter = spec.NotAfter, EligibleAgentIds = eligibleIds, QueueReason = eligible.Count == 0 ? $"No eligible agent: {reason}" : null,
                MaxAttempts = Math.Clamp(spec.MaxAttempts, 1, limits.MaxAttempts), BackoffSeconds = spec.BackoffSeconds,
                CreatedAt = now, PayloadJson = JsonSerializer.Serialize(payload, ContractJson.Options),
            });
        }
        var result = new PlanResult(created, skipped, targets, plan.OutOfScope, unassignable, unassignableReason)
        {
            BatchSize = batchSize, BatchReason = batchReason, Throughput = throughput, EligibleAgentIds = eligibleAgents,
        };
        if (dryRun) return result;
        await db.SaveChangesAsync(ct);

        if (created > 0)
            await events.PublishAsync(time, ScanExecutionEventType.JobQueued, spec.ScanRunId,
                (unassignable > 0 ? $"{created} jobs queued, {unassignable} without an eligible agent ({unassignableReason}); they wait for one" : $"{created} jobs queued")
                + $"; {batchReason}",
                spec.WorkflowRunId, spec.StepId, data: new Dictionary<string, string>
                {
                    ["jobs"] = created.ToString(CultureInfo.InvariantCulture), ["targets"] = targets.ToString(CultureInfo.InvariantCulture),
                    ["unassignable"] = unassignable.ToString(CultureInfo.InvariantCulture), ["outOfScope"] = plan.OutOfScope.ToString(CultureInfo.InvariantCulture),
                    ["batchSize"] = batchSize.ToString(CultureInfo.InvariantCulture),
                }, ct: ct);
        return result;
    }

    /// <summary>
    /// Measured per-job throughput (targets/s over its last <see cref="ThroughputSampleJobs"/> completed jobs of this capability
    /// with the tool it would use) of every online agent that could run the step: authorized for one of its zones and with an
    /// approved tool for the capability. Agents without measurements are absent.
    /// </summary>
    /// <remarks>
    /// Not the <c>job_performance</c> EWMA: that is per tool, so nmap host discovery (fast) and nmap port scans (slow) would share
    /// one rate and port-scan batches would be sized from ping-sweep speed.
    /// </remarks>
    private async Task<IReadOnlyDictionary<string, double>> MeasuredThroughputAsync(AgentStepSpec spec, string capability,
        IReadOnlyList<SegmentTargets> segments, IEnumerable<AgentSnapshot> online, CancellationToken ct)
    {
        var zones = segments.Select(s => s.Zone).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var tools = online.Where(a => a.AuthorizedZones.Any(zones.Contains))
            .Select(a => (a.AgentId, Tool: Eligibility.SelectTool(a, capability, spec.PreferredToolId, _options, spec.RequiredParameters)))
            .Where(t => t.Tool is not null).ToList();
        if (tools.Count == 0) return new Dictionary<string, double>();
        var ids = tools.Select(t => t.AgentId).ToList();
        var recent = await db.Jobs.AsNoTracking()
            .Where(j => j.Status == JobStatus.Completed && j.AgentId != null && ids.Contains(j.AgentId) && j.Capability == capability && j.DurationMs > 0)
            .OrderByDescending(j => j.FinishedAt).Take(ThroughputSampleJobs * ids.Count)
            .Select(j => new { j.AgentId, j.ToolId, j.TargetCount, j.DurationMs }).ToListAsync(ct);
        return tools
            .Select(t => (t.AgentId, Jobs: recent.Where(j => j.AgentId == t.AgentId && j.ToolId == t.Tool).Take(ThroughputSampleJobs).ToList()))
            .Where(t => t.Jobs.Count > 0)
            .ToDictionary(t => t.AgentId, t => t.Jobs.Sum(j => j.TargetCount) / (t.Jobs.Sum(j => j.DurationMs!.Value) / 1000.0), StringComparer.Ordinal);
    }

    private const int ThroughputSampleJobs = 20;
}
