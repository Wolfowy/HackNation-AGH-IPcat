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

    /// <summary>Endpoint targets for endpoint operations.</summary>
    public IReadOnlyCollection<ScanEndpoint>? Endpoints { get; init; }

    /// <summary>Mixed into the dedup key so one step can queue the same targets again (e.g. RecheckMissing rounds).</summary>
    public string? TargetKeySalt { get; init; }
}

public sealed record PlanResult(int JobsCreated, int JobsExisting, long TargetCount, int OutOfScope, int Unassignable, string? UnassignableReason)
{
    public int JobsTotal => JobsCreated + JobsExisting;
}

/// <summary>DB-backed planner: resolves the authorized scope, batches it and queues deduplicated jobs.</summary>
public sealed class TaskPlanner(
    ScanningDbContext db, INetworkScopeService scope, IAgentDirectory agents, ScanLimitsStore limitsStore,
    IOptions<PlannerOptions> plannerOptions, IScanEventPublisher events, TimeProvider time, ILogger<TaskPlanner> logger)
{
    private readonly PlannerOptions _options = plannerOptions.Value;

    /// <summary>Scope of the networks with the planner's own re-check against the global scope policy.</summary>
    public async Task<IReadOnlyList<SegmentTargets>> ResolveScopeAsync(IReadOnlyCollection<Guid> networkIds, CancellationToken ct = default)
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
        return TargetPlanner.ResolveTargets(resolved with { Segments = segments }, _options.MaxIpv6SegmentAddresses);
    }

    public async Task<PlanResult> PlanAsync(AgentStepSpec spec, CancellationToken ct = default)
    {
        var limits = await limitsStore.GetAsync(ct);
        var segments = await ResolveScopeAsync(spec.NetworkIds, ct);
        var batchSize = TargetPlanner.NormalizeBatchSize(spec.BatchSize, limits.DefaultBatchSize);
        var plan = OperationCatalog.Get(spec.Operation).InputKind == TargetKind.Endpoints
            ? TargetPlanner.PlanEndpoints(segments, spec.Endpoints ?? [], batchSize, limits.SubnetPrefixLength)
            : TargetPlanner.PlanHosts(segments, batchSize, limits.SubnetPrefixLength, spec.Hosts);
        if (plan.OutOfScope > 0)
            logger.LogWarning("Run {RunId} step {StepId}: {Count} targets outside the authorized scope were dropped", spec.ScanRunId, spec.StepId, plan.OutOfScope);

        var capability = _options.CapabilityFor(spec.Operation);
        var needsRawSockets = OperationCatalog.NeedsRawSockets(spec.Operation, spec.Parameters);
        var stepRate = spec.Parameters.TryGetValue("rate", out var r) && int.TryParse(r, CultureInfo.InvariantCulture, out var rate) ? rate : int.MaxValue;
        var onlineAgents = (await agents.GetActiveAgentsAsync(ct))
            .Where(a => a.IsOnline && a.Status == AgentStatus.Active)
            .Select(a => (Agent: a, Reach: AgentReach.Build(a, _options.AllowDefaultRoute))).ToList();
        var existing = (await db.Jobs.Where(j => j.ScanRunId == spec.ScanRunId && j.StepId == spec.StepId)
            .Select(j => j.TargetKey).ToListAsync(ct)).ToHashSet();

        var now = time.GetUtcNow();
        int created = 0, skipped = 0, unassignable = 0;
        string? unassignableReason = null;
        long targets = 0;
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

            var requested = Math.Min(stepRate, Math.Min(spec.RunRateCap ?? int.MaxValue, batch.NetworkRateCap ?? int.MaxValue));
            var jobId = Guid.NewGuid();
            var payload = new ScanJob
            {
                JobId = jobId, ScanRunId = spec.ScanRunId, WorkflowRunId = spec.WorkflowRunId, WorkflowStepId = spec.StepId,
                Operation = spec.Operation, Tool = new ToolSelection { Capability = capability, ToolId = spec.PreferredToolId },
                Targets = new JobTargets { Hosts = batch.Hosts, Endpoints = batch.Endpoints, Count = batch.Count },
                AuthorizedScope = batch.AuthorizedScope, Parameters = spec.Parameters,
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
            created++;
        }
        await db.SaveChangesAsync(ct);

        var result = new PlanResult(created, skipped, targets, plan.OutOfScope, unassignable, unassignableReason);
        if (created > 0)
            await events.PublishAsync(time, ScanExecutionEventType.JobQueued, spec.ScanRunId,
                unassignable > 0 ? $"{created} jobs queued, {unassignable} without an eligible agent ({unassignableReason}); they wait for one" : $"{created} jobs queued",
                spec.WorkflowRunId, spec.StepId, data: new Dictionary<string, string>
                {
                    ["jobs"] = created.ToString(CultureInfo.InvariantCulture), ["targets"] = targets.ToString(CultureInfo.InvariantCulture),
                    ["unassignable"] = unassignable.ToString(CultureInfo.InvariantCulture), ["outOfScope"] = plan.OutOfScope.ToString(CultureInfo.InvariantCulture),
                }, ct: ct);
        return result;
    }
}
