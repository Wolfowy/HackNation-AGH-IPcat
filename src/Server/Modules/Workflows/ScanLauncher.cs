using WebScan.Server.Kernel.Ports;
using WebScan.Server.Kernel.Scanning;
using WebScan.Server.Modules.Scanning.Persistence;
using WebScan.Server.Modules.Scanning.Runs;
using WebScan.Server.Modules.Workflows.Definitions;
using WebScan.Server.Modules.Workflows.Runtime;

namespace WebScan.Server.Modules.Workflows;

/// <summary>
/// <see cref="IScanLauncher"/>: validates the request, creates the scan run and starts its workflow.
/// Idempotent on (ScheduleId, ScheduledFireTime): a double fire returns the existing run.
/// </summary>
public sealed class ScanLauncher(
    ScanRunStore runs, WorkflowDefinitionStore definitions, INetworkScopeService scope, IWorkflowRuntime runtime, TimeProvider time) : IScanLauncher
{
    public async Task<Guid> StartAsync(StartScanRequest request, CancellationToken ct = default)
    {
        // PostgreSQL keeps microseconds: normalize so the (schedule, fire time) lookup matches what is stored.
        var fireTime = request.ScheduledFireTime is { } f ? f.AddTicks(-(f.Ticks % 10)).ToUniversalTime() : (DateTimeOffset?)null;
        if (request.ScheduleId is { } scheduleId && fireTime is { } fire && await runs.FindByScheduleAsync(scheduleId, fire, ct) is { } existing)
            return existing.Id;

        var now = time.GetUtcNow();
        if (string.IsNullOrWhiteSpace(request.Name) || request.Name.Length > 200) throw new ScanLaunchException("name is required (max 200 characters).");
        if (request.NetworkIds is null || request.NetworkIds.Count == 0) throw new ScanLaunchException("At least one network is required.");
        if (request.Priority is < 0 or > 100) throw new ScanLaunchException("priority must be between 0 and 100.");
        if (request.MaxRatePerSecond is < 1) throw new ScanLaunchException("maxRatePerSecond must be at least 1.");
        if (request.NotAfter <= now) throw new ScanLaunchException("The scan window end (notAfter) is already in the past.");

        var workflow = await definitions.GetAsync(request.WorkflowKey, request.WorkflowVersion, ct)
                       ?? throw new ScanLaunchException($"Workflow '{request.WorkflowKey}'{(request.WorkflowVersion is { } v ? $" version {v}" : "")} not found.");
        var networkIds = request.NetworkIds.Distinct().ToList();
        var resolved = await scope.ResolveAsync(networkIds, ct);
        var missing = networkIds.Except(resolved.Segments.Select(s => s.NetworkId)).ToList();
        if (missing.Count > 0) throw new ScanLaunchException($"Unknown or disabled networks: {string.Join(", ", missing)}.");

        var (run, created) = await runs.CreateAsync(new ScanRun
        {
            Id = Guid.NewGuid(), Name = request.Name.Trim(), Status = ScanRunStatus.Pending, WorkflowKey = workflow.Key, WorkflowVersion = workflow.Version,
            NetworkIds = networkIds, Priority = request.Priority, MaxRatePerSecond = request.MaxRatePerSecond, NotAfter = request.NotAfter,
            ScheduleId = request.ScheduleId, ScheduledFireTime = fireTime, TriggeredBy = request.TriggeredBy, CreatedAt = now,
        }, ct);
        if (created) await runtime.StartAsync(run.Id, ct);
        return run.Id;
    }

    public Task CancelAsync(Guid scanRunId, string reason, CancellationToken ct = default) => runtime.CancelAsync(scanRunId, reason, ct);
}
