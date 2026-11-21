using WebScan.Contracts;

namespace WebScan.Server.Kernel.Ports;

/// <summary>Starts scan runs (manual API, Quartz schedules). Implemented by the Scanning/Workflows modules.</summary>
public interface IScanLauncher
{
    Task<Guid> StartAsync(StartScanRequest request, CancellationToken ct = default);
    Task CancelAsync(Guid scanRunId, string reason, CancellationToken ct = default);
}

public sealed record StartScanRequest
{
    public required string Name { get; init; }
    public required string WorkflowKey { get; init; }

    /// <summary>Null = latest version.</summary>
    public int? WorkflowVersion { get; init; }

    public required IReadOnlyList<Guid> NetworkIds { get; init; }
    public int Priority { get; init; }

    /// <summary>Run-level rate cap (packets/s).</summary>
    public int? MaxRatePerSecond { get; init; }

    /// <summary>Scan window end; when reached, active jobs are cancelled and the run ends as WindowExpired.</summary>
    public DateTimeOffset? NotAfter { get; init; }

    public Guid? ScheduleId { get; init; }

    /// <summary>Quartz fire time; (ScheduleId, ScheduledFireTime) is unique → no duplicate runs from double firing.</summary>
    public DateTimeOffset? ScheduledFireTime { get; init; }

    /// <summary>"manual:{userId}" or "schedule:{scheduleId}".</summary>
    public required string TriggeredBy { get; init; }
}

/// <summary>Publishes execution events (persist + SignalR). Implemented by the Scanning module.</summary>
public interface IScanEventPublisher
{
    Task PublishAsync(ScanExecutionEvent evt, CancellationToken ct = default);
}
