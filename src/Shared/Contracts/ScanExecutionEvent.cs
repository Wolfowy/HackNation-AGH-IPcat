namespace WebScan.Contracts;

/// <summary>
/// Execution state change of a scan run / workflow step / job / agent. Persisted by the server and pushed
/// to the admin panel through SignalR hub <c>/hubs/scans</c> (client method <c>"scanEvent"</c>).
/// </summary>
public sealed record ScanExecutionEvent
{
    public required Guid EventId { get; init; }
    public required DateTimeOffset OccurredAt { get; init; }
    public required ScanExecutionEventType Type { get; init; }

    public Guid? ScanRunId { get; init; }
    public Guid? WorkflowRunId { get; init; }
    public string? StepId { get; init; }
    public Guid? JobId { get; init; }
    public string? AgentId { get; init; }

    public string? Message { get; init; }

    /// <summary>0–100 for progress events.</summary>
    public double? Progress { get; init; }

    public IReadOnlyDictionary<string, string>? Data { get; init; }
}

public enum ScanExecutionEventType
{
    RunCreated,
    RunStarted,
    RunCompleted,
    RunPartiallyCompleted,
    RunFailed,
    RunCancelled,
    RunWindowExpired,
    StepStarted,
    StepCompleted,
    StepSkipped,
    StepFailed,
    JobQueued,
    JobAssigned,
    JobProgress,
    JobCompleted,
    JobFailed,
    JobRetryScheduled,
    JobCancelled,
    JobLeaseExpired,
    ResultsReceived,
    AgentOnline,
    AgentOffline,
    ChangeDetected,
}

public static class ScanHub
{
    public const string Path = "/hubs/scans";

    /// <summary>Client-side method receiving <see cref="ScanExecutionEvent"/>.</summary>
    public const string EventMethod = "scanEvent";

    /// <summary>Server method: subscribe to one run's events (all users receive run-level events anyway).</summary>
    public const string JoinRunMethod = "JoinRun";

    public const string LeaveRunMethod = "LeaveRun";
}
