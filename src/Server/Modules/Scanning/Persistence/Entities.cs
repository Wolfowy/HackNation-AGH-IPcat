using WebScan.Contracts;

namespace WebScan.Server.Modules.Scanning.Persistence;

public enum ScanRunStatus { Pending, Running, Completed, PartiallyCompleted, Failed, Cancelled, WindowExpired }

public enum JobStatus { Queued, Leased, Completed, Failed, Cancelled }

public static class ScanRunStatuses
{
    public static bool IsTerminal(this ScanRunStatus s) => s is not (ScanRunStatus.Pending or ScanRunStatus.Running);
}

public sealed class ScanRun
{
    public Guid Id { get; set; }
    public required string Name { get; set; }
    public ScanRunStatus Status { get; set; }
    public required string WorkflowKey { get; set; }
    public int WorkflowVersion { get; set; }
    public List<Guid> NetworkIds { get; set; } = [];
    public int Priority { get; set; }
    public int? MaxRatePerSecond { get; set; }
    public DateTimeOffset? NotAfter { get; set; }
    public Guid? ScheduleId { get; set; }
    public DateTimeOffset? ScheduledFireTime { get; set; }
    public required string TriggeredBy { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? StartedAt { get; set; }
    public DateTimeOffset? FinishedAt { get; set; }
    public bool CoverageComplete { get; set; }
    public string? Message { get; set; }
}

/// <summary>Persistent queue entry for one <see cref="ScanJob"/> (one batch, one step, one perspective).</summary>
public sealed class ScanJobRecord
{
    /// <summary>Perspective key of jobs that any eligible (agent, interface) may execute.</summary>
    public const string AnyPerspective = "*";

    public Guid Id { get; set; }
    public Guid ScanRunId { get; set; }
    public Guid? WorkflowRunId { get; set; }
    public required string StepId { get; set; }
    public ScanOperation Operation { get; set; }
    public JobStatus Status { get; set; }

    /// <summary>Deterministic hash of the batch targets; with run, step and perspective it is unique (dedup).</summary>
    public required string TargetKey { get; set; }
    public string PerspectiveKey { get; set; } = AnyPerspective;
    public required string TargetSummary { get; set; }
    public long TargetCount { get; set; }

    /// <summary>Host entries (or endpoint addresses) used for reachability checks at claim time.</summary>
    public List<string> ReachTargets { get; set; } = [];

    public required string Capability { get; set; }
    public string? PreferredToolId { get; set; }

    /// <summary>Step parameters set explicitly: only tools supporting all of them may run the job.</summary>
    public List<string> RequiredParameters { get; set; } = [];

    /// <summary>The selected technique needs raw sockets (agents reporting RawSockets=false are not eligible).</summary>
    public bool NeedsRawSockets { get; set; }
    public required string Zone { get; set; }
    public Guid NetworkId { get; set; }
    public string? SubnetKey { get; set; }
    public int Priority { get; set; }

    /// <summary>min(step rate, run cap, network cap); agent cap and global share are applied at claim time.</summary>
    public int RequestedRatePerSecond { get; set; }
    public int StepMaxConcurrency { get; set; }
    public int TimeoutSeconds { get; set; }
    public DateTimeOffset? NotAfter { get; set; }

    /// <summary>Planner hint for the UI (agents eligible when the job was queued) and why nobody could take it.</summary>
    public List<string> EligibleAgentIds { get; set; } = [];
    public string? QueueReason { get; set; }

    public string? AgentId { get; set; }
    public string? InterfaceName { get; set; }
    public string? ToolId { get; set; }
    public string? LastAgentId { get; set; }
    public Guid? LeaseId { get; set; }
    public DateTimeOffset? LeaseExpiresAt { get; set; }
    public int? AssignedRatePerSecond { get; set; }

    /// <summary>Number of leases handed out so far (the current lease's 1-based attempt).</summary>
    public int Attempt { get; set; }
    public int MaxAttempts { get; set; }
    public int BackoffSeconds { get; set; }
    public DateTimeOffset? NextAttemptAt { get; set; }
    public bool CancelRequested { get; set; }

    public double? ProgressPercent { get; set; }
    public string? ProgressMessage { get; set; }
    public string? CoverageJson { get; set; }
    public string? Error { get; set; }
    public JobFailureReason? FailureReason { get; set; }
    public long? DurationMs { get; set; }
    public string? ToolVersion { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? StartedAt { get; set; }
    public DateTimeOffset? FinishedAt { get; set; }

    /// <summary>The <see cref="ScanJob"/> contract (updated with tool/interface/rate when leased).</summary>
    public required string PayloadJson { get; set; }

    /// <summary>PostgreSQL xmin, optimistic concurrency between agent calls, sweeper and cancellation.</summary>
    public uint Version { get; set; }

    public bool IsTerminal => Status is JobStatus.Completed or JobStatus.Failed or JobStatus.Cancelled;
}

public sealed class ResultBatchRecord
{
    public Guid BatchId { get; set; }
    public Guid JobId { get; set; }
    public Guid ScanRunId { get; set; }
    public required string StepId { get; set; }
    public Guid LeaseId { get; set; }
    public int Sequence { get; set; }
    public int ObservationCount { get; set; }
    public DateTimeOffset ReceivedAt { get; set; }

    /// <summary>Accepted (scope-checked, re-masked) observations as a JSON array.</summary>
    public required string PayloadJson { get; set; }
}

public sealed class ScanEventRecord
{
    public long Seq { get; set; }
    public Guid EventId { get; set; }
    public Guid? ScanRunId { get; set; }
    public DateTimeOffset OccurredAt { get; set; }
    public ScanExecutionEventType Type { get; set; }
    public required string PayloadJson { get; set; }
}

/// <summary>Measured execution performance per perspective and tool (EWMA), feeds the claim score.</summary>
public sealed class JobPerformance
{
    public required string AgentId { get; set; }
    public required string InterfaceName { get; set; }
    public required string ToolId { get; set; }
    public long JobsCompleted { get; set; }
    public double AvgDurationMs { get; set; }
    public double AvgTargetsPerSecond { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary>Global planner limits (single row holding a serialized <see cref="Planning.ScanLimits"/>).</summary>
public sealed class ScanLimitsRecord
{
    public const int SingletonId = 1;
    public int Id { get; set; } = SingletonId;
    public required string ValuesJson { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
