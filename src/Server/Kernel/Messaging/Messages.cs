using WebScan.Contracts;
using WebScan.Server.Kernel.Ports;

namespace WebScan.Server.Kernel.Messaging;

// Cross-module messages carried by Wolverine (RabbitMQ in production, local queues in tests).
// Producers publish via Wolverine IMessageBus; handlers live in the consuming module.

/// <summary>Scanning → Discovery: a result batch was stored (idempotently) and must be normalized/persisted.</summary>
public sealed record ScanResultBatchReceived(IngestContext Context, ScanResultBatch Batch);

/// <summary>Scanning → Workflows: a job reached a terminal state.</summary>
public sealed record ScanJobFinished(Guid JobId, Guid ScanRunId, Guid? WorkflowRunId, string? StepId, string FinalStatus);

/// <summary>Agents → Scanning: agent stopped heartbeating; its leases must be released for reassignment.</summary>
public sealed record AgentWentOffline(string AgentId, DateTimeOffset LastHeartbeatAt);

/// <summary>Scanning/Workflows → Discovery/Integrations: a run reached a terminal state.</summary>
public sealed record ScanRunFinished(Guid ScanRunId, string FinalStatus, bool CoverageComplete);

/// <summary>Discovery → anyone (UI notifications, integrations).</summary>
public sealed record AssetChangesDetected(Guid ScanRunId, int Count);
