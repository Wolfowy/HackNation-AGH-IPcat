using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WebScan.Contracts;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Scanning.Persistence;

namespace WebScan.Server.Modules.Scanning.Events;

/// <summary>SignalR hub at <see cref="ScanHub.Path"/>. Run-level events go to everyone, the rest to the run's group.</summary>
[Authorize(Policy = Policies.CanRead)]
public sealed class ScanEventsHub : Hub
{
    public static string GroupName(Guid runId) => $"run:{runId:N}";

    public Task JoinRun(Guid runId) => Groups.AddToGroupAsync(Context.ConnectionId, GroupName(runId));
    public Task LeaveRun(Guid runId) => Groups.RemoveFromGroupAsync(Context.ConnectionId, GroupName(runId));
}

/// <summary>Persists every event (scanning.scan_events) and broadcasts it to the admin panel.</summary>
public sealed class ScanEventPublisher(IServiceScopeFactory scopes, IHubContext<ScanEventsHub> hub, ILogger<ScanEventPublisher> logger)
    : IScanEventPublisher
{
    public async Task PublishAsync(ScanExecutionEvent evt, CancellationToken ct = default)
    {
        // Own scope: never flush pending changes of the caller's DbContext.
        await using (var scope = scopes.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ScanningDbContext>();
            db.Events.Add(new ScanEventRecord
            {
                EventId = evt.EventId, ScanRunId = evt.ScanRunId, OccurredAt = evt.OccurredAt, Type = evt.Type,
                PayloadJson = JsonSerializer.Serialize(evt, ContractJson.Options),
            });
            await db.SaveChangesAsync(ct);
        }

        try
        {
            var clients = evt.ScanRunId is { } runId && !IsRunLevel(evt.Type) ? hub.Clients.Group(ScanEventsHub.GroupName(runId)) : hub.Clients.All;
            await clients.SendAsync(ScanHub.EventMethod, evt, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Broadcasting scan event {Type} failed", evt.Type);
        }
    }

    private static bool IsRunLevel(ScanExecutionEventType type) => type.ToString().StartsWith("Run", StringComparison.Ordinal);
}

public static class ScanEventPublisherExtensions
{
    public static Task PublishAsync(this IScanEventPublisher publisher, TimeProvider time, ScanExecutionEventType type, Guid? runId,
        string? message = null, Guid? workflowRunId = null, string? stepId = null, Guid? jobId = null, string? agentId = null,
        double? progress = null, IReadOnlyDictionary<string, string>? data = null, CancellationToken ct = default) =>
        publisher.PublishAsync(new ScanExecutionEvent
        {
            EventId = Guid.NewGuid(), OccurredAt = time.GetUtcNow(), Type = type, ScanRunId = runId, WorkflowRunId = workflowRunId,
            StepId = stepId, JobId = jobId, AgentId = agentId, Message = message, Progress = progress, Data = data,
        }, ct);
}
