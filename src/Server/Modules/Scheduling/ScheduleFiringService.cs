using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WebScan.Contracts;
using WebScan.Server.Kernel.Messaging;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Kernel.Scanning;
using WebScan.Server.Modules.Scheduling.Persistence;
using Wolverine.Attributes;

namespace WebScan.Server.Modules.Scheduling;

public enum FireOutcome { Started, Skipped, Queued, NotFound }

public sealed record FireResult(FireOutcome Outcome, Guid? ScanRunId, string? Reason = null);

/// <summary>Turns a schedule fire (Quartz or manual trigger) into a scan run, honouring windows and the overlap policy.</summary>
public sealed class ScheduleFiringService(
    SchedulingDbContext db, IScanLauncher launcher, IScanRunStatusReader runStatus, IScanEventPublisher events, TimeProvider time,
    ILogger<ScheduleFiringService> logger)
{
    public async Task<FireResult> FireAsync(Guid scheduleId, DateTimeOffset fireTime, bool manual, string triggeredBy, CancellationToken ct = default)
    {
        var schedule = await db.Schedules.FirstOrDefaultAsync(s => s.Id == scheduleId, ct);
        if (schedule is null) return new FireResult(FireOutcome.NotFound, null, "Schedule not found");
        if (!manual && !schedule.Enabled) return new FireResult(FireOutcome.Skipped, null, "Schedule is paused");
        var zone = ScheduleCalculator.FindTimeZone(schedule.TimeZone) ?? throw new InvalidOperationException($"Unknown time zone '{schedule.TimeZone}'.");
        var now = time.GetUtcNow();
        schedule.LastFireAt = fireTime;
        schedule.NextFireAt = ScheduleCalculator.NextFire(schedule.CronExpression, zone, schedule.AllowedWindows, now);

        // Manual triggers ignore the allowed windows, but a window they fall into still bounds the run.
        var inside = ScheduleCalculator.IsInsideWindows(schedule.AllowedWindows, zone, fireTime, out var windowEnd);
        if (!inside && !manual) return await SkipAsync(schedule, fireTime, "outside-window", "outside the allowed windows", ct);

        if (schedule.LastRunId is { } previous && await IsActiveAsync(previous, ct))
        {
            switch (schedule.OverlapPolicy)
            {
                case OverlapPolicy.Skip:
                    return await SkipAsync(schedule, fireTime, "previous-run-active", $"previous run {previous} is still active", ct);
                case OverlapPolicy.Queue:
                    schedule.QueuedFireTime = fireTime;
                    await db.SaveChangesAsync(ct);
                    // The previous run may have finished meanwhile; its ScanRunFinished could have been handled already.
                    if (await IsActiveAsync(previous, ct)) return new FireResult(FireOutcome.Queued, null, $"Queued behind run {previous}");
                    schedule.QueuedFireTime = null;
                    break;
                case OverlapPolicy.CancelPrevious:
                    await launcher.CancelAsync(previous, "Superseded by a newer scheduled run", ct);
                    break;
            }
        }

        var notAfter = ScheduleCalculator.NotAfter(fireTime, windowEnd, schedule.WindowDurationMinutes);
        if (notAfter <= now) return await SkipAsync(schedule, fireTime, "window-over", "its scan window is already over", ct);

        var local = TimeZoneInfo.ConvertTime(fireTime, zone);
        var runId = await launcher.StartAsync(new StartScanRequest
        {
            Name = $"{schedule.Name} {local.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)}",
            WorkflowKey = schedule.WorkflowKey, WorkflowVersion = schedule.WorkflowVersion, NetworkIds = schedule.NetworkIds,
            Priority = schedule.Priority, MaxRatePerSecond = schedule.MaxRatePerSecond, NotAfter = notAfter,
            ScheduleId = schedule.Id, ScheduledFireTime = fireTime, TriggeredBy = triggeredBy,
        }, ct);
        schedule.LastRunId = runId;
        await db.SaveChangesAsync(ct);
        return new FireResult(FireOutcome.Started, runId);
    }

    /// <summary>Starts the fire deferred by <see cref="OverlapPolicy.Queue"/> once the blocking run finished.</summary>
    public async Task<FireResult?> FireQueuedAsync(Guid finishedRunId, CancellationToken ct = default)
    {
        var schedule = await db.Schedules.FirstOrDefaultAsync(s => s.LastRunId == finishedRunId && s.QueuedFireTime != null, ct);
        if (schedule is null) return null;
        var fireTime = schedule.QueuedFireTime!.Value;
        schedule.QueuedFireTime = null;
        await db.SaveChangesAsync(ct);
        return await FireAsync(schedule.Id, fireTime, manual: false, $"schedule:{schedule.Id}", ct);
    }

    private async Task<bool> IsActiveAsync(Guid runId, CancellationToken ct) =>
        ScanRunStatusNames.IsActive((await runStatus.GetStatusesAsync([runId], ct)).GetValueOrDefault(runId));

    private async Task<FireResult> SkipAsync(Schedule schedule, DateTimeOffset fireTime, string code, string reason, CancellationToken ct)
    {
        await db.SaveChangesAsync(ct);
        var message = $"Schedule '{schedule.Name}' fire at {fireTime:O} skipped: {reason}";
        logger.LogInformation("{Message}", message);
        // No dedicated event type exists for skipped fires; RunCancelled without a run id carries it (see Data.reason).
        await events.PublishAsync(new ScanExecutionEvent
        {
            EventId = Guid.NewGuid(), OccurredAt = time.GetUtcNow(), Type = ScanExecutionEventType.RunCancelled, Message = message,
            Data = new Dictionary<string, string> { ["scheduleId"] = schedule.Id.ToString(), ["fireTime"] = fireTime.ToString("O"), ["reason"] = code },
        }, ct);
        return new FireResult(FireOutcome.Skipped, null, message);
    }
}

/// <summary>Wolverine handler: a run finished → start a fire that the Queue overlap policy deferred (scope: see ScanJobFinishedHandler).</summary>
public static class ScheduleRunFinishedHandler
{
    [NonTransactional]
    public static async Task Handle(ScanRunFinished message, IServiceScopeFactory scopes, CancellationToken ct)
    {
        await using var scope = scopes.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<ScheduleFiringService>().FireQueuedAsync(message.ScanRunId, ct);
    }
}
