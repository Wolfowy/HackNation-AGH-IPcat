using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Quartz;
using WebScan.Server.Kernel.Scanning;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Scheduling.Persistence;

namespace WebScan.Server.Modules.Scheduling.Api;

public sealed record ScheduleInput(
    string Name, string CronExpression, string TimeZone, string WorkflowKey, int? WorkflowVersion, IReadOnlyList<Guid> NetworkIds,
    int? Priority, int? MaxRatePerSecond, int? WindowDurationMinutes, IReadOnlyList<AllowedWindow>? AllowedWindows, OverlapPolicy? OverlapPolicy, bool? Enabled)
{
    public Dictionary<string, string[]> Validate()
    {
        var errors = new Dictionary<string, string[]>();
        void Add(string key, string message) => errors[key] = [.. errors.GetValueOrDefault(key) ?? [], message];
        if (string.IsNullOrWhiteSpace(Name) || Name.Length > 200) Add("name", "name is required (max 200 characters).");
        if (string.IsNullOrWhiteSpace(CronExpression) || !Quartz.CronExpression.IsValidExpression(CronExpression))
            Add("cronExpression", "Invalid cron expression (Quartz syntax: sec min hour day-of-month month day-of-week [year], e.g. '0 0 2 ? * MON-FRI').");
        if (ScheduleCalculator.FindTimeZone(TimeZone) is null) Add("timeZone", $"Unknown time zone '{TimeZone}' (use an IANA id such as 'Europe/Warsaw').");
        if (string.IsNullOrWhiteSpace(WorkflowKey)) Add("workflowKey", "workflowKey is required.");
        if (NetworkIds is null || NetworkIds.Count == 0) Add("networkIds", "At least one network is required.");
        if (Priority is < 0 or > 100) Add("priority", "priority must be between 0 and 100.");
        if (MaxRatePerSecond is < 1) Add("maxRatePerSecond", "maxRatePerSecond must be at least 1.");
        if (WindowDurationMinutes is < 1 or > 10_080) Add("windowDurationMinutes", "windowDurationMinutes must be between 1 and 10080.");
        if (OverlapPolicy is { } p && !Enum.IsDefined(p)) Add("overlapPolicy", "Invalid overlap policy.");
        foreach (var e in ScheduleCalculator.ValidateWindows(AllowedWindows)) Add("allowedWindows", e);
        return errors;
    }

    public void ApplyTo(Schedule s)
    {
        s.Name = Name.Trim();
        s.CronExpression = CronExpression.Trim();
        s.TimeZone = TimeZone;
        s.WorkflowKey = WorkflowKey;
        s.WorkflowVersion = WorkflowVersion;
        s.NetworkIds = NetworkIds.Distinct().ToList();
        s.Priority = Priority ?? 50;
        s.MaxRatePerSecond = MaxRatePerSecond;
        s.WindowDurationMinutes = WindowDurationMinutes;
        s.AllowedWindows = (AllowedWindows ?? []).ToList();
        s.OverlapPolicy = OverlapPolicy ?? Persistence.OverlapPolicy.Skip;
        s.Enabled = Enabled ?? s.Enabled;
    }
}

public sealed record ScheduleDto(
    Guid Id, string Name, string CronExpression, string TimeZone, string WorkflowKey, int? WorkflowVersion, IReadOnlyList<Guid> NetworkIds,
    int Priority, int? MaxRatePerSecond, int? WindowDurationMinutes, IReadOnlyList<AllowedWindow> AllowedWindows, OverlapPolicy OverlapPolicy,
    bool Enabled, DateTimeOffset? NextFireAt, DateTimeOffset? LastFireAt, Guid? LastRunId, string? LastRunStatus, DateTimeOffset? QueuedFireTime,
    DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt);

public sealed record TriggerResultDto(Guid? ScanRunId, string Outcome, string? Reason);

public static class ScheduleEndpoints
{
    public static void MapScheduleEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var schedules = endpoints.MapGroup("/api/schedules").WithTags("Schedules");

        schedules.MapGet("", async (SchedulingDbContext db, IScanRunStatusReader runs, CancellationToken ct) =>
        {
            var all = await db.Schedules.AsNoTracking().OrderBy(s => s.Name).ToListAsync(ct);
            var statuses = await runs.GetStatusesAsync(all.Where(s => s.LastRunId is not null).Select(s => s.LastRunId!.Value).ToList(), ct);
            return all.Select(s => ToDto(s, statuses)).ToList();
        }).RequireAuthorization(Policies.CanRead);

        schedules.MapGet("/{id:guid}", async (Guid id, SchedulingDbContext db, IScanRunStatusReader runs, CancellationToken ct) =>
            await db.Schedules.AsNoTracking().FirstOrDefaultAsync(s => s.Id == id, ct) is { } s
                ? Results.Ok(ToDto(s, await runs.GetStatusesAsync(s.LastRunId is { } r ? [r] : [], ct)))
                : Results.NotFound()).RequireAuthorization(Policies.CanRead);

        schedules.MapPost("", async (ScheduleInput input, SchedulingDbContext db, QuartzScheduleSync sync, IAuditLog audit, TimeProvider time, CancellationToken ct) =>
        {
            var errors = input.Validate();
            if (errors.Count > 0) return Results.ValidationProblem(errors, statusCode: StatusCodes.Status422UnprocessableEntity);
            var now = time.GetUtcNow();
            var schedule = new Schedule
            {
                Id = Guid.NewGuid(), Name = input.Name, CronExpression = input.CronExpression, TimeZone = input.TimeZone, WorkflowKey = input.WorkflowKey,
                CreatedAt = now, UpdatedAt = now,
            };
            input.ApplyTo(schedule);
            schedule.NextFireAt = NextFire(schedule, now);
            db.Schedules.Add(schedule);
            await db.SaveChangesAsync(ct);
            await sync.ApplyAsync(schedule, ct);
            await audit.WriteAsync(new AuditEntry("schedule.created", "Schedule", schedule.Id.ToString(), new { schedule.Name, schedule.CronExpression }), ct);
            return Results.Created($"/api/schedules/{schedule.Id}", ToDto(schedule, new Dictionary<Guid, string>()));
        }).RequireAuthorization(Policies.CanManage);

        schedules.MapPut("/{id:guid}", async (Guid id, ScheduleInput input, SchedulingDbContext db, QuartzScheduleSync sync, IAuditLog audit,
            IScanRunStatusReader runs, TimeProvider time, CancellationToken ct) =>
        {
            var schedule = await db.Schedules.FirstOrDefaultAsync(s => s.Id == id, ct);
            if (schedule is null) return Results.NotFound();
            var errors = input.Validate();
            if (errors.Count > 0) return Results.ValidationProblem(errors, statusCode: StatusCodes.Status422UnprocessableEntity);
            input.ApplyTo(schedule);
            schedule.UpdatedAt = time.GetUtcNow();
            schedule.NextFireAt = schedule.Enabled ? NextFire(schedule, schedule.UpdatedAt) : null;
            await db.SaveChangesAsync(ct);
            await sync.ApplyAsync(schedule, ct);
            await audit.WriteAsync(new AuditEntry("schedule.updated", "Schedule", id.ToString(), new { schedule.Name, schedule.CronExpression }), ct);
            return Results.Ok(ToDto(schedule, await runs.GetStatusesAsync(schedule.LastRunId is { } r ? [r] : [], ct)));
        }).RequireAuthorization(Policies.CanEdit);

        schedules.MapDelete("/{id:guid}", async (Guid id, SchedulingDbContext db, QuartzScheduleSync sync, IAuditLog audit, CancellationToken ct) =>
        {
            var schedule = await db.Schedules.FirstOrDefaultAsync(s => s.Id == id, ct);
            if (schedule is null) return Results.NotFound();
            db.Schedules.Remove(schedule);
            await db.SaveChangesAsync(ct);
            await sync.RemoveAsync(id, ct);
            await audit.WriteAsync(new AuditEntry("schedule.deleted", "Schedule", id.ToString(), new { schedule.Name }), ct);
            return Results.NoContent();
        }).RequireAuthorization(Policies.CanManage);

        schedules.MapPost("/{id:guid}/trigger", async (Guid id, ClaimsPrincipal user, ScheduleFiringService firing, IAuditLog audit, TimeProvider time, CancellationToken ct) =>
        {
            FireResult result;
            try
            {
                result = await firing.FireAsync(id, time.GetUtcNow(), manual: true, $"manual:{user.GetUserId() ?? user.Identity?.Name ?? "unknown"}", ct);
            }
            catch (ScanLaunchException ex)
            {
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["schedule"] = [ex.Message] }, statusCode: StatusCodes.Status422UnprocessableEntity);
            }
            if (result.Outcome == FireOutcome.NotFound) return Results.NotFound();
            await audit.WriteAsync(new AuditEntry("schedule.triggered", "Schedule", id.ToString(), new { result.ScanRunId, Outcome = result.Outcome.ToString() }), ct);
            return result.Outcome == FireOutcome.Skipped
                ? Results.Problem(result.Reason, statusCode: StatusCodes.Status409Conflict)
                : Results.Ok(new TriggerResultDto(result.ScanRunId, result.Outcome.ToString(), result.Reason));
        }).RequireAuthorization(Policies.CanEdit);

        schedules.MapPost("/{id:guid}/pause", (Guid id, SchedulingDbContext db, QuartzScheduleSync sync, IAuditLog audit, TimeProvider time, CancellationToken ct) =>
            SetEnabledAsync(id, false, db, sync, audit, time, ct)).RequireAuthorization(Policies.CanEdit);

        schedules.MapPost("/{id:guid}/resume", (Guid id, SchedulingDbContext db, QuartzScheduleSync sync, IAuditLog audit, TimeProvider time, CancellationToken ct) =>
            SetEnabledAsync(id, true, db, sync, audit, time, ct)).RequireAuthorization(Policies.CanEdit);
    }

    private static async Task<IResult> SetEnabledAsync(Guid id, bool enabled, SchedulingDbContext db, QuartzScheduleSync sync, IAuditLog audit, TimeProvider time, CancellationToken ct)
    {
        var schedule = await db.Schedules.FirstOrDefaultAsync(s => s.Id == id, ct);
        if (schedule is null) return Results.NotFound();
        schedule.Enabled = enabled;
        schedule.UpdatedAt = time.GetUtcNow();
        schedule.NextFireAt = enabled ? NextFire(schedule, schedule.UpdatedAt) : null; // resume = next fire per schedule, no catch-up
        await db.SaveChangesAsync(ct);
        await sync.ApplyAsync(schedule, ct);
        await audit.WriteAsync(new AuditEntry(enabled ? "schedule.resumed" : "schedule.paused", "Schedule", id.ToString()), ct);
        return Results.Ok(ToDto(schedule, new Dictionary<Guid, string>()));
    }

    private static DateTimeOffset? NextFire(Schedule s, DateTimeOffset now) =>
        ScheduleCalculator.FindTimeZone(s.TimeZone) is { } zone ? ScheduleCalculator.NextFire(s.CronExpression, zone, s.AllowedWindows, now) : null;

    private static ScheduleDto ToDto(Schedule s, IReadOnlyDictionary<Guid, string> runStatuses) => new(
        s.Id, s.Name, s.CronExpression, s.TimeZone, s.WorkflowKey, s.WorkflowVersion, s.NetworkIds, s.Priority, s.MaxRatePerSecond,
        s.WindowDurationMinutes, s.AllowedWindows, s.OverlapPolicy, s.Enabled, s.NextFireAt, s.LastFireAt, s.LastRunId,
        s.LastRunId is { } r ? runStatuses.GetValueOrDefault(r) : null, s.QueuedFireTime, s.CreatedAt, s.UpdatedAt);
}
