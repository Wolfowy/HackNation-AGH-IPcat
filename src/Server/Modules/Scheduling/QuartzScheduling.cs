using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Quartz;
using WebScan.Server.Modules.Scheduling.Persistence;

namespace WebScan.Server.Modules.Scheduling;

/// <summary>Quartz job shared by all schedule triggers (trigger data carries the schedule id).</summary>
public sealed class ScheduleFireJob(ScheduleFiringService firing, ILogger<ScheduleFireJob> logger) : IJob
{
    public static readonly JobKey Key = new("schedule-fire", "webscan");
    public const string ScheduleIdKey = "scheduleId";

    public async Task Execute(IJobExecutionContext context)
    {
        var scheduleId = Guid.Parse(context.MergedJobDataMap.GetString(ScheduleIdKey)!);
        var fireTime = context.ScheduledFireTimeUtc ?? context.FireTimeUtc;
        try
        {
            var result = await firing.FireAsync(scheduleId, fireTime, manual: false, $"schedule:{scheduleId}", context.CancellationToken);
            logger.LogInformation("Schedule {ScheduleId} fired at {FireTime}: {Outcome} {RunId} {Reason}", scheduleId, fireTime, result.Outcome, result.ScanRunId, result.Reason);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Never let Quartz refire (misfire policy is "do nothing"); the next cron fire tries again.
            logger.LogError(ex, "Schedule {ScheduleId} fire at {FireTime} failed", scheduleId, fireTime);
        }
    }
}

/// <summary>Keeps Quartz RAM-store triggers in sync with the schedules table (at startup and after every change).</summary>
public sealed class QuartzScheduleSync(ISchedulerFactory schedulerFactory, IServiceScopeFactory scopes, ILogger<QuartzScheduleSync> logger) : IHostedService
{
    private const string TriggerGroup = "webscan-schedules";

    public static TriggerKey TriggerKeyFor(Guid scheduleId) => new(scheduleId.ToString("N"), TriggerGroup);

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SchedulingDbContext>();
        foreach (var schedule in await db.Schedules.AsNoTracking().ToListAsync(cancellationToken))
            await ApplyAsync(schedule, cancellationToken);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>(Re)creates or removes the trigger of one schedule.</summary>
    public async Task ApplyAsync(Schedule schedule, CancellationToken ct = default)
    {
        var scheduler = await schedulerFactory.GetScheduler(ct);
        var key = TriggerKeyFor(schedule.Id);
        await scheduler.UnscheduleJob(key, ct);
        var zone = ScheduleCalculator.FindTimeZone(schedule.TimeZone);
        if (!schedule.Enabled || zone is null || !CronExpression.IsValidExpression(schedule.CronExpression))
        {
            if (schedule.Enabled) logger.LogWarning("Schedule {ScheduleId} has an invalid cron or time zone; not scheduled", schedule.Id);
            return;
        }
        var trigger = TriggerBuilder.Create()
            .WithIdentity(key)
            .ForJob(ScheduleFireJob.Key)
            .UsingJobData(ScheduleFireJob.ScheduleIdKey, schedule.Id.ToString())
            .WithCronSchedule(schedule.CronExpression, cron => cron.InTimeZone(zone).WithMisfireHandlingInstructionDoNothing())
            .Build();
        await scheduler.ScheduleJob(trigger, ct);
    }

    public async Task RemoveAsync(Guid scheduleId, CancellationToken ct = default) =>
        await (await schedulerFactory.GetScheduler(ct)).UnscheduleJob(TriggerKeyFor(scheduleId), ct);
}
