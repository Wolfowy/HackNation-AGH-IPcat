using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Quartz;
using WebScan.Contracts;
using WebScan.Scheduling.UnitTests.Support;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Scanning.Persistence;
using WebScan.Server.Modules.Scheduling;
using WebScan.Server.Modules.Scheduling.Api;
using WebScan.Server.Modules.Scheduling.Persistence;
using WebScan.Server.Modules.Workflows.Definitions;

namespace WebScan.Scheduling.UnitTests;

[Collection(DbCollection.Name)]
public sealed class ScheduleTests(TestHost host) : DbTestBase(host)
{
    private ScheduleInput Input(Guid network, OverlapPolicy policy = OverlapPolicy.Skip, IReadOnlyList<AllowedWindow>? windows = null, int? windowMinutes = null) =>
        new($"nightly-{Zone}", "0 0 2 * * ?", "Europe/Warsaw", StandardWorkflows.StandardDiscoveryKey, null, [network], 40, 1000, windowMinutes, windows, policy, true);

    private async Task<ScheduleDto> CreateAsync(ScheduleInput input)
    {
        var response = await Host.UserClient(Roles.Manager).PostAsJsonAsync("/api/schedules", input, ContractJson.Options);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<ScheduleDto>(ContractJson.Options))!;
    }

    private Task<FireResult> FireAsync(Guid scheduleId, DateTimeOffset fireTime) =>
        Host.WithScopeAsync(sp => sp.GetRequiredService<ScheduleFiringService>().FireAsync(scheduleId, fireTime, manual: false, $"schedule:{scheduleId}"));

    private Task<Schedule> ScheduleAsync(Guid id) =>
        Host.WithScopeAsync(sp => sp.GetRequiredService<SchedulingDbContext>().Schedules.AsNoTracking().FirstAsync(s => s.Id == id));

    private async Task<ITrigger?> TriggerAsync(Guid id) =>
        await (await Host.App.Services.GetRequiredService<ISchedulerFactory>().GetScheduler()).GetTrigger(QuartzScheduleSync.TriggerKeyFor(id));

    [Fact]
    public async Task Schedules_are_validated_and_kept_in_sync_with_quartz()
    {
        var net = Host.Scope.Add(Zone, ["10.90.0.0/28"]);
        var bad = Input(net, windows: [new([], "25:00", "06:00")]) with { CronExpression = "every night", TimeZone = "Mars/Base" };
        var invalid = await Host.UserClient(Roles.Manager).PostAsJsonAsync("/api/schedules", bad, ContractJson.Options);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, invalid.StatusCode);
        var problem = await invalid.Content.ReadFromJsonAsync<JsonElement>();
        foreach (var key in new[] { "cronExpression", "timeZone", "allowedWindows" }) Assert.True(problem.GetProperty("errors").TryGetProperty(key, out _), key);
        Assert.Equal(HttpStatusCode.Forbidden, (await Host.UserClient(Roles.Viewer).PostAsJsonAsync("/api/schedules", Input(net), ContractJson.Options)).StatusCode);

        var created = await CreateAsync(Input(net));
        Assert.NotNull(created.NextFireAt);
        Assert.Equal(TimeSpan.FromHours(2), TimeZoneInfo.ConvertTime(created.NextFireAt!.Value, TimeZoneInfo.FindSystemTimeZoneById("Europe/Warsaw")).TimeOfDay);
        var trigger = await TriggerAsync(created.Id);
        Assert.NotNull(trigger);
        Assert.Equal(created.NextFireAt!.Value, trigger!.GetNextFireTimeUtc()!.Value, TimeSpan.FromDays(1)); // same daily cadence
        Assert.Equal(MisfireInstruction.CronTrigger.DoNothing, trigger.MisfireInstruction);

        var client = Host.UserClient(Roles.Editor);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync($"/api/schedules/{created.Id}/pause", null)).StatusCode);
        Assert.Null(await TriggerAsync(created.Id));
        Assert.Null((await ScheduleAsync(created.Id)).NextFireAt);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync($"/api/schedules/{created.Id}/resume", null)).StatusCode);
        Assert.NotNull(await TriggerAsync(created.Id));

        var updated = await client.PutAsJsonAsync($"/api/schedules/{created.Id}", Input(net) with { CronExpression = "0 30 3 ? * MON-FRI" }, ContractJson.Options);
        Assert.Equal(HttpStatusCode.OK, updated.StatusCode);
        Assert.Equal("0 30 3 ? * MON-FRI", ((ICronTrigger)(await TriggerAsync(created.Id))!).CronExpressionString);

        var list = await Host.UserClient(Roles.Viewer).GetFromJsonAsync<List<ScheduleDto>>("/api/schedules", ContractJson.Options);
        Assert.Contains(list!, s => s.Id == created.Id);
        Assert.Equal(HttpStatusCode.NoContent, (await Host.UserClient(Roles.Manager).DeleteAsync($"/api/schedules/{created.Id}")).StatusCode);
        Assert.Null(await TriggerAsync(created.Id));
    }

    [Fact]
    public async Task Quartz_trigger_fires_the_schedule_through_the_launcher()
    {
        var net = Host.Scope.Add(Zone, ["10.96.0.0/28"]);
        var schedule = await CreateAsync(Input(net) with { CronExpression = "* * * * * ?" }); // every second
        try
        {
            await Host.WaitUntilAsync(async () => (await ScheduleAsync(schedule.Id)).LastRunId is not null, "Quartz fire", 15);
            var run = await Host.RunAsync((await ScheduleAsync(schedule.Id)).LastRunId!.Value);
            Assert.Equal($"schedule:{schedule.Id}", run.TriggeredBy);
            Assert.Equal(0, run.ScheduledFireTime!.Value.Millisecond); // Quartz fire times are whole seconds
        }
        finally
        {
            await Host.UserClient(Roles.Editor).PostAsync($"/api/schedules/{schedule.Id}/pause", null);
        }
    }

    [Fact]
    public async Task Fire_outside_the_allowed_windows_is_skipped_with_an_event()
    {
        var net = Host.Scope.Add(Zone, ["10.91.0.0/28"]);
        var now = Host.Time.GetUtcNow();
        var local = TimeZoneInfo.ConvertTime(now, TimeZoneInfo.FindSystemTimeZoneById("Europe/Warsaw"));
        var otherDay = local.AddDays(3).DayOfWeek;
        var schedule = await CreateAsync(Input(net, windows: [new([otherDay], "00:00", "00:00")]));

        var result = await FireAsync(schedule.Id, now);

        Assert.Equal(FireOutcome.Skipped, result.Outcome);
        Assert.Null((await ScheduleAsync(schedule.Id)).LastRunId);
        var events = await Host.DbAsync(db => db.Events.Where(e => e.ScanRunId == null && e.Type == ScanExecutionEventType.RunCancelled).Select(e => e.PayloadJson).ToListAsync());
        Assert.Contains(events, e => e.Contains(schedule.Id.ToString()) && e.Contains("outside-window"));
    }

    [Fact]
    public async Task Manual_trigger_starts_a_run_bounded_by_the_window_duration()
    {
        var net = Host.Scope.Add(Zone, ["10.92.0.0/28"]);
        var schedule = await CreateAsync(Input(net, windowMinutes: 90));

        var response = await Host.UserClient(Roles.Editor).PostAsync($"/api/schedules/{schedule.Id}/trigger", null);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<TriggerResultDto>(ContractJson.Options);

        var run = await Host.RunAsync(result!.ScanRunId!.Value);
        Assert.Equal(schedule.Id, run.ScheduleId);
        Assert.StartsWith("manual:", run.TriggeredBy);
        Assert.Equal(run.ScheduledFireTime!.Value.AddMinutes(90), run.NotAfter!.Value, TimeSpan.FromMilliseconds(1));
        Assert.Equal(40, run.Priority);
        Assert.Equal("Running", (await Host.UserClient().GetFromJsonAsync<ScheduleDto>($"/api/schedules/{schedule.Id}", ContractJson.Options))!.LastRunStatus);
    }

    [Fact]
    public async Task Overlap_skip_leaves_the_active_run_alone()
    {
        var net = Host.Scope.Add(Zone, ["10.93.0.0/28"]);
        var schedule = await CreateAsync(Input(net, OverlapPolicy.Skip));
        var first = await FireAsync(schedule.Id, Host.Time.GetUtcNow());
        var second = await FireAsync(schedule.Id, Host.Time.GetUtcNow().AddMinutes(1));

        Assert.Equal(FireOutcome.Started, first.Outcome);
        Assert.Equal(FireOutcome.Skipped, second.Outcome);
        Assert.Contains("still active", second.Reason);
        Assert.Equal(ScanRunStatus.Running, (await Host.RunAsync(first.ScanRunId!.Value)).Status);
    }

    [Fact]
    public async Task Overlap_cancel_previous_replaces_the_active_run()
    {
        var net = Host.Scope.Add(Zone, ["10.94.0.0/28"]);
        var schedule = await CreateAsync(Input(net, OverlapPolicy.CancelPrevious));
        var first = await FireAsync(schedule.Id, Host.Time.GetUtcNow());
        var second = await FireAsync(schedule.Id, Host.Time.GetUtcNow().AddMinutes(1));

        Assert.Equal(FireOutcome.Started, second.Outcome);
        Assert.Equal(ScanRunStatus.Cancelled, (await Host.RunAsync(first.ScanRunId!.Value)).Status);
        Assert.Equal(second.ScanRunId, (await ScheduleAsync(schedule.Id)).LastRunId);
    }

    [Fact]
    public async Task Overlap_queue_starts_the_deferred_fire_when_the_previous_run_finishes()
    {
        var net = Host.Scope.Add(Zone, ["10.95.0.0/28"]);
        var schedule = await CreateAsync(Input(net, OverlapPolicy.Queue));
        var first = await FireAsync(schedule.Id, Host.Time.GetUtcNow());
        var queuedFire = Host.Time.GetUtcNow().AddMinutes(1);
        var second = await FireAsync(schedule.Id, queuedFire);
        Assert.Equal(FireOutcome.Queued, second.Outcome);
        Assert.NotNull((await ScheduleAsync(schedule.Id)).QueuedFireTime);

        await Host.WithScopeAsync(sp => sp.GetRequiredService<IScanLauncher>().CancelAsync(first.ScanRunId!.Value, "test"));

        await Host.WaitUntilAsync(async () => (await ScheduleAsync(schedule.Id)).LastRunId != first.ScanRunId, "queued fire started");
        var schedule2 = await ScheduleAsync(schedule.Id);
        Assert.Null(schedule2.QueuedFireTime);
        var run = await Host.RunAsync(schedule2.LastRunId!.Value);
        Assert.Equal(queuedFire, run.ScheduledFireTime!.Value, TimeSpan.FromMilliseconds(1));
    }
}
