using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Quartz;
using WebScan.Contracts;
using WebScan.Scheduling.UnitTests.Support;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Scanning.Persistence;
using WebScan.Server.Modules.Scanning.Planning;
using WebScan.Server.Modules.Scheduling;
using WebScan.Server.Modules.Scheduling.Api;
using WebScan.Server.Modules.Scheduling.Persistence;
using WebScan.Server.Modules.Workflows.Api;
using WebScan.Server.Modules.Workflows.Definitions;

namespace WebScan.Scheduling.UnitTests;

/// <summary>Adaptive batch sizes, duration estimates, ETA and resuming runs cut by their scan window.</summary>
[Collection(DbCollection.Name)]
public sealed class ScanWindowTests(TestHost host) : DbTestBase(host)
{
    private static readonly TimeZoneInfo Warsaw = ScheduleCalculator.FindTimeZone("Europe/Warsaw")!;

    private string AgentId => $"perf-{Zone}";

    /// <summary>
    /// Online agent of this test's zone reaching 10.110.0.0/20; with <paramref name="targetsPerSecond"/> it has completed a
    /// host-discovery job (nmap) at that rate, plus a much slower port scan with the same tool that must not count.
    /// </summary>
    private async Task MeasuredAgentAsync(double? targetsPerSecond)
    {
        Host.Agents.Set(Agents.Simple(AgentId, Zone, "10.110.0.1/20"));
        if (targetsPerSecond is not { } tps) return;
        var now = Host.Time.GetUtcNow();
        ScanJobRecord Done(ScanOperation operation, string capability, double rate) => new()
        {
            Id = Guid.NewGuid(), ScanRunId = Guid.NewGuid(), StepId = "history", Operation = operation, Status = JobStatus.Completed,
            TargetKey = Guid.NewGuid().ToString("N"), TargetSummary = "history", TargetCount = 100, Capability = capability, Zone = "history",
            AgentId = AgentId, ToolId = "nmap", DurationMs = (long)(100 / rate * 1000), CreatedAt = now, FinishedAt = now, PayloadJson = "{}",
        };
        await Host.DbAsync(db =>
        {
            db.Jobs.AddRange(Done(ScanOperation.DiscoverHosts, ToolCapabilities.HostDiscovery, tps), Done(ScanOperation.ScanPorts, ToolCapabilities.PortScan, tps / 100));
            return db.SaveChangesAsync();
        });
    }

    private Task<PlanResult> PlanAsync(Guid runId, Guid net, int? batchSize = null) => Host.WithScopeAsync(sp => sp.GetRequiredService<TaskPlanner>().PlanAsync(new AgentStepSpec
    {
        ScanRunId = runId, StepId = "step", Operation = ScanOperation.DiscoverHosts, NetworkIds = [net], BatchSize = batchSize,
        Parameters = ParameterValidator.Validate(OperationCatalog.Get(ScanOperation.DiscoverHosts).Parameters, null).Values,
    }));

    [Fact]
    public async Task Planner_sizes_batches_from_measured_throughput_and_keeps_the_size_of_existing_jobs()
    {
        var net = Host.Scope.Add(Zone, ["10.110.0.0/20"]); // 4096 addresses
        await MeasuredAgentAsync(null);

        var (runId, unmeasured) = await QueueJobsAsync(net);
        Assert.Equal(256, unmeasured.BatchSize);
        Assert.Equal(16, unmeasured.JobsCreated);
        Assert.Contains("no throughput measured", unmeasured.BatchReason);

        await MeasuredAgentAsync(2.0); // 2 t/s × 300 s = 600 → 512
        var (_, measured) = await QueueJobsAsync(net);
        Assert.Equal(512, measured.BatchSize);
        Assert.Equal(8, measured.JobsCreated);
        Assert.Contains("measured 2 targets/s", measured.BatchReason);

        var (_, explicitSize) = await QueueJobsAsync(net, batchSize: 128);
        Assert.Equal(128, explicitSize.BatchSize);
        Assert.Equal(32, explicitSize.JobsCreated);

        // Re-planning the first run's step (e.g. a step retry) keeps its 256 batches so TargetKey dedup still holds.
        var replanned = await PlanAsync(runId, net);
        Assert.Equal(256, replanned.BatchSize);
        Assert.Equal(0, replanned.JobsCreated);
        Assert.Equal(16, replanned.JobsExisting);
        Assert.Contains("kept", replanned.BatchReason);
        var events = await Host.DbAsync(db => db.Events.Where(e => e.ScanRunId == runId && e.Type == ScanExecutionEventType.JobQueued).Select(e => e.PayloadJson).ToListAsync());
        Assert.Contains(events, e => e.Contains("batch size 256"));
    }

    [Fact]
    public async Task Estimate_reports_addresses_jobs_duration_and_window_overrun()
    {
        var net = Host.Scope.Add(Zone, ["10.110.0.0/20"]);
        var viewer = Host.UserClient(Roles.Viewer);
        var request = new ScanEstimateRequest(StandardWorkflows.StandardDiscoveryKey, null, [net], null, 5);

        var invalid = await viewer.PostAsJsonAsync("/api/scans/estimate", request with { NetworkIds = [Guid.NewGuid()] }, ContractJson.Options);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, invalid.StatusCode);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, (await viewer.PostAsJsonAsync("/api/scans/estimate", request with { WorkflowKey = "nope" }, ContractJson.Options)).StatusCode);

        var noAgent = await (await viewer.PostAsJsonAsync("/api/scans/estimate", request, ContractJson.Options)).Content.ReadFromJsonAsync<ScanEstimateDto>(ContractJson.Options);
        Assert.Equal(4096, noAgent!.AddressCount);
        Assert.Null(noAgent.EstimatedSecondsMax);
        Assert.Contains(noAgent.Warnings, w => w.Contains("No online agent"));

        await MeasuredAgentAsync(2.0);
        var response = await viewer.PostAsJsonAsync("/api/scans/estimate", request, ContractJson.Options);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var estimate = (await response.Content.ReadFromJsonAsync<ScanEstimateDto>(ContractJson.Options))!;
        var step = Assert.Single(estimate.Steps);
        Assert.Equal("discover", step.StepId);
        Assert.Equal(8, step.Jobs);
        Assert.Equal(512, step.BatchSize);
        Assert.Equal(1, step.EligibleAgents);
        Assert.Equal(2.0, step.TargetsPerSecond);
        Assert.Equal(512, estimate.EstimatedSecondsMin); // 4096 targets / (2 t/s × 4 parallel jobs)
        Assert.Equal(512, estimate.EstimatedSecondsMax); // 2 waves × 512 targets at 2 t/s
        Assert.True(estimate.ExceedsWindow);
        Assert.Contains(estimate.Warnings, w => w.Contains("5-minute window"));
        Assert.Equal(0, await Host.DbAsync(db => db.Jobs.CountAsync(j => j.Zone == Zone))); // a dry run queues nothing

        var roomy = await (await viewer.PostAsJsonAsync("/api/scans/estimate", request with { WindowMinutes = 60 }, ContractJson.Options)).Content.ReadFromJsonAsync<ScanEstimateDto>(ContractJson.Options);
        Assert.False(roomy!.ExceedsWindow);
    }

    [Fact]
    public async Task Running_scans_report_remaining_time_from_their_own_rate()
    {
        Assert.Null(ScanEndpoints.RemainingSeconds(ScanRunStatus.Running, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddSeconds(10), 0, 100)); // nothing done yet
        Assert.Null(ScanEndpoints.RemainingSeconds(ScanRunStatus.Completed, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddSeconds(10), 50, 50));
        Assert.Equal(30, ScanEndpoints.RemainingSeconds(ScanRunStatus.Running, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddSeconds(10), 25, 75));

        var net = Host.Scope.Add(Zone, ["10.111.0.0/24"]);
        var (runId, plan) = await QueueJobsAsync(net, batchSize: 64);
        Assert.Equal(4, plan.JobsCreated);
        var now = Host.Time.GetUtcNow();
        await Host.DbAsync(async db =>
        {
            await db.ScanRuns.Where(r => r.Id == runId).ExecuteUpdateAsync(s => s.SetProperty(r => r.StartedAt, now.AddSeconds(-100)));
            var first = await db.Jobs.Where(j => j.ScanRunId == runId).OrderBy(j => j.TargetSummary).Select(j => j.Id).FirstAsync();
            return await db.Jobs.Where(j => j.Id == first).ExecuteUpdateAsync(s => s.SetProperty(j => j.Status, JobStatus.Completed));
        });

        var run = await Host.UserClient(Roles.Viewer).GetFromJsonAsync<ScanRunDto>($"/api/scans/{runId}", ContractJson.Options);
        Assert.Equal(300, run!.RemainingSeconds); // 64 targets in 100 s → 192 open targets take 300 s
        Assert.Equal(now.AddSeconds(300), run.EstimatedFinishAt!.Value, TimeSpan.FromSeconds(1));
    }

    private ScheduleInput WindowedInput(Guid network, bool? resume = null)
    {
        // A 24-hour window (start == end) on every day that opened a minute ago; runs are cut after one minute.
        var start = TimeZoneInfo.ConvertTime(Host.Time.GetUtcNow(), Warsaw).AddMinutes(-1).ToString("HH:mm", CultureInfo.InvariantCulture);
        return new($"resume-{Zone}", "0 0 2 * * ?", "Europe/Warsaw", StandardWorkflows.StandardDiscoveryKey, null, [network], 40, null, 1,
            [new(Enum.GetValues<DayOfWeek>(), start, start)], OverlapPolicy.Skip, true, resume);
    }

    private async Task<ScheduleDto> CreateScheduleAsync(ScheduleInput input)
    {
        var response = await Host.UserClient(Roles.Manager).PostAsJsonAsync("/api/schedules", input, ContractJson.Options);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<ScheduleDto>(ContractJson.Options))!;
    }

    private Task<T> FiringAsync<T>(Func<ScheduleFiringService, Task<T>> action) => Host.WithScopeAsync(sp => action(sp.GetRequiredService<ScheduleFiringService>()));

    private Task<Schedule> ScheduleAsync(Guid id) =>
        Host.WithScopeAsync(sp => sp.GetRequiredService<SchedulingDbContext>().Schedules.AsNoTracking().FirstAsync(s => s.Id == id));

    private async Task<ITrigger?> ResumeTriggerAsync(Guid id) =>
        await (await Host.App.Services.GetRequiredService<ISchedulerFactory>().GetScheduler()).GetTrigger(QuartzScheduleSync.ResumeTriggerKeyFor(id));

    [Fact]
    public async Task Run_cut_by_its_window_resumes_at_the_next_window_start_once_and_respects_pause()
    {
        var net = Host.Scope.Add(Zone, ["10.112.0.0/28"]);
        var schedule = await CreateScheduleAsync(WindowedInput(net));
        Assert.True(schedule.ResumeInNextWindow);
        var editor = Host.UserClient(Roles.Editor);
        try
        {
            var first = await FiringAsync(f => f.FireAsync(schedule.Id, Host.Time.GetUtcNow(), manual: false, $"schedule:{schedule.Id}"));
            Assert.Equal(FireOutcome.Started, first.Outcome);

            Host.Time.Advance(TimeSpan.FromMinutes(2)); // past the one-minute run window
            await Host.WaitUntilAsync(async () => (await ScheduleAsync(schedule.Id)).ResumeAt is not null, "resume planned");
            Assert.Equal(ScanRunStatus.WindowExpired, (await Host.RunAsync(first.ScanRunId!.Value)).Status);
            var resumeAt = (await ScheduleAsync(schedule.Id)).ResumeAt!.Value;
            var windows = (await ScheduleAsync(schedule.Id)).AllowedWindows;
            Assert.Equal(ScheduleCalculator.NextWindowStart(windows, Warsaw, Host.Time.GetUtcNow()), resumeAt);
            Assert.Equal(resumeAt, (await ResumeTriggerAsync(schedule.Id))!.StartTimeUtc);
            Assert.Equal(resumeAt, (await Host.UserClient(Roles.Viewer).GetFromJsonAsync<ScheduleDto>($"/api/schedules/{schedule.Id}", ContractJson.Options))!.ResumeAt);

            // The one-off fire starts the run at the window start; a cron occurrence in the same window does not start another.
            var resumed = await FiringAsync(f => f.FireResumeAsync(schedule.Id));
            Assert.Equal(FireOutcome.Started, resumed.Outcome);
            var run = await Host.RunAsync(resumed.ScanRunId!.Value);
            Assert.Equal(resumeAt, run.ScheduledFireTime!.Value, TimeSpan.FromMilliseconds(1));
            Assert.EndsWith("(resumed)", run.Name);
            Assert.Null((await ScheduleAsync(schedule.Id)).ResumeAt);
            var cron = await FiringAsync(f => f.FireAsync(schedule.Id, resumeAt.AddMinutes(30), manual: false, $"schedule:{schedule.Id}"));
            Assert.Equal(FireOutcome.Skipped, cron.Outcome);
            Assert.Contains("resumed run already started", cron.Reason);
            Assert.Equal(FireOutcome.Skipped, (await FiringAsync(f => f.FireResumeAsync(schedule.Id))).Outcome); // nothing pending: no double fire

            // Only WindowExpired resumes; a paused schedule never does, and pausing drops a pending resume.
            Assert.Null(await FiringAsync(f => f.PlanResumeAsync(resumed.ScanRunId!.Value, "Completed")));
            Assert.Equal(HttpStatusCode.OK, (await editor.PostAsync($"/api/schedules/{schedule.Id}/pause", null)).StatusCode);
            Assert.Null(await FiringAsync(f => f.PlanResumeAsync(resumed.ScanRunId!.Value, "WindowExpired")));
            Assert.Equal(HttpStatusCode.OK, (await editor.PostAsync($"/api/schedules/{schedule.Id}/resume", null)).StatusCode);
            var planned = await FiringAsync(f => f.PlanResumeAsync(resumed.ScanRunId!.Value, "WindowExpired"));
            await Host.App.Services.GetRequiredService<QuartzScheduleSync>().ApplyAsync(planned!);
            Assert.NotNull(await ResumeTriggerAsync(schedule.Id));
            Assert.Equal(HttpStatusCode.OK, (await editor.PostAsync($"/api/schedules/{schedule.Id}/pause", null)).StatusCode);
            Assert.Null((await ScheduleAsync(schedule.Id)).ResumeAt);
            Assert.Null(await ResumeTriggerAsync(schedule.Id));
            Assert.Equal(FireOutcome.Skipped, (await FiringAsync(f => f.FireResumeAsync(schedule.Id))).Outcome);
        }
        finally
        {
            await editor.PostAsync($"/api/schedules/{schedule.Id}/pause", null);
        }
    }

    [Fact]
    public async Task Resume_can_be_turned_off_per_schedule()
    {
        var net = Host.Scope.Add(Zone, ["10.113.0.0/28"]);
        var schedule = await CreateScheduleAsync(WindowedInput(net, resume: false));
        try
        {
            Assert.False(schedule.ResumeInNextWindow);
            var fire = await FiringAsync(f => f.FireAsync(schedule.Id, Host.Time.GetUtcNow(), manual: false, $"schedule:{schedule.Id}"));
            Assert.Null(await FiringAsync(f => f.PlanResumeAsync(fire.ScanRunId!.Value, "WindowExpired")));
        }
        finally
        {
            await Host.UserClient(Roles.Editor).PostAsync($"/api/schedules/{schedule.Id}/pause", null);
        }
    }
}
