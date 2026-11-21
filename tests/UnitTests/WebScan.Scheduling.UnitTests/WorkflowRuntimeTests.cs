using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WebScan.Contracts;
using WebScan.Scheduling.UnitTests.Support;
using WebScan.Server.Kernel.Networking;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Kernel.Scanning;
using WebScan.Server.Modules.Scanning.Persistence;
using WebScan.Server.Modules.Workflows.Definitions;
using WebScan.Server.Modules.Workflows.Persistence;

namespace WebScan.Scheduling.UnitTests;

[Collection(DbCollection.Name)]
public sealed class WorkflowRuntimeTests(TestHost host) : DbTestBase(host)
{
    private string AgentId => $"wf-{Zone}";

    /// <summary>Synthetic tool output: host .1 serves http:80 + ssh:22, host .2 serves https:443 (unless overridden).</summary>
    private static Func<ScanJob, IReadOnlyList<DiscoveryObservation>> Lab(Dictionary<int, int[]>? portsByHost = null)
    {
        portsByHost ??= new() { [1] = [80, 22], [2] = [443] };
        return job =>
        {
            var id = job.JobId;
            return job.Operation switch
            {
                ScanOperation.DiscoverHosts => Addresses(job).Where(a => portsByHost.ContainsKey(LastOctet(a))).Select(a => Observations.Make(id, ObservationKind.HostUp, a)).ToList(),
                ScanOperation.ScanPorts => Addresses(job).SelectMany(a => portsByHost.GetValueOrDefault(LastOctet(a), []).Select(p => Observations.Make(id, ObservationKind.PortOpen, a, p))).ToList(),
                ScanOperation.DetectService => job.Targets.Endpoints.Select(e => Observations.Make(id, ObservationKind.Service, e.Address, e.Port, service: e.Port switch
                {
                    80 => new ServiceDetails { Name = "http" },
                    443 => new ServiceDetails { Name = "https", Tunnel = "ssl" },
                    _ => new ServiceDetails { Name = "ssh" },
                })).ToList(),
                ScanOperation.HttpProbe => job.Targets.Endpoints.Select(e => Observations.Make(id, ObservationKind.HttpResponse, e.Address, e.Port,
                    http: new HttpDetails { Url = $"{e.Scheme}://{e.Address}:{e.Port}/", Scheme = e.Scheme ?? "http", StatusCode = 200 })).ToList(),
                ScanOperation.TlsProbe => job.Targets.Endpoints.Select(e => Observations.Make(id, ObservationKind.TlsCertificate, e.Address, e.Port)).ToList(),
                _ => [],
            };
        };
    }

    private static IEnumerable<string> Addresses(ScanJob job) =>
        IpRangeSet.Parse(job.Targets.Hosts).Ranges.SelectMany(r => Enumerable.Range(0, (int)r.Count).Select(i => IpRangeSet.ToAddress(r.Family, r.Start + (UInt128)i).ToString()));

    private static int LastOctet(string address) => int.Parse(address.Split('.')[^1]);

    private Task<Guid> LaunchAsync(Guid network, string workflowKey = StandardWorkflows.StandardDiscoveryKey, DateTimeOffset? notAfter = null) =>
        Host.WithScopeAsync(sp => sp.GetRequiredService<IScanLauncher>().StartAsync(new StartScanRequest
        {
            Name = $"run-{Zone}", WorkflowKey = workflowKey, NetworkIds = [network], TriggeredBy = "test", NotAfter = notAfter,
        }));

    private async Task<string> CreateWorkflowAsync(params WorkflowStep[] steps)
    {
        var key = $"wf-{Guid.NewGuid():N}"[..20];
        var result = await Host.WithScopeAsync(sp => sp.GetRequiredService<WorkflowDefinitionStore>()
            .CreateAsync(new ScanWorkflowDefinition { Key = key, Name = key, Steps = steps }, "test"));
        Assert.Equal(SaveStatus.Saved, result.Status);
        return key;
    }

    private Task<Dictionary<string, WorkflowStepRun>> StepsAsync(Guid runId) => Host.WithScopeAsync(async sp =>
    {
        var db = sp.GetRequiredService<WorkflowsDbContext>();
        var wf = await db.Runs.AsNoTracking().FirstAsync(w => w.ScanRunId == runId);
        return await db.StepRuns.AsNoTracking().Where(s => s.WorkflowRunId == wf.Id).ToDictionaryAsync(s => s.StepId);
    });

    private Task<List<ScanJob>> JobsAsync(Guid runId, string stepId) => Host.DbAsync(async db =>
        (await db.Jobs.AsNoTracking().Where(j => j.ScanRunId == runId && j.StepId == stepId).Select(j => j.PayloadJson).ToListAsync())
        .Select(p => System.Text.Json.JsonSerializer.Deserialize<ScanJob>(p, ContractJson.Options)!).ToList());

    /// <summary>Agent loop until the run is terminal; returns the operations of each claim round.</summary>
    private async Task<List<HashSet<ScanOperation>>> RunAgentUntilFinishedAsync(Guid runId, Func<ScanJob, IReadOnlyList<DiscoveryObservation>> results)
    {
        var rounds = new List<HashSet<ScanOperation>>();
        await Host.WaitUntilAsync(async () =>
        {
            var claim = await Host.ClaimAsync(AgentId, 50);
            if (claim.Assignments.Count > 0) rounds.Add(claim.Assignments.Select(a => a.Job.Operation).ToHashSet());
            foreach (var a in claim.Assignments) await Host.CompleteAsync(AgentId, a, results(a.Job));
            return (await Host.RunAsync(runId)).Status.IsTerminal();
        }, "run finished", 60);
        return rounds;
    }

    [Fact]
    public async Task Standard_discovery_runs_end_to_end_with_parallel_http_and_tls_branches()
    {
        var net = Host.Scope.Add(Zone, ["10.60.0.0/28"]);
        Host.Agents.Set(Agents.Simple(AgentId, Zone, "10.60.0.0/24", maxJobs: 10));

        var runId = await LaunchAsync(net);
        var rounds = await RunAgentUntilFinishedAsync(runId, Lab());

        var run = await Host.RunAsync(runId);
        Assert.Equal(ScanRunStatus.Completed, run.Status);
        Assert.True(run.CoverageComplete);
        Assert.All((await StepsAsync(runId)).Values, s => Assert.Equal(StepStatus.Completed, s.Status));
        Assert.Contains(rounds, r => r.Contains(ScanOperation.HttpProbe) && r.Contains(ScanOperation.TlsProbe)); // branches ran in parallel

        Assert.Equal(["10.60.0.1", "10.60.0.2"], (await JobsAsync(runId, "ports")).SelectMany(j => j.Targets.Hosts).Order());
        var http = (await JobsAsync(runId, "http")).SelectMany(j => j.Targets.Endpoints).Select(e => $"{e.Scheme}://{e.Address}:{e.Port}").Order();
        Assert.Equal(["http://10.60.0.1:80", "https://10.60.0.2:443"], http);
        Assert.Equal(["10.60.0.2:443"], (await JobsAsync(runId, "tls")).SelectMany(j => j.Targets.Endpoints).Select(e => $"{e.Address}:{e.Port}"));
        Assert.Equal("tech-detect", (await JobsAsync(runId, "signatures")).Single().Signatures!.Items.Single().Id);

        var persisted = Host.Discovery.Persisted.Single(p => p.RunId == runId).Coverage;
        Assert.True(persisted.Complete);
        Assert.Contains("10.60.0.0/28", persisted.CoveredHosts);
        Assert.Contains("10.60.0.2:443", persisted.CoveredEndpoints);
        Assert.Contains(ScanOperation.ScanPorts, persisted.OperationsExecuted);
        Assert.Contains(runId, Host.Discovery.Compared);
        Assert.Contains(runId, Host.Findings.Published);
        await Host.WaitUntilAsync(() => Task.FromResult(Host.Messages.RunsFinished.Any(m => m.ScanRunId == runId && m.FinalStatus == "Completed")), "ScanRunFinished");

        Assert.Empty(await Host.DeadLettersAsync()); // every Wolverine handler (job finished, run finished) could run

        var events = await Host.DbAsync(db => db.Events.Where(e => e.ScanRunId == runId).Select(e => e.Type).ToListAsync());
        Assert.Contains(ScanExecutionEventType.RunStarted, events);
        Assert.Contains(ScanExecutionEventType.StepCompleted, events);
        Assert.Contains(ScanExecutionEventType.RunCompleted, events);
    }

    [Fact]
    public async Task Steps_whose_when_condition_matches_nothing_are_skipped()
    {
        var net = Host.Scope.Add(Zone, ["10.61.0.0/28"]);
        Host.Agents.Set(Agents.Simple(AgentId, Zone, "10.61.0.0/24", maxJobs: 10));

        var runId = await LaunchAsync(net);
        await RunAgentUntilFinishedAsync(runId, Lab(new() { [1] = [22] }));

        var steps = await StepsAsync(runId);
        Assert.Equal(StepStatus.Skipped, steps["http"].Status);
        Assert.Contains("when", steps["http"].Message);
        Assert.Equal(StepStatus.Skipped, steps["tls"].Status);
        Assert.Equal(StepStatus.Skipped, steps["signatures"].Status);
        Assert.Equal(StepStatus.Completed, steps["persist"].Status);
        Assert.Equal(ScanRunStatus.Completed, (await Host.RunAsync(runId)).Status);
    }

    [Theory]
    [InlineData(StepFailurePolicy.Continue, ScanRunStatus.PartiallyCompleted, StepStatus.Completed)]
    [InlineData(StepFailurePolicy.FailWorkflow, ScanRunStatus.Failed, StepStatus.Cancelled)]
    public async Task OnFailure_policy_decides_whether_the_workflow_continues(StepFailurePolicy policy, ScanRunStatus runStatus, StepStatus persistStatus)
    {
        var net = Host.Scope.Add(Zone, ["10.62.0.0/28"]);
        Host.Agents.Set(Agents.Simple(AgentId, Zone, "10.62.0.0/24", maxJobs: 10));
        var key = await CreateWorkflowAsync(
            new() { Id = "discover", Operation = ScanOperation.DiscoverHosts },
            new() { Id = "ports", Operation = ScanOperation.ScanPorts, DependsOn = ["discover"], Input = new StepInput { FromSteps = ["discover"] }, OnFailure = policy },
            new() { Id = "persist", Operation = ScanOperation.PersistObservations, DependsOn = ["ports"] });
        var runId = await LaunchAsync(net, key);

        await Host.WaitUntilAsync(async () =>
        {
            foreach (var a in (await Host.ClaimAsync(AgentId)).Assignments)
            {
                if (a.Job.Operation == ScanOperation.DiscoverHosts) { await Host.CompleteAsync(AgentId, a, Lab()(a.Job)); continue; }
                (await Host.AgentClient(AgentId).PostAsJsonAsync(AgentApiRoutes.JobFail(a.Job.JobId),
                    new JobFailureRequest { LeaseId = a.Lease.LeaseId, Reason = JobFailureReason.ToolError, Retryable = false }, ContractJson.Options)).EnsureSuccessStatusCode();
            }
            return (await Host.RunAsync(runId)).Status.IsTerminal();
        }, "run finished");

        var run = await Host.RunAsync(runId);
        Assert.Equal(runStatus, run.Status);
        Assert.False(run.CoverageComplete);
        var steps = await StepsAsync(runId);
        Assert.Equal(StepStatus.Failed, steps["ports"].Status);
        Assert.Equal(persistStatus, steps["persist"].Status);
    }

    [Fact]
    public async Task Failed_server_step_is_retried_per_retry_policy()
    {
        var net = Host.Scope.Add(Zone, ["10.64.0.0/28"]);
        Host.Agents.Set(Agents.Simple(AgentId, Zone, "10.64.0.0/24"));
        var key = await CreateWorkflowAsync(
            new() { Id = "discover", Operation = ScanOperation.DiscoverHosts },
            new() { Id = "persist", Operation = ScanOperation.PersistObservations, DependsOn = ["discover"], Retry = new RetryPolicy { MaxAttempts = 3, BackoffSeconds = 0 } });
        var failures = 0;
        Host.Discovery.OnPersist = (_, _) => Interlocked.Increment(ref failures) == 1 ? throw new InvalidOperationException("database hiccup") : Task.CompletedTask;
        try
        {
            var runId = await LaunchAsync(net, key);
            await RunAgentUntilFinishedAsync(runId, Lab());

            var persist = (await StepsAsync(runId))["persist"];
            Assert.Equal(StepStatus.Completed, persist.Status);
            Assert.Equal(2, persist.Attempt);
            Assert.Equal(ScanRunStatus.Completed, (await Host.RunAsync(runId)).Status);
        }
        finally { Host.Discovery.OnPersist = null; }
    }

    [Fact]
    public async Task Server_step_exceeding_its_timeout_fails_the_run()
    {
        var net = Host.Scope.Add(Zone, ["10.65.0.0/28"]);
        Host.Agents.Set(Agents.Simple(AgentId, Zone, "10.65.0.0/24"));
        var key = await CreateWorkflowAsync(
            new() { Id = "discover", Operation = ScanOperation.DiscoverHosts },
            new() { Id = "persist", Operation = ScanOperation.PersistObservations, DependsOn = ["discover"], TimeoutSeconds = 1, Retry = new RetryPolicy { MaxAttempts = 1 } });
        Host.Discovery.OnPersist = (_, ct) => Task.Delay(TimeSpan.FromSeconds(5), ct);
        try
        {
            var runId = await LaunchAsync(net, key);
            await RunAgentUntilFinishedAsync(runId, Lab());

            var persist = (await StepsAsync(runId))["persist"];
            Assert.Equal(StepStatus.Failed, persist.Status);
            Assert.Contains("Timed out", persist.Message);
            Assert.Equal(ScanRunStatus.Failed, (await Host.RunAsync(runId)).Status);
        }
        finally { Host.Discovery.OnPersist = null; }
    }

    [Fact]
    public async Task Cancelling_a_run_cancels_queued_jobs_and_signals_running_ones()
    {
        var net = Host.Scope.Add(Zone, ["10.66.0.0/23"]);
        Host.Agents.Set(Agents.Simple(AgentId, Zone, "10.66.0.0/16"));
        var runId = await LaunchAsync(net);
        var leased = (await Host.ClaimAsync(AgentId, 1)).Assignments.Single();

        var response = await Host.UserClient(WebScan.Server.Kernel.Security.Roles.Editor).PostAsync($"/api/scans/{runId}/cancel", null);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        Assert.Equal(ScanRunStatus.Cancelled, (await Host.RunAsync(runId)).Status);
        var jobs = await Host.DbAsync(db => db.Jobs.AsNoTracking().Where(j => j.ScanRunId == runId).ToListAsync());
        Assert.Contains(jobs, j => j.Status == JobStatus.Cancelled);
        Assert.True(jobs.Single(j => j.Id == leased.Job.JobId).CancelRequested);
        var heartbeat = await (await Host.AgentClient(AgentId).PostAsJsonAsync(AgentApiRoutes.JobHeartbeat(leased.Job.JobId),
            new JobHeartbeatRequest { LeaseId = leased.Lease.LeaseId }, ContractJson.Options)).Content.ReadFromJsonAsync<JobHeartbeatResponse>(ContractJson.Options);
        Assert.True(heartbeat!.CancelRequested);
        Assert.All((await StepsAsync(runId)).Values, s => Assert.Equal(StepStatus.Cancelled, s.Status));
        Assert.Equal(HttpStatusCode.Conflict, (await Host.UserClient().PostAsync($"/api/scans/{runId}/cancel", null)).StatusCode);
    }

    [Fact]
    public async Task Window_expiry_keeps_partial_results_and_persists_them_with_incomplete_coverage()
    {
        var net = Host.Scope.Add(Zone, ["10.67.0.0/28"]);
        Host.Agents.Set(Agents.Simple(AgentId, Zone, "10.67.0.0/24"));
        var key = await CreateWorkflowAsync(
            new() { Id = "discover", Operation = ScanOperation.DiscoverHosts },
            new() { Id = "ports", Operation = ScanOperation.ScanPorts, DependsOn = ["discover"], Input = new StepInput { FromSteps = ["discover"] } },
            new() { Id = "persist", Operation = ScanOperation.PersistObservations, DependsOn = ["ports"] },
            new() { Id = "compare", Operation = ScanOperation.ComparePreviousScan, DependsOn = ["persist"] });
        var runId = await LaunchAsync(net, key, Host.Time.GetUtcNow().AddMinutes(10));

        var discover = (await Host.ClaimAsync(AgentId)).Assignments.Single();
        await Host.CompleteAsync(AgentId, discover, Lab()(discover.Job));
        JobAssignment? ports = null;
        await Host.WaitUntilAsync(async () => (ports = (await Host.ClaimAsync(AgentId)).Assignments.SingleOrDefault()) is not null, "ports job");
        var client = Host.AgentClient(AgentId);
        (await client.PostAsJsonAsync(AgentApiRoutes.JobResults(ports!.Job.JobId), new ScanResultBatch
        {
            BatchId = Guid.NewGuid(), JobId = ports.Job.JobId, LeaseId = ports.Lease.LeaseId, Sequence = 0, CreatedAt = DateTimeOffset.UtcNow,
            Observations = [Observations.Make(ports.Job.JobId, ObservationKind.PortOpen, "10.67.0.1", 80)],
        }, ContractJson.Options)).EnsureSuccessStatusCode();

        Host.Time.Advance(TimeSpan.FromMinutes(11));
        await Host.TickAsync();
        Assert.Equal(ScanRunStatus.Running, (await Host.RunAsync(runId)).Status); // waits for the agent to flush and stop
        Assert.DoesNotContain(Host.Discovery.Persisted, p => p.RunId == runId);
        var heartbeat = await (await client.PostAsJsonAsync(AgentApiRoutes.JobHeartbeat(ports.Job.JobId), new JobHeartbeatRequest { LeaseId = ports.Lease.LeaseId }, ContractJson.Options))
            .Content.ReadFromJsonAsync<JobHeartbeatResponse>(ContractJson.Options);
        Assert.True(heartbeat!.CancelRequested);

        (await client.PostAsJsonAsync(AgentApiRoutes.JobFail(ports.Job.JobId), new JobFailureRequest
        {
            LeaseId = ports.Lease.LeaseId, Reason = JobFailureReason.WindowExpired, TotalBatches = 1,
            Coverage = new JobCoverage { Complete = false, UncoveredTargets = ["10.67.0.2"] },
        }, ContractJson.Options)).EnsureSuccessStatusCode();
        await Host.WaitUntilAsync(async () => (await Host.RunAsync(runId)).Status.IsTerminal(), "run finished");

        var run = await Host.RunAsync(runId);
        Assert.Equal(ScanRunStatus.WindowExpired, run.Status);
        Assert.False(run.CoverageComplete);
        var steps = await StepsAsync(runId);
        Assert.Equal(StepStatus.Cancelled, steps["ports"].Status);
        Assert.Equal(StepStatus.Completed, steps["persist"].Status);
        Assert.Equal(StepStatus.Cancelled, steps["compare"].Status);
        var coverage = Host.Discovery.Persisted.Single(p => p.RunId == runId).Coverage;
        Assert.False(coverage.Complete);
        Assert.DoesNotContain(ScanOperation.ScanPorts, coverage.OperationsExecuted); // uncovered ports are never "gone"
        Assert.Equal(1, await Host.DbAsync(db => db.ResultBatches.CountAsync(b => b.ScanRunId == runId && b.StepId == "ports"))); // partial results kept
    }

    [Fact]
    public async Task Launcher_is_idempotent_per_schedule_fire_and_validates_input()
    {
        var net = Host.Scope.Add(Zone, ["10.68.0.0/28"]);
        var scheduleId = Guid.NewGuid();
        var fire = new DateTimeOffset(2026, 11, 21, 2, 0, 0, TimeSpan.Zero).AddTicks(1234567);
        var request = new StartScanRequest
        {
            Name = "nightly", WorkflowKey = StandardWorkflows.StandardDiscoveryKey, NetworkIds = [net], TriggeredBy = $"schedule:{scheduleId}",
            ScheduleId = scheduleId, ScheduledFireTime = fire,
        };

        var ids = await Task.WhenAll(Enumerable.Range(0, 3).Select(_ => Host.WithScopeAsync(sp => sp.GetRequiredService<IScanLauncher>().StartAsync(request))));
        Assert.Single(ids.Distinct());
        Assert.Equal(1, await Host.DbAsync(db => db.ScanRuns.CountAsync(r => r.ScheduleId == scheduleId)));

        async Task<string> Rejected(StartScanRequest r) =>
            (await Assert.ThrowsAsync<ScanLaunchException>(() => Host.WithScopeAsync(sp => sp.GetRequiredService<IScanLauncher>().StartAsync(r)))).Message;
        Assert.Contains("Unknown or disabled networks", await Rejected(request with { ScheduleId = null, NetworkIds = [Guid.NewGuid()] }));
        Assert.Contains("not found", await Rejected(request with { ScheduleId = null, WorkflowKey = "nope" }));
        Assert.Contains("past", await Rejected(request with { ScheduleId = null, NotAfter = Host.Time.GetUtcNow().AddMinutes(-1) }));
    }
}
