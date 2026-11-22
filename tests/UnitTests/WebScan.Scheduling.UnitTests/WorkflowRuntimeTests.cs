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
    public async Task Built_in_workflow_updates_reach_existing_databases_unless_a_user_saved_a_newer_version()
    {
        var key = StandardWorkflows.StandardDiscoveryKey;
        Task<List<WorkflowDefinitionRecord>> Versions() => Host.WithScopeAsync(sp =>
            sp.GetRequiredService<WorkflowsDbContext>().Definitions.AsNoTracking().Where(d => d.Key == key).OrderBy(d => d.Version).ToListAsync());
        Task Seed() => Host.WithScopeAsync(sp => sp.GetRequiredService<WorkflowDefinitionStore>().EnsureSeededAsync());
        async Task Add(ScanWorkflowDefinition definition, string by) => await Host.WithScopeAsync(async sp =>
        {
            var db = sp.GetRequiredService<WorkflowsDbContext>();
            var version = await db.Definitions.Where(d => d.Key == key).MaxAsync(d => d.Version) + 1;
            db.Definitions.Add(new WorkflowDefinitionRecord
            {
                Key = key, Version = version, Name = definition.Name, CreatedAt = DateTimeOffset.UtcNow, CreatedBy = by,
                DefinitionJson = System.Text.Json.JsonSerializer.Serialize(WorkflowValidator.Normalize(definition) with { Version = version }, ContractJson.Options),
            });
            await db.SaveChangesAsync();
        });

        // An older built-in (here: without the last step) seeded by the system is upgraded to the current built-in once.
        var builtIn = StandardWorkflows.StandardDiscovery;
        await Add(builtIn with { Steps = builtIn.Steps.Take(builtIn.Steps.Count - 1).ToList() }, "system");
        var before = (await Versions()).Count;
        await Seed();
        await Seed();
        var versions = await Versions();
        Assert.Equal(before + 1, versions.Count);
        Assert.Equal(("system", builtIn.Steps.Count), (versions[^1].CreatedBy, System.Text.Json.JsonSerializer.Deserialize<ScanWorkflowDefinition>(versions[^1].DefinitionJson, ContractJson.Options)!.Steps.Count));

        // A user's own newer version is never replaced.
        await Add(builtIn, "alice");
        await Seed();
        Assert.Equal(("alice", before + 2), ((await Versions())[^1].CreatedBy, (await Versions()).Count));
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
        Assert.Equal([Zone], persisted.CoveredHostsByZone!.Keys); // zone-qualified copy for Discovery's miss counting
        Assert.Contains("10.60.0.0/28", persisted.CoveredHostsByZone[Zone]);
        Assert.Contains("10.60.0.2:443", persisted.CoveredEndpointsByZone![Zone]);
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
    public async Task Domain_targets_keep_their_hostname_from_discovery_to_http_probing()
    {
        const string name = "app.example.com", ip = "203.0.113.7"; // the name resolves outside the scope
        var net = Host.Scope.Add(Zone, [name]);
        Host.Agents.Set(Agents.Create(AgentId, [Zone], new() { ["eth0"] = ["10.69.0.5/24"] }, [Agents.Route("0.0.0.0/0", "eth0")], maxJobs: 10));

        IReadOnlyList<DiscoveryObservation> Lab(ScanJob job)
        {
            var id = job.JobId;
            var byName = job.Targets.Hosts.Contains(name);
            return job.Operation switch
            {
                ScanOperation.DiscoverHosts when byName => [Observations.Make(id, ObservationKind.HostUp, ip) with { Hostname = name }],
                ScanOperation.ScanPorts when byName => [Observations.Make(id, ObservationKind.PortOpen, ip, 443) with { Hostname = name }],
                ScanOperation.DetectService => [.. job.Targets.Endpoints.Select(e =>
                    Observations.Make(id, ObservationKind.Service, e.Address, e.Port, service: new ServiceDetails { Name = "https", Tunnel = "ssl" }) with { Hostname = e.Hostname })],
                ScanOperation.HttpProbe or ScanOperation.TlsProbe => [.. job.Targets.Endpoints.Select(e =>
                    Observations.Make(id, ObservationKind.HttpResponse, e.Address, e.Port, http: new HttpDetails { Url = $"https://{e.Hostname}:{e.Port}/", Scheme = "https" }) with { Hostname = e.Hostname })],
                _ => [],
            };
        }

        var runId = await LaunchAsync(net);
        await RunAgentUntilFinishedAsync(runId, Lab);

        Assert.Equal([name], (await JobsAsync(runId, "ports")).SelectMany(j => j.Targets.Hosts));
        foreach (var step in new[] { "services", "http", "tls" })
        {
            var endpoint = Assert.Single((await JobsAsync(runId, step)).SelectMany(j => j.Targets.Endpoints));
            Assert.Equal((name, ip, 443), (endpoint.Hostname, endpoint.Address, endpoint.Port));
        }
        Assert.Equal("https", (await JobsAsync(runId, "http")).Single().Targets.Endpoints.Single().Scheme);
        Assert.DoesNotContain((await StepsAsync(runId)).Values, s => s.Message?.Contains("out-of-scope") == true);
    }

    [Fact]
    public async Task Scope_policy_ports_clip_port_parameters_and_endpoints()
    {
        var net = Host.Scope.Add(Zone, ["10.70.0.0/28"]);
        Host.Agents.Set(Agents.Simple(AgentId, Zone, "10.70.0.0/24", maxJobs: 10));
        Host.Scope.AllowedPorts.AddRange(["80", "443", "8000-8100"]);
        Host.Scope.ExcludedPorts.Add("8080");
        try
        {
            var runId = await LaunchAsync(net);
            await RunAgentUntilFinishedAsync(runId, Lab()); // the synthetic lab still reports ssh:22: it must not reach later steps

            const string allowed = "80,443,8000-8079,8081-8100";
            var sweep = (await JobsAsync(runId, "sweep")).First();
            Assert.True(PortSet.TryParse(StandardWorkflows.SweepPorts, out var sweepPorts));
            Assert.True(PortSet.TryParse(allowed, out var allowedPorts));
            Assert.Equal((allowed, sweepPorts.Intersect(allowedPorts).ToString()), (sweep.AuthorizedPorts, sweep.Parameters["ports"])); // sweep list clipped
            var ports = (await JobsAsync(runId, "ports")).First();
            Assert.Equal(allowed, ports.AuthorizedPorts);
            Assert.Equal("80,443,8000-8002,8007-8011,8021-8022,8031,8042,8045,8081-8090,8093,8099-8100", ports.Parameters["ports"]); // nmap top-1000 ∩ allowed
            Assert.Equal(["10.70.0.1:80", "10.70.0.2:443"],
                (await JobsAsync(runId, "services")).SelectMany(j => j.Targets.Endpoints).Select(e => $"{e.Address}:{e.Port}").Order());
        }
        finally
        {
            Host.Scope.AllowedPorts.Clear();
            Host.Scope.ExcludedPorts.Clear();
        }
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
    public async Task RecheckMissing_reprobes_only_missing_targets_in_scope_round_by_round_before_persist()
    {
        var net = Host.Scope.Add(Zone, ["10.61.0.0/28"]);
        Host.Agents.Set(Agents.Simple(AgentId, Zone, "10.61.0.0/24", maxJobs: 10));
        var key = await CreateWorkflowAsync(
            new() { Id = "discover", Operation = ScanOperation.DiscoverHosts },
            new()
            {
                Id = "recheck", Operation = ScanOperation.RecheckMissing, DependsOn = ["discover"],
                Parameters = new Dictionary<string, string> { ["attempts"] = "3", ["delaySeconds"] = "0" },
            },
            new() { Id = "persist", Operation = ScanOperation.PersistObservations, DependsOn = ["recheck"] });
        var runId = await LaunchAsync(net, key);
        static ScanEndpoint E(string address, int port) => new() { Address = address, Port = port };
        Host.Recheck.Targets = (run, round) => run != runId ? RecheckTargets.None : round switch
        {
            1 => new(["10.61.0.5", "10.99.0.1"], [E("10.61.0.1", 8080), E("10.61.0.1", 22), E("10.61.0.2", 8080)], 1),
            2 => new(["10.61.0.5"], [], 1), // still silent after round 1
            _ => RecheckTargets.None, // answered in round 2: round 3 queues nothing
        };

        await RunAgentUntilFinishedAsync(runId, Lab());

        Assert.Equal(ScanRunStatus.Completed, (await Host.RunAsync(runId)).Status);
        var steps = await StepsAsync(runId);
        Assert.Equal(StepStatus.Completed, steps["recheck"].Status);
        Assert.StartsWith("Round 3/3", steps["recheck"].Message);
        Assert.Equal(3, Host.Recheck.Calls[runId]);
        var jobs = await JobsAsync(runId, "recheck");
        Assert.Equal(2, jobs.Count(j => j.Operation == ScanOperation.DiscoverHosts && j.Targets.Hosts.SequenceEqual(["10.61.0.5"]))); // same target, both rounds
        var portScans = jobs.Where(j => j.Operation == ScanOperation.ScanPorts).ToDictionary(j => j.Parameters["ports"], j => j.Targets.Hosts.Single());
        Assert.Equal(new Dictionary<string, string> { ["22,8080"] = "10.61.0.1", ["8080"] = "10.61.0.2" }, portScans); // only each host's own ports
        Assert.DoesNotContain(jobs, j => j.Targets.Hosts.Contains("10.99.0.1")); // outside the authorized scope
        Assert.Contains(Host.Discovery.Persisted, p => p.RunId == runId);
        Assert.True(steps["persist"].StartedAt >= steps["recheck"].FinishedAt);
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
