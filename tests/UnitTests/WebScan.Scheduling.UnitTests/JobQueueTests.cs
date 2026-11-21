using System.Net;
using System.Net.Http.Json;
using System.Text;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WebScan.Contracts;
using WebScan.Scheduling.UnitTests.Support;
using WebScan.Server.Kernel.Messaging;
using WebScan.Server.Modules.Scanning.Jobs;
using WebScan.Server.Modules.Scanning.Persistence;
using Wolverine;

namespace WebScan.Scheduling.UnitTests;

[Collection(DbCollection.Name)]
public sealed class JobQueueTests(TestHost host) : DbTestBase(host)
{
    [Fact]
    public async Task Parallel_claimers_never_receive_the_same_job()
    {
        var net = Host.Scope.Add(Zone, ["10.40.0.0/20"]);
        var (_, plan) = await QueueJobsAsync(net);
        Assert.Equal(16, plan.JobsCreated);
        var agents = Enumerable.Range(0, 4).Select(i => $"claimer-{Zone}-{i}").ToList();
        foreach (var a in agents) Host.Agents.Set(Agents.Simple(a, Zone, "10.40.0.0/16", maxJobs: 16));

        var claims = await Task.WhenAll(agents.SelectMany(a => Enumerable.Range(0, 3).Select(_ => Host.ClaimAsync(a, 2))));

        var jobIds = claims.SelectMany(c => c.Assignments).Select(a => a.Job.JobId).ToList();
        Assert.Equal(jobIds.Count, jobIds.Distinct().Count());
        Assert.Equal(16, jobIds.Count);
        var leased = await Host.DbAsync(db => db.Jobs.CountAsync(j => j.Status == JobStatus.Leased && j.TargetSummary.StartsWith("10.40.")));
        Assert.Equal(16, leased);
    }

    [Fact]
    public async Task Planning_the_same_step_twice_does_not_duplicate_jobs()
    {
        var net = Host.Scope.Add(Zone, ["10.41.0.0/22"]);
        var (runId, first) = await QueueJobsAsync(net);
        var second = await Host.WithScopeAsync(sp => sp.GetRequiredService<WebScan.Server.Modules.Scanning.Planning.TaskPlanner>().PlanAsync(
            new() { ScanRunId = runId, StepId = "step", Operation = ScanOperation.DiscoverHosts, NetworkIds = [net] }));
        Assert.Equal(4, first.JobsCreated);
        Assert.Equal(0, second.JobsCreated);
        Assert.Equal(4, second.JobsExisting);
        Assert.Equal(4, await Host.DbAsync(db => db.Jobs.CountAsync(j => j.ScanRunId == runId)));
    }

    [Fact]
    public async Task Expired_lease_is_requeued_for_another_agent_and_the_stale_lease_gets_409()
    {
        var net = Host.Scope.Add(Zone, ["10.42.0.0/24"]);
        await QueueJobsAsync(net);
        Host.Agents.Set(Agents.Simple("lost-" + Zone, Zone, "10.42.0.0/16"));
        Host.Agents.Set(Agents.Simple("other-" + Zone, Zone, "10.42.0.0/16"));
        var first = (await Host.ClaimAsync("lost-" + Zone)).Assignments.Single();

        Host.Time.Advance(TimeSpan.FromSeconds(121));
        var released = await Host.WithScopeAsync(sp => sp.GetRequiredService<LeaseSweeper>().SweepOnceAsync());
        Assert.True(released >= 1);
        var requeued = await Host.DbAsync(db => db.Jobs.AsNoTracking().FirstAsync(j => j.Id == first.Job.JobId));
        Assert.Equal(JobStatus.Queued, requeued.Status);
        Assert.Equal(1, requeued.Attempt);
        Assert.Equal("lost-" + Zone, requeued.LastAgentId);

        var second = (await Host.ClaimAsync("other-" + Zone)).Assignments.Single();
        Assert.Equal(first.Job.JobId, second.Job.JobId);
        Assert.Equal(2, second.Lease.Attempt);

        var lost = Host.AgentClient("lost-" + Zone);
        var heartbeat = await lost.PostAsJsonAsync(AgentApiRoutes.JobHeartbeat(first.Job.JobId), new JobHeartbeatRequest { LeaseId = first.Lease.LeaseId }, ContractJson.Options);
        Assert.Equal(HttpStatusCode.Conflict, heartbeat.StatusCode);
        var complete = await lost.PostAsJsonAsync(AgentApiRoutes.JobComplete(first.Job.JobId), new JobCompletionRequest
        {
            LeaseId = first.Lease.LeaseId, TotalBatches = 0, Coverage = new JobCoverage { Complete = true }, ToolRun = new ToolRunInfo { ToolId = "nmap", DurationMs = 1 },
        }, ContractJson.Options);
        Assert.Equal(HttpStatusCode.Conflict, complete.StatusCode);
    }

    [Fact]
    public async Task Lease_expiry_after_the_last_attempt_fails_the_job()
    {
        var net = Host.Scope.Add(Zone, ["10.43.0.0/24"]);
        await QueueJobsAsync(net, maxAttempts: 1);
        Host.Agents.Set(Agents.Simple("a-" + Zone, Zone, "10.43.0.0/16"));
        var a = (await Host.ClaimAsync("a-" + Zone)).Assignments.Single();
        Host.Time.Advance(TimeSpan.FromSeconds(200));
        await Host.WithScopeAsync(sp => sp.GetRequiredService<LeaseSweeper>().SweepOnceAsync());
        var job = await Host.DbAsync(db => db.Jobs.AsNoTracking().FirstAsync(j => j.Id == a.Job.JobId));
        Assert.Equal(JobStatus.Failed, job.Status);
    }

    [Fact]
    public async Task Heartbeat_extends_the_lease_and_reports_cancellation()
    {
        var net = Host.Scope.Add(Zone, ["10.44.0.0/24"]);
        await QueueJobsAsync(net);
        Host.Agents.Set(Agents.Simple("hb-" + Zone, Zone, "10.44.0.0/16"));
        var a = (await Host.ClaimAsync("hb-" + Zone)).Assignments.Single();
        var client = Host.AgentClient("hb-" + Zone);

        Host.Time.Advance(TimeSpan.FromSeconds(60));
        var response = await client.PostAsJsonAsync(AgentApiRoutes.JobHeartbeat(a.Job.JobId),
            new JobHeartbeatRequest { LeaseId = a.Lease.LeaseId, Progress = new JobProgress { Percent = 40 } }, ContractJson.Options);
        var body = await response.Content.ReadFromJsonAsync<JobHeartbeatResponse>(ContractJson.Options);
        Assert.True(body!.LeaseExpiresAt > a.Lease.ExpiresAt);
        Assert.False(body.CancelRequested);

        Assert.Equal(HttpStatusCode.OK, (await Host.UserClient().PostAsync($"/api/jobs/{a.Job.JobId}/cancel", null)).StatusCode);
        body = await (await client.PostAsJsonAsync(AgentApiRoutes.JobHeartbeat(a.Job.JobId), new JobHeartbeatRequest { LeaseId = a.Lease.LeaseId }, ContractJson.Options))
            .Content.ReadFromJsonAsync<JobHeartbeatResponse>(ContractJson.Options);
        Assert.True(body!.CancelRequested);

        var fail = await client.PostAsJsonAsync(AgentApiRoutes.JobFail(a.Job.JobId), new JobFailureRequest { LeaseId = a.Lease.LeaseId, Reason = JobFailureReason.Cancelled }, ContractJson.Options);
        Assert.Equal(HttpStatusCode.OK, fail.StatusCode);
        Assert.Equal(JobStatus.Cancelled, await Host.DbAsync(db => db.Jobs.Where(j => j.Id == a.Job.JobId).Select(j => j.Status).FirstAsync()));
    }

    [Fact]
    public async Task Unknown_job_is_404_and_malformed_payload_is_422()
    {
        var client = Host.AgentClient("someone");
        var unknown = await client.PostAsJsonAsync(AgentApiRoutes.JobHeartbeat(Guid.NewGuid()), new JobHeartbeatRequest { LeaseId = Guid.NewGuid() }, ContractJson.Options);
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        var malformed = await client.PostAsync(AgentApiRoutes.JobHeartbeat(Guid.NewGuid()), new StringContent("{\"progress\":{}}", Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.UnprocessableEntity, malformed.StatusCode);
        var anonymous = await Host.App.GetTestClient().PostAsJsonAsync(AgentApiRoutes.Claim, new JobClaimRequest { MaxJobs = 1 }, ContractJson.Options);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
    }

    [Fact]
    public async Task Same_batch_twice_is_stored_and_published_once()
    {
        var net = Host.Scope.Add(Zone, ["10.45.0.0/24"]);
        await QueueJobsAsync(net);
        Host.Agents.Set(Agents.Simple("dup-" + Zone, Zone, "10.45.0.0/16"));
        var a = (await Host.ClaimAsync("dup-" + Zone)).Assignments.Single();
        var client = Host.AgentClient("dup-" + Zone);
        var batch = new ScanResultBatch
        {
            BatchId = Guid.NewGuid(), JobId = a.Job.JobId, LeaseId = a.Lease.LeaseId, Sequence = 0, CreatedAt = DateTimeOffset.UtcNow,
            Observations = [Observations.Make(a.Job.JobId, ObservationKind.HostUp, "10.45.0.7")],
        };

        var first = await (await client.PostAsJsonAsync(AgentApiRoutes.JobResults(a.Job.JobId), batch, ContractJson.Options)).Content.ReadFromJsonAsync<ResultBatchAck>(ContractJson.Options);
        var second = await (await client.PostAsJsonAsync(AgentApiRoutes.JobResults(a.Job.JobId), batch, ContractJson.Options)).Content.ReadFromJsonAsync<ResultBatchAck>(ContractJson.Options);

        Assert.False(first!.Duplicate);
        Assert.True(second!.Duplicate);
        Assert.Equal(1, second.ObservationsAccepted);
        Assert.Equal(1, await Host.DbAsync(db => db.ResultBatches.CountAsync(b => b.BatchId == batch.BatchId)));
        await Host.WaitUntilAsync(() => Task.FromResult(Host.Messages.Batches.Any(m => m.Batch.BatchId == batch.BatchId)), "outbox delivery");
        await Task.Delay(300);
        var delivered = Host.Messages.Batches.Single(m => m.Batch.BatchId == batch.BatchId);
        Assert.Equal(Zone, delivered.Context.Zone);
        Assert.Equal(ScanOperation.DiscoverHosts, delivered.Context.Operation);
    }

    [Fact]
    public async Task Results_outside_the_job_targets_are_dropped_and_secrets_masked()
    {
        var net = Host.Scope.Add(Zone, ["10.46.0.0/24"]);
        await QueueJobsAsync(net);
        Host.Agents.Set(Agents.Simple("mask-" + Zone, Zone, "10.46.0.0/16"));
        var a = (await Host.ClaimAsync("mask-" + Zone)).Assignments.Single();
        var http = new HttpDetails
        {
            Url = "http://10.46.0.9/?token=abc123", Scheme = "http",
            Headers = new Dictionary<string, string> { ["Set-Cookie"] = "sid=secret; Path=/", ["Server"] = "nginx" },
        };
        var batch = new ScanResultBatch
        {
            BatchId = Guid.NewGuid(), JobId = a.Job.JobId, LeaseId = a.Lease.LeaseId, Sequence = 0, CreatedAt = DateTimeOffset.UtcNow,
            Observations =
            [
                Observations.Make(a.Job.JobId, ObservationKind.HttpResponse, "10.46.0.9", 80, http: http),
                Observations.Make(a.Job.JobId, ObservationKind.HostUp, "192.168.1.1"),
            ],
        };
        var ack = await (await Host.AgentClient("mask-" + Zone).PostAsJsonAsync(AgentApiRoutes.JobResults(a.Job.JobId), batch, ContractJson.Options))
            .Content.ReadFromJsonAsync<ResultBatchAck>(ContractJson.Options);

        Assert.Equal(1, ack!.ObservationsAccepted);
        var stored = await Host.DbAsync(db => db.ResultBatches.Where(b => b.BatchId == batch.BatchId).Select(b => b.PayloadJson).FirstAsync());
        Assert.DoesNotContain("secret", stored);
        Assert.DoesNotContain("abc123", stored);
        Assert.DoesNotContain("192.168.1.1", stored);
        Assert.Contains("sid=***", stored);
    }

    [Fact]
    public async Task Oversized_batch_is_rejected_with_422()
    {
        var net = Host.Scope.Add(Zone, ["10.47.0.0/24"]);
        await QueueJobsAsync(net);
        Host.Agents.Set(Agents.Simple("big-" + Zone, Zone, "10.47.0.0/16"));
        var a = (await Host.ClaimAsync("big-" + Zone)).Assignments.Single();
        var observations = Enumerable.Range(0, ScanResultBatch.MaxObservations + 1).Select(i => Observations.Make(a.Job.JobId, ObservationKind.HostUp, "10.47.0.1", i % 65535 + 1)).ToList();
        var response = await Host.AgentClient("big-" + Zone).PostAsJsonAsync(AgentApiRoutes.JobResults(a.Job.JobId), new ScanResultBatch
        {
            BatchId = Guid.NewGuid(), JobId = a.Job.JobId, LeaseId = a.Lease.LeaseId, Sequence = 0, CreatedAt = DateTimeOffset.UtcNow, Observations = observations,
        }, ContractJson.Options);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
    }

    [Fact]
    public async Task Complete_with_missing_batches_is_409_until_they_arrive()
    {
        var net = Host.Scope.Add(Zone, ["10.48.0.0/24"]);
        await QueueJobsAsync(net);
        Host.Agents.Set(Agents.Simple("miss-" + Zone, Zone, "10.48.0.0/16"));
        var a = (await Host.ClaimAsync("miss-" + Zone)).Assignments.Single();
        var client = Host.AgentClient("miss-" + Zone);
        var completion = new JobCompletionRequest
        {
            LeaseId = a.Lease.LeaseId, TotalBatches = 2, Coverage = new JobCoverage { Complete = true }, ToolRun = new ToolRunInfo { ToolId = "nmap", DurationMs = 2000 },
        };
        async Task SendBatch(int sequence) => (await client.PostAsJsonAsync(AgentApiRoutes.JobResults(a.Job.JobId), new ScanResultBatch
        {
            BatchId = Guid.NewGuid(), JobId = a.Job.JobId, LeaseId = a.Lease.LeaseId, Sequence = sequence, CreatedAt = DateTimeOffset.UtcNow,
            Observations = [Observations.Make(a.Job.JobId, ObservationKind.HostUp, $"10.48.0.{sequence + 1}")],
        }, ContractJson.Options)).EnsureSuccessStatusCode();

        await SendBatch(0);
        Assert.Equal(HttpStatusCode.Conflict, (await client.PostAsJsonAsync(AgentApiRoutes.JobComplete(a.Job.JobId), completion, ContractJson.Options)).StatusCode);
        await SendBatch(1);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync(AgentApiRoutes.JobComplete(a.Job.JobId), completion, ContractJson.Options)).StatusCode);

        var job = await Host.DbAsync(db => db.Jobs.AsNoTracking().FirstAsync(j => j.Id == a.Job.JobId));
        Assert.Equal(JobStatus.Completed, job.Status);
        var perf = await Host.DbAsync(db => db.Performance.AsNoTracking().FirstAsync(p => p.AgentId == "miss-" + Zone));
        Assert.Equal(1, perf.JobsCompleted);
        Assert.Equal(128, perf.AvgTargetsPerSecond, 3); // 256 targets in 2 s
    }

    [Fact]
    public async Task Retryable_failure_requeues_with_backoff_and_non_retryable_fails()
    {
        var net = Host.Scope.Add(Zone, ["10.49.0.0/23"]);
        await QueueJobsAsync(net, backoffSeconds: 30);
        Host.Agents.Set(Agents.Simple("f-" + Zone, Zone, "10.49.0.0/16"));
        var claim = (await Host.ClaimAsync("f-" + Zone)).Assignments;
        var client = Host.AgentClient("f-" + Zone);

        await client.PostAsJsonAsync(AgentApiRoutes.JobFail(claim[0].Job.JobId), new JobFailureRequest { LeaseId = claim[0].Lease.LeaseId, Reason = JobFailureReason.ToolError, Message = "exit 1 password=hunter2" }, ContractJson.Options);
        await client.PostAsJsonAsync(AgentApiRoutes.JobFail(claim[1].Job.JobId), new JobFailureRequest { LeaseId = claim[1].Lease.LeaseId, Reason = JobFailureReason.InvalidJob, Retryable = false }, ContractJson.Options);

        var retried = await Host.DbAsync(db => db.Jobs.AsNoTracking().FirstAsync(j => j.Id == claim[0].Job.JobId));
        Assert.Equal(JobStatus.Queued, retried.Status);
        Assert.Equal(Host.Time.GetUtcNow().AddSeconds(30), retried.NextAttemptAt!.Value, TimeSpan.FromSeconds(1));
        Assert.DoesNotContain("hunter2", retried.Error);
        Assert.Equal(JobStatus.Failed, await Host.DbAsync(db => db.Jobs.Where(j => j.Id == claim[1].Job.JobId).Select(j => j.Status).FirstAsync()));

        Assert.Empty((await Host.ClaimAsync("f-" + Zone)).Assignments); // still backing off
        Host.Time.Advance(TimeSpan.FromSeconds(31));
        Assert.Equal(claim[0].Job.JobId, (await Host.ClaimAsync("f-" + Zone)).Assignments.Single().Job.JobId);
    }

    [Fact]
    public async Task Agent_went_offline_releases_its_leases_through_wolverine()
    {
        var net = Host.Scope.Add(Zone, ["10.50.0.0/23"]);
        await QueueJobsAsync(net);
        Host.Agents.Set(Agents.Simple("gone-" + Zone, Zone, "10.50.0.0/16"));
        var claimed = (await Host.ClaimAsync("gone-" + Zone)).Assignments.Select(a => a.Job.JobId).ToList();
        Assert.Equal(2, claimed.Count);

        await Host.WithScopeAsync(sp => sp.GetRequiredService<IMessageBus>().PublishAsync(new AgentWentOffline("gone-" + Zone, DateTimeOffset.UtcNow)).AsTask());

        await Host.WaitUntilAsync(async () => await Host.DbAsync(db => db.Jobs.CountAsync(j => claimed.Contains(j.Id) && j.Status == JobStatus.Queued)) == 2, "leases released");
    }
}
