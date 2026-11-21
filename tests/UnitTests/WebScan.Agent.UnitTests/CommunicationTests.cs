using System.Net;
using WebScan.Agent.Communication;
using WebScan.Agent.Storage;
using WebScan.Contracts;

namespace WebScan.Agent.UnitTests;

/// <summary>The whole agent (hosted worker, real HttpClient pipeline, SQLite buffer, fake tool) against an in-memory server.</summary>
public class CommunicationTests
{
    private static ScanJob PortScanJob(int hosts = 64) =>
        Jobs.Hosts(ScanOperation.ScanPorts, ToolCapabilities.PortScan, [$"10.20.0.0/{32 - (int)Math.Log2(hosts)}"], ["10.20.0.0/16"],
            new Dictionary<string, string> { ["ports"] = "top-100" }, toolId: "fake");

    [Fact]
    public async Task Enrolls_with_token_persists_credentials_and_runs_a_job_to_completion()
    {
        var server = new FakeAgentServer();
        var job = PortScanJob(256);
        server.PendingAssignments.Enqueue(Jobs.Assign(job));
        await using var agent = new AgentHarness(server, new() { ["Agent:ResultBatchMaxObservations"] = "50" });

        await agent.Host.StartAsync();
        await Eventually.TrueAsync(() => server.Read(s => s.Completions.Count) == 1, "job completed");

        var (registration, token, auth) = server.Read(s => s.Registrations[0]);
        Assert.Equal("enroll-123", token);
        Assert.Null(auth);
        Assert.Equal("agent-test-01", registration.AgentId);
        Assert.Contains(registration.Tools, t => t.Id == "fake" && t.Capabilities.Contains(ToolCapabilities.PortScan));
        Assert.Equal("lab0", registration.Interfaces.Single().Name);
        Assert.Equal("10.20.0.0/16", registration.Routes.Single().Destination);
        Assert.Equal(server.CurrentSecret, agent.Get<CredentialStore>().Current!.Secret);

        var (jobId, completion) = server.Read(s => s.Completions[0]);
        var batches = server.Read(s => s.Batches.Where(b => b.JobId == jobId).OrderBy(b => b.Sequence).ToList());
        Assert.Equal(job.JobId, jobId);
        Assert.True(completion.Coverage.Complete);
        Assert.Equal(batches.Count, completion.TotalBatches);
        Assert.True(batches.Count > 1, "observations split into batches");
        Assert.All(batches, b => Assert.InRange(b.Observations.Count, 1, 50));
        Assert.Equal(Enumerable.Range(0, batches.Count), batches.Select(b => b.Sequence));
        Assert.All(batches.SelectMany(b => b.Observations), o => Assert.Equal((ObservationKind.PortOpen, "fake", job.JobId), (o.Kind, o.Source.ToolId, o.Source.JobId)));
        Assert.Equal(("fake", 0), (completion.ToolRun.ToolId, completion.ToolRun.ExitCode!.Value));

        await Eventually.TrueAsync(() => server.Read(s => s.Heartbeats.Count) > 0, "agent heartbeat");
        Assert.Empty(server.Read(s => s.UnauthorizedRequests));
        Assert.Equal(0, agent.Get<ResultBuffer>().PendingBatchCount());
    }

    [Fact]
    public async Task Re_registers_and_rotates_credentials_when_the_server_asks()
    {
        var server = new FakeAgentServer();
        await using var agent = new AgentHarness(server);
        await agent.Host.StartAsync();
        await Eventually.TrueAsync(() => server.Read(s => s.Heartbeats.Count) >= 1, "first heartbeat");
        var enrolledSecret = server.CurrentSecret;

        server.RequestReRegistration = true;
        await Eventually.TrueAsync(() => server.Read(s => s.Registrations.Count) >= 2, "re-registration");
        Assert.Equal($"Agent agent-test-01:{enrolledSecret}", server.Read(s => s.Registrations[1].Authorization));
        Assert.Null(server.Read(s => s.Registrations[1].EnrollmentToken));

        server.RequestRotation = true;
        await Eventually.TrueAsync(() => server.Read(s => s.Rotations.Count) == 1, "rotation");
        var rotated = server.Read(s => s.Rotations[0]);
        await Eventually.TrueAsync(() => agent.Get<CredentialStore>().Current!.Secret == rotated, "rotated secret persisted");
        Assert.Equal(rotated, new CredentialStore(Microsoft.Extensions.Options.Options.Create(new AgentOptions { DataDirectory = Path.Combine(agent.Dir.Path, "data") })).Current!.Secret);
    }

    [Fact]
    public async Task Rejected_credentials_trigger_re_enrollment_with_the_token()
    {
        var server = new FakeAgentServer();
        await using var agent = new AgentHarness(server);
        agent.Get<CredentialStore>().Save(new AgentCredentials("agent-test-01", "revoked-secret")); // unknown to the server → 401

        await agent.Host.StartAsync();
        await Eventually.TrueAsync(() => server.Read(s => s.Registrations.Any(r => r.EnrollmentToken == "enroll-123")), "re-enrollment");
        await Eventually.TrueAsync(() => agent.Get<CredentialStore>().Current!.Secret == server.CurrentSecret, "new secret stored");
    }

    [Fact]
    public async Task Stale_lease_drops_buffered_batches_and_never_completes()
    {
        var server = new FakeAgentServer();
        var job = PortScanJob();
        server.PendingAssignments.Enqueue(Jobs.Assign(job));
        server.Fault = r => r.RequestUri!.AbsolutePath == AgentApiRoutes.JobResults(job.JobId) ? FakeAgentServer.StatusCode(HttpStatusCode.Conflict) : null;
        await using var agent = new AgentHarness(server);

        await agent.Host.StartAsync();
        await Eventually.TrueAsync(() => server.Read(s => s.Heartbeats.Count) >= 2 && agent.Get<Execution.JobExecutor>().ActiveJobIds.Count == 0, "job finished");

        var buffer = agent.Get<ResultBuffer>();
        Assert.False(buffer.HasJob(job.JobId));
        Assert.Equal(0, buffer.PendingBatchCount());
        Assert.Empty(server.Read(s => s.Completions));
        Assert.Empty(server.Read(s => s.Batches));
    }

    [Fact]
    public async Task Results_are_retried_until_the_server_comes_back()
    {
        var server = new FakeAgentServer();
        var job = PortScanJob();
        server.PendingAssignments.Enqueue(Jobs.Assign(job));
        var outage = true;
        var failedAttempts = 0;
        server.Fault = r =>
        {
            if (!outage || !r.RequestUri!.AbsolutePath.StartsWith("/api/agents/jobs/" + job.JobId, StringComparison.Ordinal)) return null;
            Interlocked.Increment(ref failedAttempts);
            return FakeAgentServer.StatusCode(HttpStatusCode.ServiceUnavailable);
        };
        await using var agent = new AgentHarness(server);

        await agent.Host.StartAsync();
        await Eventually.TrueAsync(() => Volatile.Read(ref failedAttempts) >= 4, "upload attempts during outage");
        Assert.True(agent.Get<ResultBuffer>().PendingBatchCount() > 0, "results kept in the local buffer");
        Assert.Empty(server.Read(s => s.Completions));

        outage = false;
        await Eventually.TrueAsync(() => server.Read(s => s.Completions.Count) == 1, "completion after recovery");
        var completion = server.Read(s => s.Completions[0].Request);
        Assert.Equal(server.Read(s => s.Batches.Count), completion.TotalBatches);
        Assert.Equal(0, agent.Get<ResultBuffer>().PendingBatchCount());
    }

    [Fact]
    public async Task Server_cancellation_and_shutdown_report_failures_with_coverage()
    {
        var server = new FakeAgentServer();
        var cancelled = PortScanJob(16);
        var interrupted = PortScanJob(16) with { JobId = Guid.NewGuid() };
        server.PendingAssignments.Enqueue(Jobs.Assign(cancelled));
        server.PendingAssignments.Enqueue(Jobs.Assign(interrupted));
        server.CancelRequestedJobs.Add(cancelled.JobId);
        await using var agent = new AgentHarness(server, new() { ["Agent:FakeTools:DelayPerTargetMs"] = "1000" });

        await agent.Host.StartAsync();
        await Eventually.TrueAsync(() => server.Read(s => s.Failures.Any(f => f.JobId == cancelled.JobId)), "cancelled job reported");
        var cancel = server.Read(s => s.Failures.Single(f => f.JobId == cancelled.JobId).Request);
        Assert.Equal((JobFailureReason.Cancelled, false), (cancel.Reason, cancel.Retryable));
        Assert.False(cancel.Coverage!.Complete);
        Assert.NotEmpty(cancel.Coverage.UncoveredTargets);

        await agent.Host.StopAsync();
        var shutdown = server.Read(s => s.Failures.Single(f => f.JobId == interrupted.JobId).Request);
        Assert.Equal((JobFailureReason.AgentShutdown, true), (shutdown.Reason, shutdown.Retryable));
    }

    [Fact]
    public async Task Job_timeout_is_reported_as_timeout_with_uncovered_targets()
    {
        var server = new FakeAgentServer();
        var job = PortScanJob(16) with { Limits = new JobLimits { RatePerSecond = 100, TimeoutSeconds = 1 } };
        server.PendingAssignments.Enqueue(Jobs.Assign(job));
        await using var agent = new AgentHarness(server, new() { ["Agent:FakeTools:DelayPerTargetMs"] = "300" });

        await agent.Host.StartAsync();
        await Eventually.TrueAsync(() => server.Read(s => s.Failures.Count) == 1, "timeout reported");

        var failure = server.Read(s => s.Failures[0].Request);
        Assert.Equal((JobFailureReason.Timeout, true), (failure.Reason, failure.Retryable));
        Assert.InRange(failure.Coverage!.UncoveredTargets.Count, 8, 16);
    }

    [Fact]
    public async Task Invalid_job_is_failed_without_running_and_not_retryable()
    {
        var server = new FakeAgentServer();
        var job = Jobs.Hosts(ScanOperation.ScanPorts, ToolCapabilities.PortScan, ["8.8.8.8"], ["10.20.0.0/16"]);
        server.PendingAssignments.Enqueue(Jobs.Assign(job));
        await using var agent = new AgentHarness(server);

        await agent.Host.StartAsync();
        await Eventually.TrueAsync(() => server.Read(s => s.Failures.Count) == 1, "invalid job reported");

        var failure = server.Read(s => s.Failures[0].Request);
        Assert.Equal((JobFailureReason.InvalidJob, false, 0), (failure.Reason, failure.Retryable, failure.TotalBatches));
        Assert.Empty(server.Read(s => s.Batches));
    }
}
