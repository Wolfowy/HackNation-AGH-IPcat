using System.Text.Json.Nodes;
using WebScan.Contracts;
using WebScan.E2ETests.Infrastructure;

namespace WebScan.E2ETests.Scenarios;

/// <summary>Scenario 9: a later scan detects a deliberately introduced change.</summary>
[Collection(E2ECollection.Name)]
public sealed class ChangeDetectionTests(PostgresFixture postgres) : Scenario(postgres)
{
    [Fact]
    public async Task Second_scan_detects_new_port_and_service()
    {
        var agent = await StartAgentAsync("agent-c", "10.50.1.1/24", new Dictionary<string, string?> { ["Agent:FakeTools:AliveRatio"] = "1" });
        await WaitForAgentsOnlineAsync("agent-c");
        await ApproveToolAsync("fake");
        var net = await CreateNetworkAsync("change-lab", "lab-a", ["10.50.1.0/28"]);

        var first = await StartScanAsync("baseline", [net]);
        Assert.Equal("Completed", (await WaitForRunAsync(first, TimeSpan.FromMinutes(2), "Completed", "PartiallyCompleted", "Failed")).Str("status"));
        var baselineServices = await AllPagesAsync("/api/assets/services?search=10.50.1.5");
        Assert.DoesNotContain(baselineServices, s => s["port"]!.GetValue<int>() == 8081);

        // Deliberate change: a new HTTP service appears on 10.50.1.5:8081 (picked up by the fake tool on the next job).
        agent.UpdateConfiguration(new Dictionary<string, string?>
        {
            ["Agent:FakeTools:ExtraOpenPorts:10.50.1.5:0"] = "8081",
            ["Agent:FakeTools:ServiceOverrides:0:Address"] = "10.50.1.5",
            ["Agent:FakeTools:ServiceOverrides:0:Port"] = "8081",
            ["Agent:FakeTools:ServiceOverrides:0:Name"] = "http",
            ["Agent:FakeTools:ServiceOverrides:0:Product"] = "changed-app",
        });

        var second = await StartScanAsync("after-change", [net]);
        Assert.Equal("Completed", (await WaitForRunAsync(second, TimeSpan.FromMinutes(2), "Completed", "PartiallyCompleted", "Failed")).Str("status"));

        var changes = await AllPagesAsync($"/api/changes?scanRunId={second}");
        Assert.Contains(changes, c => c.Str("type") == "NewPort" && c.Str("address") == "10.50.1.5" && c["port"]!.GetValue<int>() == 8081);
        Assert.DoesNotContain(changes, c => c.Str("type") is "HostGone" or "PortGone"); // nothing disappeared
        var firstRunChanges = await AllPagesAsync($"/api/changes?scanRunId={first}");
        Assert.Contains(firstRunChanges, c => c.Str("type") == "NewHost");

        var diff = await Admin.GetAsync($"/api/scans/{second}/diff?baseline={first}");
        Assert.Contains(diff["added"]!.AsArray(), e => e!.Str("address") == "10.50.1.5" && e["port"]?.GetValue<int>() == 8081);
    }
}

/// <summary>Scenario 10: losing an agent mid-scan loses no work and produces no duplicate results.</summary>
[Collection(E2ECollection.Name)]
public sealed class AgentLossTests(PostgresFixture postgres) : Scenario(postgres)
{
    [Fact]
    public async Task Jobs_of_lost_agent_are_reassigned_without_duplicates()
    {
        var slow = new Dictionary<string, string?> { ["Agent:FakeTools:AliveRatio"] = "1", ["Agent:FakeTools:DelayPerTargetMs"] = "60", ["Agent:MaxConcurrentJobs"] = "2" };
        var doomed = await StartAgentAsync("agent-doomed", "10.50.2.10/24", slow);
        await StartAgentAsync("agent-survivor", "10.50.2.11/24", slow);
        await WaitForAgentsOnlineAsync("agent-doomed", "agent-survivor");
        await ApproveToolAsync("fake");
        await SetScanLimitsAsync(l => { l["defaultBatchSize"] = 64; l["leaseDurationSeconds"] = 30; });
        var net = await CreateNetworkAsync("loss-lab", "lab-a", ["10.50.2.0/24"]);

        var runId = await StartScanAsync("agent-loss", [net]);
        await ApiClient.EventuallyAsync(() => AllPagesAsync($"/api/scans/{runId}/jobs"),
            jobs => jobs.Any(j => j["agentId"]?.GetValue<string>() == "agent-doomed" && j.Str("status") == "Leased"),
            TimeSpan.FromSeconds(30), "doomed agent holding a lease");
        await doomed.KillAsync(); // abrupt: no graceful fail/complete, buffered results never sent

        var run = await WaitForRunAsync(runId, TimeSpan.FromMinutes(3), "Completed", "PartiallyCompleted", "Failed");
        Assert.Equal("Completed", run.Str("status"));

        var jobs = await AllPagesAsync($"/api/scans/{runId}/jobs");
        Assert.All(jobs, j => Assert.Equal("Completed", j.Str("status")));
        Assert.Contains(jobs, j => j["attempt"]!.GetValue<int>() > 1 && j.Str("agentId") == "agent-survivor"); // reassigned work

        // No duplicates: every address has exactly one host-discovery observation and one host row.
        var hostObs = await AllPagesAsync($"/api/observations?scanRunId={runId}&kind={ObservationKind.HostUp}");
        var addresses = hostObs.Select(o => o["observation"]!.Str("address")).ToList();
        Assert.Equal(addresses.Count, addresses.Distinct().Count());
        Assert.Equal(256, addresses.Count);
        var hosts = await AllPagesAsync("/api/assets/hosts");
        Assert.Equal(256, hosts.Count);
    }
}

/// <summary>Scenario 11: exceeding the scan window stops the scan, keeps partial data, marks nothing gone.</summary>
[Collection(E2ECollection.Name)]
public sealed class ScanWindowTests(PostgresFixture postgres) : Scenario(postgres)
{
    [Fact]
    public async Task Window_expiry_cancels_active_work_and_keeps_partial_observations()
    {
        await StartAgentAsync("agent-w", "10.50.3.1/24", new Dictionary<string, string?>
        {
            ["Agent:FakeTools:AliveRatio"] = "1", ["Agent:FakeTools:DelayPerTargetMs"] = "400", ["Agent:MaxConcurrentJobs"] = "1",
        });
        await WaitForAgentsOnlineAsync("agent-w");
        await ApproveToolAsync("fake");
        await SetScanLimitsAsync(l => l["defaultBatchSize"] = 64);
        var net = await CreateNetworkAsync("window-lab", "lab-a", ["10.50.3.0/24"]);

        // 4 batches × 64 targets × 400 ms sequentially ≈ 100 s of host discovery alone > 1 minute window.
        var runId = await StartScanAsync("windowed", [net], windowMinutes: 1);
        var run = await WaitForRunAsync(runId, TimeSpan.FromMinutes(3), "WindowExpired", "Completed", "Failed", "PartiallyCompleted");
        Assert.Equal("WindowExpired", run.Str("status"));
        Assert.False(run["coverageComplete"]!.GetValue<bool>());

        var jobs = await AllPagesAsync($"/api/scans/{runId}/jobs");
        Assert.Contains(jobs, j => j.Str("status") == "Cancelled");
        Assert.DoesNotContain(jobs, j => j.Str("status") is "Queued" or "Leased");

        var hosts = await AllPagesAsync("/api/assets/hosts");
        Assert.NotEmpty(hosts);                    // partial observations kept
        Assert.True(hosts.Count < 256);            // the window cut the scan short
        Assert.DoesNotContain(hosts, h => h.Str("status") == "Gone");
        var changes = await AllPagesAsync($"/api/changes?scanRunId={runId}");
        Assert.DoesNotContain(changes, c => c.Str("type") is "HostGone" or "PortGone");
    }
}
