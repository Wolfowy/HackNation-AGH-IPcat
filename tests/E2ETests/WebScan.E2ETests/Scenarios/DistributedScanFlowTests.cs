using System.Collections.Concurrent;
using System.Net;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using WebScan.Contracts;
using WebScan.E2ETests.Infrastructure;
using WebScan.Server.Kernel.Networking;

namespace WebScan.E2ETests.Scenarios;

/// <summary>
/// Acceptance scenarios 1–8: migrations, agent registration, scope, planning into non-overlapping batches,
/// routing to the right agents, execution, normalization/persistence, live progress.
/// </summary>
[Collection(E2ECollection.Name)]
public sealed class DistributedScanFlowTests(PostgresFixture postgres) : Scenario(postgres)
{
    [Fact]
    public async Task Two_agents_scan_two_networks_end_to_end()
    {
        // 1. Server starts and applies the migrations of every module.
        var ready = await Server.CreateClient().GetAsync("/health/ready");
        Assert.Equal(HttpStatusCode.OK, ready.StatusCode);
        await using (var db = new NpgsqlConnection(ConnectionString()))
        {
            await db.OpenAsync();
            await using var cmd = new NpgsqlCommand("select table_schema from information_schema.tables where table_name = '__EFMigrationsHistory'", db);
            var schemas = new HashSet<string>();
            await using (var reader = await cmd.ExecuteReaderAsync())
                while (await reader.ReadAsync()) schemas.Add(reader.GetString(0));
            Assert.Superset(new HashSet<string> { "infra", "identity", "agents", "networks", "scanning", "scheduling", "workflows", "signatures", "discovery", "integrations" }, schemas);
        }

        // 2. Two agents connect (enrollment token), register capabilities; the admin approves the reported tool.
        await StartAgentAsync("agent-a", "10.50.0.100/24");
        await StartAgentAsync("agent-b", "10.60.0.100/24");
        var agents = await WaitForAgentsOnlineAsync("agent-a", "agent-b");
        foreach (var agent in agents.Items())
        {
            var fake = agent["tools"]!.AsArray().Single(t => t!.Str("id") == "fake")!;
            Assert.Contains(ToolCapabilities.PortScan, fake["capabilities"]!.AsArray().Select(c => c!.GetValue<string>()));
            Assert.Contains(agent["interfaces"]!.AsArray(), i => i!.Str("name") == "lab0");
        }
        var tools = await Admin.GetAsync("/api/tools");
        Assert.False(tools.Items().Single(t => t.Str("toolId") == "fake")["approved"]!.GetValue<bool>()); // unknown tools start unapproved
        await ApproveToolAsync("fake");

        // 3. Administrator adds the ranges (inside the seeded scope policy), with an exclusion.
        var netA = await CreateNetworkAsync("lab-a", "lab-a", ["10.50.0.0/24"], ["10.50.0.250"]);
        var netB = await CreateNetworkAsync("lab-b", "lab-b", ["10.60.0.0/24"]);
        var outside = await Admin.StatusOfAsync(HttpMethod.Post, "/api/networks",
            new { name = "evil", zone = "lab-a", ranges = new[] { "8.8.8.0/24" }, exclusions = Array.Empty<string>(), tags = Array.Empty<string>(), enabled = true });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, outside); // outside the authorized scope policy

        await SetScanLimitsAsync(l => l["defaultBatchSize"] = 64);

        var events = new ConcurrentQueue<ScanExecutionEvent>();
        await using var hub = await ConnectHubAsync(events.Enqueue);

        // 4. The planner splits the scope into non-overlapping batches.
        var runId = await StartScanAsync("e2e-full", [netA, netB]);
        await hub.InvokeAsync(ScanHub.JoinRunMethod, runId); // job-level events are sent to the run group
        var run = await WaitForRunAsync(runId, TimeSpan.FromMinutes(3), "Completed", "PartiallyCompleted", "Failed");
        Assert.Equal("Completed", run.Str("status"));
        Assert.True(run["coverageComplete"]!.GetValue<bool>());

        var jobs = await AllPagesAsync($"/api/scans/{runId}/jobs");
        var discovery = jobs.Where(j => j.Str("operation") == nameof(ScanOperation.DiscoverHosts)).ToList();
        Assert.Equal(8, discovery.Count); // 2 × /24 in batches of 64
        var details = new List<JsonNode>();
        foreach (var job in discovery) details.Add(await Admin.GetAsync($"/api/jobs/{job.Str("id")}"));

        var batches = details.Select(d => IpRangeSet.Parse(d["payload"]!["targets"]!["hosts"]!.AsArray().Select(h => h!.GetValue<string>()))).ToList();
        UInt128 total = 0;
        foreach (var b in batches) total += b.Count;
        var union = batches.Aggregate(new IpRangeSet(), (acc, b) => acc.Union(b));
        Assert.Equal(union.Count, total); // no overlap
        var expected = IpRangeSet.Parse(["10.50.0.0/24", "10.60.0.0/24"]).Subtract(IpRangeSet.Parse(["10.50.0.250"]));
        Assert.True(union.IsSupersetOf(expected) && expected.IsSupersetOf(union)); // exact coverage, exclusion honoured

        // 5. Jobs went to the agent that can actually reach the network (interface subnet).
        foreach (var d in details)
        {
            var job = d["job"]!;
            var firstHost = d["payload"]!["targets"]!["hosts"]![0]!.GetValue<string>();
            var expectedAgent = firstHost.StartsWith("10.50.") ? "agent-a" : "agent-b";
            Assert.Equal(expectedAgent, job.Str("agentId"));
            Assert.Equal("Completed", job.Str("status"));
            Assert.Equal("fake", job.Str("toolId"));
        }

        // 6 + 7. Agents executed every workflow step and the server normalized and persisted observations.
        Assert.All(run["steps"]!.AsArray(), s => Assert.Contains(s!.Str("status"), new[] { "Completed", "Skipped" }));
        Assert.Contains(run["steps"]!.AsArray(), s => s!.Str("operation") == nameof(ScanOperation.HttpProbe) && s.Str("status") == "Completed");
        var observations = await Admin.GetAsync($"/api/observations?scanRunId={runId}&pageSize=1");
        Assert.True(observations["total"]!.GetValue<int>() > 0);

        var hosts = await AllPagesAsync("/api/assets/hosts");
        Assert.NotEmpty(hosts);
        Assert.Equal(hosts.Count, hosts.Select(h => h.Str("address")).Distinct().Count()); // one current-state row per address
        Assert.DoesNotContain(hosts, h => h.Str("address") == "10.50.0.250");
        Assert.All(hosts, h => Assert.True(expected.Contains(IPAddress.Parse(h.Str("address")))));
        Assert.Contains(hosts, h => h.Str("address").StartsWith("10.50.") && h.Str("status") == "Active");
        Assert.Contains(hosts, h => h.Str("address").StartsWith("10.60.") && h.Str("status") == "Active");
        var services = await Admin.GetAsync("/api/assets/services?pageSize=1");
        Assert.True(services["total"]!.GetValue<int>() > 0);

        // 8. Progress is exposed through the API and pushed live through SignalR.
        Assert.Equal(100, run["progress"]!["percent"]!.GetValue<double>());
        var summary = await Admin.GetAsync("/api/dashboard/summary");
        Assert.Equal(hosts.Count, summary["hostsTotal"]!.GetValue<int>());
        await ApiClient.EventuallyAsync(() => Task.FromResult(events.Select(e => $"{e.Type}:{e.ScanRunId}").ToList()),
            e => e.Contains($"{ScanExecutionEventType.RunCompleted}:{runId}") && e.Contains($"{ScanExecutionEventType.JobCompleted}:{runId}"),
            TimeSpan.FromSeconds(10), "live run events over SignalR");
    }

    private string ConnectionString() =>
        Server.Services.GetRequiredService<IConfiguration>().GetConnectionString("WebScan")!;
}
