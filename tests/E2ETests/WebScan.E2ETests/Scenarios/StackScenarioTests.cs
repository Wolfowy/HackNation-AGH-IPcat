using System.Diagnostics;
using System.Text.Json.Nodes;
using WebScan.Contracts;
using WebScan.E2ETests.Infrastructure;

namespace WebScan.E2ETests.Scenarios;

/// <summary>Runs only against the real Docker Compose stack + TestLab (see docs/RUNNING.md, "Stack E2E").</summary>
public sealed class StackFactAttribute : FactAttribute
{
    public StackFactAttribute()
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WEBSCAN_STACK_URL")))
            Skip = "Set WEBSCAN_STACK_URL (+ WEBSCAN_STACK_ADMIN_USER/PASSWORD) to run against the docker compose stack.";
    }
}

/// <summary>
/// Real tools (nmap, naabu, httpx, nuclei) in two agent containers scanning the TestLab network 172.30.0.0/24:
/// scenario 6 with real scanners, scenario 9 with a real infrastructure change, scenario 14 (custom safe signature).
/// </summary>
public sealed class StackScenarioTests
{
    private const string SignatureId = "webscan-testlab-admin-panel";
    private const string WorkflowKey = "testlab-discovery";

    [StackFact]
    public async Task Real_tools_custom_signature_and_real_change_against_testlab()
    {
        var http = new HttpClient { BaseAddress = new Uri(Environment.GetEnvironmentVariable("WEBSCAN_STACK_URL")!) };
        var api = new ApiClient(http);
        await api.LoginAsync(Environment.GetEnvironmentVariable("WEBSCAN_STACK_ADMIN_USER") ?? "admin",
            Environment.GetEnvironmentVariable("WEBSCAN_STACK_ADMIN_PASSWORD") ?? throw new InvalidOperationException("WEBSCAN_STACK_ADMIN_PASSWORD missing"));
        StopChangeService(); // known starting state

        // Both containerized agents enrolled with the bootstrap token and report the real tools.
        var agents = await ApiClient.EventuallyAsync(() => api.GetAsync("/api/agents"),
            l => l.Items().Count(a => a["isOnline"]!.GetValue<bool>() && a.Str("status") == "Active") >= 2,
            TimeSpan.FromMinutes(2), "two containerized agents online");
        foreach (var agent in agents.Items())
        {
            var toolIds = agent["tools"]!.AsArray().Select(t => t!.Str("id")).ToList();
            Assert.Superset(new HashSet<string> { "nmap", "naabu", "httpx", "nuclei" }, toolIds.ToHashSet());
        }

        // Network for the lab (excluding gateway and the agents themselves).
        var networks = await api.GetAsync("/api/networks");
        var lab = networks.Items().FirstOrDefault(n => n.Str("name") == "testlab")?.Str("id")
                  ?? (await api.PostAsync("/api/networks", new
                  {
                      name = "testlab", zone = "lab", ranges = new[] { "172.30.0.0/24" },
                      exclusions = new[] { "172.30.0.1", "172.30.0.100", "172.30.0.101" }, tags = new[] { "testlab" }, enabled = true,
                  }))!.Str("id");

        // Scenario 14: custom safe signature (info severity) — validated, versioned, approved.
        var template = await File.ReadAllTextAsync(Path.Combine(InProcessAgent.RepoRoot(), "tests", "TestLab", "signatures", $"{SignatureId}.yaml"));
        var validation = await api.PostAsync("/api/signatures/validate", new { kind = "NucleiTemplate", content = template });
        Assert.True(validation!["valid"]!.GetValue<bool>());
        if ((await api.StatusOfAsync(HttpMethod.Get, $"/api/signatures/{SignatureId}")) == System.Net.HttpStatusCode.NotFound)
        {
            await api.PostAsync("/api/signatures", new { id = SignatureId, name = "WebScan TestLab Admin Panel", kind = "NucleiTemplate", content = template });
            await api.PostAsync($"/api/signatures/{SignatureId}/versions/1/approve", new { });
        }

        // Workflow version with the lab's ports (the banner service listens on 2323, outside nmap's top lists).
        if ((await api.StatusOfAsync(HttpMethod.Get, $"/api/workflows/{WorkflowKey}")) == System.Net.HttpStatusCode.NotFound)
        {
            var standard = (await api.GetAsync("/api/workflows/standard-discovery"))["definition"]!.AsObject();
            standard["key"] = WorkflowKey;
            standard["name"] = "TestLab discovery";
            foreach (var step in standard["steps"]!.AsArray())
                if (step!.Str("operation") == nameof(ScanOperation.ScanPorts))
                    step["parameters"]!["ports"] = "22,80,443,2323,8080,8081,8443";
            await api.PostAsync("/api/workflows", standard);
        }

        // Scenario 6 with real scanners.
        var baseline = await RunScanAsync(api, lab, "stack-baseline");
        var hosts = await AllAsync(api, "/api/assets/hosts");
        foreach (var ip in new[] { "172.30.0.10", "172.30.0.11", "172.30.0.12", "172.30.0.13", "172.30.0.14" })
            Assert.Contains(hosts, h => h.Str("address") == ip);
        var services = await AllAsync(api, "/api/assets/services");
        Assert.Contains(services, s => s.Str("address") == "172.30.0.10" && s["port"]!.GetValue<int>() == 80 && s["http"] is not null);
        Assert.Contains(services, s => s.Str("address") == "172.30.0.14" && s["port"]!.GetValue<int>() == 2323);
        Assert.Contains(services, s => s.Str("address") == "172.30.0.12" && s["port"]!.GetValue<int>() == 8443 && s["tls"] is not null);

        // Scenario 14: the custom signature detected the prepared admin panel.
        var findings = await AllAsync(api, "/api/findings");
        Assert.Contains(findings, f => f.Str("signatureId") == SignatureId && f.Str("address") == "172.30.0.13");
        Assert.DoesNotContain(findings, f => f.Str("signatureId") == SignatureId && f.Str("address") != "172.30.0.13");

        // Scenario 9 with a real change: a new service appears in the lab.
        StartChangeService();
        try
        {
            var after = await RunScanAsync(api, lab, "stack-after-change");
            var changes = await AllAsync(api, $"/api/changes?scanRunId={after}");
            Assert.Contains(changes, c => c.Str("address") == "172.30.0.15" && c.Str("type") is "NewHost" or "HostReappeared");
            Assert.Contains(changes, c => c.Str("address") == "172.30.0.15" && c.Str("type") == "NewPort" && c["port"]!.GetValue<int>() == 8081);
            var diff = await api.GetAsync($"/api/scans/{after}/diff?baseline={baseline}");
            Assert.Contains(diff["added"]!.AsArray(), e => e!.Str("address") == "172.30.0.15");
        }
        finally
        {
            StopChangeService();
        }
    }

    private static async Task<Guid> RunScanAsync(ApiClient api, string networkId, string name)
    {
        var run = await api.PostAsync("/api/scans", new { name, workflowKey = WorkflowKey, networkIds = new[] { networkId } });
        var id = Guid.Parse(run!.Str("id"));
        var done = await ApiClient.EventuallyAsync(() => api.GetAsync($"/api/scans/{id}"),
            r => r.Str("status") is "Completed" or "PartiallyCompleted" or "Failed" or "Cancelled" or "WindowExpired",
            TimeSpan.FromMinutes(20), $"stack scan {name}");
        Assert.Equal("Completed", done.Str("status"));
        return id;
    }

    private static async Task<List<JsonNode>> AllAsync(ApiClient api, string url)
    {
        var sep = url.Contains('?') ? '&' : '?';
        return (await api.GetAsync($"{url}{sep}pageSize=500")).Items().ToList();
    }

    private static void StartChangeService() => Compose("--profile", "change", "up", "-d", "change");
    private static void StopChangeService() => Compose("--profile", "change", "rm", "-sf", "change");

    private static void Compose(params string[] args)
    {
        var root = InProcessAgent.RepoRoot();
        var psi = new ProcessStartInfo("docker") { WorkingDirectory = root, RedirectStandardError = true, RedirectStandardOutput = true };
        foreach (var a in new[] { "compose", "-p", Environment.GetEnvironmentVariable("WEBSCAN_STACK_PROJECT") ?? "webscan",
                     "--env-file", "deploy/docker/.env", "-f", "deploy/docker/docker-compose.yml", "-f", "tests/TestLab/docker-compose.yml" }.Concat(args))
            psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        p.WaitForExit(120_000);
        if (p.ExitCode != 0) throw new InvalidOperationException($"docker compose failed: {p.StandardError.ReadToEnd()}");
    }
}
