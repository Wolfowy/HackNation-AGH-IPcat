using System.Net;
using System.Text.Json.Nodes;
using WebScan.E2ETests.Infrastructure;

namespace WebScan.E2ETests.Scenarios;

/// <summary>Scenario 12: RBAC limits access according to roles.</summary>
[Collection(E2ECollection.Name)]
public sealed class RbacTests(PostgresFixture postgres) : Scenario(postgres)
{
    private const string Password = "Role-Password-123";

    [Fact]
    public async Task Roles_are_enforced_on_every_layer()
    {
        var net = await CreateNetworkAsync("rbac-lab", "lab-a", ["10.50.4.0/28"]);
        foreach (var role in new[] { "Viewer", "Editor", "Manager" })
            await Admin.PostAsync("/api/users", new { userName = role.ToLowerInvariant(), displayName = role, password = Password, roles = new[] { role }, isActive = true });

        var anonymous = new ApiClient(Server.CreateClient());
        Assert.Equal(HttpStatusCode.Unauthorized, await anonymous.StatusOfAsync(HttpMethod.Get, "/api/networks"));

        var viewer = await LoginAsync("viewer");
        var editor = await LoginAsync("editor");
        var manager = await LoginAsync("manager");
        var newNetwork = new { name = "x", zone = "lab-a", ranges = new[] { "10.50.4.32/28" }, exclusions = Array.Empty<string>(), tags = Array.Empty<string>(), enabled = true };
        var update = new { name = "rbac-lab", zone = "lab-a", ranges = new[] { "10.50.4.0/28" }, exclusions = new[] { "10.50.4.1" }, tags = Array.Empty<string>(), enabled = true };
        var scan = new { name = "s", workflowKey = "standard-discovery", networkIds = new[] { net } };

        // Viewer: read only.
        Assert.Equal(HttpStatusCode.OK, await viewer.StatusOfAsync(HttpMethod.Get, "/api/networks"));
        Assert.Equal(HttpStatusCode.OK, await viewer.StatusOfAsync(HttpMethod.Get, "/api/assets/hosts"));
        Assert.Equal(HttpStatusCode.Forbidden, await viewer.StatusOfAsync(HttpMethod.Post, "/api/networks", newNetwork));
        Assert.Equal(HttpStatusCode.Forbidden, await viewer.StatusOfAsync(HttpMethod.Put, $"/api/networks/{net}", update));
        Assert.Equal(HttpStatusCode.Forbidden, await viewer.StatusOfAsync(HttpMethod.Post, "/api/scans", scan));
        Assert.Equal(HttpStatusCode.Forbidden, await viewer.StatusOfAsync(HttpMethod.Get, "/api/users"));
        Assert.Equal(HttpStatusCode.Forbidden, await viewer.StatusOfAsync(HttpMethod.Get, "/api/audit"));
        Assert.Equal(HttpStatusCode.Forbidden, await viewer.StatusOfAsync(HttpMethod.Put, $"/api/findings/{Guid.NewGuid()}", new { triage = "FalsePositive" }));
        Assert.Equal(HttpStatusCode.Forbidden, await viewer.StatusOfAsync(HttpMethod.Put, $"/api/scans/{Guid.NewGuid()}", new { name = "x" }));

        // Editor: modify existing + run scans, but no create/delete.
        Assert.Equal(HttpStatusCode.OK, await editor.StatusOfAsync(HttpMethod.Put, $"/api/networks/{net}", update));
        Assert.Equal(HttpStatusCode.Forbidden, await editor.StatusOfAsync(HttpMethod.Post, "/api/networks", newNetwork));
        Assert.Equal(HttpStatusCode.Forbidden, await editor.StatusOfAsync(HttpMethod.Delete, $"/api/networks/{net}"));
        Assert.True((int)await editor.StatusOfAsync(HttpMethod.Post, "/api/scans", scan) is >= 200 and < 300);

        // Manager: create/delete, but no administration.
        Assert.True((int)await manager.StatusOfAsync(HttpMethod.Post, "/api/networks", newNetwork) is >= 200 and < 300);
        Assert.Equal(HttpStatusCode.Forbidden, await manager.StatusOfAsync(HttpMethod.Get, "/api/users"));
        Assert.Equal(HttpStatusCode.Forbidden, await manager.StatusOfAsync(HttpMethod.Put, "/api/scope-policy", new { allowed = new[] { "0.0.0.0/0" }, excluded = Array.Empty<string>() }));
        Assert.Equal(HttpStatusCode.Forbidden, await manager.StatusOfAsync(HttpMethod.Put, "/api/tools/fake", new { approved = true, enabled = true }));

        // Administrator: everything, and every mutation above is audited.
        var audit = await Admin.GetAsync("/api/audit?pageSize=200");
        Assert.Contains(audit.Items(), a => a.Str("action").StartsWith("network.", StringComparison.Ordinal) && a["userName"]?.GetValue<string>() == "editor");
    }

    private async Task<ApiClient> LoginAsync(string user)
    {
        var client = new ApiClient(Server.CreateClient());
        await client.LoginAsync(user, Password);
        return client;
    }
}

/// <summary>Scenario 13: JSON/CSV import and export.</summary>
[Collection(E2ECollection.Name)]
public sealed class ImportExportTests(PostgresFixture postgres) : Scenario(postgres)
{
    [Fact]
    public async Task Networks_and_assets_round_trip_through_json_and_csv()
    {
        await CreateNetworkAsync("io-a", "lab-a", ["10.50.5.0/29"], ["10.50.5.7"]);
        await CreateNetworkAsync("io-b", "lab-b", ["10.60.5.0/29"]);

        var json = await Admin.GetStringAsync("/api/networks/export?format=json");
        var csv = await Admin.GetStringAsync("/api/networks/export?format=csv");
        Assert.Contains("io-a", json);
        Assert.Contains("10.50.5.7", csv);

        foreach (var n in (await Admin.GetAsync("/api/networks")).Items()) await Admin.DeleteAsync($"/api/networks/{n.Str("id")}");
        var fromCsv = await Admin.PostRawAsync("/api/networks/import?format=csv", csv, "text/csv");
        Assert.Equal(2, fromCsv!["created"]!.GetValue<int>());
        var restored = (await Admin.GetAsync("/api/networks")).Items().ToList();
        Assert.Contains(restored, n => n.Str("name") == "io-a" && n["exclusions"]!.AsArray().Any(e => e!.GetValue<string>() == "10.50.5.7"));

        var fromJson = await Admin.PostRawAsync("/api/networks/import?format=json", json, "application/json");
        Assert.Equal(2, fromJson!["updated"]!.GetValue<int>());

        // Assets: scan to get hosts, export them, import annotations, check they are applied without touching evidence.
        await StartAgentAsync("agent-io", "10.50.5.1/24", new Dictionary<string, string?> { ["Agent:FakeTools:AliveRatio"] = "1" });
        await WaitForAgentsOnlineAsync("agent-io");
        await ApproveToolAsync("fake");
        var netA = restored.Single(n => n.Str("name") == "io-a").Str("id");
        var runId = await StartScanAsync("io-scan", [Guid.Parse(netA)]);
        await WaitForRunAsync(runId, TimeSpan.FromMinutes(2), "Completed");

        var hostsCsv = await Admin.GetStringAsync("/api/export/hosts?format=csv");
        Assert.Contains("10.50.5.3", hostsCsv);
        Assert.DoesNotContain("10.50.5.7", hostsCsv);
        var hostsJson = JsonNode.Parse(await Admin.GetStringAsync("/api/export/hosts?format=json"))!;
        Assert.Equal(7, hostsJson.AsArray().Count);

        var annotations = "address,description,classification,businessState,owner,tags\n10.50.5.3,Payroll server,server,production,finance,pci;critical\n";
        var imported = await Admin.PostRawAsync("/api/import/assets?format=csv", annotations, "text/csv");
        Assert.True(imported!["imported"]!.GetValue<int>() + imported["updated"]!.GetValue<int>() >= 1);
        var host = (await Admin.GetAsync("/api/assets/hosts?search=10.50.5.3")).Items().Single(h => h.Str("address") == "10.50.5.3");
        Assert.Equal("Payroll server", host["annotation"]!.Str("description"));
        Assert.Equal("Active", host.Str("status"));
    }
    [Fact]
    public async Task Scan_results_and_findings_import_through_the_scan_pipeline()
    {
        // First import (merge): one host, SSH + a web panel, and a finding from another tool.
        const string first = "address,port,transport,serviceName,product,version,httpTitle,httpStatusCode,signatureId,name,severity,evidence\n" +
                             "10.70.1.5,22,Tcp,ssh,OpenSSH,8.9,,,,,,\n" +
                             "10.70.1.5,80,Tcp,http,nginx,1.24,Admin login,200,ext-admin-panel,Exposed admin panel,medium,title=Admin login\n";
        var created = await Admin.PostRawAsync("/api/scans/import?format=csv&zone=imp&name=external-scan-1", first, "text/csv");
        var run1 = created!.Str("scanRunId");
        Assert.Empty(created["errors"]!.AsArray());
        var run = await Admin.GetAsync($"/api/scans/{run1}");
        Assert.Equal(("Completed", "import"), (run.Str("status"), run.Str("workflowKey")));

        var services = (await Admin.GetAsync("/api/assets/services?search=10.70.1.5")).Items().ToList();
        Assert.Equal(2, services.Count);
        Assert.Contains((await Admin.GetAsync("/api/findings")).Items(), f => f.Str("signatureId") == "ext-admin-panel" && f.Str("address") == "10.70.1.5");
        Assert.Contains((await Admin.GetAsync($"/api/changes?scanRunId={run1}")).Items(), c => c.Str("type") == "NewHost");

        // Second import (JSON snapshot): SSH upgraded, HTTPS added → change events like a second scan.
        const string second = """
            [{ "address": "10.70.1.5", "zone": "imp", "port": 22, "serviceName": "ssh", "product": "OpenSSH", "version": "9.6" },
             { "address": "10.70.1.5", "zone": "imp", "port": 443, "serviceName": "https", "product": "nginx", "tlsFingerprintSha256": "ab12" }]
            """;
        var run2 = (await Admin.PostRawAsync("/api/scans/import?format=json&zone=imp&snapshot=true", second, "application/json"))!.Str("scanRunId");
        var changes = (await Admin.GetAsync($"/api/changes?scanRunId={run2}")).Items().ToList();
        Assert.Contains(changes, c => c.Str("type") == "NewPort" && c["port"]!.GetValue<int>() == 443);
        Assert.Contains(changes, c => c.Str("type") == "ServiceChanged" && c["port"]!.GetValue<int>() == 22);

        // Raw nmap XML goes through the agent's own parser.
        const string nmap = """
            <?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.70.1.9" addrtype="ipv4"/>
            <ports><port protocol="tcp" portid="8080"><state state="open"/><service name="http" product="Jetty" version="9.4" method="probed" conf="10"/></port></ports></host></nmaprun>
            """;
        await Admin.PostRawAsync("/api/scans/import?format=nmap-xml&zone=imp", nmap, "application/xml");
        Assert.Contains((await Admin.GetAsync("/api/assets/services?search=10.70.1.9")).Items(), s => s["port"]!.GetValue<int>() == 8080 && s.Str("product") == "Jetty");

        // Importing results adds data: Editors may not, invalid input is rejected without creating a run.
        await Admin.PostAsync("/api/users", new { userName = "import-editor", displayName = "Editor", password = "Role-Password-123", roles = new[] { "Editor" }, isActive = true });
        var editor = new ApiClient(Server.CreateClient());
        await editor.LoginAsync("import-editor", "Role-Password-123");
        Assert.Equal(HttpStatusCode.Forbidden, await editor.StatusOfAsync(HttpMethod.Post, "/api/scans/import?format=csv&zone=imp"));
        Assert.Equal(HttpStatusCode.UnprocessableEntity, await Admin.StatusOfAsync(HttpMethod.Post, "/api/scans/import?format=exe&zone=imp"));

        // Editors triage imported findings; importing the same finding again keeps the triage.
        var findingId = (await Admin.GetAsync("/api/findings")).Items().First(f => f.Str("signatureId") == "ext-admin-panel").Str("id");
        Assert.Equal(HttpStatusCode.OK,
            await editor.StatusOfAsync(HttpMethod.Put, $"/api/findings/{findingId}", new { triage = "FalsePositive", severityOverride = "low", notes = "WAF test page" }));
        await Admin.PostRawAsync("/api/scans/import?format=csv&zone=imp", first, "text/csv");
        var triaged = (await Admin.GetAsync("/api/findings?triage=FalsePositive")).Items().Single(f => f.Str("id") == findingId);
        Assert.Equal(("medium", "low", "WAF test page"), (triaged.Str("severity"), triaged.Str("effectiveSeverity"), triaged.Str("notes")));
    }
}
