using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WebScan.Contracts;
using WebScan.Discovery.UnitTests.Infrastructure;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Analytics;
using WebScan.Server.Modules.Discovery.Api;
using WebScan.Server.Modules.Discovery.Domain;

namespace WebScan.Discovery.UnitTests;

[Collection(DbCollection.Name)]
public class ApiTests(TestApp app) : IAsyncLifetime
{
    private static readonly JsonSerializerOptions Json = ContractJson.Options;
    private readonly Scenario _s = new(app);

    public Task InitializeAsync() => app.ResetAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<Guid> SeedHostAsync(string address = "10.4.0.1")
    {
        await _s.RunAsync(Scenario.Coverage(["10.4.0.0/24"]), 3, _s.HostUp(address), _s.Port(address, 443),
            _s.Signature(address, 443, "exposed-panel", "medium", "=cmd|' /C calc'!A0"));
        return await _s.QueryAsync(db => db.Hosts.Where(h => h.Address == address).Select(h => h.Id).SingleAsync());
    }

    [Theory]
    [InlineData("GET", "/api/assets/hosts", null, HttpStatusCode.Unauthorized)]
    [InlineData("GET", "/api/assets/hosts", Roles.Viewer, HttpStatusCode.OK)]
    [InlineData("GET", "/api/dashboard/summary", Roles.Viewer, HttpStatusCode.OK)]
    [InlineData("POST", "/api/import/assets?format=json", Roles.Editor, HttpStatusCode.Forbidden)]
    [InlineData("POST", "/api/signatures", Roles.Editor, HttpStatusCode.Forbidden)]
    [InlineData("GET", "/api/integrations/defectdojo", Roles.Manager, HttpStatusCode.Forbidden)]
    [InlineData("GET", "/api/integrations/defectdojo", Roles.Administrator, HttpStatusCode.OK)]
    public async Task Endpoints_enforce_roles(string method, string url, string? role, HttpStatusCode expected)
    {
        var request = new HttpRequestMessage(new HttpMethod(method), url) { Content = method == "POST" ? JsonContent.Create(new { }) : null };
        Assert.Equal(expected, (await app.Client(role).SendAsync(request)).StatusCode);
    }

    [Fact]
    public async Task Annotation_requires_editor_is_audited_and_never_touches_evidence()
    {
        var id = await SeedHostAsync();
        var body = new { description = "Payment gateway", classification = "critical", businessState = "production", owner = "team-pay", tags = new[] { "pci", "dmz" } };

        Assert.Equal(HttpStatusCode.Forbidden, (await app.Client(Roles.Viewer).PutAsJsonAsync($"/api/assets/hosts/{id}/annotation", body, Json)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await app.Client(Roles.Editor).PutAsJsonAsync($"/api/assets/hosts/{id}/annotation", body, Json)).StatusCode);
        await app.Client(Roles.Editor).PutAsJsonAsync($"/api/assets/hosts/{id}/annotation", body with { owner = "team-core" }, Json);

        var detail = await app.Client(Roles.Viewer).GetFromJsonAsync<HostDetailDto>($"/api/assets/hosts/{id}", Json);
        Assert.Equal(("team-core", "critical"), (detail!.Annotation!.Owner, detail.Annotation.Classification));
        Assert.Equal(["pci", "dmz"], detail.Annotation.Tags);
        Assert.Single(detail.Services);
        Assert.Single(detail.Findings);
        Assert.Equal(2, await _s.QueryAsync(db => db.AnnotationRevisions.CountAsync()));
        Assert.Equal(["asset.annotation_created", "asset.annotation_updated"], app.Audit.Entries.Select(e => e.Action));
        Assert.Equal(HttpStatusCode.NotFound, (await app.Client(Roles.Editor).PutAsJsonAsync($"/api/assets/hosts/{Guid.NewGuid()}/annotation", body, Json)).StatusCode);
    }

    [Fact]
    public async Task Csv_export_is_rfc4180_and_injection_safe()
    {
        await SeedHostAsync();
        var response = await app.Client(Roles.Viewer).GetAsync("/api/export/findings?format=csv");
        Assert.Equal("text/csv", response.Content.Headers.ContentType!.MediaType);
        var csv = await response.Content.ReadAsStringAsync();

        var rows = Csv.Parse(csv);
        Assert.Equal(2, rows.Count);
        var evidence = rows[1][rows[0].IndexOf("evidence")];
        Assert.Equal("'=cmd|' /C calc'!A0", evidence);
        Assert.EndsWith("\r\n", csv);

        var hosts = await app.Client(Roles.Viewer).GetFromJsonAsync<JsonElement>("/api/export/hosts?format=json", Json);
        Assert.Equal("10.4.0.1", hosts[0].GetProperty("address").GetString());
        Assert.Equal(HttpStatusCode.NotFound, (await app.Client(Roles.Viewer).GetAsync("/api/export/secrets?format=csv")).StatusCode);
    }

    [Fact]
    public async Task Import_upserts_annotations_by_address_without_fabricating_hosts()
    {
        await SeedHostAsync("10.4.0.1");
        const string csv = "address,owner,tags,description\r\n10.4.0.1,team-a,a;b,\"Main, primary\"\r\n10.4.0.99,team-b,,\r\nnot an address,x,,\r\n";
        var manager = app.Client(Roles.Manager);
        var result = await (await manager.PostAsync("/api/import/assets?format=csv", new StringContent(csv, Encoding.UTF8, "text/csv")))
            .Content.ReadFromJsonAsync<ImportResult>(Json);

        Assert.Equal((2, 0), (result!.Imported, result.Updated));
        Assert.Equal(["Row 4: invalid address 'not an address'."], result.Errors);
        Assert.Single(await _s.QueryAsync(db => db.Hosts.ToListAsync()));

        const string json = """[{ "address": "10.4.0.1", "owner": "team-z", "tags": ["a", "b"], "description": "Main, primary" }]""";
        var second = await (await manager.PostAsync("/api/import/assets?format=json", new StringContent(json, Encoding.UTF8, "application/json")))
            .Content.ReadFromJsonAsync<ImportResult>(Json);
        Assert.Equal((0, 1), (second!.Imported, second.Updated));

        var host = (await app.Client(Roles.Viewer).GetFromJsonAsync<PagedResult<HostListItemDto>>("/api/assets/hosts?search=10.4.0", Json))!.Items.Single();
        Assert.Equal(("team-z", "Main, primary"), (host.Annotation!.Owner, host.Annotation.Description));
        Assert.Contains(app.Audit.Entries, e => e.Action == "assets.imported");
    }

    [Fact]
    public async Task Import_matches_by_zone_or_unambiguous_address_and_reports_ambiguous_rows()
    {
        _s.Perspective = ("agent-1", "eth0", "dc-warsaw");
        await _s.RunAsync(Scenario.ZoneCoverage("dc-warsaw", "10.4.1.0/24"), 3, _s.HostUpWithMac("10.4.1.5", "00:11:22:33:44:55", "Cisco"), _s.HostUp("10.4.1.6"));
        _s.NextRun().Perspective = ("agent-2", "eth0", "lab");
        await _s.RunAsync(Scenario.ZoneCoverage("lab", "10.4.1.0/24"), 3, _s.HostUp("10.4.1.5"));
        var manager = app.Client(Roles.Manager);

        const string csv = "zone,address,owner\r\nlab,10.4.1.5,team-lab\r\n,10.4.1.5,team-x\r\n,10.4.1.6,team-waw\r\n";
        var result = await (await manager.PostAsync("/api/import/assets?format=csv", new StringContent(csv, Encoding.UTF8, "text/csv")))
            .Content.ReadFromJsonAsync<ImportResult>(Json);
        Assert.Equal((2, 0), (result!.Imported, result.Updated));
        Assert.Equal(["Row 3: address '10.4.1.5' is ambiguous: it exists in zones dc-warsaw, lab; add a zone."], result.Errors);

        const string json = """[{ "zone": "dc-warsaw", "address": "10.4.1.5", "owner": "team-core" }, { "address": "10.4.1.5", "owner": "team-x" }]""";
        var second = await (await manager.PostAsync("/api/import/assets?format=json", new StringContent(json, Encoding.UTF8, "application/json")))
            .Content.ReadFromJsonAsync<ImportResult>(Json);
        Assert.Equal((1, 0, 1), (second!.Imported, second.Updated, second.Errors.Count));

        var hosts = (await app.Client(Roles.Viewer).GetFromJsonAsync<PagedResult<HostListItemDto>>("/api/assets/hosts?search=10.4.1", Json))!.Items;
        Assert.Equal([("dc-warsaw", "10.4.1.5", "team-core"), ("dc-warsaw", "10.4.1.6", "team-waw"), ("lab", "10.4.1.5", "team-lab")],
            hosts.Select(h => (h.Zone, h.Address, h.Annotation?.Owner))); // sorted by zone, then address
        Assert.Equal(("00:11:22:33:44:55", "Cisco"), (hosts[0].MacAddress, hosts[0].MacVendor));
        Assert.Equal(["lab"], (await app.Client(Roles.Viewer).GetFromJsonAsync<PagedResult<HostListItemDto>>("/api/assets/hosts?zone=lab", Json))!
            .Items.Select(h => h.Zone));

        var export = Csv.Parse(await app.Client(Roles.Viewer).GetStringAsync("/api/export/hosts?format=csv"));
        var col = (string name) => export[0].IndexOf(name);
        Assert.Equal(("dc-warsaw", "10.4.1.5", "00:11:22:33:44:55", "Cisco"),
            (export[1][col("zone")], export[1][col("address")], export[1][col("macAddress")], export[1][col("macVendor")]));
    }

    [Fact]
    public async Task Lists_dashboard_changes_observations_and_diff()
    {
        await SeedHostAsync();
        var firstRun = _s.RunId;
        _s.NextRun(TimeSpan.FromDays(2));
        await _s.RunAsync(Scenario.Coverage(["10.4.0.0/24"]), 3, _s.HostUp("10.4.0.1"), _s.Port("10.4.0.1", 443), _s.Port("10.4.0.1", 8443));

        var viewer = app.Client(Roles.Viewer);
        var summary = await viewer.GetFromJsonAsync<DashboardSummaryDto>("/api/dashboard/summary", Json);
        Assert.Equal((1, 1, 2, 1), (summary!.HostsTotal, summary.HostsActive, summary.ServicesTotal, summary.FindingsOpen));
        Assert.Equal(1, summary.ChangesLast24h); // the first run's changes are two days older

        var changes = await viewer.GetFromJsonAsync<PagedResult<ChangeDto>>($"/api/changes?scanRunId={_s.RunId}", Json);
        Assert.Equal(("New open port 10.4.0.1:8443/tcp", "lab"), (Assert.Single(changes!.Items).Summary, changes.Items[0].Zone));
        Assert.Empty((await viewer.GetFromJsonAsync<PagedResult<ChangeDto>>("/api/changes?zone=dmz", Json))!.Items);

        var services = await viewer.GetFromJsonAsync<PagedResult<ServiceDto>>("/api/assets/services?port=8443&search=10.4.0&zone=lab", Json);
        Assert.Equal((1, "lab"), (services!.Total, services.Items[0].Zone));
        Assert.Equal(0, (await viewer.GetFromJsonAsync<PagedResult<ServiceDto>>("/api/assets/services?zone=dmz", Json))!.Total);

        var findings = await viewer.GetFromJsonAsync<PagedResult<FindingDto>>("/api/findings?severity=medium&status=Open&zone=lab", Json);
        Assert.Equal(("exposed-panel", "lab"), (Assert.Single(findings!.Items).SignatureId, findings.Items[0].Zone));
        Assert.Empty((await viewer.GetFromJsonAsync<PagedResult<FindingDto>>("/api/findings?zone=dmz", Json))!.Items);

        var observations = await viewer.GetFromJsonAsync<PagedResult<ObservationDto>>($"/api/observations?scanRunId={_s.RunId}&pageSize=2", Json);
        Assert.Equal((3, 2), (observations!.Total, observations.Items.Count));

        var diff = await viewer.GetFromJsonAsync<RunDiffDto>($"/api/scans/{_s.RunId}/diff?baseline={firstRun}", Json);
        Assert.Equal(["endpoint|lab|10.4.0.1|8443|tcp"], diff!.Added.Select(a => a.Key));
        Assert.Empty(diff.Removed);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, (await viewer.GetAsync($"/api/scans/{_s.RunId}/diff")).StatusCode);
    }

    [Fact]
    public async Task Service_detail_returns_http_details_artifacts_recog_device_and_artifact_findings()
    {
        var coverage = Scenario.Coverage(["10.4.0.0/24"]);
        var probe = _s.Http("10.4.0.9", 80, 200, "Login", "Microsoft-IIS/10.0");
        probe = probe with
        {
            Http = probe.Http! with
            {
                Headers = new Dictionary<string, string> { ["server"] = "Microsoft-IIS/10.0", ["x-debug-token"] = "a1b2c3", ["set-cookie"] = "ASP.NET_SessionId=***; path=/" },
                Cookies = HttpCookies.Parse("BIGipServerweb=1677787402.36895.0000; path=/, ASP.NET_SessionId=abc; path=/"),
                FaviconMd5 = "842c79ab11f38323fc554afbea5c990a", PageType = "login", Cdn = "cloudflare", CdnType = "waf",
            },
        };
        await _s.RunAsync(coverage, 1, _s.HostUp("10.4.0.9"), probe);
        var viewer = app.Client(Roles.Viewer);

        var listed = Assert.Single((await viewer.GetFromJsonAsync<PagedResult<ServiceDto>>("/api/assets/services", Json))!.Items);
        Assert.Equal("IP Camera", listed.DeviceType);
        Assert.Contains("debug", listed.ArtifactTags);
        Assert.Contains("IP Camera", (await viewer.GetFromJsonAsync<HostDetailDto>($"/api/assets/hosts/{listed.HostId}", Json))!.Classifications);

        var detail = (await viewer.GetFromJsonAsync<ServiceDetailDto>($"/api/assets/services/{listed.Id}", Json))!;
        Assert.Equal(("login", "cloudflare", "842c79ab11f38323fc554afbea5c990a"), (detail.Http!.PageType, detail.Http.Cdn, detail.Http.FaviconMd5));
        Assert.Equal(["BIGipServerweb", "ASP.NET_SessionId"], detail.Http.Cookies.Select(c => c.Name));
        Assert.Equal(new DeviceDto("IP Camera", "D-Link", "DCS-932"), detail.Device);
        Assert.Contains(detail.Technologies, t => t is { Name: "Microsoft IIS", Version: "10.0" } && t.ConfidenceMethod.Contains("recog"));
        Assert.Contains(detail.Artifacts, a => a.Name == "BIGipServerweb" && a.Value == "10.1.1.100:8080" && a.Tags.Contains("internal-ip-leak"));
        Assert.Contains(detail.Artifacts, a => a.Name == "x-debug-token" && a.Severity == "low");
        Assert.Equal(["artifact-debug", "artifact-internal-ip-leak", "artifact-login-page"],
            detail.Findings.Where(f => f.Source == "artifact").Select(f => f.SignatureId).Order());
        Assert.Equal(HttpStatusCode.NotFound, (await viewer.GetAsync($"/api/assets/services/{Guid.NewGuid()}")).StatusCode);

        // The next HTTP probe without the debug header replaces the artifacts and resolves the artifact finding.
        _s.NextRun();
        await _s.RunAsync(coverage, 1, _s.HostUp("10.4.0.9"), _s.Http("10.4.0.9", 80, 200, "Login", "Microsoft-IIS/10.0"));
        detail = (await viewer.GetFromJsonAsync<ServiceDetailDto>($"/api/assets/services/{listed.Id}", Json))!;
        Assert.DoesNotContain(detail.Artifacts, a => a.Name == "x-debug-token");
        Assert.Null(detail.Device);
        Assert.Equal(FindingStatus.Resolved, detail.Findings.Single(f => f.SignatureId == "artifact-debug").Status);
        Assert.Equal(FindingStatus.Open, detail.Findings.Single(f => f.SignatureId == "artifact-login-page").Status);
    }
}
