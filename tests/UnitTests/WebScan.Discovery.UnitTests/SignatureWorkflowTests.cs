using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WebScan.Contracts;
using WebScan.Discovery.UnitTests.Infrastructure;
using WebScan.Server.Kernel.Discovery;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Discovery.Domain;
using WebScan.Server.Modules.Signatures;
using WebScan.Server.Modules.Signatures.Domain;

namespace WebScan.Discovery.UnitTests;

[Collection(DbCollection.Name)]
public class SignatureWorkflowTests(TestApp app) : IAsyncLifetime
{
    private static readonly JsonSerializerOptions Json = ContractJson.Options;

    public Task InitializeAsync() => app.ResetAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private static string Template(string id, string severity = "low", string tags = "tech") => $$$"""
        id: {{{id}}}
        info:
          name: {{{id}}} detection
          severity: {{{severity}}}
          tags: {{{tags}}}
        http:
          - method: GET
            path: ["{{BaseURL}}/{{{id}}}"]
            matchers:
              - type: status
                status: [200]
        """;

    private Task<SignatureBundle> BundleAsync(string[]? ids = null, string[]? tags = null, string[]? severities = null) =>
        app.WithScopeAsync(sp => sp.GetRequiredService<ISignatureCatalog>().GetApprovedBundleAsync(ids ?? [], tags ?? [], severities ?? []));

    [Fact]
    public async Task Draft_is_not_executable_approved_is_and_retired_is_removed()
    {
        var manager = app.Client(Roles.Manager);
        var created = await manager.PostAsJsonAsync("/api/signatures", new { id = "wf-check", name = "Workflow check", kind = "NucleiTemplate", content = Template("wf-check") }, Json);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.DoesNotContain((await BundleAsync()).Items, i => i.Id == "wf-check");

        Assert.Equal(HttpStatusCode.Forbidden, (await manager.PostAsync("/api/signatures/wf-check/versions/1/approve", null)).StatusCode);
        var approve = await app.Client(Roles.Administrator).PostAsync("/api/signatures/wf-check/versions/1/approve", null);
        Assert.Equal(HttpStatusCode.OK, approve.StatusCode);
        var item = Assert.Single((await BundleAsync(["wf-check"])).Items);
        Assert.Equal((1, "nuclei-yaml"), (item.Version, item.Format));

        // A newer draft version does not replace the approved one until it is approved.
        Assert.Equal(HttpStatusCode.Created, (await manager.PostAsJsonAsync("/api/signatures/wf-check/versions", new { content = Template("wf-check") + "\n# v2\n" }, Json)).StatusCode);
        Assert.Equal(1, Assert.Single((await BundleAsync(["wf-check"])).Items).Version);
        await app.Client(Roles.Administrator).PostAsync("/api/signatures/wf-check/versions/2/approve", null);
        Assert.Equal(2, Assert.Single((await BundleAsync(["wf-check"])).Items).Version);

        Assert.Equal(HttpStatusCode.OK, (await manager.PostAsync("/api/signatures/wf-check/retire", null)).StatusCode);
        Assert.Empty((await BundleAsync(["wf-check"])).Items);

        var detail = await app.Client(Roles.Viewer).GetFromJsonAsync<SignatureDetailDto>("/api/signatures/wf-check", Json);
        Assert.Equal((SignatureStatus.Retired, 2, 2), (detail!.Status, detail.ApprovedVersion, detail.LatestVersion));
        Assert.Equal("test-administrator", detail.Versions[1].ApprovedBy);
        Assert.Contains(app.Audit.Entries, e => e.Action == "signature.approved" && e.EntityId == "wf-check");
        Assert.Contains(app.Audit.Entries, e => e.Action == "signature.retired");
    }

    [Fact]
    public async Task Bundle_is_filtered_ordered_by_id_and_hashed_in_the_shared_format()
    {
        var manager = app.Client(Roles.Manager);
        var admin = app.Client(Roles.Administrator);
        foreach (var (id, severity, tags) in new[] { ("zz-b", "low", "web"), ("zz-a", "info", "web,tls"), ("zz-c", "medium", "db") })
        {
            await manager.PostAsJsonAsync("/api/signatures", new { id, name = id, kind = "NucleiTemplate", content = Template(id, severity, tags) }, Json);
            await admin.PostAsync($"/api/signatures/{id}/versions/1/approve", null);
        }

        var bundle = await BundleAsync(tags: ["web"], severities: ["info", "low"]);
        Assert.Equal(["zz-a", "zz-b"], bundle.Items.Select(i => i.Id));
        var bytes = System.Text.Encoding.UTF8.GetBytes(string.Concat(bundle.Items.Select(i => $"{i.Id}\n{i.Version}\n{i.Content}\n")));
        Assert.Equal(Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes)), bundle.Sha256);

        var all = await BundleAsync();
        Assert.Contains(all.Items, i => i.Id == "nginx-default-page"); // seeded, approved by "system"
        Assert.DoesNotContain(all.Items, i => i.Id == "nginx-web-server"); // classification rules are not agent-executable
        Assert.Equal(all.Items.Select(i => i.Id).Order(StringComparer.Ordinal), all.Items.Select(i => i.Id));
    }

    [Fact]
    public async Task Create_rejects_unsafe_templates_and_mismatched_ids()
    {
        var manager = app.Client(Roles.Manager);
        var unsafeTemplate = Template("bad-one").Replace("tags: tech", "tags: tech,intrusive");
        var response = await manager.PostAsJsonAsync("/api/signatures", new { id = "bad-one", name = "Bad", kind = "NucleiTemplate", content = unsafeTemplate }, Json);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
        Assert.Contains("intrusive", await response.Content.ReadAsStringAsync());

        var mismatch = await manager.PostAsJsonAsync("/api/signatures", new { id = "other-id", name = "X", kind = "NucleiTemplate", content = Template("bad-two") }, Json);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, mismatch.StatusCode);

        var viewerValidate = await app.Client(Roles.Viewer).PostAsJsonAsync("/api/signatures/validate", new { kind = "NucleiTemplate", content = unsafeTemplate }, Json);
        var result = await viewerValidate.Content.ReadFromJsonAsync<ValidateSignatureResponse>(Json);
        Assert.False(result!.Valid);
    }

    [Fact]
    public async Task High_severity_requires_an_approval_note()
    {
        await app.Client(Roles.Manager).PostAsJsonAsync("/api/signatures", new { id = "hi-sev", name = "High", kind = "NucleiTemplate", content = Template("hi-sev", "high") }, Json);
        var admin = app.Client(Roles.Administrator);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, (await admin.PostAsync("/api/signatures/hi-sev/versions/1/approve", null)).StatusCode);
        var ok = await admin.PostAsJsonAsync("/api/signatures/hi-sev/versions/1/approve", new { note = "Validated against staging, read-only check" }, Json);
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Single((await BundleAsync(["hi-sev"])).Items);
    }

    [Fact]
    public async Task Approved_classification_rules_are_applied_on_persist_with_combined_confidence()
    {
        var s = new Scenario(app);
        await s.RunAsync(Scenario.Coverage(["10.3.0.0/24"]), 3, s.HostUp("10.3.0.1"),
            s.Service("10.3.0.1", 80, "http", "nginx", "1.25.3"), s.Http("10.3.0.1", 80, 200, "Router Admin Console", "nginx/1.25.3"));

        var nginx = await s.QueryAsync(db => db.Technologies.SingleAsync(t => t.NameKey == "nginx"));
        Assert.Equal(("1.25.3", "web-server"), (nginx.Version, nginx.Category));
        Assert.Equal("signature-match+version-probe", nginx.ConfidenceMethod);
        Assert.Equal(0.98, nginx.Confidence); // 1 - 0.2 * 0.1
        Assert.Contains("nginx-web-server@v1", nginx.Sources);

        var matches = await s.QueryAsync(db => db.SignatureMatches.OrderBy(m => m.SignatureId).ToListAsync());
        Assert.Equal(["admin-panel", "nginx-web-server"], matches.Select(m => m.SignatureId));
        var admin = matches[0];
        Assert.Equal(("admin-panel", SignatureMatch.ClassificationSource, 1, "info"), (admin.ClassificationTag, admin.Source, admin.SignatureVersion, admin.Severity));
        Assert.Equal((0.6, "signature-match"), (admin.ConfidenceScore, admin.ConfidenceMethod));
        Assert.Contains("http.title=Router Admin Console", admin.Evidence);
        Assert.Equal(app.Clock.GetUtcNow(), admin.MatchedAt);

        var hosts = await app.Client(Roles.Viewer).GetFromJsonAsync<JsonElement>("/api/assets/hosts", Json);
        var host = hosts.GetProperty("items")[0];
        Assert.Equal("admin-panel", host.GetProperty("classifications")[0].GetString());
        Assert.Contains("nginx", host.GetProperty("technologies").EnumerateArray().Select(t => t.GetString()));

        var technologies = await app.Client(Roles.Viewer).GetFromJsonAsync<JsonElement>("/api/assets/technologies", Json);
        var summary = technologies.EnumerateArray().Single(t => t.GetProperty("name").GetString() == "nginx");
        Assert.Equal((1, 1, 0.98), (summary.GetProperty("hostCount").GetInt32(), summary.GetProperty("serviceCount").GetInt32(), summary.GetProperty("confidence").GetDouble()));
    }

    [Fact]
    public async Task Retired_classification_rules_are_not_applied()
    {
        await app.Client(Roles.Manager).PostAsync("/api/signatures/admin-panel/retire", null);
        var s = new Scenario(app);
        await s.RunAsync(Scenario.Coverage(["10.3.1.0/24"]), 3, s.HostUp("10.3.1.1"), s.Http("10.3.1.1", 80, 200, "Admin"));
        Assert.Empty(await s.QueryAsync(db => db.SignatureMatches.ToListAsync()));
    }
}
