using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WebScan.Contracts;
using WebScan.Discovery.UnitTests.Infrastructure;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Integrations;
using WebScan.Server.Modules.Integrations.DefectDojo;
using WebScan.Server.Modules.Integrations.Persistence;

namespace WebScan.Discovery.UnitTests;

[Collection(DbCollection.Name)]
public class DefectDojoTests(TestApp app) : IAsyncLifetime
{
    private static readonly JsonSerializerOptions Json = ContractJson.Options;
    private readonly Scenario _s = new(app);

    public Task InitializeAsync() => app.ResetAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task ConfigureAsync(bool enabled = true, string minimumSeverity = "low")
    {
        var response = await app.Client(Roles.Administrator).PutAsJsonAsync("/api/integrations/defectdojo", new
        {
            enabled, baseUrl = "https://dojo.example.test/", apiKey = "secret-key", productId = 3, engagementId = 7, minimumSeverity, verifyTls = true,
        }, Json);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private async Task<List<Guid>> SeedFindingsAsync()
    {
        await _s.RunAsync(Scenario.Coverage(["10.5.0.0/24"]), 3, _s.HostUp("10.5.0.1"), _s.Port("10.5.0.1", 80), _s.Port("10.5.0.1", 22),
            _s.Signature("10.5.0.1", 80, "exposed-git", "high", "[core] repositoryformatversion"),
            _s.Signature("10.5.0.1", 80, "server-banner", "info"));
        return await _s.QueryAsync(db => db.SignatureMatches.OrderBy(m => m.SignatureId).Select(m => m.Id).ToListAsync());
    }

    [Fact]
    public async Task Settings_store_the_api_key_encrypted_and_never_return_it()
    {
        await ConfigureAsync();
        var dto = await app.Client(Roles.Administrator).GetFromJsonAsync<DefectDojoSettingsDto>("/api/integrations/defectdojo", Json);
        Assert.True(dto!.HasApiKey);
        var stored = await app.WithScopeAsync(sp => sp.GetRequiredService<IntegrationsDbContext>().DefectDojo.SingleAsync());
        Assert.NotEqual("secret-key", stored.ApiKeyProtected);
        Assert.StartsWith("enc:", stored.ApiKeyProtected);
        var audit = Assert.Single(app.Audit.Entries);
        Assert.DoesNotContain("secret-key", JsonSerializer.Serialize(audit.Details));

        var invalid = await app.Client(Roles.Administrator).PutAsJsonAsync("/api/integrations/defectdojo",
            new { enabled = true, baseUrl = "ftp://x", engagementId = 1, minimumSeverity = "low" }, Json);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, invalid.StatusCode);
    }

    [Fact]
    public async Task Export_creates_findings_with_the_expected_request_shape_and_stores_external_ids()
    {
        await ConfigureAsync(minimumSeverity: "low");
        var ids = await SeedFindingsAsync(); // [exposed-git (high), server-banner (info)]
        app.DefectDojo.Enqueue(HttpStatusCode.OK, """{ "count": 1, "results": [{ "id": 12, "name": "Generic Findings Import" }] }""");
        app.DefectDojo.Enqueue(HttpStatusCode.Created, """{ "id": 55 }""");
        app.DefectDojo.Enqueue(HttpStatusCode.Created, """{ "id": 901 }""");

        var response = await app.Client(Roles.Manager).PostAsJsonAsync("/api/integrations/defectdojo/export", new { findingIds = ids }, Json);
        var result = await response.Content.ReadFromJsonAsync<ExportResult>(Json);
        Assert.Equal((1, 1), (result!.Exported, result.Skipped)); // info is below the configured minimum
        Assert.Empty(result.Errors);

        var requests = app.DefectDojo.Requests;
        Assert.Equal(3, requests.Count);
        Assert.Equal("https://dojo.example.test/api/v2/test_types/?name=Generic%20Findings%20Import", requests[0].Uri.AbsoluteUri);
        Assert.All(requests, r => Assert.Equal("Token secret-key", r.Authorization));
        Assert.Equal((HttpMethod.Post, "/api/v2/tests/"), (requests[1].Method, requests[1].Uri.AbsolutePath));
        using var test = JsonDocument.Parse(requests[1].Body!);
        Assert.Equal((7, 12), (test.RootElement.GetProperty("engagement").GetInt32(), test.RootElement.GetProperty("test_type").GetInt32()));

        Assert.Equal((HttpMethod.Post, "/api/v2/findings/"), (requests[2].Method, requests[2].Uri.AbsolutePath));
        using var finding = JsonDocument.Parse(requests[2].Body!);
        var f = finding.RootElement;
        Assert.Equal(55, f.GetProperty("test").GetInt32());
        Assert.Equal(12, f.GetProperty("found_by")[0].GetInt32());
        Assert.Equal("Finding exposed-git (10.5.0.1:80)", f.GetProperty("title").GetString());
        Assert.Equal(("High", "S1"), (f.GetProperty("severity").GetString(), f.GetProperty("numerical_severity").GetString()));
        Assert.True(f.GetProperty("active").GetBoolean());
        Assert.Equal(ids[0].ToString(), f.GetProperty("unique_id_from_tool").GetString());
        Assert.Equal("exposed-git", f.GetProperty("vuln_id_from_tool").GetString());
        Assert.Contains("repositoryformatversion", f.GetProperty("description").GetString());

        var exported = await _s.QueryAsync(db => db.SignatureMatches.SingleAsync(m => m.Id == ids[0]));
        var reference = Assert.Single(exported.ExternalRefs);
        Assert.Equal(("defectdojo", "901"), (reference.System, reference.ExternalId));
        var detail = await app.Client(Roles.Viewer).GetFromJsonAsync<JsonElement>("/api/findings?severity=high", Json);
        Assert.Equal("901", detail.GetProperty("items")[0].GetProperty("externalRefs")[0].GetProperty("externalId").GetString());

        // Re-export of unchanged findings is skipped without calling DefectDojo.
        app.DefectDojo.Requests.Clear();
        var again = await (await app.Client(Roles.Manager).PostAsJsonAsync("/api/integrations/defectdojo/export", new { findingIds = ids }, Json))
            .Content.ReadFromJsonAsync<ExportResult>(Json);
        Assert.Equal((0, 2), (again!.Exported, again.Skipped));
        Assert.Empty(app.DefectDojo.Requests);
    }

    [Fact]
    public async Task Changed_findings_are_updated_in_place()
    {
        await ConfigureAsync();
        var ids = await SeedFindingsAsync();
        app.DefectDojo.Enqueue(HttpStatusCode.OK, """{ "results": [{ "id": 12 }] }""");
        app.DefectDojo.Enqueue(HttpStatusCode.Created, """{ "id": 55 }""");
        app.DefectDojo.Enqueue(HttpStatusCode.Created, """{ "id": 901 }""");
        await app.Client(Roles.Manager).PostAsJsonAsync("/api/integrations/defectdojo/export", new { findingIds = new[] { ids[0] } }, Json);

        _s.NextRun();
        await _s.RunAsync(Scenario.Coverage(["10.5.0.0/24"]), 3, _s.HostUp("10.5.0.1"),
            _s.Signature("10.5.0.1", 80, "exposed-git", "high", "[core] bare = false"));
        app.DefectDojo.Requests.Clear();
        app.DefectDojo.Enqueue(HttpStatusCode.OK, """{ "id": 901 }""");

        var result = await app.WithScopeAsync(sp => sp.GetRequiredService<IFindingPublisher>().PublishAsync(_s.RunId, "defectdojo", "medium"));

        Assert.Equal(1, result.Published);
        var patch = Assert.Single(app.DefectDojo.Requests);
        Assert.Equal((HttpMethod.Patch, "/api/v2/findings/901/"), (patch.Method, patch.Uri.AbsolutePath));
        Assert.Contains("bare = false", patch.Body);
        Assert.DoesNotContain("\"test\"", patch.Body);
    }

    [Fact]
    public async Task Publisher_respects_destination_enablement_and_severity()
    {
        var ids = await SeedFindingsAsync();
        var publisher = (IServiceProvider sp) => sp.GetRequiredService<IFindingPublisher>();

        var disabled = await app.WithScopeAsync(sp => publisher(sp).PublishAsync(_s.RunId, "defectdojo", "info"));
        Assert.Equal((0, 2), (disabled.Published, disabled.Skipped));
        Assert.Empty(app.DefectDojo.Requests);

        var internalResult = await app.WithScopeAsync(sp => publisher(sp).PublishAsync(_s.RunId, "internal", "medium"));
        Assert.Equal((1, 1), (internalResult.Published, internalResult.Skipped));
        var published = await _s.QueryAsync(db => db.SignatureMatches.Where(m => m.PublishedAt != null).Select(m => m.Id).ToListAsync());
        Assert.Equal([ids[0]], published);

        await Assert.ThrowsAsync<ArgumentException>(() => app.WithScopeAsync(sp => publisher(sp).PublishAsync(_s.RunId, "email", "low")));
    }

    [Fact]
    public async Task False_positives_are_never_published_and_overrides_set_the_exported_severity()
    {
        await ConfigureAsync(minimumSeverity: "medium");
        var ids = await SeedFindingsAsync(); // [exposed-git (high), server-banner (info)]
        var editor = app.Client(Roles.Editor);
        await editor.PutAsJsonAsync($"/api/findings/{ids[0]}", new { triage = "FalsePositive" }, Json);
        await editor.PutAsJsonAsync($"/api/findings/{ids[1]}", new { triage = "Confirmed", severityOverride = "high" }, Json);

        var internalResult = await app.WithScopeAsync(sp => sp.GetRequiredService<IFindingPublisher>().PublishAsync(_s.RunId, "internal", "medium"));
        Assert.Equal((1, 1), (internalResult.Published, internalResult.Skipped));
        Assert.Equal([ids[1]], await _s.QueryAsync(db => db.SignatureMatches.Where(m => m.PublishedAt != null).Select(m => m.Id).ToListAsync()));

        app.DefectDojo.Enqueue(HttpStatusCode.OK, """{ "results": [{ "id": 12 }] }""");
        app.DefectDojo.Enqueue(HttpStatusCode.Created, """{ "id": 55 }""");
        app.DefectDojo.Enqueue(HttpStatusCode.Created, """{ "id": 902 }""");
        var result = await (await app.Client(Roles.Manager).PostAsJsonAsync("/api/integrations/defectdojo/export", new { findingIds = ids }, Json))
            .Content.ReadFromJsonAsync<ExportResult>(Json);
        Assert.Equal((1, 1), (result!.Exported, result.Skipped)); // the false positive is skipped although selected
        using var finding = JsonDocument.Parse(app.DefectDojo.Requests[^1].Body!);
        Assert.Equal((ids[1].ToString(), "High"),
            (finding.RootElement.GetProperty("unique_id_from_tool").GetString(), finding.RootElement.GetProperty("severity").GetString()));
    }

    [Fact]
    public async Task Export_requires_enabled_integration_and_test_reports_failures()
    {
        await ConfigureAsync(enabled: false);
        var ids = await SeedFindingsAsync();
        var response = await app.Client(Roles.Manager).PostAsJsonAsync("/api/integrations/defectdojo/export", new { findingIds = ids }, Json);
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);

        app.DefectDojo.Enqueue(HttpStatusCode.Forbidden, """{ "detail": "Invalid token." }""");
        var test = await (await app.Client(Roles.Administrator).PostAsync("/api/integrations/defectdojo/test", null))
            .Content.ReadFromJsonAsync<DefectDojoTestResult>(Json);
        Assert.False(test!.Ok);
        Assert.Contains("403", test.Message);
        Assert.Equal("/api/v2/engagements/7/", Assert.Single(app.DefectDojo.Requests).Uri.AbsolutePath);
    }
}
