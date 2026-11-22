using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using WebScan.Server.Infrastructure.Http;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Modules.Networks;

namespace WebScan.Server.UnitTests.Integration;

[Collection("server")]
public sealed class NetworkTests(WebScanFactory factory)
{
    private static string Unique(string prefix) => $"{prefix}-{Guid.NewGuid():N}"[..(prefix.Length + 13)];

    [Fact]
    public async Task Scope_policy_is_seeded_from_configuration()
    {
        var admin = await factory.AdminAsync();
        var policy = await (await admin.GetAsync("/api/scope-policy")).ReadAsync<ScopePolicyDto>();
        Assert.Contains("10.0.0.0/8", policy.Allowed);
        Assert.Contains("*.example.com", policy.Allowed);
        Assert.Equal(["10.255.0.0/16"], policy.Excluded);
    }

    [Fact]
    public async Task Networks_outside_the_scope_policy_are_rejected()
    {
        var admin = await factory.AdminAsync();
        var outside = await admin.PostJsonAsync("/api/networks",
            new NetworkInput { Name = Unique("outside"), Zone = "corp", Ranges = ["10.1.0.0/16", "192.168.1.0/24", "evil.org"] });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, outside.StatusCode);
        var problem = await outside.ReadAsync<ValidationProblemDetails>();
        Assert.Equal(2, problem.Errors["ranges"].Length);
        Assert.Contains(problem.Errors["ranges"], e => e.Contains("192.168.1.0/24"));

        var partlyOutside = await admin.PostJsonAsync("/api/networks", new NetworkInput { Name = Unique("wide"), Zone = "corp", Ranges = ["0.0.0.0/0"] });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, partlyOutside.StatusCode);

        var invalid = await admin.PostJsonAsync("/api/networks", new NetworkInput { Name = Unique("bad"), Zone = "corp", Ranges = ["10.0.0.0/33", "*.example.com"] });
        Assert.Equal(2, (await invalid.ReadAsync<ValidationProblemDetails>()).Errors["ranges"].Length);

        var ok = await admin.PostJsonAsync("/api/networks", new NetworkInput
        {
            Name = Unique("inside"), Zone = "corp", Ranges = ["10.20.0.0/24", "10.20.1.1-10.20.1.10", "App.Example.com"],
            Exclusions = ["10.20.0.0/28"], Tags = ["prod"], MaxRatePerSecond = 500,
        });
        Assert.Equal(HttpStatusCode.Created, ok.StatusCode);
        var network = await ok.ReadAsync<NetworkDto>();
        Assert.Equal(256 + 10 - 16 + 1, network.AddressCount);
        Assert.Contains("app.example.com", network.Ranges);
    }

    [Fact]
    public async Task Crud_zones_and_scope_resolution()
    {
        var admin = await factory.AdminAsync();
        var zone = Unique("zone");
        Assert.Equal(HttpStatusCode.Created, (await admin.PostJsonAsync("/api/zones", new { name = zone, description = "Test zone" })).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PostJsonAsync("/api/zones", new { name = zone })).StatusCode);

        var created = await (await admin.PostJsonAsync("/api/networks", new NetworkInput
        {
            Name = Unique("net"), Zone = zone, Ranges = ["10.30.0.0/24", "10.255.1.0/24"], Exclusions = ["10.30.0.1"],
        })).ReadAsync<NetworkDto>();
        Assert.Equal(HttpStatusCode.UnprocessableEntity, // duplicate name
            (await admin.PostJsonAsync("/api/networks", new NetworkInput { Name = created.Name, Zone = zone, Ranges = ["10.30.1.0/24"] })).StatusCode);

        var zones = await (await admin.GetAsync("/api/zones")).ReadAsync<List<ZoneDto>>();
        Assert.Equal(1, zones.Single(z => z.Name == zone).NetworkCount);
        Assert.Equal(HttpStatusCode.Conflict, (await admin.DeleteAsync($"/api/zones/{zone}")).StatusCode);

        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var scopeService = scope.ServiceProvider.GetRequiredService<INetworkScopeService>();
            var resolved = await scopeService.ResolveAsync([created.Id]);
            var segment = Assert.Single(resolved.Segments);
            Assert.Equal(zone, segment.Zone);
            Assert.Equal(["10.30.0.0/24", "10.255.1.0/24"], segment.Include);
            Assert.Equal(["10.30.0.1"], segment.Exclude);
            Assert.Equal(["10.255.0.0/16"], resolved.GlobalExclusions);

            Assert.True(await scopeService.IsAuthorizedAsync("10.30.0.5"));
            Assert.False(await scopeService.IsAuthorizedAsync("10.255.1.5")); // globally excluded
            Assert.False(await scopeService.IsAuthorizedAsync("192.168.0.1"));
            Assert.True(await scopeService.IsAuthorizedAsync("api.example.com"));
            Assert.False(await scopeService.IsAuthorizedAsync("example.org"));
        }

        var updated = await admin.PutJsonAsync($"/api/networks/{created.Id}",
            new NetworkInput { Name = created.Name, Zone = zone, Ranges = ["10.30.0.0/25"], Enabled = false });
        Assert.Equal(HttpStatusCode.OK, updated.StatusCode);
        Assert.False((await updated.ReadAsync<NetworkDto>()).Enabled);
        await using (var scope = factory.Services.CreateAsyncScope())
            Assert.Empty((await scope.ServiceProvider.GetRequiredService<INetworkScopeService>().ResolveAsync([created.Id])).Segments);

        Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync($"/api/networks/{created.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync($"/api/networks/{created.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync($"/api/zones/{zone}")).StatusCode);

        var audit = await (await admin.GetAsync($"/api/audit?entityType=network&pageSize=100")).ReadAsync<PagedResult<WebScan.Server.Infrastructure.AuditEntryDto>>();
        Assert.Contains(audit.Items, e => e.EntityId == created.Id.ToString() && e.Action == "network.created");
        Assert.Contains(audit.Items, e => e.EntityId == created.Id.ToString() && e.Action == "network.deleted");
    }

    [Fact]
    public async Task Scope_policy_update_validates_and_narrows_resolution()
    {
        var admin = await factory.AdminAsync();
        var original = await (await admin.GetAsync("/api/scope-policy")).ReadAsync<ScopePolicyDto>();
        var network = await (await admin.PostJsonAsync("/api/networks", new NetworkInput { Name = Unique("narrow"), Zone = "corp", Ranges = ["10.40.0.0/23"] }))
            .ReadAsync<NetworkDto>();
        try
        {
            Assert.Equal(HttpStatusCode.UnprocessableEntity, (await admin.PutJsonAsync("/api/scope-policy", new { allowed = new[] { "not an ip" } })).StatusCode);
            var narrowed = await admin.PutJsonAsync("/api/scope-policy", new { allowed = new[] { "10.40.0.0/24", "*.example.com" }, excluded = Array.Empty<string>() });
            Assert.Equal(HttpStatusCode.OK, narrowed.StatusCode);

            await using var scope = factory.Services.CreateAsyncScope();
            var resolved = await scope.ServiceProvider.GetRequiredService<INetworkScopeService>().ResolveAsync([network.Id]);
            Assert.Equal(["10.40.0.0/24"], Assert.Single(resolved.Segments).Include);
        }
        finally
        {
            await admin.PutJsonAsync("/api/scope-policy", new { allowed = original.Allowed, excluded = original.Excluded });
            await admin.DeleteAsync($"/api/networks/{network.Id}");
        }
    }

    [Fact]
    public async Task Scope_policy_ports_are_validated_audited_kept_by_older_clients_and_resolved()
    {
        var admin = await factory.AdminAsync();
        var original = await (await admin.GetAsync("/api/scope-policy")).ReadAsync<ScopePolicyDto>();
        Assert.Empty(original.AllowedPorts); // empty allowlist = every port
        try
        {
            var invalid = await admin.PutJsonAsync("/api/scope-policy",
                new { allowed = original.Allowed, excluded = original.Excluded, allowedPorts = new[] { "80", "top-100", "0", "90-80" } });
            Assert.Equal(HttpStatusCode.UnprocessableEntity, invalid.StatusCode);
            Assert.Equal(3, (await invalid.ReadAsync<ValidationProblemDetails>()).Errors["allowedPorts"].Length);

            var updated = await (await admin.PutJsonAsync("/api/scope-policy",
                new { allowed = original.Allowed, excluded = original.Excluded, allowedPorts = new[] { " 80", "443", "8000-8100", "443" }, excludedPorts = new[] { "8080" } }))
                .ReadAsync<ScopePolicyDto>();
            Assert.Equal(["80", "443", "8000-8100"], updated.AllowedPorts);
            Assert.Equal(["8080"], updated.ExcludedPorts);

            // A client that does not know the port fields (e.g. "Add to scope policy") keeps them.
            var kept = await (await admin.PutJsonAsync("/api/scope-policy", new { allowed = original.Allowed, excluded = original.Excluded })).ReadAsync<ScopePolicyDto>();
            Assert.Equal(["80", "443", "8000-8100"], kept.AllowedPorts);

            await using var scope = factory.Services.CreateAsyncScope();
            var resolved = await scope.ServiceProvider.GetRequiredService<INetworkScopeService>().ResolveAsync([]);
            Assert.Equal(["80", "443", "8000-8100"], resolved.AllowedPorts);
            Assert.Equal(["8080"], resolved.ExcludedPorts);

            var audit = await (await admin.GetAsync("/api/audit?action=scope_policy.updated&pageSize=5")).ReadAsync<PagedResult<WebScan.Server.Infrastructure.AuditEntryDto>>();
            Assert.Contains(audit.Items, e => e.Details?.GetRawText().Contains("8000-8100") == true);

            var manager = await factory.UserWithRoleAsync("Manager");
            Assert.Equal(HttpStatusCode.Forbidden, (await manager.PutJsonAsync("/api/scope-policy", new { allowed = original.Allowed, allowedPorts = Array.Empty<string>() })).StatusCode);
        }
        finally
        {
            await admin.PutJsonAsync("/api/scope-policy", new { allowed = original.Allowed, excluded = original.Excluded, allowedPorts = original.AllowedPorts, excludedPorts = original.ExcludedPorts });
        }
    }

    [Fact]
    public async Task Json_import_export_round_trip()
    {
        var admin = await factory.AdminAsync();
        var a = Unique("json-a");
        var b = Unique("json-b");
        var items = new[]
        {
            new NetworkInput { Name = a, Zone = "imported", Ranges = ["10.50.0.0/24"], Exclusions = ["10.50.0.1"], Tags = ["x", "y"], Description = "A", MaxRatePerSecond = 100, Enabled = false },
            new NetworkInput { Name = b, Zone = "imported", Ranges = ["10.50.1.0/24", "db.example.com"] },
            new NetworkInput { Name = Unique("json-bad"), Zone = "imported", Ranges = ["8.8.8.8"] },
        };
        var import = await admin.PostAsync("/api/networks/import?format=json",
            new StringContent(JsonSerializer.Serialize(items, WebScan.Contracts.ContractJson.Options), Encoding.UTF8, "application/json"));
        var result = await import.ReadAsync<ImportResult>();
        Assert.Equal(2, result.Created);
        Assert.Equal(0, result.Updated);
        Assert.Single(result.Errors);
        Assert.Contains("8.8.8.8", result.Errors[0]);

        var exportResponse = await admin.GetAsync("/api/networks/export?format=json");
        Assert.Equal("application/json", exportResponse.Content.Headers.ContentType!.MediaType);
        var exported = await exportResponse.ReadAsync<List<NetworkInput>>();
        var exportedA = exported.Single(n => n.Name == a);
        Assert.Equal((items[0].Zone, items[0].Description, items[0].MaxRatePerSecond, items[0].Enabled),
            (exportedA.Zone, exportedA.Description, exportedA.MaxRatePerSecond, exportedA.Enabled));
        Assert.Equal(items[0].Ranges, exportedA.Ranges);
        Assert.Equal(items[0].Exclusions, exportedA.Exclusions);
        Assert.Equal(items[0].Tags, exportedA.Tags);

        // Re-importing the export updates instead of duplicating.
        var mine = exported.Where(n => n.Name == a || n.Name == b).ToList();
        var again = await (await admin.PostAsync("/api/networks/import?format=json",
            new StringContent(JsonSerializer.Serialize(mine, WebScan.Contracts.ContractJson.Options), Encoding.UTF8, "application/json"))).ReadAsync<ImportResult>();
        Assert.Equal((0, 2, 0), (again.Created, again.Updated, again.Errors.Count));

        var garbage = await admin.PostAsync("/api/networks/import?format=json", new StringContent("{not json", Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.UnprocessableEntity, garbage.StatusCode);
    }

    [Fact]
    public async Task Csv_import_export_round_trip()
    {
        var admin = await factory.AdminAsync();
        var name = Unique("csv");
        var csv = "name,zone,ranges,exclusions,tags,description\r\n" +
                  $"{name},csvzone,10.60.0.0/24;10.60.1.0/24,10.60.0.1,a;b,\"Office, floor 2 \"\"north\"\"\"\r\n";
        var created = await (await admin.PostAsync("/api/networks/import?format=csv", new StringContent(csv, Encoding.UTF8, "text/csv"))).ReadAsync<ImportResult>();
        Assert.Equal((1, 0, 0), (created.Created, created.Updated, created.Errors.Count));

        var export = await admin.GetAsync("/api/networks/export?format=csv");
        Assert.Equal("text/csv", export.Content.Headers.ContentType!.MediaType);
        var text = await export.Content.ReadAsStringAsync();
        var rows = Csv.Parse(text);
        Assert.Equal(["name", "zone", "ranges", "exclusions", "tags", "description"], rows[0]);
        var row = rows.Single(r => r[0] == name);
        Assert.Equal(["csvzone", "10.60.0.0/24;10.60.1.0/24", "10.60.0.1", "a;b", "Office, floor 2 \"north\""], row.Skip(1));

        // Round trip: re-import the exported file → updates only, nothing created, no errors for our row.
        var reimport = await (await admin.PostAsync("/api/networks/import?format=csv", new StringContent(text, Encoding.UTF8, "text/csv"))).ReadAsync<ImportResult>();
        Assert.Equal(0, reimport.Created);
        Assert.True(reimport.Updated >= 1);
        Assert.Empty(reimport.Errors);

        var missingColumns = await admin.PostAsync("/api/networks/import?format=csv", new StringContent("name,zone\r\nx,y\r\n", Encoding.UTF8, "text/csv"));
        Assert.Equal(HttpStatusCode.UnprocessableEntity, missingColumns.StatusCode);
    }
}
