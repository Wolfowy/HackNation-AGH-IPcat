using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using WebScan.Server.Infrastructure;
using WebScan.Server.Infrastructure.Http;
using WebScan.Server.Infrastructure.Persistence;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Identity;

namespace WebScan.Server.UnitTests.Integration;

[Collection("server")]
public sealed class InfrastructureTests(WebScanFactory factory)
{
    [Fact]
    public async Task Startup_applies_migrations_of_every_module_and_creates_wolverine_storage()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var registry = scope.ServiceProvider.GetRequiredService<ModuleDbContextRegistry>();
        Assert.Contains(typeof(InfraDbContext), registry.Contexts);
        Assert.True(registry.Contexts.Count >= 4);
        foreach (var type in registry.Contexts)
        {
            var db = (DbContext)scope.ServiceProvider.GetRequiredService(type);
            Assert.Empty(await db.Database.GetPendingMigrationsAsync());
            Assert.NotEmpty(await db.Database.GetAppliedMigrationsAsync());
        }

        await using var connection = new NpgsqlConnection(factory.ConnectionString);
        await connection.OpenAsync();
        await using var cmd = new NpgsqlCommand(
            "SELECT schema_name FROM information_schema.schemata WHERE schema_name IN ('infra','identity','agents','networks','wolverine')", connection);
        var schemas = new List<string>();
        await using (var reader = await cmd.ExecuteReaderAsync())
            while (await reader.ReadAsync()) schemas.Add(reader.GetString(0));
        Assert.Equal(["agents", "identity", "infra", "networks", "wolverine"], schemas.Order());
    }

    [Fact]
    public async Task Health_endpoints_are_anonymous()
    {
        var client = factory.CreateClient();
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health/live")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health/ready")).StatusCode);
    }

    [Fact]
    public async Task Unknown_endpoints_deny_anonymous_by_default()
    {
        var response = await factory.CreateClient().GetAsync("/api/settings");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Settings_round_trip_and_null_deletes()
    {
        var admin = await factory.AdminAsync();
        var put = await admin.PutJsonAsync("/api/settings", new { values = new Dictionary<string, string?> { ["ui.theme"] = "dark", ["retention.days"] = "30" } });
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);

        await admin.PutJsonAsync("/api/settings", new { values = new Dictionary<string, string?> { ["retention.days"] = null } });
        var settings = await (await admin.GetAsync("/api/settings")).ReadAsync<SettingsDto>();
        Assert.Equal("dark", settings.Values["ui.theme"]);
        Assert.False(settings.Values.ContainsKey("retention.days"));

        var invalid = await admin.PutJsonAsync("/api/settings", new { values = new Dictionary<string, string?> { ["bad key!"] = "x" } });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, invalid.StatusCode);
    }

    [Fact]
    public async Task Audit_entries_are_written_with_user_and_details()
    {
        var admin = await factory.AdminAsync();
        await admin.PutJsonAsync("/api/settings", new { values = new Dictionary<string, string?> { ["audit.probe"] = "1" } });

        var page = await (await admin.GetAsync("/api/audit?action=settings.updated&pageSize=5")).ReadAsync<PagedResult<AuditEntryDto>>();
        var entry = page.Items.First();
        Assert.Equal(WebScanFactory.AdminUserName, entry.UserName);
        Assert.NotNull(entry.UserId);
        Assert.Equal("settings", entry.EntityType);
        Assert.Contains("audit.probe", entry.Details!.Value.GetProperty("keys").EnumerateArray().Select(k => k.GetString()));
        Assert.True(page.Total >= 1);
        Assert.Equal(5, page.PageSize);
    }

    [Fact]
    public async Task Secret_protector_round_trips_and_persists_keys_in_database()
    {
        var protector = factory.Services.GetRequiredService<ISecretProtector>();
        var cipher = protector.Protect("dojo-api-key");
        Assert.NotEqual("dojo-api-key", cipher);
        Assert.Equal("dojo-api-key", protector.Unprotect(cipher));

        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<InfraDbContext>();
        Assert.True(await db.DataProtectionKeys.AnyAsync());
    }

    [Fact]
    public async Task Display_names_and_audit_details_are_encrypted_at_rest_with_aes_gcm_but_returned_in_plaintext()
    {
        var admin = await factory.AdminAsync();
        var userName = $"enc-{Guid.NewGuid():N}"[..20];
        var created = await (await admin.PostJsonAsync("/api/users",
            new { userName, displayName = "Jane Confidential", password = "Initial-Password-1", roles = new[] { Roles.Viewer } })).ReadAsync<UserDto>();
        (await admin.PutJsonAsync($"/api/users/{created.Id}", new { displayName = "Jane Renamed" })).EnsureSuccessStatusCode();

        await using var connection = new NpgsqlConnection(factory.ConnectionString);
        await connection.OpenAsync();
        async Task<string> RawAsync(string sql)
        {
            await using var cmd = new NpgsqlCommand(sql, connection) { Parameters = { new() { Value = created.Id.ToString() } } };
            return (string)(await cmd.ExecuteScalarAsync())!;
        }
        var displayName = await RawAsync("""SELECT "DisplayName" FROM identity.users WHERE "Id"::text = $1""");
        var details = await RawAsync("""SELECT "Details" FROM infra.audit_entries WHERE "EntityId" = $1 AND "Action" = 'user.updated'""");
        Assert.All(new[] { displayName, details }, v => Assert.StartsWith(FieldEncryptor.Prefix, v));
        Assert.All(new[] { displayName, details }, v => Assert.DoesNotContain("Jane", v));

        Assert.Contains((await (await admin.GetAsync("/api/users")).ReadAsync<List<UserDto>>()), u => u.DisplayName == "Jane Renamed");
        var audit = await (await admin.GetAsync("/api/audit?action=user.updated&pageSize=100")).ReadAsync<PagedResult<AuditEntryDto>>();
        Assert.Equal("Jane Renamed", audit.Items.Single(e => e.EntityId == created.Id.ToString()).Details!.Value.GetProperty("displayName").GetString());

        // Keys of a fresh key ring are AES-256-GCM.
        var key = factory.Services.GetRequiredService<IKeyManager>().GetAllKeys().MaxBy(k => k.ActivationDate)!;
        Assert.Equal("AES_256_GCM", key.Descriptor.ExportToXml().SerializedDescriptorElement.Element("encryption")?.Attribute("algorithm")?.Value);
    }

    [Fact]
    public async Task Gzip_request_bodies_are_decompressed()
    {
        var admin = await factory.AdminAsync();
        var json = JsonSerializer.Serialize(new { values = new Dictionary<string, string> { ["gzip.probe"] = "yes" } });
        using var compressed = new MemoryStream();
        await using (var gzip = new GZipStream(compressed, CompressionLevel.Fastest, leaveOpen: true))
            await gzip.WriteAsync(Encoding.UTF8.GetBytes(json));

        var content = new ByteArrayContent(compressed.ToArray());
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        content.Headers.ContentEncoding.Add("gzip");
        var response = await admin.PutAsync("/api/settings", content);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("yes", (await response.ReadAsync<SettingsDto>()).Values["gzip.probe"]);
    }
}
