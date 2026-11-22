using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WebScan.Contracts;
using WebScan.Discovery.UnitTests.Infrastructure;
using WebScan.Server.Infrastructure.Persistence;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Discovery.Api;

namespace WebScan.Discovery.UnitTests;

[Collection(DbCollection.Name)]
public class EncryptionAtRestTests(TestApp app) : IAsyncLifetime
{
    private const string Banner = "SSH-2.0-OpenSSH_9.6 build-host-secret";
    private readonly Scenario _s = new(app);

    public Task InitializeAsync() => app.ResetAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private Task<List<string>> RawAsync(string sql) => _s.QueryAsync(db => db.Database.SqlQueryRaw<string>(sql).ToListAsync());

    private async Task<Guid> SeedAsync()
    {
        var ssh = _s.Service("10.9.0.1", 22, "ssh", "OpenSSH", "9.6");
        await _s.RunAsync(Scenario.Coverage(["10.9.0.0/24"]), 3, _s.HostUp("10.9.0.1"), _s.Port("10.9.0.1", 22),
            ssh with { Service = ssh.Service! with { Banner = Banner } }, _s.Signature("10.9.0.1", 22, "weak-kex", "medium", "kex: diffie-hellman-group1"));
        var id = await _s.QueryAsync(db => db.Hosts.Select(h => h.Id).SingleAsync());
        var annotation = new { description = "Jump host of the payment team", owner = "alice@example.com", tags = Array.Empty<string>() };
        (await app.Client(Roles.Editor).PutAsJsonAsync($"/api/assets/hosts/{id}/annotation", annotation, ContractJson.Options)).EnsureSuccessStatusCode();
        return id;
    }

    private async Task AssertApiReturnsPlaintextAsync(Guid id)
    {
        var detail = (await app.Client(Roles.Viewer).GetFromJsonAsync<HostDetailDto>($"/api/assets/hosts/{id}", ContractJson.Options))!;
        Assert.Equal(Banner, detail.Services.Single().Banner);
        Assert.Equal(("kex: diffie-hellman-group1", "http://10.9.0.1:22/"), (detail.Findings.Single().Evidence, detail.Findings.Single().MatchedUrl));
        Assert.Equal(("Jump host of the payment team", "alice@example.com"), (detail.Annotation!.Description, detail.Annotation.Owner));
        var observations = (await app.Client(Roles.Viewer).GetFromJsonAsync<PagedResult<ObservationDto>>($"/api/observations?hostId={id}", ContractJson.Options))!;
        Assert.Contains(observations.Items, o => o.Observation.Service?.Banner == Banner);
    }

    private static readonly string[] EncryptedColumns =
    [
        """SELECT "Payload" AS "Value" FROM discovery.observations""",
        """SELECT "Banner" AS "Value" FROM discovery.services WHERE "Banner" IS NOT NULL""",
        """SELECT "Evidence" AS "Value" FROM discovery.signature_matches UNION ALL SELECT "MatchedUrl" FROM discovery.signature_matches""",
        """SELECT "Description" AS "Value" FROM discovery.asset_annotations UNION ALL SELECT "Owner" FROM discovery.asset_annotations""",
        """SELECT "Description" AS "Value" FROM discovery.asset_annotation_revisions UNION ALL SELECT "Owner" FROM discovery.asset_annotation_revisions""",
    ];

    private async Task AssertColumnsHoldCiphertextAsync()
    {
        foreach (var sql in EncryptedColumns)
        {
            var values = await RawAsync(sql);
            Assert.NotEmpty(values);
            Assert.All(values, v => Assert.StartsWith(FieldEncryptor.Prefix, v));
            Assert.All(values, v => Assert.DoesNotContain("OpenSSH", v));
        }
    }

    [Fact]
    public async Task Sensitive_columns_hold_ciphertext_while_the_api_returns_plaintext()
    {
        var id = await SeedAsync();

        await AssertColumnsHoldCiphertextAsync();
        await AssertApiReturnsPlaintextAsync(id);
        // Lookup columns stay plaintext (filtered/joined in SQL).
        Assert.Equal(["10.9.0.1"], await RawAsync("""SELECT "Address" AS "Value" FROM discovery.services"""));
    }

    [Fact]
    public async Task Legacy_plaintext_is_readable_and_the_backfill_encrypts_it_once()
    {
        var id = await SeedAsync();
        // An existing deployment: rows written before encryption hold plaintext (Payload was jsonb).
        var payload = await _s.QueryAsync(db => db.Observations.Where(o => o.Kind == ObservationKind.Service).Select(o => o.Payload).SingleAsync());
        await _s.QueryAsync(db => db.Database.ExecuteSqlAsync($"""
            UPDATE discovery.observations SET "Payload" = {payload} WHERE "Kind" = 'Service';
            UPDATE discovery.services SET "Banner" = {Banner};
            UPDATE discovery.signature_matches SET "Evidence" = 'kex: diffie-hellman-group1', "MatchedUrl" = 'http://10.9.0.1:22/';
            UPDATE discovery.asset_annotations SET "Description" = 'Jump host of the payment team', "Owner" = 'alice@example.com';
            UPDATE discovery.asset_annotation_revisions SET "Description" = 'Jump host of the payment team', "Owner" = 'alice@example.com';
            """));
        Assert.Equal([Banner], await RawAsync("""SELECT "Banner" AS "Value" FROM discovery.services"""));
        await AssertApiReturnsPlaintextAsync(id);

        var backfill = ActivatorUtilities.CreateInstance<FieldEncryptionBackfill>(app.Services);
        Assert.Equal(8, await backfill.RunAsync(CancellationToken.None));
        Assert.Equal(0, await backfill.RunAsync(CancellationToken.None));

        await AssertColumnsHoldCiphertextAsync();
        await AssertApiReturnsPlaintextAsync(id);
    }

    [Fact]
    public async Task Service_search_does_not_match_the_encrypted_banner()
    {
        await SeedAsync();
        var page = (await app.Client(Roles.Viewer).GetFromJsonAsync<PagedResult<ServiceDto>>("/api/assets/services?search=build-host-secret", ContractJson.Options))!;
        Assert.Empty(page.Items);
        page = (await app.Client(Roles.Viewer).GetFromJsonAsync<PagedResult<ServiceDto>>("/api/assets/services?search=openssh", ContractJson.Options))!;
        Assert.Equal(Banner, page.Items.Single().Banner);
    }
}
