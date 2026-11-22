using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Testcontainers.PostgreSql;
using WebScan.Contracts;
using WebScan.Server.Infrastructure.Persistence;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Kernel.Scanning;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Analytics;
using WebScan.Server.Modules.Discovery;
using WebScan.Server.Modules.Discovery.Persistence;
using WebScan.Server.Modules.Integrations;
using WebScan.Server.Modules.Integrations.DefectDojo;
using WebScan.Server.Modules.Signatures;
using Wolverine;

namespace WebScan.Discovery.UnitTests.Infrastructure;

[CollectionDefinition(Name)]
public sealed class DbCollection : ICollectionFixture<TestApp>
{
    public const string Name = "postgres";
}

/// <summary>
/// Minimal host for the four stream-D modules on a real PostgreSQL (Testcontainers) with Wolverine (in-process),
/// header-based test authentication, and fakes for the stream-A services (audit, secrets, current user).
/// </summary>
public sealed class TestApp : IAsyncLifetime
{
    private PostgreSqlContainer? _postgres;
    private WebApplication? _app;

    public ManualClock Clock { get; } = new(new DateTimeOffset(2026, 11, 2, 10, 0, 0, TimeSpan.Zero));
    public FakeAuditLog Audit { get; } = new();
    public FakeHttpHandler DefectDojo { get; } = new();
    public RecordingScanEventPublisher ScanEvents { get; } = new();
    public FakeNetworkScope NetworkScope { get; } = new();
    public FakeRecentScans RecentScans { get; } = new();
    public IServiceProvider Services => _app!.Services;

    public async Task InitializeAsync()
    {
        // Docker Engine 20.10 on the shared build machine only speaks API 1.41 (Testcontainers 4 defaults to 1.44); an explicit setting wins.
        if (Environment.GetEnvironmentVariable("DOCKER_API_VERSION") is null) Environment.SetEnvironmentVariable("DOCKER_API_VERSION", "1.41");
        _postgres = new PostgreSqlBuilder("postgres:17-alpine").Build();
        await _postgres.StartAsync();
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        builder.WebHost.UseTestServer();
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:WebScan"] = _postgres.GetConnectionString(),
            ["Discovery:IngestSettleSeconds"] = "0",
        });
        builder.Host.UseWolverine(opts =>
        {
            opts.Durability.Mode = DurabilityMode.Solo;
            opts.Discovery.IncludeAssembly(typeof(DiscoveryModule).Assembly);
        });

        var services = builder.Services;
        services.AddDiscoveryModule(builder.Configuration).AddAnalyticsModule(builder.Configuration)
            .AddSignaturesModule(builder.Configuration).AddIntegrationsModule(builder.Configuration);
        services.AddSingleton<TimeProvider>(Clock);
        services.AddSingleton<IAuditLog>(Audit);
        services.AddSingleton<IScanEventPublisher>(ScanEvents);
        services.AddSingleton<ISecretProtector, FakeSecretProtector>();
        services.AddDataProtection().UseEphemeralDataProtectionProvider(); // keys for encrypted columns
        services.AddSingleton<INetworkScopeService>(NetworkScope);
        services.AddSingleton<IRecentScanRunReader>(RecentScans);
        services.AddHttpContextAccessor();
        services.AddScoped<ICurrentUser, HttpContextCurrentUser>();
        services.ConfigureHttpJsonOptions(o => ContractJson.Configure(o.SerializerOptions));
        services.AddHttpClient(DefectDojoClient.VerifiedTlsClient).ConfigurePrimaryHttpMessageHandler(() => DefectDojo);
        services.AddAuthentication(TestAuthHandler.Scheme).AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.Scheme, null);
        services.AddAuthorization(o =>
        {
            o.AddPolicy(Policies.CanRead, p => p.RequireRole(Roles.Viewer, Roles.Editor, Roles.Manager, Roles.Administrator));
            o.AddPolicy(Policies.CanEdit, p => p.RequireRole(Roles.Editor, Roles.Manager, Roles.Administrator));
            o.AddPolicy(Policies.CanManage, p => p.RequireRole(Roles.Manager, Roles.Administrator));
            o.AddPolicy(Policies.AdminOnly, p => p.RequireRole(Roles.Administrator));
        });

        _app = builder.Build();
        _app.UseAuthentication();
        _app.UseAuthorization();
        _app.MapDiscoveryEndpoints();
        _app.MapAnalyticsEndpoints();
        _app.MapSignaturesEndpoints();
        _app.MapIntegrationsEndpoints();
        await _app.Services.MigrateModuleDatabasesAsync();
        await _app.StartAsync();
    }

    public async Task DisposeAsync()
    {
        if (_app is not null) await _app.DisposeAsync();
        if (_postgres is not null) await _postgres.DisposeAsync();
    }

    /// <summary>HTTP client authenticated with the given role (null = anonymous).</summary>
    public HttpClient Client(string? role = Roles.Administrator)
    {
        var client = _app!.GetTestClient();
        if (role is not null)
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.UserHeader, $"test-{role.ToLowerInvariant()}");
            client.DefaultRequestHeaders.Add(TestAuthHandler.RolesHeader, role);
        }
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        return client;
    }

    public async Task<T> WithScopeAsync<T>(Func<IServiceProvider, Task<T>> action)
    {
        await using var scope = Services.CreateAsyncScope();
        return await action(scope.ServiceProvider);
    }

    public Task WithScopeAsync(Func<IServiceProvider, Task> action) => WithScopeAsync(async sp => { await action(sp); return 0; });

    /// <summary>Clears discovery/integration data and user-created signatures; keeps the seeded built-ins.</summary>
    public async Task ResetAsync()
    {
        await WithScopeAsync(async sp =>
        {
            var db = sp.GetRequiredService<DiscoveryDbContext>();
            await db.Database.ExecuteSqlRawAsync("""
                TRUNCATE discovery.observations, discovery.processed_batches, discovery.run_processing, discovery.hosts, discovery.services,
                  discovery.technologies, discovery.certificates, discovery.http_snapshots, discovery.signature_matches, discovery.change_events,
                  discovery.asset_annotations, discovery.asset_annotation_revisions RESTART IDENTITY;
                TRUNCATE integrations.defectdojo_settings;
                DELETE FROM signatures.signature_versions WHERE "CreatedBy" <> 'system';
                DELETE FROM signatures.signatures s WHERE NOT EXISTS (SELECT 1 FROM signatures.signature_versions v WHERE v."SignatureId" = s."Id");
                UPDATE signatures.signatures SET "Status" = 'Approved', "ApprovedVersion" = 1, "LatestVersion" = 1;
                """);
        });
        Audit.Entries.Clear();
        ScanEvents.Events.Clear();
        DefectDojo.Reset();
        RecentScans.Runs.Clear();
    }
}

/// <summary>Scanning module stand-in for the dashboard's recent scans.</summary>
public sealed class FakeRecentScans : IRecentScanRunReader
{
    public List<ScanRunSummary> Runs { get; } = [];

    public Task<IReadOnlyList<ScanRunSummary>> GetRecentAsync(int count, CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<ScanRunSummary>>(Runs.Take(count).ToList());
}

public sealed class ManualClock(DateTimeOffset start) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = start;
    public override DateTimeOffset GetUtcNow() => Now;
    public void Advance(TimeSpan by) => Now += by;
}

public sealed class FakeAuditLog : IAuditLog
{
    public List<AuditEntry> Entries { get; } = [];

    public Task WriteAsync(AuditEntry entry, CancellationToken ct = default)
    {
        lock (Entries) Entries.Add(entry);
        return Task.CompletedTask;
    }
}

public sealed class RecordingScanEventPublisher : IScanEventPublisher
{
    public List<ScanExecutionEvent> Events { get; } = [];

    public Task PublishAsync(ScanExecutionEvent evt, CancellationToken ct = default)
    {
        lock (Events) Events.Add(evt);
        return Task.CompletedTask;
    }
}

/// <summary>Networks module stand-in: <see cref="Networks"/> maps network ids to include entries, <see cref="Zones"/> to zones (default "lab").</summary>
public sealed class FakeNetworkScope : INetworkScopeService
{
    public Dictionary<Guid, string[]> Networks { get; } = [];
    public Dictionary<Guid, string> Zones { get; } = [];

    public Task<ResolvedScope> ResolveAsync(IReadOnlyCollection<Guid> networkIds, CancellationToken ct = default) =>
        Task.FromResult(new ResolvedScope
        {
            Segments = networkIds.Where(Networks.ContainsKey)
                .Select(id => new ScopeSegment { NetworkId = id, NetworkName = id.ToString(), Zone = Zones.GetValueOrDefault(id, "lab"), Include = Networks[id] }).ToList(),
        });

    public Task<bool> IsAuthorizedAsync(string target, CancellationToken ct = default) => Task.FromResult(true);
}

public sealed class FakeSecretProtector : ISecretProtector
{
    public string Protect(string plaintext) => "enc:" + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(plaintext));
    public string Unprotect(string protectedValue) => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(protectedValue["enc:".Length..]));
}

public sealed class HttpContextCurrentUser(IHttpContextAccessor accessor) : ICurrentUser
{
    private ClaimsPrincipal? Principal => accessor.HttpContext?.User;
    public string? UserId => Principal?.FindFirstValue(ClaimTypes.NameIdentifier);
    public string? UserName => Principal?.Identity?.Name;
    public bool IsAuthenticated => Principal?.Identity?.IsAuthenticated == true;
    public bool IsInRole(string role) => Principal?.IsInRole(role) == true;
}

public sealed class TestAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string Scheme = "Test";
    public const string UserHeader = "X-Test-User";
    public const string RolesHeader = "X-Test-Roles";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(UserHeader, out var user)) return Task.FromResult(AuthenticateResult.NoResult());
        var claims = new List<Claim> { new(ClaimTypes.NameIdentifier, user.ToString()), new(ClaimTypes.Name, user.ToString()) };
        claims.AddRange(Request.Headers[RolesHeader].ToString().Split(',', StringSplitOptions.RemoveEmptyEntries).Select(r => new Claim(ClaimTypes.Role, r.Trim())));
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, Scheme));
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme)));
    }
}

/// <summary>Records requests and answers with queued (or default) responses.</summary>
public sealed class FakeHttpHandler : HttpMessageHandler
{
    private readonly Queue<Func<HttpRequestMessage, HttpResponseMessage>> _responses = new();
    public List<(HttpMethod Method, Uri Uri, string? Authorization, string? Body)> Requests { get; } = [];

    public void Enqueue(System.Net.HttpStatusCode status, string json) =>
        _responses.Enqueue(_ => new HttpResponseMessage(status) { Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json") });

    public void Reset()
    {
        _responses.Clear();
        Requests.Clear();
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct);
        Requests.Add((request.Method, request.RequestUri!, request.Headers.Authorization?.ToString(), body));
        return _responses.Count > 0
            ? _responses.Dequeue()(request)
            : new HttpResponseMessage(System.Net.HttpStatusCode.InternalServerError) { Content = new StringContent("{\"detail\":\"unexpected\"}") };
    }

    protected override void Dispose(bool disposing)
    {
        // Shared across HttpClientFactory handler rotations; never disposed by them.
    }
}
