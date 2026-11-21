using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Testcontainers.PostgreSql;
using WebScan.Contracts;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Identity;
using Wolverine;

namespace WebScan.Server.UnitTests.Integration;

/// <summary>System clock plus an adjustable offset (tests run sequentially within the collection).</summary>
public sealed class TestTimeProvider : TimeProvider
{
    public TimeSpan Offset { get; set; }
    public override DateTimeOffset GetUtcNow() => base.GetUtcNow() + Offset;
}

/// <summary>One PostgreSQL container and one server host shared by every integration test (collection "server").</summary>
public sealed class WebScanFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    public const string AdminUserName = "admin";
    public const string AdminPassword = "Bootstrap-Admin-Pass-1";
    public const string BootstrapEnrollmentToken = "compose-bootstrap-enrollment-token";

    private readonly PostgreSqlContainer _postgres = new PostgreSqlBuilder("postgres:17-alpine").Build();

    static WebScanFactory() => DockerApiVersion.Configure();

    public TestTimeProvider Time { get; } = new();
    public string ConnectionString => _postgres.GetConnectionString();

    public async Task InitializeAsync()
    {
        await _postgres.StartAsync();
        _ = Server; // start the host: migrations, seeding, Wolverine
    }

    async Task IAsyncLifetime.DisposeAsync()
    {
        await DisposeAsync();
        await _postgres.DisposeAsync();
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("ConnectionStrings:WebScan", _postgres.GetConnectionString());
        builder.UseSetting("Auth:Jwt:SigningKey", "integration-tests-signing-key-0123456789abcdef");
        builder.UseSetting("Bootstrap:AdminUserName", AdminUserName);
        builder.UseSetting("Bootstrap:AdminPassword", AdminPassword);
        builder.UseSetting("Agents:BootstrapEnrollmentToken", BootstrapEnrollmentToken);
        builder.UseSetting("Agents:BootstrapEnrollmentZones", "lab");
        builder.UseSetting("Agents:OfflineCheckIntervalSeconds", "3600");
        builder.UseSetting("Networks:SeedScopePolicy:Allowed", "10.0.0.0/8,172.30.0.0/24,example.com,*.example.com");
        builder.UseSetting("Networks:SeedScopePolicy:Excluded", "10.255.0.0/16");
        builder.ConfigureTestServices(services =>
        {
            services.AddSingleton<TimeProvider>(Time);
            services.AddSingleton<IScanEventPublisher>(Events);
            services.AddSingleton<IStartupFilter, HubProbeStartupFilter>();
            services.RunWolverineInSoloMode();
            services.ConfigureWolverine(opts => opts.Discovery.IncludeAssembly(typeof(WebScanFactory).Assembly));
        });
    }

    /// <summary>Stands in for the Scanning module's publisher (optional dependency of the Agents module).</summary>
    public RecordingScanEventPublisher Events { get; } = new();

    public sealed class RecordingScanEventPublisher : IScanEventPublisher
    {
        public ConcurrentQueue<ScanExecutionEvent> Published { get; } = new();

        public Task PublishAsync(ScanExecutionEvent evt, CancellationToken ct = default)
        {
            Published.Enqueue(evt);
            return Task.CompletedTask;
        }
    }

    /// <summary><c>/hubs/probe</c>: 200 when the user scheme authenticates the request (SignalR-style token in the query).</summary>
    private sealed class HubProbeStartupFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            // Not app.Map: that moves the path into PathBase, whereas hub endpoints keep the full request path.
            app.Use(async (ctx, nextMiddleware) =>
            {
                if (ctx.Request.Path.StartsWithSegments("/hubs/probe"))
                    ctx.Response.StatusCode = (await ctx.AuthenticateAsync(AuthSchemes.User)).Succeeded ? 200 : 401;
                else
                    await nextMiddleware(ctx);
            });
            next(app);
        };
    }

    public HttpClient CreateClient(string? accessToken)
    {
        var client = CreateClient();
        if (accessToken is not null) client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return client;
    }

    public async Task<HttpClient> LoginAsync(string userName, string password)
    {
        var response = await CreateClient().PostAsJsonAsync("/api/auth/login", new { userName, password });
        response.EnsureSuccessStatusCode();
        var login = await response.ReadAsync<LoginResponse>();
        return CreateClient(login.AccessToken);
    }

    public Task<HttpClient> AdminAsync() => LoginAsync(AdminUserName, AdminPassword);

    /// <summary>Creates a user with a single role and returns a client logged in as that user.</summary>
    public async Task<HttpClient> UserWithRoleAsync(string role)
    {
        var admin = await AdminAsync();
        var userName = $"{role.ToLowerInvariant()}-{Guid.NewGuid():N}"[..30];
        const string password = "Role-User-Password-1";
        var created = await admin.PostAsJsonAsync("/api/users", new { userName, password, roles = new[] { role } });
        created.EnsureSuccessStatusCode();
        return await LoginAsync(userName, password);
    }
}

[CollectionDefinition("server")]
public sealed class ServerCollection : ICollectionFixture<WebScanFactory>;

public static class HttpTestExtensions
{
    public static async Task<T> ReadAsync<T>(this HttpResponseMessage response) =>
        (await response.Content.ReadFromJsonAsync<T>(ContractJson.Options))!;

    public static Task<HttpResponseMessage> PostJsonAsync<T>(this HttpClient client, string url, T body) =>
        client.PostAsJsonAsync(url, body, ContractJson.Options);

    public static Task<HttpResponseMessage> PutJsonAsync<T>(this HttpClient client, string url, T body) =>
        client.PutAsJsonAsync(url, body, ContractJson.Options);
}
