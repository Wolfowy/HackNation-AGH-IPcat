using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Testcontainers.PostgreSql;
using WebScan.Contracts;
using WebScan.Server.Infrastructure.Persistence;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Scanning;
using WebScan.Server.Modules.Scanning.Persistence;
using WebScan.Server.Modules.Scanning.Planning;
using WebScan.Server.Modules.Scheduling;
using WebScan.Server.Modules.Workflows;
using WebScan.Server.Modules.Workflows.Runtime;
using Wolverine;
using Wolverine.EntityFrameworkCore;
using Wolverine.Postgresql;

namespace WebScan.Scheduling.UnitTests.Support;

[CollectionDefinition(Name)]
public sealed class DbCollection : ICollectionFixture<TestHost>
{
    public const string Name = "postgres";
}

/// <summary>
/// Minimal server host for the three modules: PostgreSQL (Testcontainers), Wolverine with PostgreSQL persistence and the
/// EF Core outbox, header-based test authentication, fakes for the ports of other streams. Background loops are off;
/// tests drive sweeps and ticks explicitly (Wolverine handlers still run).
/// </summary>
public sealed class TestHost : IAsyncLifetime
{
    static TestHost()
    {
        // Older Docker engines (API < 1.44) reject Testcontainers' default API version: pin the server's version.
        if (Environment.GetEnvironmentVariable("DOCKER_API_VERSION") is not null) return;
        try
        {
            using var docker = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("docker", "version --format {{.Server.APIVersion}}")
                { RedirectStandardOutput = true, RedirectStandardError = true })!;
            var version = docker.StandardOutput.ReadToEnd().Trim();
            docker.WaitForExit(10_000);
            if (Version.TryParse(version, out var v) && v < new Version(1, 44)) Environment.SetEnvironmentVariable("DOCKER_API_VERSION", version);
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // No docker CLI: keep Testcontainers defaults.
        }
    }

    private readonly PostgreSqlContainer _postgres = new PostgreSqlBuilder().WithImage("postgres:17-alpine").Build();

    public WebApplication App { get; private set; } = null!;
    public ManualTimeProvider Time { get; } = new(DateTimeOffset.UtcNow);
    public FakeAgentDirectory Agents { get; } = new();
    public FakeNetworkScope Scope { get; } = new();
    public FakeDiscoveryProcessor Discovery { get; } = new();
    public FakeFindingPublisher Findings { get; } = new();
    public FakeSignatureCatalog Signatures { get; } = new();
    public RecordingAuditLog Audit { get; } = new();
    public MessageLog Messages { get; } = new();
    public string ConnectionString => _postgres.GetConnectionString();

    public async Task InitializeAsync()
    {
        await _postgres.StartAsync();
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        builder.WebHost.UseTestServer();
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:WebScan"] = ConnectionString,
            ["Scanning:SweeperEnabled"] = "false",
            ["Workflows:TickerEnabled"] = "false",
        });

        builder.UseWolverine(opts =>
        {
            opts.ApplicationAssembly = typeof(TestHost).Assembly;
            opts.Discovery.IncludeAssembly(typeof(ScanningModule).Assembly);
            opts.Discovery.IncludeAssembly(typeof(WorkflowsModule).Assembly);
            opts.Discovery.IncludeAssembly(typeof(SchedulingModule).Assembly);
            opts.PersistMessagesWithPostgresql(ConnectionString, "wolverine");
            opts.UseEntityFrameworkCoreTransactions();
            opts.Policies.UseDurableLocalQueues();
            opts.Durability.Mode = DurabilityMode.Solo;
        });

        var services = builder.Services;
        services.AddSingleton<TimeProvider>(Time);
        services.AddSingleton<IAgentDirectory>(Agents);
        services.AddSingleton<INetworkScopeService>(Scope);
        services.AddSingleton<IDiscoveryRunProcessor>(Discovery);
        services.AddSingleton<IFindingPublisher>(Findings);
        services.AddSingleton<ISignatureCatalog>(Signatures);
        services.AddSingleton<IAuditLog>(Audit);
        services.AddDataProtection().UseEphemeralDataProtectionProvider(); // keys for encrypted columns
        services.AddSingleton(Messages);
        services.AddProblemDetails();
        services.ConfigureHttpJsonOptions(o => ContractJson.Configure(o.SerializerOptions));
        services.AddAuthentication(TestAuthHandler.Scheme).AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.Scheme, _ => { });
        services.AddAuthorization(o =>
        {
            o.AddPolicy(Policies.Agent, p => p.RequireClaim(WebScanClaims.AgentId));
            o.AddPolicy(Policies.CanRead, p => p.RequireRole(Roles.All));
            o.AddPolicy(Policies.CanEdit, p => p.RequireRole(Roles.Administrator, Roles.Manager, Roles.Editor));
            o.AddPolicy(Policies.CanManage, p => p.RequireRole(Roles.Administrator, Roles.Manager));
            o.AddPolicy(Policies.AdminOnly, p => p.RequireRole(Roles.Administrator));
        });
        services.AddScanningModule(builder.Configuration).AddWorkflowsModule(builder.Configuration).AddSchedulingModule(builder.Configuration);

        App = builder.Build();
        await App.Services.MigrateModuleDatabasesAsync();
        App.UseAuthentication();
        App.UseAuthorization();
        App.MapScanningEndpoints();
        App.MapWorkflowsEndpoints();
        App.MapSchedulingEndpoints();
        await App.StartAsync();
        await SetLimitsAsync(new ScanLimits { MaxRatePerSecondGlobal = 10_000_000, MaxConcurrentJobsPerSubnet = 1000, MaxConcurrentJobsPerInterface = 100 });
    }

    public async Task DisposeAsync()
    {
        await App.StopAsync();
        await App.DisposeAsync();
        await _postgres.DisposeAsync();
    }

    public HttpClient UserClient(string role = Roles.Administrator)
    {
        var client = App.GetTestClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.RolesHeader, role);
        return client;
    }

    public HttpClient AgentClient(string agentId)
    {
        var client = App.GetTestClient();
        client.DefaultRequestHeaders.Add(TestAuthHandler.AgentHeader, agentId);
        return client;
    }

    public async Task<T> WithScopeAsync<T>(Func<IServiceProvider, Task<T>> action)
    {
        await using var scope = App.Services.CreateAsyncScope();
        return await action(scope.ServiceProvider);
    }

    public Task WithScopeAsync(Func<IServiceProvider, Task> action) => WithScopeAsync(async sp => { await action(sp); return true; });

    public Task<TResult> DbAsync<TResult>(Func<ScanningDbContext, Task<TResult>> query) =>
        WithScopeAsync(sp => query(sp.GetRequiredService<ScanningDbContext>()));

    public Task SetLimitsAsync(ScanLimits limits) => WithScopeAsync(sp => sp.GetRequiredService<ScanLimitsStore>().SaveAsync(limits));

    /// <summary>Isolation between tests sharing the database: nothing queued or leased survives a test.</summary>
    public Task ResetQueueAsync() => DbAsync(db => db.Jobs.Where(j => j.Status == JobStatus.Queued || j.Status == JobStatus.Leased)
        .ExecuteUpdateAsync(s => s.SetProperty(j => j.Status, JobStatus.Cancelled)));

    public Task TickAsync() => WithScopeAsync(sp => sp.GetRequiredService<IWorkflowRuntime>().TickAsync());

    /// <summary>Ticks the workflow runtime until the condition holds (Wolverine handlers advance runs in the background too).</summary>
    public async Task WaitUntilAsync(Func<Task<bool>> condition, string what, int timeoutSeconds = 30)
    {
        var deadline = DateTime.UtcNow.AddSeconds(timeoutSeconds);
        while (DateTime.UtcNow < deadline)
        {
            if (await condition()) return;
            await TickAsync();
            if (await condition()) return;
            await Task.Delay(100);
        }
        throw new TimeoutException($"Timed out waiting for: {what}. Wolverine dead letters: {string.Join(" | ", await DeadLettersAsync())}");
    }

    /// <summary>Messages Wolverine could not handle (e.g. handler code generation failures).</summary>
    public Task<List<string>> DeadLettersAsync() => DbAsync(db => db.Database.SqlQueryRaw<string>(
        "SELECT message_type || ': ' || coalesce(exception_message, '') AS \"Value\" FROM wolverine.wolverine_dead_letters").ToListAsync());

    public Task<ScanRun> RunAsync(Guid runId) => DbAsync(db => db.ScanRuns.AsNoTracking().FirstAsync(r => r.Id == runId));

    public async Task<JobClaimResponse> ClaimAsync(string agentId, int maxJobs = 10)
    {
        var response = await AgentClient(agentId).PostAsJsonAsync(AgentApiRoutes.Claim, new JobClaimRequest { MaxJobs = maxJobs }, ContractJson.Options);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<JobClaimResponse>(ContractJson.Options))!;
    }

    /// <summary>Simulated agent: sends one result batch per assignment and completes it.</summary>
    public async Task CompleteAsync(string agentId, JobAssignment a, IReadOnlyList<DiscoveryObservation> observations)
    {
        var client = AgentClient(agentId);
        var batch = new ScanResultBatch
        {
            BatchId = Guid.NewGuid(), JobId = a.Job.JobId, LeaseId = a.Lease.LeaseId, Sequence = 0, CreatedAt = DateTimeOffset.UtcNow, Observations = observations,
        };
        (await client.PostAsJsonAsync(AgentApiRoutes.JobResults(a.Job.JobId), batch, ContractJson.Options)).EnsureSuccessStatusCode();
        var completion = new JobCompletionRequest
        {
            LeaseId = a.Lease.LeaseId, TotalBatches = 1, Coverage = new JobCoverage { Complete = true },
            ToolRun = new ToolRunInfo { ToolId = a.Job.Tool.ToolId ?? "fake", DurationMs = 1000 },
        };
        (await client.PostAsJsonAsync(AgentApiRoutes.JobComplete(a.Job.JobId), completion, ContractJson.Options)).EnsureSuccessStatusCode();
    }

    /// <summary>Claims and completes jobs until none are left for this agent; returns the number of jobs processed.</summary>
    public async Task<int> DrainAsync(string agentId, Func<ScanJob, IReadOnlyList<DiscoveryObservation>> results, int maxRounds = 100)
    {
        var processed = 0;
        for (var round = 0; round < maxRounds; round++)
        {
            var claim = await ClaimAsync(agentId, 50);
            if (claim.Assignments.Count == 0) return processed;
            foreach (var a in claim.Assignments) await CompleteAsync(agentId, a, results(a.Job));
            processed += claim.Assignments.Count;
        }
        return processed;
    }
}

public sealed class TestAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string Scheme = "Test";
    public const string AgentHeader = "X-Test-Agent";
    public const string RolesHeader = "X-Test-Roles";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        List<Claim> claims;
        if (Request.Headers.TryGetValue(AgentHeader, out var agent))
            claims = [new Claim(WebScanClaims.AgentId, agent.ToString()), new Claim(ClaimTypes.Name, agent.ToString())];
        else if (Request.Headers.TryGetValue(RolesHeader, out var roles) || Request.Query.TryGetValue("roles", out roles))
            claims = [new Claim(ClaimTypes.NameIdentifier, "user-1"), new Claim(ClaimTypes.Name, "tester"), .. roles.ToString().Split(',').Select(r => new Claim(ClaimTypes.Role, r))];
        else
            return Task.FromResult(AuthenticateResult.NoResult());
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity(claims, Scheme)), Scheme)));
    }
}
