using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Wolverine;

namespace WebScan.E2ETests.Infrastructure;

/// <summary>Full server (all modules, real PostgreSQL, Wolverine local queues) hosted in-process.</summary>
public sealed class E2EServerFactory(string connectionString, IReadOnlyDictionary<string, string?>? overrides = null)
    : WebApplicationFactory<Program>
{
    public const string AdminUserName = "admin";
    public const string AdminPassword = "E2E-Admin-Password-1";
    public const string EnrollmentToken = "e2e-bootstrap-enrollment-token-0123456789";

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        var settings = new Dictionary<string, string?>
        {
            ["ConnectionStrings:WebScan"] = connectionString,
            ["Auth:Jwt:SigningKey"] = "e2e-tests-signing-key-0123456789abcdef0123456789",
            ["Bootstrap:AdminUserName"] = AdminUserName,
            ["Bootstrap:AdminPassword"] = AdminPassword,
            ["Agents:BootstrapEnrollmentToken"] = EnrollmentToken,
            ["Agents:BootstrapEnrollmentZones"] = "lab-a,lab-b",
            ["Agents:HeartbeatTimeoutSeconds"] = "8",
            ["Agents:OfflineCheckIntervalSeconds"] = "2",
            ["Networks:SeedScopePolicy:Allowed"] = "10.50.0.0/16,10.60.0.0/16",
            ["Discovery:IngestSettleSeconds"] = "1",
        };
        foreach (var (k, v) in overrides ?? new Dictionary<string, string?>()) settings[k] = v;
        foreach (var (k, v) in settings) builder.UseSetting(k, v);
        builder.ConfigureTestServices(services => services.RunWolverineInSoloMode());
    }

    public async Task<ApiClient> AdminClientAsync()
    {
        var client = new ApiClient(CreateClient());
        await client.LoginAsync(AdminUserName, AdminPassword);
        return client;
    }
}
