using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WebScan.Agent;

namespace WebScan.E2ETests.Infrastructure;

/// <summary>
/// Real scanner agent (same composition as the Worker) running in-process against the test server through the
/// TestServer handler. Uses only the synthetic "fake" tool, so no packet ever leaves the machine.
/// </summary>
public sealed class InProcessAgent : IAsyncDisposable
{
    private readonly IHost _host;
    private readonly string _dataDir;

    public string AgentId { get; }
    public IConfiguration Configuration => _host.Services.GetRequiredService<IConfiguration>();

    /// <summary>Changes agent configuration at runtime and fires the reload token (IOptionsMonitor consumers see it).</summary>
    public void UpdateConfiguration(IReadOnlyDictionary<string, string?> values)
    {
        var root = (IConfigurationRoot)Configuration;
        foreach (var (key, value) in values) root[key] = value;
        root.Reload();
    }

    private InProcessAgent(string agentId, IHost host, string dataDir)
    {
        AgentId = agentId;
        _host = host;
        _dataDir = dataDir;
    }

    /// <param name="interfaceCidr">Simulated interface address, e.g. "10.50.0.100/24" — decides reachability.</param>
    public static async Task<InProcessAgent> StartAsync(E2EServerFactory server, string agentId, string interfaceCidr,
        IReadOnlyDictionary<string, string?>? extra = null)
    {
        var dataDir = Directory.CreateTempSubdirectory($"webscan-e2e-{agentId}-").FullName;
        var toolsDir = Directory.CreateDirectory(Path.Combine(dataDir, "tools.d")).FullName;
        File.Copy(Path.Combine(RepoRoot(), "src", "Agent", "Worker", "tools.d", "fake.json"), Path.Combine(toolsDir, "fake.json"));

        var settings = new Dictionary<string, string?>
        {
            ["Agent:ServerUrl"] = server.Server.BaseAddress.ToString(),
            ["Agent:AgentId"] = agentId,
            ["Agent:EnrollmentToken"] = E2EServerFactory.EnrollmentToken,
            ["Agent:DataDirectory"] = dataDir,
            ["Agent:EnableFakeTools"] = "true",
            ["Agent:ToolManifestPaths:0"] = toolsDir,
            ["Agent:MaxConcurrentJobs"] = "4",
            ["Agent:MaxRatePerSecond"] = "2000",
            ["Agent:HeartbeatIntervalSeconds"] = "2",
            ["Agent:ResultBatchFlushSeconds"] = "1",
            ["Agent:ErrorBackoffSeconds"] = "1",
            ["Agent:StaticInterfaces:0:Name"] = "lab0",
            ["Agent:StaticInterfaces:0:Addresses:0"] = interfaceCidr,
            ["Agent:FakeTools:AliveRatio"] = "0.5",
            ["Agent:FakeTools:DelayPerTargetMs"] = "0",
        };
        foreach (var (k, v) in extra ?? new Dictionary<string, string?>()) settings[k] = v;

        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { EnvironmentName = "Development" });
        builder.Configuration.Sources.Clear();
        builder.Configuration.AddInMemoryCollection(settings);
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        builder.Services.AddScannerAgent(builder.Configuration, http => http.ConfigurePrimaryHttpMessageHandler(() => server.Server.CreateHandler()));
        var host = builder.Build();
        await host.StartAsync();
        return new InProcessAgent(agentId, host, dataDir);
    }

    /// <summary>Simulates abrupt connection loss: the host stops without a graceful flush.</summary>
    public async Task KillAsync()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(1));
        try { await _host.StopAsync(cts.Token); } catch (OperationCanceledException) { }
        _host.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        try { await _host.StopAsync(TimeSpan.FromSeconds(5)); } catch (ObjectDisposedException) { }
        _host.Dispose();
        try { Directory.Delete(_dataDir, recursive: true); } catch (IOException) { }
    }

    public static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "WebScan.slnx"))) dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("Repository root not found.");
    }
}
