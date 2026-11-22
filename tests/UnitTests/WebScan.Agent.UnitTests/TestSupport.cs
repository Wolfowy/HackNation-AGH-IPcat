using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using WebScan.Agent.Tools;
using WebScan.Agent.Tools.Abstractions;
using WebScan.Agent.Tools.Adapters;
using WebScan.Agent.Tools.Parsers;
using WebScan.Contracts;

namespace WebScan.Agent.UnitTests;

internal static class TestPaths
{
    public static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Fixtures", name);
    public static string ShippedManifests => Path.Combine(AppContext.BaseDirectory, "tools.d");
    public static string Plugins => Path.Combine(AppContext.BaseDirectory, "plugins");
}

internal sealed class TempDir : IDisposable
{
    public string Path { get; } = Directory.CreateTempSubdirectory("webscan-agent-test-").FullName;

    public string File(string name, string content)
    {
        var path = System.IO.Path.Combine(Path, name);
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
        System.IO.File.WriteAllText(path, content);
        return path;
    }

    public void Dispose()
    {
        try { Directory.Delete(Path, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}

internal static class Jobs
{
    public static ScanJob Hosts(ScanOperation operation, string capability, IReadOnlyList<string> hosts, IReadOnlyList<string>? scope = null,
        IReadOnlyDictionary<string, string>? parameters = null, string? toolId = null) => new()
    {
        JobId = Guid.NewGuid(),
        ScanRunId = Guid.NewGuid(),
        Operation = operation,
        Tool = new ToolSelection { Capability = capability, ToolId = toolId },
        Targets = new JobTargets { Hosts = hosts, Count = hosts.Count },
        AuthorizedScope = scope ?? hosts,
        Parameters = parameters ?? new Dictionary<string, string>(),
        Limits = new JobLimits { RatePerSecond = 100, TimeoutSeconds = 60 },
    };

    public static ScanJob Endpoints(ScanOperation operation, string capability, IReadOnlyList<ScanEndpoint> endpoints, IReadOnlyList<string> scope) => new()
    {
        JobId = Guid.NewGuid(),
        ScanRunId = Guid.NewGuid(),
        Operation = operation,
        Tool = new ToolSelection { Capability = capability },
        Targets = new JobTargets { Endpoints = endpoints, Count = endpoints.Count },
        AuthorizedScope = scope,
        Limits = new JobLimits { RatePerSecond = 100, TimeoutSeconds = 60 },
    };

    public static JobAssignment Assign(ScanJob job, int heartbeatSeconds = 1) => new()
    {
        Job = job,
        Lease = new JobLease { LeaseId = Guid.NewGuid(), ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5), Attempt = 1, MaxAttempts = 3, HeartbeatIntervalSeconds = heartbeatSeconds },
    };
}

internal static class Parsing
{
    public static ParseContext Context(ScanJob? job = null, JsonElement? options = null) => new()
    {
        Job = job ?? Jobs.Hosts(ScanOperation.ScanPorts, ToolCapabilities.PortScan, ["172.30.0.0/24"]),
        Source = new ObservationSource { ToolId = "test", AgentId = "agent-test", JobId = Guid.NewGuid() },
        ParserOptions = options,
    };

    public static async Task<List<DiscoveryObservation>> ParseFixtureAsync(IToolOutputParser parser, string fixture, ParseContext? context = null)
    {
        await using var stream = File.OpenRead(TestPaths.Fixture(fixture));
        return await ParseAsync(parser, stream, context);
    }

    public static async Task<List<DiscoveryObservation>> ParseAsync(IToolOutputParser parser, Stream stream, ParseContext? context = null)
    {
        var list = new List<DiscoveryObservation>();
        await foreach (var o in parser.ParseAsync(stream, context ?? Context(), CancellationToken.None)) list.Add(o);
        return list;
    }

    public static ToolComponentRegistry BuiltInRegistry(bool withFake = true)
    {
        IToolAdapter[] adapters = withFake
            ? [new ManifestToolAdapter(Microsoft.Extensions.Logging.Abstractions.NullLogger<ManifestToolAdapter>.Instance), new FakeScannerAdapter(new StaticOptionsMonitor<AgentOptions>(new AgentOptions()))]
            : [new ManifestToolAdapter(Microsoft.Extensions.Logging.Abstractions.NullLogger<ManifestToolAdapter>.Instance)];
        return new ToolComponentRegistry([new NmapXmlParser(), new NaabuJsonlParser(), new HttpxJsonlParser(), new NucleiJsonlParser(), new GenericJsonlParser(), new NervaJsonlParser()], adapters);
    }
}

internal sealed class StaticOptionsMonitor<T>(T value) : Microsoft.Extensions.Options.IOptionsMonitor<T>
{
    public T CurrentValue => value;
    public T Get(string? name) => value;
    public IDisposable? OnChange(Action<T, string?> listener) => null;
}

/// <summary>Builds an agent host from in-memory configuration, optionally wired to a fake server handler.</summary>
internal sealed class AgentHarness : IAsyncDisposable
{
    public TempDir Dir { get; } = new();
    public IHost Host { get; }
    public IConfigurationRoot Configuration { get; }
    public IServiceProvider Services => Host.Services;

    public AgentHarness(HttpMessageHandler? server = null, Dictionary<string, string?>? settings = null)
    {
        var manifests = Directory.CreateDirectory(System.IO.Path.Combine(Dir.Path, "tools.d")).FullName;
        File.Copy(System.IO.Path.Combine(TestPaths.ShippedManifests, "fake.json"), System.IO.Path.Combine(manifests, "fake.json"));

        var config = new Dictionary<string, string?>
        {
            ["Agent:ServerUrl"] = "http://agent-api.test",
            ["Agent:AgentId"] = "agent-test-01",
            ["Agent:EnrollmentToken"] = "enroll-123",
            ["Agent:DataDirectory"] = System.IO.Path.Combine(Dir.Path, "data"),
            ["Agent:ToolManifestPaths:0"] = manifests,
            ["Agent:EnableFakeTools"] = "true",
            ["Agent:MaxConcurrentJobs"] = "2",
            ["Agent:MaxRatePerSecond"] = "1000",
            ["Agent:HeartbeatIntervalSeconds"] = "1",
            ["Agent:ResultBatchFlushSeconds"] = "1",
            ["Agent:ErrorBackoffSeconds"] = "0.05",
            ["Agent:HttpRetryAttempts"] = "1",
            ["Agent:HttpRetryBaseDelayMs"] = "10",
            ["Agent:ShutdownFlushSeconds"] = "5",
            ["Agent:StaticInterfaces:0:Name"] = "lab0",
            ["Agent:StaticInterfaces:0:Addresses:0"] = "10.10.0.5/24",
            ["Agent:StaticRoutes:0:Destination"] = "10.20.0.0/16",
            ["Agent:StaticRoutes:0:InterfaceName"] = "lab0",
        };
        foreach (var (k, v) in settings ?? []) config[k] = v;

        var builder = Microsoft.Extensions.Hosting.Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings());
        builder.Configuration.AddInMemoryCollection(config);
        Configuration = builder.Configuration;
        builder.Services.AddScannerAgent(builder.Configuration, server is null ? null : b => b.ConfigurePrimaryHttpMessageHandler(() => server));
        Host = builder.Build();
    }

    public T Get<T>() where T : notnull => Services.GetRequiredService<T>();

    public async ValueTask DisposeAsync()
    {
        try { await Host.StopAsync(TimeSpan.FromSeconds(10)); } catch (OperationCanceledException) { }
        Host.Dispose();
        Dir.Dispose();
    }
}

internal static class Eventually
{
    public static async Task TrueAsync(Func<bool> condition, string because, int timeoutMs = 15000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline) Assert.Fail($"Timed out waiting: {because}");
            await Task.Delay(25);
        }
    }
}
