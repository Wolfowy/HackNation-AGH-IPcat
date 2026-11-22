using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using WebScan.Agent.Inventory;
using WebScan.Agent.Storage;
using WebScan.Agent.Tools;
using WebScan.Agent.Tools.Abstractions;
using WebScan.Agent.Tools.Adapters;
using WebScan.Contracts;

namespace WebScan.Agent.UnitTests;

public class ResultBufferTests : IDisposable
{
    private readonly TempDir _dir = new();
    private IOptions<AgentOptions> Options => Microsoft.Extensions.Options.Options.Create(new AgentOptions { DataDirectory = _dir.Path });

    public void Dispose() => _dir.Dispose();

    private static ScanResultBatch Batch(Guid jobId, Guid leaseId, int sequence) => new()
    {
        BatchId = Guid.NewGuid(), JobId = jobId, LeaseId = leaseId, Sequence = sequence, CreatedAt = DateTimeOffset.UtcNow,
        Observations =
        [
            new DiscoveryObservation
            {
                ObservationId = "abc", Kind = ObservationKind.PortOpen, Address = "10.0.0.1", Port = 80, Transport = TransportProtocol.Tcp,
                ObservedAt = DateTimeOffset.UtcNow, Source = new ObservationSource { ToolId = "fake", AgentId = "a", JobId = jobId },
            },
        ],
    };

    [Fact]
    public void Buffered_batches_and_job_state_survive_a_restart()
    {
        var jobId = Guid.NewGuid();
        var leaseId = Guid.NewGuid();
        var first = new ResultBuffer(Options, TimeProvider.System);
        first.StartJob(jobId, leaseId);
        Assert.True(first.AddBatch(Batch(jobId, leaseId, 0)));
        Assert.True(first.AddBatch(Batch(jobId, leaseId, 1)));

        var restarted = new ResultBuffer(Options, TimeProvider.System);
        var pending = restarted.PendingBatches(10);
        Assert.Equal([0, 1], pending.Select(b => b.Sequence));
        Assert.Equal(80, ResultBuffer.Decompress(pending[0].GzipPayload).Observations.Single().Port);
        Assert.Equal(2, restarted.BatchCount(jobId));
        Assert.Equal((jobId, leaseId, 2), restarted.InterruptedJobs().Single());
    }

    [Fact]
    public void Finals_wait_for_batches_and_dropped_jobs_lose_their_batches()
    {
        var buffer = new ResultBuffer(Options, TimeProvider.System);
        var (jobId, leaseId) = (Guid.NewGuid(), Guid.NewGuid());
        buffer.StartJob(jobId, leaseId);
        var batch = Batch(jobId, leaseId, 0);
        buffer.AddBatch(batch);
        buffer.SetFinal(jobId, FinalKind.Complete, "{}");

        Assert.Empty(buffer.PendingFinals());
        buffer.DeleteBatch(batch.BatchId);
        Assert.Equal(FinalKind.Complete, buffer.PendingFinals().Single().Kind);

        buffer.RemoveJob(jobId);
        Assert.False(buffer.HasJob(jobId));
        Assert.False(buffer.AddBatch(Batch(jobId, leaseId, 1))); // stale job: refused
        Assert.Equal(0, buffer.PendingBatchCount());
    }

    [Fact]
    public void Credentials_are_persisted_with_owner_only_permissions()
    {
        var store = new CredentialStore(Options);
        store.Save(new AgentCredentials("agent-x", "secret-1"));

        Assert.Equal("secret-1", new CredentialStore(Options).Current!.Secret);
        if (!OperatingSystem.IsWindows())
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Path.Combine(_dir.Path, "credentials.json")));
    }
}

public class PluginTests
{
    [Fact]
    public async Task Parser_from_plugin_assembly_is_loaded_into_the_registry_and_usable_from_a_manifest()
    {
        var registry = Parsing.BuiltInRegistry();
        var loader = new PluginLoader(registry, new ServiceCollection().BuildServiceProvider(), NullLogger<PluginLoader>.Instance);

        var loaded = loader.Load([TestPaths.Plugins], []);

        Assert.Single(loaded);
        var parser = registry.GetParser("test-plugin-ports");
        Assert.NotNull(parser);
        Assert.NotSame(typeof(PluginTests).Assembly, parser.GetType().Assembly);

        var observations = await Parsing.ParseAsync(parser, new MemoryStream(Encoding.UTF8.GetBytes("10.0.0.1 22\n10.0.0.2 443\n")));
        Assert.Equal(["10.0.0.1:22", "10.0.0.2:443"], observations.Select(o => $"{o.Address}:{o.Port}"));

        var manifest = new ToolManifest
        {
            Id = "plugintool", Executable = "plugintool",
            Capabilities = new Dictionary<string, ToolCapabilityDefinition>
            {
                ["port-scan"] = new() { Parser = "test-plugin-ports", Output = new() { Mode = ToolOutputMode.Stdout }, Arguments = ["-l", "{input}"] },
            },
        };
        Assert.Empty(ToolManifestLoader.Validate(manifest, registry));
    }

    [Fact]
    public void Plugins_not_in_the_sha256_allowlist_are_not_loaded()
    {
        var registry = Parsing.BuiltInRegistry();
        var loader = new PluginLoader(registry, new ServiceCollection().BuildServiceProvider(), NullLogger<PluginLoader>.Instance);

        Assert.Empty(loader.Load([TestPaths.Plugins], [new string('a', 64)]));
        Assert.Null(registry.GetParser("test-plugin-ports"));
    }
}

public class FakeScannerTests
{
    private static async Task<List<DiscoveryObservation>> RunAsync(FakeScannerAdapter adapter, ScanJob job)
    {
        var writer = new ListWriter();
        var request = new ToolExecutionRequest
        {
            Job = job, AgentId = "a", Manifest = new ToolManifest { Id = "fake", Version = "1", Capabilities = new Dictionary<string, ToolCapabilityDefinition>() },
            Capability = job.Tool.Capability, Definition = new ToolCapabilityDefinition { Adapter = "fake" },
            Parameters = Contracts.ParameterValidator.Validate(OperationCatalog.Get(job.Operation).Parameters, job.Parameters).Values,
            RatePerSecond = 100, Parallelism = 10, Timeout = TimeSpan.FromMinutes(1), WorkingDirectory = Path.GetTempPath(),
            ProcessRunner = null!, TimeProvider = TimeProvider.System,
        };
        var result = await adapter.RunAsync(request, writer, CancellationToken.None);
        Assert.Equal(0, result.ExitCode);
        return writer.Items;
    }

    [Fact]
    public async Task Results_are_deterministic_and_overrides_apply_on_the_next_job()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Agent:FakeTools:AliveRatio"] = "0.5" }).Build();
        var services = new ServiceCollection().AddOptions().Configure<AgentOptions>(config.GetSection("Agent")).BuildServiceProvider();
        var adapter = new FakeScannerAdapter(services.GetRequiredService<IOptionsMonitor<AgentOptions>>());
        var discovery = Jobs.Hosts(ScanOperation.DiscoverHosts, ToolCapabilities.HostDiscovery, ["10.1.0.0/24"]);

        var first = (await RunAsync(adapter, discovery)).Select(o => o.Address).ToList();
        var second = (await RunAsync(adapter, discovery with { JobId = Guid.NewGuid() })).Select(o => o.Address).ToList();
        Assert.Equal(first, second);
        Assert.InRange(first.Count, 90, 166); // ~50% of 256

        var alive = first[0];
        var portScan = Jobs.Hosts(ScanOperation.ScanPorts, ToolCapabilities.PortScan, [alive], parameters: new Dictionary<string, string> { ["ports"] = "1-65535" });
        var before = (await RunAsync(adapter, portScan)).Select(o => o.Port!.Value).ToHashSet();
        Assert.DoesNotContain(8081, before);

        config["Agent:FakeTools:ExtraOpenPorts:" + alive + ":0"] = "8081";
        config["Agent:FakeTools:ClosedPorts:" + alive + ":0"] = before.First().ToString();
        config["Agent:FakeTools:DownHosts:0"] = first[1];
        config["Agent:FakeTools:ServiceOverrides:0:Address"] = alive;
        config["Agent:FakeTools:ServiceOverrides:0:Port"] = "8081";
        config["Agent:FakeTools:ServiceOverrides:0:Name"] = "http";
        config["Agent:FakeTools:ServiceOverrides:0:Product"] = "changed-app";
        config.Reload();

        var after = (await RunAsync(adapter, portScan)).Select(o => o.Port!.Value).ToHashSet();
        Assert.Contains(8081, after);
        Assert.DoesNotContain(before.First(), after);
        Assert.DoesNotContain(first[1], (await RunAsync(adapter, discovery)).Select(o => o.Address));

        var service = await RunAsync(adapter, Jobs.Endpoints(ScanOperation.DetectService, ToolCapabilities.ServiceDetection, [new ScanEndpoint { Address = alive, Port = 8081 }], [alive]));
        Assert.Equal(("http", "changed-app"), (service.Single().Service!.Name, service.Single().Service!.Product));
        var http = await RunAsync(adapter, Jobs.Endpoints(ScanOperation.HttpProbe, ToolCapabilities.HttpProbe, [new ScanEndpoint { Address = alive, Port = 8081 }], [alive]));
        Assert.Contains(http, o => o.Kind == ObservationKind.HttpResponse && o.Http!.StatusCode == 200);
    }

    private sealed class ListWriter : IObservationWriter
    {
        public List<DiscoveryObservation> Items { get; } = [];
        public ValueTask WriteAsync(DiscoveryObservation observation, CancellationToken cancellationToken) { lock (Items) Items.Add(observation); return ValueTask.CompletedTask; }
    }
}

public class InventoryTests
{
    [Theory]
    [InlineData(null, false, false, null, null, false)]                       // macOS user without sudo
    [InlineData(null, false, true, null, null, true)]                         // root
    [InlineData(null, false, false, "Name:\tdotnet\nCapEff:\t0000000000002000\n", null, true)] // CAP_NET_RAW (bit 13)
    [InlineData(null, false, false, "CapEff:\t0000000000000400\n", null, false)]
    [InlineData(null, false, false, null, "1", true)]                         // container image: tools carry file capabilities
    [InlineData(false, false, true, null, "1", false)]                        // operator override wins
    public void Raw_socket_capability_is_detected(bool? configured, bool windows, bool privileged, string? procStatus, string? nmapPrivileged, bool expected) =>
        Assert.Equal(expected, NetworkInventory.DetectRawSockets(configured, windows, privileged, procStatus, nmapPrivileged));

    [Fact]
    public void Raw_socket_capability_is_unknown_on_windows() => Assert.Null(NetworkInventory.DetectRawSockets(null, true, false, null, null));

    [Fact]
    public void Linux_route_tables_are_parsed()
    {
        const string v4 = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
                          "eth0\t00000000\t010011AC\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
                          "eth0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n";
        const string v6 = "fd000000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n" +
                          "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n";

        var routes = NetworkInventory.ParseLinuxRoutes(v4).Concat(NetworkInventory.ParseLinuxIpv6Routes(v6)).ToList();

        Assert.Equal(["0.0.0.0/0 via 172.17.0.1 m100", "172.17.0.0/16 via - m0", "fd00::/64 via - m256", "::/0 via fe80::1 m1024"],
            routes.Select(r => $"{r.Destination} via {r.Gateway ?? "-"} m{r.Metric}"));
    }

    [Fact]
    public void Macos_netstat_is_parsed()
    {
        const string output = """
            Routing tables

            Internet:
            Destination        Gateway            Flags               Netif Expire
            default            192.168.1.1        UGScg                 en0
            127                127.0.0.1          UCS                   lo0
            192.168.1          link#11            UCS                   en0      !
            192.168.1.1/32     link#11            UCS                   en0      !
            10.8.0.2           10.8.0.1           UH                  utun3

            Internet6:
            Destination                             Gateway                                 Flags               Netif Expire
            default                                 fe80::%utun0                            UGcIg               utun0
            fd00:1::/64                             link#11                                 UC                    en0
            """;
        var routes = NetworkInventory.ParseNetstat(output).Select(r => $"{r.Destination}|{r.Gateway ?? "-"}|{r.InterfaceName}").ToList();

        Assert.Equal(["0.0.0.0/0|192.168.1.1|en0", "192.168.1.0/24|-|en0", "192.168.1.1/32|-|en0", "10.8.0.2/32|10.8.0.1|utun3", "::/0|fe80::|utun0", "fd00:1::/64|-|en0"], routes);
    }

    [Fact]
    public void Static_interfaces_and_filters_replace_detection()
    {
        var options = new AgentOptions
        {
            StaticInterfaces = [new StaticInterfaceOptions { Name = "lab0", Addresses = ["10.10.0.5/24"] }, new StaticInterfaceOptions { Name = "lab1", Addresses = ["10.11.0.5/24"] }],
            Interfaces = new InterfaceFilterOptions { Exclude = ["lab1"] },
        };
        var inventory = new NetworkInventory(new StaticOptionsMonitor<AgentOptions>(options), null!, NullLogger<NetworkInventory>.Instance);

        Assert.Equal(["lab0"], inventory.GetInterfaces().Select(i => i.Name));
        Assert.NotEmpty(new NetworkInventory(new StaticOptionsMonitor<AgentOptions>(new AgentOptions()), null!, NullLogger<NetworkInventory>.Instance).GetInterfaces());
    }
}
