using System.Collections.Concurrent;
using WebScan.Contracts;
using WebScan.Server.Kernel.Messaging;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Kernel.Security;

namespace WebScan.Scheduling.UnitTests.Support;

public sealed class ManualTimeProvider(DateTimeOffset start) : TimeProvider
{
    private long _offsetTicks;
    public override DateTimeOffset GetUtcNow() => start.AddTicks(Interlocked.Read(ref _offsetTicks));
    public void Advance(TimeSpan by) => Interlocked.Add(ref _offsetTicks, by.Ticks);
}

public sealed class FakeAgentDirectory : IAgentDirectory
{
    private readonly ConcurrentDictionary<string, AgentSnapshot> _agents = new();
    public void Set(AgentSnapshot agent) => _agents[agent.AgentId] = agent;
    public void Remove(string agentId) => _agents.TryRemove(agentId, out _);
    public Task<IReadOnlyList<AgentSnapshot>> GetActiveAgentsAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<AgentSnapshot>>(_agents.Values.Where(a => a.Status == AgentStatus.Active).ToList());
    public Task<AgentSnapshot?> GetAsync(string agentId, CancellationToken ct = default) => Task.FromResult(_agents.GetValueOrDefault(agentId));
}

public sealed class FakeNetworkScope : INetworkScopeService
{
    private readonly ConcurrentDictionary<Guid, ScopeSegment> _segments = new();
    public ConcurrentBag<string> Unauthorized { get; } = [];
    public List<string> GlobalExclusions { get; } = [];

    public Guid Add(string zone, string[] include, string[]? exclude = null, int? maxRate = null)
    {
        var id = Guid.NewGuid();
        _segments[id] = new ScopeSegment { NetworkId = id, NetworkName = $"net-{id:N}"[..12], Zone = zone, Include = include, Exclude = exclude ?? [], MaxRatePerSecond = maxRate };
        return id;
    }

    public Task<ResolvedScope> ResolveAsync(IReadOnlyCollection<Guid> networkIds, CancellationToken ct = default) =>
        Task.FromResult(new ResolvedScope
        {
            Segments = networkIds.Where(_segments.ContainsKey).Select(id => _segments[id]).ToList(),
            GlobalExclusions = [.. GlobalExclusions],
        });

    public Task<bool> IsAuthorizedAsync(string target, CancellationToken ct = default) => Task.FromResult(!Unauthorized.Contains(target));
}

public sealed class FakeDiscoveryProcessor : IDiscoveryRunProcessor
{
    public ConcurrentQueue<(Guid RunId, RunCoverage Coverage)> Persisted { get; } = new();
    public ConcurrentQueue<Guid> Compared { get; } = new();
    public Func<Guid, CancellationToken, Task>? OnPersist { get; set; }

    public async Task<PersistRunResult> PersistRunAsync(Guid scanRunId, RunCoverage coverage, CancellationToken ct = default)
    {
        if (OnPersist is not null) await OnPersist(scanRunId, ct);
        Persisted.Enqueue((scanRunId, coverage));
        return new PersistRunResult(0, 0, 0);
    }

    public Task<CompareRunResult> CompareWithPreviousAsync(Guid scanRunId, int missingThreshold, CancellationToken ct = default)
    {
        Compared.Enqueue(scanRunId);
        return Task.FromResult(new CompareRunResult(0, new Dictionary<string, int>()));
    }
}

public sealed class FakeFindingPublisher : IFindingPublisher
{
    public ConcurrentQueue<Guid> Published { get; } = new();
    public Task<PublishFindingsResult> PublishAsync(Guid scanRunId, string destination, string minSeverity, CancellationToken ct = default)
    {
        Published.Enqueue(scanRunId);
        return Task.FromResult(new PublishFindingsResult(0, 0));
    }
}

public sealed class FakeSignatureCatalog : ISignatureCatalog
{
    public SignatureBundle Bundle { get; set; } = new()
    {
        Sha256 = "abc", Items = [new SignatureContent { Id = "tech-detect", Version = 1, Format = "nuclei-yaml", Content = "id: tech-detect" }],
    };

    public Task<SignatureBundle> GetApprovedBundleAsync(IReadOnlyCollection<string> signatureIds, IReadOnlyCollection<string> tags,
        IReadOnlyCollection<string> severities, CancellationToken ct = default) => Task.FromResult(Bundle);
}

public sealed class RecordingAuditLog : IAuditLog
{
    public ConcurrentQueue<AuditEntry> Entries { get; } = new();
    public Task WriteAsync(AuditEntry entry, CancellationToken ct = default) { Entries.Enqueue(entry); return Task.CompletedTask; }
}

/// <summary>Messages observed by test handlers (proves outbox delivery through Wolverine).</summary>
public sealed class MessageLog
{
    public ConcurrentQueue<ScanResultBatchReceived> Batches { get; } = new();
    public ConcurrentQueue<ScanRunFinished> RunsFinished { get; } = new();
}

public static class ScanResultBatchReceivedTestHandler
{
    public static void Handle(ScanResultBatchReceived message, MessageLog log) => log.Batches.Enqueue(message);
}

public static class ScanRunFinishedTestHandler
{
    public static void Handle(ScanRunFinished message, MessageLog log) => log.RunsFinished.Enqueue(message);
}

public static class Agents
{
    public static readonly ToolDescriptor Nmap = Tool("nmap", ToolCapabilities.HostDiscovery, ToolCapabilities.PortScan, ToolCapabilities.ServiceDetection);
    public static readonly ToolDescriptor Naabu = Tool("naabu", ToolCapabilities.PortScan);
    public static readonly ToolDescriptor Httpx = Tool("httpx", ToolCapabilities.HttpProbe, ToolCapabilities.TlsProbe);
    public static readonly ToolDescriptor Nuclei = Tool("nuclei", ToolCapabilities.SignatureScan);
    public static readonly ToolDescriptor[] All = [Nmap, Naabu, Httpx, Nuclei];

    public static ToolDescriptor Tool(string id, params string[] capabilities) => new() { Id = id, Version = "1.0", Capabilities = capabilities };

    /// <summary>Agent with one interface per entry of <paramref name="interfaces"/> (name → addresses with prefix).</summary>
    public static AgentSnapshot Create(string id, string[] zones, Dictionary<string, string[]> interfaces, RouteInfo[]? routes = null,
        ToolDescriptor[]? tools = null, int maxJobs = 4, int maxRate = 10_000, Guid[]? networks = null, bool online = true) => new()
    {
        AgentId = id, Status = AgentStatus.Active, IsOnline = online, ApprovedTools = tools ?? All,
        Interfaces = interfaces.Select(i => new NetworkInterfaceInfo { Name = i.Key, Addresses = i.Value }).ToList(),
        Routes = routes ?? [], AuthorizedZones = zones, AuthorizedNetworkIds = networks ?? [],
        Limits = new AgentLimits { MaxConcurrentJobs = maxJobs, MaxRatePerSecond = maxRate },
    };

    public static AgentSnapshot Simple(string id, string zone, string cidr, int maxJobs = 4, ToolDescriptor[]? tools = null) =>
        Create(id, [zone], new() { ["eth0"] = [cidr] }, tools: tools, maxJobs: maxJobs);

    public static RouteInfo Route(string destination, string nic) => new() { Destination = destination, InterfaceName = nic };
}

public static class Observations
{
    public static DiscoveryObservation Make(Guid jobId, ObservationKind kind, string address, int? port = null,
        ServiceDetails? service = null, HttpDetails? http = null, string agentId = "agent") => new()
    {
        ObservationId = ObservationIds.Compute(jobId, kind, address, port, port is null ? null : TransportProtocol.Tcp, service?.Name ?? http?.Url),
        Kind = kind, Address = address, Port = port, Transport = port is null ? null : TransportProtocol.Tcp, ObservedAt = DateTimeOffset.UtcNow,
        Source = new ObservationSource { ToolId = "fake", AgentId = agentId, JobId = jobId },
        Host = kind == ObservationKind.HostUp ? new HostDetails { Status = "up" } : null,
        PortState = kind == ObservationKind.PortOpen ? new PortDetails { State = "open" } : null,
        Service = service, Http = http,
    };
}
