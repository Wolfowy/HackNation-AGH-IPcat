using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WebScan.Contracts;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Modules.Discovery.Domain;
using WebScan.Server.Modules.Discovery.Persistence;

namespace WebScan.Discovery.UnitTests.Infrastructure;

/// <summary>Builds observations and drives ingest → persist → compare like the workflow engine would.</summary>
public sealed class Scenario(TestApp app)
{
    public static readonly ScanOperation[] FullScan =
        [ScanOperation.DiscoverHosts, ScanOperation.ScanPorts, ScanOperation.DetectService, ScanOperation.HttpProbe, ScanOperation.TlsProbe,
         ScanOperation.ExecuteSignatures];

    public Guid JobId { get; private set; } = Guid.NewGuid();
    public Guid RunId { get; private set; } = Guid.NewGuid();

    /// <summary>Starts a new run (new run and job ids) and advances the clock by <paramref name="after"/> (default 1 day).</summary>
    public Scenario NextRun(TimeSpan? after = null)
    {
        RunId = Guid.NewGuid();
        JobId = Guid.NewGuid();
        app.Clock.Advance(after ?? TimeSpan.FromDays(1));
        return this;
    }

    public static RunCoverage Coverage(string[] hosts, ScanOperation[]? operations = null, bool complete = true, string[]? endpoints = null) => new()
    {
        CoveredHosts = hosts, CoveredEndpoints = endpoints ?? [], Complete = complete, OperationsExecuted = operations ?? FullScan,
    };

    public async Task IngestAsync(params DiscoveryObservation[] observations) => await IngestBatchAsync(Guid.NewGuid(), observations);

    public Task IngestBatchAsync(Guid batchId, params DiscoveryObservation[] observations) =>
        app.WithScopeAsync(sp => sp.GetRequiredService<IObservationSink>().IngestAsync(Context(), new ScanResultBatch
        {
            BatchId = batchId, JobId = JobId, LeaseId = Guid.NewGuid(), Sequence = 0, CreatedAt = app.Clock.GetUtcNow(), Observations = observations,
        }));

    /// <summary>Scan perspective of the next ingests.</summary>
    public (string AgentId, string? InterfaceName, string? Zone) Perspective { get; set; } = ("agent-1", "eth0", "lab");

    public IngestContext Context() => new()
    {
        ScanRunId = RunId, JobId = JobId, Operation = ScanOperation.ScanPorts, AgentId = Perspective.AgentId,
        InterfaceName = Perspective.InterfaceName, Zone = Perspective.Zone,
    };

    /// <summary>Ingests, persists and compares one run; returns the change events of the run.</summary>
    public async Task<List<ChangeEvent>> RunAsync(RunCoverage coverage, int missingThreshold, params DiscoveryObservation[] observations)
    {
        if (observations.Length > 0) await IngestAsync(observations);
        await app.WithScopeAsync(async sp =>
        {
            var processor = sp.GetRequiredService<IDiscoveryRunProcessor>();
            await processor.PersistRunAsync(RunId, coverage);
            await processor.CompareWithPreviousAsync(RunId, missingThreshold);
        });
        return await QueryAsync(db => db.Changes.Where(c => c.ScanRunId == RunId).OrderBy(c => c.Type).ToListAsync());
    }

    public Task<T> QueryAsync<T>(Func<DiscoveryDbContext, Task<T>> query) =>
        app.WithScopeAsync(sp => query(sp.GetRequiredService<DiscoveryDbContext>()));

    // ---- observation builders ----

    private DiscoveryObservation Base(ObservationKind kind, string address, int? port, string? discriminator = null, string tool = "nmap") => new()
    {
        ObservationId = ObservationIds.Compute(JobId, kind, address, port, port is null ? null : TransportProtocol.Tcp, discriminator),
        Kind = kind, Address = address, Port = port, Transport = port is null ? null : TransportProtocol.Tcp, ObservedAt = app.Clock.GetUtcNow(),
        Source = new ObservationSource { ToolId = tool, AgentId = "agent-1", JobId = JobId },
    };

    public DiscoveryObservation HostUp(string address, params string[] hostnames) =>
        Base(ObservationKind.HostUp, address, null) with { Host = new HostDetails { Status = "up", Reason = "echo-reply", Hostnames = hostnames } };

    public DiscoveryObservation HostDown(string address) =>
        Base(ObservationKind.HostDown, address, null) with { Host = new HostDetails { Status = "down", Reason = "no-response" } };

    public DiscoveryObservation Port(string address, int port) =>
        Base(ObservationKind.PortOpen, address, port, tool: "naabu") with { PortState = new PortDetails { State = "open" } };

    public DiscoveryObservation Service(string address, int port, string name, string? product = null, string? version = null) =>
        Base(ObservationKind.Service, address, port) with { Service = new ServiceDetails { Name = name, Product = product, Version = version } };

    public DiscoveryObservation Http(string address, int port, int status, string? title, string? server = null, string path = "/") =>
        Base(ObservationKind.HttpResponse, address, port, path, "httpx") with
        {
            Http = new HttpDetails { Url = $"http://{address}:{port}{path}", Scheme = "http", StatusCode = status, Title = title, WebServer = server },
        };

    public DiscoveryObservation Tls(string address, int port, string fingerprint, string cn) =>
        Base(ObservationKind.TlsCertificate, address, port, fingerprint, "httpx") with
        {
            Tls = new TlsDetails { FingerprintSha256 = fingerprint, SubjectCommonName = cn, Issuer = "Test CA", NotAfter = app.Clock.GetUtcNow().AddDays(90) },
        };

    public DiscoveryObservation Technology(string address, int port, string name, string? version = null) =>
        Base(ObservationKind.Technology, address, port, name, "httpx") with { Technology = new TechnologyDetails { Name = name, Version = version } };

    public DiscoveryObservation Signature(string address, int port, string signatureId, string severity, string evidence = "matched") =>
        Base(ObservationKind.SignatureMatch, address, port, signatureId, "nuclei") with
        {
            Signature = new SignatureMatchDetails
            {
                SignatureId = signatureId, SignatureVersion = 1, Name = $"Finding {signatureId}", Severity = severity, Evidence = evidence,
                MatchedAt = $"http://{address}:{port}/",
            },
        };
}
