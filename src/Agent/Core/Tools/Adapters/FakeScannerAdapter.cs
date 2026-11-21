using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using WebScan.Agent.Execution;
using WebScan.Agent.Tools.Abstractions;
using WebScan.Contracts;

namespace WebScan.Agent.Tools.Adapters;

/// <summary>
/// Synthetic scanner: deterministic observations derived from a hash of each target, for every capability. It never opens
/// sockets. Overrides from <c>Agent:FakeTools</c> (IOptionsMonitor) apply from the next job on, so E2E tests can introduce a
/// deliberate change between two scans. Registered only when <c>Agent:EnableFakeTools=true</c>.
/// </summary>
public sealed partial class FakeScannerAdapter(IOptionsMonitor<AgentOptions> options) : IToolAdapter
{
    public const string AdapterId = "fake";
    public string Id => AdapterId;

    /// <summary>Synthetic port pool; each port is open on roughly half of the alive hosts.</summary>
    private static readonly (int Port, string Name, string Product, string Version)[] Pool =
    [
        (22, "ssh", "OpenSSH", "9.6"), (80, "http", "nginx", "1.25.3"), (443, "https", "nginx", "1.25.3"), (3306, "mysql", "MySQL", "8.0.36"),
        (3389, "ms-wbt-server", "Microsoft Terminal Services", ""), (5432, "postgresql", "PostgreSQL", "16.2"),
        (8080, "http", "Apache Tomcat", "10.1.19"), (8443, "https", "Jetty", "12.0.7"),
    ];

    public async Task<ToolExecutionResult> RunAsync(ToolExecutionRequest request, IObservationWriter writer, CancellationToken cancellationToken)
    {
        var o = options.CurrentValue.FakeTools;
        var started = request.TimeProvider.GetTimestamp();
        var ctx = request.CreateParseContext();
        var job = request.Job;
        try
        {
            // Hosts for host-based jobs, endpoints otherwise (one "target" each for the per-target delay).
            var hosts = job.Targets.Endpoints.Count > 0 ? new List<string>() : job.Targets.Hosts.SelectMany(Targets.Expand).Distinct().ToList();
            var endpoints = job.Targets.Endpoints;
            var requested = request.Parameters.TryGetValue("ports", out var spec) ? PortFilter(spec) : _ => true;

            foreach (var address in hosts)
            {
                await DelayAsync(o, request, cancellationToken);
                if (!IsAlive(address, o)) continue;
                switch (request.Capability)
                {
                    case ToolCapabilities.HostDiscovery:
                        await writer.WriteAsync(ctx.NewObservation(ObservationKind.HostUp, address) with
                        {
                            Host = new HostDetails { Status = "up", Reason = "syn-ack", LatencyMs = 0.5 + Hash(address, "rtt") % 50 / 10.0 },
                        }, cancellationToken);
                        break;
                    case ToolCapabilities.PortScan:
                        foreach (var port in OpenPorts(address, o).Where(requested))
                            await writer.WriteAsync(ctx.NewObservation(ObservationKind.PortOpen, address, port, TransportProtocol.Tcp) with
                            {
                                PortState = new PortDetails { State = "open", Reason = "syn-ack" },
                            }, cancellationToken);
                        break;
                }
            }

            foreach (var e in endpoints)
            {
                await DelayAsync(o, request, cancellationToken);
                if (!IsAlive(e.Address, o) || !OpenPorts(e.Address, o).Contains(e.Port)) continue;
                foreach (var observation in EndpointObservations(request, ctx, e, o))
                    await writer.WriteAsync(observation, cancellationToken);
            }
            return new ToolExecutionResult { ExitCode = 0, Duration = request.TimeProvider.GetElapsedTime(started) };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return new ToolExecutionResult { ExitCode = null, Duration = request.TimeProvider.GetElapsedTime(started), StderrTail = "fake scan cancelled" };
        }
    }

    private static IEnumerable<DiscoveryObservation> EndpointObservations(ToolExecutionRequest request, ParseContext ctx, ScanEndpoint e, FakeToolOptions o)
    {
        var service = ServiceFor(e.Address, e.Port, o);
        var isHttp = service.Name is "http" or "https";
        var isTls = service.Name == "https" || e.Scheme == "https";
        var scheme = isTls ? "https" : "http";
        var url = $"{scheme}://{TargetFormatter.Endpoint(e)}/";

        switch (request.Capability)
        {
            case ToolCapabilities.ServiceDetection:
                yield return ctx.NewObservation(ObservationKind.Service, e.Address, e.Port, e.Transport) with
                {
                    Service = new ServiceDetails
                    {
                        Name = service.Name, Product = service.Product, Version = service.Version,
                        Tunnel = isTls ? "ssl" : null,
                        Cpe = service.Product is { Length: > 0 } p ? [$"cpe:/a:{p.ToLowerInvariant().Replace(' ', '_')}:{service.Version}"] : [],
                    },
                    Confidence = new Confidence { Score = 1.0, Method = "version-probe" },
                };
                break;
            case ToolCapabilities.HttpProbe when isHttp:
                yield return ctx.NewObservation(ObservationKind.HttpResponse, e.Address, e.Port, e.Transport, url) with
                {
                    Http = new HttpDetails
                    {
                        Url = url, Scheme = scheme, StatusCode = 200, Title = $"Fake {service.Product} on {e.Address}",
                        WebServer = $"{service.Product}/{service.Version}", ContentType = "text/html", ContentLength = 512 + (long)(Hash(e.Address, "len") % 4096),
                        Headers = new Dictionary<string, string> { ["server"] = $"{service.Product}/{service.Version}", ["set-cookie"] = $"session={SensitiveDataMasker.Mask}; Path=/" },
                        CookieNames = ["session"],
                        BodySha256 = Sha256Hex($"body|{e.Address}|{e.Port}|{service.Product}"),
                        Technologies = [$"{service.Product}:{service.Version}"],
                    },
                };
                yield return ctx.NewObservation(ObservationKind.Technology, e.Address, e.Port, e.Transport, service.Product.ToLowerInvariant()) with
                {
                    Technology = new TechnologyDetails { Name = service.Product, Version = service.Version, Category = "web-server" },
                    Confidence = new Confidence { Score = 0.8, Method = "tool-reported" },
                };
                break;
            case ToolCapabilities.TlsProbe when isTls:
                var fingerprint = Sha256Hex($"cert|{e.Address}|{e.Port}");
                yield return ctx.NewObservation(ObservationKind.TlsCertificate, e.Address, e.Port, e.Transport, fingerprint) with
                {
                    Tls = new TlsDetails
                    {
                        SubjectCommonName = $"fake-{e.Address.Replace(':', '-')}.local", SubjectAlternativeNames = [$"fake-{e.Address.Replace(':', '-')}.local"],
                        Issuer = "CN=WebScan Fake CA", NotBefore = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
                        NotAfter = new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero), SerialNumber = fingerprint[..16].ToUpperInvariant(),
                        FingerprintSha256 = fingerprint, TlsVersion = "tls13", Cipher = "TLS_AES_128_GCM_SHA256", SelfSigned = false,
                    },
                };
                break;
            case ToolCapabilities.SignatureScan when isHttp:
                foreach (var signature in request.Job.Signatures?.Items ?? [])
                {
                    if (Hash($"{e.Address}|{e.Port}", signature.Id) % 4 != 0) continue;
                    yield return ctx.NewObservation(ObservationKind.SignatureMatch, e.Address, e.Port, e.Transport, $"{signature.Id}||{url}") with
                    {
                        Signature = new SignatureMatchDetails
                        {
                            SignatureId = signature.Id, SignatureVersion = signature.Version, Name = signature.Id, Severity = "info",
                            MatchedAt = url, Evidence = "synthetic match", Tags = ["fake"],
                        },
                        Confidence = new Confidence { Score = 0.9, Method = "signature-match" },
                    };
                }
                break;
        }
    }

    private static bool IsAlive(string address, FakeToolOptions o) =>
        !o.DownHosts.Contains(address, StringComparer.OrdinalIgnoreCase)
        && (o.ExtraOpenPorts.ContainsKey(address) || Hash(address, "alive") % 10_000 < o.AliveRatio * 10_000);

    private static SortedSet<int> OpenPorts(string address, FakeToolOptions o)
    {
        var ports = new SortedSet<int>(Pool.Where(p => Hash(address, $"port{p.Port}") % 2 == 0).Select(p => p.Port));
        if (ports.Count == 0) ports.Add(Pool[(int)(Hash(address, "fallback") % (ulong)Pool.Length)].Port);
        if (o.ExtraOpenPorts.TryGetValue(address, out var extra)) ports.UnionWith(extra);
        if (o.ClosedPorts.TryGetValue(address, out var closed)) ports.ExceptWith(closed);
        return ports;
    }

    private static (string Name, string Product, string Version) ServiceFor(string address, int port, FakeToolOptions o)
    {
        if (o.ServiceOverrides.FirstOrDefault(s => s.Port == port && string.Equals(s.Address, address, StringComparison.OrdinalIgnoreCase)) is { } custom)
            return (custom.Name, custom.Product ?? "", custom.Version ?? "");
        foreach (var p in Pool) if (p.Port == port) return (p.Name, p.Product, p.Version);
        return ("unknown", "", "");
    }

    /// <summary>"top-N" accepts every port (the pool is part of any top list); explicit specs are matched exactly.</summary>
    private static Func<int, bool> PortFilter(string spec)
    {
        if (TopPorts().IsMatch(spec)) return _ => true;
        var ranges = ParameterValidator.SplitList(spec).Select(item =>
        {
            var parts = item.Split('-');
            var from = int.Parse(parts[0]);
            return (From: from, To: parts.Length > 1 ? int.Parse(parts[1]) : from);
        }).ToList();
        return port => ranges.Any(r => port >= r.From && port <= r.To);
    }

    private static async Task DelayAsync(FakeToolOptions o, ToolExecutionRequest request, CancellationToken ct)
    {
        if (o.DelayPerTargetMs > 0) await Task.Delay(TimeSpan.FromMilliseconds(o.DelayPerTargetMs), request.TimeProvider, ct);
        else ct.ThrowIfCancellationRequested();
    }

    private static ulong Hash(string value, string salt) =>
        BinaryPrimitives.ReadUInt64BigEndian(SHA256.HashData(Encoding.UTF8.GetBytes($"{salt}|{value.ToLowerInvariant()}")));

    private static string Sha256Hex(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    [GeneratedRegex(@"^top-\d+$")]
    private static partial Regex TopPorts();
}
