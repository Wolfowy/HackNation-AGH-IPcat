using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using WebScan.Agent.Tools.Abstractions;
using WebScan.Agent.Tools.Parsers;
using WebScan.Contracts;
using WebScan.Server.Infrastructure.Http;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Modules.Scanning.Persistence;

namespace WebScan.Server.Modules.Workflows.Import;

/// <summary>Import formats: our flat rows (JSON/CSV, same columns as the services/findings export) or raw tool output.</summary>
public static class ImportFormats
{
    public const string Json = "json";
    public const string Csv = "csv";
    public static readonly IReadOnlyList<string> ToolFormats = ["nmap-xml", "httpx-jsonl", "naabu-jsonl", "nuclei-jsonl"];
    public static readonly IReadOnlyList<string> All = [Json, Csv, .. ToolFormats];
}

public sealed record ImportOptions(string Format, string Zone, string? Name, bool Snapshot, string User);

public sealed record ImportResult(Guid? ScanRunId, int Rows, int Observations, int ChangesDetected, IReadOnlyList<string> Errors);

/// <summary>
/// Imports scan results as a scan run that goes through the same pipeline as agent results: ingestion (masking, normalization,
/// live asset state, findings), PersistObservations (coverage) and ComparePreviousScan (new / changed / gone).
/// A merge import only adds and updates; a snapshot import also counts services missing on the imported hosts as misses.
/// </summary>
public sealed partial class ResultImporter(IObservationSink sink, IDiscoveryRunProcessor processor, ScanningDbContext db, TimeProvider time)
{
    public const string AgentId = "import";
    public const string WorkflowKey = "import";
    private const int BatchSize = 500;
    private const int DefaultMissingThreshold = 3;

    [GeneratedRegex("^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")]
    public static partial Regex ZonePattern();

    public async Task<ImportResult> ImportAsync(Stream body, ImportOptions options, CancellationToken ct)
    {
        var runId = Guid.NewGuid();
        var errors = new List<string>();
        var started = time.GetUtcNow();
        var (rows, observations) = await ParseAsync(body, options, runId, errors, ct);
        if (observations.Count == 0)
            return new ImportResult(null, rows, 0, 0, errors.Count > 0 ? errors : ["The file contains no importable results."]);

        var status = ScanRunStatus.Failed;
        var message = "Import failed";
        try
        {
            var groups = observations.GroupBy(o => (Zone: Zone(o.Observation, options), Operation: OperationOf(o.Observation.Kind)));
            foreach (var group in groups)
            {
                var jobId = group.First().Observation.Source.JobId;
                var context = new IngestContext { ScanRunId = runId, JobId = jobId, Operation = group.Key.Operation, AgentId = AgentId, Zone = group.Key.Zone, WorkflowStepId = "import" };
                var sequence = 0;
                foreach (var chunk in group.Select(o => o.Observation).Chunk(BatchSize))
                    await sink.IngestAsync(context, new ScanResultBatch
                    {
                        BatchId = Guid.NewGuid(), JobId = jobId, LeaseId = Guid.Empty, Sequence = sequence++, CreatedAt = time.GetUtcNow(), Observations = chunk,
                    }, ct);
            }

            var hostsByZone = observations.GroupBy(o => Zone(o.Observation, options))
                .ToDictionary(g => g.Key, g => (IReadOnlyList<string>)g.Select(o => o.Observation.Address).Distinct().ToList());
            var endpointsByZone = observations.Where(o => o.Observation.Port is not null).GroupBy(o => Zone(o.Observation, options))
                .ToDictionary(g => g.Key, g => (IReadOnlyList<string>)g.Select(o => $"{o.Observation.Address}:{o.Observation.Port}").Distinct().ToList());
            await processor.PersistRunAsync(runId, new RunCoverage
            {
                Complete = options.Snapshot,
                CoveredHosts = hostsByZone.Values.SelectMany(v => v).Distinct().ToList(),
                CoveredEndpoints = endpointsByZone.Values.SelectMany(v => v).Distinct().ToList(),
                CoveredHostsByZone = hostsByZone, CoveredEndpointsByZone = endpointsByZone,
                OperationsExecuted = observations.Select(o => OperationOf(o.Observation.Kind)).Distinct().ToList(),
            }, ct);
            var changes = await processor.CompareWithPreviousAsync(runId, DefaultMissingThreshold, ct);
            status = ScanRunStatus.Completed;
            message = $"Imported {observations.Count} observations from {rows} {options.Format} records ({changes.ChangesDetected} changes)" +
                      (errors.Count > 0 ? $"; {errors.Count} records skipped" : "");
            return new ImportResult(runId, rows, observations.Count, changes.ChangesDetected, errors);
        }
        finally
        {
            // The run row is written last and already finished, so the workflow runtime never tries to drive it.
            db.ScanRuns.Add(new ScanRun
            {
                Id = runId, Name = string.IsNullOrWhiteSpace(options.Name) ? $"Import {options.Format} {started:yyyy-MM-dd HH:mm}" : options.Name.Trim(),
                Status = status, WorkflowKey = WorkflowKey, WorkflowVersion = 1, TriggeredBy = $"import:{options.User}", CreatedAt = started,
                StartedAt = started, FinishedAt = time.GetUtcNow(), CoverageComplete = options.Snapshot && status == ScanRunStatus.Completed, Message = message,
            });
            await db.SaveChangesAsync(CancellationToken.None);
        }
    }

    private static string Zone(DiscoveryObservation o, ImportOptions options) =>
        o.Attributes?.TryGetValue("import.zone", out var zone) == true && ZonePattern().IsMatch(zone) ? zone : options.Zone;

    public static ScanOperation OperationOf(ObservationKind kind) => kind switch
    {
        ObservationKind.HostUp or ObservationKind.HostDown => ScanOperation.DiscoverHosts,
        ObservationKind.PortOpen or ObservationKind.PortClosed => ScanOperation.ScanPorts,
        ObservationKind.Service => ScanOperation.DetectService,
        ObservationKind.TlsCertificate => ScanOperation.TlsProbe,
        ObservationKind.SignatureMatch => ScanOperation.ExecuteSignatures,
        _ => ScanOperation.HttpProbe,
    };

    private sealed record Parsed(DiscoveryObservation Observation);

    private async Task<(int Rows, IReadOnlyList<Parsed> Observations)> ParseAsync(Stream body, ImportOptions options, Guid runId, List<string> errors, CancellationToken ct)
    {
        var jobId = Guid.NewGuid();
        var source = new ObservationSource { ToolId = $"import:{options.Format}", AgentId = AgentId, JobId = jobId };
        if (ImportFormats.ToolFormats.Contains(options.Format))
        {
            IToolOutputParser parser = options.Format switch
            {
                "nmap-xml" => new NmapXmlParser(),
                "httpx-jsonl" => new HttpxJsonlParser(),
                "naabu-jsonl" => new NaabuJsonlParser(),
                _ => new NucleiJsonlParser(),
            };
            var context = new ParseContext { Job = DummyJob(runId, jobId), Source = source with { ToolId = parser.Id.Split('-')[0] }, TimeProvider = time };
            var list = new List<Parsed>();
            await foreach (var o in parser.ParseAsync(body, context, ct)) list.Add(new Parsed(o));
            return (list.Select(p => p.Observation.Address).Distinct().Count(), list);
        }

        string text;
        using (var reader = new StreamReader(body, Encoding.UTF8)) text = await reader.ReadToEndAsync(ct);
        var rows = options.Format == ImportFormats.Csv ? CsvRows(text, errors) : JsonRows(text, errors);
        var result = new List<Parsed>();
        var now = time.GetUtcNow();
        for (var i = 0; i < rows.Count; i++)
        {
            try { result.AddRange(ImportRows.ToObservations(rows[i], source, now).Select(o => new Parsed(o)).ToList()); } // whole record or nothing
            catch (FormatException ex) { errors.Add($"Record {i + 1}: {ex.Message}"); }
        }
        return (rows.Count, result);
    }

    private static ScanJob DummyJob(Guid runId, Guid jobId) => new()
    {
        JobId = jobId, ScanRunId = runId, Operation = ScanOperation.ScanPorts, Tool = new ToolSelection { Capability = "import" },
        Targets = new JobTargets { Hosts = [], Count = 0 }, AuthorizedScope = [], Limits = new JobLimits { RatePerSecond = 1, TimeoutSeconds = 1 },
    };

    private static List<IReadOnlyDictionary<string, string>> CsvRows(string text, List<string> errors)
    {
        List<List<string>> table;
        try { table = Csv.Parse(text); }
        catch (FormatException ex) { errors.Add($"CSV: {ex.Message}"); return []; }
        if (table.Count == 0) return [];
        var header = table[0].Select(h => h.Trim()).ToList();
        return table.Skip(1).Select(r => (IReadOnlyDictionary<string, string>)header.Select((h, i) => (h, v: i < r.Count ? r[i] : ""))
            .Where(x => x.v.Length > 0).ToDictionary(x => x.h, x => x.v.TrimStart('\''), StringComparer.OrdinalIgnoreCase)).ToList();
    }

    private static List<IReadOnlyDictionary<string, string>> JsonRows(string text, List<string> errors)
    {
        JsonElement root;
        try { root = JsonDocument.Parse(text).RootElement; }
        catch (JsonException ex) { errors.Add($"JSON: {ex.Message}"); return []; }
        var array = root.ValueKind == JsonValueKind.Object && root.TryGetProperty("items", out var items) ? items : root;
        if (array.ValueKind != JsonValueKind.Array) { errors.Add("JSON: expected an array of records (or { \"items\": [...] })."); return []; }
        return array.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.Object).Select(e =>
            (IReadOnlyDictionary<string, string>)e.EnumerateObject().Where(p => p.Value.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined))
                .ToDictionary(p => p.Name, p => p.Value.ValueKind switch
                {
                    JsonValueKind.String => p.Value.GetString()!,
                    JsonValueKind.Array => string.Join(';', p.Value.EnumerateArray().Select(v => v.ValueKind == JsonValueKind.String ? v.GetString() : v.GetRawText())),
                    _ => p.Value.GetRawText(),
                }, StringComparer.OrdinalIgnoreCase)).ToList();
    }
}

/// <summary>
/// Flat import record → observations. Columns (case-insensitive, CSV or JSON; lists use ';'):
/// address* (ip/host), zone, hostnames, macAddress, macVendor, port, transport, state, serviceName, product, version, banner, tunnel,
/// httpUrl, httpStatusCode, httpTitle, webServer, headers (JSON object or "Name: value" list), cookieNames, redirectChain, finalUrl,
/// faviconHash, tlsSubjectCommonName, tlsIssuer, tlsNotBefore, tlsNotAfter, tlsFingerprintSha256, technologies,
/// signatureId, name, severity, matchedUrl, evidence, observedAt (also lastSeenAt).
/// </summary>
public static class ImportRows
{
    public static IEnumerable<DiscoveryObservation> ToObservations(IReadOnlyDictionary<string, string> row, ObservationSource source, DateTimeOffset now)
    {
        string? S(params string[] names) => names.Select(n => row.TryGetValue(n, out var v) && !string.IsNullOrWhiteSpace(v) ? v.Trim() : null).FirstOrDefault(v => v is not null);
        List<string> L(params string[] names) => S(names)?.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList() ?? [];
        int? I(params string[] names) => S(names) is { } v ? int.TryParse(v, CultureInfo.InvariantCulture, out var n) ? n : throw new FormatException($"'{v}' is not a number.") : null;
        DateTimeOffset? D(params string[] names) => S(names) is { } v ? DateTimeOffset.TryParse(v, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var d) ? d : throw new FormatException($"'{v}' is not a date.") : null;

        var address = S("address", "ip", "host") ?? throw new FormatException("address is required.");
        var port = I("port");
        if (port is < 1 or > 65535) throw new FormatException($"port {port} is out of range.");
        if (S("state") is { } state && !state.Equals("open", StringComparison.OrdinalIgnoreCase))
            yield break; // closed / gone rows of an export are history, not current results
        var transport = port is null ? (TransportProtocol?)null : Enum.TryParse<TransportProtocol>(S("transport", "protocol") ?? "Tcp", true, out var t) ? t : TransportProtocol.Tcp;
        var observedAt = D("observedAt", "lastSeenAt") ?? now;
        var attributes = S("zone") is { } zone ? new Dictionary<string, string> { ["import.zone"] = zone } : null;
        var hostname = L("hostnames", "hostname").FirstOrDefault();

        DiscoveryObservation New(ObservationKind kind, int? p, string? discriminator = null) => new()
        {
            ObservationId = ObservationIds.Compute(source.JobId, kind, address, p, p is null ? null : transport, discriminator),
            Kind = kind, Address = address, Hostname = hostname, Port = p, Transport = p is null ? null : transport, ObservedAt = observedAt,
            Source = source, Attributes = attributes,
        };

        yield return New(ObservationKind.HostUp, null) with
        {
            Host = new HostDetails { Status = "up", Reason = "import", MacAddress = S("macAddress"), MacVendor = S("macVendor"), Hostnames = L("hostnames", "hostname") },
        };
        if (port is null) yield break;

        yield return New(ObservationKind.PortOpen, port) with { PortState = new PortDetails { State = "open", Reason = "import" } };

        var serviceName = S("serviceName", "service");
        if (serviceName is not null || S("product") is not null)
            yield return New(ObservationKind.Service, port) with
            {
                Service = new ServiceDetails { Name = serviceName ?? "unknown", Product = S("product"), Version = S("version"), Banner = S("banner"), Tunnel = S("tunnel") },
            };

        var url = S("httpUrl", "url");
        if (url is not null || I("httpStatusCode", "statusCode") is not null || S("httpTitle", "title") is not null)
        {
            var scheme = url is not null && url.StartsWith("https", StringComparison.OrdinalIgnoreCase) || S("tunnel") == "ssl" || port is 443 or 8443 ? "https" : "http";
            url ??= $"{scheme}://{(address.Contains(':') ? $"[{address}]" : address)}:{port}/";
            yield return New(ObservationKind.HttpResponse, port, url) with
            {
                Http = new HttpDetails
                {
                    Url = url, Scheme = scheme, StatusCode = I("httpStatusCode", "statusCode"), Title = S("httpTitle", "title"), WebServer = S("webServer"),
                    Headers = Headers(S("headers")), CookieNames = L("cookieNames", "cookies"), RedirectChain = L("redirectChain"), FinalUrl = S("finalUrl"),
                    FaviconHash = S("faviconHash"), Technologies = L("technologies"),
                },
            };
        }

        if (S("tlsFingerprintSha256") is { } fingerprint)
            yield return New(ObservationKind.TlsCertificate, port, fingerprint) with
            {
                Tls = new TlsDetails
                {
                    FingerprintSha256 = fingerprint, SubjectCommonName = S("tlsSubjectCommonName"), Issuer = S("tlsIssuer"),
                    NotBefore = D("tlsNotBefore"), NotAfter = D("tlsNotAfter"),
                },
            };

        foreach (var technology in L("technologies"))
        {
            var (name, version) = technology.Split(':', 2) is [var n, var v] ? (n.Trim(), v.Trim()) : (technology, (string?)null);
            yield return New(ObservationKind.Technology, port, name.ToLowerInvariant()) with { Technology = new TechnologyDetails { Name = name, Version = version } };
        }

        if (S("signatureId") is { } signatureId)
            yield return New(ObservationKind.SignatureMatch, port, signatureId) with
            {
                Signature = new SignatureMatchDetails
                {
                    SignatureId = signatureId, Name = S("name", "signatureName") ?? signatureId, Severity = (S("severity") ?? "info").ToLowerInvariant(),
                    MatchedAt = S("matchedUrl"), Evidence = S("evidence"),
                },
            };
    }

    /// <summary>JSON object text or "Name: value" pairs separated by ';' or new lines.</summary>
    private static Dictionary<string, string> Headers(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return [];
        if (raw.TrimStart().StartsWith('{'))
        {
            try
            {
                return JsonDocument.Parse(raw).RootElement.EnumerateObject()
                    .ToDictionary(p => p.Name, p => p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString()! : p.Value.GetRawText(), StringComparer.OrdinalIgnoreCase);
            }
            catch (JsonException) { throw new FormatException("headers is not a JSON object."); }
        }
        return raw.Split([';', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Select(h => h.Split(':', 2)).Where(p => p.Length == 2 && p[0].Trim().Length > 0)
            .GroupBy(p => p[0].Trim(), StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.Last()[1].Trim(), StringComparer.OrdinalIgnoreCase);
    }
}
