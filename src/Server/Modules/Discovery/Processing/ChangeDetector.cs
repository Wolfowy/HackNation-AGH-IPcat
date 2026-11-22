using System.Globalization;
using Microsoft.EntityFrameworkCore;
using WebScan.Contracts;
using WebScan.Server.Kernel.Discovery;
using WebScan.Server.Modules.Discovery.Domain;
using WebScan.Server.Modules.Discovery.Ingestion;
using WebScan.Server.Modules.Discovery.Persistence;

namespace WebScan.Server.Modules.Discovery.Processing;

internal sealed record DetectedChange(ChangeEvent Event, IReadOnlyDictionary<string, string?> Fields);

/// <summary>
/// Compares the evidence of one run with the current-state baselines (values as of the previous comparison) and advances
/// the host/service/finding state machines. Miss counting follows <see cref="CoverageSet"/>: only complete runs that covered
/// the target with the relevant operation count; "gone" needs <c>missingThreshold</c> consecutive misses; flapping hosts
/// become unstable and stop producing gone/reappeared events.
/// </summary>
internal sealed class ChangeDetector(DiscoveryDbContext db, Guid runId, CoverageSet coverage, int missingThreshold, DiscoveryOptions options, DateTimeOffset now)
{
    private readonly List<DetectedChange> _changes = [];
    // Keys start with the zone: hosts are identified by (zone, address).
    private HashSet<(string, string)> _seenHosts = [];
    private HashSet<(string, string, int, TransportProtocol)> _seenEndpoints = [];
    private HashSet<Guid> _newHosts = [];
    private HashSet<Guid> _newServices = [];

    public async Task<List<DetectedChange>> DetectAsync(CancellationToken ct)
    {
        var seen = await db.Observations.Where(o => o.ScanRunId == runId)
            .Select(o => new { o.Zone, o.Address, o.Port, o.Transport, o.Kind }).Distinct().ToListAsync(ct);
        _seenHosts = seen.Where(s => AssetStateUpdater.UpKinds.Contains(s.Kind)).Select(s => (s.Zone, s.Address)).ToHashSet();
        _seenEndpoints = seen.Where(s => s.Port is not null && AssetStateUpdater.EndpointKinds.Contains(s.Kind))
            .Select(s => (s.Zone, s.Address, s.Port!.Value, s.Transport ?? TransportProtocol.Tcp)).ToHashSet();
        var tlsEndpoints = seen.Where(s => s.Port is not null && s.Kind == ObservationKind.TlsCertificate)
            .Select(s => (s.Zone, s.Address, s.Port!.Value, s.Transport ?? TransportProtocol.Tcp)).ToHashSet();

        // shortcut: coverage containment is tested in memory over all hosts; fine up to ~10^5 hosts, move it to SQL (inet <<=) beyond.
        var hosts = (await db.Hosts.ToListAsync(ct)).Where(h => _seenHosts.Contains((h.Zone, h.Address)) || coverage.CoversHost(h.Zone, h.Address)).ToList();
        var hostsById = hosts.ToDictionary(h => h.Id);
        var hostIds = hostsById.Keys.ToList();
        var services = await db.Services.Where(s => hostIds.Contains(s.HostId)).ToListAsync(ct);
        var technologies = await db.Technologies.Where(t => hostIds.Contains(t.HostId) && t.LastSeenRunId == runId).ToListAsync(ct);
        var openFindings = await db.SignatureMatches.Where(m => hostIds.Contains(m.HostId) && m.Status == FindingStatus.Open).ToListAsync(ct);
        var httpServiceIds = await db.HttpSnapshots.Where(s => s.LastScanRunId == runId).Select(s => s.ServiceId).Distinct().ToListAsync(ct);
        var snapshots = await db.HttpSnapshots.Where(s => httpServiceIds.Contains(s.ServiceId)).ToListAsync(ct);
        var tlsServiceIds = services.Where(s => tlsEndpoints.Contains((s.Zone, s.Address, s.Port, s.Transport))).Select(s => s.Id).ToList();
        var certificates = await db.Certificates.Where(c => tlsServiceIds.Contains(c.ServiceId)).ToListAsync(ct);

        _newHosts = hosts.Where(h => h.ComparedAt is null).Select(h => h.Id).ToHashSet();
        _newServices = services.Where(s => s.ComparedAt is null || s.State == ServiceState.Gone).Select(s => s.Id).ToHashSet();

        var goneHosts = DetectHosts(hosts);
        var goneServices = DetectServices(services, hostsById, tlsEndpoints, certificates, goneHosts);
        DetectTechnologies(technologies, hostsById, services.ToDictionary(s => s.Id));
        DetectHttp(snapshots, hostsById, services.Where(s => httpServiceIds.Contains(s.Id)).ToList());
        ResolveFindings(openFindings, goneHosts, goneServices);
        return _changes;
    }

    private HashSet<Guid> DetectHosts(List<Host> hosts)
    {
        var gone = new HashSet<Guid>();
        foreach (var host in hosts)
        {
            var seen = _seenHosts.Contains((host.Zone, host.Address));
            var missed = !seen && (coverage.CanCountMiss(host.Zone, host.Address, ScanOperation.DiscoverHosts)
                || coverage.CanCountMiss(host.Zone, host.Address, ScanOperation.ScanPorts));
            if (!seen && !missed) continue;

            RecordOutcome(host, seen ? 'U' : 'D');
            if (seen)
            {
                if (_newHosts.Contains(host.Id)) Emit(AssetChangeType.NewHost, host, null, $"New host {Label(host)}", null, "Active");
                else if (host.Status == HostStatus.Gone && !host.Unstable)
                    Emit(AssetChangeType.HostReappeared, host, null, $"Host {Label(host)} reappeared", "Gone", "Active");
                host.Status = HostStatus.Active;
                host.ConsecutiveMisses = 0;
                host.ComparedAt = now;
                continue;
            }

            host.ConsecutiveMisses++;
            if (host.Status is HostStatus.Active or HostStatus.Unknown) host.Status = HostStatus.Unreachable;
            if (host.ConsecutiveMisses >= missingThreshold && host.Status != HostStatus.Gone)
            {
                host.Status = HostStatus.Gone;
                gone.Add(host.Id);
                if (!host.Unstable)
                    Emit(AssetChangeType.HostGone, host, null, $"Host {Label(host)} gone: no response in {host.ConsecutiveMisses} covering scan(s)", "Active", "Gone");
            }
        }
        return gone;
    }

    private void RecordOutcome(Host host, char outcome)
    {
        if (host.StateHistory.Length > 0 && host.StateHistory[^1] != outcome) host.StateChangeCount++;
        var history = host.StateHistory + outcome;
        host.StateHistory = history.Length > Host.StateHistoryLength ? history[^Host.StateHistoryLength..] : history;
        var transitions = Enumerable.Range(1, host.StateHistory.Length - 1).Count(i => host.StateHistory[i] != host.StateHistory[i - 1]);
        host.Unstable = transitions >= options.FlapTransitions;

        var hour = now.UtcDateTime.Hour;
        host.HourlySeen = Hourly(host.HourlySeen, outcome == 'U' ? hour : -1);
        host.HourlyMissed = Hourly(host.HourlyMissed, outcome == 'D' ? hour : -1);
    }

    /// <summary>24 per-hour counters (padded), <paramref name="hour"/> incremented; a new list so EF sees the change.</summary>
    private static List<int> Hourly(List<int> counts, int hour) =>
        Enumerable.Range(0, 24).Select(h => counts.ElementAtOrDefault(h) + (h == hour ? 1 : 0)).ToList();

    private HashSet<Guid> DetectServices(List<Service> services, Dictionary<Guid, Host> hosts, HashSet<(string, string, int, TransportProtocol)> tlsEndpoints,
        List<Certificate> certificates, HashSet<Guid> goneHosts)
    {
        var gone = new HashSet<Guid>();
        foreach (var s in services)
        {
            var host = hosts[s.HostId];
            var key = (s.Zone, s.Address, s.Port, s.Transport);
            var endpoint = $"{s.Address}:{s.Port}/{s.Transport.ToString().ToLowerInvariant()}";
            var summary = Summary(s);
            if (_seenEndpoints.Contains(key))
            {
                if (_newServices.Contains(s.Id))
                    Emit(AssetChangeType.NewPort, host, s, s.State == ServiceState.Gone ? $"Port {endpoint} reopened" : $"New open port {endpoint}", null, summary);
                else if (!IsKnown(s.ComparedServiceName) && IsKnown(s.ServiceName))
                    Emit(AssetChangeType.NewService, host, s, $"Service {s.ServiceName} identified on {endpoint}", s.ComparedSummary, summary);
                else if (IsKnown(s.ServiceName) && s.ComparedSummary != summary)
                    Emit(AssetChangeType.ServiceChanged, host, s, $"Service on {endpoint} changed", s.ComparedSummary, summary);

                if (tlsEndpoints.Contains(key) && s.CurrentCertFingerprint is { } fp)
                {
                    if (!_newServices.Contains(s.Id) && s.ComparedCertFingerprint is { } previous && previous != fp)
                        Emit(AssetChangeType.TlsCertificateChanged, host, s, $"TLS certificate on {endpoint} changed",
                            CertLabel(certificates, s.Id, previous), CertLabel(certificates, s.Id, fp));
                    s.ComparedCertFingerprint = fp;
                }

                s.State = ServiceState.Open;
                s.ConsecutiveMisses = 0;
                s.ComparedAt = now;
                s.ComparedServiceName = s.ServiceName;
                s.ComparedSummary = summary;
            }
            else if (s.State == ServiceState.Open && goneHosts.Contains(s.HostId))
            {
                s.State = ServiceState.Gone; // reported once, as HostGone
                gone.Add(s.Id);
            }
            else if (s.State == ServiceState.Open && coverage.CanCountMiss(s.Zone, s.Address, ScanOperation.ScanPorts))
            {
                s.ConsecutiveMisses++;
                if (s.ConsecutiveMisses < missingThreshold) continue;
                s.State = ServiceState.Gone;
                gone.Add(s.Id);
                Emit(AssetChangeType.PortGone, host, s, $"Port {endpoint} gone: closed in {s.ConsecutiveMisses} covering scan(s)", summary, null);
            }
        }
        return gone;
    }

    private void DetectTechnologies(List<Technology> technologies, Dictionary<Guid, Host> hosts, Dictionary<Guid, Service> services)
    {
        foreach (var t in technologies)
        {
            if (!hosts.TryGetValue(t.HostId, out var host)) continue;
            var service = t.ServiceId is { } sid ? services.GetValueOrDefault(sid) : null;
            var endpointIsNew = service is not null ? _newServices.Contains(service.Id) : _newHosts.Contains(host.Id);
            var where = service is null ? host.Address : $"{host.Address}:{service.Port}";
            if (t.ComparedAt is null)
            {
                if (!endpointIsNew)
                    Emit(AssetChangeType.TechnologyChanged, host, service, $"Technology {Label(t.Name, t.Version)} detected on {where}", null,
                        Label(t.Name, t.Version), t);
            }
            else if (t.Version is not null && t.Version != t.ComparedVersion)
                Emit(AssetChangeType.TechnologyChanged, host, service, $"{t.Name} on {where} changed version", Label(t.Name, t.ComparedVersion),
                    Label(t.Name, t.Version), t);

            t.ComparedAt = now;
            t.ComparedVersion = t.Version ?? t.ComparedVersion;
        }
    }

    private void DetectHttp(List<HttpSnapshot> snapshots, Dictionary<Guid, Host> hosts, List<Service> httpServices)
    {
        var variance = new Dictionary<Guid, string>();
        foreach (var group in snapshots.GroupBy(s => (s.ServiceId, s.Path)))
        {
            var service = httpServices.FirstOrDefault(s => s.Id == group.Key.ServiceId);
            if (service is null || !hosts.TryGetValue(service.HostId, out var host)) continue;
            var current = group.Where(s => s.LastScanRunId == runId).MaxBy(s => s.LastSeenAt);
            if (current is null) continue;

            var prior = group.Where(s => s.FirstScanRunId != runId).ToList();
            if (prior.Count > 0 && current.FirstScanRunId == runId && !_newServices.Contains(service.Id))
            {
                // New response for this hour: compare with what this hour usually returns, else with any known response.
                var sameHour = prior.Where(s => s.HourBucket == current.HourBucket).ToList();
                var before = sameHour.Count > 0 ? sameHour.MaxBy(s => s.ObservationCount)
                    : prior.Any(s => s.Fingerprint == current.Fingerprint) ? null
                    : prior.MaxBy(s => s.LastSeenAt);
                if (before is not null)
                    Emit(AssetChangeType.HttpResponseChanged, host, service, $"HTTP response of {Url(service, group.Key.Path)} changed",
                        Describe(before), Describe(current));
            }

            var analysis = TimeOfDayVarianceAnalyzer.Analyze(
                group.Select(s => new HourlyResponse(s.HourBucket, s.Fingerprint, s.ObservationCount, Describe(s), s.FirstSeenAt, s.LastSeenAt)),
                options.TimeOfDayMinObservations);
            if (analysis.HasVariance && !variance.ContainsKey(service.Id))
                variance[service.Id] = $"{group.Key.Path} → {analysis.Describe()}";
        }

        foreach (var service in httpServices)
        {
            var hasVariance = variance.TryGetValue(service.Id, out var description);
            if (hasVariance && !service.TimeOfDayVariance && hosts.TryGetValue(service.HostId, out var host))
                Emit(AssetChangeType.TimeOfDayVariance, host, service, $"{service.Address}:{service.Port} responds differently by time of day", null, description);
            service.TimeOfDayVariance = hasVariance;
        }
    }

    /// <summary>
    /// Detections resolve after <c>missingThreshold</c> complete runs that executed signatures on the covered endpoint without
    /// reproducing them (artifact findings: runs that probed HTTP); any finding resolves when its host or port is gone. Classification results are interpretations of
    /// whatever evidence a run produced, so they resolve only with their asset.
    /// </summary>
    private void ResolveFindings(List<SignatureMatch> openFindings, HashSet<Guid> goneHosts, HashSet<Guid> goneServices)
    {
        foreach (var m in openFindings.Where(m => m.LastSeenRunId != runId))
        {
            var assetGone = goneHosts.Contains(m.HostId) || (m.ServiceId is { } sid && goneServices.Contains(sid));
            var missed = !assetGone && m.Source != SignatureMatch.ClassificationSource && coverage.Complete
                && coverage.Executed(m.Source == SignatureMatch.ArtifactSource ? ScanOperation.HttpProbe : ScanOperation.ExecuteSignatures)
                && (m.Port is { } port ? coverage.CoversEndpoint(m.Zone, m.Address, port) : coverage.CoversHost(m.Zone, m.Address));
            if (missed) m.ConsecutiveMisses++;
            if (assetGone || (missed && m.ConsecutiveMisses >= missingThreshold))
            {
                m.Status = FindingStatus.Resolved;
                m.ResolvedAt = now;
            }
        }
    }

    private void Emit(AssetChangeType type, Host host, Service? service, string summary, string? before, string? after, Technology? technology = null)
    {
        var change = new ChangeEvent
        {
            Id = Guid.CreateVersion7(), DetectedAt = now, ScanRunId = runId, Type = type, HostId = host.Id, Zone = host.Zone, Address = host.Address,
            Port = service?.Port, Summary = summary, Before = before, After = after, Severity = DefaultSeverity(type),
        };
        var fields = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            [ConditionFields.Address] = host.Address,
            [ConditionFields.Hostname] = host.Hostnames.FirstOrDefault(),
            [ConditionFields.Port] = service?.Port.ToString(CultureInfo.InvariantCulture),
            [ConditionFields.Transport] = service?.Transport.ToString().ToLowerInvariant(),
            [ConditionFields.ServiceName] = service?.ServiceName,
            [ConditionFields.ServiceProduct] = service?.Product,
            [ConditionFields.ServiceVersion] = service?.Version,
            [ConditionFields.TechnologyName] = technology?.Name,
            [ConditionFields.TechnologyCategory] = technology?.Category,
        };
        _changes.Add(new DetectedChange(change, fields));
    }

    public static string DefaultSeverity(AssetChangeType type) => type switch
    {
        AssetChangeType.NewHost or AssetChangeType.HostGone or AssetChangeType.NewPort or AssetChangeType.ServiceChanged
            or AssetChangeType.TlsCertificateChanged => "low",
        _ => "info",
    };

    private static bool IsKnown(string? serviceName) => serviceName is not null and not "unknown";

    public static string Summary(Service s) => string.Join(' ', new[] { s.ServiceName, s.Product, s.Version }.Where(x => !string.IsNullOrEmpty(x)));

    private static string Label(Host h) => h.Hostnames.Count > 0 ? $"{h.Address} ({h.Hostnames[0]})" : h.Address;

    private static string Label(string name, string? version) => version is null ? name : $"{name} {version}";

    private static string Url(Service s, string path) => $"{s.Address}:{s.Port}{path}";

    private static string Describe(HttpSnapshot s) => $"{s.StatusCode} '{s.Title}' {s.WebServer}".Trim();

    private static string CertLabel(List<Certificate> certificates, Guid serviceId, string fingerprint)
    {
        var cert = certificates.FirstOrDefault(c => c.ServiceId == serviceId && c.FingerprintSha256 == fingerprint);
        var subject = cert?.SubjectCommonName is { } cn ? $"CN={cn}, " : "";
        var expiry = cert?.NotAfter is { } na ? $", expires {na:yyyy-MM-dd}" : "";
        return $"{subject}sha256 {fingerprint[..Math.Min(16, fingerprint.Length)]}{expiry}";
    }
}
