using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WebScan.Contracts;
using WebScan.Server.Kernel.Discovery;
using WebScan.Server.Modules.Discovery.Domain;
using WebScan.Server.Modules.Discovery.Fingerprinting;
using WebScan.Server.Modules.Discovery.Normalization;
using WebScan.Server.Modules.Discovery.Persistence;

namespace WebScan.Server.Modules.Discovery.Ingestion;

/// <summary>
/// Applies normalized observations to the current-state model ("last seen", attributes, facts). Never marks anything
/// gone and never changes host/service status of known assets — that is the job of the run comparison.
/// Loads the state of the involved addresses of one zone once (hosts are identified by (zone, address)), mutates tracked
/// entities; the caller saves.
/// </summary>
internal sealed class AssetStateUpdater
{
    /// <summary>Observation kinds proving that the host answered.</summary>
    public static readonly IReadOnlySet<ObservationKind> UpKinds = new HashSet<ObservationKind>
    {
        ObservationKind.HostUp, ObservationKind.PortOpen, ObservationKind.PortClosed, ObservationKind.Service, ObservationKind.HttpResponse,
        ObservationKind.TlsCertificate, ObservationKind.Technology, ObservationKind.SignatureMatch,
    };

    /// <summary>Observation kinds (with a port) proving that the endpoint is open.</summary>
    public static readonly IReadOnlySet<ObservationKind> EndpointKinds = new HashSet<ObservationKind>
    {
        ObservationKind.PortOpen, ObservationKind.Service, ObservationKind.HttpResponse, ObservationKind.TlsCertificate,
        ObservationKind.Technology, ObservationKind.SignatureMatch,
    };

    private readonly DiscoveryDbContext _db;
    private readonly Guid _runId;
    private readonly string _zone;
    private readonly DateTimeOffset _now;
    private readonly Dictionary<string, Host> _hosts;
    private readonly Dictionary<(Guid, int, TransportProtocol), Service> _services;
    private readonly Dictionary<(Guid, int?, string), Technology> _technologies;
    private readonly Dictionary<(Guid, int?, string), SignatureMatch> _matches;
    private readonly Dictionary<(Guid, string), Certificate> _certificates;
    private readonly Dictionary<(Guid, string, int, string), HttpSnapshot> _snapshots;

    private AssetStateUpdater(DiscoveryDbContext db, Guid runId, string zone, DateTimeOffset now, List<Host> hosts, List<Service> services,
        List<Technology> technologies, List<SignatureMatch> matches, List<Certificate> certificates, List<HttpSnapshot> snapshots)
    {
        _db = db;
        _runId = runId;
        _zone = zone;
        _now = now;
        _hosts = hosts.ToDictionary(h => h.Address);
        _services = services.ToDictionary(s => (s.HostId, s.Port, s.Transport));
        _technologies = technologies.ToDictionary(t => (t.HostId, t.Port, t.NameKey));
        _matches = matches.ToDictionary(m => (m.HostId, m.Port, m.SignatureId));
        _certificates = certificates.ToDictionary(c => (c.ServiceId, c.FingerprintSha256));
        _snapshots = snapshots.ToDictionary(s => (s.ServiceId, s.Path, s.HourBucket, s.Fingerprint));
    }

    public static async Task<AssetStateUpdater> LoadAsync(DiscoveryDbContext db, Guid runId, string zone, IEnumerable<string> addresses,
        DateTimeOffset now, CancellationToken ct)
    {
        var addressList = addresses.Distinct().ToList();
        var hosts = await db.Hosts.Where(h => h.Zone == zone && addressList.Contains(h.Address)).ToListAsync(ct);
        var hostIds = hosts.Select(h => h.Id).ToList();
        return new AssetStateUpdater(db, runId, zone, now, hosts,
            await db.Services.Where(s => hostIds.Contains(s.HostId)).ToListAsync(ct),
            await db.Technologies.Where(t => hostIds.Contains(t.HostId)).ToListAsync(ct),
            await db.SignatureMatches.Where(m => hostIds.Contains(m.HostId)).ToListAsync(ct),
            await db.Certificates.Where(c => hostIds.Contains(c.HostId)).ToListAsync(ct),
            await db.HttpSnapshots.Where(s => hostIds.Contains(s.HostId)).ToListAsync(ct));
    }

    public void Apply(DiscoveryObservation o)
    {
        if (o.Kind == ObservationKind.DnsRecord)
        {
            if (_hosts.TryGetValue(o.Address, out var known) && o.Dns is { } dns)
                MergeHostnames(known, dns.RecordType == "PTR" ? dns.Values.Select(Normalizer.CanonicalHostname) : [Normalizer.CanonicalHostname(dns.Name)]);
            return;
        }
        if (!UpKinds.Contains(o.Kind)) return; // HostDown / Generic: raw evidence only

        var seenAt = o.ObservedAt > _now ? _now : o.ObservedAt;
        var host = TouchHost(o.Address, seenAt);
        MergeHostnames(host, [o.Hostname, .. o.Host?.Hostnames ?? []]);
        var service = o.Port is { } port && EndpointKinds.Contains(o.Kind) ? TouchService(host, port, o.Transport ?? TransportProtocol.Tcp, seenAt) : null;

        switch (o.Kind)
        {
            case ObservationKind.HostUp when o.Host is { } h:
                if (h.MacAddress is not null)
                {
                    // Latest value only; history stays in the raw observations. A new MAC without vendor drops the stale vendor.
                    host.MacVendor = h.MacVendor ?? (h.MacAddress == host.MacAddress ? host.MacVendor : null);
                    host.MacAddress = h.MacAddress;
                }
                host.OsGuess = h.OsGuess ?? host.OsGuess;
                break;
            case ObservationKind.Service when service is not null && o.Service is { } s:
                MergeServiceAttributes(service, o, s);
                if (s.Product is not null)
                {
                    var (method, score) = ConfidenceModel.ForService(o);
                    AddTechnology(host, service, s.Product, s.Version, null, method, score, o.Source.ToolId, seenAt);
                }
                ApplyFingerprint(host, service, ServiceFingerprinter.Banner(s), o, seenAt);
                break;
            case ObservationKind.HttpResponse when service is not null && o.Http is { } http:
                ApplyHttp(host, service, http, o, seenAt);
                ApplyFingerprint(host, service, ServiceFingerprinter.Http(http, o.Address), o, seenAt, authoritative: true);
                break;
            case ObservationKind.TlsCertificate when service is not null && o.Tls is { FingerprintSha256: { Length: > 0 } } tls:
                ApplyTls(host, service, tls, seenAt);
                ApplyFingerprint(host, service, ServiceFingerprinter.Tls(tls), o, seenAt);
                break;
            case ObservationKind.Technology when o.Technology is { } t:
            {
                var (method, score) = ConfidenceModel.ForObservation(o, ConfidenceModel.ToolReported);
                AddTechnology(host, service, t.Name, t.Version, t.Category, method, score, o.Source.ToolId, seenAt);
                break;
            }
            case ObservationKind.SignatureMatch when o.Signature is { } sig:
            {
                var (method, score) = ConfidenceModel.ForObservation(o, ConfidenceModel.SignatureMatch);
                var match = UpsertMatch(host, service, o.Port, o.Transport, sig.SignatureId, sig.SignatureVersion, sig.Name, sig.Severity,
                    o.Source.ToolId, sig.Evidence, method, score, o.Hostname, seenAt);
                match.MatcherName = sig.MatcherName;
                match.MatchedUrl = sig.MatchedAt;
                match.Tags = [.. sig.Tags];
                break;
            }
        }
    }

    /// <summary>Records the outcome of an approved classification rule that matched observation <paramref name="o"/>.</summary>
    public void ApplyClassification(ClassificationRule rule, DiscoveryObservation o, string evidence)
    {
        if (!_hosts.TryGetValue(o.Address, out var host)) return; // rule matched non-liveness evidence of an unknown host
        Service? service = null;
        if (o.Port is { } port) _services.TryGetValue((host.Id, port, o.Transport ?? TransportProtocol.Tcp), out service);
        var seenAt = o.ObservedAt > _now ? _now : o.ObservedAt;
        var outcome = rule.Outcome;
        var source = $"{rule.SignatureId}@v{rule.Version}";

        var match = UpsertMatch(host, service, service?.Port, service?.Transport, rule.SignatureId, rule.Version, rule.Name, "info",
            SignatureMatch.ClassificationSource, evidence, ConfidenceModel.SignatureMatch, outcome.Confidence, o.Hostname, seenAt);
        match.ClassificationTag = outcome.ClassificationTag;
        match.Tags = outcome.ClassificationTag is null ? [] : [outcome.ClassificationTag];

        if (outcome.TechnologyName is not null)
        {
            var version = outcome.TechnologyVersion ?? (outcome.TechnologyVersionField is { } f ? ConditionEvaluator.GetField(o, f) : null);
            AddTechnology(host, service, outcome.TechnologyName, version, outcome.TechnologyCategory, ConfidenceModel.SignatureMatch,
                outcome.Confidence, source, seenAt);
        }
    }

    private Host TouchHost(string address, DateTimeOffset seenAt)
    {
        if (!_hosts.TryGetValue(address, out var host))
        {
            host = new Host
            {
                Id = Guid.CreateVersion7(), Address = address, Status = HostStatus.Active, FirstSeenAt = seenAt, LastSeenAt = seenAt,
                FirstSeenRunId = _runId, LastSeenRunId = _runId, Zone = _zone,
            };
            _hosts[address] = host;
            _db.Hosts.Add(host);
        }
        if (seenAt >= host.LastSeenAt) host.LastSeenAt = seenAt;
        host.LastSeenRunId = _runId;
        return host;
    }

    private Service TouchService(Host host, int port, TransportProtocol transport, DateTimeOffset seenAt)
    {
        if (!_services.TryGetValue((host.Id, port, transport), out var service))
        {
            service = new Service
            {
                Id = Guid.CreateVersion7(), HostId = host.Id, Zone = host.Zone, Address = host.Address, Port = port, Transport = transport, State = ServiceState.Open,
                FirstSeenAt = seenAt, LastSeenAt = seenAt, FirstSeenRunId = _runId, LastSeenRunId = _runId,
            };
            _services[(host.Id, port, transport)] = service;
            _db.Services.Add(service);
        }
        if (seenAt >= service.LastSeenAt) service.LastSeenAt = seenAt;
        service.LastSeenRunId = _runId;
        return service;
    }

    private static void MergeHostnames(Host host, IEnumerable<string?> names)
    {
        foreach (var name in names.OfType<string>().Where(n => n.Length > 0 && n != host.Address))
            if (!host.Hostnames.Contains(name) && host.Hostnames.Count < 50) host.Hostnames = [.. host.Hostnames, name];
    }

    /// <summary>Newer run replaces attributes; within a run the most confident observation wins and gaps are filled from the others.</summary>
    private void MergeServiceAttributes(Service service, DiscoveryObservation o, ServiceDetails s)
    {
        var (method, score) = ConfidenceModel.ForService(o);
        var sameRun = service.AttributesRunId == _runId;
        if (!sameRun || score >= (service.Confidence ?? 0))
        {
            service.ServiceName = s.Name != "unknown" || !sameRun ? s.Name : service.ServiceName;
            service.Product = s.Product ?? (sameRun ? service.Product : null);
            service.Version = s.Version ?? (sameRun ? service.Version : null);
            service.ExtraInfo = s.ExtraInfo ?? (sameRun ? service.ExtraInfo : null);
            service.Banner = s.Banner ?? (sameRun ? service.Banner : null);
            service.Tunnel = s.Tunnel ?? (sameRun ? service.Tunnel : null);
            service.Cpe = s.Cpe.Count > 0 || !sameRun ? [.. s.Cpe] : service.Cpe;
            service.Confidence = score;
            service.ConfidenceMethod = method;
            service.AttributesRunId = _runId;
        }
        else
        {
            if (service.ServiceName is null or "unknown") service.ServiceName = s.Name;
            service.Product ??= s.Product;
            service.Version ??= s.Version;
            service.ExtraInfo ??= s.ExtraInfo;
            service.Banner ??= s.Banner;
            service.Tunnel ??= s.Tunnel;
            if (service.Cpe.Count == 0) service.Cpe = [.. s.Cpe];
        }
    }

    private void ApplyHttp(Host host, Service service, HttpDetails http, DiscoveryObservation o, DateTimeOffset seenAt)
    {
        if (service.ServiceName is null or "unknown") service.ServiceName = http.Scheme == "https" ? "https" : "http";
        if (service.HttpObservedAt is null || seenAt >= service.HttpObservedAt)
        {
            service.HttpUrl = http.Url;
            service.HttpStatusCode = http.StatusCode;
            service.HttpTitle = http.Title;
            service.HttpWebServer = http.WebServer;
            service.HttpDetailsJson = JsonSerializer.Serialize(http, ContractJson.Options);
            service.HttpObservedAt = seenAt;
        }

        var path = HttpPath(http.Url);
        var fingerprint = HttpFingerprint(http.StatusCode, http.Title, http.WebServer, http.FaviconHash);
        var bucket = o.ObservedAt.UtcDateTime.Hour;
        if (!_snapshots.TryGetValue((service.Id, path, bucket, fingerprint), out var snapshot))
        {
            snapshot = new HttpSnapshot
            {
                Id = Guid.CreateVersion7(), HostId = host.Id, ServiceId = service.Id, Path = path, HourBucket = bucket, Fingerprint = fingerprint,
                StatusCode = http.StatusCode, Title = http.Title, WebServer = http.WebServer, FirstSeenAt = seenAt, FirstScanRunId = _runId,
            };
            _snapshots[(service.Id, path, bucket, fingerprint)] = snapshot;
            _db.HttpSnapshots.Add(snapshot);
        }
        snapshot.ObservationCount++;
        snapshot.BodySha256 = http.BodySha256 ?? snapshot.BodySha256;
        snapshot.FaviconHash = http.FaviconHash ?? snapshot.FaviconHash;
        if (seenAt >= snapshot.LastSeenAt) snapshot.LastSeenAt = seenAt;
        snapshot.LastScanRunId = _runId;

        foreach (var tech in http.Technologies.Where(t => !string.IsNullOrWhiteSpace(t)))
            AddTechnology(host, service, tech, null, null, ConfidenceModel.ToolReported, ConfidenceModel.BaseScore(ConfidenceModel.ToolReported),
                o.Source.ToolId, seenAt);
    }

    /// <summary>
    /// Recog technologies, device classification and artifacts. Device and artifacts describe the latest run that fingerprinted the
    /// service: its first result replaces them (an HTTP response always counts, so a removed header disappears), later ones merge.
    /// High-signal artifacts are also kept as findings (source "artifact").
    /// </summary>
    private void ApplyFingerprint(Host host, Service service, FingerprintResult result, DiscoveryObservation o, DateTimeOffset seenAt,
        bool authoritative = false)
    {
        if (result.IsEmpty && !authoritative) return;
        if (service.FingerprintRunId != _runId)
        {
            service.Artifacts = [];
            service.DeviceType = service.DeviceVendor = service.DeviceProduct = null;
            service.FingerprintRunId = _runId;
        }
        foreach (var t in result.Technologies)
            AddTechnology(host, service, t.Name, t.Version, t.Category, ConfidenceModel.Recog, t.Score, ConfidenceModel.Recog, seenAt);
        if (result.Device is { } device && service.DeviceType is null)
            (service.DeviceType, service.DeviceVendor, service.DeviceProduct) = (device.Type, device.Vendor, device.Product);
        host.OsGuess ??= result.OsGuess;

        var artifacts = service.Artifacts.ToList();
        foreach (var a in result.Artifacts) HttpArtifacts.Add(artifacts, a.Kind, a.Name, a.Value, a.Reason, a.Tags, a.Severity);
        service.Artifacts = artifacts;

        foreach (var (tag, name) in HttpArtifacts.FindingTags)
        {
            var hits = artifacts.Where(a => a.Tags.Contains(tag)).ToList();
            if (hits.Count == 0) continue;
            var evidence = string.Join('\n', hits.Select(a => $"{a.Kind} {a.Name}: {a.Value} ({a.Reason})"));
            var match = UpsertMatch(host, service, service.Port, service.Transport, $"artifact-{tag}", null, name,
                hits.Any(a => a.Severity == "low") ? "low" : "info", SignatureMatch.ArtifactSource, evidence.Length > 2048 ? evidence[..2048] : evidence,
                SignatureMatch.ArtifactSource, 0.9, o.Hostname, seenAt);
            match.MatchedUrl = o.Http?.Url ?? match.MatchedUrl;
            match.Tags = ["artifact", tag];
        }
    }

    private void ApplyTls(Host host, Service service, TlsDetails tls, DateTimeOffset seenAt)
    {
        var fp = tls.FingerprintSha256!;
        if (!_certificates.TryGetValue((service.Id, fp), out var cert))
        {
            cert = new Certificate
            {
                Id = Guid.CreateVersion7(), HostId = host.Id, ServiceId = service.Id, Address = host.Address, Port = service.Port,
                FingerprintSha256 = fp, FirstSeenAt = seenAt,
            };
            _certificates[(service.Id, fp)] = cert;
            _db.Certificates.Add(cert);
        }
        cert.SubjectCommonName = tls.SubjectCommonName ?? cert.SubjectCommonName;
        cert.SubjectAlternativeNames = tls.SubjectAlternativeNames.Count > 0 ? [.. tls.SubjectAlternativeNames] : cert.SubjectAlternativeNames;
        cert.Issuer = tls.Issuer ?? cert.Issuer;
        cert.NotBefore = tls.NotBefore ?? cert.NotBefore;
        cert.NotAfter = tls.NotAfter ?? cert.NotAfter;
        cert.SerialNumber = tls.SerialNumber ?? cert.SerialNumber;
        cert.SelfSigned = tls.SelfSigned ?? cert.SelfSigned;
        cert.TlsVersion = tls.TlsVersion ?? cert.TlsVersion;
        if (seenAt >= cert.LastSeenAt) cert.LastSeenAt = seenAt;

        if (service.TlsObservedAt is null || seenAt >= service.TlsObservedAt)
        {
            service.CurrentCertFingerprint = fp;
            service.TlsObservedAt = seenAt;
        }
    }

    private void AddTechnology(Host host, Service? service, string rawName, string? rawVersion, string? rawCategory, string method, double score,
        string source, DateTimeOffset seenAt)
    {
        var (name, version, category, key) = Normalizer.CanonicalTechnology(rawName, rawVersion, rawCategory);
        if (name.Length is 0 or > 100) return;
        var port = service?.Port;
        if (!_technologies.TryGetValue((host.Id, port, key), out var tech))
        {
            tech = new Technology
            {
                Id = Guid.CreateVersion7(), HostId = host.Id, ServiceId = service?.Id, Address = host.Address, Port = port, Name = name,
                NameKey = key, ConfidenceMethod = method, FirstSeenAt = seenAt, LastSeenRunId = _runId,
            };
            _technologies[(host.Id, port, key)] = tech;
            _db.Technologies.Add(tech);
        }
        else if (tech.LastSeenRunId != _runId)
        {
            // Evidence and version reflect the latest run that saw the technology.
            tech.Evidence = [];
            tech.Sources = [];
            tech.VersionScore = 0;
            tech.LastSeenRunId = _runId;
        }

        var existing = tech.Evidence.FirstOrDefault(e => e.Method == method);
        if (existing is null) tech.Evidence = [.. tech.Evidence, new TechnologyEvidence { Method = method, Score = score }];
        else if (score > existing.Score) tech.Evidence = [.. tech.Evidence.Where(e => e != existing), new TechnologyEvidence { Method = method, Score = score }];
        if (!tech.Sources.Contains(source) && tech.Sources.Count < 20) tech.Sources = [.. tech.Sources, source];
        if (version is not null && score >= tech.VersionScore)
        {
            tech.Version = version;
            tech.VersionScore = score;
        }
        tech.Category ??= category;
        (tech.Confidence, tech.ConfidenceMethod) = ConfidenceModel.Combine(tech.Evidence.Select(e => (e.Method, e.Score)));
        if (seenAt >= tech.LastSeenAt) tech.LastSeenAt = seenAt;
    }

    private SignatureMatch UpsertMatch(Host host, Service? service, int? port, TransportProtocol? transport, string signatureId, int? version,
        string name, string severity, string source, string? evidence, string method, double score, string? hostname, DateTimeOffset seenAt)
    {
        if (!_matches.TryGetValue((host.Id, port, signatureId), out var match))
        {
            match = new SignatureMatch
            {
                Id = Guid.CreateVersion7(), HostId = host.Id, Zone = host.Zone, Address = host.Address, Port = port, Transport = transport, SignatureId = signatureId,
                Name = name, Severity = severity, Source = source, ConfidenceMethod = method, FirstSeenAt = seenAt, MatchedAt = seenAt,
            };
            _matches[(host.Id, port, signatureId)] = match;
            _db.SignatureMatches.Add(match);
        }
        match.ServiceId = service?.Id ?? match.ServiceId;
        match.Hostname = hostname ?? match.Hostname;
        match.SignatureVersion = version ?? match.SignatureVersion;
        match.Name = name;
        match.Severity = Normalizer.CanonicalSeverity(severity);
        match.Source = source;
        match.Evidence = evidence ?? match.Evidence;
        match.ConfidenceScore = Math.Round(score, 3);
        match.ConfidenceMethod = method;
        if (seenAt >= match.MatchedAt) match.MatchedAt = seenAt;
        if (seenAt >= match.LastSeenAt) match.LastSeenAt = seenAt;
        match.LastSeenRunId = _runId;
        match.Status = FindingStatus.Open;
        match.ResolvedAt = null;
        match.ConsecutiveMisses = 0;
        return match;
    }

    public static string HttpPath(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var uri) ? uri.PathAndQuery : url.Length > 500 ? url[..500] : url;

    /// <summary>Material response fingerprint: status, title, server header and favicon (body hash excluded: dynamic pages change it every request).</summary>
    public static string HttpFingerprint(int? status, string? title, string? server, string? favicon) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes($"{status}|{title}|{server}|{favicon}")));
}
