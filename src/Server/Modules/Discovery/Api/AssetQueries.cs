using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WebScan.Contracts;
using WebScan.Server.Kernel.Discovery;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Kernel.Scanning;
using WebScan.Server.Modules.Discovery.Domain;
using WebScan.Server.Modules.Discovery.Normalization;
using WebScan.Server.Modules.Discovery.Persistence;

namespace WebScan.Server.Modules.Discovery.Api;

/// <param name="Sort">"interest" = highest interest score first; default zone/address order.</param>
/// <param name="MinInterest">Only hosts whose interest score is at least this.</param>
public sealed record HostQuery(string? Search, HostStatus? Status, string? Zone, bool NetworkDevice = false, string? Sort = null, int? MinInterest = null);
/// <param name="Sort">"interest" = highest interest score first; default zone/address/port order.</param>
/// <param name="MinInterest">Only services whose interest score is at least this.</param>
public sealed record ServiceQuery(int? Port, string? ServiceName, string? Search, string? Zone = null, string? Sort = null, int? MinInterest = null);
public sealed record ChangeQuery(DateTimeOffset? Since, AssetChangeType? Type, Guid? HostId, Guid? ScanRunId, string? Zone = null);
public sealed record FindingQuery(string? Severity, FindingStatus? Status, string? Zone = null);
public sealed record TopologyQuery(string? Zone, string? Search);

/// <summary>Read models of the current-state tables, shared by the list and export endpoints.</summary>
internal sealed class AssetQueries(DiscoveryDbContext db, TimeProvider time)
{
    public const int MaxPageSize = 500;

    /// <summary>shortcut: exports are built in memory and capped; stream rows if larger exports are needed.</summary>
    public const int MaxExportRows = 100_000;

    public static (int Page, int PageSize) Paging(int? page, int? pageSize) => (Math.Max(1, page ?? 1), Math.Clamp(pageSize ?? 50, 1, MaxPageSize));

    public async Task<PagedResult<HostListItemDto>> HostsAsync(HostQuery query, int page, int pageSize, CancellationToken ct)
    {
        var q = db.Hosts.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(query.Search))
        {
            var like = Like(query.Search);
            q = q.Where(h => EF.Functions.ILike(h.Address, like) || h.Hostnames.Any(n => EF.Functions.ILike(n, like)));
        }
        if (query.Status is not null) q = q.Where(h => h.Status == query.Status);
        if (!string.IsNullOrWhiteSpace(query.Zone)) q = q.Where(h => h.Zone == query.Zone);
        if (query.NetworkDevice)
        {
            var deviceHosts = (await DevicesAsync(null, ct)).ByHost.Keys.ToList();
            q = q.Where(h => deviceHosts.Contains(h.Id));
        }

        q = q.OrderBy(h => h.Zone).ThenBy(h => h.Address);
        if (ByInterest(query.Sort, query.MinInterest))
        {
            // shortcut: the score is computed, not stored, so ranking loads every matching host (capped); persist scores if this gets slow.
            var all = await q.Take(MaxExportRows).ToListAsync(ct);
            var (_, scores) = await InterestAsync(all.Select(h => h.Id).ToList(), null, ct);
            var ranked = Rank(all, h => scores[h.Id].Score, query.Sort, query.MinInterest);
            return new PagedResult<HostListItemDto>(await ToHostItemsAsync(ranked.Skip((page - 1) * pageSize).Take(pageSize).ToList(), ct, scores),
                ranked.Count, page, pageSize);
        }

        var total = await q.CountAsync(ct);
        var hosts = await q.Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(ct);
        return new PagedResult<HostListItemDto>(await ToHostItemsAsync(hosts, ct), total, page, pageSize);
    }

    private static bool ByInterest(string? sort, int? minInterest) => string.Equals(sort, "interest", StringComparison.OrdinalIgnoreCase) || minInterest > 0;

    /// <summary>Filters by <paramref name="minInterest"/>; sorts by score (stable, keeps the default order on ties) when asked to.</summary>
    private static List<T> Rank<T>(List<T> items, Func<T, int> score, string? sort, int? minInterest)
    {
        var kept = items.Where(i => score(i) >= (minInterest ?? 0));
        return (string.Equals(sort, "interest", StringComparison.OrdinalIgnoreCase) ? kept.OrderByDescending(score) : kept).ToList();
    }

    public async Task<HostDetailDto?> HostAsync(Guid id, CancellationToken ct)
    {
        var host = await db.Hosts.AsNoTracking().FirstOrDefaultAsync(h => h.Id == id, ct);
        if (host is null) return null;
        var hostServices = await db.Services.AsNoTracking().Where(s => s.HostId == id).OrderBy(s => s.Port).ToListAsync(ct);
        var (serviceScores, hostScores) = await InterestAsync([id], hostServices, ct);
        var item = (await ToHostItemsAsync([host], ct, hostScores))[0];
        var services = await ToServiceDtosAsync(hostServices, ct, serviceScores);
        var technologies = await db.Technologies.AsNoTracking().Where(t => t.HostId == id).OrderBy(t => t.Port).ThenBy(t => t.Name).ToListAsync(ct);
        var certificates = await db.Certificates.AsNoTracking().Where(c => c.HostId == id).OrderByDescending(c => c.LastSeenAt).ToListAsync(ct);
        var findings = await db.SignatureMatches.AsNoTracking().Where(m => m.HostId == id).OrderByDescending(m => m.MatchedAt).ToListAsync(ct);
        var changes = await db.Changes.AsNoTracking().Where(c => c.HostId == id).OrderByDescending(c => c.DetectedAt).Take(50).ToListAsync(ct);
        var device = host.MacAddress is null ? null : (await DevicesAsync([host.MacAddress], ct)).ByHost.GetValueOrDefault(id);
        return new HostDetailDto(host.Id, host.Address, host.Hostnames, host.Status, host.Unstable, host.FirstSeenAt, host.LastSeenAt,
            host.LastScannedAt, item.OpenPortCount, host.Zone, item.Annotation, item.Classifications, host.MacAddress, host.MacVendor,
            host.OsGuess, host.ConsecutiveMisses, host.StateChangeCount, services, technologies.Select(t => t.ToDto()).ToList(),
            certificates.Select(c => c.ToDto()).ToList(), findings.Select(f => f.ToDto()).ToList(), changes.Select(c => c.ToDto()).ToList(),
            item.NetworkDevice, item.NetworkDeviceConfidence, device?.Interfaces.Where(i => i.HostId != id).ToList() ?? [],
            Enumerable.Range(0, 24).Select(h => new HourVisibilityDto(h, host.HourlySeen.ElementAtOrDefault(h), host.HourlyMissed.ElementAtOrDefault(h))).ToList(),
            item.InterestScore, item.InterestReasons ?? []);
    }

    public async Task<PagedResult<ServiceDto>> ServicesAsync(ServiceQuery query, int page, int pageSize, CancellationToken ct)
    {
        var q = db.Services.AsNoTracking();
        if (query.Port is not null) q = q.Where(s => s.Port == query.Port);
        if (!string.IsNullOrWhiteSpace(query.ServiceName))
        {
            var name = Normalizer.CanonicalServiceName(query.ServiceName);
            q = q.Where(s => s.ServiceName == name);
        }
        if (!string.IsNullOrWhiteSpace(query.Search))
        {
            var like = Like(query.Search);
            q = q.Where(s => EF.Functions.ILike(s.Address, like) || EF.Functions.ILike(s.Product ?? "", like)
                || EF.Functions.ILike(s.Banner ?? "", like) || EF.Functions.ILike(s.HttpTitle ?? "", like));
        }
        if (!string.IsNullOrWhiteSpace(query.Zone)) q = q.Where(s => s.Zone == query.Zone);

        q = q.OrderBy(s => s.Zone).ThenBy(s => s.Address).ThenBy(s => s.Port);
        if (ByInterest(query.Sort, query.MinInterest))
        {
            // shortcut: computed score, so ranking loads every matching service (capped); persist scores if this gets slow.
            var all = await q.Take(MaxExportRows).ToListAsync(ct);
            var (scores, _) = await InterestAsync(all.Select(s => s.HostId).Distinct().ToList(), all, ct);
            var ranked = Rank(all, s => scores[s.Id].Score, query.Sort, query.MinInterest);
            return new PagedResult<ServiceDto>(await ToServiceDtosAsync(ranked.Skip((page - 1) * pageSize).Take(pageSize).ToList(), ct, scores),
                ranked.Count, page, pageSize);
        }

        var total = await q.CountAsync(ct);
        var services = await q.Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(ct);
        return new PagedResult<ServiceDto>(await ToServiceDtosAsync(services, ct), total, page, pageSize);
    }

    /// <summary>Current-state graph (Gone hosts included with their status, Gone services excluded), capped at <see cref="Topology.MaxHosts"/>.</summary>
    public async Task<TopologyDto> TopologyAsync(TopologyQuery query, ResolvedScope? network, CancellationToken ct)
    {
        var q = db.Hosts.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(query.Search))
        {
            var like = Like(query.Search);
            q = q.Where(h => EF.Functions.ILike(h.Address, like) || h.Hostnames.Any(n => EF.Functions.ILike(n, like)));
        }
        if (!string.IsNullOrWhiteSpace(query.Zone)) q = q.Where(h => h.Zone == query.Zone);
        if (network is not null)
        {
            // A network's ranges contain only machines of its own zone (the same IP elsewhere is another machine).
            var networkZones = network.Segments.Select(s => Normalizer.CanonicalZone(s.Zone)).Distinct().ToList();
            q = q.Where(h => networkZones.Contains(h.Zone));
        }
        q = q.OrderBy(h => h.Zone).ThenBy(h => h.Address);
        // Network membership needs IP math, so a network filter loads the (projected) zone/search matches and filters in memory.
        if (network is null) q = q.Take(Topology.MaxHosts + 1);
        var rows = await q.Select(h => new { h.Id, h.Address, h.Hostnames, h.Status, h.Unstable, h.Zone, h.LastSeenAt, h.MacAddress, h.MacVendor })
            .ToListAsync(ct);
        if (network is not null)
        {
            var inNetwork = Topology.NetworkMatcher(network);
            rows = rows.Where(h => inNetwork(h.Address, h.Hostnames)).Take(Topology.MaxHosts + 1).ToList();
        }
        var truncated = rows.Count > Topology.MaxHosts;
        if (truncated) rows.RemoveAt(Topology.MaxHosts);

        var ids = rows.Select(h => h.Id).ToList();
        var addresses = rows.Select(h => h.Address).ToList();
        var services = (await db.Services.AsNoTracking().Where(s => ids.Contains(s.HostId) && s.State == ServiceState.Open)
                .OrderBy(s => s.Port).ThenBy(s => s.Transport)
                .Select(s => new { s.HostId, s.Port, s.Transport, s.ServiceName, s.Product, s.Version, s.Tunnel, s.HttpUrl, Cert = s.CurrentCertFingerprint != null })
                .ToListAsync(ct))
            .ToLookup(s => s.HostId);
        var technologies = (await db.Technologies.AsNoTracking().Where(t => ids.Contains(t.HostId)).Select(t => new { t.HostId, t.Name }).Distinct()
            .ToListAsync(ct)).ToLookup(t => t.HostId, t => t.Name);
        // shortcut: DISTINCT over all raw observations of the hosts; add an (address, agent, interface) index or a perspective table if this gets slow.
        var seen = await db.Observations.AsNoTracking().Where(o => addresses.Contains(o.Address))
            .Select(o => new { o.Address, o.AgentId, o.InterfaceName, o.Zone }).Distinct().ToListAsync(ct);
        // Only observations of the host's own zone: the same IP in another zone is another machine (and another perspective edge).
        var observedBy = seen.ToLookup(o => (o.Zone, o.Address));
        var inference = await DevicesAsync(rows.Select(h => h.MacAddress).OfType<string>().Distinct().ToList(), ct);

        var hosts = rows.Select(h => new TopologyHostDto(h.Id, h.Address, h.Hostnames, h.Status, h.Unstable,
            Topology.SubnetId(h.Zone, Topology.SubnetOf(h.Address)), h.Zone, h.LastSeenAt, h.MacAddress, h.MacVendor, services[h.Id].Count(),
            services[h.Id].Select(s => new TopologyServiceDto(s.Port, s.Transport, s.ServiceName, s.Product, s.Version,
                Topology.ServiceUrl(h.Address, s.Port, s.ServiceName, s.Tunnel, s.HttpUrl, s.Cert),
                s.HttpUrl is not null || Topology.IsWebName(s.ServiceName), Topology.IsTls(s.ServiceName, s.Tunnel, s.Cert))).ToList(),
            technologies[h.Id].Order(StringComparer.OrdinalIgnoreCase).ToList(),
            observedBy[(h.Zone, h.Address)].Select(o => new ObservedByDto(o.AgentId, o.InterfaceName)).Distinct()
                .OrderBy(o => o.AgentId, StringComparer.Ordinal).ThenBy(o => o.InterfaceName, StringComparer.Ordinal).ToList(),
            inference.ByHost.GetValueOrDefault(h.Id)?.Id, inference.SharedMac.Contains(h.Id))).ToList();
        var subnets = hosts.GroupBy(h => (h.Zone, Cidr: Topology.SubnetOf(h.Address)))
            .OrderBy(g => g.Key.Zone, StringComparer.Ordinal).ThenBy(g => g.Key.Cidr, StringComparer.Ordinal)
            .Select(g => new TopologySubnetDto(Topology.SubnetId(g.Key.Zone, g.Key.Cidr), g.Key.Cidr, g.Key.Zone, g.Count())).ToList();
        var perspectives = seen.GroupBy(o => (o.AgentId, o.InterfaceName))
            .OrderBy(g => g.Key.AgentId, StringComparer.Ordinal).ThenBy(g => g.Key.InterfaceName, StringComparer.Ordinal)
            .Select(g => new TopologyPerspectiveDto(g.Key.AgentId, g.Key.InterfaceName, g.Select(o => o.Zone).FirstOrDefault(z => z.Length > 0))).ToList();
        var zones = hosts.GroupBy(h => h.Zone).OrderBy(g => g.Key, StringComparer.Ordinal)
            .Select(g => new TopologyZoneDto(g.Key, g.Select(h => h.Subnet).Distinct().Count(), g.Count())).ToList();
        // Devices with an interface among the returned hosts; their zones/interfaces stay complete (links leave the filtered view).
        var shown = hosts.Select(h => h.DeviceId).OfType<string>().ToHashSet();
        var devices = inference.Devices.Where(d => shown.Contains(d.Id)).ToList();
        return new TopologyDto(perspectives, subnets, hosts, truncated, zones, devices);
    }

    public async Task<IReadOnlyList<TechnologySummaryDto>> TechnologiesAsync(CancellationToken ct)
    {
        var rows = await db.Technologies.AsNoTracking()
            .GroupBy(t => new { t.Name, t.Version, t.Category })
            .Select(g => new
            {
                g.Key.Name, g.Key.Version, g.Key.Category, Hosts = g.Select(t => t.HostId).Distinct().Count(),
                Services = g.Count(t => t.Port != null), Confidence = g.Max(t => t.Confidence),
            })
            .ToListAsync(ct);
        return rows.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ThenBy(r => r.Version, StringComparer.Ordinal)
            .Select(r => new TechnologySummaryDto(r.Name, r.Version, r.Category, r.Hosts, r.Services, r.Confidence)).ToList();
    }

    public async Task<PagedResult<ChangeDto>> ChangesAsync(ChangeQuery query, int page, int pageSize, CancellationToken ct)
    {
        var q = db.Changes.AsNoTracking();
        if (query.Since is not null) q = q.Where(c => c.DetectedAt >= query.Since);
        if (query.Type is not null) q = q.Where(c => c.Type == query.Type);
        if (query.HostId is not null) q = q.Where(c => c.HostId == query.HostId);
        if (query.ScanRunId is not null) q = q.Where(c => c.ScanRunId == query.ScanRunId);
        if (!string.IsNullOrWhiteSpace(query.Zone)) q = q.Where(c => c.Zone == query.Zone);
        var total = await q.CountAsync(ct);
        var items = await q.OrderByDescending(c => c.DetectedAt).ThenBy(c => c.Id).Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(ct);
        return new PagedResult<ChangeDto>(items.Select(c => c.ToDto()).ToList(), total, page, pageSize);
    }

    public async Task<PagedResult<FindingDto>> FindingsAsync(FindingQuery query, int page, int pageSize, CancellationToken ct)
    {
        var q = db.SignatureMatches.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(query.Severity))
        {
            var severity = query.Severity.Trim().ToLowerInvariant();
            q = q.Where(m => m.Severity == severity);
        }
        if (query.Status is not null) q = q.Where(m => m.Status == query.Status);
        if (!string.IsNullOrWhiteSpace(query.Zone)) q = q.Where(m => m.Zone == query.Zone);
        var total = await q.CountAsync(ct);
        var items = await q.OrderByDescending(m => m.MatchedAt).ThenBy(m => m.Id).Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(ct);
        return new PagedResult<FindingDto>(items.Select(m => m.ToDto()).ToList(), total, page, pageSize);
    }

    public async Task<PagedResult<ObservationDto>?> ObservationsAsync(Guid? hostId, Guid? scanRunId, ObservationKind? kind, int page, int pageSize,
        CancellationToken ct)
    {
        var q = db.Observations.AsNoTracking();
        if (hostId is not null)
        {
            var host = await db.Hosts.Where(h => h.Id == hostId).Select(h => new { h.Zone, h.Address }).FirstOrDefaultAsync(ct);
            if (host is null) return null;
            q = q.Where(o => o.Zone == host.Zone && o.Address == host.Address);
        }
        if (scanRunId is not null) q = q.Where(o => o.ScanRunId == scanRunId);
        if (kind is not null) q = q.Where(o => o.Kind == kind);
        var total = await q.CountAsync(ct);
        var rows = await q.OrderByDescending(o => o.Id).Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(ct);
        var items = rows.Select(o => new ObservationDto(o.Id, o.ScanRunId, o.JobId, o.BatchId, o.AgentId, o.InterfaceName, o.Zone, o.ReceivedAt,
            JsonSerializer.Deserialize<DiscoveryObservation>(o.Payload, ContractJson.Options)!)).ToList();
        return new PagedResult<ObservationDto>(items, total, page, pageSize);
    }

    public async Task<DashboardSummaryDto> DashboardAsync(DateTimeOffset now, CancellationToken ct)
    {
        var since = now.AddHours(-24);
        return new DashboardSummaryDto(
            await db.Hosts.CountAsync(ct),
            await db.Hosts.CountAsync(h => h.Status == HostStatus.Active, ct),
            await db.Services.CountAsync(s => s.State == ServiceState.Open, ct),
            await db.Changes.CountAsync(c => c.DetectedAt >= since, ct),
            await db.SignatureMatches.CountAsync(m => m.Status == FindingStatus.Open, ct),
            await db.ProcessedBatches.MaxAsync(b => (DateTimeOffset?)b.ProcessedAt, ct));
    }

    private async Task<List<HostListItemDto>> ToHostItemsAsync(List<Host> hosts, CancellationToken ct, Dictionary<Guid, InterestScore>? scores = null)
    {
        scores ??= (await InterestAsync(hosts.Select(h => h.Id).ToList(), null, ct)).Hosts;
        var ids = hosts.Select(h => h.Id).ToList();
        var addresses = hosts.Select(h => h.Address).ToList();
        var openPorts = await db.Services.Where(s => ids.Contains(s.HostId) && s.State == ServiceState.Open)
            .GroupBy(s => s.HostId).Select(g => new { g.Key, Count = g.Count() }).ToDictionaryAsync(x => x.Key, x => x.Count, ct);
        var technologies = (await db.Technologies.Where(t => ids.Contains(t.HostId)).Select(t => new { t.HostId, t.Name }).ToListAsync(ct))
            .ToLookup(t => t.HostId, t => t.Name);
        var classifications = (await db.SignatureMatches
                .Where(m => ids.Contains(m.HostId) && m.Status == FindingStatus.Open && m.ClassificationTag != null)
                .Select(m => new { m.HostId, m.ClassificationTag }).ToListAsync(ct))
            .ToLookup(m => m.HostId, m => m.ClassificationTag!);
        var annotations = await db.Annotations.AsNoTracking().Where(a => addresses.Contains(a.Address)).ToDictionaryAsync(a => (a.Zone, a.Address), ct);
        var devices = (await DevicesAsync(hosts.Select(h => h.MacAddress).OfType<string>().Distinct().ToList(), ct)).ByHost;

        return hosts.Select(h => new HostListItemDto(h.Id, h.Address, h.Hostnames, h.Status, h.Unstable, h.FirstSeenAt, h.LastSeenAt,
            h.LastScannedAt, openPorts.GetValueOrDefault(h.Id), technologies[h.Id].Distinct().Order().ToList(), h.Zone,
            annotations.GetValueOrDefault((h.Zone, h.Address)).ToDto(), classifications[h.Id].Distinct().Order().ToList(), h.MacAddress, h.MacVendor,
            devices.ContainsKey(h.Id), devices.GetValueOrDefault(h.Id)?.Confidence,
            scores.GetValueOrDefault(h.Id, InterestScore.None).Score, scores.GetValueOrDefault(h.Id, InterestScore.None).Reasons)).ToList();
    }

    /// <summary>
    /// Network devices among the current (not Gone) hosts, see <see cref="Topology.InferDevices"/>; <paramref name="macs"/> limits the
    /// MACs considered. Gone hosts are left out so a machine that moved to another zone is not linked to its old record.
    /// shortcut: computed on every read (GROUP BY over hosts, no MAC index); add an index on mac_address or a cache if hosts grow large.
    /// </summary>
    private async Task<DeviceInference> DevicesAsync(List<string>? macs, CancellationToken ct)
    {
        var current = db.Hosts.AsNoTracking().Where(h => h.MacAddress != null && h.Status != HostStatus.Gone);
        if (macs is not null)
        {
            if (macs.Count == 0) return new DeviceInference([], new HashSet<Guid>());
            current = current.Where(h => macs.Contains(h.MacAddress!));
        }
        // Only a MAC on several hosts can link interfaces; a virtual-router MAC is a device even on one host.
        var shared = current.GroupBy(h => h.MacAddress).Where(g => g.Count() > 1).Select(g => g.Key);
        var rows = await current
            .Where(h => shared.Contains(h.MacAddress) || h.MacAddress!.StartsWith(Topology.VrrpMacPrefix) || h.MacAddress.StartsWith(Topology.HsrpMacPrefix))
            .Select(h => new MacInterface(h.Id, h.Zone, h.Address, h.MacAddress!, h.MacVendor)).ToListAsync(ct);
        return Topology.InferDevices(rows);
    }

    private async Task<List<ServiceDto>> ToServiceDtosAsync(List<Service> services, CancellationToken ct, Dictionary<Guid, InterestScore>? scores = null)
    {
        var ids = services.Select(s => s.Id).ToList();
        var technologies = (await db.Technologies.Where(t => t.ServiceId != null && ids.Contains(t.ServiceId.Value))
            .Select(t => new { t.ServiceId, t.Name }).ToListAsync(ct)).ToLookup(t => t.ServiceId!.Value, t => t.Name);
        var fingerprints = services.Select(s => s.CurrentCertFingerprint).OfType<string>().ToList();
        var certificates = (await db.Certificates.AsNoTracking().Where(c => ids.Contains(c.ServiceId) && fingerprints.Contains(c.FingerprintSha256))
            .ToListAsync(ct)).ToDictionary(c => (c.ServiceId, c.FingerprintSha256));
        scores ??= (await InterestAsync(services.Select(s => s.HostId).Distinct().ToList(), services, ct)).Services;
        var hours = await HourlyResponsesAsync(services.Where(s => s.TimeOfDayVariance).Select(s => s.Id).ToList(), ct);

        return services.Select(s =>
        {
            var cert = s.CurrentCertFingerprint is { } fp ? certificates.GetValueOrDefault((s.Id, fp)) : null;
            var interest = scores.GetValueOrDefault(s.Id, InterestScore.None);
            return new ServiceDto(s.Id, s.HostId, s.Address, s.Port, s.Transport, s.State, s.ServiceName, s.Product, s.Version, s.Banner, s.Cpe,
                s.HttpUrl is null ? null : new HttpInfoDto(s.HttpUrl, s.HttpStatusCode, s.HttpTitle, s.HttpWebServer),
                cert is null ? null : new TlsInfoDto(cert.SubjectCommonName, cert.Issuer, cert.NotAfter, cert.FingerprintSha256),
                technologies[s.Id].Distinct().Order().ToList(), s.Confidence, s.ConfidenceMethod, s.TimeOfDayVariance, s.FirstSeenAt, s.LastSeenAt,
                Topology.ServiceUrl(s.Address, s.Port, s.ServiceName, s.Tunnel, s.HttpUrl, s.CurrentCertFingerprint is not null), s.Zone,
                interest.Score, interest.Reasons, hours.GetValueOrDefault(s.Id));
        }).ToList();
    }

    /// <summary>Per UTC hour: HTTP observations (all paths) and the most frequent response of that hour, from the hourly snapshots.</summary>
    private async Task<Dictionary<Guid, IReadOnlyList<HourVisibilityDto>>> HourlyResponsesAsync(List<Guid> serviceIds, CancellationToken ct)
    {
        if (serviceIds.Count == 0) return [];
        var snapshots = await db.HttpSnapshots.AsNoTracking().Where(s => serviceIds.Contains(s.ServiceId))
            .Select(s => new { s.ServiceId, s.HourBucket, s.ObservationCount, s.StatusCode, s.Title, s.WebServer }).ToListAsync(ct);
        return snapshots.GroupBy(s => s.ServiceId).ToDictionary(g => g.Key, g => (IReadOnlyList<HourVisibilityDto>)g.GroupBy(s => s.HourBucket)
            .Select(h =>
            {
                var top = h.MaxBy(s => s.ObservationCount)!;
                return new HourVisibilityDto(h.Key, h.Sum(s => s.ObservationCount), 0, $"{top.StatusCode} '{top.Title}' {top.WebServer}".Trim());
            })
            .OrderBy(h => h.Hour).ToList());
    }

    /// <summary>
    /// Interest scores of <paramref name="services"/> (null = the open services of the hosts) and of the hosts: the max of their open
    /// services and their host-level signals (findings without a port, unstable, new).
    /// </summary>
    private async Task<(Dictionary<Guid, InterestScore> Services, Dictionary<Guid, InterestScore> Hosts)> InterestAsync(
        List<Guid> hostIds, List<Service>? services, CancellationToken ct)
    {
        services ??= await db.Services.AsNoTracking().Where(s => hostIds.Contains(s.HostId) && s.State == ServiceState.Open).ToListAsync(ct);
        var serviceIds = services.Select(s => s.Id).ToList();
        var hosts = await db.Hosts.AsNoTracking().Where(h => hostIds.Contains(h.Id))
            .Select(h => new { h.Id, h.Unstable, h.FirstSeenAt, h.FirstSeenRunId }).ToDictionaryAsync(h => h.Id, ct);
        var findings = (await db.SignatureMatches.AsNoTracking().Where(InterestScorer.CountsFinding).Where(m => hostIds.Contains(m.HostId))
            .Select(m => new { m.HostId, m.ServiceId, m.Severity, m.Name, m.Source, m.ClassificationTag }).ToListAsync(ct)).ToLookup(m => m.ServiceId ?? m.HostId);
        var versions = (await db.Technologies.AsNoTracking().Where(t => t.ServiceId != null && t.Version != null && serviceIds.Contains(t.ServiceId.Value))
            .Select(t => new { t.ServiceId, t.Name, t.Version }).ToListAsync(ct)).ToLookup(t => t.ServiceId!.Value, t => $"{t.Name} {t.Version}");
        var fingerprints = services.Select(s => s.CurrentCertFingerprint).OfType<string>().ToList();
        var certificates = (await db.Certificates.AsNoTracking().Where(c => serviceIds.Contains(c.ServiceId) && fingerprints.Contains(c.FingerprintSha256))
            .Select(c => new { c.ServiceId, c.FingerprintSha256, c.SelfSigned, c.NotAfter }).ToListAsync(ct)).ToDictionary(c => (c.ServiceId, c.FingerprintSha256));
        var lastRun = await db.Runs.AsNoTracking().Where(r => r.ComparedAt != null).OrderByDescending(r => r.ComparedAt)
            .Select(r => (Guid?)r.ScanRunId).FirstOrDefaultAsync(ct);
        var now = time.GetUtcNow();

        // Findings keyed by service id, host-level ones (no service) by host id.
        InterestInput Base(Guid key, Guid hostId, DateTimeOffset firstSeen, Guid firstRun) => new()
        {
            Findings = findings[key].Where(f => f.Source != SignatureMatch.ClassificationSource).Select(f => (f.Severity, f.Name)).ToList(),
            Classifications = findings[key].Select(f => f.ClassificationTag).OfType<string>().ToList(),
            NewInLastRun = firstRun == lastRun, FirstSeenAt = firstSeen, HostUnstable = hosts.GetValueOrDefault(hostId)?.Unstable == true,
        };

        var serviceScores = services.ToDictionary(s => s.Id, s =>
        {
            var cert = s.CurrentCertFingerprint is { } fp ? certificates.GetValueOrDefault((s.Id, fp)) : null;
            return InterestScorer.Score(Base(s.Id, s.HostId, s.FirstSeenAt, s.FirstSeenRunId) with
            {
                Port = s.Port, ServiceName = s.ServiceName, Http = s.HttpUrl is not null || Topology.IsWebName(s.ServiceName),
                VersionedTechnologies = versions[s.Id].Distinct().Order().ToList(), SelfSigned = cert?.SelfSigned, CertNotAfter = cert?.NotAfter,
                TimeOfDayVariance = s.TimeOfDayVariance,
            }, now);
        });
        var openByHost = services.Where(s => s.State == ServiceState.Open).ToLookup(s => s.HostId, s => serviceScores[s.Id]);
        var hostScores = hosts.Values.ToDictionary(h => h.Id, h => openByHost[h.Id]
            .Append(InterestScorer.Score(Base(h.Id, h.Id, h.FirstSeenAt, h.FirstSeenRunId), now)).MaxBy(s => s.Score)!);
        return (serviceScores, hostScores);
    }

    /// <summary>Dashboard insights: top findings and services, changes per day, recent scans (passed in by the endpoint from Scanning).</summary>
    public async Task<DashboardInsightsDto> InsightsAsync(DateTimeOffset now, int days, IReadOnlyList<ScanRunSummary> scans, CancellationToken ct)
    {
        const int top = 10;
        var findings = await db.SignatureMatches.AsNoTracking().Where(InterestScorer.CountsFinding)
            .OrderByDescending(m => m.Severity == "critical" ? 4 : m.Severity == "high" ? 3 : m.Severity == "medium" ? 2 : m.Severity == "low" ? 1 : 0)
            .ThenByDescending(m => m.MatchedAt).Take(top).ToListAsync(ct);

        // shortcut: scores every open service in memory; persist the score (or pre-filter candidates) if services grow beyond ~10^5.
        var open = await db.Services.AsNoTracking().Where(s => s.State == ServiceState.Open).ToListAsync(ct);
        var (scores, _) = await InterestAsync(open.Select(s => s.HostId).Distinct().ToList(), open, ct);
        var topServices = open.Where(s => scores[s.Id].Score > 0).OrderByDescending(s => scores[s.Id].Score).ThenByDescending(s => s.FirstSeenAt)
            .Take(top).ToList();

        var firstDay = new DateTimeOffset(now.UtcDateTime.Date, TimeSpan.Zero).AddDays(1 - days);
        var changes = (await db.Changes.AsNoTracking().Where(c => c.DetectedAt >= firstDay).Select(c => new { c.DetectedAt, c.Type }).ToListAsync(ct))
            .ToLookup(c => c.DetectedAt.UtcDateTime.Date);
        var byDay = Enumerable.Range(0, days).Select(i => firstDay.AddDays(i).UtcDateTime.Date).Select(day => new ChangeDayDto(
            day.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), changes[day].Count(),
            changes[day].GroupBy(c => c.Type.ToString()).ToDictionary(g => g.Key, g => g.Count()))).ToList();

        var scanIds = scans.Select(s => s.Id).ToList();
        var compared = await db.Runs.AsNoTracking().Where(r => scanIds.Contains(r.ScanRunId)).ToDictionaryAsync(r => r.ScanRunId, r => r.ChangesDetected, ct);
        var recent = scans.Select(s => new RecentScanDto(s.Id, s.Name, s.Status, s.WorkflowKey, s.CreatedAt, s.StartedAt, s.FinishedAt,
            s.StartedAt is { } started && s.FinishedAt is { } finished ? (finished - started).TotalSeconds : null, s.CoverageComplete,
            compared.GetValueOrDefault(s.Id))).ToList();

        return new DashboardInsightsDto(findings.Select(f => f.ToDto()).ToList(), await ToServiceDtosAsync(topServices, ct, scores), byDay, recent,
            await db.Hosts.CountAsync(h => h.Unstable && h.Status != HostStatus.Gone, ct),
            await db.Services.CountAsync(s => s.TimeOfDayVariance && s.State == ServiceState.Open, ct));
    }

    private static string Like(string search) =>
        "%" + search.Trim().Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_") + "%";
}
