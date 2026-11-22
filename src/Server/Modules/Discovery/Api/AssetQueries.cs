using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WebScan.Contracts;
using WebScan.Server.Kernel.Discovery;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Modules.Discovery.Domain;
using WebScan.Server.Modules.Discovery.Normalization;
using WebScan.Server.Modules.Discovery.Persistence;

namespace WebScan.Server.Modules.Discovery.Api;

public sealed record HostQuery(string? Search, HostStatus? Status, string? Zone, bool NetworkDevice = false);
public sealed record ServiceQuery(int? Port, string? ServiceName, string? Search, string? Zone = null);
public sealed record ChangeQuery(DateTimeOffset? Since, AssetChangeType? Type, Guid? HostId, Guid? ScanRunId, string? Zone = null);
/// <param name="Severity">Matches the effective severity (user override, else detected).</param>
public sealed record FindingQuery(string? Severity, FindingStatus? Status, string? Zone = null, FindingTriage? Triage = null);
public sealed record TopologyQuery(string? Zone, string? Search);

/// <summary>Read models of the current-state tables, shared by the list and export endpoints.</summary>
internal sealed class AssetQueries(DiscoveryDbContext db)
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

        var total = await q.CountAsync(ct);
        var hosts = await q.OrderBy(h => h.Zone).ThenBy(h => h.Address).Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(ct);
        return new PagedResult<HostListItemDto>(await ToHostItemsAsync(hosts, ct), total, page, pageSize);
    }

    public async Task<HostDetailDto?> HostAsync(Guid id, CancellationToken ct)
    {
        var host = await db.Hosts.AsNoTracking().FirstOrDefaultAsync(h => h.Id == id, ct);
        if (host is null) return null;
        var item = (await ToHostItemsAsync([host], ct))[0];
        var services = await ToServiceDtosAsync(await db.Services.AsNoTracking().Where(s => s.HostId == id).OrderBy(s => s.Port).ToListAsync(ct), ct);
        var technologies = await db.Technologies.AsNoTracking().Where(t => t.HostId == id).OrderBy(t => t.Port).ThenBy(t => t.Name).ToListAsync(ct);
        var certificates = await db.Certificates.AsNoTracking().Where(c => c.HostId == id).OrderByDescending(c => c.LastSeenAt).ToListAsync(ct);
        var findings = await db.SignatureMatches.AsNoTracking().Where(m => m.HostId == id).OrderByDescending(m => m.MatchedAt).ToListAsync(ct);
        var changes = await db.Changes.AsNoTracking().Where(c => c.HostId == id).OrderByDescending(c => c.DetectedAt).Take(50).ToListAsync(ct);
        var device = host.MacAddress is null ? null : (await DevicesAsync([host.MacAddress], ct)).ByHost.GetValueOrDefault(id);
        return new HostDetailDto(host.Id, host.Address, host.Hostnames, host.Status, host.Unstable, host.FirstSeenAt, host.LastSeenAt,
            host.LastScannedAt, item.OpenPortCount, host.Zone, item.Annotation, item.Classifications, host.MacAddress, host.MacVendor,
            host.OsGuess, host.ConsecutiveMisses, host.StateChangeCount, services, technologies.Select(t => t.ToDto()).ToList(),
            certificates.Select(c => c.ToDto()).ToList(), findings.Select(f => f.ToDto()).ToList(), changes.Select(c => c.ToDto()).ToList(),
            item.NetworkDevice, item.NetworkDeviceConfidence, device?.Interfaces.Where(i => i.HostId != id).ToList() ?? []);
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
            // Banner is encrypted at rest (random-nonce ciphertext), so it is not searchable in SQL.
            q = q.Where(s => EF.Functions.ILike(s.Address, like) || EF.Functions.ILike(s.Product ?? "", like) || EF.Functions.ILike(s.HttpTitle ?? "", like));
        }
        if (!string.IsNullOrWhiteSpace(query.Zone)) q = q.Where(s => s.Zone == query.Zone);

        var total = await q.CountAsync(ct);
        var services = await q.OrderBy(s => s.Zone).ThenBy(s => s.Address).ThenBy(s => s.Port).Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(ct);
        return new PagedResult<ServiceDto>(await ToServiceDtosAsync(services, ct), total, page, pageSize);
    }

    public async Task<ServiceDetailDto?> ServiceAsync(Guid id, CancellationToken ct)
    {
        var service = await db.Services.AsNoTracking().FirstOrDefaultAsync(s => s.Id == id, ct);
        if (service is null) return null;
        var technologies = await db.Technologies.AsNoTracking().Where(t => t.ServiceId == id).OrderByDescending(t => t.Confidence).ThenBy(t => t.Name)
            .ToListAsync(ct);
        var certificate = service.CurrentCertFingerprint is { } fp
            ? await db.Certificates.AsNoTracking().FirstOrDefaultAsync(c => c.ServiceId == id && c.FingerprintSha256 == fp, ct)
            : null;
        var findings = await db.SignatureMatches.AsNoTracking().Where(m => m.ServiceId == id).OrderByDescending(m => m.MatchedAt).ToListAsync(ct);
        return new ServiceDetailDto((await ToServiceDtosAsync([service], ct))[0],
            service.HttpDetailsJson is null ? null : JsonSerializer.Deserialize<HttpDetails>(service.HttpDetailsJson, ContractJson.Options),
            service.Artifacts.Select(a => a.ToDto()).ToList(),
            service.DeviceType is null ? null : new DeviceDto(service.DeviceType, service.DeviceVendor, service.DeviceProduct),
            technologies.Select(t => t.ToDto()).ToList(), certificate?.ToDto(), findings.Select(f => f.ToDto()).ToList());
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
            q = q.Where(m => (m.SeverityOverride ?? m.Severity) == severity);
        }
        if (query.Status is not null) q = q.Where(m => m.Status == query.Status);
        if (query.Triage is not null) q = q.Where(m => m.Triage == query.Triage);
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
            await db.SignatureMatches.CountAsync(m => m.Status == FindingStatus.Open && m.Triage != FindingTriage.FalsePositive, ct),
            await db.ProcessedBatches.MaxAsync(b => (DateTimeOffset?)b.ProcessedAt, ct));
    }

    private async Task<List<HostListItemDto>> ToHostItemsAsync(List<Host> hosts, CancellationToken ct)
    {
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
        // Device types recognized on open services (IoT detection) classify the host as well.
        var deviceTypes = (await db.Services.Where(s => ids.Contains(s.HostId) && s.State == ServiceState.Open && s.DeviceType != null)
            .Select(s => new { s.HostId, s.DeviceType }).ToListAsync(ct)).ToLookup(s => s.HostId, s => s.DeviceType!);
        var annotations = await db.Annotations.AsNoTracking().Where(a => addresses.Contains(a.Address)).ToDictionaryAsync(a => (a.Zone, a.Address), ct);
        var devices = (await DevicesAsync(hosts.Select(h => h.MacAddress).OfType<string>().Distinct().ToList(), ct)).ByHost;

        return hosts.Select(h => new HostListItemDto(h.Id, h.Address, h.Hostnames, h.Status, h.Unstable, h.FirstSeenAt, h.LastSeenAt,
            h.LastScannedAt, openPorts.GetValueOrDefault(h.Id), technologies[h.Id].Distinct().Order().ToList(), h.Zone,
            annotations.GetValueOrDefault((h.Zone, h.Address)).ToDto(), classifications[h.Id].Concat(deviceTypes[h.Id]).Distinct().Order().ToList(), h.MacAddress, h.MacVendor,
            devices.ContainsKey(h.Id), devices.GetValueOrDefault(h.Id)?.Confidence)).ToList();
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

    private async Task<List<ServiceDto>> ToServiceDtosAsync(List<Service> services, CancellationToken ct)
    {
        var ids = services.Select(s => s.Id).ToList();
        var technologies = (await db.Technologies.Where(t => t.ServiceId != null && ids.Contains(t.ServiceId.Value))
            .Select(t => new { t.ServiceId, t.Name }).ToListAsync(ct)).ToLookup(t => t.ServiceId!.Value, t => t.Name);
        var fingerprints = services.Select(s => s.CurrentCertFingerprint).OfType<string>().ToList();
        var certificates = (await db.Certificates.AsNoTracking().Where(c => ids.Contains(c.ServiceId) && fingerprints.Contains(c.FingerprintSha256))
            .ToListAsync(ct)).ToDictionary(c => (c.ServiceId, c.FingerprintSha256));
        var addresses = services.Select(s => s.Address).Distinct().ToList();
        var annotations = await db.ServiceAnnotations.AsNoTracking().Where(a => addresses.Contains(a.Address))
            .ToDictionaryAsync(a => (a.Zone, a.Address, a.Port, a.Transport), ct);

        return services.Select(s =>
        {
            var cert = s.CurrentCertFingerprint is { } fp ? certificates.GetValueOrDefault((s.Id, fp)) : null;
            return new ServiceDto(s.Id, s.HostId, s.Address, s.Port, s.Transport, s.State, s.ServiceName, s.Product, s.Version, s.Banner, s.Cpe,
                s.HttpUrl is null ? null : new HttpInfoDto(s.HttpUrl, s.HttpStatusCode, s.HttpTitle, s.HttpWebServer),
                cert is null ? null : new TlsInfoDto(cert.SubjectCommonName, cert.Issuer, cert.NotAfter, cert.FingerprintSha256),
                technologies[s.Id].Distinct().Order().ToList(), s.Confidence, s.ConfidenceMethod, s.TimeOfDayVariance, s.FirstSeenAt, s.LastSeenAt,
                Topology.ServiceUrl(s.Address, s.Port, s.ServiceName, s.Tunnel, s.HttpUrl, s.CurrentCertFingerprint is not null), s.Zone,
                annotations.GetValueOrDefault((s.Zone, s.Address, s.Port, s.Transport)).ToDto(),
                s.Artifacts.Count, s.Artifacts.SelectMany(a => a.Tags).Distinct().Order(StringComparer.Ordinal).ToList(), s.DeviceType);
        }).ToList();
    }

    private static string Like(string search) =>
        "%" + search.Trim().Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_") + "%";
}
