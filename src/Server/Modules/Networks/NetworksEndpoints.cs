using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using WebScan.Contracts;
using WebScan.Server.Infrastructure.Http;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Networks.Persistence;

namespace WebScan.Server.Modules.Networks;

/// <summary>Create/update/import shape of a network (also the JSON export shape).</summary>
public sealed record NetworkInput
{
    public string? Name { get; init; }
    public string? Description { get; init; }
    public string? Zone { get; init; }
    public IReadOnlyList<string>? Ranges { get; init; }
    public IReadOnlyList<string>? Exclusions { get; init; }
    public IReadOnlyList<string>? Tags { get; init; }
    public int? MaxRatePerSecond { get; init; }
    public bool? Enabled { get; init; }
}

public sealed record NetworkDto(Guid Id, string Name, string? Description, string Zone, IReadOnlyList<string> Ranges,
    IReadOnlyList<string> Exclusions, IReadOnlyList<string> Tags, int? MaxRatePerSecond, bool Enabled, long AddressCount,
    DateTimeOffset CreatedAt, DateTimeOffset UpdatedAt)
{
    public static NetworkDto From(Network n) => new(n.Id, n.Name, n.Description, n.Zone, n.Ranges, n.Exclusions, n.Tags,
        n.MaxRatePerSecond, n.Enabled, ScopeRules.CountAddresses(n.Ranges, n.Exclusions), n.CreatedAt, n.UpdatedAt);
}

public sealed record ImportResult(int Created, int Updated, IReadOnlyList<string> Errors);

public sealed record ZoneDto(string Name, string? Description, int NetworkCount);

public sealed record CreateZoneRequest(string? Name, string? Description);

public sealed record ScopePolicyDto(IReadOnlyList<string> Allowed, IReadOnlyList<string> Excluded, DateTimeOffset? UpdatedAt);

public sealed record ScopePolicyRequest(IReadOnlyList<string>? Allowed, IReadOnlyList<string>? Excluded);

internal static partial class NetworksEndpoints
{
    private static readonly string[] CsvColumns = ["name", "zone", "ranges", "exclusions", "tags", "description"];

    [GeneratedRegex("^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")]
    internal static partial Regex ZoneNameRegex();

    public static void Map(IEndpointRouteBuilder endpoints)
    {
        var networks = endpoints.MapGroup("/api/networks");
        networks.MapGet("/", List).RequireAuthorization(Policies.CanRead);
        networks.MapGet("/export", Export).RequireAuthorization(Policies.CanRead);
        networks.MapPost("/import", Import).RequireAuthorization(Policies.CanManage);
        networks.MapGet("/{id:guid}", Get).RequireAuthorization(Policies.CanRead);
        networks.MapPost("/", Create).RequireAuthorization(Policies.CanManage);
        networks.MapPut("/{id:guid}", Update).RequireAuthorization(Policies.CanEdit);
        networks.MapDelete("/{id:guid}", Delete).RequireAuthorization(Policies.CanManage);

        var zones = endpoints.MapGroup("/api/zones");
        zones.MapGet("/", ListZones).RequireAuthorization(Policies.CanRead);
        zones.MapPost("/", CreateZone).RequireAuthorization(Policies.CanManage);
        zones.MapDelete("/{name}", DeleteZone).RequireAuthorization(Policies.CanManage);

        endpoints.MapGet("/api/scope-policy", GetPolicy).RequireAuthorization(Policies.CanRead);
        endpoints.MapPut("/api/scope-policy", PutPolicy).RequireAuthorization(Policies.AdminOnly);
    }

    private static async Task<List<NetworkDto>> List(NetworksDbContext db, CancellationToken ct) =>
        (await db.Networks.AsNoTracking().OrderBy(n => n.Name).ToListAsync(ct)).Select(NetworkDto.From).ToList();

    private static async Task<IResult> Get(Guid id, NetworksDbContext db, CancellationToken ct)
    {
        var network = await db.Networks.AsNoTracking().SingleOrDefaultAsync(n => n.Id == id, ct);
        return network is null ? Results.NotFound() : Results.Ok(NetworkDto.From(network));
    }

    private static async Task<IResult> Create(NetworkInput input, NetworksDbContext db, IAuditLog audit, TimeProvider time, CancellationToken ct)
    {
        var errors = Validate(input, await LoadRulesAsync(db, ct));
        if (!errors.IsValid) return errors.ToResult();
        if (await db.Networks.AnyAsync(n => n.Name == input.Name!.Trim(), ct))
            return ValidationErrors.Single("name", $"A network named '{input.Name}' already exists.");

        var now = time.GetUtcNow();
        var network = new Network { Id = Guid.CreateVersion7(), Name = "", Zone = "", CreatedAt = now };
        Apply(network, input, keepUnspecified: false, now);
        await EnsureZoneAsync(db, network.Zone, now, ct);
        db.Networks.Add(network);
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuditEntry("network.created", "network", network.Id.ToString(), Snapshot(network)), ct);
        return Results.Created($"/api/networks/{network.Id}", NetworkDto.From(network));
    }

    private static async Task<IResult> Update(Guid id, NetworkInput input, NetworksDbContext db, IAuditLog audit, TimeProvider time, CancellationToken ct)
    {
        var errors = Validate(input, await LoadRulesAsync(db, ct));
        if (!errors.IsValid) return errors.ToResult();

        var network = await db.Networks.SingleOrDefaultAsync(n => n.Id == id, ct);
        if (network is null) return Results.NotFound();
        if (await db.Networks.AnyAsync(n => n.Id != id && n.Name == input.Name!.Trim(), ct))
            return ValidationErrors.Single("name", $"A network named '{input.Name}' already exists.");

        var now = time.GetUtcNow();
        Apply(network, input, keepUnspecified: false, now);
        await EnsureZoneAsync(db, network.Zone, now, ct);
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuditEntry("network.updated", "network", id.ToString(), Snapshot(network)), ct);
        return Results.Ok(NetworkDto.From(network));
    }

    private static async Task<IResult> Delete(Guid id, NetworksDbContext db, IAuditLog audit, CancellationToken ct)
    {
        var network = await db.Networks.SingleOrDefaultAsync(n => n.Id == id, ct);
        if (network is null) return Results.NotFound();
        db.Networks.Remove(network);
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuditEntry("network.deleted", "network", id.ToString(), new { network.Name, network.Zone }), ct);
        return Results.NoContent();
    }

    private static async Task<IResult> Export(string? format, NetworksDbContext db, CancellationToken ct)
    {
        var networks = await db.Networks.AsNoTracking().OrderBy(n => n.Name).ToListAsync(ct);
        switch (format?.ToLowerInvariant() ?? "json")
        {
            case "json":
                var items = networks.Select(n => new NetworkInput
                {
                    Name = n.Name, Description = n.Description, Zone = n.Zone, Ranges = n.Ranges, Exclusions = n.Exclusions,
                    Tags = n.Tags, MaxRatePerSecond = n.MaxRatePerSecond, Enabled = n.Enabled,
                });
                return Results.File(JsonSerializer.SerializeToUtf8Bytes(items, ContractJson.Options), "application/json", "networks.json");
            case "csv":
                var rows = networks.Select(n => (IReadOnlyList<string?>)
                    [n.Name, n.Zone, string.Join(';', n.Ranges), string.Join(';', n.Exclusions), string.Join(';', n.Tags), n.Description]);
                var csv = Csv.Write([CsvColumns, .. rows]);
                return Results.File(Encoding.UTF8.GetBytes(csv), "text/csv", "networks.csv");
            default:
                return ValidationErrors.Single("format", "Use json or csv.");
        }
    }

    /// <summary>Upserts networks by name. Valid rows are applied, invalid rows are reported in <c>errors</c>.</summary>
    private static async Task<IResult> Import(string? format, HttpRequest request, NetworksDbContext db, IAuditLog audit, TimeProvider time,
        CancellationToken ct)
    {
        using var reader = new StreamReader(request.Body, Encoding.UTF8);
        var body = await reader.ReadToEndAsync(ct);
        var isCsv = string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase);
        if (!isCsv && format is not null && !string.Equals(format, "json", StringComparison.OrdinalIgnoreCase))
            return ValidationErrors.Single("format", "Use json or csv.");

        List<NetworkInput> items;
        try
        {
            items = isCsv ? ParseCsv(body) : JsonSerializer.Deserialize<List<NetworkInput>>(body, ContractJson.Options) ?? [];
        }
        catch (Exception ex) when (ex is JsonException or FormatException)
        {
            return ValidationErrors.Single("body", $"Could not parse {(isCsv ? "CSV" : "JSON")}: {ex.Message}");
        }

        var rules = await LoadRulesAsync(db, ct);
        var existing = await db.Networks.ToDictionaryAsync(n => n.Name, ct);
        var now = time.GetUtcNow();
        var errors = new List<string>();
        var seen = new HashSet<string>();
        int created = 0, updated = 0;

        for (var i = 0; i < items.Count; i++)
        {
            var item = items[i];
            var label = $"Item {i + 1}{(string.IsNullOrWhiteSpace(item.Name) ? "" : $" ({item.Name})")}";
            var validation = Validate(item, rules);
            if (!validation.IsValid)
            {
                errors.AddRange(validation.Messages.Select(m => $"{label}: {m}"));
                continue;
            }
            if (!seen.Add(item.Name!.Trim()))
            {
                errors.Add($"{label}: duplicate name in the import.");
                continue;
            }

            if (existing.TryGetValue(item.Name.Trim(), out var network))
            {
                Apply(network, item, keepUnspecified: isCsv, now);
                updated++;
            }
            else
            {
                network = new Network { Id = Guid.CreateVersion7(), Name = "", Zone = "", CreatedAt = now };
                Apply(network, item, keepUnspecified: false, now);
                db.Networks.Add(network);
                existing[network.Name] = network;
                created++;
            }
            await EnsureZoneAsync(db, network.Zone, now, ct);
        }

        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuditEntry("network.imported", "network", null, new { format = isCsv ? "csv" : "json", created, updated, errors = errors.Count }), ct);
        return Results.Ok(new ImportResult(created, updated, errors));
    }

    private static async Task<List<ZoneDto>> ListZones(NetworksDbContext db, CancellationToken ct)
    {
        var counts = await db.Networks.GroupBy(n => n.Zone).Select(g => new { g.Key, Count = g.Count() }).ToDictionaryAsync(x => x.Key, x => x.Count, ct);
        return (await db.Zones.AsNoTracking().OrderBy(z => z.Name).ToListAsync(ct))
            .Select(z => new ZoneDto(z.Name, z.Description, counts.GetValueOrDefault(z.Name))).ToList();
    }

    private static async Task<IResult> CreateZone(CreateZoneRequest request, NetworksDbContext db, IAuditLog audit, TimeProvider time, CancellationToken ct)
    {
        var errors = new ValidationErrors()
            .Require(ZoneNameRegex().IsMatch(request.Name ?? ""), "name", "1-64 letters, digits, '_', '.', '-'.")
            .Require(request.Description is null or { Length: <= 1000 }, "description", "Max 1000 characters.");
        if (!errors.IsValid) return errors.ToResult();
        if (await db.Zones.AnyAsync(z => z.Name == request.Name, ct))
            return Results.Problem(statusCode: StatusCodes.Status409Conflict, title: $"Zone '{request.Name}' already exists.");

        var zone = new Zone { Name = request.Name!, Description = request.Description, CreatedAt = time.GetUtcNow() };
        db.Zones.Add(zone);
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuditEntry("zone.created", "zone", zone.Name, new { zone.Description }), ct);
        return Results.Created($"/api/zones/{zone.Name}", new ZoneDto(zone.Name, zone.Description, 0));
    }

    private static async Task<IResult> DeleteZone(string name, NetworksDbContext db, IAuditLog audit, CancellationToken ct)
    {
        var zone = await db.Zones.SingleOrDefaultAsync(z => z.Name == name, ct);
        if (zone is null) return Results.NotFound();
        if (await db.Networks.AnyAsync(n => n.Zone == name, ct))
            return Results.Problem(statusCode: StatusCodes.Status409Conflict, title: $"Zone '{name}' still contains networks.");
        db.Zones.Remove(zone);
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuditEntry("zone.deleted", "zone", name), ct);
        return Results.NoContent();
    }

    private static async Task<ScopePolicyDto> GetPolicy(NetworksDbContext db, CancellationToken ct)
    {
        var policy = await db.ScopePolicies.AsNoTracking().SingleOrDefaultAsync(ct);
        return new ScopePolicyDto(policy?.Allowed ?? [], policy?.Excluded ?? [], policy?.UpdatedAt);
    }

    private static async Task<IResult> PutPolicy(ScopePolicyRequest request, NetworksDbContext db, IAuditLog audit, TimeProvider time, CancellationToken ct)
    {
        var errors = new ValidationErrors();
        ScopeRules.ValidateEntries(errors, "allowed", request.Allowed, allowWildcards: true, required: false);
        ScopeRules.ValidateEntries(errors, "excluded", request.Excluded, allowWildcards: true, required: false);
        if (!errors.IsValid) return errors.ToResult();

        var policy = await SetPolicyAsync(db, request.Allowed, request.Excluded, time.GetUtcNow(), ct);
        await audit.WriteAsync(new AuditEntry("scope_policy.updated", "scope_policy", null, new { policy.Allowed, policy.Excluded }), ct);
        return Results.Ok(new ScopePolicyDto(policy.Allowed, policy.Excluded, policy.UpdatedAt));
    }

    internal static async Task<ScopePolicy> SetPolicyAsync(NetworksDbContext db, IEnumerable<string>? allowed, IEnumerable<string>? excluded,
        DateTimeOffset now, CancellationToken ct)
    {
        var policy = await db.ScopePolicies.SingleOrDefaultAsync(ct);
        if (policy is null) db.ScopePolicies.Add(policy = new ScopePolicy());
        policy.Allowed = ScopeRules.Normalize(allowed);
        policy.Excluded = ScopeRules.Normalize(excluded);
        policy.UpdatedAt = now;
        await db.SaveChangesAsync(ct);
        return policy;
    }

    internal static async Task<ScopeRules> LoadRulesAsync(NetworksDbContext db, CancellationToken ct)
    {
        var policy = await db.ScopePolicies.AsNoTracking().SingleOrDefaultAsync(ct);
        return ScopeRules.Create(policy?.Allowed ?? [], policy?.Excluded ?? []);
    }

    internal static ValidationErrors Validate(NetworkInput input, ScopeRules rules)
    {
        var errors = new ValidationErrors()
            .Require(!string.IsNullOrWhiteSpace(input.Name) && input.Name.Trim().Length <= 128, "name", "1-128 characters.")
            .Require(ZoneNameRegex().IsMatch(input.Zone?.Trim() ?? ""), "zone", "1-64 letters, digits, '_', '.', '-'.")
            .Require(input.Description is null or { Length: <= 1000 }, "description", "Max 1000 characters.")
            .Require(input.Tags is null || (input.Tags.Count <= 50 && input.Tags.All(t => t is { Length: > 0 and <= 64 })), "tags",
                "Max 50 tags of 1-64 characters.")
            .Require(input.MaxRatePerSecond is null or > 0, "maxRatePerSecond", "Must be positive.");
        ScopeRules.ValidateEntries(errors, "ranges", input.Ranges, allowWildcards: false, required: true);
        ScopeRules.ValidateEntries(errors, "exclusions", input.Exclusions, allowWildcards: false, required: false);

        if (errors.IsValid)
        {
            foreach (var range in ScopeRules.Normalize(input.Ranges).Where(r => !rules.Covers(r)))
                errors.Add("ranges", $"'{range}' is outside the scope policy.");
        }
        return errors;
    }

    /// <summary>Copies validated input; CSV imports keep rate cap and enabled flag of existing networks (columns absent).</summary>
    private static void Apply(Network network, NetworkInput input, bool keepUnspecified, DateTimeOffset now)
    {
        network.Name = input.Name!.Trim();
        network.Description = string.IsNullOrWhiteSpace(input.Description) ? null : input.Description.Trim();
        network.Zone = input.Zone!.Trim();
        network.Ranges = ScopeRules.Normalize(input.Ranges);
        network.Exclusions = ScopeRules.Normalize(input.Exclusions);
        network.Tags = (input.Tags ?? []).Select(t => t.Trim()).Distinct().ToList();
        if (!keepUnspecified)
        {
            network.MaxRatePerSecond = input.MaxRatePerSecond;
            network.Enabled = input.Enabled ?? true;
        }
        network.UpdatedAt = now;
    }

    private static async Task EnsureZoneAsync(NetworksDbContext db, string zone, DateTimeOffset now, CancellationToken ct)
    {
        if (db.Zones.Local.Any(z => z.Name == zone) || await db.Zones.AnyAsync(z => z.Name == zone, ct)) return;
        db.Zones.Add(new Zone { Name = zone, CreatedAt = now });
    }

    private static List<NetworkInput> ParseCsv(string body)
    {
        var rows = Csv.Parse(body);
        if (rows.Count == 0) return [];
        var header = rows[0].Select(h => h.Trim().ToLowerInvariant()).ToList();
        var missing = CsvColumns.Where(c => !header.Contains(c)).ToList();
        if (missing.Count > 0) throw new FormatException($"Missing CSV column(s): {string.Join(", ", missing)}.");

        string Field(List<string> row, string column)
        {
            var index = header.IndexOf(column);
            return index < row.Count ? row[index] : "";
        }
        static List<string> SplitList(string value) =>
            value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

        return rows.Skip(1).Select(row => new NetworkInput
        {
            Name = Field(row, "name"),
            Zone = Field(row, "zone"),
            Ranges = SplitList(Field(row, "ranges")),
            Exclusions = SplitList(Field(row, "exclusions")),
            Tags = SplitList(Field(row, "tags")),
            Description = Field(row, "description"),
        }).ToList();
    }

    private static object Snapshot(Network n) => new { n.Name, n.Zone, n.Ranges, n.Exclusions, n.Tags, n.MaxRatePerSecond, n.Enabled };
}
