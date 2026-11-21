using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using WebScan.Server.Infrastructure.Http;
using WebScan.Server.Infrastructure.Persistence;
using WebScan.Server.Kernel.Security;

namespace WebScan.Server.Infrastructure;

public sealed record SettingsDto(IReadOnlyDictionary<string, string?> Values);

public sealed record AuditEntryDto(Guid Id, DateTimeOffset OccurredAt, string? UserId, string? UserName, string Action,
    string EntityType, string? EntityId, JsonElement? Details, string? IpAddress);

/// <summary>Health probes, settings (<c>/api/settings</c>) and audit trail (<c>/api/audit</c>).</summary>
public static partial class InfrastructureEndpoints
{
    public const string ReadyTag = "ready";

    [GeneratedRegex("^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$")]
    private static partial Regex SettingKeyRegex();

    public static IEndpointRouteBuilder MapInfrastructureEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false }).AllowAnonymous();
        endpoints.MapHealthChecks("/health/ready", new HealthCheckOptions { Predicate = c => c.Tags.Contains(ReadyTag) }).AllowAnonymous();

        endpoints.MapGet("/api/settings", GetSettings).RequireAuthorization(Policies.AdminOnly);
        endpoints.MapPut("/api/settings", PutSettings).RequireAuthorization(Policies.AdminOnly);
        endpoints.MapGet("/api/audit", GetAudit).RequireAuthorization(Policies.AdminOnly);
        return endpoints;
    }

    private static async Task<SettingsDto> GetSettings(InfraDbContext db, CancellationToken ct) =>
        new(await db.Settings.AsNoTracking().OrderBy(s => s.Key).ToDictionaryAsync(s => s.Key, s => (string?)s.Value, ct));

    /// <summary>Upserts the given keys; a <c>null</c> value deletes the key. Keys not mentioned stay unchanged.</summary>
    private static async Task<IResult> PutSettings(SettingsDto request, InfraDbContext db, IAuditLog audit, ICurrentUser user,
        TimeProvider time, CancellationToken ct)
    {
        var errors = new ValidationErrors();
        foreach (var (key, value) in request.Values ?? new Dictionary<string, string?>())
        {
            errors.Require(SettingKeyRegex().IsMatch(key), $"values.{key}", "Invalid key (letters, digits, '_', '.', ':', '-'; max 128).");
            errors.Require(value is null || value.Length <= SettingRecord.MaxValueLength, $"values.{key}", $"Value longer than {SettingRecord.MaxValueLength} characters.");
        }
        if (!errors.IsValid) return errors.ToResult();

        var values = request.Values ?? new Dictionary<string, string?>();
        var keys = values.Keys.ToList();
        var existing = await db.Settings.Where(s => keys.Contains(s.Key)).ToDictionaryAsync(s => s.Key, ct);
        var now = time.GetUtcNow();
        foreach (var (key, value) in values)
        {
            existing.TryGetValue(key, out var record);
            if (value is null)
            {
                if (record is not null) db.Settings.Remove(record);
            }
            else if (record is null)
            {
                db.Settings.Add(new SettingRecord { Key = key, Value = value, UpdatedAt = now, UpdatedBy = user.UserName });
            }
            else
            {
                record.Value = value;
                record.UpdatedAt = now;
                record.UpdatedBy = user.UserName;
            }
        }
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuditEntry("settings.updated", "settings", null, new { keys }), ct);
        return Results.Ok(await GetSettings(db, ct));
    }

    private static async Task<PagedResult<AuditEntryDto>> GetAudit(InfraDbContext db, int? page, int? pageSize, string? action,
        string? entityType, string? userId, CancellationToken ct)
    {
        var (p, size, skip) = Paging.Normalize(page, pageSize);
        var query = db.AuditEntries.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(action)) query = query.Where(a => a.Action == action);
        if (!string.IsNullOrWhiteSpace(entityType)) query = query.Where(a => a.EntityType == entityType);
        if (!string.IsNullOrWhiteSpace(userId)) query = query.Where(a => a.UserId == userId);

        var total = await query.CountAsync(ct);
        var rows = await query.OrderByDescending(a => a.OccurredAt).ThenByDescending(a => a.Id).Skip(skip).Take(size).ToListAsync(ct);
        var items = rows.Select(a => new AuditEntryDto(a.Id, a.OccurredAt, a.UserId, a.UserName, a.Action, a.EntityType, a.EntityId,
            a.Details is null ? null : JsonDocument.Parse(a.Details).RootElement, a.IpAddress)).ToList();
        return new PagedResult<AuditEntryDto>(items, total, p, size);
    }
}

internal sealed class DatabaseHealthCheck(InfraDbContext db) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default) =>
        await db.Database.CanConnectAsync(cancellationToken)
            ? HealthCheckResult.Healthy()
            : HealthCheckResult.Unhealthy("PostgreSQL is not reachable.");
}
