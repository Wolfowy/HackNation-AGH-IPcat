using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using WebScan.Server.Infrastructure.Persistence;
using WebScan.Server.Kernel.Discovery;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Integrations.DefectDojo;
using WebScan.Server.Modules.Integrations.Persistence;

namespace WebScan.Server.Modules.Integrations;

public sealed record DefectDojoSettingsDto(bool Enabled, string? BaseUrl, bool HasApiKey, int? ProductId, int? EngagementId, string MinimumSeverity,
    bool VerifyTls, DateTimeOffset? UpdatedAt);

/// <param name="ApiKey">Write-only: null keeps the stored key, "" removes it.</param>
public sealed record DefectDojoSettingsRequest(bool Enabled, string? BaseUrl, string? ApiKey, int? ProductId, int? EngagementId, string? MinimumSeverity,
    bool VerifyTls = true);

public sealed record DefectDojoExportRequest(IReadOnlyList<Guid>? FindingIds);
public sealed record DefectDojoTestResult(bool Ok, string Message);

public static class IntegrationsModule
{
    public static IServiceCollection AddIntegrationsModule(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddModuleDbContext<IntegrationsDbContext>(IntegrationsDbContext.Schema);
        services.TryAddSingleton(TimeProvider.System);
        var timeout = TimeSpan.FromSeconds(configuration.GetValue("Integrations:DefectDojo:TimeoutSeconds", 30));
        services.AddHttpClient<DefectDojoClient>(DefectDojoClient.VerifiedTlsClient, c => c.Timeout = timeout);
        services.AddHttpClient<DefectDojoClient>(DefectDojoClient.InsecureTlsClient, c => c.Timeout = timeout)
            .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
            {
                // Only used when an administrator explicitly disables TLS verification for a self-signed DefectDojo.
                ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
            });
        services.AddScoped<DefectDojoExporter>();
        services.AddScoped<IFindingPublisher, FindingPublisher>();
        return services;
    }

    public static IEndpointRouteBuilder MapIntegrationsEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var g = endpoints.MapGroup("/api/integrations/defectdojo").WithTags("Integrations");
        g.MapGet("", async (DefectDojoExporter exporter, CancellationToken ct) => ToDto(await exporter.GetSettingsAsync(ct)))
            .RequireAuthorization(Policies.AdminOnly);
        g.MapPut("", PutSettings).RequireAuthorization(Policies.AdminOnly);
        g.MapPost("/test", TestConnection).RequireAuthorization(Policies.AdminOnly);
        g.MapPost("/export", Export).RequireAuthorization(Policies.CanManage);
        return endpoints;
    }

    private static async Task<IResult> PutSettings(DefectDojoSettingsRequest r, IntegrationsDbContext db, ISecretProtector secrets, ICurrentUser user,
        IAuditLog audit, TimeProvider time, CancellationToken ct)
    {
        var settings = await db.DefectDojo.FindAsync([DefectDojoSettings.SingletonId], ct);
        var errors = new Dictionary<string, string[]>();
        var baseUrl = r.BaseUrl?.Trim();
        if (!string.IsNullOrEmpty(baseUrl) && !(Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri) && uri.Scheme is "https" or "http"))
            errors["baseUrl"] = ["baseUrl must be an absolute http(s) URL."];
        var minimum = (r.MinimumSeverity ?? "medium").Trim().ToLowerInvariant();
        if (!Severities.IsValid(minimum)) errors["minimumSeverity"] = [$"minimumSeverity must be one of {string.Join(", ", Severities.All)}."];
        var hasKey = r.ApiKey is null ? settings?.ApiKeyProtected is not null : r.ApiKey.Length > 0;
        if (r.Enabled && (string.IsNullOrEmpty(baseUrl) || !hasKey || r.EngagementId is not > 0))
            errors["enabled"] = ["baseUrl, apiKey and engagementId are required to enable the integration."];
        if (errors.Count > 0) return Results.ValidationProblem(errors, statusCode: StatusCodes.Status422UnprocessableEntity);

        if (settings is null) db.DefectDojo.Add(settings = new DefectDojoSettings());
        settings.Enabled = r.Enabled;
        settings.BaseUrl = string.IsNullOrEmpty(baseUrl) ? null : baseUrl;
        if (r.ApiKey is not null) settings.ApiKeyProtected = r.ApiKey.Length == 0 ? null : secrets.Protect(r.ApiKey);
        settings.ProductId = r.ProductId;
        settings.EngagementId = r.EngagementId;
        settings.MinimumSeverity = minimum;
        settings.VerifyTls = r.VerifyTls;
        settings.TestId = null; // target may have changed: the WebScan test is (re)created on the next export
        settings.UpdatedAt = time.GetUtcNow();
        settings.UpdatedBy = user.UserName ?? user.UserId;
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuditEntry("integration.defectdojo_updated", "integration", "defectdojo", new
        {
            r.Enabled, settings.BaseUrl, r.ProductId, r.EngagementId, minimum, r.VerifyTls, apiKeyChanged = r.ApiKey is not null,
        }), ct);
        return Results.Ok(ToDto(settings));
    }

    private static async Task<IResult> TestConnection(DefectDojoExporter exporter, CancellationToken ct)
    {
        var settings = await exporter.GetSettingsAsync(ct);
        if (settings is not { IsConfigured: true }) return Results.Ok(new DefectDojoTestResult(false, "Integration is not configured."));
        try
        {
            await exporter.CreateClient(settings).CheckEngagementAsync(settings.EngagementId!.Value, ct);
            return Results.Ok(new DefectDojoTestResult(true, $"Connected; engagement {settings.EngagementId} is accessible."));
        }
        catch (Exception ex) when (ex is DefectDojoApiException or HttpRequestException or TaskCanceledException)
        {
            return Results.Ok(new DefectDojoTestResult(false, ex.Message));
        }
    }

    private static async Task<IResult> Export(DefectDojoExportRequest r, DefectDojoExporter exporter, IFindingStore findings, IAuditLog audit,
        CancellationToken ct)
    {
        var ids = r.FindingIds?.Distinct().ToList() ?? [];
        if (ids.Count is 0 or > 1000)
            return Results.ValidationProblem(new Dictionary<string, string[]> { ["findingIds"] = ["Select between 1 and 1000 findings."] }, statusCode: StatusCodes.Status422UnprocessableEntity);
        var settings = await exporter.GetSettingsAsync(ct);
        if (settings is not { Enabled: true, IsConfigured: true })
            return Results.Problem("DefectDojo integration is disabled or not configured.", statusCode: StatusCodes.Status409Conflict);

        var selected = await findings.GetByIdsAsync(ids, ct);
        var result = await exporter.ExportAsync(settings, selected, null, ct);
        var errors = ids.Except(selected.Select(f => f.Id)).Select(id => $"{id}: finding not found").Concat(result.Errors).ToList();
        await audit.WriteAsync(new AuditEntry("integration.defectdojo_exported", "integration", "defectdojo",
            new { requested = ids.Count, result.Exported, result.Skipped, errors = errors.Count }), ct);
        return Results.Ok(result with { Errors = errors });
    }

    private static DefectDojoSettingsDto ToDto(DefectDojoSettings? s) => s is null
        ? new DefectDojoSettingsDto(false, null, false, null, null, "medium", true, null)
        : new DefectDojoSettingsDto(s.Enabled, s.BaseUrl, s.ApiKeyProtected is not null, s.ProductId, s.EngagementId, s.MinimumSeverity, s.VerifyTls, s.UpdatedAt);
}
