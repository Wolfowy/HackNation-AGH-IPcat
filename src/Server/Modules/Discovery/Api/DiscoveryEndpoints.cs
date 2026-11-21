using System.Globalization;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using WebScan.Contracts;
using WebScan.Server.Kernel.Discovery;
using WebScan.Server.Kernel.Networking;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Discovery.Domain;
using WebScan.Server.Modules.Discovery.Normalization;
using WebScan.Server.Modules.Discovery.Persistence;

namespace WebScan.Server.Modules.Discovery.Api;

internal static class DiscoveryEndpoints
{
    private const int MaxImportBytes = 10 * 1024 * 1024;

    public static void Map(IEndpointRouteBuilder e)
    {
        var api = e.MapGroup("/api").WithTags("Discovery");

        api.MapGet("/dashboard/summary", (AssetQueries q, TimeProvider time, CancellationToken ct) => q.DashboardAsync(time.GetUtcNow(), ct))
            .RequireAuthorization(Policies.CanRead);

        api.MapGet("/assets/hosts", (AssetQueries q, string? search, HostStatus? status, string? zone, int? page, int? pageSize, CancellationToken ct) =>
        {
            var (p, size) = AssetQueries.Paging(page, pageSize);
            return q.HostsAsync(new HostQuery(search, status, zone), p, size, ct);
        }).RequireAuthorization(Policies.CanRead);

        api.MapGet("/assets/hosts/{id:guid}", async (Guid id, AssetQueries q, CancellationToken ct) =>
            await q.HostAsync(id, ct) is { } host ? Results.Ok(host) : Results.NotFound()).RequireAuthorization(Policies.CanRead);

        api.MapPut("/assets/hosts/{id:guid}/annotation", PutAnnotation).RequireAuthorization(Policies.CanEdit);

        api.MapGet("/assets/services", (AssetQueries q, int? port, string? serviceName, string? search, int? page, int? pageSize, CancellationToken ct) =>
        {
            var (p, size) = AssetQueries.Paging(page, pageSize);
            return q.ServicesAsync(new ServiceQuery(port, serviceName, search), p, size, ct);
        }).RequireAuthorization(Policies.CanRead);

        api.MapGet("/assets/technologies", (AssetQueries q, CancellationToken ct) => q.TechnologiesAsync(ct)).RequireAuthorization(Policies.CanRead);

        api.MapGet("/observations", async (AssetQueries q, Guid? hostId, Guid? scanRunId, ObservationKind? kind, int? page, int? pageSize, CancellationToken ct) =>
        {
            var (p, size) = AssetQueries.Paging(page, pageSize);
            return await q.ObservationsAsync(hostId, scanRunId, kind, p, size, ct) is { } result ? Results.Ok(result) : Results.NotFound();
        }).RequireAuthorization(Policies.CanRead);

        api.MapGet("/changes", (AssetQueries q, DateTimeOffset? since, AssetChangeType? type, Guid? hostId, Guid? scanRunId, int? page, int? pageSize,
            CancellationToken ct) =>
        {
            var (p, size) = AssetQueries.Paging(page, pageSize);
            return q.ChangesAsync(new ChangeQuery(since, type, hostId, scanRunId), p, size, ct);
        }).RequireAuthorization(Policies.CanRead);

        api.MapGet("/findings", (AssetQueries q, string? severity, FindingStatus? status, int? page, int? pageSize, CancellationToken ct) =>
        {
            var (p, size) = AssetQueries.Paging(page, pageSize);
            return q.FindingsAsync(new FindingQuery(severity, status), p, size, ct);
        }).RequireAuthorization(Policies.CanRead);

        api.MapGet("/export/{dataset}", Export).RequireAuthorization(Policies.CanRead);
        api.MapPost("/import/assets", Import).RequireAuthorization(Policies.CanManage);
    }

    private static async Task<IResult> PutAnnotation(Guid id, AnnotationRequest request, DiscoveryDbContext db, AnnotationService annotations,
        IAuditLog audit, CancellationToken ct)
    {
        var errors = AnnotationService.Validate(request);
        if (errors.Count > 0) return Results.ValidationProblem(new Dictionary<string, string[]> { ["annotation"] = [.. errors] }, statusCode: StatusCodes.Status422UnprocessableEntity);
        var address = await db.Hosts.Where(h => h.Id == id).Select(h => h.Address).FirstOrDefaultAsync(ct);
        if (address is null) return Results.NotFound();

        var (created, changed, annotation) = await annotations.UpsertAsync(address, request, "api", ct);
        if (changed)
        {
            await db.SaveChangesAsync(ct);
            await audit.WriteAsync(new AuditEntry(created ? "asset.annotation_created" : "asset.annotation_updated", "host", id.ToString(),
                new { address, annotation.Classification, annotation.BusinessState, annotation.Owner, annotation.Tags }), ct);
        }
        return Results.Ok(annotation.ToDto());
    }

    private static async Task<IResult> Export(string dataset, string? format, AssetQueries q, CancellationToken ct)
    {
        format = (format ?? "json").ToLowerInvariant();
        if (format is not ("json" or "csv"))
            return Results.ValidationProblem(new Dictionary<string, string[]> { ["format"] = ["format must be json or csv."] }, statusCode: StatusCodes.Status422UnprocessableEntity);

        const int rows = AssetQueries.MaxExportRows;
        (IReadOnlyList<string> Header, Func<IEnumerable<IReadOnlyList<string?>>> Rows, object Json)? export = dataset.ToLowerInvariant() switch
        {
            "hosts" => HostsExport((await q.HostsAsync(new HostQuery(null, null, null), 1, rows, ct)).Items),
            "services" => ServicesExport((await q.ServicesAsync(new ServiceQuery(null, null, null), 1, rows, ct)).Items),
            "changes" => ChangesExport((await q.ChangesAsync(new ChangeQuery(null, null, null, null), 1, rows, ct)).Items),
            "findings" => FindingsExport((await q.FindingsAsync(new FindingQuery(null, null), 1, rows, ct)).Items),
            _ => null,
        };
        if (export is null) return Results.NotFound();

        var fileName = $"webscan-{dataset.ToLowerInvariant()}.{format}";
        return format == "json"
            ? Results.Json(export.Value.Json, contentType: "application/json")
            : Results.File(System.Text.Encoding.UTF8.GetBytes(Csv.Write(export.Value.Header, export.Value.Rows())), "text/csv; charset=utf-8", fileName);
    }

    private static async Task<IResult> Import(HttpRequest request, string? format, DiscoveryDbContext db, AnnotationService annotations,
        IAuditLog audit, CancellationToken ct)
    {
        format = (format ?? "json").ToLowerInvariant();
        if (format is not ("json" or "csv"))
            return Results.ValidationProblem(new Dictionary<string, string[]> { ["format"] = ["format must be json or csv."] }, statusCode: StatusCodes.Status422UnprocessableEntity);
        if (request.ContentLength > MaxImportBytes) return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);

        string body;
        using (var reader = new StreamReader(request.Body))
        {
            var buffer = new char[MaxImportBytes + 1];
            var read = await reader.ReadBlockAsync(buffer, ct);
            if (read > MaxImportBytes) return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
            body = new string(buffer, 0, read);
        }

        var errors = new List<string>();
        var rows = format == "json" ? ParseJson(body, errors) : ParseCsv(body, errors);
        int imported = 0, updated = 0;
        for (var i = 0; i < rows.Count; i++)
        {
            var (line, row) = rows[i];
            var address = Normalizer.CanonicalAddress(row.Address);
            if (address is null || IpRangeSet.Classify(address) is not (TargetEntryKind.Address or TargetEntryKind.Hostname))
            {
                errors.Add($"Row {line}: invalid address '{row.Address}'.");
                continue;
            }
            var annotation = new AnnotationRequest(row.Description, row.Classification, row.BusinessState, row.Owner, row.Tags);
            var rowErrors = AnnotationService.Validate(annotation);
            if (rowErrors.Count > 0)
            {
                errors.AddRange(rowErrors.Select(err => $"Row {line}: {err}"));
                continue;
            }
            var (created, changed, _) = await annotations.UpsertAsync(address, annotation, "import", ct);
            if (created) imported++;
            else if (changed) updated++;
        }

        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuditEntry("assets.imported", "asset_annotation", null, new { format, imported, updated, errors = errors.Count }), ct);
        return Results.Ok(new ImportResult(imported, updated, errors));
    }

    private static List<(int Line, AssetImportRow Row)> ParseJson(string body, List<string> errors)
    {
        try
        {
            var rows = JsonSerializer.Deserialize<List<AssetImportRow>>(body, ContractJson.Options) ?? [];
            return rows.Select((r, i) => (i + 1, r)).ToList();
        }
        catch (JsonException ex)
        {
            errors.Add($"Invalid JSON: {ex.Message}");
            return [];
        }
    }

    /// <summary>Header row required: address, description, classification, businessState, owner, tags (';'-separated); column order free.</summary>
    private static List<(int Line, AssetImportRow Row)> ParseCsv(string body, List<string> errors)
    {
        var table = Csv.Parse(body);
        if (table.Count == 0) return [];
        var header = table[0].Select(h => h.Trim().ToLowerInvariant()).ToList();
        var col = (string name) => header.IndexOf(name.ToLowerInvariant());
        if (col("address") < 0)
        {
            errors.Add("CSV header must contain an 'address' column.");
            return [];
        }
        string? Cell(List<string> row, string name) => col(name) is var i and >= 0 && i < row.Count && row[i].Length > 0 ? row[i] : null;
        return table.Skip(1).Select((row, i) => (i + 2, new AssetImportRow(Cell(row, "address"), Cell(row, "description"),
            Cell(row, "classification"), Cell(row, "businessState"), Cell(row, "owner"),
            Cell(row, "tags")?.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)))).ToList();
    }

    private static string? D(DateTimeOffset? d) => d?.ToString("O", CultureInfo.InvariantCulture);
    private static string? N(double? d) => d?.ToString(CultureInfo.InvariantCulture);
    private static string? I(int? i) => i?.ToString(CultureInfo.InvariantCulture);

    private static (IReadOnlyList<string>, Func<IEnumerable<IReadOnlyList<string?>>>, object) HostsExport(IReadOnlyList<HostListItemDto> items) =>
    (["id", "address", "hostnames", "status", "unstable", "zone", "firstSeenAt", "lastSeenAt", "lastScannedAt", "openPortCount", "technologies",
            "classifications", "description", "classification", "businessState", "owner", "tags"],
        () => items.Select(h => (IReadOnlyList<string?>)
        [
            h.Id.ToString(), h.Address, string.Join(';', h.Hostnames), h.Status.ToString(), h.Unstable ? "true" : "false", h.Zone, D(h.FirstSeenAt),
            D(h.LastSeenAt), D(h.LastScannedAt), I(h.OpenPortCount), string.Join(';', h.Technologies), string.Join(';', h.Classifications),
            h.Annotation?.Description, h.Annotation?.Classification, h.Annotation?.BusinessState, h.Annotation?.Owner,
            string.Join(';', h.Annotation?.Tags ?? []),
        ]), items);

    private static (IReadOnlyList<string>, Func<IEnumerable<IReadOnlyList<string?>>>, object) ServicesExport(IReadOnlyList<ServiceDto> items) =>
    (["id", "hostId", "address", "port", "transport", "state", "serviceName", "product", "version", "httpUrl", "httpStatusCode", "httpTitle",
            "webServer", "tlsSubjectCommonName", "tlsIssuer", "tlsNotAfter", "tlsFingerprintSha256", "technologies", "confidence", "firstSeenAt", "lastSeenAt"],
        () => items.Select(s => (IReadOnlyList<string?>)
        [
            s.Id.ToString(), s.HostId.ToString(), s.Address, I(s.Port), s.Transport.ToString(), s.State.ToString(), s.ServiceName, s.Product,
            s.Version, s.Http?.Url, I(s.Http?.StatusCode), s.Http?.Title, s.Http?.WebServer, s.Tls?.SubjectCommonName, s.Tls?.Issuer,
            D(s.Tls?.NotAfter), s.Tls?.FingerprintSha256, string.Join(';', s.Technologies), N(s.Confidence), D(s.FirstSeenAt), D(s.LastSeenAt),
        ]), items);

    private static (IReadOnlyList<string>, Func<IEnumerable<IReadOnlyList<string?>>>, object) ChangesExport(IReadOnlyList<ChangeDto> items) =>
    (["id", "detectedAt", "scanRunId", "type", "hostId", "address", "port", "severity", "summary", "before", "after"],
        () => items.Select(c => (IReadOnlyList<string?>)
        [
            c.Id.ToString(), D(c.DetectedAt), c.ScanRunId.ToString(), c.Type.ToString(), c.HostId?.ToString(), c.Address, I(c.Port), c.Severity,
            c.Summary, c.Before, c.After,
        ]), items);

    private static (IReadOnlyList<string>, Func<IEnumerable<IReadOnlyList<string?>>>, object) FindingsExport(IReadOnlyList<FindingDto> items) =>
    (["id", "signatureId", "signatureVersion", "name", "severity", "status", "hostId", "address", "port", "matchedAt", "firstSeenAt", "lastSeenAt",
            "source", "confidence", "confidenceMethod", "matchedUrl", "evidence", "externalRefs"],
        () => items.Select(f => (IReadOnlyList<string?>)
        [
            f.Id.ToString(), f.SignatureId, I(f.SignatureVersion), f.Name, f.Severity, f.Status.ToString(), f.HostId.ToString(), f.Address, I(f.Port),
            D(f.MatchedAt), D(f.FirstSeenAt), D(f.LastSeenAt), f.Source, N(f.Confidence), f.ConfidenceMethod, f.MatchedUrl, f.Evidence,
            string.Join(';', f.ExternalRefs.Select(r => $"{r.System}:{r.ExternalId}")),
        ]), items);
}
