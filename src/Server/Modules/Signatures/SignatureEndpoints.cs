using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Signatures.Domain;
using WebScan.Server.Modules.Signatures.Persistence;
using WebScan.Server.Modules.Signatures.Validation;

namespace WebScan.Server.Modules.Signatures;

public sealed record SignatureSummaryDto(string Id, string Name, SignatureKind Kind, int LatestVersion, int? ApprovedVersion,
    SignatureStatus Status, string? Severity, IReadOnlyList<string> Tags, DateTimeOffset UpdatedAt);

public sealed record SignatureVersionDto(int Version, string Content, string Sha256, string? Severity, IReadOnlyList<string> Tags,
    bool RequiresApprovalNote, DateTimeOffset CreatedAt, string CreatedBy, DateTimeOffset? ApprovedAt, string? ApprovedBy, string? ApprovalNote);

public sealed record SignatureDetailDto(string Id, string Name, SignatureKind Kind, int LatestVersion, int? ApprovedVersion,
    SignatureStatus Status, string? Severity, IReadOnlyList<string> Tags, DateTimeOffset UpdatedAt, IReadOnlyList<SignatureVersionDto> Versions);

public sealed record CreateSignatureRequest(string? Id, string? Name, SignatureKind Kind, string? Content);
public sealed record CreateVersionRequest(string? Content);
public sealed record ApproveVersionRequest(string? Note);
public sealed record ValidateSignatureRequest(SignatureKind Kind, string? Content);
public sealed record ValidateSignatureResponse(bool Valid, IReadOnlyList<string> Errors, IReadOnlyList<string> Warnings);

internal static class SignatureEndpoints
{
    public static void Map(IEndpointRouteBuilder endpoints)
    {
        var g = endpoints.MapGroup("/api/signatures").WithTags("Signatures");
        g.MapGet("", List).RequireAuthorization(Policies.CanRead);
        g.MapGet("/{id}", Get).RequireAuthorization(Policies.CanRead);
        g.MapPost("", Create).RequireAuthorization(Policies.CanManage);
        g.MapPost("/{id}/versions", CreateVersion).RequireAuthorization(Policies.CanManage);
        g.MapPost("/{id}/versions/{version:int}/approve", Approve).RequireAuthorization(Policies.AdminOnly);
        g.MapPost("/{id}/retire", Retire).RequireAuthorization(Policies.CanManage);
        g.MapPost("/validate", (ValidateSignatureRequest r) =>
        {
            var v = SignatureValidator.Validate(r.Kind, r.Content);
            return Results.Ok(new ValidateSignatureResponse(v.Valid, v.Errors, v.Warnings));
        }).RequireAuthorization(Policies.CanRead);
    }

    private static async Task<IResult> List(SignaturesDbContext db, SignatureKind? kind, SignatureStatus? status, CancellationToken ct)
    {
        var q = db.Signatures.AsNoTracking();
        if (kind is not null) q = q.Where(s => s.Kind == kind);
        if (status is not null) q = q.Where(s => s.Status == status);
        var list = await q.OrderBy(s => s.Id).ToListAsync(ct);
        return Results.Ok(list.Select(ToSummary));
    }

    private static async Task<IResult> Get(string id, SignaturesDbContext db, CancellationToken ct)
    {
        var s = await db.Signatures.AsNoTracking().Include(x => x.Versions).FirstOrDefaultAsync(x => x.Id == id, ct);
        return s is null ? Results.NotFound() : Results.Ok(ToDetail(s));
    }

    private static async Task<IResult> Create(CreateSignatureRequest r, SignaturesDbContext db, ICurrentUser user, IAuditLog audit,
        TimeProvider time, CancellationToken ct)
    {
        var errors = new Dictionary<string, string[]>();
        if (string.IsNullOrWhiteSpace(r.Id) || !Regex.IsMatch(r.Id, Signature.IdPattern)) errors["id"] = [$"Id must match {Signature.IdPattern}."];
        if (string.IsNullOrWhiteSpace(r.Name) || r.Name.Length > 200) errors["name"] = ["Name is required (max 200 chars)."];
        if (errors.Count > 0) return Results.ValidationProblem(errors, statusCode: StatusCodes.Status422UnprocessableEntity);

        var validation = ValidateContent(r.Kind, r.Id!, r.Content);
        if (validation.Errors.Count > 0) return Results.ValidationProblem(new Dictionary<string, string[]> { ["content"] = [.. validation.Errors] }, statusCode: StatusCodes.Status422UnprocessableEntity);
        if (await db.Signatures.AnyAsync(s => s.Id == r.Id, ct)) return Results.Problem(statusCode: StatusCodes.Status409Conflict, title: $"Signature '{r.Id}' already exists.");

        var now = time.GetUtcNow();
        var signature = new Signature
        {
            Id = r.Id!, Name = r.Name!.Trim(), Kind = r.Kind, Status = SignatureStatus.Draft, Severity = validation.Severity,
            Tags = [.. validation.Tags], LatestVersion = 1, CreatedAt = now, UpdatedAt = now,
            Versions = [NewVersion(r.Id!, 1, r.Content!, validation, user, now)],
        };
        db.Signatures.Add(signature);
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuditEntry("signature.created", "signature", signature.Id, new { signature.Kind, version = 1 }), ct);
        return Results.Created($"/api/signatures/{signature.Id}", ToDetail(signature));
    }

    private static async Task<IResult> CreateVersion(string id, CreateVersionRequest r, SignaturesDbContext db, ICurrentUser user,
        IAuditLog audit, TimeProvider time, CancellationToken ct)
    {
        var signature = await db.Signatures.FirstOrDefaultAsync(s => s.Id == id, ct);
        if (signature is null) return Results.NotFound();

        var validation = ValidateContent(signature.Kind, id, r.Content);
        if (validation.Errors.Count > 0) return Results.ValidationProblem(new Dictionary<string, string[]> { ["content"] = [.. validation.Errors] }, statusCode: StatusCodes.Status422UnprocessableEntity);

        var now = time.GetUtcNow();
        var version = NewVersion(id, signature.LatestVersion + 1, r.Content!, validation, user, now);
        db.Versions.Add(version);
        signature.LatestVersion = version.Version;
        signature.UpdatedAt = now;
        if (signature.ApprovedVersion is null)
        {
            signature.Severity = version.Severity;
            signature.Tags = [.. version.Tags];
        }
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuditEntry("signature.version_created", "signature", id, new { version = version.Version }), ct);
        return Results.Created($"/api/signatures/{id}", ToVersion(version));
    }

    private static async Task<IResult> Approve(string id, int version, ApproveVersionRequest? r, SignaturesDbContext db, ICurrentUser user,
        IAuditLog audit, TimeProvider time, CancellationToken ct)
    {
        var signature = await db.Signatures.FirstOrDefaultAsync(s => s.Id == id, ct);
        var v = await db.Versions.FirstOrDefaultAsync(x => x.SignatureId == id && x.Version == version, ct);
        if (signature is null || v is null) return Results.NotFound();

        // Re-validate at approval time: validator rules may have tightened since the version was created.
        var validation = ValidateContent(signature.Kind, id, v.Content);
        if (validation.Errors.Count > 0) return Results.ValidationProblem(new Dictionary<string, string[]> { ["content"] = [.. validation.Errors] }, statusCode: StatusCodes.Status422UnprocessableEntity);
        var note = r?.Note?.Trim();
        if (validation.RequiresApprovalNote && string.IsNullOrEmpty(note))
            return Results.ValidationProblem(new Dictionary<string, string[]>
            {
                ["note"] = [$"Severity '{validation.Severity}' is above medium: an approval note is required."],
            }, statusCode: StatusCodes.Status422UnprocessableEntity);

        var now = time.GetUtcNow();
        v.ApprovedBy = UserName(user);
        v.ApprovedAt = now;
        v.ApprovalNote = note;
        signature.ApprovedVersion = version;
        signature.Status = SignatureStatus.Approved;
        signature.Severity = v.Severity;
        signature.Tags = [.. v.Tags];
        signature.UpdatedAt = now;
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuditEntry("signature.approved", "signature", id, new { version, note }), ct);
        return Results.Ok(ToVersion(v));
    }

    private static async Task<IResult> Retire(string id, SignaturesDbContext db, IAuditLog audit, TimeProvider time, CancellationToken ct)
    {
        var signature = await db.Signatures.FirstOrDefaultAsync(s => s.Id == id, ct);
        if (signature is null) return Results.NotFound();
        signature.Status = SignatureStatus.Retired;
        signature.UpdatedAt = time.GetUtcNow();
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuditEntry("signature.retired", "signature", id), ct);
        return Results.Ok(ToSummary(signature));
    }

    private static SignatureValidationResult ValidateContent(SignatureKind kind, string id, string? content)
    {
        var result = SignatureValidator.Validate(kind, content);
        if (kind == SignatureKind.NucleiTemplate && result.TemplateId is not null && result.TemplateId != id)
            return result with { Valid = false, Errors = [.. result.Errors, $"Template id '{result.TemplateId}' must equal the signature id '{id}'."] };
        return result;
    }

    private static SignatureVersion NewVersion(string id, int version, string content, SignatureValidationResult v, ICurrentUser user, DateTimeOffset now) => new()
    {
        SignatureId = id, Version = version, Content = content, Sha256 = SignatureHashing.ContentSha256(content), Severity = v.Severity,
        Tags = [.. v.Tags], RequiresApprovalNote = v.RequiresApprovalNote, CreatedBy = UserName(user), CreatedAt = now,
    };

    private static string UserName(ICurrentUser user) => user.UserName ?? user.UserId ?? "unknown";

    private static SignatureSummaryDto ToSummary(Signature s) =>
        new(s.Id, s.Name, s.Kind, s.LatestVersion, s.ApprovedVersion, s.Status, s.Severity, s.Tags, s.UpdatedAt);

    private static SignatureDetailDto ToDetail(Signature s) =>
        new(s.Id, s.Name, s.Kind, s.LatestVersion, s.ApprovedVersion, s.Status, s.Severity, s.Tags, s.UpdatedAt,
            s.Versions.OrderBy(v => v.Version).Select(ToVersion).ToList());

    private static SignatureVersionDto ToVersion(SignatureVersion v) =>
        new(v.Version, v.Content, v.Sha256, v.Severity, v.Tags, v.RequiresApprovalNote, v.CreatedAt, v.CreatedBy, v.ApprovedAt, v.ApprovedBy, v.ApprovalNote);
}
