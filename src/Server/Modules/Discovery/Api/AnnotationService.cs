using Microsoft.EntityFrameworkCore;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Discovery.Domain;
using WebScan.Server.Modules.Discovery.Persistence;

namespace WebScan.Server.Modules.Discovery.Api;

/// <summary>User annotations per address: separate from evidence, every saved change kept as a revision.</summary>
internal sealed class AnnotationService(DiscoveryDbContext db, ICurrentUser user, TimeProvider time)
{
    public static List<string> Validate(AnnotationRequest r)
    {
        var errors = new List<string>();
        if (r.Description?.Length > 2000) errors.Add("description: max 2000 characters.");
        if (r.Classification?.Length > 200) errors.Add("classification: max 200 characters.");
        if (r.BusinessState?.Length > 200) errors.Add("businessState: max 200 characters.");
        if (r.Owner?.Length > 200) errors.Add("owner: max 200 characters.");
        if (r.Tags is { Count: > 50 }) errors.Add("tags: max 50 tags.");
        if (r.Tags?.Any(t => t.Length > 64) == true) errors.Add("tags: max 64 characters per tag.");
        return errors;
    }

    /// <summary>Creates or updates the annotation of <paramref name="address"/> (caller saves). Returns (created, changed).</summary>
    public async Task<(bool Created, bool Changed, AssetAnnotation Annotation)> UpsertAsync(string address, AnnotationRequest r, string source, CancellationToken ct)
    {
        var tags = (r.Tags ?? []).Select(t => t.Trim()).Where(t => t.Length > 0).Distinct().ToList();
        var annotation = db.Annotations.Local.FirstOrDefault(a => a.Address == address)
                         ?? await db.Annotations.FirstOrDefaultAsync(a => a.Address == address, ct);
        var created = annotation is null;
        annotation ??= db.Annotations.Add(new AssetAnnotation { Address = address }).Entity;

        var changed = created || annotation.Description != Clean(r.Description) || annotation.Classification != Clean(r.Classification)
            || annotation.BusinessState != Clean(r.BusinessState) || annotation.Owner != Clean(r.Owner) || !annotation.Tags.SequenceEqual(tags);
        if (!changed) return (false, false, annotation);

        var now = time.GetUtcNow();
        var by = user.UserName ?? user.UserId;
        annotation.Description = Clean(r.Description);
        annotation.Classification = Clean(r.Classification);
        annotation.BusinessState = Clean(r.BusinessState);
        annotation.Owner = Clean(r.Owner);
        annotation.Tags = tags;
        annotation.UpdatedAt = now;
        annotation.UpdatedBy = by;
        db.AnnotationRevisions.Add(new AssetAnnotationRevision
        {
            Address = address, Description = annotation.Description, Classification = annotation.Classification,
            BusinessState = annotation.BusinessState, Owner = annotation.Owner, Tags = [.. tags], ChangedAt = now, ChangedBy = by, Source = source,
        });
        return (created, true, annotation);
    }

    private static string? Clean(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
}
