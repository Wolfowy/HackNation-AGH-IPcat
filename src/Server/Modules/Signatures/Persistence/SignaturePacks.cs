using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;
using WebScan.Server.Modules.Signatures.Domain;
using WebScan.Server.Modules.Signatures.Validation;

namespace WebScan.Server.Modules.Signatures.Persistence;

public sealed record PackSignature(string Id, string Name, SignatureKind Kind, string Content);

/// <summary>A versioned set of signatures shipped with the server (embedded <c>Packs/&lt;name&gt;/pack.json</c>).</summary>
public sealed record SignaturePack(string Name, string Version, string Tag, IReadOnlyList<PackSignature> Signatures)
{
    /// <summary>CreatedBy/ApprovedBy of versions written by the seeder; a signature whose latest version has another author is left alone.</summary>
    public string Author => $"pack:{Name}";
}

public sealed record PackSeedResult(int Created, int Updated, int Retired, int Unchanged, int Skipped, int Invalid);

/// <summary>
/// Loads the embedded packs and applies them idempotently: new signatures are created as Approved, changed pack content becomes a new
/// approved version, signatures dropped from the pack are retired. Signatures retired or edited by an administrator are never touched.
/// </summary>
public static class SignaturePacks
{
    private const string ResourcePrefix = "Packs/";
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    private sealed record PackFile(string Name, string Version, string Tag, List<RuleEntry>? Rules, List<TemplateEntry>? Templates);
    private sealed record RuleEntry(string Id, string Name, JsonElement Rule);
    private sealed record TemplateEntry(string Id, string Name);

    public static IReadOnlyList<SignaturePack> LoadEmbedded()
    {
        var assembly = typeof(SignaturePacks).Assembly;
        var resources = assembly.GetManifestResourceNames().ToDictionary(n => n.Replace('\\', '/'), n => n);
        string Read(string path)
        {
            using var stream = assembly.GetManifestResourceStream(resources[ResourcePrefix + path])!;
            return new StreamReader(stream).ReadToEnd();
        }

        var packs = new List<SignaturePack>();
        foreach (var manifest in resources.Keys.Where(k => k.StartsWith(ResourcePrefix, StringComparison.Ordinal) && k.EndsWith("/pack.json", StringComparison.Ordinal)).Order())
        {
            var dir = manifest[ResourcePrefix.Length..^"pack.json".Length];
            var file = JsonSerializer.Deserialize<PackFile>(Read(dir + "pack.json"), Json)!;
            var signatures = (file.Rules ?? []).Select(r => new PackSignature(r.Id, r.Name, SignatureKind.ClassificationRule, JsonSerializer.Serialize(r.Rule, Indented)))
                .Concat((file.Templates ?? []).Select(t => new PackSignature(t.Id, t.Name, SignatureKind.NucleiTemplate, Read($"{dir}templates/{t.Id}.yaml"))))
                .ToList();
            packs.Add(new SignaturePack(file.Name, file.Version, file.Tag, signatures));
        }
        return packs;
    }

    public static async Task<PackSeedResult> SeedAsync(SignaturesDbContext db, SignaturePack pack, DateTimeOffset now, ILogger logger, CancellationToken ct = default)
    {
        int created = 0, updated = 0, retired = 0, unchanged = 0, skipped = 0, invalid = 0;
        var author = pack.Author;
        var ids = pack.Signatures.Select(s => s.Id).ToList();
        var existing = await db.Signatures.Include(s => s.Versions)
            .Where(s => ids.Contains(s.Id) || s.Versions.Any(v => v.CreatedBy == author))
            .ToDictionaryAsync(s => s.Id, ct);

        foreach (var item in pack.Signatures)
        {
            var validation = SignatureValidator.Validate(item.Kind, item.Content);
            if (!validation.Valid || (item.Kind == SignatureKind.NucleiTemplate && validation.TemplateId != item.Id))
            {
                invalid++;
                logger.LogWarning("Pack {Pack} signature {SignatureId} fails validation and is skipped: {Errors}", pack.Name, item.Id,
                    string.Join("; ", validation.Errors.DefaultIfEmpty("template id differs from signature id")));
                continue;
            }

            var sha = SignatureHashing.ContentSha256(item.Content);
            if (!existing.TryGetValue(item.Id, out var signature))
            {
                db.Signatures.Add(new Signature
                {
                    Id = item.Id, Name = item.Name, Kind = item.Kind, Status = SignatureStatus.Approved, Severity = validation.Severity,
                    Tags = [.. validation.Tags], LatestVersion = 1, ApprovedVersion = 1, CreatedAt = now, UpdatedAt = now,
                    Versions = [NewVersion(item, 1, sha, validation, author, now, pack)],
                });
                created++;
                continue;
            }

            var latest = signature.Versions.MaxBy(v => v.Version);
            // Retired by an admin, edited by an admin, or an id owned by someone else: the pack never overrides it.
            if (signature.Kind != item.Kind || signature.Status == SignatureStatus.Retired || latest?.CreatedBy != author) { skipped++; continue; }
            if (latest.Sha256 == sha) { unchanged++; continue; }

            var version = NewVersion(item, signature.LatestVersion + 1, sha, validation, author, now, pack);
            db.Versions.Add(version);
            signature.Name = item.Name;
            signature.LatestVersion = version.Version;
            signature.ApprovedVersion = version.Version;
            signature.Status = SignatureStatus.Approved;
            signature.Severity = version.Severity;
            signature.Tags = [.. version.Tags];
            signature.UpdatedAt = now;
            updated++;
        }

        var current = ids.ToHashSet(StringComparer.Ordinal);
        foreach (var signature in existing.Values.Where(s => !current.Contains(s.Id) && s.Status != SignatureStatus.Retired
                     && s.Versions.MaxBy(v => v.Version)?.CreatedBy == author))
        {
            signature.Status = SignatureStatus.Retired;
            signature.UpdatedAt = now;
            retired++;
        }

        await db.SaveChangesAsync(ct);
        var result = new PackSeedResult(created, updated, retired, unchanged, skipped, invalid);
        logger.LogInformation("Signature pack {Pack} {Version}: {Result}", pack.Name, pack.Version, result);
        return result;
    }

    private static SignatureVersion NewVersion(PackSignature item, int version, string sha, SignatureValidationResult v, string author, DateTimeOffset now,
        SignaturePack pack) => new()
    {
        SignatureId = item.Id, Version = version, Content = item.Content, Sha256 = sha, Severity = v.Severity, Tags = [.. v.Tags],
        RequiresApprovalNote = v.RequiresApprovalNote, CreatedBy = author, CreatedAt = now, ApprovedBy = author, ApprovedAt = now,
        ApprovalNote = $"Signature pack {pack.Name} {pack.Version}",
    };
}

/// <summary>Applies the embedded signature packs once the host starts (after migrations).</summary>
internal sealed class SignaturePackSeeder(IServiceScopeFactory scopes, TimeProvider time, ILogger<SignaturePackSeeder> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        foreach (var pack in SignaturePacks.LoadEmbedded())
        {
            await using var scope = scopes.CreateAsyncScope();
            try
            {
                await SignaturePacks.SeedAsync(scope.ServiceProvider.GetRequiredService<SignaturesDbContext>(), pack, time.GetUtcNow(), logger, cancellationToken);
            }
            catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
            {
                logger.LogWarning("Signature pack {Pack} was seeded concurrently by another instance; skipped.", pack.Name);
            }
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
