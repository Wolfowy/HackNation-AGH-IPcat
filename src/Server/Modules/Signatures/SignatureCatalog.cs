using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using WebScan.Contracts;
using WebScan.Server.Kernel.Discovery;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Modules.Signatures.Domain;
using WebScan.Server.Modules.Signatures.Persistence;
using WebScan.Server.Modules.Signatures.Validation;

namespace WebScan.Server.Modules.Signatures;

/// <summary>Serves only approved, non-retired signature versions (active bundle for agents, rules for Discovery).</summary>
internal sealed class SignatureCatalog(SignaturesDbContext db, ILogger<SignatureCatalog> logger) : ISignatureCatalog, IInterpretationRuleProvider
{
    public const string NucleiFormat = "nuclei-yaml";

    public async Task<SignatureBundle> GetApprovedBundleAsync(IReadOnlyCollection<string> signatureIds, IReadOnlyCollection<string> tags,
        IReadOnlyCollection<string> severities, CancellationToken ct = default)
    {
        var approved = await LoadApprovedAsync(SignatureKind.NucleiTemplate, ct);
        var items = approved
            .Where(x => signatureIds.Count == 0 || signatureIds.Contains(x.Signature.Id))
            .Where(x => tags.Count == 0 || x.Version.Tags.Any(t => tags.Contains(t, StringComparer.OrdinalIgnoreCase)))
            .Where(x => severities.Count == 0 || severities.Contains(x.Version.Severity ?? "", StringComparer.OrdinalIgnoreCase))
            .OrderBy(x => x.Signature.Id, StringComparer.Ordinal)
            .Select(x => new SignatureContent { Id = x.Signature.Id, Version = x.Version.Version, Format = NucleiFormat, Content = x.Version.Content })
            .ToList();
        return new SignatureBundle { Sha256 = SignatureHashing.BundleSha256(items), Items = items };
    }

    public async Task<IReadOnlyList<ClassificationRule>> GetApprovedClassificationRulesAsync(CancellationToken ct = default)
    {
        var rules = new List<ClassificationRule>();
        foreach (var (signature, version) in await LoadApprovedAsync(SignatureKind.ClassificationRule, ct))
        {
            if (!TryParse<ClassificationRuleDocument>(signature, version, out var doc) || doc!.When is null || doc.Outcome is null) continue;
            var o = doc.Outcome;
            rules.Add(new ClassificationRule(signature.Id, version.Version, signature.Name, doc.When, new ClassificationOutcome(
                o.Technology?.Name, o.Technology?.Version, o.Technology?.VersionField, o.Technology?.Category, o.ClassificationTag,
                o.Confidence ?? SignatureValidator.DefaultRuleConfidence)));
        }
        return rules;
    }

    public async Task<IReadOnlyList<ChangeRule>> GetApprovedChangeRulesAsync(CancellationToken ct = default)
    {
        var rules = new List<ChangeRule>();
        foreach (var (signature, version) in await LoadApprovedAsync(SignatureKind.ChangeRule, ct))
        {
            if (!TryParse<ChangeRuleDocument>(signature, version, out var doc) || doc!.ChangeTypes is null || doc.Severity is null) continue;
            rules.Add(new ChangeRule(signature.Id, version.Version, signature.Name, doc.ChangeTypes, doc.When, doc.Severity.Trim().ToLowerInvariant()));
        }
        return rules;
    }

    private bool TryParse<T>(Signature signature, SignatureVersion version, out T? doc) where T : class
    {
        if (SignatureValidator.TryParse(version.Content, out doc, out var error)) return true;
        logger.LogWarning("Approved signature {SignatureId} v{Version} cannot be parsed: {Error}", signature.Id, version.Version, error);
        return false;
    }

    private async Task<List<(Signature Signature, SignatureVersion Version)>> LoadApprovedAsync(SignatureKind kind, CancellationToken ct)
    {
        var rows = await (
            from s in db.Signatures.AsNoTracking()
            where s.Kind == kind && s.Status == SignatureStatus.Approved && s.ApprovedVersion != null
            join v in db.Versions.AsNoTracking() on new { s.Id, Version = s.ApprovedVersion!.Value } equals new { Id = v.SignatureId, v.Version }
            select new { s, v }).ToListAsync(ct);
        return rows.Select(r => (r.s, r.v)).ToList();
    }
}
