using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Logging;
using WebScan.Server.Kernel.Discovery;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Integrations.Persistence;

namespace WebScan.Server.Modules.Integrations.DefectDojo;

public sealed record ExportResult(int Exported, int Skipped, IReadOnlyList<string> Errors);

/// <summary>
/// Exports signature-match findings (never plain ports/services — <see cref="IFindingStore"/> only holds signature results)
/// to DefectDojo. Idempotent: the external id and a hash of the exported content are stored per finding; unchanged findings
/// are skipped, changed ones are updated in place.
/// </summary>
internal sealed class DefectDojoExporter(
    IntegrationsDbContext db,
    IFindingStore findings,
    ISecretProtector secrets,
    IHttpClientFactory httpClients,
    ITypedHttpClientFactory<DefectDojoClient> clients,
    TimeProvider time,
    ILogger<DefectDojoExporter> logger)
{
    public const string System = "defectdojo";

    public async Task<DefectDojoSettings?> GetSettingsAsync(CancellationToken ct) => await db.DefectDojo.FindAsync([DefectDojoSettings.SingletonId], ct);

    public DefectDojoClient CreateClient(DefectDojoSettings settings) =>
        clients.CreateClient(httpClients.CreateClient(settings.VerifyTls ? DefectDojoClient.VerifiedTlsClient : DefectDojoClient.InsecureTlsClient))
            .Connect(settings.BaseUrl!, secrets.Unprotect(settings.ApiKeyProtected!));

    /// <param name="minSeverity">Additional lower bound (the configured minimum severity always applies).</param>
    public async Task<ExportResult> ExportAsync(DefectDojoSettings settings, IReadOnlyList<FindingRecord> selected, string? minSeverity, CancellationToken ct)
    {
        var client = CreateClient(settings);
        var min = minSeverity is null ? settings.MinimumSeverity : Severities.Max(settings.MinimumSeverity, minSeverity);
        int exported = 0, skipped = 0;
        var errors = new List<string>();

        foreach (var finding in selected)
        {
            var existing = finding.ExternalRefs.FirstOrDefault(r => r.System == System);
            var body = FindingBody(finding);
            var hash = ContentHash(body);
            if (finding.IsFalsePositive || Severities.Rank(finding.Severity) < Severities.Rank(min) || existing?.ContentHash == hash)
            {
                skipped++;
                continue;
            }

            try
            {
                string externalId;
                if (existing is not null && int.TryParse(existing.ExternalId, CultureInfo.InvariantCulture, out var ddId))
                {
                    await client.UpdateFindingAsync(ddId, body, ct);
                    externalId = existing.ExternalId;
                }
                else
                {
                    var testId = await EnsureTestAsync(client, settings, ct);
                    var create = new Dictionary<string, object?>(body) { ["test"] = testId, ["found_by"] = new[] { settings.TestTypeId!.Value } };
                    externalId = (await client.CreateFindingAsync(create, ct)).ToString(CultureInfo.InvariantCulture);
                }
                await findings.SetExternalRefAsync(finding.Id, new FindingExternalRef(System, externalId, hash, time.GetUtcNow()), ct);
                exported++;
            }
            catch (Exception ex) when (ex is DefectDojoApiException or HttpRequestException or TaskCanceledException { CancellationToken.IsCancellationRequested: false })
            {
                logger.LogWarning(ex, "DefectDojo export of finding {FindingId} failed", finding.Id);
                errors.Add($"{finding.Id}: {ex.Message}");
            }
        }
        return new ExportResult(exported, skipped, errors);
    }

    private async Task<int> EnsureTestAsync(DefectDojoClient client, DefectDojoSettings settings, CancellationToken ct)
    {
        if (settings.TestId is { } existing && settings.TestTypeId is not null) return existing;
        settings.TestTypeId ??= await client.FindTestTypeIdAsync(ct);
        settings.TestId = await client.CreateTestAsync(settings.EngagementId!.Value, settings.TestTypeId.Value, time.GetUtcNow(), ct);
        await db.SaveChangesAsync(ct);
        return settings.TestId.Value;
    }

    /// <summary>DefectDojo finding fields (snake_case as in API v2). <c>unique_id_from_tool</c> = WebScan finding id.</summary>
    internal static Dictionary<string, object?> FindingBody(FindingRecord f)
    {
        var where = f.Port is { } port ? $"{f.Address}:{port}" : f.Address;
        var description = new StringBuilder()
            .AppendLine($"**Signature:** {f.SignatureId}{(f.SignatureVersion is { } v ? $" v{v}" : "")}")
            .AppendLine($"**Target:** {where}{(f.Hostname is null ? "" : $" ({f.Hostname})")}")
            .AppendLine($"**Detected:** {f.MatchedAt:O} by {f.Source}")
            .AppendLine($"**Confidence:** {f.ConfidenceScore.ToString("0.###", CultureInfo.InvariantCulture)} ({f.ConfidenceMethod})");
        if (f.MatchedUrl is not null) description.AppendLine($"**Matched at:** {f.MatchedUrl}");
        if (f.Evidence is not null) description.AppendLine().AppendLine("**Evidence:**").AppendLine("```").AppendLine(f.Evidence).AppendLine("```");

        var severity = Severities.Rank(f.Severity);
        return new Dictionary<string, object?>
        {
            ["title"] = $"{f.Name} ({where})",
            ["description"] = description.ToString(),
            ["severity"] = CultureInfo.InvariantCulture.TextInfo.ToTitleCase(Severities.All[severity]),
            ["numerical_severity"] = $"S{4 - severity}",
            ["active"] = f.Status == "Open",
            ["verified"] = false,
            ["date"] = f.MatchedAt.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
            ["unique_id_from_tool"] = f.Id.ToString(),
            ["vuln_id_from_tool"] = f.SignatureId,
            ["references"] = f.MatchedUrl,
            ["static_finding"] = false,
            ["dynamic_finding"] = true,
            ["tags"] = new[] { "webscan" }.Concat(f.Tags).Distinct().ToArray(),
        };
    }

    private static string ContentHash(Dictionary<string, object?> body) =>
        Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(body)));
}
