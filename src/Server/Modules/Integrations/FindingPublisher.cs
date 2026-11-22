using Microsoft.Extensions.Logging;
using WebScan.Server.Kernel.Discovery;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Modules.Integrations.DefectDojo;

namespace WebScan.Server.Modules.Integrations;

/// <summary>
/// PublishFinding step. "internal" marks the run's open findings (≥ minSeverity) as published; "defectdojo" exports them when
/// the integration is enabled (configured minimum severity also applies). Only signature matches are ever published, never ones triaged
/// as false positive; severity is the effective (user-overridden) one.
/// </summary>
internal sealed class FindingPublisher(IFindingStore findings, DefectDojoExporter defectDojo, ILogger<FindingPublisher> logger) : IFindingPublisher
{
    public async Task<PublishFindingsResult> PublishAsync(Guid scanRunId, string destination, string minSeverity, CancellationToken ct = default)
    {
        if (!Severities.IsValid(minSeverity)) throw new ArgumentException($"Unknown severity '{minSeverity}'.", nameof(minSeverity));
        var runFindings = await findings.GetRunFindingsAsync(scanRunId, ct);
        var eligible = runFindings.Where(f => !f.IsFalsePositive && Severities.Rank(f.Severity) >= Severities.Rank(minSeverity)).ToList();

        switch (destination.Trim().ToLowerInvariant())
        {
            case "internal":
            {
                var published = await findings.MarkPublishedAsync(eligible.Select(f => f.Id).ToList(), ct);
                return new PublishFindingsResult(published, runFindings.Count - published);
            }
            case "defectdojo":
            {
                var settings = await defectDojo.GetSettingsAsync(ct);
                if (settings is not { Enabled: true, IsConfigured: true })
                {
                    logger.LogWarning("PublishFinding to DefectDojo skipped for run {ScanRunId}: integration disabled or not configured", scanRunId);
                    return new PublishFindingsResult(0, runFindings.Count);
                }
                var result = await defectDojo.ExportAsync(settings, eligible, minSeverity, ct);
                // Failing the step lets the workflow retry; already exported findings are skipped on retry.
                if (result.Errors.Count > 0)
                    throw new DefectDojoApiException($"{result.Errors.Count} finding(s) failed to export: {string.Join("; ", result.Errors.Take(3))}");
                return new PublishFindingsResult(result.Exported, runFindings.Count - result.Exported);
            }
            default:
                throw new ArgumentException($"Unknown destination '{destination}'.", nameof(destination));
        }
    }
}
