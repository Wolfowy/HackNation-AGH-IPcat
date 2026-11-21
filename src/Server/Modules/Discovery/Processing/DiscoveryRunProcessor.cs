using WebScan.Server.Kernel.Scanning;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Wolverine;
using WebScan.Contracts;
using WebScan.Server.Kernel.Discovery;
using WebScan.Server.Kernel.Messaging;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Modules.Discovery.Domain;
using WebScan.Server.Modules.Discovery.Ingestion;
using WebScan.Server.Modules.Discovery.Normalization;
using WebScan.Server.Modules.Discovery.Persistence;

namespace WebScan.Server.Modules.Discovery.Processing;

public sealed class DiscoveryOptions
{
    public const string Section = "Discovery";

    /// <summary>Persist waits until no batch of the run was ingested for this long (in-flight Wolverine messages); 0 = no wait.</summary>
    public double IngestSettleSeconds { get; set; } = 3;

    /// <summary>Upper bound for the settle wait.</summary>
    public double IngestMaxWaitSeconds { get; set; } = 30;

    /// <summary>Up/down transitions within the last 10 covering outcomes that flag a host as unstable.</summary>
    public int FlapTransitions { get; set; } = 4;

    /// <summary>Minimum observations of an endpoint path before time-of-day variance is evaluated.</summary>
    public int TimeOfDayMinObservations { get; set; } = 6;
}

/// <summary>PersistObservations + ComparePreviousScan.</summary>
internal sealed class DiscoveryRunProcessor(
    DiscoveryDbContext db,
    IInterpretationRuleProvider rules,
    IMessageBus bus,
    TimeProvider time,
    IOptions<DiscoveryOptions> options,
    ILogger<DiscoveryRunProcessor> logger,
    IRunBatchCatalog? batchCatalog = null) : IDiscoveryRunProcessor
{
    public async Task<PersistRunResult> PersistRunAsync(Guid scanRunId, RunCoverage coverage, CancellationToken ct = default)
    {
        await WaitForIngestionAsync(scanRunId, ct);
        var classificationRules = await rules.GetApprovedClassificationRulesAsync(ct);

        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await DiscoveryLock.AcquireAsync(db, ct);
        var now = time.GetUtcNow();

        var run = await db.Runs.FindAsync([scanRunId], ct);
        if (run is null) db.Runs.Add(run = new RunProcessing { ScanRunId = scanRunId });
        run.CoverageComplete = coverage.Complete;
        run.CoveredHosts = [.. coverage.CoveredHosts];
        run.CoveredEndpoints = [.. coverage.CoveredEndpoints];
        run.OperationsExecuted = coverage.OperationsExecuted.Select(o => o.ToString()).ToList();
        run.PersistedAt = now;

        if (classificationRules.Count > 0) await ApplyClassificationRulesAsync(scanRunId, classificationRules, now, ct);

        var coverageSet = CoverageSet.From(run);
        var seenAddresses = (await db.Observations.Where(o => o.ScanRunId == scanRunId).Select(o => o.Address).Distinct().ToListAsync(ct)).ToHashSet();
        // shortcut: coverage containment tested in memory over all hosts (see ChangeDetector).
        var scanned = (await db.Hosts.ToListAsync(ct)).Where(h => seenAddresses.Contains(h.Address) || coverageSet.CoversHost(h.Address)).ToList();
        foreach (var host in scanned) host.LastScannedAt = now;

        var services = await db.Services.CountAsync(s => s.LastSeenRunId == scanRunId, ct);
        var observations = await db.Observations.CountAsync(o => o.ScanRunId == scanRunId, ct);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        db.ChangeTracker.Clear();

        logger.LogInformation("Persisted run {ScanRunId}: {Hosts} hosts, {Services} services, {Observations} observations, {Rules} classification rules",
            scanRunId, scanned.Count, services, observations, classificationRules.Count);
        return new PersistRunResult(scanned.Count, services, observations);
    }

    public async Task<CompareRunResult> CompareWithPreviousAsync(Guid scanRunId, int missingThreshold, CancellationToken ct = default)
    {
        if (missingThreshold < 1) throw new ArgumentOutOfRangeException(nameof(missingThreshold), "Must be at least 1.");
        var changeRules = await rules.GetApprovedChangeRulesAsync(ct);

        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await DiscoveryLock.AcquireAsync(db, ct);
        var run = await db.Runs.FindAsync([scanRunId], ct);
        if (run?.ComparedAt is not null)
        {
            // Retried step: misses were already counted for this run.
            var previous = JsonSerializer.Deserialize<Dictionary<string, int>>(run.ChangesByType ?? "{}") ?? [];
            return new CompareRunResult(run.ChangesDetected ?? 0, previous);
        }
        if (run is null)
        {
            logger.LogWarning("Run {ScanRunId} compared without PersistObservations: no coverage, nothing will be counted as missing", scanRunId);
            db.Runs.Add(run = new RunProcessing { ScanRunId = scanRunId });
        }

        var now = time.GetUtcNow();
        var coverage = run.PersistedAt is null ? CoverageSet.None : CoverageSet.From(run);
        var changes = await new ChangeDetector(db, scanRunId, coverage, missingThreshold, options.Value, now).DetectAsync(ct);
        foreach (var change in changes) ApplyChangeRules(change, changeRules);

        var byType = changes.GroupBy(c => c.Event.Type.ToString()).ToDictionary(g => g.Key, g => g.Count());
        db.Changes.AddRange(changes.Select(c => c.Event));
        run.ComparedAt = now;
        run.ChangesDetected = changes.Count;
        run.ChangesByType = JsonSerializer.Serialize(byType);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        db.ChangeTracker.Clear();

        if (changes.Count > 0) await bus.PublishAsync(new AssetChangesDetected(scanRunId, changes.Count));
        logger.LogInformation("Compared run {ScanRunId}: {Count} changes", scanRunId, changes.Count);
        return new CompareRunResult(changes.Count, byType);
    }

    private static void ApplyChangeRules(DetectedChange change, IReadOnlyList<ChangeRule> changeRules)
    {
        foreach (var rule in changeRules.Where(r => r.ChangeTypes.Contains(change.Event.Type)))
        {
            if (rule.When is not null && !ConditionEvaluator.Evaluate(rule.When, f => change.Fields.GetValueOrDefault(f))) continue;
            if (Severities.Rank(rule.Severity) > Severities.Rank(change.Event.Severity)) change.Event.Severity = rule.Severity;
            change.Event.RaisedBy.Add($"{rule.SignatureId}@v{rule.Version}");
        }
    }

    /// <summary>Evaluates approved classification rules over every observation of the run (streamed).</summary>
    private async Task ApplyClassificationRulesAsync(Guid scanRunId, IReadOnlyList<ClassificationRule> classificationRules, DateTimeOffset now,
        CancellationToken ct)
    {
        var matches = new Dictionary<(string, int?, string), (ClassificationRule Rule, DiscoveryObservation Observation)>();
        var payloads = db.Observations.AsNoTracking().Where(o => o.ScanRunId == scanRunId).OrderBy(o => o.Id).Select(o => o.Payload).AsAsyncEnumerable();
        await foreach (var payload in payloads.WithCancellation(ct))
        {
            if (JsonSerializer.Deserialize<DiscoveryObservation>(payload, ContractJson.Options) is not { } raw || Normalizer.Normalize(raw) is not { } o) continue;
            foreach (var rule in classificationRules.Where(r => ConditionEvaluator.Evaluate(r.When, o)))
                matches[(o.Address, o.Port, rule.SignatureId)] = (rule, o);
        }
        if (matches.Count == 0) return;

        var updater = await AssetStateUpdater.LoadAsync(db, scanRunId, null, matches.Keys.Select(k => k.Item1), now, ct);
        foreach (var (rule, o) in matches.Values) updater.ApplyClassification(rule, o, Evidence(rule, o));
    }

    /// <summary>"field=value" pairs of the fields the rule tested, e.g. "http.title=Admin Login".</summary>
    private static string Evidence(ClassificationRule rule, DiscoveryObservation o)
    {
        var pairs = ConditionEvaluator.ReferencedFields(rule.When)
            .Select(f => (Field: f, Value: ConditionEvaluator.GetField(o, f)))
            .Where(p => !string.IsNullOrEmpty(p.Value))
            .Select(p => $"{p.Field}={p.Value}");
        var text = $"{o.Kind} {o.Address}{(o.Port is { } port ? $":{port}" : "")} via {o.Source.ToolId}: {string.Join("; ", pairs)}";
        return text.Length > 2048 ? text[..2048] : text;
    }

    private async Task WaitForIngestionAsync(Guid scanRunId, CancellationToken ct)
    {
        var deadline = time.GetUtcNow() + TimeSpan.FromSeconds(options.Value.IngestMaxWaitSeconds);
        if (batchCatalog is not null)
        {
            // Exact: every batch Scanning accepted for this run must be ingested (messages may still be in flight).
            var accepted = (await batchCatalog.GetAcceptedBatchIdsAsync(scanRunId, ct)).ToHashSet();
            while (accepted.Count > 0)
            {
                var processed = await db.ProcessedBatches.AsNoTracking().Where(b => b.ScanRunId == scanRunId).Select(b => b.BatchId).ToListAsync(ct);
                accepted.ExceptWith(processed);
                if (accepted.Count == 0) return;
                if (time.GetUtcNow() >= deadline)
                {
                    logger.LogWarning("Run {RunId}: {Count} accepted result batches not ingested after {Seconds}s; persisting what is available.",
                        scanRunId, accepted.Count, options.Value.IngestMaxWaitSeconds);
                    return;
                }
                await Task.Delay(TimeSpan.FromMilliseconds(250), time, ct);
            }
            return;
        }

        // Fallback without a catalog (module tests): wait for a quiet period.
        var settle = TimeSpan.FromSeconds(options.Value.IngestSettleSeconds);
        if (settle <= TimeSpan.Zero) return;
        while (true)
        {
            var last = await db.ProcessedBatches.Where(b => b.ScanRunId == scanRunId).MaxAsync(b => (DateTimeOffset?)b.ProcessedAt, ct);
            var now = time.GetUtcNow();
            if (last is null || now - last >= settle || now >= deadline) return;
            await Task.Delay(TimeSpan.FromMilliseconds(250), time, ct);
        }
    }
}
