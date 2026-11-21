using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WebScan.Contracts;
using WebScan.Server.Kernel.Messaging;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Kernel.Telemetry;
using WebScan.Server.Modules.Discovery.Domain;
using WebScan.Server.Modules.Discovery.Normalization;
using WebScan.Server.Modules.Discovery.Persistence;

namespace WebScan.Server.Modules.Discovery.Ingestion;

/// <summary>
/// Stores raw observations (append-only, deduplicated by (job id, observation id)) and updates live "last seen" state.
/// Idempotent per <see cref="ScanResultBatch.BatchId"/>.
/// </summary>
internal sealed class ObservationIngestor(DiscoveryDbContext db, TimeProvider time, ILogger<ObservationIngestor> logger) : IObservationSink
{
    public async Task IngestAsync(IngestContext context, ScanResultBatch batch, CancellationToken ct = default)
    {
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await DiscoveryLock.AcquireAsync(db, ct);
        if (await db.ProcessedBatches.AnyAsync(b => b.BatchId == batch.BatchId, ct))
        {
            logger.LogDebug("Batch {BatchId} already ingested", batch.BatchId);
            return;
        }

        var now = time.GetUtcNow();
        var candidates = new List<(DiscoveryObservation Raw, DiscoveryObservation Normalized)>();
        foreach (var raw in batch.Observations.DistinctBy(o => o.ObservationId))
        {
            var masked = Normalizer.Mask(raw);
            if (Normalizer.Normalize(masked) is { } normalized) candidates.Add((masked, normalized));
            else logger.LogWarning("Dropping observation {ObservationId} of job {JobId}: invalid address or port", raw.ObservationId, batch.JobId);
        }

        var ids = candidates.Select(c => c.Raw.ObservationId).ToList();
        var known = (await db.Observations.Where(o => o.JobId == batch.JobId && ids.Contains(o.ObservationId))
            .Select(o => o.ObservationId).ToListAsync(ct)).ToHashSet();
        var fresh = candidates.Where(c => !known.Contains(c.Raw.ObservationId)).OrderBy(c => c.Normalized.ObservedAt).ToList();

        foreach (var (raw, normalized) in fresh)
        {
            db.Observations.Add(new ObservationRecord
            {
                ScanRunId = context.ScanRunId, JobId = batch.JobId, BatchId = batch.BatchId, ObservationId = raw.ObservationId,
                AgentId = context.AgentId, InterfaceName = context.InterfaceName, Zone = context.Zone, WorkflowStepId = context.WorkflowStepId,
                Operation = context.Operation, Kind = normalized.Kind, Address = normalized.Address, Port = normalized.Port,
                Transport = normalized.Transport, ObservedAt = normalized.ObservedAt, ReceivedAt = now,
                Payload = JsonSerializer.Serialize(raw, ContractJson.Options),
            });
        }

        var updater = await AssetStateUpdater.LoadAsync(db, context.ScanRunId, context.Zone, fresh.Select(f => f.Normalized.Address), now, ct);
        foreach (var (_, normalized) in fresh) updater.Apply(normalized);

        db.ProcessedBatches.Add(new ProcessedBatch
        {
            BatchId = batch.BatchId, JobId = batch.JobId, ScanRunId = context.ScanRunId, Sequence = batch.Sequence,
            ObservationsReceived = batch.Observations.Count, ObservationsAccepted = fresh.Count, ProcessedAt = now,
        });
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        db.ChangeTracker.Clear();

        WebScanTelemetry.ObservationsIngested.Add(fresh.Count,
            new KeyValuePair<string, object?>("operation", context.Operation.ToString()),
            new KeyValuePair<string, object?>("agent", context.AgentId));
        logger.LogInformation("Ingested batch {BatchId} of run {ScanRunId}: {Accepted}/{Received} new observations",
            batch.BatchId, context.ScanRunId, fresh.Count, batch.Observations.Count);
    }
}

/// <summary>Wolverine handler (discovered by convention): Scanning → Discovery.</summary>
public static class ScanResultBatchReceivedHandler
{
    // The sink is resolved from a scope here because its implementation is internal: Wolverine's generated code
    // cannot construct it and its default ServiceLocationPolicy forbids container lookups.
    public static async Task Handle(ScanResultBatchReceived message, IServiceScopeFactory scopes, CancellationToken ct)
    {
        await using var scope = scopes.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<IObservationSink>().IngestAsync(message.Context, message.Batch, ct);
    }
}

internal static class DiscoveryLock
{
    private const string LockSql = "SELECT pg_advisory_xact_lock(5745425343)";

    /// <summary>
    /// Serializes ingestion and run processing (transaction-scoped advisory lock) so concurrent batches never race on
    /// creating the same host/service and comparisons see a consistent state.
    /// shortcut: one global lock caps ingestion at one batch at a time; shard the key per address range if that becomes a bottleneck.
    /// </summary>
    public static Task AcquireAsync(DiscoveryDbContext db, CancellationToken ct) =>
        db.Database.ExecuteSqlRawAsync(LockSql, ct);
}
