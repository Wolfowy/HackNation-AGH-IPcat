using Microsoft.EntityFrameworkCore;
using WebScan.Server.Kernel.Scanning;
using WebScan.Server.Modules.Scanning.Persistence;

namespace WebScan.Server.Modules.Scanning.Runs;

public sealed class ScanRunStatusReader(ScanningDbContext db) : IScanRunStatusReader, IRecentScanRunReader
{
    public async Task<IReadOnlyDictionary<Guid, string>> GetStatusesAsync(IReadOnlyCollection<Guid> scanRunIds, CancellationToken ct = default) =>
        await db.ScanRuns.AsNoTracking().Where(r => scanRunIds.Contains(r.Id))
            .ToDictionaryAsync(r => r.Id, r => r.Status.ToString(), ct);

    public async Task<IReadOnlyList<ScanRunSummary>> GetRecentAsync(int count, CancellationToken ct = default) =>
        (await db.ScanRuns.AsNoTracking().OrderByDescending(r => r.CreatedAt).Take(count).ToListAsync(ct))
        .Select(r => new ScanRunSummary(r.Id, r.Name, r.Status.ToString(), r.WorkflowKey, r.CreatedAt, r.StartedAt, r.FinishedAt, r.CoverageComplete))
        .ToList();
}

public sealed class RunBatchCatalog(ScanningDbContext db) : IRunBatchCatalog
{
    public async Task<IReadOnlyCollection<Guid>> GetAcceptedBatchIdsAsync(Guid scanRunId, CancellationToken ct = default) =>
        await db.ResultBatches.AsNoTracking().Where(b => b.ScanRunId == scanRunId).Select(b => b.BatchId).ToListAsync(ct);
}
