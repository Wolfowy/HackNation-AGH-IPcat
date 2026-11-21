using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WebScan.Contracts;
using WebScan.Server.Modules.Scanning.Persistence;

namespace WebScan.Server.Modules.Scanning.Planning;

public sealed class ScanLimitsStore(ScanningDbContext db, TimeProvider time)
{
    public async Task<ScanLimits> GetAsync(CancellationToken ct = default)
    {
        var row = await db.Limits.AsNoTracking().FirstOrDefaultAsync(x => x.Id == ScanLimitsRecord.SingletonId, ct);
        return row is null ? new ScanLimits() : JsonSerializer.Deserialize<ScanLimits>(row.ValuesJson, ContractJson.Options) ?? new ScanLimits();
    }

    public async Task SaveAsync(ScanLimits limits, CancellationToken ct = default)
    {
        var row = await db.Limits.FirstOrDefaultAsync(x => x.Id == ScanLimitsRecord.SingletonId, ct);
        var json = JsonSerializer.Serialize(limits, ContractJson.Options);
        if (row is null) db.Limits.Add(new ScanLimitsRecord { ValuesJson = json, UpdatedAt = time.GetUtcNow() });
        else { row.ValuesJson = json; row.UpdatedAt = time.GetUtcNow(); }
        await db.SaveChangesAsync(ct);
    }
}
