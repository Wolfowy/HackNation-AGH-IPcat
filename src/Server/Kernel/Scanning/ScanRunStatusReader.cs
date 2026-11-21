namespace WebScan.Server.Kernel.Scanning;

/// <summary>
/// Read access to scan run status for other modules (e.g. the Scheduling overlap policy). Implemented by the Scanning module.
/// Status names: Pending, Running, Completed, PartiallyCompleted, Failed, Cancelled, WindowExpired.
/// </summary>
public interface IScanRunStatusReader
{
    /// <summary>Status per run id; unknown ids are absent from the result.</summary>
    Task<IReadOnlyDictionary<Guid, string>> GetStatusesAsync(IReadOnlyCollection<Guid> scanRunIds, CancellationToken ct = default);
}

public static class ScanRunStatusNames
{
    public static bool IsActive(string? status) => status is "Pending" or "Running";
}

/// <summary>
/// Result batches the Scanning module has accepted for a run. Lets Discovery wait until exactly these batches are
/// ingested before finalizing a run (instead of guessing with a quiet period). Implemented by the Scanning module.
/// </summary>
public interface IRunBatchCatalog
{
    Task<IReadOnlyCollection<Guid>> GetAcceptedBatchIdsAsync(Guid scanRunId, CancellationToken ct = default);
}
