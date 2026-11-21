using WebScan.Agent.Storage;
using WebScan.Agent.Tools.Abstractions;
using WebScan.Contracts;

namespace WebScan.Agent.Execution;

/// <summary>Wakes a waiter without losing a signal that arrives before the wait starts.</summary>
public sealed class AsyncSignal
{
    private readonly SemaphoreSlim _semaphore = new(0, 1);

    public void Set()
    {
        try { _semaphore.Release(); } catch (SemaphoreFullException) { }
    }

    public Task<bool> WaitAsync(TimeSpan timeout, CancellationToken ct) => _semaphore.WaitAsync(timeout, ct);
}

/// <summary>
/// Collects a job's observations into result batches (≤ max observations or every flush interval) and writes each batch to the
/// local buffer before it is uploaded. Tracks covered targets for <see cref="JobCoverage"/> and progress.
/// </summary>
public sealed class ResultBatcher : IObservationWriter, IAsyncDisposable
{
    private readonly ScanJob _job;
    private readonly Guid _leaseId;
    private readonly ResultBuffer _buffer;
    private readonly Action _onBatchStored;
    private readonly int _maxObservations;
    private readonly TimeProvider _time;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private readonly List<DiscoveryObservation> _pending = [];
    private readonly HashSet<string> _covered = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _targets;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _flushLoop;
    private int _sequence;
    private int _done;

    public ResultBatcher(ScanJob job, Guid leaseId, ResultBuffer buffer, Action onBatchStored, int maxObservations, TimeSpan flushInterval, TimeProvider time)
    {
        _job = job;
        _leaseId = leaseId;
        _buffer = buffer;
        _onBatchStored = onBatchStored;
        _maxObservations = Math.Clamp(maxObservations, 1, ScanResultBatch.MaxObservations);
        _time = time;
        _targets = Targets.CoverageKeys(job.Targets).ToHashSet(StringComparer.OrdinalIgnoreCase);
        _flushLoop = FlushPeriodicallyAsync(flushInterval);
    }

    public int TotalBatches => _sequence;
    public long ObservationCount { get; private set; }

    /// <summary>False once the buffer refused a batch (job dropped because its lease is stale).</summary>
    public bool Accepted { get; private set; } = true;

    public async ValueTask WriteAsync(DiscoveryObservation observation, CancellationToken cancellationToken)
    {
        await _lock.WaitAsync(CancellationToken.None);
        try
        {
            _pending.Add(observation);
            ObservationCount++;
            if (observation.Port is { } port) Cover(Targets.EndpointKey(observation.Address, port));
            Cover(observation.Address);
            if (observation.Hostname is { } name) Cover(name);
            if (_pending.Count >= _maxObservations) FlushLocked();
        }
        finally { _lock.Release(); }
    }

    /// <summary>Thread-safe snapshot (counts only); 100% is reported by the completion call, not by progress.</summary>
    public JobProgress Progress(string? message = null)
    {
        var done = Volatile.Read(ref _done);
        return new JobProgress
        {
            TargetsTotal = _targets.Count, TargetsCompleted = done,
            Percent = Math.Round(Math.Min(99.0, 100.0 * done / Math.Max(_targets.Count, 1)), 1), Message = message,
        };
    }

    private void Cover(string key)
    {
        if (_covered.Add(key) && _targets.Contains(key)) Interlocked.Increment(ref _done);
    }

    /// <summary>Targets without any observation (host addresses, hostnames/large CIDRs as given, or "addr:port").</summary>
    public IReadOnlyList<string> UncoveredTargets() => [.. _targets.Where(t => !_covered.Contains(t)).Order(StringComparer.Ordinal)];

    /// <summary>Stops the periodic flush and writes the remaining observations.</summary>
    public async Task CompleteAsync()
    {
        await _stop.CancelAsync();
        await _flushLoop;
        await _lock.WaitAsync();
        try { FlushLocked(); }
        finally { _lock.Release(); }
    }

    private async Task FlushPeriodicallyAsync(TimeSpan interval)
    {
        try
        {
            while (true)
            {
                await Task.Delay(interval, _time, _stop.Token);
                await _lock.WaitAsync(_stop.Token);
                try { FlushLocked(); }
                finally { _lock.Release(); }
            }
        }
        catch (OperationCanceledException) { }
    }

    private void FlushLocked()
    {
        if (_pending.Count == 0 || !Accepted) { _pending.Clear(); return; }
        var batch = new ScanResultBatch
        {
            BatchId = Guid.NewGuid(),
            JobId = _job.JobId,
            LeaseId = _leaseId,
            Sequence = _sequence,
            CreatedAt = _time.GetUtcNow(),
            Observations = [.. _pending],
            Progress = Progress(),
        };
        _pending.Clear();
        if (!_buffer.AddBatch(batch)) { Accepted = false; return; }
        _sequence++;
        _onBatchStored();
    }

    public async ValueTask DisposeAsync()
    {
        if (!_stop.IsCancellationRequested) await _stop.CancelAsync();
        await _flushLoop;
        _stop.Dispose();
    }
}
