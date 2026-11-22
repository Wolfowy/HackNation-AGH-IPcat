using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WebScan.Contracts;
using WebScan.Server.Kernel.Messaging;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Kernel.Telemetry;
using WebScan.Server.Modules.Scanning.Events;
using WebScan.Server.Modules.Scanning.Persistence;
using WebScan.Server.Modules.Scanning.Runs;
using WebScan.Server.Modules.Workflows.Conditions;
using WebScan.Server.Modules.Workflows.Execution;
using WebScan.Server.Modules.Workflows.Persistence;
using Wolverine.Attributes;

namespace WebScan.Server.Modules.Workflows.Runtime;

/// <summary>Workflow engine abstraction (own DAG implementation today; Elsa 3 could implement it by hosting the step executors).</summary>
public interface IWorkflowRuntime
{
    /// <summary>Creates the workflow run for a scan run and starts its root steps.</summary>
    Task StartAsync(Guid scanRunId, CancellationToken ct = default);

    Task CancelAsync(Guid scanRunId, string reason, CancellationToken ct = default);

    /// <summary>A job of the run reached a terminal state: advance the DAG.</summary>
    Task SignalJobFinishedAsync(Guid scanRunId, CancellationToken ct = default);

    /// <summary>Periodic advancement of all active runs (window expiry, retry backoff, missed signals).</summary>
    Task TickAsync(CancellationToken ct = default);
}

public sealed class WorkflowOptions
{
    public const string Section = "Workflows";
    public bool TickerEnabled { get; set; } = true;
    public int TickIntervalSeconds { get; set; } = 5;
}

/// <summary>
/// DB-backed DAG runtime. Each advancement of a run holds a PostgreSQL advisory lock for that run, so the
/// <see cref="ScanJobFinished"/> handler, the ticker and API calls never advance the same run concurrently.
/// </summary>
public sealed class WorkflowRuntime(
    WorkflowsDbContext db, ScanRunStore runs, IEnumerable<IStepExecutor> executors, IScanEventPublisher events,
    IServiceScopeFactory scopes, TimeProvider time, ILogger<WorkflowRuntime> logger) : IWorkflowRuntime
{
    private const int LockNamespace = 0x57464C57; // "WFLW"

    public Task StartAsync(Guid scanRunId, CancellationToken ct = default) => AdvanceAsync(scanRunId, ct);

    public Task SignalJobFinishedAsync(Guid scanRunId, CancellationToken ct = default) => AdvanceAsync(scanRunId, ct);

    public async Task TickAsync(CancellationToken ct = default)
    {
        foreach (var runId in await runs.ActiveRunIdsAsync(ct))
        {
            // Fresh scope per run: outbox transitions must not share a scope (see JobQueue).
            await using var scope = scopes.CreateAsyncScope();
            try { await scope.ServiceProvider.GetRequiredService<IWorkflowRuntime>().SignalJobFinishedAsync(runId, ct); }
            catch (Exception ex) when (ex is not OperationCanceledException) { logger.LogError(ex, "Advancing run {RunId} failed", runId); }
        }
    }

    public Task CancelAsync(Guid scanRunId, string reason, CancellationToken ct = default) =>
        WithRunLockAsync(scanRunId, wait: true, async () =>
        {
            var run = await runs.GetAsync(scanRunId, ct);
            if (run is null || run.Status.IsTerminal()) return;
            var wf = await db.Runs.FirstOrDefaultAsync(w => w.ScanRunId == scanRunId, ct);
            if (wf is not null)
            {
                wf.CancelRequested = true;
                foreach (var state in await db.StepRuns.Where(s => s.WorkflowRunId == wf.Id).ToListAsync(ct))
                    if (!state.IsTerminal) await FinishStepAsync(run, wf, state, StepStatus.Cancelled, $"Run cancelled: {reason}", ct);
                await db.SaveChangesAsync(ct);
            }
            await runs.CancelJobsAsync(scanRunId, $"Run cancelled: {reason}", ct: ct);
            await runs.FinishAsync(scanRunId, ScanRunStatus.Cancelled, false, $"Cancelled: {reason}", ct);
        }, ct);

    public Task AdvanceAsync(Guid scanRunId, CancellationToken ct = default) =>
        WithRunLockAsync(scanRunId, wait: false, () => AdvanceLockedAsync(scanRunId, ct), ct);

    private async Task AdvanceLockedAsync(Guid runId, CancellationToken ct)
    {
        var run = await runs.GetAsync(runId, ct);
        if (run is null || run.Status.IsTerminal()) return;
        var wf = await db.Runs.FirstOrDefaultAsync(w => w.ScanRunId == runId, ct) ?? await CreateWorkflowRunAsync(run, ct);
        if (wf is null || wf.CancelRequested) return;

        var definition = JsonSerializer.Deserialize<ScanWorkflowDefinition>(wf.DefinitionJson, ContractJson.Options)!;
        var stepById = definition.Steps.ToDictionary(s => s.Id, StringComparer.Ordinal);
        var states = await db.StepRuns.Where(s => s.WorkflowRunId == wf.Id).ToDictionaryAsync(s => s.StepId, StringComparer.Ordinal, ct);
        await runs.MarkRunningAsync(runId, wf.Id, ct);

        if (!wf.WindowExpired && run.NotAfter <= time.GetUtcNow())
        {
            wf.WindowExpired = true;
            await db.SaveChangesAsync(ct);
            await runs.CancelJobsAsync(runId, "Scan window expired", ct: ct);
        }

        for (var progressed = true; progressed;)
        {
            progressed = false;
            var now = time.GetUtcNow();
            var counts = await runs.StepJobCountsAsync(runId, ct);
            foreach (var state in states.Values.Where(s => s.Status == StepStatus.Running).ToList())
            {
                if (OperationCatalog.Get(state.Operation).Plane == OperationPlane.Server)
                {
                    state.Status = StepStatus.Pending; // interrupted by a crash: server executors are idempotent, run again
                    progressed = true;
                    continue;
                }
                var c = counts.GetValueOrDefault(state.StepId, StepJobCounts.None);
                if (c.Active > 0 && !wf.WindowExpired) continue;
                if (wf.WindowExpired && c.Completed < c.Total) await FinishStepAsync(run, wf, state, StepStatus.Cancelled, "Scan window expired", ct);
                else if (!wf.WindowExpired && NextRecheckRoundDelay(stepById[state.StepId], state.Attempt) is { } delay)
                {
                    state.Status = StepStatus.Pending; // next RecheckMissing round: it probes only what is still missing
                    state.NextAttemptAt = now.Add(delay);
                    await db.SaveChangesAsync(ct);
                }
                else await FinishAgentStepAsync(run, wf, state, c, ct);
                progressed = true;
            }

            var status = states.ToDictionary(s => s.Key, s => s.Value.Status, StringComparer.Ordinal);
            if (!wf.WindowExpired && DagScheduler.FatalFailure(definition, status) is { } fatal)
            {
                await FailRunAsync(run, wf, states.Values, $"Step '{fatal.Id}' failed: {states[fatal.Id].Message}", ct);
                return;
            }

            // After window expiry only PersistObservations still runs (partial results, incomplete coverage).
            var ready = wf.WindowExpired
                ? definition.Steps.Where(s => status[s.Id] == StepStatus.Pending).ToList()
                : DagScheduler.ReadySteps(definition, status);
            foreach (var step in ready)
            {
                var state = states[step.Id];
                if (state.NextAttemptAt > now) continue;
                if (wf.WindowExpired && step.Operation != ScanOperation.PersistObservations)
                {
                    await FinishStepAsync(run, wf, state, StepStatus.Cancelled, "Scan window expired", ct);
                    progressed = true;
                    continue;
                }
                if (wf.WindowExpired && await runs.LeasedJobCountAsync(runId, ct) > 0) continue; // agents are still flushing partial results
                await ExecuteStepAsync(run, wf, definition, stepById[step.Id], state, ct);
                progressed = true;
            }
        }

        if (states.Values.All(s => s.IsTerminal)) await CompleteRunAsync(run, wf, states.Values, ct);
    }

    private async Task ExecuteStepAsync(ScanRun run, WorkflowRun wf, ScanWorkflowDefinition definition, WorkflowStep step, WorkflowStepRun state, CancellationToken ct)
    {
        var first = state.Attempt == 0;
        state.Attempt++;
        state.Status = StepStatus.Running;
        state.StartedAt ??= time.GetUtcNow();
        state.NextAttemptAt = null;
        await db.SaveChangesAsync(ct);
        if (first) await events.PublishAsync(time, ScanExecutionEventType.StepStarted, run.Id, $"{step.Operation} started", wf.Id, step.Id, ct: ct);

        IReadOnlyList<DiscoveryObservation> input = [];
        if (step.Input is not null)
        {
            input = await new InputResolver(runs, run.Id, definition).ResolveAsync(step.Input, ct);
            if (step.When is not null && !input.Any(o => ConditionEvaluator.Evaluate(step.When, o)))
            {
                await FinishStepAsync(run, wf, state, StepStatus.Skipped, "Condition 'when' is not satisfied by any input observation", ct);
                return;
            }
        }

        var defaults = definition.Defaults ?? new WorkflowDefaults();
        var timeout = TimeSpan.FromSeconds(step.TimeoutSeconds ?? defaults.TimeoutSeconds);
        var executor = executors.FirstOrDefault(e => e.CanExecute(step.Operation));
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        if (OperationCatalog.Get(step.Operation).Plane == OperationPlane.Server) cts.CancelAfter(timeout); // agent jobs carry their own timeout
        StepOutcome outcome;
        try
        {
            outcome = executor is null
                ? StepOutcome.Failed($"No executor registered for {step.Operation}.")
                : await executor.ExecuteAsync(new StepExecutionContext(run, wf.Id, definition, step, state.Attempt, input, wf.WindowExpired), cts.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            outcome = StepOutcome.Failed($"Timed out after {timeout.TotalSeconds:0}s.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Step {StepId} of run {RunId} threw", step.Id, run.Id);
            outcome = StepOutcome.Failed(ex.Message);
        }

        switch (outcome.Kind)
        {
            case StepOutcomeKind.WaitingForJobs:
                state.Message = outcome.Message;
                await db.SaveChangesAsync(ct);
                break;
            case StepOutcomeKind.Completed:
                await FinishStepAsync(run, wf, state, StepStatus.Completed, outcome.Message, ct);
                break;
            case StepOutcomeKind.Skipped:
                await FinishStepAsync(run, wf, state, StepStatus.Skipped, outcome.Message, ct);
                break;
            default:
                var retry = step.Retry ?? defaults.Retry ?? new RetryPolicy();
                if (state.Attempt < retry.MaxAttempts)
                {
                    state.Status = StepStatus.Pending;
                    state.NextAttemptAt = time.GetUtcNow().AddSeconds(Math.Min(3600, retry.BackoffSeconds * Math.Pow(2, state.Attempt - 1)));
                    state.Message = $"Attempt {state.Attempt}/{retry.MaxAttempts} failed: {outcome.Message}";
                    await db.SaveChangesAsync(ct);
                    await events.PublishAsync(time, ScanExecutionEventType.StepFailed, run.Id, $"{state.Message}; retry at {state.NextAttemptAt:O}", wf.Id, step.Id,
                        data: new Dictionary<string, string> { ["retry"] = "true" }, ct: ct);
                }
                else await FinishStepAsync(run, wf, state, StepStatus.Failed, outcome.Message, ct);
                break;
        }
    }

    /// <summary>Delay before the next round of a RecheckMissing step whose jobs finished; null when its last round ran.</summary>
    internal static TimeSpan? NextRecheckRoundDelay(WorkflowStep step, int attempt)
    {
        if (step.Operation != ScanOperation.RecheckMissing) return null;
        var values = ParameterValidator.Validate(OperationCatalog.Get(step.Operation).Parameters, step.Parameters).Values;
        return attempt < int.Parse(values["attempts"], CultureInfo.InvariantCulture)
            ? TimeSpan.FromSeconds(int.Parse(values["delaySeconds"], CultureInfo.InvariantCulture))
            : null;
    }

    private Task FinishAgentStepAsync(ScanRun run, WorkflowRun wf, WorkflowStepRun state, StepJobCounts c, CancellationToken ct)
    {
        if (c.Completed == c.Total) return FinishStepAsync(run, wf, state, StepStatus.Completed, $"{c.Completed} jobs completed", ct);
        if (c.Completed == 0) return FinishStepAsync(run, wf, state, StepStatus.Failed, $"No job completed ({c.Failed} failed, {c.Cancelled} cancelled)", ct);
        state.HasFailures = true;
        return FinishStepAsync(run, wf, state, StepStatus.Completed, $"{c.Completed}/{c.Total} jobs completed ({c.Failed} failed, {c.Cancelled} cancelled)", ct);
    }

    private async Task FinishStepAsync(ScanRun run, WorkflowRun wf, WorkflowStepRun state, StepStatus status, string? message, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        state.Status = status;
        state.FinishedAt = now;
        state.NextAttemptAt = null;
        state.Message = message;
        await db.SaveChangesAsync(ct);
        if (state.StartedAt is { } started)
            WebScanTelemetry.WorkflowStepDuration.Record((now - started).TotalSeconds,
                new KeyValuePair<string, object?>("operation", state.Operation.ToString()), new KeyValuePair<string, object?>("status", status.ToString()));
        var type = status switch
        {
            StepStatus.Completed => ScanExecutionEventType.StepCompleted,
            StepStatus.Skipped => ScanExecutionEventType.StepSkipped,
            _ => ScanExecutionEventType.StepFailed,
        };
        await events.PublishAsync(time, type, run.Id, message, wf.Id, state.StepId,
            data: new Dictionary<string, string> { ["status"] = status.ToString() }, ct: ct);
    }

    private async Task FailRunAsync(ScanRun run, WorkflowRun wf, IEnumerable<WorkflowStepRun> states, string message, CancellationToken ct)
    {
        await runs.CancelJobsAsync(run.Id, "Workflow failed", ct: ct);
        foreach (var state in states.Where(s => !s.IsTerminal).ToList())
            await FinishStepAsync(run, wf, state, StepStatus.Cancelled, "Workflow failed", ct);
        await runs.FinishAsync(run.Id, ScanRunStatus.Failed, false, message, ct);
    }

    private async Task CompleteRunAsync(ScanRun run, WorkflowRun wf, IEnumerable<WorkflowStepRun> states, CancellationToken ct)
    {
        if (wf.WindowExpired)
        {
            await runs.FinishAsync(run.Id, ScanRunStatus.WindowExpired, false, "Scan window expired; partial results kept, coverage incomplete", ct);
            return;
        }
        var problems = states.Where(s => s.Status is StepStatus.Failed or StepStatus.Cancelled || s.HasFailures).Select(s => s.StepId).ToList();
        var partial = problems.Count > 0 || await runs.HasFailedJobsAsync(run.Id, ct);
        await runs.FinishAsync(run.Id, partial ? ScanRunStatus.PartiallyCompleted : ScanRunStatus.Completed, !partial,
            partial ? $"Finished with failures{(problems.Count > 0 ? " in " + string.Join(", ", problems) : "")}" : "All steps finished", ct);
    }

    private async Task<WorkflowRun?> CreateWorkflowRunAsync(ScanRun run, CancellationToken ct)
    {
        var definition = await db.Definitions.AsNoTracking().FirstOrDefaultAsync(d => d.Key == run.WorkflowKey && d.Version == run.WorkflowVersion, ct);
        if (definition is null)
        {
            await runs.FinishAsync(run.Id, ScanRunStatus.Failed, false, $"Workflow '{run.WorkflowKey}' version {run.WorkflowVersion} not found", ct);
            return null;
        }
        var wf = new WorkflowRun
        {
            Id = Guid.NewGuid(), ScanRunId = run.Id, WorkflowKey = definition.Key, WorkflowVersion = definition.Version,
            DefinitionJson = definition.DefinitionJson, CreatedAt = time.GetUtcNow(),
        };
        db.Runs.Add(wf);
        foreach (var step in JsonSerializer.Deserialize<ScanWorkflowDefinition>(definition.DefinitionJson, ContractJson.Options)!.Steps)
            db.StepRuns.Add(new WorkflowStepRun { WorkflowRunId = wf.Id, StepId = step.Id, Operation = step.Operation, Status = StepStatus.Pending });
        await db.SaveChangesAsync(ct);
        return wf;
    }

    /// <summary>Runs <paramref name="action"/> under the run's advisory lock. Without <paramref name="wait"/> a busy lock means "someone else advances".</summary>
    private async Task WithRunLockAsync(Guid runId, bool wait, Func<Task> action, CancellationToken ct)
    {
        var key = runId.GetHashCode();
        await db.Database.OpenConnectionAsync(ct);
        try
        {
            var held = await TryLockAsync(key, ct);
            for (var waited = Stopwatch.StartNew(); !held && wait && waited.Elapsed < TimeSpan.FromSeconds(30); held = await TryLockAsync(key, ct))
                await Task.Delay(200, ct);
            if (!held && !wait) return;
            if (!held) logger.LogWarning("Run {RunId}: lock not acquired within 30s, proceeding", runId);
            try { await action(); }
            finally
            {
                if (held) await db.Database.ExecuteSqlAsync($"SELECT pg_advisory_unlock({LockNamespace}, {key})", CancellationToken.None);
            }
        }
        finally
        {
            await db.Database.CloseConnectionAsync();
        }
    }

    private async Task<bool> TryLockAsync(int key, CancellationToken ct) =>
        await db.Database.SqlQuery<bool>($"SELECT pg_try_advisory_lock({LockNamespace}, {key}) AS \"Value\"").SingleAsync(ct);
}

/// <summary>Step input: union of <c>FromSteps</c> outputs (EvaluateCondition outputs are its filtered input), then <c>Filter</c>.</summary>
internal sealed class InputResolver(ScanRunStore runs, Guid runId, ScanWorkflowDefinition definition)
{
    private readonly Dictionary<string, IReadOnlyList<DiscoveryObservation>> _outputs = new(StringComparer.Ordinal);

    public async Task<IReadOnlyList<DiscoveryObservation>> ResolveAsync(StepInput input, CancellationToken ct)
    {
        var all = new List<DiscoveryObservation>();
        foreach (var from in input.FromSteps) all.AddRange(await OutputAsync(from, ct));
        var distinct = all.DistinctBy(o => o.ObservationId);
        return (input.Filter is null ? distinct : distinct.Where(o => ConditionEvaluator.Evaluate(input.Filter, o))).ToList();
    }

    private async Task<IReadOnlyList<DiscoveryObservation>> OutputAsync(string stepId, CancellationToken ct)
    {
        if (_outputs.TryGetValue(stepId, out var cached)) return cached;
        var step = definition.Steps.First(s => s.Id == stepId);
        IReadOnlyList<DiscoveryObservation> output = [];
        if (step.Operation == ScanOperation.EvaluateCondition && step.Input is not null)
        {
            var input = await ResolveAsync(step.Input, ct);
            output = step.When is null ? input : input.Where(o => ConditionEvaluator.Evaluate(step.When, o)).ToList();
        }
        else if (OperationCatalog.Get(step.Operation).Plane == OperationPlane.Agent)
        {
            output = await runs.ObservationsAsync(runId, [stepId], ct);
        }
        return _outputs[stepId] = output;
    }
}

public sealed class WorkflowTickerService(IServiceScopeFactory scopes, IOptions<WorkflowOptions> options, ILogger<WorkflowTickerService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Value.TickerEnabled) return;
        var interval = TimeSpan.FromSeconds(Math.Max(1, options.Value.TickIntervalSeconds));
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var scope = scopes.CreateAsyncScope();
                await scope.ServiceProvider.GetRequiredService<IWorkflowRuntime>().TickAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { logger.LogError(ex, "Workflow tick failed"); }
            try { await Task.Delay(interval, stoppingToken); } catch (OperationCanceledException) { break; }
        }
    }
}

/// <summary>
/// Wolverine handler: job finished → advance its workflow. The runtime manages its own transactions and locks; it is
/// resolved from a scope because Wolverine's code generation forbids service location in handler dependency graphs.
/// </summary>
public static class ScanJobFinishedHandler
{
    [NonTransactional]
    public static async Task Handle(ScanJobFinished message, IServiceScopeFactory scopes, CancellationToken ct)
    {
        await using var scope = scopes.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<IWorkflowRuntime>().SignalJobFinishedAsync(message.ScanRunId, ct);
    }
}
