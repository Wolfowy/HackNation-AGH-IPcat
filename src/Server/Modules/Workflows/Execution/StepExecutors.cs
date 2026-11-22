using System.Globalization;
using Microsoft.Extensions.DependencyInjection;
using WebScan.Contracts;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Modules.Scanning.Planning;
using WebScan.Server.Modules.Scanning.Runs;

namespace WebScan.Server.Modules.Workflows.Execution;

/// <summary>Agent-plane operations: turns the step input (or the run scope) into queued jobs via the planner.</summary>
public sealed class AgentStepExecutor(TaskPlanner planner, IServiceProvider services) : IStepExecutor
{
    public bool CanExecute(ScanOperation operation) => OperationCatalog.Get(operation).Plane == OperationPlane.Agent;

    public async Task<StepOutcome> ExecuteAsync(StepExecutionContext context, CancellationToken ct)
    {
        var step = context.Step;
        var descriptor = OperationCatalog.Get(step.Operation);
        var parameters = ParameterValidator.Validate(descriptor.Parameters, step.Parameters);
        if (!parameters.IsValid) return StepOutcome.Failed(string.Join(" ", parameters.Errors));

        SignatureBundle? signatures = null;
        if (step.Operation == ScanOperation.ExecuteSignatures)
        {
            var catalog = services.GetService<ISignatureCatalog>();
            if (catalog is null) return StepOutcome.Failed("ISignatureCatalog is not registered (Signatures module missing); cannot execute signatures.");
            IReadOnlyCollection<string> List(string name) => parameters.Values.TryGetValue(name, out var v) ? ParameterValidator.SplitList(v) : [];
            signatures = await catalog.GetApprovedBundleAsync(List("signatureIds"), List("signatureTags"), List("severities"), ct);
            if (signatures.Items.Count == 0) return StepOutcome.Skipped("No approved signatures match the step filter.");
        }

        IReadOnlyCollection<string>? hosts = null;
        IReadOnlyCollection<ScanEndpoint>? endpoints = null;
        if (step.Input is not null)
        {
            if (descriptor.InputKind == TargetKind.Endpoints) endpoints = StepInputs.Endpoints(context.Input);
            else hosts = StepInputs.Hosts(context.Input);
            if ((endpoints?.Count ?? hosts!.Count) == 0) return StepOutcome.Skipped("No targets from the input steps.");
        }
        else if (descriptor.InputKind == TargetKind.Endpoints)
        {
            return StepOutcome.Failed($"{step.Operation} needs endpoints from input.fromSteps.");
        }

        var defaults = context.Definition.Defaults ?? new WorkflowDefaults();
        var retry = step.Retry ?? defaults.Retry ?? new RetryPolicy();
        PlanResult plan;
        try
        {
            plan = await planner.PlanAsync(new AgentStepSpec
            {
                ScanRunId = context.Run.Id, WorkflowRunId = context.WorkflowRunId, StepId = step.Id, Operation = step.Operation,
                NetworkIds = context.Run.NetworkIds, Parameters = parameters.Values, PreferredToolId = step.ToolId,
                RequiredParameters = descriptor.Parameters.Select(p => p.Name).Where(step.Parameters.ContainsKey).ToList(),
                Priority = context.Run.Priority, RunRateCap = context.Run.MaxRatePerSecond, NotAfter = context.Run.NotAfter,
                TimeoutSeconds = step.TimeoutSeconds ?? defaults.TimeoutSeconds, MaxConcurrency = step.MaxConcurrency ?? defaults.MaxConcurrency,
                MaxAttempts = retry.MaxAttempts, BackoffSeconds = retry.BackoffSeconds, BatchSize = defaults.BatchSize,
                Signatures = signatures, Hosts = hosts, Endpoints = endpoints,
            }, ct);
        }
        catch (PlanningException ex)
        {
            return StepOutcome.Failed(ex.Message);
        }

        if (plan.JobsTotal == 0)
            return StepOutcome.Skipped(plan.OutOfScope > 0 ? $"All {plan.OutOfScope} targets are outside the authorized scope." : "No targets in the authorized scope.");
        var message = $"{plan.JobsTotal} jobs, {plan.TargetCount} targets";
        if (plan.Unassignable > 0) message += $"; {plan.Unassignable} jobs wait for an eligible agent ({plan.UnassignableReason})";
        if (plan.OutOfScope > 0) message += $"; {plan.OutOfScope} out-of-scope targets dropped";
        return StepOutcome.Waiting(plan.JobsTotal, message);
    }
}

/// <summary>EvaluateCondition: the runtime applies <c>Input.Filter</c> and <c>When</c>; the matching observations are the step output.</summary>
public sealed class EvaluateConditionExecutor : IStepExecutor
{
    public bool CanExecute(ScanOperation operation) => operation == ScanOperation.EvaluateCondition;

    public Task<StepOutcome> ExecuteAsync(StepExecutionContext context, CancellationToken ct) =>
        Task.FromResult(StepOutcome.Completed($"{context.Input.Count} observations match"));
}

/// <summary>PersistObservations / ComparePreviousScan through the Discovery module's <see cref="IDiscoveryRunProcessor"/>.</summary>
public sealed class DiscoveryStepExecutor(IServiceProvider services, ScanRunStore runs) : IStepExecutor
{
    public bool CanExecute(ScanOperation operation) => operation is ScanOperation.PersistObservations or ScanOperation.ComparePreviousScan;

    public async Task<StepOutcome> ExecuteAsync(StepExecutionContext context, CancellationToken ct)
    {
        var processor = services.GetService<IDiscoveryRunProcessor>();
        if (processor is null) return StepOutcome.Failed("IDiscoveryRunProcessor is not registered (Discovery module missing).");
        var runId = context.Run.Id;

        if (context.Step.Operation == ScanOperation.ComparePreviousScan)
        {
            var values = ParameterValidator.Validate(OperationCatalog.Get(ScanOperation.ComparePreviousScan).Parameters, context.Step.Parameters).Values;
            var threshold = int.Parse(values["missingThreshold"], CultureInfo.InvariantCulture);
            var changes = await processor.CompareWithPreviousAsync(runId, threshold, ct);
            return StepOutcome.Completed($"{changes.ChangesDetected} changes detected");
        }

        // Coverage is complete only if nothing expired, failed, was cancelled or is still running.
        var counts = await runs.StepJobCountsAsync(runId, ct);
        var complete = !context.WindowExpired && counts.Values.All(c => c.Active == 0) && !await runs.HasFailedJobsAsync(runId, ct);
        var coverage = await runs.CoverageAsync(runId, complete, ct);
        var result = await processor.PersistRunAsync(runId, coverage, ct);
        return StepOutcome.Completed(
            $"{result.ObservationsTotal} observations, {result.HostsUpdated} hosts, {result.ServicesUpdated} services updated (coverage {(complete ? "complete" : "incomplete")})");
    }
}

/// <summary>PublishFinding through the Integrations module's <see cref="IFindingPublisher"/>.</summary>
public sealed class PublishFindingExecutor(IServiceProvider services) : IStepExecutor
{
    public bool CanExecute(ScanOperation operation) => operation == ScanOperation.PublishFinding;

    public async Task<StepOutcome> ExecuteAsync(StepExecutionContext context, CancellationToken ct)
    {
        var publisher = services.GetService<IFindingPublisher>();
        if (publisher is null) return StepOutcome.Failed("IFindingPublisher is not registered (Integrations module missing).");
        var values = ParameterValidator.Validate(OperationCatalog.Get(ScanOperation.PublishFinding).Parameters, context.Step.Parameters).Values;
        var result = await publisher.PublishAsync(context.Run.Id, values["destination"], values["minSeverity"], ct);
        return StepOutcome.Completed($"{result.Published} findings published, {result.Skipped} skipped");
    }
}
