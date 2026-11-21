using WebScan.Contracts;
using WebScan.Server.Modules.Workflows.Persistence;

namespace WebScan.Server.Modules.Workflows.Runtime;

/// <summary>Pure DAG rules: readiness, fatal failures, ancestry. No I/O.</summary>
public static class DagScheduler
{
    /// <summary>A finished dependency: Completed, Skipped, or Failed with <see cref="StepFailurePolicy.Continue"/>.</summary>
    public static bool IsSatisfied(WorkflowStep dependency, StepStatus status) =>
        status is StepStatus.Completed or StepStatus.Skipped || (status == StepStatus.Failed && dependency.OnFailure == StepFailurePolicy.Continue);

    /// <summary>Pending steps whose dependencies are all satisfied, in definition order (independent ones run in parallel).</summary>
    public static IReadOnlyList<WorkflowStep> ReadySteps(ScanWorkflowDefinition definition, IReadOnlyDictionary<string, StepStatus> status)
    {
        var byId = definition.Steps.ToDictionary(s => s.Id, StringComparer.Ordinal);
        return definition.Steps
            .Where(s => status.GetValueOrDefault(s.Id) == StepStatus.Pending)
            .Where(s => s.DependsOn.All(d => IsSatisfied(byId[d], status.GetValueOrDefault(d))))
            .ToList();
    }

    /// <summary>First step that failed with <see cref="StepFailurePolicy.FailWorkflow"/>, if any.</summary>
    public static WorkflowStep? FatalFailure(ScanWorkflowDefinition definition, IReadOnlyDictionary<string, StepStatus> status) =>
        definition.Steps.FirstOrDefault(s => s.OnFailure == StepFailurePolicy.FailWorkflow && status.GetValueOrDefault(s.Id) == StepStatus.Failed);

    /// <summary>Transitive dependencies of a step (assumes valid references; cycles are tolerated).</summary>
    public static IReadOnlySet<string> Ancestors(IReadOnlyList<WorkflowStep> steps, string stepId)
    {
        var byId = steps.GroupBy(s => s.Id, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
        var result = new HashSet<string>(StringComparer.Ordinal);
        var stack = new Stack<string>(byId.TryGetValue(stepId, out var start) ? start.DependsOn : []);
        while (stack.TryPop(out var id))
            if (result.Add(id) && byId.TryGetValue(id, out var step))
                foreach (var d in step.DependsOn) stack.Push(d);
        return result;
    }

    /// <summary>Ids of steps on a dependency cycle (empty when acyclic). Kahn's algorithm.</summary>
    public static IReadOnlyList<string> CyclicSteps(IReadOnlyList<WorkflowStep> steps)
    {
        var ids = steps.Select(s => s.Id).ToHashSet(StringComparer.Ordinal);
        var indegree = steps.ToDictionary(s => s.Id, s => s.DependsOn.Count(ids.Contains), StringComparer.Ordinal);
        var dependents = steps.SelectMany(s => s.DependsOn.Where(ids.Contains).Select(d => (d, s.Id))).ToLookup(x => x.d, x => x.Id);
        var queue = new Queue<string>(indegree.Where(kv => kv.Value == 0).Select(kv => kv.Key));
        while (queue.TryDequeue(out var id))
            foreach (var next in dependents[id])
                if (--indegree[next] == 0) queue.Enqueue(next);
        return indegree.Where(kv => kv.Value > 0).Select(kv => kv.Key).Order(StringComparer.Ordinal).ToList();
    }
}
