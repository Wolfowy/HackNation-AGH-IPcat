using System.Text.RegularExpressions;
using WebScan.Contracts;
using WebScan.Server.Modules.Workflows.Conditions;
using WebScan.Server.Modules.Workflows.Runtime;

namespace WebScan.Server.Modules.Workflows.Definitions;

/// <summary>
/// Structural and semantic validation of workflow definitions: identifiers, acyclic dependencies, inputs that come from
/// ancestor steps, operation parameters (<see cref="ParameterValidator"/>), typed conditions and numeric bounds.
/// </summary>
public static partial class WorkflowValidator
{
    public const int MaxSteps = 100;
    public const int MaxConditionDepth = 8;

    [GeneratedRegex("^[a-z0-9][a-z0-9-]{1,63}$")] private static partial Regex KeyPattern();
    [GeneratedRegex("^[a-zA-Z][a-zA-Z0-9_-]{0,63}$")] private static partial Regex StepIdPattern();
    [GeneratedRegex("^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")] private static partial Regex ToolIdPattern();

    public static IReadOnlyList<string> Validate(ScanWorkflowDefinition? definition)
    {
        var errors = new List<string>();
        if (definition is null) return ["Definition is required."];
        if (definition.Key is null || !KeyPattern().IsMatch(definition.Key)) errors.Add("key must match ^[a-z0-9][a-z0-9-]{1,63}$.");
        if (string.IsNullOrWhiteSpace(definition.Name) || definition.Name.Length > 200) errors.Add("name is required (max 200 characters).");
        if (definition.Description?.Length > 2000) errors.Add("description is too long (max 2000 characters).");

        var defaults = definition.Defaults ?? new WorkflowDefaults();
        ValidateBounds(errors, "defaults", defaults.TimeoutSeconds, defaults.MaxConcurrency, defaults.Retry);
        if (defaults.BatchSize is { } batch && (batch < 64 || batch > 1024)) errors.Add("defaults.batchSize must be between 64 and 1024.");

        if (definition.Steps is null || definition.Steps.Count == 0) { errors.Add("At least one step is required."); return errors; }
        if (definition.Steps.Count > MaxSteps) errors.Add($"At most {MaxSteps} steps are allowed.");
        if (definition.Steps.Any(s => s is null)) { errors.Add("Steps must not be null."); return errors; }
        var steps = Normalize(definition).Steps;

        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var step in steps)
        {
            if (step.Id is null || !StepIdPattern().IsMatch(step.Id)) errors.Add($"Step id '{step.Id}' must match ^[a-zA-Z][a-zA-Z0-9_-]{{0,63}}$.");
            else if (!ids.Add(step.Id)) errors.Add($"Duplicate step id '{step.Id}'.");
        }

        var referencesValid = true;
        foreach (var step in steps)
        {
            var at = $"Step '{step.Id}'";
            foreach (var dep in step.DependsOn)
            {
                if (dep == step.Id) { errors.Add($"{at} depends on itself."); referencesValid = false; }
                else if (!ids.Contains(dep)) { errors.Add($"{at} depends on unknown step '{dep}'."); referencesValid = false; }
            }
            if (step.DependsOn.Distinct().Count() != step.DependsOn.Count) errors.Add($"{at} lists a dependency twice.");
            ValidateStep(errors, step, at, ids);
        }
        if (!referencesValid) return errors;

        var cyclic = DagScheduler.CyclicSteps(steps);
        if (cyclic.Count > 0) { errors.Add($"Dependencies contain a cycle involving: {string.Join(", ", cyclic)}."); return errors; }

        foreach (var step in steps.Where(s => s.Input is not null))
        {
            var ancestors = DagScheduler.Ancestors(steps, step.Id);
            foreach (var from in step.Input!.FromSteps?.Where(ids.Contains) ?? [])
                if (!ancestors.Contains(from)) errors.Add($"Step '{step.Id}' reads input from '{from}', which must be one of its (transitive) dependencies.");
        }
        return errors;
    }

    /// <summary>JSON may carry explicit nulls for collections; treat them as empty.</summary>
    public static ScanWorkflowDefinition Normalize(ScanWorkflowDefinition definition) => definition with
    {
        Defaults = definition.Defaults ?? new WorkflowDefaults(),
        Steps = definition.Steps.Select(s => s with { DependsOn = s.DependsOn ?? [], Parameters = s.Parameters ?? new Dictionary<string, string>() }).ToList(),
    };

    private static void ValidateStep(List<string> errors, WorkflowStep step, string at, IReadOnlySet<string> ids)
    {
        if (!Enum.IsDefined(step.Operation)) { errors.Add($"{at} has an unknown operation."); return; }
        var descriptor = OperationCatalog.Get(step.Operation);
        foreach (var e in ParameterValidator.Validate(descriptor.Parameters, step.Parameters).Errors) errors.Add($"{at}: {e}");
        if (!Enum.IsDefined(step.OnFailure)) errors.Add($"{at} has an invalid onFailure policy.");
        ValidateBounds(errors, at, step.TimeoutSeconds, step.MaxConcurrency, step.Retry);

        var isServer = descriptor.Plane == OperationPlane.Server;
        if (step.ToolId is not null && (isServer || !ToolIdPattern().IsMatch(step.ToolId)))
            errors.Add(isServer ? $"{at}: server steps cannot pin a toolId." : $"{at}: toolId '{step.ToolId}' is invalid.");

        if (step.Operation == ScanOperation.EvaluateCondition && step.Input is null) errors.Add($"{at}: EvaluateCondition requires input.fromSteps.");
        else if (isServer && step.Operation != ScanOperation.EvaluateCondition && (step.Input is not null || step.When is not null))
            errors.Add($"{at}: server step {step.Operation} has no targets (input/when are not allowed).");
        if (descriptor.InputKind == TargetKind.Endpoints && step.Input is null) errors.Add($"{at}: {step.Operation} needs endpoints from input.fromSteps.");
        if (step.When is not null && step.Input is null && !isServer) errors.Add($"{at}: 'when' is evaluated on the step input and requires input.fromSteps.");

        if (step.Input is not null)
        {
            if (step.Input.FromSteps is null || step.Input.FromSteps.Count == 0) errors.Add($"{at}: input.fromSteps must not be empty.");
            foreach (var from in step.Input.FromSteps ?? [])
                if (from == step.Id || !ids.Contains(from)) errors.Add($"{at}: input.fromSteps references unknown step '{from}'.");
            if (step.Input.Filter is not null) errors.AddRange(ValidateCondition(step.Input.Filter, $"{at} input.filter"));
        }
        if (step.When is not null) errors.AddRange(ValidateCondition(step.When, $"{at} when"));
    }

    private static void ValidateBounds(List<string> errors, string at, int? timeout, int? maxConcurrency, RetryPolicy? retry)
    {
        if (timeout is { } t && (t < 1 || t > 86_400)) errors.Add($"{at}: timeoutSeconds must be between 1 and 86400.");
        if (maxConcurrency is { } c && (c < 1 || c > 1000)) errors.Add($"{at}: maxConcurrency must be between 1 and 1000.");
        if (retry is null) return;
        if (retry.MaxAttempts < 1 || retry.MaxAttempts > 10) errors.Add($"{at}: retry.maxAttempts must be between 1 and 10.");
        if (retry.BackoffSeconds < 0 || retry.BackoffSeconds > 3600) errors.Add($"{at}: retry.backoffSeconds must be between 0 and 3600.");
    }

    public static IReadOnlyList<string> ValidateCondition(ConditionExpression condition, string at, int depth = 1)
    {
        if (depth > MaxConditionDepth) return [$"{at}: condition nesting exceeds depth {MaxConditionDepth}."];
        var isLeaf = condition.Field is not null || condition.Operator is not null || condition.Values is not null;
        var forms = (isLeaf ? 1 : 0) + (condition.All is not null ? 1 : 0) + (condition.Any is not null ? 1 : 0) + (condition.Not is not null ? 1 : 0);
        if (forms != 1) return [$"{at}: a condition must be exactly one of field/operator, all, any or not."];

        if (condition.All is { } all) return all.Count == 0 ? [$"{at}: 'all' must not be empty."] : all.SelectMany((c, i) => Child(c, $"{at}.all[{i}]", depth)).ToList();
        if (condition.Any is { } any) return any.Count == 0 ? [$"{at}: 'any' must not be empty."] : any.SelectMany((c, i) => Child(c, $"{at}.any[{i}]", depth)).ToList();
        if (condition.Not is { } not) return ValidateCondition(not, $"{at}.not", depth + 1);

        var errors = new List<string>();
        if (condition.Field is null || !ConditionFields.All.Contains(condition.Field)) { errors.Add($"{at}: unknown field '{condition.Field}'."); return errors; }
        if (condition.Operator is not { } op || !Enum.IsDefined(op)) { errors.Add($"{at}: operator is required."); return errors; }

        var field = condition.Field;
        var numeric = ConditionFieldTypes.Numeric.Contains(field);
        var isEnum = ConditionFieldTypes.Enums.TryGetValue(field, out var enumValues);
        if (op is ConditionOperator.GreaterThan or ConditionOperator.LessThan && !numeric)
            errors.Add($"{at}: {op} requires a numeric field ({string.Join(", ", ConditionFieldTypes.Numeric)}).");
        if (op is ConditionOperator.Contains or ConditionOperator.StartsWith && (numeric || isEnum))
            errors.Add($"{at}: {op} is only valid for text fields.");

        var values = condition.Values ?? [];
        var expected = op switch
        {
            ConditionOperator.Exists or ConditionOperator.NotExists => values.Count == 0 ? null : "takes no values",
            ConditionOperator.In or ConditionOperator.NotIn => values.Count >= 1 ? null : "needs at least one value",
            _ => values.Count == 1 ? null : "needs exactly one value",
        };
        if (expected is not null) errors.Add($"{at}: {op} {expected}.");
        foreach (var v in values)
        {
            if (v is null || v.Length > 500) errors.Add($"{at}: values must be non-null strings up to 500 characters.");
            else if (numeric && !ConditionEvaluator.TryNumber(v, out _)) errors.Add($"{at}: '{v}' is not a number (field {field}).");
            else if (isEnum && !enumValues!.Contains(v, StringComparer.OrdinalIgnoreCase)) errors.Add($"{at}: '{v}' is not a valid {field} ({string.Join(", ", enumValues!)}).");
        }
        return errors;

        static IReadOnlyList<string> Child(ConditionExpression? c, string path, int depth) =>
            c is null ? [$"{path}: condition must not be null."] : ValidateCondition(c, path, depth + 1);
    }
}
