using Microsoft.Extensions.Options;
using WebScan.Agent.Inventory;
using WebScan.Agent.Tools;
using WebScan.Agent.Tools.Abstractions;
using WebScan.Contracts;

namespace WebScan.Agent.Execution;

/// <summary>A job that passed every agent-side check, with the derived execution settings.</summary>
public sealed record ValidatedJob(
    ScanJob Job,
    RegisteredTool Tool,
    ToolCapabilityDefinition Definition,
    IReadOnlyDictionary<string, string> Parameters,
    int RatePerSecond,
    int Parallelism,
    TimeSpan Timeout,
    bool TimeoutIsWindowEnd);

public sealed record JobValidationResult(ValidatedJob? Job, JobFailureReason Reason, string? Error, bool Retryable)
{
    public bool IsValid => Job is not null;
    public static JobValidationResult Ok(ValidatedJob job) => new(job, default, null, false);
    public static JobValidationResult Fail(JobFailureReason reason, string error, bool retryable = false) => new(null, reason, error, retryable);
}

/// <summary>
/// Defence in depth: the agent re-validates every job from the server before anything runs — agent-plane operation,
/// locally resolvable tool, parameters against <see cref="OperationCatalog"/> (unknown rejected), every target inside
/// <see cref="ScanJob.AuthorizedScope"/>, interface present locally, signature bundle integrity, and the time window.
/// </summary>
public sealed class JobValidator(ToolRegistry tools, NetworkInventory inventory, IOptionsMonitor<AgentOptions> options, TimeProvider time)
{
    public const int MaxTargetEntries = 100_000;

    public JobValidationResult Validate(ScanJob job)
    {
        if (!OperationCatalog.All.TryGetValue(job.Operation, out var operation) || operation.Plane != OperationPlane.Agent)
            return JobValidationResult.Fail(JobFailureReason.InvalidJob, $"Operation {job.Operation} is not executed by agents.");

        var parameters = ParameterValidator.Validate(operation.Parameters, job.Parameters);
        if (!parameters.IsValid) return JobValidationResult.Fail(JobFailureReason.InvalidJob, string.Join(" ", parameters.Errors));

        if (TargetError(job, operation) is { } targetError) return JobValidationResult.Fail(JobFailureReason.InvalidJob, targetError);

        if (job.InterfaceName is { } nic && !inventory.GetInterfaces().Any(i => i.Name == nic))
            return JobValidationResult.Fail(JobFailureReason.InvalidJob, $"Interface '{nic}' does not exist on this agent.");

        if (job.Limits.RatePerSecond < 1 || job.Limits.TimeoutSeconds < 0)
            return JobValidationResult.Fail(JobFailureReason.InvalidJob, "Job limits are invalid.");

        if (tools.Resolve(job.Tool) is not { } resolved)
            return JobValidationResult.Fail(JobFailureReason.ToolNotAvailable, $"No local tool provides capability '{job.Tool.Capability}'.", retryable: true);
        var (tool, definition) = resolved;

        if (job.Signatures is { } bundle && SignatureBundles.Validate(bundle) is { } bundleError)
            return JobValidationResult.Fail(JobFailureReason.InvalidJob, bundleError);
        if (job.Signatures is null && ArgumentBuilder.Uses(definition, ToolPlaceholders.TemplatesDir))
            return JobValidationResult.Fail(JobFailureReason.InvalidJob, "The job carries no signature bundle.");

        var now = time.GetUtcNow();
        var timeout = TimeSpan.FromSeconds(job.Limits.TimeoutSeconds > 0 ? job.Limits.TimeoutSeconds : tool.Manifest.DefaultTimeoutSeconds);
        var windowEnd = false;
        if (job.NotAfter is { } notAfter)
        {
            if (notAfter <= now) return JobValidationResult.Fail(JobFailureReason.WindowExpired, "The job's scan window has already ended.");
            if (notAfter - now < timeout) { timeout = notAfter - now; windowEnd = true; }
        }

        var o = options.CurrentValue;
        var agentShare = Math.Max(1, o.MaxRatePerSecond / Math.Max(1, o.MaxConcurrentJobs));
        var rate = Math.Min(job.Limits.RatePerSecond, agentShare);
        if (parameters.Values.TryGetValue("rate", out var r) && int.TryParse(r, out var requested)) rate = Math.Min(rate, requested);

        return JobValidationResult.Ok(new ValidatedJob(job, tool, definition, parameters.Values, Math.Max(1, rate),
            Math.Clamp(job.Limits.MaxParallelism, 1, 1000), timeout, windowEnd));
    }

    private static string? TargetError(ScanJob job, OperationDescriptor operation)
    {
        var hosts = job.Targets.Hosts;
        var endpoints = job.Targets.Endpoints;
        if (hosts.Count + endpoints.Count == 0) return "The job has no targets.";
        if (hosts.Count + endpoints.Count > MaxTargetEntries) return "The job has too many targets.";
        if (operation.InputKind == TargetKind.Endpoints && endpoints.Count == 0) return $"Operation {job.Operation} requires endpoint targets.";
        if (hosts.Count > 0 && endpoints.Count > 0) return "A job carries either hosts or endpoints, not both.";
        if (job.AuthorizedScope.Count == 0) return "The job has no authorized scope.";

        foreach (var host in hosts)
        {
            if (!Targets.TryParseNetwork(host, out _) && !Targets.IsHostname(host)) return $"Target '{host}' is not an IP address, CIDR or hostname.";
            if (!Targets.IsInScope(host, job.AuthorizedScope)) return $"Target '{host}' is outside the authorized scope.";
        }
        foreach (var e in endpoints)
        {
            if (e.Port is < 1 or > 65535) return $"Endpoint port {e.Port} is invalid.";
            if (e.Address.Contains('/') || (!Targets.TryParseNetwork(e.Address, out _) && !Targets.IsHostname(e.Address)))
                return $"Endpoint address '{e.Address}' is invalid.";
            if (!Targets.IsInScope(e.Address, job.AuthorizedScope)) return $"Endpoint '{e.Address}:{e.Port}' is outside the authorized scope.";
            if (e.Scheme is not (null or "http" or "https")) return $"Endpoint scheme '{e.Scheme}' is not supported.";
        }
        return null;
    }
}
