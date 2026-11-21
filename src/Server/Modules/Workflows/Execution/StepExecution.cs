using WebScan.Contracts;
using WebScan.Server.Modules.Scanning.Persistence;

namespace WebScan.Server.Modules.Workflows.Execution;

/// <summary>
/// Executes one workflow operation. Executors depend only on <see cref="StepExecutionContext"/> and DI services, never on the
/// DAG runtime, so a different engine can host them: in Elsa Workflows 3 each executor becomes an activity body, and
/// <see cref="StepOutcomeKind.WaitingForJobs"/> maps to a bookmark resumed by the <c>ScanJobFinished</c> message.
/// </summary>
public interface IStepExecutor
{
    bool CanExecute(ScanOperation operation);
    Task<StepOutcome> ExecuteAsync(StepExecutionContext context, CancellationToken ct);
}

/// <param name="Input">Observations of <c>Input.FromSteps</c> after <c>Input.Filter</c> (empty when the step has no input).</param>
/// <param name="WindowExpired">The scan window passed: coverage must be reported as incomplete.</param>
public sealed record StepExecutionContext(
    ScanRun Run, Guid WorkflowRunId, ScanWorkflowDefinition Definition, WorkflowStep Step, int Attempt,
    IReadOnlyList<DiscoveryObservation> Input, bool WindowExpired);

public enum StepOutcomeKind { Completed, Skipped, Failed, WaitingForJobs }

public sealed record StepOutcome(StepOutcomeKind Kind, string? Message = null, int Jobs = 0)
{
    public static StepOutcome Completed(string? message = null) => new(StepOutcomeKind.Completed, message);
    public static StepOutcome Skipped(string message) => new(StepOutcomeKind.Skipped, message);
    public static StepOutcome Failed(string message) => new(StepOutcomeKind.Failed, message);
    public static StepOutcome Waiting(int jobs, string? message = null) => new(StepOutcomeKind.WaitingForJobs, message, jobs);
}

/// <summary>Derives agent targets from observations of earlier steps.</summary>
public static class StepInputs
{
    private static readonly HashSet<string> HttpServices = new(StringComparer.OrdinalIgnoreCase) { "http", "http-alt", "http-proxy" };
    private static readonly HashSet<string> HttpsServices = new(StringComparer.OrdinalIgnoreCase) { "https", "https-alt" };

    /// <summary>Distinct addresses of observations that show a live host.</summary>
    public static IReadOnlyCollection<string> Hosts(IEnumerable<DiscoveryObservation> observations) =>
        observations.Where(o => o.Kind is not (ObservationKind.HostDown or ObservationKind.PortClosed))
            .Select(o => o.Address).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    /// <summary>Endpoints from PortOpen/Service/HttpResponse/... observations; scheme from service detection or HTTP probing.</summary>
    public static IReadOnlyCollection<ScanEndpoint> Endpoints(IEnumerable<DiscoveryObservation> observations)
    {
        var endpoints = new Dictionary<(string, int, TransportProtocol), ScanEndpoint>();
        foreach (var o in observations)
        {
            if (o.Port is not { } port || o.Kind is ObservationKind.HostDown or ObservationKind.PortClosed) continue;
            var scheme = o.Kind switch
            {
                ObservationKind.HttpResponse => o.Http?.Scheme?.ToLowerInvariant(),
                ObservationKind.Service when o.Service is { } s => s.Tunnel == "ssl" || HttpsServices.Contains(s.Name) ? "https" : HttpServices.Contains(s.Name) ? "http" : null,
                _ => null,
            };
            var key = (o.Address.ToLowerInvariant(), port, o.Transport ?? TransportProtocol.Tcp);
            if (endpoints.TryGetValue(key, out var existing))
                endpoints[key] = existing with { Scheme = existing.Scheme ?? scheme, Hostname = existing.Hostname ?? o.Hostname };
            else
                endpoints[key] = new ScanEndpoint { Address = o.Address, Port = port, Transport = key.Item3, Hostname = o.Hostname, Scheme = scheme };
        }
        return endpoints.Values.ToList();
    }
}
