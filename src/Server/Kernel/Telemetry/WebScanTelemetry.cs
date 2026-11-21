using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace WebScan.Server.Kernel.Telemetry;

/// <summary>
/// Shared OpenTelemetry instruments (meter/activity source "WebScan"). Infrastructure registers the meter and source
/// with the OTel SDK; modules only record values. Network observations are never stored only here.
/// </summary>
public static class WebScanTelemetry
{
    public const string Name = "WebScan";

    public static readonly ActivitySource ActivitySource = new(Name);
    public static readonly Meter Meter = new(Name);

    /// <summary>Addresses/endpoints scanned (rate in the backend = IPs per second). Tags: agent, interface, tool, operation.</summary>
    public static readonly Counter<long> IpsScanned = Meter.CreateCounter<long>("webscan.ips_scanned", "{address}");

    /// <summary>Job wall-clock duration. Tags: operation, tool, status.</summary>
    public static readonly Histogram<double> JobDuration = Meter.CreateHistogram<double>("webscan.job.duration", "s");

    public static readonly Counter<long> JobTimeouts = Meter.CreateCounter<long>("webscan.job.timeouts", "{job}");
    public static readonly Counter<long> JobFailures = Meter.CreateCounter<long>("webscan.job.failures", "{job}");

    /// <summary>Targets/s achieved per interface. Tags: agent, interface.</summary>
    public static readonly Histogram<double> InterfaceThroughput = Meter.CreateHistogram<double>("webscan.interface.throughput", "{address}/s");

    /// <summary>Workflow step duration. Tags: operation, status.</summary>
    public static readonly Histogram<double> WorkflowStepDuration = Meter.CreateHistogram<double>("webscan.workflow.step.duration", "s");

    public static readonly Counter<long> ObservationsIngested = Meter.CreateCounter<long>("webscan.observations.ingested", "{observation}");

    private static Func<long> _queueLength = () => 0;
    private static Func<int> _activeAgents = () => 0;

    /// <summary>Scanning module sets the provider (e.g. cached count of queued jobs).</summary>
    public static void SetQueueLengthProvider(Func<long> provider) => _queueLength = provider;

    /// <summary>Agents module sets the provider (cached count of online agents).</summary>
    public static void SetActiveAgentsProvider(Func<int> provider) => _activeAgents = provider;

    static WebScanTelemetry()
    {
        Meter.CreateObservableGauge("webscan.queue.length", () => _queueLength(), "{job}");
        Meter.CreateObservableGauge("webscan.agents.active", () => _activeAgents(), "{agent}");
    }
}
