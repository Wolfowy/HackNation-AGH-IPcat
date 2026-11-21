using System.Reflection;

namespace WebScan.Server.Api;

/// <summary>Assemblies of all modules — used for Wolverine handler discovery and similar scans.</summary>
public static class ModuleAssemblies
{
    public static readonly IReadOnlyList<Assembly> All =
    [
        typeof(WebScan.Server.Modules.Identity.IdentityModule).Assembly,
        typeof(WebScan.Server.Modules.Agents.AgentsModule).Assembly,
        typeof(WebScan.Server.Modules.Networks.NetworksModule).Assembly,
        typeof(WebScan.Server.Modules.Scanning.ScanningModule).Assembly,
        typeof(WebScan.Server.Modules.Scheduling.SchedulingModule).Assembly,
        typeof(WebScan.Server.Modules.Workflows.WorkflowsModule).Assembly,
        typeof(WebScan.Server.Modules.Signatures.SignaturesModule).Assembly,
        typeof(WebScan.Server.Modules.Discovery.DiscoveryModule).Assembly,
        typeof(WebScan.Server.Modules.Analytics.AnalyticsModule).Assembly,
        typeof(WebScan.Server.Modules.Integrations.IntegrationsModule).Assembly,
    ];
}
