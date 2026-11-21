using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using WebScan.Contracts;
using WebScan.Server.Infrastructure.Persistence;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Kernel.Scanning;
using WebScan.Server.Kernel.Telemetry;
using WebScan.Server.Modules.Scanning.Api;
using WebScan.Server.Modules.Scanning.Events;
using WebScan.Server.Modules.Scanning.Jobs;
using WebScan.Server.Modules.Scanning.Persistence;
using WebScan.Server.Modules.Scanning.Planning;
using WebScan.Server.Modules.Scanning.Runs;

namespace WebScan.Server.Modules.Scanning;

/// <summary>
/// Scanning module: scan runs, persistent job queue with leases, agent job API, task planner, execution events (DB + SignalR).
/// Requires from the host: Wolverine with PostgreSQL message persistence and <c>UseEntityFrameworkCoreTransactions()</c>
/// (for <c>IDbContextOutbox&lt;ScanningDbContext&gt;</c>), authentication/authorization policies and JSON options.
/// </summary>
public static class ScanningModule
{
    public static IServiceCollection AddScanningModule(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddModuleDbContext<ScanningDbContext>(ScanningDbContext.Schema);
        services.Configure<PlannerOptions>(configuration.GetSection(PlannerOptions.Section));
        services.Configure<ScanningOptions>(configuration.GetSection(ScanningOptions.Section));
        services.TryAddSingleton(TimeProvider.System);

        services.AddScoped<ScanLimitsStore>();
        services.AddScoped<TaskPlanner>();
        services.AddScoped<JobQueue>();
        services.AddScoped<ScanRunStore>();
        services.AddScoped<IScanRunStatusReader, ScanRunStatusReader>();
        services.AddSingleton<LeaseSweeper>();
        services.AddHostedService<LeaseSweeperService>();

        services.AddSingleton<IScanEventPublisher, ScanEventPublisher>();
        services.AddSignalR().AddJsonProtocol(o => ContractJson.Configure(o.PayloadSerializerOptions));
        return services;
    }

    public static IEndpointRouteBuilder MapScanningEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var sweeper = endpoints.ServiceProvider.GetRequiredService<LeaseSweeper>();
        WebScanTelemetry.SetQueueLengthProvider(() => sweeper.QueuedJobs);

        endpoints.MapAgentJobEndpoints();
        endpoints.MapJobEndpoints();
        endpoints.MapHub<ScanEventsHub>(ScanHub.Path);
        return endpoints;
    }
}
