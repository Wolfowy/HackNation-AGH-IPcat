using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using WebScan.Server.Infrastructure.Persistence;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Modules.Workflows.Api;
using WebScan.Server.Modules.Workflows.Definitions;
using WebScan.Server.Modules.Workflows.Execution;
using WebScan.Server.Modules.Workflows.Persistence;
using WebScan.Server.Modules.Workflows.Runtime;

namespace WebScan.Server.Modules.Workflows;

/// <summary>
/// Workflows module: versioned workflow definitions, validator, DAG runtime with step executors, scan launcher and the scans API.
/// References the Scanning module directly (planner, job queue, run store) — the one sanctioned module-to-module reference.
/// </summary>
public static class WorkflowsModule
{
    public static IServiceCollection AddWorkflowsModule(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddModuleDbContext<WorkflowsDbContext>(WorkflowsDbContext.Schema);
        services.Configure<WorkflowOptions>(configuration.GetSection(WorkflowOptions.Section));

        services.AddScoped<WorkflowDefinitionStore>();
        services.AddHostedService<WorkflowSeeder>();

        services.AddScoped<IStepExecutor, AgentStepExecutor>();
        services.AddScoped<IStepExecutor, EvaluateConditionExecutor>();
        services.AddScoped<IStepExecutor, DiscoveryStepExecutor>();
        services.AddScoped<IStepExecutor, PublishFindingExecutor>();
        services.AddScoped<IWorkflowRuntime, WorkflowRuntime>();
        services.AddHostedService<WorkflowTickerService>();

        services.AddScoped<IScanLauncher, ScanLauncher>();
        services.AddScoped<Import.ResultImporter>();
        return services;
    }

    public static IEndpointRouteBuilder MapWorkflowsEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapWorkflowEndpoints();
        endpoints.MapScanEndpoints();
        return endpoints;
    }
}
