using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace WebScan.Server.Modules.Workflows;

public static class WorkflowsModule
{
    public static IServiceCollection AddWorkflowsModule(this IServiceCollection services, IConfiguration configuration)
    {
        return services;
    }

    public static IEndpointRouteBuilder MapWorkflowsEndpoints(this IEndpointRouteBuilder endpoints)
    {
        return endpoints;
    }
}
