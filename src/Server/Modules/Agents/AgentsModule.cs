using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace WebScan.Server.Modules.Agents;

public static class AgentsModule
{
    public static IServiceCollection AddAgentsModule(this IServiceCollection services, IConfiguration configuration)
    {
        return services;
    }

    public static IEndpointRouteBuilder MapAgentsEndpoints(this IEndpointRouteBuilder endpoints)
    {
        return endpoints;
    }
}
