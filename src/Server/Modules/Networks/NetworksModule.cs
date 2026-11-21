using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace WebScan.Server.Modules.Networks;

public static class NetworksModule
{
    public static IServiceCollection AddNetworksModule(this IServiceCollection services, IConfiguration configuration)
    {
        return services;
    }

    public static IEndpointRouteBuilder MapNetworksEndpoints(this IEndpointRouteBuilder endpoints)
    {
        return endpoints;
    }
}
