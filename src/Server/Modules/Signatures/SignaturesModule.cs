using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace WebScan.Server.Modules.Signatures;

public static class SignaturesModule
{
    public static IServiceCollection AddSignaturesModule(this IServiceCollection services, IConfiguration configuration)
    {
        return services;
    }

    public static IEndpointRouteBuilder MapSignaturesEndpoints(this IEndpointRouteBuilder endpoints)
    {
        return endpoints;
    }
}
