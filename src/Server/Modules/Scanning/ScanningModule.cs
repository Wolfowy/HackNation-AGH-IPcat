using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace WebScan.Server.Modules.Scanning;

public static class ScanningModule
{
    public static IServiceCollection AddScanningModule(this IServiceCollection services, IConfiguration configuration)
    {
        return services;
    }

    public static IEndpointRouteBuilder MapScanningEndpoints(this IEndpointRouteBuilder endpoints)
    {
        return endpoints;
    }
}
