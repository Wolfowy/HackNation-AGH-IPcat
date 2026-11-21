using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using WebScan.Server.Infrastructure.Persistence;
using WebScan.Server.Kernel.Discovery;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Modules.Discovery.Api;
using WebScan.Server.Modules.Discovery.Ingestion;
using WebScan.Server.Modules.Discovery.Persistence;
using WebScan.Server.Modules.Discovery.Processing;

namespace WebScan.Server.Modules.Discovery;

public static class DiscoveryModule
{
    public static IServiceCollection AddDiscoveryModule(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddModuleDbContext<DiscoveryDbContext>(DiscoveryDbContext.Schema);
        services.Configure<DiscoveryOptions>(configuration.GetSection(DiscoveryOptions.Section));
        services.TryAddSingleton(TimeProvider.System);
        services.AddScoped<IObservationSink, ObservationIngestor>();
        services.AddScoped<IDiscoveryRunProcessor, DiscoveryRunProcessor>();
        services.AddScoped<IObservationReader, ObservationReader>();
        services.AddScoped<IFindingStore, FindingStore>();
        services.AddScoped<AssetQueries>();
        services.AddScoped<AnnotationService>();
        return services;
    }

    public static IEndpointRouteBuilder MapDiscoveryEndpoints(this IEndpointRouteBuilder endpoints)
    {
        DiscoveryEndpoints.Map(endpoints);
        return endpoints;
    }
}
