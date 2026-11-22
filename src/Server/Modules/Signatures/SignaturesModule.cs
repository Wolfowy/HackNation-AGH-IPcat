using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using WebScan.Server.Infrastructure.Persistence;
using WebScan.Server.Kernel.Discovery;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Modules.Signatures.Persistence;

namespace WebScan.Server.Modules.Signatures;

public static class SignaturesModule
{
    public static IServiceCollection AddSignaturesModule(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddModuleDbContext<SignaturesDbContext>(SignaturesDbContext.Schema);
        services.TryAddSingleton(TimeProvider.System);
        services.AddScoped<SignatureCatalog>();
        services.AddScoped<ISignatureCatalog>(sp => sp.GetRequiredService<SignatureCatalog>());
        services.AddScoped<IInterpretationRuleProvider>(sp => sp.GetRequiredService<SignatureCatalog>());
        services.AddHostedService<SignaturePackSeeder>();
        return services;
    }

    public static IEndpointRouteBuilder MapSignaturesEndpoints(this IEndpointRouteBuilder endpoints)
    {
        SignatureEndpoints.Map(endpoints);
        return endpoints;
    }
}
