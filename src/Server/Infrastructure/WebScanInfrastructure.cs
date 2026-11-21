using System.Reflection;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Scalar.AspNetCore;
using WebScan.Contracts;
using WebScan.Server.Infrastructure.Auditing;
using WebScan.Server.Infrastructure.Messaging;
using WebScan.Server.Infrastructure.Persistence;
using WebScan.Server.Infrastructure.Security;
using WebScan.Server.Infrastructure.Telemetry;
using WebScan.Server.Kernel.Security;

namespace WebScan.Server.Infrastructure;

public static class WebScanInfrastructure
{
    /// <summary>Cross-cutting services: persistence, auth, audit, secrets, messaging, telemetry, HTTP conventions.</summary>
    public static WebApplicationBuilder AddWebScanInfrastructure(this WebApplicationBuilder builder, IEnumerable<Assembly> moduleAssemblies)
    {
        var services = builder.Services;

        services.TryAddSingleton(TimeProvider.System);
        services.AddModuleDbContext<InfraDbContext>(InfraDbContext.Schema);

        services.ConfigureHttpJsonOptions(o => ContractJson.Configure(o.SerializerOptions));
        services.AddProblemDetails();
        services.AddRequestDecompression();
        services.AddOpenApi();
        services.AddSignalR().AddJsonProtocol(o => ContractJson.Configure(o.PayloadSerializerOptions));
        services.AddHealthChecks().AddCheck<DatabaseHealthCheck>("database", tags: [InfrastructureEndpoints.ReadyTag]);

        services.AddWebScanAuth();
        services.AddWebScanSecretProtection(builder.Configuration);
        services.AddScoped<IAuditLog, DbAuditLog>();

        builder.AddWebScanMessaging(moduleAssemblies);
        builder.AddWebScanTelemetry();
        return builder;
    }

    /// <summary>HTTP pipeline: ProblemDetails for errors, gzip request bodies (agent uploads), authentication, authorization.</summary>
    public static WebApplication UseWebScanInfrastructure(this WebApplication app)
    {
        app.UseExceptionHandler();
        app.UseStatusCodePages();
        app.UseRequestDecompression();
        app.UseAuthentication();
        app.UseAuthorization();

        if (app.Environment.IsDevelopment())
        {
            app.MapOpenApi().AllowAnonymous();
            app.MapScalarApiReference().AllowAnonymous();
        }

        app.MapInfrastructureEndpoints();
        return app;
    }
}
