using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using WebScan.Server.Infrastructure.Persistence;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Agents.Persistence;

namespace WebScan.Server.Modules.Agents;

public static class AgentsModule
{
    public static IServiceCollection AddAgentsModule(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddModuleDbContext<AgentsDbContext>(AgentsDbContext.Schema);
        services.AddOptions<AgentsOptions>().Configure(o => AgentsOptions.Bind(o, configuration))
            .Validate(o => o.HeartbeatTimeoutSeconds > 0 && o.SecretRotationGraceMinutes >= 0, "Invalid Agents configuration.");

        services.AddAuthentication().AddScheme<AuthenticationSchemeOptions, AgentKeyAuthenticationHandler>(AuthSchemes.Agent, null);

        services.AddScoped<ToolCatalog>();
        services.AddScoped<IAgentDirectory, AgentDirectory>();
        services.AddHostedService<BootstrapEnrollmentTokenInitializer>();
        services.AddSingleton<AgentOfflineDetector>();
        services.AddHostedService(sp => sp.GetRequiredService<AgentOfflineDetector>());
        return services;
    }

    public static IEndpointRouteBuilder MapAgentsEndpoints(this IEndpointRouteBuilder endpoints)
    {
        AgentApiEndpoints.Map(endpoints);
        AgentAdminEndpoints.Map(endpoints);
        return endpoints;
    }
}
