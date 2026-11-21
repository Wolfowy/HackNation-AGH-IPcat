using WebScan.Server.Api;
using WebScan.Server.Infrastructure;
using WebScan.Server.Infrastructure.Persistence;
using WebScan.Server.Modules.Agents;
using WebScan.Server.Modules.Analytics;
using WebScan.Server.Modules.Discovery;
using WebScan.Server.Modules.Identity;
using WebScan.Server.Modules.Integrations;
using WebScan.Server.Modules.Networks;
using WebScan.Server.Modules.Scanning;
using WebScan.Server.Modules.Scheduling;
using WebScan.Server.Modules.Signatures;
using WebScan.Server.Modules.Workflows;

var builder = WebApplication.CreateBuilder(args);

// Persistence, auth (JWT + policies), audit, secrets, Wolverine (handlers from ModuleAssemblies.All), OpenTelemetry,
// ProblemDetails, request decompression, OpenAPI, SignalR JSON protocol, health checks.
builder.AddWebScanInfrastructure([typeof(Program).Assembly, .. ModuleAssemblies.All]);

builder.Services
    .AddIdentityModule(builder.Configuration)
    .AddAgentsModule(builder.Configuration)
    .AddNetworksModule(builder.Configuration)
    .AddScanningModule(builder.Configuration)
    .AddSchedulingModule(builder.Configuration)
    .AddWorkflowsModule(builder.Configuration)
    .AddSignaturesModule(builder.Configuration)
    .AddDiscoveryModule(builder.Configuration)
    .AddAnalyticsModule(builder.Configuration)
    .AddIntegrationsModule(builder.Configuration);

builder.Services.GetModuleDbContextRegistry();

var app = builder.Build();

if (app.Configuration.GetValue("Database:MigrateOnStartup", true))
    await app.Services.MigrateModuleDatabasesAsync();

app.UseWebScanInfrastructure();

app.MapIdentityEndpoints();
app.MapAgentsEndpoints();
app.MapNetworksEndpoints();
app.MapScanningEndpoints();
app.MapSchedulingEndpoints();
app.MapWorkflowsEndpoints();
app.MapSignaturesEndpoints();
app.MapDiscoveryEndpoints();
app.MapAnalyticsEndpoints();
app.MapIntegrationsEndpoints();

app.Run();

public partial class Program;
