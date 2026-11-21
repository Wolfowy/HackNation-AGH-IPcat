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

// TODO(Agent A): infrastructure (auth schemes + policies, Wolverine/RabbitMQ incl. ModuleAssemblies.All,
// OpenTelemetry, ProblemDetails, request decompression, SignalR, Data Protection, audit, CORS, health checks).

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

app.MapGet("/health/live", () => Results.Ok(new { status = "ok" }));

app.Run();

public partial class Program;
