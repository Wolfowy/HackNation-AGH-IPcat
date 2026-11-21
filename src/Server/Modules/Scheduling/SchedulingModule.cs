using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Quartz;
using WebScan.Server.Infrastructure.Persistence;
using WebScan.Server.Modules.Scheduling.Api;
using WebScan.Server.Modules.Scheduling.Persistence;

namespace WebScan.Server.Modules.Scheduling;

/// <summary>
/// Scheduling module: schedules (cron + IANA time zone + allowed windows + overlap policy) stored in PostgreSQL and fired by
/// Quartz.NET (RAM store, rebuilt from the database at startup and on every change). Starts runs only through <c>IScanLauncher</c>.
/// </summary>
public static class SchedulingModule
{
    public static IServiceCollection AddSchedulingModule(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddModuleDbContext<SchedulingDbContext>(SchedulingDbContext.Schema);
        services.TryAddSingleton(TimeProvider.System);
        services.AddScoped<ScheduleFiringService>();

        services.AddQuartz(q => q.AddJob<ScheduleFireJob>(j => j.WithIdentity(ScheduleFireJob.Key).StoreDurably()));
        services.AddQuartzHostedService(o => o.WaitForJobsToComplete = true);
        services.AddSingleton<QuartzScheduleSync>();
        services.AddHostedService(sp => sp.GetRequiredService<QuartzScheduleSync>());
        return services;
    }

    public static IEndpointRouteBuilder MapSchedulingEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapScheduleEndpoints();
        return endpoints;
    }
}
