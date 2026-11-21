using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using WebScan.Server.Kernel.Discovery;
using WebScan.Server.Kernel.Security;

namespace WebScan.Server.Modules.Analytics;

/// <summary>
/// Run-to-run analysis over the observation store (read through <see cref="IObservationReader"/>). Change detection and
/// time-of-day variance live in the Discovery module next to the state they advance.
/// </summary>
public static class AnalyticsModule
{
    public static IServiceCollection AddAnalyticsModule(this IServiceCollection services, IConfiguration configuration) => services;

    public static IEndpointRouteBuilder MapAnalyticsEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/scans/{runId:guid}/diff", async (Guid runId, Guid? baseline, IObservationReader reader, CancellationToken ct) =>
        {
            if (baseline is null)
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["baseline"] = ["Query parameter 'baseline' (run id) is required."] });
            var diff = await RunDiff.ComputeAsync(runId, baseline.Value, reader.ReadRunObservationsAsync(runId, ct),
                reader.ReadRunObservationsAsync(baseline.Value, ct), ct);
            return Results.Ok(diff);
        }).RequireAuthorization(Policies.CanRead).WithTags("Analytics");
        return endpoints;
    }
}
