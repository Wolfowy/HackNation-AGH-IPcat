using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using WebScan.Contracts;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Scanning.Jobs;

namespace WebScan.Server.Modules.Scanning.Api;

/// <summary>Agent job protocol (<see cref="AgentApiRoutes"/>): 404 unknown job, 409 stale lease, 422 invalid payload.</summary>
public static class AgentJobEndpoints
{
    public static void MapAgentJobEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var jobs = endpoints.MapGroup("/api/agents/jobs").RequireAuthorization(Policies.Agent).WithTags("Agent jobs");

        jobs.MapPost("/claim", async (HttpRequest http, ClaimsPrincipal user, JobQueue queue, CancellationToken ct) =>
        {
            var (request, error) = await ReadAsync<JobClaimRequest>(http, ct);
            return request is null ? error! : Results.Ok(await queue.ClaimAsync(user.GetRequiredAgentId(), request, ct));
        });

        jobs.MapPost("/{jobId:guid}/heartbeat", async (Guid jobId, HttpRequest http, ClaimsPrincipal user, JobQueue queue, CancellationToken ct) =>
        {
            var (request, error) = await ReadAsync<JobHeartbeatRequest>(http, ct);
            return request is null ? error! : ToResult(await queue.HeartbeatAsync(user.GetRequiredAgentId(), jobId, request, ct));
        });

        jobs.MapPost("/{jobId:guid}/results", async (Guid jobId, HttpRequest http, ClaimsPrincipal user, JobQueue queue, CancellationToken ct) =>
        {
            var (batch, error) = await ReadAsync<ScanResultBatch>(http, ct);
            return batch is null ? error! : ToResult(await queue.SubmitResultsAsync(user.GetRequiredAgentId(), jobId, batch, ct));
        });

        jobs.MapPost("/{jobId:guid}/complete", async (Guid jobId, HttpRequest http, ClaimsPrincipal user, JobQueue queue, CancellationToken ct) =>
        {
            var (request, error) = await ReadAsync<JobCompletionRequest>(http, ct);
            return request is null ? error! : ToResult(await queue.CompleteAsync(user.GetRequiredAgentId(), jobId, request, ct), noBody: true);
        });

        jobs.MapPost("/{jobId:guid}/fail", async (Guid jobId, HttpRequest http, ClaimsPrincipal user, JobQueue queue, CancellationToken ct) =>
        {
            var (request, error) = await ReadAsync<JobFailureRequest>(http, ct);
            return request is null ? error! : ToResult(await queue.FailAsync(user.GetRequiredAgentId(), jobId, request, ct), noBody: true);
        });
    }

    /// <summary>Reads a contract body; malformed or incomplete JSON is a 422 (not the framework's 400).</summary>
    private static async Task<(T? Value, IResult? Error)> ReadAsync<T>(HttpRequest http, CancellationToken ct) where T : class
    {
        try
        {
            var value = await JsonSerializer.DeserializeAsync<T>(http.Body, ContractJson.Options, ct);
            return value is null ? (null, Invalid("Request body is required.")) : (value, null);
        }
        catch (JsonException ex)
        {
            return (null, Invalid($"Invalid request body: {ex.Message}"));
        }
    }

    private static IResult Invalid(string detail) =>
        Results.Problem(detail, statusCode: StatusCodes.Status422UnprocessableEntity, title: "Invalid payload");

    internal static IResult ToResult<T>(JobCallResult<T> result, bool noBody = false) => result.Status switch
    {
        JobCallStatus.Ok => noBody ? Results.Ok() : Results.Ok(result.Value),
        JobCallStatus.NotFound => Results.Problem(result.Error, statusCode: StatusCodes.Status404NotFound, title: "Not found"),
        JobCallStatus.Conflict => Results.Problem(result.Error, statusCode: StatusCodes.Status409Conflict, title: "Conflict"),
        _ => Invalid(result.Error ?? "Invalid payload."),
    };
}
