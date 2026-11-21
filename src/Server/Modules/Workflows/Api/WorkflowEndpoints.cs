using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using WebScan.Contracts;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Scanning.Planning;
using WebScan.Server.Modules.Workflows.Definitions;

namespace WebScan.Server.Modules.Workflows.Api;

public sealed record OperationsDto(IReadOnlyList<OperationDescriptor> Operations, IReadOnlyDictionary<string, string> CapabilityMapping);
public sealed record ValidationResultDto(bool Valid, IReadOnlyList<string> Errors);

public static class WorkflowEndpoints
{
    public static void MapWorkflowEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/operations", (IOptions<PlannerOptions> planner) =>
                new OperationsDto(OperationCatalog.All.Values.OrderBy(o => o.Operation).ToList(), planner.Value.EffectiveCapabilityMapping()))
            .RequireAuthorization(Policies.CanRead).WithTags("Workflows");

        var workflows = endpoints.MapGroup("/api/workflows").WithTags("Workflows");

        workflows.MapGet("", (WorkflowDefinitionStore store, CancellationToken ct) => store.ListAsync(ct)).RequireAuthorization(Policies.CanRead);

        workflows.MapGet("/{key}", async (string key, WorkflowDefinitionStore store, CancellationToken ct) =>
            await store.GetAsync(key, null, ct) is { } wf ? Results.Ok(wf) : Results.NotFound()).RequireAuthorization(Policies.CanRead);

        workflows.MapGet("/{key}/versions", async (string key, WorkflowDefinitionStore store, CancellationToken ct) =>
            await store.VersionsAsync(key, ct) is { Count: > 0 } versions ? Results.Ok(versions) : Results.NotFound()).RequireAuthorization(Policies.CanRead);

        workflows.MapGet("/{key}/versions/{version:int}", async (string key, int version, WorkflowDefinitionStore store, CancellationToken ct) =>
            await store.GetAsync(key, version, ct) is { } wf ? Results.Ok(wf) : Results.NotFound()).RequireAuthorization(Policies.CanRead);

        workflows.MapPost("", async (HttpRequest http, ClaimsPrincipal user, WorkflowDefinitionStore store, IAuditLog audit, CancellationToken ct) =>
        {
            var (definition, error) = await ReadDefinitionAsync(http, ct);
            if (definition is null) return Invalid([error!]);
            var result = await store.CreateAsync(definition, UserName(user), ct);
            if (result.Status == SaveStatus.Saved)
                await audit.WriteAsync(new AuditEntry("workflow.created", "Workflow", $"{result.Saved!.Key}:{result.Saved.Version}"), ct);
            return ToResult(result);
        }).RequireAuthorization(Policies.CanManage);

        workflows.MapPost("/{key}/versions", async (string key, HttpRequest http, ClaimsPrincipal user, WorkflowDefinitionStore store, IAuditLog audit, CancellationToken ct) =>
        {
            var (definition, error) = await ReadDefinitionAsync(http, ct);
            if (definition is null) return Invalid([error!]);
            var result = await store.AddVersionAsync(key, definition, UserName(user), ct);
            if (result.Status == SaveStatus.Saved)
                await audit.WriteAsync(new AuditEntry("workflow.version-created", "Workflow", $"{result.Saved!.Key}:{result.Saved.Version}"), ct);
            return ToResult(result);
        }).RequireAuthorization(Policies.CanManage);

        workflows.MapPost("/validate", async (HttpRequest http, CancellationToken ct) =>
        {
            var (definition, error) = await ReadDefinitionAsync(http, ct);
            var errors = definition is null ? [error!] : WorkflowValidator.Validate(definition);
            return new ValidationResultDto(errors.Count == 0, errors);
        }).RequireAuthorization(Policies.CanRead);
    }

    internal static string UserName(ClaimsPrincipal user) => user.Identity?.Name ?? user.GetUserId() ?? "unknown";

    private static async Task<(ScanWorkflowDefinition? Definition, string? Error)> ReadDefinitionAsync(HttpRequest http, CancellationToken ct)
    {
        try
        {
            var definition = await JsonSerializer.DeserializeAsync<ScanWorkflowDefinition>(http.Body, ContractJson.Options, ct);
            return definition is null ? (null, "A workflow definition is required.") : (definition, null);
        }
        catch (JsonException ex)
        {
            return (null, $"Invalid workflow JSON: {ex.Message}");
        }
    }

    private static IResult Invalid(IReadOnlyList<string> errors) =>
        Results.ValidationProblem(new Dictionary<string, string[]> { ["definition"] = [.. errors] }, statusCode: StatusCodes.Status422UnprocessableEntity);

    private static IResult ToResult(SaveResult result) => result.Status switch
    {
        SaveStatus.Saved => Results.Created($"/api/workflows/{result.Saved!.Key}/versions/{result.Saved.Version}", result.Saved),
        SaveStatus.Invalid => Invalid(result.Errors!),
        SaveStatus.NotFound => Results.Problem(result.Errors![0], statusCode: StatusCodes.Status404NotFound),
        _ => Results.Problem(result.Errors![0], statusCode: StatusCodes.Status409Conflict),
    };
}
