using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WebScan.Contracts;
using WebScan.Server.Infrastructure.Http;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Agents.Persistence;

namespace WebScan.Server.Modules.Agents;

public sealed record AgentToolDto(string Id, string Version, IReadOnlyList<string> Capabilities, bool Approved);

public sealed record LimitOverridesDto(int? MaxConcurrentJobs, int? MaxRatePerSecond);

public sealed record AgentDto(
    string AgentId, string Hostname, AgentStatus Status, bool IsOnline, DateTimeOffset? LastHeartbeatAt, DateTimeOffset RegisteredAt,
    string OsPlatform, string OsDescription, string AgentVersion, IReadOnlyList<AgentToolDto> Tools,
    IReadOnlyList<NetworkInterfaceInfo> Interfaces, IReadOnlyList<RouteInfo> Routes, IReadOnlyList<string> DeclaredZones,
    IReadOnlyList<string> AuthorizedZones, IReadOnlyList<Guid> AuthorizedNetworkIds, AgentLimits Limits, AgentLimits ReportedLimits,
    LimitOverridesDto LimitOverrides, AgentLoad? Load, bool RotateRequested);

public sealed record AgentStatusRequest(AgentStatus? Status);

public sealed record AgentAssignmentRequest(IReadOnlyList<string>? AuthorizedZones, IReadOnlyList<Guid>? AuthorizedNetworkIds,
    int? MaxConcurrentJobs, int? MaxRatePerSecond);

public sealed record EnrollmentTokenDto(Guid Id, string Name, DateTimeOffset ExpiresAt, int MaxUses, int Uses, bool AutoApprove,
    IReadOnlyList<string> Zones, bool Revoked, string? CreatedBy, DateTimeOffset CreatedAt);

public sealed record CreateEnrollmentTokenRequest(string? Name, int ExpiresInHours = 24, int MaxUses = 1, bool AutoApprove = false,
    IReadOnlyList<string>? Zones = null);

public sealed record CreatedEnrollmentTokenDto(Guid Id, string Name, string Token, DateTimeOffset ExpiresAt, int MaxUses, bool AutoApprove,
    IReadOnlyList<string> Zones);

public sealed record ToolDto(string ToolId, bool Approved, bool Enabled, IReadOnlyList<string> Capabilities, IReadOnlyList<string> Versions,
    int AgentCount, DateTimeOffset FirstSeenAt);

public sealed record UpdateToolRequest(bool Approved, bool Enabled);

/// <summary>Administration of agents, enrollment tokens and the tool catalog (UI API).</summary>
internal static partial class AgentAdminEndpoints
{
    [GeneratedRegex("^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")]
    internal static partial Regex ZoneNameRegex();

    public static void Map(IEndpointRouteBuilder endpoints)
    {
        var agents = endpoints.MapGroup("/api/agents");
        agents.MapGet("/", ListAgents).RequireAuthorization(Policies.CanRead);
        agents.MapGet("/{agentId}", GetAgent).RequireAuthorization(Policies.CanRead);
        agents.MapPost("/{agentId}/status", SetStatus).RequireAuthorization(Policies.AdminOnly);
        agents.MapPut("/{agentId}/assignment", SetAssignment).RequireAuthorization(Policies.AdminOnly);
        agents.MapPost("/{agentId}/rotate-credentials", RequestRotation).RequireAuthorization(Policies.AdminOnly);
        agents.MapDelete("/{agentId}", DeleteAgent).RequireAuthorization(Policies.AdminOnly);

        var tokens = endpoints.MapGroup("/api/enrollment-tokens").RequireAuthorization(Policies.AdminOnly);
        tokens.MapGet("/", ListTokens);
        tokens.MapPost("/", CreateToken);
        tokens.MapDelete("/{id:guid}", RevokeToken);

        var tools = endpoints.MapGroup("/api/tools");
        tools.MapGet("/", ListTools).RequireAuthorization(Policies.CanRead);
        tools.MapPut("/{toolId}", UpdateTool).RequireAuthorization(Policies.AdminOnly);
    }

    private static async Task<List<AgentDto>> ListAgents(AgentsDbContext db, IOptions<AgentsOptions> options, TimeProvider time, CancellationToken ct)
    {
        var agents = await db.Agents.AsNoTracking().OrderBy(a => a.AgentId).ToListAsync(ct);
        var usable = await UsableToolIdsAsync(db, ct);
        var now = time.GetUtcNow();
        return agents.Select(a => ToDto(a, usable, now, options.Value.HeartbeatTimeout)).ToList();
    }

    private static async Task<IResult> GetAgent(string agentId, AgentsDbContext db, IOptions<AgentsOptions> options, TimeProvider time, CancellationToken ct)
    {
        var agent = await db.Agents.AsNoTracking().SingleOrDefaultAsync(a => a.AgentId == agentId, ct);
        if (agent is null) return Results.NotFound();
        return Results.Ok(ToDto(agent, await UsableToolIdsAsync(db, ct), time.GetUtcNow(), options.Value.HeartbeatTimeout));
    }

    private static async Task<IResult> SetStatus(string agentId, AgentStatusRequest request, AgentsDbContext db, IAuditLog audit, CancellationToken ct)
    {
        if (request.Status is not (AgentStatus.Active or AgentStatus.Disabled or AgentStatus.Blocked))
            return ValidationErrors.Single("status", "Must be Active, Disabled or Blocked.");

        var agent = await db.Agents.SingleOrDefaultAsync(a => a.AgentId == agentId, ct);
        if (agent is null) return Results.NotFound();

        var previous = agent.Status;
        agent.Status = request.Status.Value;
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuditEntry($"agent.status.{agent.Status.ToString().ToLowerInvariant()}", "agent", agentId,
            new { from = previous, to = agent.Status }), ct);
        return Results.NoContent();
    }

    private static async Task<IResult> SetAssignment(string agentId, AgentAssignmentRequest request, AgentsDbContext db, IAuditLog audit,
        CancellationToken ct)
    {
        var errors = new ValidationErrors();
        ValidateZones(errors, "authorizedZones", request.AuthorizedZones);
        errors.Require(request.MaxConcurrentJobs is null or > 0, "maxConcurrentJobs", "Must be positive.");
        errors.Require(request.MaxRatePerSecond is null or > 0, "maxRatePerSecond", "Must be positive.");
        if (!errors.IsValid) return errors.ToResult();

        var agent = await db.Agents.SingleOrDefaultAsync(a => a.AgentId == agentId, ct);
        if (agent is null) return Results.NotFound();

        agent.AuthorizedZones = (request.AuthorizedZones ?? []).Distinct().ToList();
        agent.AuthorizedNetworkIds = (request.AuthorizedNetworkIds ?? []).Distinct().ToList();
        agent.MaxConcurrentJobsOverride = request.MaxConcurrentJobs;
        agent.MaxRatePerSecondOverride = request.MaxRatePerSecond;
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuditEntry("agent.assignment.updated", "agent", agentId, request), ct);
        return Results.NoContent();
    }

    private static async Task<IResult> RequestRotation(string agentId, AgentsDbContext db, IAuditLog audit, CancellationToken ct)
    {
        var agent = await db.Agents.SingleOrDefaultAsync(a => a.AgentId == agentId, ct);
        if (agent is null) return Results.NotFound();

        agent.RotateRequested = true;
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuditEntry("agent.credentials_rotation_requested", "agent", agentId), ct);
        return Results.Accepted();
    }

    private static async Task<IResult> DeleteAgent(string agentId, AgentsDbContext db, IAuditLog audit, CancellationToken ct)
    {
        var deleted = await db.Agents.Where(a => a.AgentId == agentId).ExecuteDeleteAsync(ct);
        if (deleted == 0) return Results.NotFound();
        await audit.WriteAsync(new AuditEntry("agent.deleted", "agent", agentId), ct);
        return Results.NoContent();
    }

    private static async Task<List<EnrollmentTokenDto>> ListTokens(AgentsDbContext db, CancellationToken ct) =>
        (await db.EnrollmentTokens.AsNoTracking().OrderByDescending(t => t.CreatedAt).ToListAsync(ct))
        .Select(t => new EnrollmentTokenDto(t.Id, t.Name, t.ExpiresAt, t.MaxUses, t.Uses, t.AutoApprove, t.Zones, t.Revoked, t.CreatedBy, t.CreatedAt))
        .ToList();

    private static async Task<IResult> CreateToken(CreateEnrollmentTokenRequest request, AgentsDbContext db, ICurrentUser user, IAuditLog audit,
        TimeProvider time, CancellationToken ct)
    {
        var errors = new ValidationErrors();
        errors.Require(request.Name is { Length: > 0 and <= 128 } && !string.IsNullOrWhiteSpace(request.Name), "name", "1-128 characters.");
        errors.Require(request.ExpiresInHours is > 0 and <= 24 * 365, "expiresInHours", "Between 1 and 8760 hours.");
        errors.Require(request.MaxUses is > 0 and <= 10_000, "maxUses", "Between 1 and 10000.");
        ValidateZones(errors, "zones", request.Zones);
        if (!errors.IsValid) return errors.ToResult();

        var now = time.GetUtcNow();
        var secret = AgentSecrets.NewSecret();
        var token = new EnrollmentToken
        {
            Id = Guid.CreateVersion7(),
            Name = request.Name!.Trim(),
            TokenHash = AgentSecrets.Hash(secret),
            ExpiresAt = now.AddHours(request.ExpiresInHours),
            MaxUses = request.MaxUses,
            AutoApprove = request.AutoApprove,
            Zones = (request.Zones ?? []).Distinct().ToList(),
            CreatedBy = user.UserName,
            CreatedAt = now,
        };
        db.EnrollmentTokens.Add(token);
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuditEntry("enrollment_token.created", "enrollment_token", token.Id.ToString(),
            new { token.Name, token.ExpiresAt, token.MaxUses, token.AutoApprove, token.Zones }), ct);
        return Results.Created($"/api/enrollment-tokens/{token.Id}",
            new CreatedEnrollmentTokenDto(token.Id, token.Name, secret, token.ExpiresAt, token.MaxUses, token.AutoApprove, token.Zones));
    }

    private static async Task<IResult> RevokeToken(Guid id, AgentsDbContext db, IAuditLog audit, CancellationToken ct)
    {
        var token = await db.EnrollmentTokens.SingleOrDefaultAsync(t => t.Id == id, ct);
        if (token is null) return Results.NotFound();
        token.Revoked = true;
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuditEntry("enrollment_token.revoked", "enrollment_token", id.ToString(), new { token.Name }), ct);
        return Results.NoContent();
    }

    private static async Task<List<ToolDto>> ListTools(AgentsDbContext db, CancellationToken ct)
    {
        var tools = await db.Tools.AsNoTracking().OrderBy(t => t.ToolId).ToListAsync(ct);
        var inventories = await db.Agents.AsNoTracking().Select(a => a.Inventory).ToListAsync(ct);
        var agentCounts = inventories.SelectMany(i => i.Tools.Select(t => t.Id).Distinct())
            .GroupBy(id => id).ToDictionary(g => g.Key, g => g.Count());
        return tools.Select(t => new ToolDto(t.ToolId, t.Approved, t.Enabled, t.Capabilities, t.Versions,
            agentCounts.GetValueOrDefault(t.ToolId), t.FirstSeenAt)).ToList();
    }

    private static async Task<IResult> UpdateTool(string toolId, UpdateToolRequest request, AgentsDbContext db, IAuditLog audit, CancellationToken ct)
    {
        var tool = await db.Tools.SingleOrDefaultAsync(t => t.ToolId == toolId, ct);
        if (tool is null) return Results.NotFound();
        tool.Approved = request.Approved;
        tool.Enabled = request.Enabled;
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuditEntry("tool.updated", "tool", toolId, new { tool.Approved, tool.Enabled }), ct);
        return Results.NoContent();
    }

    internal static async Task<HashSet<string>> UsableToolIdsAsync(AgentsDbContext db, CancellationToken ct) =>
        (await db.Tools.AsNoTracking().Where(t => t.Approved && t.Enabled).Select(t => t.ToolId).ToListAsync(ct)).ToHashSet();

    private static void ValidateZones(ValidationErrors errors, string field, IReadOnlyList<string>? zones) =>
        errors.Require(zones is null || zones.All(z => ZoneNameRegex().IsMatch(z ?? "")), field,
            "Zone names: 1-64 letters, digits, '_', '.', '-'.");

    private static AgentDto ToDto(Agent a, HashSet<string> usableTools, DateTimeOffset now, TimeSpan heartbeatTimeout) => new(
        a.AgentId, a.Hostname, a.Status, a.IsOnlineAt(now, heartbeatTimeout), a.LastHeartbeatAt, a.RegisteredAt,
        a.OsPlatform, a.OsDescription, a.AgentVersion,
        a.Inventory.Tools.Select(t => new AgentToolDto(t.Id, t.Version, t.Capabilities, usableTools.Contains(t.Id))).ToList(),
        a.Inventory.Interfaces, a.Inventory.Routes, a.DeclaredZones, a.AuthorizedZones, a.AuthorizedNetworkIds,
        a.EffectiveLimits,
        new AgentLimits { MaxConcurrentJobs = a.ReportedMaxConcurrentJobs, MaxRatePerSecond = a.ReportedMaxRatePerSecond },
        new LimitOverridesDto(a.MaxConcurrentJobsOverride, a.MaxRatePerSecondOverride),
        a.Load, a.RotateRequested);
}
