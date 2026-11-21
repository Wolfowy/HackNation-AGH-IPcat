using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WebScan.Contracts;
using WebScan.Server.Infrastructure.Http;
using WebScan.Server.Infrastructure.Security;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Agents.Persistence;

namespace WebScan.Server.Modules.Agents;

/// <summary>Agent-facing API: register (enrollment token or agent key), heartbeat, credential rotation.</summary>
internal static partial class AgentApiEndpoints
{
    [GeneratedRegex(AgentRegistration.AgentIdPattern)]
    internal static partial Regex AgentIdRegex();

    [GeneratedRegex("^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")]
    internal static partial Regex ToolIdRegex();

    [GeneratedRegex(ToolCapabilities.Pattern)]
    private static partial Regex CapabilityRegex();

    public static void Map(IEndpointRouteBuilder endpoints)
    {
        // Anonymous only for the enrollment path; re-registration authenticates explicitly with the agent key.
        endpoints.MapPost(AgentApiRoutes.Register, Register).AllowAnonymous();
        endpoints.MapPost(AgentApiRoutes.Heartbeat, Heartbeat).RequireAuthorization(AgentAuthorization.RegisteredPolicy);
        endpoints.MapPost(AgentApiRoutes.RotateCredentials, Rotate).RequireAuthorization(Policies.Agent);
    }

    private static async Task<IResult> Register(AgentRegistration registration, HttpContext http, AgentsDbContext db,
        ToolCatalog catalog, IOptions<AgentsOptions> options, IAuditLog audit, TimeProvider time, CancellationToken ct)
    {
        var errors = Validate(registration);
        if (!errors.IsValid) return errors.ToResult();

        var now = time.GetUtcNow();
        Agent agent;
        string? secret = null;

        if (http.Request.Headers.TryGetValue(AgentApiRoutes.EnrollmentTokenHeader, out var enrollmentHeader))
        {
            var tokenHash = AgentSecrets.Hash(enrollmentHeader.ToString());
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            var token = await db.EnrollmentTokens.SingleOrDefaultAsync(t => t.TokenHash == tokenHash, ct);
            // Atomic use counting: concurrent enrollments can never exceed MaxUses.
            var claimed = token is not null && await db.EnrollmentTokens
                .Where(t => t.Id == token.Id && !t.Revoked && t.ExpiresAt > now && t.Uses < t.MaxUses)
                .ExecuteUpdateAsync(s => s.SetProperty(t => t.Uses, t => t.Uses + 1), ct) == 1;
            if (!claimed)
                return Results.Problem(statusCode: StatusCodes.Status401Unauthorized, title: "Invalid, expired or exhausted enrollment token.");

            if (await db.Agents.AnyAsync(a => a.AgentId == registration.AgentId, ct))
                return Results.Problem(statusCode: StatusCodes.Status409Conflict,
                    title: $"Agent '{registration.AgentId}' is already enrolled. Re-register with its credentials or ask an administrator to delete it.");

            secret = AgentSecrets.NewSecret();
            agent = new Agent
            {
                AgentId = registration.AgentId,
                Hostname = registration.Hostname,
                OsPlatform = registration.OsPlatform,
                OsDescription = registration.OsDescription,
                AgentVersion = registration.AgentVersion,
                Status = token!.AutoApprove ? AgentStatus.Active : AgentStatus.PendingApproval,
                RegisteredAt = now,
                AuthorizedZones = token.Zones.ToList(),
                SecretHash = AgentSecrets.Hash(secret),
                EnrollmentTokenId = token.Id,
            };
            agent.ApplyRegistration(registration, now);
            db.Agents.Add(agent);
            await db.SaveChangesAsync(ct);
            await tx.CommitAsync(ct);
            await audit.WriteAsync(new AuditEntry("agent.enrolled", "agent", agent.AgentId,
                new { agent.Hostname, agent.Status, enrollmentToken = token.Name, agent.AuthorizedZones }), ct);
        }
        else
        {
            var auth = await http.AuthenticateAsync(AuthSchemes.Agent);
            if (!auth.Succeeded) return Results.Challenge(authenticationSchemes: [AuthSchemes.Agent]);
            if (auth.Principal.GetAgentId() != registration.AgentId)
                return Results.Problem(statusCode: StatusCodes.Status403Forbidden, title: "Agent id does not match the credentials.");

            agent = await db.Agents.SingleAsync(a => a.AgentId == registration.AgentId, ct);
            if (agent.Status is AgentStatus.Disabled or AgentStatus.Blocked)
                return Results.Problem(statusCode: StatusCodes.Status403Forbidden, title: $"Agent is {agent.Status}.");

            agent.ApplyRegistration(registration, now);
            await db.SaveChangesAsync(ct);
        }

        var unapproved = await catalog.RecordAsync(registration.Tools, ct);
        var settings = options.Value;
        return Results.Ok(new AgentRegistrationResponse
        {
            AgentId = agent.AgentId,
            Status = agent.Status,
            AgentSecret = secret,
            HeartbeatIntervalSeconds = settings.HeartbeatIntervalSeconds,
            JobPollIntervalSeconds = settings.JobPollIntervalSeconds,
            UnapprovedTools = unapproved,
        });
    }

    private static async Task<IResult> Heartbeat(AgentHeartbeat heartbeat, HttpContext http, AgentsDbContext db, TimeProvider time,
        IServiceProvider services, ILoggerFactory loggers, CancellationToken ct)
    {
        if (http.User.GetAgentId() != heartbeat.AgentId)
            return Results.Problem(statusCode: StatusCodes.Status403Forbidden, title: "Agent id does not match the credentials.");

        var agent = await db.Agents.SingleOrDefaultAsync(a => a.AgentId == heartbeat.AgentId, ct);
        if (agent is null) return Results.Unauthorized();

        var now = time.GetUtcNow();
        var cameOnline = !agent.IsOnline;
        agent.IsOnline = true;
        agent.LastHeartbeatAt = now;
        agent.Load = heartbeat.Load;
        agent.InventoryHash ??= heartbeat.InventoryHash;
        var reRegister = heartbeat.InventoryHash is not null && agent.InventoryHash != heartbeat.InventoryHash;
        await db.SaveChangesAsync(ct);

        if (cameOnline)
            await AgentEvents.PublishAsync(services, loggers, ScanExecutionEventType.AgentOnline, agent.AgentId, now, "Agent is online.", ct);

        return Results.Ok(new AgentHeartbeatResponse
        {
            Status = agent.Status,
            ReRegisterRequired = reRegister,
            RotateCredentials = agent.RotateRequested && agent.Status == AgentStatus.Active,
            ServerTime = now,
        });
    }

    private static async Task<IResult> Rotate(HttpContext http, AgentsDbContext db, IOptions<AgentsOptions> options, IAuditLog audit,
        TimeProvider time, CancellationToken ct)
    {
        var agentId = http.User.GetRequiredAgentId();
        var agent = await db.Agents.SingleOrDefaultAsync(a => a.AgentId == agentId, ct);
        if (agent is null) return Results.Unauthorized();

        var secret = AgentSecrets.NewSecret();
        var validUntil = time.GetUtcNow().AddMinutes(options.Value.SecretRotationGraceMinutes);
        agent.PreviousSecretHash = agent.SecretHash;
        agent.PreviousSecretValidUntil = validUntil;
        agent.SecretHash = AgentSecrets.Hash(secret);
        agent.RotateRequested = false;
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuditEntry("agent.credentials_rotated", "agent", agentId, new { previousSecretValidUntil = validUntil }), ct);

        return Results.Ok(new AgentCredentialRotationResponse { AgentSecret = secret, PreviousSecretValidUntil = validUntil });
    }

    internal static ValidationErrors Validate(AgentRegistration r)
    {
        var errors = new ValidationErrors();
        errors.Require(AgentIdRegex().IsMatch(r.AgentId ?? ""), "agentId", $"Must match {AgentRegistration.AgentIdPattern}.");
        errors.Require(r.Hostname is { Length: > 0 and <= 255 }, "hostname", "1-255 characters.");
        errors.Require(r.OsPlatform is { Length: > 0 and <= 32 }, "osPlatform", "1-32 characters.");
        errors.Require(r.OsDescription is { Length: <= 256 }, "osDescription", "Max 256 characters.");
        errors.Require(r.AgentVersion is { Length: > 0 and <= 64 }, "agentVersion", "1-64 characters.");
        errors.Require(r.Tools is { Count: <= 100 }, "tools", "Max 100 tools.");
        foreach (var tool in r.Tools ?? [])
        {
            errors.Require(ToolIdRegex().IsMatch(tool.Id ?? ""), "tools", $"Invalid tool id '{tool.Id}'.");
            errors.Require(tool.Version is { Length: <= 64 }, "tools", $"Tool '{tool.Id}': version max 64 characters.");
            errors.Require(tool.Capabilities is not null && tool.Capabilities.All(c => CapabilityRegex().IsMatch(c ?? "")), "tools",
                $"Tool '{tool.Id}': capabilities must match {ToolCapabilities.Pattern}.");
        }
        errors.Require(r.Interfaces is { Count: <= 256 }, "interfaces", "Max 256 interfaces.");
        errors.Require(r.Routes is { Count: <= 4096 }, "routes", "Max 4096 routes.");
        errors.Require(r.DeclaredZones is not null && r.DeclaredZones.All(z => z is { Length: > 0 and <= 64 }), "declaredZones", "Zone names 1-64 characters.");
        errors.Require(r.Limits is { MaxConcurrentJobs: > 0, MaxRatePerSecond: > 0 }, "limits", "Limits must be positive.");
        return errors;
    }
}

/// <summary>Emits agent online/offline execution events when the Scanning module provides <see cref="IScanEventPublisher"/>.</summary>
internal static class AgentEvents
{
    public static async Task PublishAsync(IServiceProvider services, ILoggerFactory loggers, ScanExecutionEventType type, string agentId,
        DateTimeOffset at, string message, CancellationToken ct)
    {
        var publisher = services.GetService<IScanEventPublisher>();
        if (publisher is null) return;
        try
        {
            await publisher.PublishAsync(new ScanExecutionEvent
            {
                EventId = Guid.CreateVersion7(),
                OccurredAt = at,
                Type = type,
                AgentId = agentId,
                Message = message,
            }, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Events are informational; the agent state change itself is already persisted.
            loggers.CreateLogger(typeof(AgentEvents)).LogWarning(ex, "Publishing {EventType} for agent {AgentId} failed", type, agentId);
        }
    }
}
