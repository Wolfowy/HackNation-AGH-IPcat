using System.Security.Claims;

namespace WebScan.Server.Kernel.Security;

/// <summary>RBAC roles (hierarchical: Administrator ⊃ Manager ⊃ Editor ⊃ Viewer).</summary>
public static class Roles
{
    /// <summary>Everything, incl. users, scope policy, agents, tools, settings, audit.</summary>
    public const string Administrator = "Administrator";

    /// <summary>"Zarządzanie": create / delete / modify networks, schedules, workflows, signatures, scans.</summary>
    public const string Manager = "Manager";

    /// <summary>"Edycja i odczyt": modify existing objects, run and cancel scans, annotate assets.</summary>
    public const string Editor = "Editor";

    /// <summary>"Tylko odczyt".</summary>
    public const string Viewer = "Viewer";

    public static readonly IReadOnlyList<string> All = [Administrator, Manager, Editor, Viewer];
}

/// <summary>Authorization policy names. Use with <c>RequireAuthorization(Policies.X)</c>.</summary>
public static class Policies
{
    public const string CanRead = "CanRead";       // Viewer, Editor, Manager, Administrator
    public const string CanEdit = "CanEdit";       // Editor, Manager, Administrator
    public const string CanManage = "CanManage";   // Manager, Administrator
    public const string AdminOnly = "AdminOnly";   // Administrator
    public const string Agent = "Agent";           // authenticated, active scanner agent (AgentKey scheme)
}

public static class AuthSchemes
{
    /// <summary>JWT bearer for users / UI.</summary>
    public const string User = "Bearer";

    /// <summary><c>Authorization: Agent {agentId}:{secret}</c>.</summary>
    public const string Agent = "AgentKey";
}

public static class WebScanClaims
{
    public const string AgentId = "webscan:agent_id";
    public const string UserId = ClaimTypes.NameIdentifier;
}

public static class ClaimsPrincipalExtensions
{
    public static string? GetAgentId(this ClaimsPrincipal principal) => principal.FindFirstValue(WebScanClaims.AgentId);

    public static string GetRequiredAgentId(this ClaimsPrincipal principal) =>
        principal.GetAgentId() ?? throw new UnauthorizedAccessException("Not an agent principal.");

    public static string? GetUserId(this ClaimsPrincipal principal) => principal.FindFirstValue(WebScanClaims.UserId);
}

/// <summary>Current human user (null-object for agents/background jobs).</summary>
public interface ICurrentUser
{
    string? UserId { get; }
    string? UserName { get; }
    bool IsAuthenticated { get; }
    bool IsInRole(string role);
}

/// <summary>Append-only audit trail. Implemented by Infrastructure; every mutating admin action must call it.</summary>
public interface IAuditLog
{
    Task WriteAsync(AuditEntry entry, CancellationToken ct = default);
}

/// <param name="Action">e.g. "network.created", "agent.blocked", "signature.approved".</param>
/// <param name="Details">Serialized to JSON; must not contain secrets.</param>
public sealed record AuditEntry(string Action, string EntityType, string? EntityId, object? Details = null);

/// <summary>Encrypts sensitive values at rest (ASP.NET Data Protection based).</summary>
public interface ISecretProtector
{
    string Protect(string plaintext);
    string Unprotect(string protectedValue);
}
