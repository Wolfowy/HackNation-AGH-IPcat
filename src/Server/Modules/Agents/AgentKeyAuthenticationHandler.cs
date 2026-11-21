using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WebScan.Contracts;
using WebScan.Server.Infrastructure.Security;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Agents.Persistence;

namespace WebScan.Server.Modules.Agents;

/// <summary>
/// <c>Authorization: Agent {agentId}:{secret}</c>. Accepts the current secret, or the previous one during the rotation grace period.
/// Every known agent authenticates with its status claim; the authorization policies reject Disabled/Blocked (403)
/// and restrict PendingApproval to register/heartbeat.
/// </summary>
internal sealed class AgentKeyAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    AgentsDbContext db) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    private const string Prefix = AgentApiRoutes.AuthorizationScheme + " ";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        string? header = Request.Headers.Authorization;
        if (header is null || !header.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
            return AuthenticateResult.NoResult();

        var credential = header[Prefix.Length..].Trim();
        var separator = credential.IndexOf(':');
        if (separator <= 0 || separator == credential.Length - 1)
            return AuthenticateResult.Fail("Malformed agent credentials.");

        var agentId = credential[..separator];
        var secret = credential[(separator + 1)..];
        var agent = await db.Agents.AsNoTracking()
            .Where(a => a.AgentId == agentId)
            .Select(a => new { a.AgentId, a.Status, a.SecretHash, a.PreviousSecretHash, a.PreviousSecretValidUntil })
            .SingleOrDefaultAsync(Context.RequestAborted);
        if (agent is null) return AuthenticateResult.Fail("Invalid agent credentials.");

        var valid = AgentSecrets.Matches(secret, agent.SecretHash)
                    || (agent.PreviousSecretValidUntil > TimeProvider.GetUtcNow() && AgentSecrets.Matches(secret, agent.PreviousSecretHash));
        if (!valid) return AuthenticateResult.Fail("Invalid agent credentials.");

        var identity = new ClaimsIdentity(
        [
            new Claim(WebScanClaims.AgentId, agent.AgentId),
            new Claim(ClaimTypes.Name, agent.AgentId),
            new Claim(AgentAuthorization.StatusClaim, agent.Status.ToString()),
        ], Scheme.Name);
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.Headers.WWWAuthenticate = AgentApiRoutes.AuthorizationScheme;
        return base.HandleChallengeAsync(properties);
    }
}
