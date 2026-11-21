using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using WebScan.Contracts;
using WebScan.Server.Kernel.Security;

namespace WebScan.Server.Infrastructure.Security;

/// <summary><c>Auth:Jwt</c> configuration section.</summary>
public sealed class JwtSettings
{
    public const string Section = "Auth:Jwt";

    public string Issuer { get; set; } = "webscan";
    public string Audience { get; set; } = "webscan";

    /// <summary>HMAC-SHA256 key (UTF-8, at least 32 characters). Generated randomly in Development when missing.</summary>
    public string? SigningKey { get; set; }

    public int AccessTokenMinutes { get; set; } = 60;

    internal SymmetricSecurityKey GetSecurityKey() => new(Encoding.UTF8.GetBytes(SigningKey!));
}

/// <summary>Agent principal claims and agent-specific policies (the AgentKey handler lives in the Agents module).</summary>
public static class AgentAuthorization
{
    /// <summary>Claim carrying the agent's <see cref="AgentStatus"/>; policies decide which statuses may call what.</summary>
    public const string StatusClaim = "webscan:agent_status";

    /// <summary>Authenticated agent that is Active or still PendingApproval (register / heartbeat only).</summary>
    public const string RegisteredPolicy = "AgentRegistered";
}

public sealed record IssuedToken(string AccessToken, DateTimeOffset ExpiresAt);

/// <summary>Issues user access tokens (JWT, HS256) validated by the <see cref="AuthSchemes.User"/> scheme.</summary>
public sealed class JwtTokenIssuer(IOptions<JwtSettings> settings, TimeProvider time)
{
    public const string DisplayNameClaim = "display_name";

    private readonly JsonWebTokenHandler _handler = new();

    public IssuedToken Issue(string userId, string userName, string displayName, IEnumerable<string> roles)
    {
        var jwt = settings.Value;
        var now = time.GetUtcNow();
        var expires = now.AddMinutes(jwt.AccessTokenMinutes);
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId),
            new(JwtRegisteredClaimNames.UniqueName, userName),
            new(DisplayNameClaim, displayName),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
        };
        claims.AddRange(roles.Select(r => new Claim("role", r)));

        var token = _handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = jwt.Issuer,
            Audience = jwt.Audience,
            Subject = new ClaimsIdentity(claims),
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = expires.UtcDateTime,
            SigningCredentials = new SigningCredentials(jwt.GetSecurityKey(), SecurityAlgorithms.HmacSha256),
        });
        return new IssuedToken(token, expires);
    }
}

internal sealed class HttpCurrentUser(IHttpContextAccessor accessor) : ICurrentUser
{
    private ClaimsPrincipal? Principal => accessor.HttpContext?.User;

    public bool IsAuthenticated => Principal?.Identity?.IsAuthenticated == true && Principal.GetAgentId() is null;
    public string? UserId => IsAuthenticated ? Principal!.GetUserId() : null;
    public string? UserName => IsAuthenticated ? Principal!.Identity!.Name : null;
    public bool IsInRole(string role) => IsAuthenticated && Principal!.IsInRole(role);
}

public static class AuthenticationSetup
{
    public static IServiceCollection AddWebScanAuth(this IServiceCollection services)
    {
        services.AddOptions<JwtSettings>()
            .BindConfiguration(JwtSettings.Section)
            .PostConfigure<IHostEnvironment>((s, env) =>
            {
                // Development convenience only: tokens become invalid after a restart.
                if (string.IsNullOrWhiteSpace(s.SigningKey) && env.IsDevelopment())
                    s.SigningKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
            })
            .Validate(s => s.SigningKey is { Length: >= 32 }, "Auth:Jwt:SigningKey must be configured (at least 32 characters).")
            .Validate(s => s.AccessTokenMinutes is > 0 and <= 24 * 60, "Auth:Jwt:AccessTokenMinutes must be between 1 and 1440.")
            .ValidateOnStart();

        services.AddAuthentication(AuthSchemes.User).AddJwtBearer(AuthSchemes.User);
        services.AddOptions<JwtBearerOptions>(AuthSchemes.User).Configure<IOptions<JwtSettings>>((o, settings) =>
        {
            var jwt = settings.Value;
            o.TokenValidationParameters = new TokenValidationParameters
            {
                ValidIssuer = jwt.Issuer,
                ValidAudience = jwt.Audience,
                IssuerSigningKey = jwt.GetSecurityKey(),
                ValidateIssuerSigningKey = true,
                ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
                ClockSkew = TimeSpan.FromSeconds(30),
            };
            o.Events = new JwtBearerEvents
            {
                OnMessageReceived = ctx =>
                {
                    // Browsers cannot set headers on WebSocket/SSE connections, so SignalR sends the token in the query.
                    if (ctx.Request.Path.StartsWithSegments("/hubs") && ctx.Request.Query.TryGetValue("access_token", out var token))
                        ctx.Token = token;
                    return Task.CompletedTask;
                },
            };
        });

        var authenticatedUser = new AuthorizationPolicyBuilder(AuthSchemes.User).RequireAuthenticatedUser().Build();
        services.AddAuthorizationBuilder()
            .SetDefaultPolicy(authenticatedUser)
            .SetFallbackPolicy(authenticatedUser)
            .AddPolicy(Policies.CanRead, UserPolicy(Roles.Administrator, Roles.Manager, Roles.Editor, Roles.Viewer))
            .AddPolicy(Policies.CanEdit, UserPolicy(Roles.Administrator, Roles.Manager, Roles.Editor))
            .AddPolicy(Policies.CanManage, UserPolicy(Roles.Administrator, Roles.Manager))
            .AddPolicy(Policies.AdminOnly, UserPolicy(Roles.Administrator))
            .AddPolicy(Policies.Agent, AgentPolicy(nameof(AgentStatus.Active)))
            .AddPolicy(AgentAuthorization.RegisteredPolicy, AgentPolicy(nameof(AgentStatus.Active), nameof(AgentStatus.PendingApproval)));

        services.AddHttpContextAccessor();
        services.AddScoped<ICurrentUser, HttpCurrentUser>();
        services.AddSingleton<JwtTokenIssuer>();
        return services;
    }

    private static AuthorizationPolicy UserPolicy(params string[] roles) =>
        new AuthorizationPolicyBuilder(AuthSchemes.User).RequireAuthenticatedUser().RequireRole(roles).Build();

    // Disabled/Blocked agents authenticate (so the caller learns why) but satisfy no policy → 403.
    private static AuthorizationPolicy AgentPolicy(params string[] statuses) =>
        new AuthorizationPolicyBuilder(AuthSchemes.Agent)
            .RequireAuthenticatedUser()
            .RequireClaim(WebScanClaims.AgentId)
            .RequireClaim(AgentAuthorization.StatusClaim, statuses)
            .Build();
}
