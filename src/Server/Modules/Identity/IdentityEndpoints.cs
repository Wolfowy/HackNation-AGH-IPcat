using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using WebScan.Server.Infrastructure.Http;
using WebScan.Server.Infrastructure.Security;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Identity.Persistence;

namespace WebScan.Server.Modules.Identity;

public sealed record LoginRequest(string? UserName, string? Password);

public sealed record UserDto(Guid Id, string UserName, string DisplayName, IReadOnlyList<string> Roles, bool IsActive,
    DateTimeOffset CreatedAt, DateTimeOffset? LastLoginAt)
{
    public static UserDto From(User u) => new(u.Id, u.UserName, u.DisplayName, u.Roles, u.IsActive, u.CreatedAt, u.LastLoginAt);
}

public sealed record LoginResponse(string AccessToken, DateTimeOffset ExpiresAt, UserDto User);

public sealed record CreateUserRequest(string? UserName, string? DisplayName, string? Password, IReadOnlyList<string>? Roles, bool IsActive = true);

public sealed record UpdateUserRequest(string? DisplayName, IReadOnlyList<string>? Roles, bool? IsActive);

public sealed record SetPasswordRequest(string? Password);

internal static partial class IdentityEndpoints
{
    public const int MinPasswordLength = 12;
    public const int MaxPasswordLength = 256;

    [GeneratedRegex("^[a-zA-Z0-9][a-zA-Z0-9_.@-]{2,63}$")]
    private static partial Regex UserNameRegex();

    public static void Map(IEndpointRouteBuilder endpoints)
    {
        var auth = endpoints.MapGroup("/api/auth");
        auth.MapPost("/login", Login).AllowAnonymous();
        auth.MapGet("/me", Me).RequireAuthorization(Policies.CanRead);

        var users = endpoints.MapGroup("/api/users").RequireAuthorization(Policies.AdminOnly);
        users.MapGet("/", ListUsers);
        users.MapPost("/", CreateUser);
        users.MapPut("/{id:guid}", UpdateUser);
        users.MapDelete("/{id:guid}", DeleteUser);
        users.MapPost("/{id:guid}/password", SetPassword);
    }

    private static async Task<IResult> Login(LoginRequest request, IdentityDbContext db, IPasswordHasher<User> hasher,
        JwtTokenIssuer tokens, IAuditLog audit, TimeProvider time, CancellationToken ct)
    {
        var invalid = Results.Problem(statusCode: StatusCodes.Status401Unauthorized, title: "Invalid user name or password.");
        if (string.IsNullOrWhiteSpace(request.UserName) || string.IsNullOrEmpty(request.Password) || request.Password.Length > MaxPasswordLength)
            return invalid;

        var now = time.GetUtcNow();
        var normalized = User.Normalize(request.UserName);
        var user = await db.Users.SingleOrDefaultAsync(u => u.NormalizedUserName == normalized, ct);
        if (user is null)
        {
            PasswordTiming.Equalize(hasher, request.Password);
            await audit.WriteAsync(new AuditEntry("auth.login_failed", "user", null, new { userName = request.UserName, reason = "unknown_user" }), ct);
            return invalid;
        }

        string? failure = null;
        if (user.IsLockedOut(now)) failure = "locked_out";
        else if (!user.IsActive) failure = "inactive";
        else
        {
            var result = hasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);
            if (result == PasswordVerificationResult.Failed)
            {
                user.RegisterFailedLogin(now);
                failure = user.IsLockedOut(now) ? "bad_password_locked" : "bad_password";
            }
            else if (result == PasswordVerificationResult.SuccessRehashNeeded)
            {
                user.PasswordHash = hasher.HashPassword(user, request.Password);
            }
        }

        if (failure is not null)
        {
            await db.SaveChangesAsync(ct);
            await audit.WriteAsync(new AuditEntry("auth.login_failed", "user", user.Id.ToString(), new { userName = user.UserName, reason = failure }), ct);
            return invalid;
        }

        user.RegisterSuccessfulLogin(now);
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuditEntry("auth.login", "user", user.Id.ToString(), new { userName = user.UserName }), ct);

        var token = tokens.Issue(user.Id.ToString(), user.UserName, user.DisplayName, user.Roles);
        return Results.Ok(new LoginResponse(token.AccessToken, token.ExpiresAt, UserDto.From(user)));
    }

    private static async Task<IResult> Me(ICurrentUser current, IdentityDbContext db, CancellationToken ct)
    {
        if (!Guid.TryParse(current.UserId, out var id)) return Results.Unauthorized();
        var user = await db.Users.AsNoTracking().SingleOrDefaultAsync(u => u.Id == id, ct);
        return user is { IsActive: true } ? Results.Ok(UserDto.From(user)) : Results.Unauthorized();
    }

    private static async Task<List<UserDto>> ListUsers(IdentityDbContext db, CancellationToken ct) =>
        (await db.Users.AsNoTracking().OrderBy(u => u.UserName).ToListAsync(ct)).Select(UserDto.From).ToList();

    private static async Task<IResult> CreateUser(CreateUserRequest request, IdentityDbContext db, IPasswordHasher<User> hasher,
        IAuditLog audit, TimeProvider time, CancellationToken ct)
    {
        var errors = new ValidationErrors();
        errors.Require(request.UserName is not null && UserNameRegex().IsMatch(request.UserName), "userName",
            "3-64 characters: letters, digits, '_', '.', '@', '-'; must start with a letter or digit.");
        ValidatePassword(errors, request.Password);
        ValidateRoles(errors, request.Roles);
        ValidateDisplayName(errors, request.DisplayName);
        if (!errors.IsValid) return errors.ToResult();

        var normalized = User.Normalize(request.UserName!);
        if (await db.Users.AnyAsync(u => u.NormalizedUserName == normalized, ct))
            return Results.Problem(statusCode: StatusCodes.Status409Conflict, title: $"User '{request.UserName}' already exists.");

        var user = new User
        {
            Id = Guid.CreateVersion7(),
            UserName = request.UserName!.Trim(),
            NormalizedUserName = normalized,
            DisplayName = string.IsNullOrWhiteSpace(request.DisplayName) ? request.UserName!.Trim() : request.DisplayName.Trim(),
            Roles = request.Roles!.Distinct().ToList(),
            IsActive = request.IsActive,
            CreatedAt = time.GetUtcNow(),
        };
        user.PasswordHash = hasher.HashPassword(user, request.Password!);
        db.Users.Add(user);
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuditEntry("user.created", "user", user.Id.ToString(), new { user.UserName, user.Roles, user.IsActive }), ct);
        return Results.Created($"/api/users/{user.Id}", UserDto.From(user));
    }

    private static async Task<IResult> UpdateUser(Guid id, UpdateUserRequest request, IdentityDbContext db, IAuditLog audit, CancellationToken ct)
    {
        var errors = new ValidationErrors();
        if (request.Roles is not null) ValidateRoles(errors, request.Roles);
        ValidateDisplayName(errors, request.DisplayName);
        if (!errors.IsValid) return errors.ToResult();

        var user = await db.Users.SingleOrDefaultAsync(u => u.Id == id, ct);
        if (user is null) return Results.NotFound();

        if (!string.IsNullOrWhiteSpace(request.DisplayName)) user.DisplayName = request.DisplayName.Trim();
        if (request.Roles is not null) user.Roles = request.Roles.Distinct().ToList();
        if (request.IsActive is { } active) user.IsActive = active;

        if (await WouldRemoveLastAdministratorAsync(db, user, ct))
            return Results.Problem(statusCode: StatusCodes.Status409Conflict, title: "At least one active administrator must remain.");

        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuditEntry("user.updated", "user", user.Id.ToString(), new { user.UserName, user.DisplayName, user.Roles, user.IsActive }), ct);
        return Results.Ok(UserDto.From(user));
    }

    private static async Task<IResult> DeleteUser(Guid id, IdentityDbContext db, ICurrentUser current, IAuditLog audit, CancellationToken ct)
    {
        if (current.UserId == id.ToString())
            return Results.Problem(statusCode: StatusCodes.Status409Conflict, title: "You cannot delete your own account.");

        var user = await db.Users.SingleOrDefaultAsync(u => u.Id == id, ct);
        if (user is null) return Results.NotFound();

        user.IsActive = false; // evaluate the remaining administrators as if this user were gone
        if (await WouldRemoveLastAdministratorAsync(db, user, ct))
            return Results.Problem(statusCode: StatusCodes.Status409Conflict, title: "At least one active administrator must remain.");

        db.Users.Remove(user);
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuditEntry("user.deleted", "user", id.ToString(), new { user.UserName }), ct);
        return Results.NoContent();
    }

    private static async Task<IResult> SetPassword(Guid id, SetPasswordRequest request, IdentityDbContext db, IPasswordHasher<User> hasher,
        IAuditLog audit, CancellationToken ct)
    {
        var errors = new ValidationErrors();
        ValidatePassword(errors, request.Password);
        if (!errors.IsValid) return errors.ToResult();

        var user = await db.Users.SingleOrDefaultAsync(u => u.Id == id, ct);
        if (user is null) return Results.NotFound();

        user.PasswordHash = hasher.HashPassword(user, request.Password!);
        user.FailedLoginCount = 0;
        user.LockoutEndAt = null;
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(new AuditEntry("user.password_changed", "user", id.ToString(), new { user.UserName }), ct);
        return Results.NoContent();
    }

    /// <summary>True when <paramref name="changed"/> (tracked, modified) leaves no active administrator.</summary>
    private static async Task<bool> WouldRemoveLastAdministratorAsync(IdentityDbContext db, User changed, CancellationToken ct)
    {
        if (changed.IsActive && changed.Roles.Contains(Roles.Administrator)) return false;
        var otherAdmins = await db.Users.AsNoTracking()
            .CountAsync(u => u.Id != changed.Id && u.IsActive && u.Roles.Contains(Roles.Administrator), ct);
        return otherAdmins == 0;
    }

    internal static void ValidatePassword(ValidationErrors errors, string? password) =>
        errors.Require(password is { Length: >= MinPasswordLength and <= MaxPasswordLength }, "password",
            $"Password must be {MinPasswordLength}-{MaxPasswordLength} characters long.");

    private static void ValidateRoles(ValidationErrors errors, IReadOnlyList<string>? roles) =>
        errors.Require(roles is { Count: > 0 } && roles.All(r => Roles.All.Contains(r)), "roles",
            $"At least one role required; allowed: {string.Join(", ", Roles.All)}.");

    private static void ValidateDisplayName(ValidationErrors errors, string? displayName) =>
        errors.Require(displayName is null || displayName.Length <= 256, "displayName", "Max 256 characters.");
}

/// <summary>Runs one hash verification for unknown user names so response times do not reveal which accounts exist.</summary>
internal static class PasswordTiming
{
    private static readonly User Dummy = new() { UserName = "-", NormalizedUserName = "-", DisplayName = "-" };
    private static string? _dummyHash;

    public static void Equalize(IPasswordHasher<User> hasher, string password)
    {
        _dummyHash ??= hasher.HashPassword(Dummy, Guid.NewGuid().ToString());
        hasher.VerifyHashedPassword(Dummy, _dummyHash, password);
    }
}
