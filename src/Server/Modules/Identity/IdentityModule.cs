using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WebScan.Server.Infrastructure.Http;
using WebScan.Server.Infrastructure.Persistence;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Identity.Persistence;

namespace WebScan.Server.Modules.Identity;

public static class IdentityModule
{
    public static IServiceCollection AddIdentityModule(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddModuleDbContext<IdentityDbContext>(IdentityDbContext.Schema);
        services.AddSingleton<IPasswordHasher<User>, PasswordHasher<User>>();
        services.AddHostedService<BootstrapAdminInitializer>();
        return services;
    }

    public static IEndpointRouteBuilder MapIdentityEndpoints(this IEndpointRouteBuilder endpoints)
    {
        IdentityEndpoints.Map(endpoints);
        return endpoints;
    }
}

/// <summary>
/// Creates the first administrator from <c>Bootstrap:AdminUserName</c> / <c>Bootstrap:AdminPassword</c> when the user store is empty.
/// There is no built-in default password: startup fails with a clear message if the values are missing.
/// </summary>
internal sealed class BootstrapAdminInitializer(IServiceScopeFactory scopes, IConfiguration configuration, TimeProvider time,
    ILogger<BootstrapAdminInitializer> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        if (await db.Users.AnyAsync(cancellationToken)) return;

        var userName = configuration["Bootstrap:AdminUserName"];
        var password = configuration["Bootstrap:AdminPassword"];
        var errors = new ValidationErrors().Require(!string.IsNullOrWhiteSpace(userName), "Bootstrap:AdminUserName", "is required");
        IdentityEndpoints.ValidatePassword(errors, password);
        if (!errors.IsValid)
        {
            var message = "No users exist and the bootstrap administrator is not configured correctly. Set Bootstrap:AdminUserName and " +
                          $"Bootstrap:AdminPassword (min {IdentityEndpoints.MinPasswordLength} characters). Problems: {string.Join("; ", errors.Messages)}";
            logger.LogCritical("{Message}", message);
            throw new InvalidOperationException(message);
        }

        var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher<User>>();
        var user = new User
        {
            Id = Guid.CreateVersion7(),
            UserName = userName!.Trim(),
            NormalizedUserName = User.Normalize(userName),
            DisplayName = "Administrator",
            Roles = [Roles.Administrator],
            CreatedAt = time.GetUtcNow(),
        };
        user.PasswordHash = hasher.HashPassword(user, password!);
        db.Users.Add(user);
        await db.SaveChangesAsync(cancellationToken);
        await scope.ServiceProvider.GetRequiredService<IAuditLog>()
            .WriteAsync(new AuditEntry("user.bootstrapped", "user", user.Id.ToString(), new { user.UserName }), cancellationToken);
        logger.LogWarning("Bootstrap administrator '{UserName}' created. Change its password after the first login.", user.UserName);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
