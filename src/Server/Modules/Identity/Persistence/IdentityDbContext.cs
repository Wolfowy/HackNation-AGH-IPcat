using Microsoft.EntityFrameworkCore;
using WebScan.Server.Infrastructure.Persistence;

namespace WebScan.Server.Modules.Identity.Persistence;

public sealed class IdentityDbContext(DbContextOptions<IdentityDbContext> options) : DbContext(options)
{
    public const string Schema = "identity";

    public DbSet<User> Users => Set<User>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.HasDefaultSchema(Schema);
        modelBuilder.Entity<User>(e =>
        {
            e.ToTable("users");
            e.HasKey(x => x.Id);
            e.Property(x => x.UserName).HasMaxLength(User.MaxUserNameLength);
            e.Property(x => x.NormalizedUserName).HasMaxLength(User.MaxUserNameLength);
            e.HasIndex(x => x.NormalizedUserName).IsUnique();
            e.Property(x => x.DisplayName).HasEncryptedConversion(); // personal data; length validated by the API
            e.Property(x => x.PasswordHash).HasMaxLength(512);
        });
    }
}

public sealed class User
{
    public const int MaxUserNameLength = 64;
    public const int MaxFailedLogins = 5;
    public static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

    public Guid Id { get; set; }
    public required string UserName { get; set; }

    /// <summary>Upper-invariant user name; unique (user names are case-insensitive).</summary>
    public required string NormalizedUserName { get; set; }

    public required string DisplayName { get; set; }
    public string PasswordHash { get; set; } = "";
    public List<string> Roles { get; set; } = [];
    public bool IsActive { get; set; } = true;
    public int FailedLoginCount { get; set; }
    public DateTimeOffset? LockoutEndAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? LastLoginAt { get; set; }

    public static string Normalize(string userName) => userName.Trim().ToUpperInvariant();

    public bool IsLockedOut(DateTimeOffset now) => LockoutEndAt > now;

    /// <summary>Counts a failed login; locks the account for <see cref="LockoutDuration"/> after <see cref="MaxFailedLogins"/> failures.</summary>
    public void RegisterFailedLogin(DateTimeOffset now)
    {
        FailedLoginCount++;
        if (FailedLoginCount < MaxFailedLogins) return;
        LockoutEndAt = now + LockoutDuration;
        FailedLoginCount = 0;
    }

    public void RegisterSuccessfulLogin(DateTimeOffset now)
    {
        FailedLoginCount = 0;
        LockoutEndAt = null;
        LastLoginAt = now;
    }
}

public sealed class IdentityDesignTimeFactory : ModuleDesignTimeFactory<IdentityDbContext>
{
    protected override string Schema => IdentityDbContext.Schema;
}
