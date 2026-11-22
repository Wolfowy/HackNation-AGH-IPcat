using Microsoft.EntityFrameworkCore;
using WebScan.Server.Infrastructure.Persistence;

namespace WebScan.Server.Modules.Networks.Persistence;

public sealed class NetworksDbContext(DbContextOptions<NetworksDbContext> options) : DbContext(options)
{
    public const string Schema = "networks";

    public DbSet<Zone> Zones => Set<Zone>();
    public DbSet<Network> Networks => Set<Network>();
    public DbSet<ScopePolicy> ScopePolicies => Set<ScopePolicy>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.HasDefaultSchema(Schema);

        modelBuilder.Entity<Zone>(e =>
        {
            e.ToTable("zones");
            e.HasKey(x => x.Name);
            e.Property(x => x.Name).HasMaxLength(64);
            e.Property(x => x.Description).HasMaxLength(1000);
        });

        modelBuilder.Entity<Network>(e =>
        {
            e.ToTable("networks");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(128);
            e.HasIndex(x => x.Name).IsUnique();
            e.Property(x => x.Description).HasMaxLength(1000);
            e.Property(x => x.Zone).HasMaxLength(64);
            e.HasIndex(x => x.Zone);
        });

        modelBuilder.Entity<ScopePolicy>(e =>
        {
            e.ToTable("scope_policy");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).ValueGeneratedNever();
        });
    }
}

public sealed class Zone
{
    public required string Name { get; set; }
    public string? Description { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

public sealed class Network
{
    public Guid Id { get; set; }
    public required string Name { get; set; }
    public string? Description { get; set; }

    /// <summary>Zone name (zones are referenced by name, also by agents' authorized zones).</summary>
    public required string Zone { get; set; }

    /// <summary>IP, CIDR, "a-b" range or hostname entries.</summary>
    public List<string> Ranges { get; set; } = [];

    public List<string> Exclusions { get; set; } = [];
    public List<string> Tags { get; set; } = [];
    public int? MaxRatePerSecond { get; set; }
    public bool Enabled { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary>Single-row global scope policy: nothing outside <see cref="Allowed"/> is ever scannable.</summary>
public sealed class ScopePolicy
{
    public const int SingletonId = 1;

    public int Id { get; set; } = SingletonId;
    public List<string> Allowed { get; set; } = [];
    public List<string> Excluded { get; set; } = [];

    /// <summary>Port allowlist ("80", "8000-8100"); empty = every port.</summary>
    public List<string> AllowedPorts { get; set; } = [];

    /// <summary>Ports never scanned, also when inside <see cref="AllowedPorts"/>.</summary>
    public List<string> ExcludedPorts { get; set; } = [];

    public DateTimeOffset UpdatedAt { get; set; }
}

public sealed class NetworksDesignTimeFactory : ModuleDesignTimeFactory<NetworksDbContext>
{
    protected override string Schema => NetworksDbContext.Schema;
}
