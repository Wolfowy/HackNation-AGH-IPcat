using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using WebScan.Contracts;
using WebScan.Server.Infrastructure.Persistence;

namespace WebScan.Server.Modules.Agents.Persistence;

public sealed class AgentsDbContext(DbContextOptions<AgentsDbContext> options) : DbContext(options)
{
    public const string Schema = "agents";

    public DbSet<Agent> Agents => Set<Agent>();
    public DbSet<EnrollmentToken> EnrollmentTokens => Set<EnrollmentToken>();
    public DbSet<ToolCatalogEntry> Tools => Set<ToolCatalogEntry>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.HasDefaultSchema(Schema);

        modelBuilder.Entity<Agent>(e =>
        {
            e.ToTable("agents");
            e.HasKey(x => x.AgentId);
            e.Property(x => x.AgentId).HasMaxLength(64);
            e.Property(x => x.Hostname).HasMaxLength(255);
            e.Property(x => x.OsPlatform).HasMaxLength(32);
            e.Property(x => x.OsDescription).HasMaxLength(256);
            e.Property(x => x.AgentVersion).HasMaxLength(64);
            e.Property(x => x.Status).HasConversion<string>().HasMaxLength(32);
            e.Property(x => x.InventoryHash).HasMaxLength(128);
            e.Property(x => x.Inventory).HasJsonConversion();
            e.Property(x => x.Load).HasJsonConversion();
            e.Property(x => x.SecretHash).HasMaxLength(32);
            e.Property(x => x.PreviousSecretHash).HasMaxLength(32);
            e.HasIndex(x => x.Status);
        });

        modelBuilder.Entity<EnrollmentToken>(e =>
        {
            e.ToTable("enrollment_tokens");
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(128);
            e.Property(x => x.TokenHash).HasMaxLength(32);
            e.HasIndex(x => x.TokenHash).IsUnique();
            e.Property(x => x.CreatedBy).HasMaxLength(256);
        });

        modelBuilder.Entity<ToolCatalogEntry>(e =>
        {
            e.ToTable("tool_catalog");
            e.HasKey(x => x.ToolId);
            e.Property(x => x.ToolId).HasMaxLength(64);
        });
    }
}

/// <summary>Registered scanner agent. The secret is never stored, only its SHA-256.</summary>
public sealed class Agent
{
    public required string AgentId { get; set; }
    public required string Hostname { get; set; }
    public required string OsPlatform { get; set; }
    public required string OsDescription { get; set; }
    public required string AgentVersion { get; set; }
    public AgentStatus Status { get; set; }

    public DateTimeOffset RegisteredAt { get; set; }
    public DateTimeOffset LastRegisteredAt { get; set; }
    public DateTimeOffset? LastHeartbeatAt { get; set; }

    /// <summary>Set by heartbeats, cleared once by the offline detector (which then publishes <c>AgentWentOffline</c>).</summary>
    public bool IsOnline { get; set; }

    public AgentInventory Inventory { get; set; } = new();

    /// <summary>Inventory hash reported by the agent's first heartbeat after (re-)registration; later mismatches ask for re-registration.</summary>
    public string? InventoryHash { get; set; }

    public List<string> DeclaredZones { get; set; } = [];
    public List<string> AuthorizedZones { get; set; } = [];
    public List<Guid> AuthorizedNetworkIds { get; set; } = [];

    public int ReportedMaxConcurrentJobs { get; set; }
    public int ReportedMaxRatePerSecond { get; set; }
    public int? MaxConcurrentJobsOverride { get; set; }
    public int? MaxRatePerSecondOverride { get; set; }

    public AgentLoad? Load { get; set; }

    public byte[] SecretHash { get; set; } = [];
    public byte[]? PreviousSecretHash { get; set; }
    public DateTimeOffset? PreviousSecretValidUntil { get; set; }
    public bool RotateRequested { get; set; }

    public Guid? EnrollmentTokenId { get; set; }

    /// <summary>Agent-reported limits, lowered (never raised) by administrator overrides.</summary>
    public AgentLimits EffectiveLimits => new()
    {
        MaxConcurrentJobs = Math.Min(ReportedMaxConcurrentJobs, MaxConcurrentJobsOverride ?? int.MaxValue),
        MaxRatePerSecond = Math.Min(ReportedMaxRatePerSecond, MaxRatePerSecondOverride ?? int.MaxValue),
    };

    public bool IsOnlineAt(DateTimeOffset now, TimeSpan heartbeatTimeout) =>
        IsOnline && LastHeartbeatAt is { } last && now - last <= heartbeatTimeout;

    public void ApplyRegistration(AgentRegistration registration, DateTimeOffset now, string? connectedFrom = null)
    {
        Hostname = registration.Hostname;
        OsPlatform = registration.OsPlatform;
        OsDescription = registration.OsDescription;
        AgentVersion = registration.AgentVersion;
        Inventory = new AgentInventory
        {
            Tools = registration.Tools,
            Interfaces = registration.Interfaces,
            Routes = registration.Routes,
            Resources = registration.Resources,
            ConnectedFrom = connectedFrom,
            RawSockets = registration.RawSockets,
        };
        InventoryHash = null;
        DeclaredZones = registration.DeclaredZones.Distinct().ToList();
        ReportedMaxConcurrentJobs = registration.Limits.MaxConcurrentJobs;
        ReportedMaxRatePerSecond = registration.Limits.MaxRatePerSecond;
        LastRegisteredAt = now;
        LastHeartbeatAt = now;
        IsOnline = true;
    }
}

/// <summary>Tools, interfaces and routes reported at registration (jsonb).</summary>
public sealed record AgentInventory
{
    public IReadOnlyList<ToolDescriptor> Tools { get; init; } = [];
    public IReadOnlyList<NetworkInterfaceInfo> Interfaces { get; init; } = [];
    public IReadOnlyList<RouteInfo> Routes { get; init; } = [];
    public AgentResources? Resources { get; init; }

    /// <summary>Source address the server saw on registration (the agent's link to the server, e.g. a management network).</summary>
    public string? ConnectedFrom { get; init; }

    /// <summary>Agent-reported raw-socket capability of its tools (null = unknown).</summary>
    public bool? RawSockets { get; init; }
}

public sealed class EnrollmentToken
{
    public Guid Id { get; set; }
    public required string Name { get; set; }
    public byte[] TokenHash { get; set; } = [];
    public DateTimeOffset ExpiresAt { get; set; }
    public int MaxUses { get; set; }
    public int Uses { get; set; }
    public bool AutoApprove { get; set; }

    /// <summary>Zones new agents enrolled with this token are authorized for.</summary>
    public List<string> Zones { get; set; } = [];

    public bool Revoked { get; set; }
    public string? CreatedBy { get; set; }
    public DateTimeOffset CreatedAt { get; set; }

    public bool IsUsableAt(DateTimeOffset now) => !Revoked && ExpiresAt > now && Uses < MaxUses;
}

/// <summary>Every tool id ever reported by an agent; only approved + enabled tools receive jobs.</summary>
public sealed class ToolCatalogEntry
{
    public required string ToolId { get; set; }
    public bool Approved { get; set; }
    public bool Enabled { get; set; } = true;
    public List<string> Capabilities { get; set; } = [];
    public List<string> Versions { get; set; } = [];
    public DateTimeOffset FirstSeenAt { get; set; }

    public bool IsUsable => Approved && Enabled;
}

internal static class JsonColumnExtensions
{
    /// <summary>Maps a record to a jsonb column using the wire JSON format; compares by serialized content.</summary>
    public static PropertyBuilder<T> HasJsonConversion<T>(this PropertyBuilder<T> property)
    {
        property.HasConversion(
            v => JsonSerializer.Serialize(v, ContractJson.Options),
            s => JsonSerializer.Deserialize<T>(s, ContractJson.Options)!,
            new ValueComparer<T>(
                (a, b) => JsonSerializer.Serialize(a, ContractJson.Options) == JsonSerializer.Serialize(b, ContractJson.Options),
                v => JsonSerializer.Serialize(v, ContractJson.Options).GetHashCode(),
                v => JsonSerializer.Deserialize<T>(JsonSerializer.Serialize(v, ContractJson.Options), ContractJson.Options)!));
        property.HasColumnType("jsonb");
        return property;
    }
}

public sealed class AgentsDesignTimeFactory : ModuleDesignTimeFactory<AgentsDbContext>
{
    protected override string Schema => AgentsDbContext.Schema;
}
