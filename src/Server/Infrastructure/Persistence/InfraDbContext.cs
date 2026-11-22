using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace WebScan.Server.Infrastructure.Persistence;

/// <summary>Infrastructure-owned tables (schema <c>infra</c>): audit trail, Data Protection key ring, settings.</summary>
public sealed class InfraDbContext(DbContextOptions<InfraDbContext> options) : DbContext(options), IDataProtectionKeyContext
{
    public const string Schema = "infra";

    public DbSet<AuditRecord> AuditEntries => Set<AuditRecord>();
    public DbSet<SettingRecord> Settings => Set<SettingRecord>();
    public DbSet<DataProtectionKey> DataProtectionKeys => Set<DataProtectionKey>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.HasDefaultSchema(Schema);

        modelBuilder.Entity<AuditRecord>(e =>
        {
            e.ToTable("audit_entries");
            e.HasKey(x => x.Id);
            e.Property(x => x.Action).HasMaxLength(128);
            e.Property(x => x.EntityType).HasMaxLength(128);
            e.Property(x => x.EntityId).HasMaxLength(256);
            e.Property(x => x.UserId).HasMaxLength(128);
            e.Property(x => x.UserName).HasMaxLength(256);
            e.Property(x => x.IpAddress).HasMaxLength(64);
            e.Property(x => x.Details).HasEncryptedConversion();
            e.HasIndex(x => x.OccurredAt);
            e.HasIndex(x => new { x.EntityType, x.EntityId });
        });

        modelBuilder.Entity<SettingRecord>(e =>
        {
            e.ToTable("settings");
            e.HasKey(x => x.Key);
            e.Property(x => x.Key).HasMaxLength(128);
            e.Property(x => x.Value).HasMaxLength(SettingRecord.MaxValueLength);
        });

        modelBuilder.Entity<DataProtectionKey>().ToTable("data_protection_keys");
    }
}

public sealed class AuditRecord
{
    public Guid Id { get; set; }
    public DateTimeOffset OccurredAt { get; set; }
    public string? UserId { get; set; }
    public string? UserName { get; set; }
    public required string Action { get; set; }
    public required string EntityType { get; set; }
    public string? EntityId { get; set; }

    /// <summary>JSON document, encrypted at rest (may carry annotation text, names).</summary>
    public string? Details { get; set; }

    public string? IpAddress { get; set; }
}

public sealed class SettingRecord
{
    public const int MaxValueLength = 4000;

    public required string Key { get; set; }
    public required string Value { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public string? UpdatedBy { get; set; }
}

public sealed class InfraDesignTimeFactory : ModuleDesignTimeFactory<InfraDbContext>
{
    protected override string Schema => InfraDbContext.Schema;
}
