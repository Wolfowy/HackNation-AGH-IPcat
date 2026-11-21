using Microsoft.EntityFrameworkCore;
using WebScan.Server.Infrastructure.Persistence;

namespace WebScan.Server.Modules.Integrations.Persistence;

/// <summary>DefectDojo connection (single row). The API key is stored encrypted with <c>ISecretProtector</c>.</summary>
public sealed class DefectDojoSettings
{
    public const int SingletonId = 1;

    public int Id { get; set; } = SingletonId;
    public bool Enabled { get; set; }
    public string? BaseUrl { get; set; }
    public string? ApiKeyProtected { get; set; }
    public int? ProductId { get; set; }
    public int? EngagementId { get; set; }
    public string MinimumSeverity { get; set; } = "medium";
    public bool VerifyTls { get; set; } = true;

    /// <summary>DefectDojo test (inside the engagement) that receives WebScan findings; created on first export.</summary>
    public int? TestId { get; set; }

    public int? TestTypeId { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public string? UpdatedBy { get; set; }

    public bool IsConfigured => !string.IsNullOrWhiteSpace(BaseUrl) && ApiKeyProtected is not null && EngagementId is > 0;
}

public sealed class IntegrationsDbContext(DbContextOptions<IntegrationsDbContext> options) : DbContext(options)
{
    public const string Schema = "integrations";

    public DbSet<DefectDojoSettings> DefectDojo => Set<DefectDojoSettings>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.HasDefaultSchema(Schema);
        b.Entity<DefectDojoSettings>(e =>
        {
            e.ToTable("defectdojo_settings");
            e.Property(x => x.Id).ValueGeneratedNever();
            e.Property(x => x.BaseUrl).HasMaxLength(500);
            e.Property(x => x.MinimumSeverity).HasMaxLength(16);
            e.Property(x => x.UpdatedBy).HasMaxLength(200);
        });
    }
}

public sealed class IntegrationsDesignTimeFactory : ModuleDesignTimeFactory<IntegrationsDbContext>
{
    protected override string Schema => IntegrationsDbContext.Schema;
}
