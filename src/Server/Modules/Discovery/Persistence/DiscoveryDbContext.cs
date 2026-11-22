using Microsoft.EntityFrameworkCore;
using WebScan.Server.Infrastructure.Persistence;
using WebScan.Server.Modules.Discovery.Domain;

namespace WebScan.Server.Modules.Discovery.Persistence;

public sealed class DiscoveryDbContext(DbContextOptions<DiscoveryDbContext> options) : DbContext(options)
{
    public const string Schema = "discovery";

    public DbSet<ObservationRecord> Observations => Set<ObservationRecord>();
    public DbSet<ProcessedBatch> ProcessedBatches => Set<ProcessedBatch>();
    public DbSet<RunProcessing> Runs => Set<RunProcessing>();
    public DbSet<Host> Hosts => Set<Host>();
    public DbSet<Service> Services => Set<Service>();
    public DbSet<Technology> Technologies => Set<Technology>();
    public DbSet<Certificate> Certificates => Set<Certificate>();
    public DbSet<HttpSnapshot> HttpSnapshots => Set<HttpSnapshot>();
    public DbSet<SignatureMatch> SignatureMatches => Set<SignatureMatch>();
    public DbSet<ChangeEvent> Changes => Set<ChangeEvent>();
    public DbSet<AssetAnnotation> Annotations => Set<AssetAnnotation>();
    public DbSet<AssetAnnotationRevision> AnnotationRevisions => Set<AssetAnnotationRevision>();
    public DbSet<ServiceAnnotation> ServiceAnnotations => Set<ServiceAnnotation>();

    protected override void ConfigureConventions(ModelConfigurationBuilder c)
    {
        c.Properties<Enum>().HaveConversion<string>().HaveMaxLength(32);
    }

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.HasDefaultSchema(Schema);

        b.Entity<ObservationRecord>(e =>
        {
            e.ToTable("observations");
            e.Property(x => x.ObservationId).HasMaxLength(64);
            e.Property(x => x.Payload).HasEncryptedConversion();
            e.HasIndex(x => new { x.JobId, x.ObservationId }).IsUnique();
            e.HasIndex(x => new { x.ScanRunId, x.Kind });
            e.HasIndex(x => new { x.Address, x.ObservedAt });
        });

        b.Entity<ProcessedBatch>(e =>
        {
            e.ToTable("processed_batches");
            e.HasKey(x => x.BatchId);
            e.HasIndex(x => x.ScanRunId);
        });

        b.Entity<RunProcessing>(e =>
        {
            e.ToTable("run_processing");
            e.HasKey(x => x.ScanRunId);
            e.Property(x => x.ChangesByType).HasColumnType("jsonb");
            e.Property(x => x.CoverageByZone).HasColumnType("jsonb");
        });

        b.Entity<Host>(e =>
        {
            e.ToTable("hosts");
            e.HasIndex(x => new { x.Zone, x.Address }).IsUnique();
            e.HasIndex(x => x.Address);
            e.HasIndex(x => x.Status);
            e.Property(x => x.StateHistory).HasMaxLength(Host.StateHistoryLength);
        });

        b.Entity<Service>(e =>
        {
            e.ToTable("services");
            e.HasIndex(x => new { x.HostId, x.Port, x.Transport }).IsUnique();
            e.HasIndex(x => new { x.Port, x.State });
            e.Property(x => x.Banner).HasEncryptedConversion();
            // Full response headers (cookie values already masked): encrypted like the raw observations they come from.
            e.Property(x => x.HttpDetailsJson).HasEncryptedConversion();
            e.OwnsMany(x => x.Artifacts, o => o.ToJson());
        });

        b.Entity<Technology>(e =>
        {
            e.ToTable("technologies");
            e.HasIndex(x => new { x.HostId, x.Port, x.NameKey }).IsUnique().AreNullsDistinct(false);
            e.HasIndex(x => x.NameKey);
            e.OwnsMany(x => x.Evidence, o => o.ToJson());
        });

        b.Entity<Certificate>(e =>
        {
            e.ToTable("certificates");
            e.HasIndex(x => new { x.ServiceId, x.FingerprintSha256 }).IsUnique();
            e.HasIndex(x => x.HostId);
        });

        b.Entity<HttpSnapshot>(e =>
        {
            e.ToTable("http_snapshots");
            e.HasIndex(x => new { x.ServiceId, x.Path, x.HourBucket, x.Fingerprint }).IsUnique();
            e.HasIndex(x => x.HostId);
        });

        b.Entity<SignatureMatch>(e =>
        {
            e.ToTable("signature_matches");
            e.HasIndex(x => new { x.HostId, x.Port, x.SignatureId }).IsUnique().AreNullsDistinct(false);
            e.HasIndex(x => new { x.Status, x.Severity });
            e.HasIndex(x => x.LastSeenRunId);
            e.OwnsMany(x => x.ExternalRefs, o => o.ToJson());
            e.Ignore(x => x.EffectiveSeverity);
            e.Property(x => x.SeverityOverride).HasMaxLength(16);
            e.Property(x => x.Notes).HasEncryptedConversion(); // length (≤4000) is validated by the API
            e.Property(x => x.MatchedUrl).HasEncryptedConversion();
            e.Property(x => x.Evidence).HasEncryptedConversion();
        });

        b.Entity<ChangeEvent>(e =>
        {
            e.ToTable("change_events");
            e.HasIndex(x => x.DetectedAt);
            e.HasIndex(x => x.ScanRunId);
            e.HasIndex(x => x.HostId);
        });

        b.Entity<AssetAnnotation>(e =>
        {
            e.ToTable("asset_annotations");
            e.HasKey(x => new { x.Zone, x.Address });
            e.Property(x => x.Description).HasEncryptedConversion();
            e.Property(x => x.Owner).HasEncryptedConversion();
        });

        b.Entity<ServiceAnnotation>(e =>
        {
            e.ToTable("service_annotations");
            e.HasKey(x => new { x.Zone, x.Address, x.Port, x.Transport });
            e.Property(x => x.Notes).HasEncryptedConversion();
            e.Property(x => x.Owner).HasEncryptedConversion();
        });

        b.Entity<AssetAnnotationRevision>(e =>
        {
            e.ToTable("asset_annotation_revisions");
            e.HasIndex(x => new { x.Zone, x.Address, x.ChangedAt });
            e.Property(x => x.Description).HasEncryptedConversion();
            e.Property(x => x.Owner).HasEncryptedConversion();
        });
    }
}

public sealed class DiscoveryDesignTimeFactory : ModuleDesignTimeFactory<DiscoveryDbContext>
{
    protected override string Schema => DiscoveryDbContext.Schema;
}
