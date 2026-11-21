using Microsoft.EntityFrameworkCore;
using WebScan.Server.Infrastructure.Persistence;
using WebScan.Server.Modules.Signatures.Domain;

namespace WebScan.Server.Modules.Signatures.Persistence;

public sealed class SignaturesDbContext(DbContextOptions<SignaturesDbContext> options) : DbContext(options)
{
    public const string Schema = "signatures";

    public DbSet<Signature> Signatures => Set<Signature>();
    public DbSet<SignatureVersion> Versions => Set<SignatureVersion>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.HasDefaultSchema(Schema);

        b.Entity<Signature>(e =>
        {
            e.ToTable("signatures");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).HasMaxLength(100);
            e.Property(x => x.Name).HasMaxLength(200);
            e.Property(x => x.Kind).HasConversion<string>().HasMaxLength(32);
            e.Property(x => x.Status).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.Severity).HasMaxLength(16);
            e.HasMany(x => x.Versions).WithOne().HasForeignKey(v => v.SignatureId);
            e.HasIndex(x => new { x.Kind, x.Status });
        });

        b.Entity<SignatureVersion>(e =>
        {
            e.ToTable("signature_versions");
            e.HasKey(x => new { x.SignatureId, x.Version });
            e.Property(x => x.Sha256).HasMaxLength(64);
            e.Property(x => x.Severity).HasMaxLength(16);
            e.Property(x => x.CreatedBy).HasMaxLength(200);
            e.Property(x => x.ApprovedBy).HasMaxLength(200);
            e.Property(x => x.ApprovalNote).HasMaxLength(2000);
        });

        BuiltInSignatures.Seed(b);
    }
}

public sealed class SignaturesDesignTimeFactory : ModuleDesignTimeFactory<SignaturesDbContext>
{
    protected override string Schema => SignaturesDbContext.Schema;
}
