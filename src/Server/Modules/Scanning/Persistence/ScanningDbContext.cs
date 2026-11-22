using System.Text;
using Microsoft.EntityFrameworkCore;
using WebScan.Server.Infrastructure.Persistence;

namespace WebScan.Server.Modules.Scanning.Persistence;

public sealed class ScanningDbContext(DbContextOptions<ScanningDbContext> options) : DbContext(options)
{
    public const string Schema = "scanning";

    public DbSet<ScanRun> ScanRuns => Set<ScanRun>();
    public DbSet<ScanJobRecord> Jobs => Set<ScanJobRecord>();
    public DbSet<ResultBatchRecord> ResultBatches => Set<ResultBatchRecord>();
    public DbSet<ScanEventRecord> Events => Set<ScanEventRecord>();
    public DbSet<JobPerformance> Performance => Set<JobPerformance>();
    public DbSet<ScanLimitsRecord> Limits => Set<ScanLimitsRecord>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.HasDefaultSchema(Schema);

        b.Entity<ScanRun>(e =>
        {
            e.ToTable("scan_runs");
            e.Property(x => x.Status).HasConversion<string>().HasMaxLength(32);
            e.Property(x => x.Name).HasMaxLength(200);
            e.Property(x => x.WorkflowKey).HasMaxLength(64);
            e.Property(x => x.TriggeredBy).HasMaxLength(200);
            e.HasIndex(x => new { x.ScheduleId, x.ScheduledFireTime }).IsUnique();
            e.HasIndex(x => new { x.Status, x.CreatedAt });
        });

        b.Entity<ScanJobRecord>(e =>
        {
            e.ToTable("scan_jobs");
            e.Property(x => x.Status).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.Operation).HasConversion<string>().HasMaxLength(32);
            e.Property(x => x.FailureReason).HasConversion<string>().HasMaxLength(32);
            e.Property(x => x.StepId).HasMaxLength(64);
            e.Property(x => x.TargetKey).HasMaxLength(64);
            e.Property(x => x.PerspectiveKey).HasMaxLength(200);
            e.Property(x => x.PayloadJson).HasColumnType("jsonb");
            e.Property(x => x.CoverageJson).HasColumnType("jsonb");
            e.Property(x => x.Version).HasColumnName("xmin").HasColumnType("xid").IsRowVersion();
            e.Ignore(x => x.IsTerminal);
            e.HasIndex(x => new { x.ScanRunId, x.StepId, x.TargetKey, x.PerspectiveKey }).IsUnique();
            e.HasIndex(x => new { x.Status, x.Priority, x.CreatedAt });
            e.HasIndex(x => new { x.AgentId, x.Status });
            e.HasIndex(x => new { x.ScanRunId, x.Status });
        });

        b.Entity<ResultBatchRecord>(e =>
        {
            e.ToTable("result_batches");
            e.HasKey(x => x.BatchId);
            e.Property(x => x.BatchId).ValueGeneratedNever();
            e.Property(x => x.PayloadJson).HasEncryptedConversion(); // raw scan results
            e.HasIndex(x => new { x.JobId, x.LeaseId });
            e.HasIndex(x => new { x.ScanRunId, x.StepId });
        });

        b.Entity<ScanEventRecord>(e =>
        {
            e.ToTable("scan_events");
            e.HasKey(x => x.Seq);
            e.Property(x => x.Type).HasConversion<string>().HasMaxLength(32);
            e.Property(x => x.PayloadJson).HasColumnType("jsonb");
            e.HasIndex(x => x.EventId).IsUnique();
            e.HasIndex(x => new { x.ScanRunId, x.Seq });
        });

        b.Entity<JobPerformance>(e =>
        {
            e.ToTable("job_performance");
            e.HasKey(x => new { x.AgentId, x.InterfaceName, x.ToolId });
        });

        b.Entity<ScanLimitsRecord>(e =>
        {
            e.ToTable("scan_limits");
            e.Property(x => x.Id).ValueGeneratedNever();
            e.Property(x => x.ValuesJson).HasColumnType("jsonb");
        });

        SnakeCaseNames.Apply(b);
    }
}

/// <summary>snake_case column/key/index names so hand-written SQL (claim, upserts) stays readable.</summary>
public static class SnakeCaseNames
{
    public static void Apply(ModelBuilder b)
    {
        foreach (var entity in b.Model.GetEntityTypes())
        {
            foreach (var property in entity.GetProperties())
                if (property.GetColumnName() != "xmin") property.SetColumnName(ToSnake(property.GetColumnName()));
            foreach (var key in entity.GetKeys()) key.SetName(ToSnake(key.GetName()!));
            foreach (var index in entity.GetIndexes()) index.SetDatabaseName(ToSnake(index.GetDatabaseName()!));
        }
    }

    public static string ToSnake(string name)
    {
        var sb = new StringBuilder(name.Length + 8);
        for (var i = 0; i < name.Length; i++)
        {
            var c = name[i];
            if (char.IsUpper(c) && i > 0 && name[i - 1] != '_' && (char.IsLower(name[i - 1]) || (i + 1 < name.Length && char.IsLower(name[i + 1]))))
                sb.Append('_');
            sb.Append(char.ToLowerInvariant(c));
        }
        return sb.ToString();
    }
}

public sealed class ScanningDesignTimeFactory : ModuleDesignTimeFactory<ScanningDbContext>
{
    protected override string Schema => ScanningDbContext.Schema;
}
