using Microsoft.EntityFrameworkCore;
using WebScan.Contracts;
using WebScan.Server.Infrastructure.Persistence;
using WebScan.Server.Modules.Scanning.Persistence;

namespace WebScan.Server.Modules.Workflows.Persistence;

/// <summary>Immutable workflow definition version (key + version).</summary>
public sealed class WorkflowDefinitionRecord
{
    public required string Key { get; set; }
    public int Version { get; set; }
    public required string Name { get; set; }
    public string? Description { get; set; }
    public required string DefinitionJson { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public required string CreatedBy { get; set; }
}

public enum StepStatus { Pending, Running, Completed, Skipped, Failed, Cancelled }

/// <summary>DAG execution state of one scan run (1:1 with <see cref="ScanRun"/>; run status lives on the scan run).</summary>
public sealed class WorkflowRun
{
    public Guid Id { get; set; }
    public Guid ScanRunId { get; set; }
    public required string WorkflowKey { get; set; }
    public int WorkflowVersion { get; set; }

    /// <summary>Snapshot of the definition the run executes.</summary>
    public required string DefinitionJson { get; set; }

    public bool WindowExpired { get; set; }
    public bool CancelRequested { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

public sealed class WorkflowStepRun
{
    public Guid WorkflowRunId { get; set; }
    public required string StepId { get; set; }
    public ScanOperation Operation { get; set; }
    public StepStatus Status { get; set; }
    public int Attempt { get; set; }
    public DateTimeOffset? NextAttemptAt { get; set; }
    public DateTimeOffset? StartedAt { get; set; }
    public DateTimeOffset? FinishedAt { get; set; }
    public string? Message { get; set; }

    /// <summary>Completed, but some of its jobs failed or were cancelled (run becomes PartiallyCompleted).</summary>
    public bool HasFailures { get; set; }

    public bool IsTerminal => Status is StepStatus.Completed or StepStatus.Skipped or StepStatus.Failed or StepStatus.Cancelled;
}

public sealed class WorkflowsDbContext(DbContextOptions<WorkflowsDbContext> options) : DbContext(options)
{
    public const string Schema = "workflows";

    public DbSet<WorkflowDefinitionRecord> Definitions => Set<WorkflowDefinitionRecord>();
    public DbSet<WorkflowRun> Runs => Set<WorkflowRun>();
    public DbSet<WorkflowStepRun> StepRuns => Set<WorkflowStepRun>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.HasDefaultSchema(Schema);

        b.Entity<WorkflowDefinitionRecord>(e =>
        {
            e.ToTable("workflow_definitions");
            e.HasKey(x => new { x.Key, x.Version });
            e.Property(x => x.Key).HasMaxLength(64);
            e.Property(x => x.Name).HasMaxLength(200);
            e.Property(x => x.CreatedBy).HasMaxLength(200);
            e.Property(x => x.DefinitionJson).HasColumnType("jsonb");
        });

        b.Entity<WorkflowRun>(e =>
        {
            e.ToTable("workflow_runs");
            e.HasIndex(x => x.ScanRunId).IsUnique();
            e.Property(x => x.DefinitionJson).HasColumnType("jsonb");
        });

        b.Entity<WorkflowStepRun>(e =>
        {
            e.ToTable("workflow_step_runs");
            e.HasKey(x => new { x.WorkflowRunId, x.StepId });
            e.Property(x => x.Status).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.Operation).HasConversion<string>().HasMaxLength(32);
            e.Ignore(x => x.IsTerminal);
        });

        SnakeCaseNames.Apply(b);
    }
}

public sealed class WorkflowsDesignTimeFactory : ModuleDesignTimeFactory<WorkflowsDbContext>
{
    protected override string Schema => WorkflowsDbContext.Schema;
}
