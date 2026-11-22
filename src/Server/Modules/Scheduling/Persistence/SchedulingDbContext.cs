using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using WebScan.Contracts;
using WebScan.Server.Infrastructure.Persistence;

namespace WebScan.Server.Modules.Scheduling.Persistence;

public enum OverlapPolicy { Skip, CancelPrevious, Queue }

/// <summary>Allowed time window in the schedule's time zone; <c>End &lt;= Start</c> crosses midnight (the day is the start day).</summary>
public sealed record AllowedWindow(IReadOnlyList<DayOfWeek> DaysOfWeek, string Start, string End);

/// <summary>Source of truth for scheduled scans (Quartz holds only in-memory triggers rebuilt from this table).</summary>
public sealed class Schedule
{
    public Guid Id { get; set; }
    public required string Name { get; set; }
    public required string CronExpression { get; set; }
    public required string TimeZone { get; set; }
    public required string WorkflowKey { get; set; }
    public int? WorkflowVersion { get; set; }
    public List<Guid> NetworkIds { get; set; } = [];
    public int Priority { get; set; }
    public int? MaxRatePerSecond { get; set; }
    public int? WindowDurationMinutes { get; set; }
    public List<AllowedWindow> AllowedWindows { get; set; } = [];
    public OverlapPolicy OverlapPolicy { get; set; }
    public bool Enabled { get; set; } = true;
    public DateTimeOffset? NextFireAt { get; set; }
    public DateTimeOffset? LastFireAt { get; set; }
    public Guid? LastRunId { get; set; }

    /// <summary>Fire deferred by <see cref="OverlapPolicy.Queue"/>; started when the previous run finishes.</summary>
    public DateTimeOffset? QueuedFireTime { get; set; }

    /// <summary>When a scheduled run ends WindowExpired, start it again at the next allowed window start (one-off fire).</summary>
    public bool ResumeInNextWindow { get; set; } = true;

    /// <summary>Pending one-off resume fire (start of the next allowed window); cleared when it fires or any other run starts.</summary>
    public DateTimeOffset? ResumeAt { get; set; }

    /// <summary>End of the window in which a resume fire started a run: regular cron fires inside that window are skipped.</summary>
    public DateTimeOffset? ResumedWindowEnd { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

public sealed class SchedulingDbContext(DbContextOptions<SchedulingDbContext> options) : DbContext(options)
{
    public const string Schema = "scheduling";

    public DbSet<Schedule> Schedules => Set<Schedule>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.HasDefaultSchema(Schema);
        b.Entity<Schedule>(e =>
        {
            e.ToTable("schedules");
            e.Property(x => x.Name).HasMaxLength(200);
            e.Property(x => x.CronExpression).HasMaxLength(200);
            e.Property(x => x.TimeZone).HasMaxLength(100);
            e.Property(x => x.WorkflowKey).HasMaxLength(64);
            e.Property(x => x.OverlapPolicy).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.AllowedWindows).HasColumnType("jsonb").HasConversion(
                v => JsonSerializer.Serialize(v, ContractJson.Options),
                s => JsonSerializer.Deserialize<List<AllowedWindow>>(s, ContractJson.Options) ?? new List<AllowedWindow>(),
                new ValueComparer<List<AllowedWindow>>(
                    (a, b) => JsonSerializer.Serialize(a, ContractJson.Options) == JsonSerializer.Serialize(b, ContractJson.Options),
                    v => JsonSerializer.Serialize(v, ContractJson.Options).GetHashCode(),
                    v => v.ToList()));
            e.HasIndex(x => x.LastRunId);
        });
    }
}

public sealed class SchedulingDesignTimeFactory : ModuleDesignTimeFactory<SchedulingDbContext>
{
    protected override string Schema => SchedulingDbContext.Schema;
}
