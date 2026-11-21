using System.Linq.Expressions;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using WebScan.Contracts;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Scanning.Jobs;
using WebScan.Server.Modules.Scanning.Persistence;
using WebScan.Server.Modules.Scanning.Planning;

namespace WebScan.Server.Modules.Scanning.Api;

public sealed record Paged<T>(IReadOnlyList<T> Items, int Total, int Page, int PageSize)
{
    public static (int Page, int PageSize) Normalize(int? page, int? pageSize) => (Math.Max(1, page ?? 1), Math.Clamp(pageSize ?? 50, 1, 500));
}

public sealed record JobDto(
    Guid Id, Guid ScanRunId, string StepId, ScanOperation Operation, JobStatus Status, string? AgentId, string? InterfaceName, string? ToolId,
    string TargetSummary, long TargetCount, int Attempt, int MaxAttempts, DateTimeOffset CreatedAt, DateTimeOffset? StartedAt,
    DateTimeOffset? FinishedAt, long? DurationMs, string? Error, double? ProgressPercent, string Zone, string? QueueReason, bool CancelRequested)
{
    public static readonly Expression<Func<ScanJobRecord, JobDto>> Projection = j => new JobDto(
        j.Id, j.ScanRunId, j.StepId, j.Operation, j.Status, j.AgentId, j.InterfaceName, j.ToolId, j.TargetSummary, j.TargetCount,
        j.Attempt, j.MaxAttempts, j.CreatedAt, j.StartedAt, j.FinishedAt, j.DurationMs, j.Error, j.ProgressPercent, j.Zone, j.QueueReason, j.CancelRequested);

    public static readonly Func<ScanJobRecord, JobDto> FromRecord = Projection.Compile();

    public static async Task<Paged<JobDto>> QueryAsync(IQueryable<ScanJobRecord> query, int? page, int? pageSize, CancellationToken ct)
    {
        var (p, size) = Paged<JobDto>.Normalize(page, pageSize);
        var total = await query.CountAsync(ct);
        var items = await query.OrderByDescending(j => j.CreatedAt).ThenBy(j => j.Id).Skip((p - 1) * size).Take(size).Select(Projection).ToListAsync(ct);
        return new Paged<JobDto>(items, total, p, size);
    }
}

public sealed record JobDetailDto(JobDto Job, ScanJob Payload, JobCoverage? Coverage, IReadOnlyList<string> EligibleAgentIds);

public sealed record PlannerStatsDto(QueueStatsDto Queue, IReadOnlyList<PerformanceDto> Performance);
public sealed record QueueStatsDto(int Queued, int Leased);
public sealed record PerformanceDto(string AgentId, string InterfaceName, string ToolId, long JobsCompleted, double AvgDurationMs, double AvgTargetsPerSecond);

public static class JobEndpoints
{
    public static void MapJobEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var jobs = endpoints.MapGroup("/api/jobs").WithTags("Jobs");

        jobs.MapGet("", (JobStatus? status, string? agentId, Guid? scanRunId, int? page, int? pageSize, ScanningDbContext db, CancellationToken ct) =>
        {
            var query = db.Jobs.AsNoTracking();
            if (status is not null) query = query.Where(j => j.Status == status);
            if (!string.IsNullOrWhiteSpace(agentId)) query = query.Where(j => j.AgentId == agentId || j.LastAgentId == agentId);
            if (scanRunId is not null) query = query.Where(j => j.ScanRunId == scanRunId);
            return JobDto.QueryAsync(query, page, pageSize, ct);
        }).RequireAuthorization(Policies.CanRead);

        jobs.MapGet("/{id:guid}", async (Guid id, ScanningDbContext db, CancellationToken ct) =>
        {
            var job = await db.Jobs.AsNoTracking().FirstOrDefaultAsync(j => j.Id == id, ct);
            if (job is null) return Results.NotFound();
            return Results.Ok(new JobDetailDto(JobDto.FromRecord(job),
                JsonSerializer.Deserialize<ScanJob>(job.PayloadJson, ContractJson.Options)!,
                job.CoverageJson is null ? null : JsonSerializer.Deserialize<JobCoverage>(job.CoverageJson, ContractJson.Options),
                job.EligibleAgentIds));
        }).RequireAuthorization(Policies.CanRead);

        jobs.MapPost("/{id:guid}/cancel", async (Guid id, JobQueue queue, IAuditLog audit, CancellationToken ct) =>
        {
            var result = await queue.CancelAsync(id, ct);
            if (result.Status == JobCallStatus.Ok) await audit.WriteAsync(new AuditEntry("job.cancelled", "ScanJob", id.ToString()), ct);
            return AgentJobEndpoints.ToResult(result, noBody: true);
        }).RequireAuthorization(Policies.CanEdit);

        jobs.MapPost("/{id:guid}/retry", async (Guid id, JobQueue queue, IAuditLog audit, CancellationToken ct) =>
        {
            var result = await queue.RetryAsync(id, ct);
            if (result.Status == JobCallStatus.Ok) await audit.WriteAsync(new AuditEntry("job.retried", "ScanJob", id.ToString()), ct);
            return AgentJobEndpoints.ToResult(result, noBody: true);
        }).RequireAuthorization(Policies.CanEdit);

        endpoints.MapGet("/api/scan-limits", (ScanLimitsStore store, CancellationToken ct) => store.GetAsync(ct))
            .RequireAuthorization(Policies.CanRead).WithTags("Jobs");

        endpoints.MapPut("/api/scan-limits", async (ScanLimits limits, ScanLimitsStore store, IAuditLog audit, CancellationToken ct) =>
        {
            var errors = limits.Validate();
            if (errors.Count > 0) return Results.ValidationProblem(errors, statusCode: StatusCodes.Status422UnprocessableEntity);
            await store.SaveAsync(limits, ct);
            await audit.WriteAsync(new AuditEntry("scan-limits.updated", "ScanLimits", null, limits), ct);
            return Results.Ok(limits);
        }).RequireAuthorization(Policies.AdminOnly).WithTags("Jobs");

        endpoints.MapGet("/api/stats/planner", async (ScanningDbContext db, CancellationToken ct) =>
        {
            var counts = await db.Jobs.AsNoTracking().Where(j => j.Status == JobStatus.Queued || j.Status == JobStatus.Leased)
                .GroupBy(j => j.Status).Select(g => new { g.Key, Count = g.Count() }).ToListAsync(ct);
            var performance = await db.Performance.AsNoTracking().OrderBy(p => p.AgentId).ThenBy(p => p.InterfaceName).ThenBy(p => p.ToolId)
                .Select(p => new PerformanceDto(p.AgentId, p.InterfaceName, p.ToolId, p.JobsCompleted, p.AvgDurationMs, p.AvgTargetsPerSecond))
                .ToListAsync(ct);
            return new PlannerStatsDto(
                new QueueStatsDto(counts.FirstOrDefault(c => c.Key == JobStatus.Queued)?.Count ?? 0, counts.FirstOrDefault(c => c.Key == JobStatus.Leased)?.Count ?? 0),
                performance);
        }).RequireAuthorization(Policies.CanRead).WithTags("Jobs");
    }
}
