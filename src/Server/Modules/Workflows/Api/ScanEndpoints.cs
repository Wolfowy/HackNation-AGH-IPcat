using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using WebScan.Contracts;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Kernel.Scanning;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Scanning.Api;
using WebScan.Server.Modules.Scanning.Persistence;
using WebScan.Server.Modules.Workflows.Persistence;

namespace WebScan.Server.Modules.Workflows.Api;

public sealed record StartScanDto(
    string Name, string WorkflowKey, int? WorkflowVersion, IReadOnlyList<Guid> NetworkIds, int? Priority, int? MaxRatePerSecond, int? WindowMinutes);

public sealed record ScanProgressDto(int JobsTotal, int JobsQueued, int JobsRunning, int JobsCompleted, int JobsFailed, double Percent);

public sealed record ScanRunDto(
    Guid Id, string Name, ScanRunStatus Status, string WorkflowKey, int WorkflowVersion, IReadOnlyList<Guid> NetworkIds, string TriggeredBy,
    int Priority, int? MaxRatePerSecond, Guid? ScheduleId, DateTimeOffset CreatedAt, DateTimeOffset? StartedAt, DateTimeOffset? FinishedAt,
    DateTimeOffset? NotAfter, ScanProgressDto Progress, bool CoverageComplete, string? Message, IReadOnlyList<ScanStepDto>? Steps = null);

public sealed record ScanStepDto(
    string StepId, ScanOperation Operation, StepStatus Status, int JobsTotal, int JobsCompleted, DateTimeOffset? StartedAt, DateTimeOffset? FinishedAt, string? Message);

/// <summary>Scan run API (lives in Workflows because run detail needs step state; jobs come from Scanning).</summary>
public static class ScanEndpoints
{
    public static void MapScanEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var scans = endpoints.MapGroup("/api/scans").WithTags("Scans");

        scans.MapGet("", async (ScanRunStatus? status, int? page, int? pageSize, ScanningDbContext db, CancellationToken ct) =>
        {
            var (p, size) = Paged<ScanRunDto>.Normalize(page, pageSize);
            var query = db.ScanRuns.AsNoTracking();
            if (status is not null) query = query.Where(r => r.Status == status);
            var total = await query.CountAsync(ct);
            var runs = await query.OrderByDescending(r => r.CreatedAt).ThenBy(r => r.Id).Skip((p - 1) * size).Take(size).ToListAsync(ct);
            var progress = await ProgressAsync(db, runs.Select(r => r.Id).ToList(), ct);
            return new Paged<ScanRunDto>(runs.Select(r => ToDto(r, progress)).ToList(), total, p, size);
        }).RequireAuthorization(Policies.CanRead);

        scans.MapPost("", async (StartScanDto body, ClaimsPrincipal user, IScanLauncher launcher, ScanningDbContext db, IAuditLog audit, TimeProvider time, CancellationToken ct) =>
        {
            if (body.WindowMinutes is < 1 or > 7 * 24 * 60) return Results.ValidationProblem(new Dictionary<string, string[]> { ["windowMinutes"] = ["windowMinutes must be between 1 and 10080."] }, statusCode: StatusCodes.Status422UnprocessableEntity);
            Guid runId;
            try
            {
                runId = await launcher.StartAsync(new StartScanRequest
                {
                    Name = body.Name, WorkflowKey = body.WorkflowKey, WorkflowVersion = body.WorkflowVersion, NetworkIds = body.NetworkIds ?? [],
                    Priority = body.Priority ?? 50, MaxRatePerSecond = body.MaxRatePerSecond,
                    NotAfter = body.WindowMinutes is { } minutes ? time.GetUtcNow().AddMinutes(minutes) : null,
                    TriggeredBy = $"manual:{user.GetUserId() ?? WorkflowEndpoints.UserName(user)}",
                }, ct);
            }
            catch (ScanLaunchException ex)
            {
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["scan"] = [ex.Message] }, statusCode: StatusCodes.Status422UnprocessableEntity);
            }
            await audit.WriteAsync(new AuditEntry("scan.started", "ScanRun", runId.ToString(), new { body.Name, body.WorkflowKey, body.NetworkIds }), ct);
            var run = await db.ScanRuns.AsNoTracking().FirstAsync(r => r.Id == runId, ct);
            return Results.Created($"/api/scans/{runId}", ToDto(run, await ProgressAsync(db, [runId], ct)));
        }).RequireAuthorization(Policies.CanEdit);

        scans.MapGet("/{id:guid}", async (Guid id, ScanningDbContext db, WorkflowsDbContext wdb, CancellationToken ct) =>
        {
            var run = await db.ScanRuns.AsNoTracking().FirstOrDefaultAsync(r => r.Id == id, ct);
            if (run is null) return Results.NotFound();
            var counts = await db.Jobs.AsNoTracking().Where(j => j.ScanRunId == id)
                .GroupBy(j => j.StepId).Select(g => new { StepId = g.Key, Total = g.Count(), Completed = g.Count(j => j.Status == JobStatus.Completed) })
                .ToDictionaryAsync(x => x.StepId, ct);
            var wf = await wdb.Runs.AsNoTracking().FirstOrDefaultAsync(w => w.ScanRunId == id, ct);
            var steps = new List<ScanStepDto>();
            if (wf is not null)
            {
                var order = JsonSerializer.Deserialize<ScanWorkflowDefinition>(wf.DefinitionJson, ContractJson.Options)!.Steps.Select(s => s.Id).ToList();
                var states = await wdb.StepRuns.AsNoTracking().Where(s => s.WorkflowRunId == wf.Id).ToListAsync(ct);
                steps = states.OrderBy(s => order.IndexOf(s.StepId)).Select(s => new ScanStepDto(s.StepId, s.Operation, s.Status,
                    counts.GetValueOrDefault(s.StepId)?.Total ?? 0, counts.GetValueOrDefault(s.StepId)?.Completed ?? 0, s.StartedAt, s.FinishedAt, s.Message)).ToList();
            }
            return Results.Ok(ToDto(run, await ProgressAsync(db, [id], ct)) with { Steps = steps });
        }).RequireAuthorization(Policies.CanRead);

        scans.MapPost("/{id:guid}/cancel", async (Guid id, IScanLauncher launcher, ScanningDbContext db, IAuditLog audit, ClaimsPrincipal user, CancellationToken ct) =>
        {
            var run = await db.ScanRuns.AsNoTracking().FirstOrDefaultAsync(r => r.Id == id, ct);
            if (run is null) return Results.NotFound();
            if (run.Status.IsTerminal()) return Results.Problem($"Scan is already {run.Status}.", statusCode: StatusCodes.Status409Conflict);
            await launcher.CancelAsync(id, $"by {WorkflowEndpoints.UserName(user)}", ct);
            await audit.WriteAsync(new AuditEntry("scan.cancelled", "ScanRun", id.ToString()), ct);
            return Results.Ok();
        }).RequireAuthorization(Policies.CanEdit);

        scans.MapGet("/{id:guid}/jobs", async (Guid id, JobStatus? status, int? page, int? pageSize, ScanningDbContext db, CancellationToken ct) =>
        {
            if (!await db.ScanRuns.AnyAsync(r => r.Id == id, ct)) return Results.NotFound();
            var query = db.Jobs.AsNoTracking().Where(j => j.ScanRunId == id);
            if (status is not null) query = query.Where(j => j.Status == status);
            return Results.Ok(await JobDto.QueryAsync(query, page, pageSize ?? 100, ct));
        }).RequireAuthorization(Policies.CanRead);

        scans.MapGet("/{id:guid}/events", async (Guid id, string? after, ScanningDbContext db, CancellationToken ct) =>
        {
            const int limit = 1000;
            var query = db.Events.AsNoTracking().Where(e => e.ScanRunId == id);
            if (Guid.TryParse(after, out var afterEventId))
            {
                var seq = await db.Events.Where(e => e.EventId == afterEventId).Select(e => (long?)e.Seq).FirstOrDefaultAsync(ct);
                if (seq is not null) query = query.Where(e => e.Seq > seq);
            }
            else if (DateTimeOffset.TryParse(after, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out var afterTime))
            {
                query = query.Where(e => e.OccurredAt > afterTime.ToUniversalTime());
            }
            else
            {
                // No cursor: the latest events (a client loading a long run wants the tail), still returned oldest first.
                query = query.OrderByDescending(e => e.Seq).Take(limit);
            }
            var payloads = await query.OrderBy(e => e.Seq).Take(limit).Select(e => e.PayloadJson).ToListAsync(ct);
            return payloads.Select(p => JsonSerializer.Deserialize<ScanExecutionEvent>(p, ContractJson.Options)!).ToList();
        }).RequireAuthorization(Policies.CanRead);
    }

    private static async Task<Dictionary<Guid, ScanProgressDto>> ProgressAsync(ScanningDbContext db, IReadOnlyList<Guid> runIds, CancellationToken ct)
    {
        var rows = await db.Jobs.AsNoTracking().Where(j => runIds.Contains(j.ScanRunId))
            .GroupBy(j => new { j.ScanRunId, j.Status }).Select(g => new { g.Key.ScanRunId, g.Key.Status, Count = g.Count() }).ToListAsync(ct);
        return rows.GroupBy(r => r.ScanRunId).ToDictionary(g => g.Key, g =>
        {
            int C(JobStatus s) => g.Where(r => r.Status == s).Sum(r => r.Count);
            var total = g.Sum(r => r.Count);
            var done = C(JobStatus.Completed) + C(JobStatus.Failed) + C(JobStatus.Cancelled);
            return new ScanProgressDto(total, C(JobStatus.Queued), C(JobStatus.Leased), C(JobStatus.Completed), C(JobStatus.Failed),
                total == 0 ? 0 : Math.Round(100.0 * done / total, 1));
        });
    }

    private static ScanRunDto ToDto(ScanRun r, IReadOnlyDictionary<Guid, ScanProgressDto> progress) => new(
        r.Id, r.Name, r.Status, r.WorkflowKey, r.WorkflowVersion, r.NetworkIds, r.TriggeredBy, r.Priority, r.MaxRatePerSecond, r.ScheduleId,
        r.CreatedAt, r.StartedAt, r.FinishedAt, r.NotAfter,
        progress.GetValueOrDefault(r.Id) ?? new ScanProgressDto(0, 0, 0, 0, 0, r.Status.IsTerminal() ? 100 : 0), r.CoverageComplete, r.Message);
}
