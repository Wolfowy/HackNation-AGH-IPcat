using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Npgsql;
using WebScan.Contracts;
using WebScan.Server.Modules.Workflows.Persistence;

namespace WebScan.Server.Modules.Workflows.Definitions;

public sealed record WorkflowSummary(string Key, int LatestVersion, string Name, string? Description, DateTimeOffset UpdatedAt);

public sealed record WorkflowVersionDto(string Key, int Version, ScanWorkflowDefinition Definition, DateTimeOffset CreatedAt, string CreatedBy);

public enum SaveStatus { Saved, Invalid, Conflict, NotFound }

public sealed record SaveResult(SaveStatus Status, WorkflowVersionDto? Saved = null, IReadOnlyList<string>? Errors = null);

/// <summary>Versioned, immutable workflow definitions (a change is always a new version).</summary>
public sealed class WorkflowDefinitionStore(WorkflowsDbContext db, TimeProvider time)
{
    public async Task<IReadOnlyList<WorkflowSummary>> ListAsync(CancellationToken ct = default)
    {
        var rows = await db.Definitions.AsNoTracking().ToListAsync(ct);
        return rows.GroupBy(r => r.Key).Select(g => g.MaxBy(r => r.Version)!)
            .OrderBy(r => r.Key, StringComparer.Ordinal)
            .Select(r => new WorkflowSummary(r.Key, r.Version, r.Name, r.Description, r.CreatedAt)).ToList();
    }

    /// <summary>Specific version, or the latest when <paramref name="version"/> is null.</summary>
    public async Task<WorkflowVersionDto?> GetAsync(string key, int? version, CancellationToken ct = default)
    {
        var query = db.Definitions.AsNoTracking().Where(d => d.Key == key);
        var row = version is { } v ? await query.FirstOrDefaultAsync(d => d.Version == v, ct) : await query.OrderByDescending(d => d.Version).FirstOrDefaultAsync(ct);
        return row is null ? null : ToDto(row);
    }

    public async Task<IReadOnlyList<WorkflowVersionDto>> VersionsAsync(string key, CancellationToken ct = default) =>
        (await db.Definitions.AsNoTracking().Where(d => d.Key == key).OrderBy(d => d.Version).ToListAsync(ct)).Select(ToDto).ToList();

    public async Task<SaveResult> CreateAsync(ScanWorkflowDefinition definition, string createdBy, CancellationToken ct = default)
    {
        var errors = WorkflowValidator.Validate(definition);
        if (errors.Count > 0) return new SaveResult(SaveStatus.Invalid, Errors: errors);
        if (await db.Definitions.AnyAsync(d => d.Key == definition.Key, ct))
            return new SaveResult(SaveStatus.Conflict, Errors: [$"Workflow '{definition.Key}' already exists; add a new version instead."]);
        return await InsertAsync(definition, 1, createdBy, ct);
    }

    public async Task<SaveResult> AddVersionAsync(string key, ScanWorkflowDefinition definition, string createdBy, CancellationToken ct = default)
    {
        definition = definition with { Key = key };
        var errors = WorkflowValidator.Validate(definition);
        if (errors.Count > 0) return new SaveResult(SaveStatus.Invalid, Errors: errors);
        var latest = await db.Definitions.Where(d => d.Key == key).MaxAsync(d => (int?)d.Version, ct);
        if (latest is null) return new SaveResult(SaveStatus.NotFound, Errors: [$"Workflow '{key}' does not exist."]);
        return await InsertAsync(definition, latest.Value + 1, createdBy, ct);
    }

    public async Task EnsureSeededAsync(CancellationToken ct = default)
    {
        var standard = StandardWorkflows.StandardDiscovery;
        if (!await db.Definitions.AnyAsync(d => d.Key == standard.Key, ct))
            await InsertAsync(standard, 1, "system", ct);
    }

    private async Task<SaveResult> InsertAsync(ScanWorkflowDefinition definition, int version, string createdBy, CancellationToken ct)
    {
        var saved = WorkflowValidator.Normalize(definition) with { Version = version };
        var row = new WorkflowDefinitionRecord
        {
            Key = saved.Key, Version = version, Name = saved.Name, Description = saved.Description, CreatedAt = time.GetUtcNow(), CreatedBy = createdBy,
            DefinitionJson = JsonSerializer.Serialize(saved, ContractJson.Options),
        };
        db.Definitions.Add(row);
        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            db.ChangeTracker.Clear();
            return new SaveResult(SaveStatus.Conflict, Errors: [$"Version {version} of '{saved.Key}' was created concurrently; retry."]);
        }
        return new SaveResult(SaveStatus.Saved, ToDto(row));
    }

    private static WorkflowVersionDto ToDto(WorkflowDefinitionRecord r) =>
        new(r.Key, r.Version, JsonSerializer.Deserialize<ScanWorkflowDefinition>(r.DefinitionJson, ContractJson.Options)!, r.CreatedAt, r.CreatedBy);
}

/// <summary>Seeds built-in workflows once the host starts (after migrations).</summary>
public sealed class WorkflowSeeder(IServiceScopeFactory scopes) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = scopes.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<WorkflowDefinitionStore>().EnsureSeededAsync(cancellationToken);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
