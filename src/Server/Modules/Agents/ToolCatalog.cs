using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WebScan.Contracts;
using WebScan.Server.Modules.Agents.Persistence;

namespace WebScan.Server.Modules.Agents;

/// <summary>Records every reported tool id. New ids are unapproved unless listed in <c>Tools:AutoApprove</c>.</summary>
internal sealed class ToolCatalog(AgentsDbContext db, IOptions<AgentsOptions> options, TimeProvider time)
{
    /// <summary>Upserts the reported tools (capability/version union) and returns the ids that cannot receive jobs.</summary>
    public async Task<IReadOnlyList<string>> RecordAsync(IReadOnlyList<ToolDescriptor> tools, CancellationToken ct)
    {
        if (tools.Count == 0) return [];
        var now = time.GetUtcNow();
        var autoApprove = options.Value.AutoApproveTools;

        // Insert-if-missing first so concurrent registrations of a brand-new tool cannot collide on the primary key.
        foreach (var id in tools.Select(t => t.Id).Distinct())
        {
            var approved = autoApprove.Contains(id, StringComparer.OrdinalIgnoreCase);
            await db.Database.ExecuteSqlAsync($"""
                INSERT INTO agents.tool_catalog ("ToolId", "Approved", "Enabled", "Capabilities", "Versions", "FirstSeenAt")
                VALUES ({id}, {approved}, TRUE, {Array.Empty<string>()}, {Array.Empty<string>()}, {now})
                ON CONFLICT ("ToolId") DO NOTHING
                """, ct);
        }

        var ids = tools.Select(t => t.Id).Distinct().ToList();
        var entries = await db.Tools.Where(t => ids.Contains(t.ToolId)).ToDictionaryAsync(t => t.ToolId, ct);
        foreach (var tool in tools)
        {
            var entry = entries[tool.Id];
            var capabilities = entry.Capabilities.Union(tool.Capabilities).Order().ToList();
            if (!capabilities.SequenceEqual(entry.Capabilities)) entry.Capabilities = capabilities;
            if (!entry.Versions.Contains(tool.Version)) entry.Versions = [.. entry.Versions, tool.Version];
        }
        await db.SaveChangesAsync(ct);
        return entries.Values.Where(e => !e.IsUsable).Select(e => e.ToolId).Order().ToList();
    }
}
