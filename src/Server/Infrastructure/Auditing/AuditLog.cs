using System.Text.Json;
using Microsoft.AspNetCore.Http;
using WebScan.Contracts;
using WebScan.Server.Infrastructure.Persistence;
using WebScan.Server.Kernel.Security;

namespace WebScan.Server.Infrastructure.Auditing;

/// <summary>Writes audit entries immediately (own SaveChanges) so they survive a later failure of the caller.</summary>
internal sealed class DbAuditLog(InfraDbContext db, ICurrentUser user, IHttpContextAccessor http, TimeProvider time) : IAuditLog
{
    public async Task WriteAsync(AuditEntry entry, CancellationToken ct = default)
    {
        db.AuditEntries.Add(new AuditRecord
        {
            Id = Guid.CreateVersion7(),
            OccurredAt = time.GetUtcNow(),
            UserId = user.UserId,
            UserName = user.UserName,
            Action = entry.Action,
            EntityType = entry.EntityType,
            EntityId = entry.EntityId,
            Details = entry.Details is null ? null : JsonSerializer.Serialize(entry.Details, ContractJson.Options),
            IpAddress = http.HttpContext?.Connection.RemoteIpAddress?.ToString(),
        });
        await db.SaveChangesAsync(ct);
    }
}
