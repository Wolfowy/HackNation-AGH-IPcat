using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WebScan.Server.Infrastructure.Persistence;
using Wolverine.Attributes;
using Wolverine.EntityFrameworkCore;
using Wolverine.Tracking;

namespace WebScan.Server.UnitTests.Integration;

public sealed record StoreSettingProbe(string Key, string Value);

public sealed record SettingStoredProbe(string Key);

/// <summary>Discovered only in tests (WebScanFactory adds this assembly): the pattern module handlers use.</summary>
public static class StoreSettingProbeHandler
{
    // Wolverine opens the transaction, saves the DbContext and persists the cascaded message in the same transaction.
    [Transactional]
    public static SettingStoredProbe Handle(StoreSettingProbe message, InfraDbContext db)
    {
        db.Settings.Add(new SettingRecord { Key = message.Key, Value = message.Value, UpdatedAt = DateTimeOffset.UtcNow });
        return new SettingStoredProbe(message.Key);
    }

    public static void Handle(SettingStoredProbe message) { }
}

[Collection("server")]
public sealed class MessagingTests(WebScanFactory factory)
{
    [Fact]
    public async Task Handlers_with_a_module_DbContext_run_in_a_transaction_and_cascade_messages()
    {
        var key = $"probe.{Guid.NewGuid():N}";
        var session = await factory.Services.TrackActivity().Timeout(TimeSpan.FromSeconds(30))
            .InvokeMessageAndWaitAsync(new StoreSettingProbe(key, "stored"));

        Assert.Contains(session.Executed.MessagesOf<SettingStoredProbe>(), m => m.Key == key);
        await using var scope = factory.Services.CreateAsyncScope();
        Assert.Equal("stored", (await scope.ServiceProvider.GetRequiredService<InfraDbContext>().Settings.SingleAsync(s => s.Key == key)).Value);
    }

    [Fact]
    public async Task DbContext_outbox_commits_entity_and_message_together()
    {
        var key = $"outbox.{Guid.NewGuid():N}";
        var session = await factory.Services.TrackActivity().Timeout(TimeSpan.FromSeconds(30))
            .ExecuteAndWaitAsync((Func<Wolverine.IMessageContext, Task>)(async _ =>
            {
                await using var scope = factory.Services.CreateAsyncScope();
                var outbox = scope.ServiceProvider.GetRequiredService<IDbContextOutbox<InfraDbContext>>();
                outbox.DbContext.Settings.Add(new SettingRecord { Key = key, Value = "v", UpdatedAt = DateTimeOffset.UtcNow });
                await outbox.PublishAsync(new SettingStoredProbe(key));
                await outbox.SaveChangesAndFlushMessagesAsync();
            }));

        Assert.Contains(session.Executed.MessagesOf<SettingStoredProbe>(), m => m.Key == key);
        await using var verify = factory.Services.CreateAsyncScope();
        Assert.True(await verify.ServiceProvider.GetRequiredService<InfraDbContext>().Settings.AnyAsync(s => s.Key == key));
    }
}
