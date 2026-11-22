using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace WebScan.Server.Infrastructure.Persistence;

/// <summary>
/// Encrypts one column value with the Data Protection key ring (AES-256-GCM, authenticated; keys roll over automatically and
/// retired keys keep decrypting). Stored form: <c>enc:v1:</c> + Data Protection payload (key id, nonce, ciphertext, tag).
/// Values without the prefix are legacy plaintext and are returned unchanged (see <see cref="FieldEncryptionBackfill"/>).
/// </summary>
public sealed class FieldEncryptor(IDataProtectionProvider provider)
{
    public const string Prefix = "enc:v1:";

    private readonly IDataProtector _protector = provider.CreateProtector("WebScan.FieldEncryption.v1");

    public IDataProtectionProvider Provider => provider;

    public static bool IsEncrypted(string stored) => stored.StartsWith(Prefix, StringComparison.Ordinal);

    public string Encrypt(string plaintext) => Prefix + _protector.Protect(plaintext);

    /// <summary>Throws <see cref="System.Security.Cryptography.CryptographicException"/> for tampered values or unknown keys.</summary>
    public string Decrypt(string stored) => IsEncrypted(stored) ? _protector.Unprotect(stored[Prefix.Length..]) : stored;
}

/// <summary>
/// Application-level encryption at rest for sensitive columns (PostgreSQL OSS has no TDE): <c>e.Property(x => x.Notes).HasEncryptedConversion()</c>.
/// Encrypted columns hold random-nonce ciphertext, so they must never be filtered, sorted, grouped or joined on in SQL.
/// </summary>
public static class FieldEncryption
{
    // EF Core caches the model, and with it this converter, per process rather than per host, so the converter cannot capture the
    // host's key ring; every module DbContext activation points it at its host's key ring instead (one server host per process).
    private static volatile FieldEncryptor? _current;

    public static readonly ValueConverter<string, string> Converter = new(v => Current.Encrypt(v), v => Current.Decrypt(v));

    /// <summary>Stores a string property encrypted in a <c>text</c> column (nulls stay null).</summary>
    public static PropertyBuilder<T> HasEncryptedConversion<T>(this PropertyBuilder<T> property) =>
        property.HasConversion(Converter).HasColumnType("text");

    public static void Use(IDataProtectionProvider provider)
    {
        if (!ReferenceEquals(_current?.Provider, provider)) _current = new FieldEncryptor(provider);
    }

    private static FieldEncryptor Current => _current
        ?? throw new InvalidOperationException("Encrypted columns need Data Protection registered in the host (AddWebScanSecretProtection).");
}

/// <summary>
/// At startup: warns when the key ring is stored unprotected in Production, then re-encrypts legacy plaintext values of every
/// encrypted column of the registered module contexts in keyset-paged batches. Idempotent and safe to run on several nodes at once
/// (an update only applies while the row still holds the plaintext it read).
/// </summary>
public sealed class FieldEncryptionBackfill(IServiceScopeFactory scopes, ModuleDbContextRegistry registry, IConfiguration configuration,
    IHostEnvironment environment, ILogger<FieldEncryptionBackfill> logger) : BackgroundService
{
    public const int BatchSize = 500;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (environment.IsProduction() && string.IsNullOrWhiteSpace(configuration["DataProtection:CertificatePath"]))
            logger.LogWarning("DataProtection:CertificatePath is not set: the Data Protection key ring that encrypts sensitive columns is " +
                              "stored unencrypted in infra.data_protection_keys, so a database dump also contains the keys.");
        try
        {
            await RunAsync(stoppingToken);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            logger.LogError(e, "Encrypting legacy plaintext columns failed; it is retried at the next start.");
        }
    }

    /// <summary>Returns the number of values encrypted.</summary>
    public async Task<int> RunAsync(CancellationToken ct)
    {
        var total = 0;
        foreach (var contextType in registry.Contexts)
        {
            await using var scope = scopes.CreateAsyncScope();
            var db = (DbContext)scope.ServiceProvider.GetRequiredService(contextType);
            foreach (var entity in db.Model.GetEntityTypes().Where(e => !e.IsOwned() && e.GetTableName() is not null))
            {
                var table = $"{Quote(entity.GetSchema() ?? "public")}.{Quote(entity.GetTableName()!)}";
                var key = entity.FindPrimaryKey()!.Properties.Select(p => Quote(p.GetColumnName())).ToArray();
                foreach (var property in entity.GetProperties().Where(p => p.GetValueConverter() == FieldEncryption.Converter))
                    total += await EncryptColumnAsync(db, table, key, Quote(property.GetColumnName()), ct);
            }
        }
        return total;
    }

    private async Task<int> EncryptColumnAsync(DbContext db, string table, string[] key, string column, CancellationToken ct)
    {
        var keys = string.Join(", ", key);
        var after = $"({keys}) > ({string.Join(", ", key.Select((_, i) => $"${i + 1}"))}) AND ";
        var update = $"UPDATE {table} SET {column} = $1 WHERE {column} = $2 AND " + string.Join(" AND ", key.Select((k, i) => $"{k} = ${i + 3}"));
        var connection = (NpgsqlConnection)db.Database.GetDbConnection();
        await db.Database.OpenConnectionAsync(ct);
        object[]? last = null;
        var encrypted = 0;
        while (true)
        {
            var rows = new List<object[]>();
            await using (var select = new NpgsqlCommand($"""
                SELECT {keys}, {column} FROM {table}
                WHERE {(last is null ? "" : after)}{column} IS NOT NULL AND NOT starts_with({column}, '{FieldEncryptor.Prefix}')
                ORDER BY {keys} LIMIT {BatchSize}
                """, connection))
            {
                foreach (var value in last ?? []) select.Parameters.Add(new NpgsqlParameter { Value = value });
                await using var reader = await select.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct))
                {
                    var row = new object[key.Length + 1];
                    reader.GetValues(row);
                    rows.Add(row);
                }
            }
            if (rows.Count == 0) break;

            await using var batch = new NpgsqlBatch(connection);
            foreach (var row in rows)
            {
                var plaintext = (string)row[^1];
                var command = new NpgsqlBatchCommand(update);
                command.Parameters.Add(new NpgsqlParameter { Value = FieldEncryption.Converter.ConvertToProvider(plaintext) });
                command.Parameters.Add(new NpgsqlParameter { Value = plaintext });
                foreach (var keyValue in row[..^1]) command.Parameters.Add(new NpgsqlParameter { Value = keyValue });
                batch.BatchCommands.Add(command);
            }
            encrypted += await batch.ExecuteNonQueryAsync(ct);
            logger.LogInformation("Encrypted legacy plaintext in {Table}.{Column}: {Count} value(s) so far", table, column, encrypted);
            if (rows.Count < BatchSize) break;
            last = rows[^1][..^1];
        }
        return encrypted;
    }

    private static string Quote(string identifier) => $"\"{identifier.Replace("\"", "\"\"")}\"";
}
