using Testcontainers.PostgreSql;

namespace WebScan.E2ETests.Infrastructure;

/// <summary>One PostgreSQL container for the whole E2E collection; each test class gets its own database.</summary>
public sealed class PostgresFixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer _container = new PostgreSqlBuilder()
        .WithImage("postgres:17-alpine")
        .WithDatabase("postgres")
        .WithUsername("webscan")
        .WithPassword("webscan")
        .Build();

    private int _dbCounter;

    public Task InitializeAsync() => _container.StartAsync();
    public Task DisposeAsync() => _container.DisposeAsync().AsTask();

    /// <summary>Connection string to a fresh, empty database (created lazily by EF migrations).</summary>
    public string NewDatabase()
    {
        var name = $"webscan_e2e_{Interlocked.Increment(ref _dbCounter)}_{Guid.NewGuid():N}"[..40];
        var builder = new Npgsql.NpgsqlConnectionStringBuilder(_container.GetConnectionString()) { Database = name };
        return builder.ConnectionString;
    }
}

[CollectionDefinition(Name)]
public sealed class E2ECollection : ICollectionFixture<PostgresFixture>
{
    public const string Name = "e2e";
}
