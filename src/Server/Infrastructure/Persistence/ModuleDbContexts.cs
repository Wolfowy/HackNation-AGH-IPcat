using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace WebScan.Server.Infrastructure.Persistence;

/// <summary>
/// Modular monolith persistence: every module owns one DbContext mapped to its own PostgreSQL schema,
/// with its own migrations and migrations-history table. Modules reference each other only by ids.
/// </summary>
public sealed class ModuleDbContextRegistry
{
    private readonly List<Type> _contexts = [];
    public IReadOnlyList<Type> Contexts => _contexts;
    public void Register<TContext>() where TContext : DbContext
    {
        if (!_contexts.Contains(typeof(TContext))) _contexts.Add(typeof(TContext));
    }
}

public static class ModuleDbContextExtensions
{
    public const string ConnectionStringName = "WebScan";

    public static ModuleDbContextRegistry GetModuleDbContextRegistry(this IServiceCollection services)
    {
        var existing = services.FirstOrDefault(d => d.ServiceType == typeof(ModuleDbContextRegistry))?.ImplementationInstance;
        if (existing is ModuleDbContextRegistry registry) return registry;
        registry = new ModuleDbContextRegistry();
        services.AddSingleton(registry);
        return registry;
    }

    /// <summary>Registers a module DbContext on the shared PostgreSQL database using schema <paramref name="schema"/>.</summary>
    public static IServiceCollection AddModuleDbContext<TContext>(this IServiceCollection services, string schema)
        where TContext : DbContext
    {
        services.AddDbContext<TContext>((sp, options) =>
        {
            if (sp.GetService<IDataProtectionProvider>() is { } dataProtection) FieldEncryption.Use(dataProtection);
            var cs = sp.GetRequiredService<IConfiguration>().GetConnectionString(ConnectionStringName)
                     ?? throw new InvalidOperationException($"Connection string '{ConnectionStringName}' is not configured.");
            ConfigureNpgsql<TContext>(options, cs, schema);
        });
        services.GetModuleDbContextRegistry().Register<TContext>();
        return services;
    }

    public static void ConfigureNpgsql<TContext>(DbContextOptionsBuilder options, string connectionString, string schema)
        where TContext : DbContext =>
        options.UseNpgsql(connectionString, npg => npg
            .MigrationsHistoryTable("__EFMigrationsHistory", schema)
            .MigrationsAssembly(typeof(TContext).Assembly.FullName));

    /// <summary>Applies pending migrations of every registered module context (sequentially, deterministic order).</summary>
    public static async Task MigrateModuleDatabasesAsync(this IServiceProvider services, CancellationToken ct = default)
    {
        var registry = services.GetRequiredService<ModuleDbContextRegistry>();
        foreach (var type in registry.Contexts)
        {
            await using var scope = services.CreateAsyncScope();
            var db = (DbContext)scope.ServiceProvider.GetRequiredService(type);
            await db.Database.MigrateAsync(ct);
        }
    }
}

/// <summary>Base design-time factory so <c>dotnet ef migrations add</c> works per module project.</summary>
public abstract class ModuleDesignTimeFactory<TContext> : IDesignTimeDbContextFactory<TContext> where TContext : DbContext
{
    protected abstract string Schema { get; }

    public TContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<TContext>();
        var cs = Environment.GetEnvironmentVariable("WEBSCAN_DESIGN_CONNECTION")
                 ?? "Host=localhost;Database=webscan;Username=webscan;Password=webscan";
        ModuleDbContextExtensions.ConfigureNpgsql<TContext>(options, cs, Schema);
        return (TContext)Activator.CreateInstance(typeof(TContext), options.Options)!;
    }
}
