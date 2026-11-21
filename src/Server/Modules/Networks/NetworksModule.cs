using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WebScan.Server.Infrastructure.Http;
using WebScan.Server.Infrastructure.Persistence;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Modules.Networks.Persistence;

namespace WebScan.Server.Modules.Networks;

public static class NetworksModule
{
    public static IServiceCollection AddNetworksModule(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddModuleDbContext<NetworksDbContext>(NetworksDbContext.Schema);
        services.AddScoped<INetworkScopeService, NetworkScopeService>();
        services.AddHostedService<ScopePolicySeeder>();
        return services;
    }

    public static IEndpointRouteBuilder MapNetworksEndpoints(this IEndpointRouteBuilder endpoints)
    {
        NetworksEndpoints.Map(endpoints);
        return endpoints;
    }
}

/// <summary>
/// Resolves enabled networks for the planner. Include entries are re-checked against the current scope policy
/// (entries outside it are clipped or dropped), so narrowing the policy immediately narrows what can be scanned.
/// </summary>
internal sealed class NetworkScopeService(NetworksDbContext db, ILogger<NetworkScopeService> logger) : INetworkScopeService
{
    public async Task<ResolvedScope> ResolveAsync(IReadOnlyCollection<Guid> networkIds, CancellationToken ct = default)
    {
        var policy = await db.ScopePolicies.AsNoTracking().SingleOrDefaultAsync(ct);
        var rules = ScopeRules.Create(policy?.Allowed ?? [], policy?.Excluded ?? []);
        var networks = await db.Networks.AsNoTracking().Where(n => networkIds.Contains(n.Id) && n.Enabled).OrderBy(n => n.Name).ToListAsync(ct);

        var segments = new List<ScopeSegment>();
        foreach (var network in networks)
        {
            var include = rules.Restrict(network.Ranges);
            if (include.Count < network.Ranges.Count || !include.SequenceEqual(network.Ranges))
                logger.LogWarning("Network {Network} has ranges outside the scope policy; they are not scanned", network.Name);
            if (include.Count == 0) continue;
            segments.Add(new ScopeSegment
            {
                NetworkId = network.Id,
                NetworkName = network.Name,
                Zone = network.Zone,
                Include = include,
                Exclude = network.Exclusions,
                MaxRatePerSecond = network.MaxRatePerSecond,
            });
        }
        return new ResolvedScope { Segments = segments, GlobalExclusions = policy?.Excluded ?? [] };
    }

    public async Task<bool> IsAuthorizedAsync(string target, CancellationToken ct = default) =>
        (await NetworksEndpoints.LoadRulesAsync(db, ct)).IsAuthorized(target);
}

/// <summary>Seeds the scope policy from <c>Networks:SeedScopePolicy:Allowed/Excluded</c> while the policy is empty.</summary>
internal sealed class ScopePolicySeeder(IServiceScopeFactory scopes, IConfiguration configuration, TimeProvider time,
    ILogger<ScopePolicySeeder> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var allowed = ReadList("Networks:SeedScopePolicy:Allowed");
        if (allowed.Count == 0) return;
        var excluded = ReadList("Networks:SeedScopePolicy:Excluded");

        var errors = new ValidationErrors();
        ScopeRules.ValidateEntries(errors, "Networks:SeedScopePolicy:Allowed", allowed, allowWildcards: true, required: true);
        ScopeRules.ValidateEntries(errors, "Networks:SeedScopePolicy:Excluded", excluded, allowWildcards: true, required: false);
        if (!errors.IsValid) throw new InvalidOperationException($"Invalid scope policy seed: {string.Join("; ", errors.Messages)}");

        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<NetworksDbContext>();
        var current = await db.ScopePolicies.AsNoTracking().SingleOrDefaultAsync(cancellationToken);
        if (current is { Allowed.Count: > 0 }) return;

        await NetworksEndpoints.SetPolicyAsync(db, allowed, excluded, time.GetUtcNow(), cancellationToken);
        logger.LogInformation("Scope policy seeded from configuration: allowed {Allowed}, excluded {Excluded}",
            string.Join(",", allowed), string.Join(",", excluded));
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    // Array (Allowed:0, Allowed:1) or comma-separated string (environment variables).
    private List<string> ReadList(string key)
    {
        var section = configuration.GetSection(key);
        var values = section.GetChildren().Any() ? section.GetChildren().Select(c => c.Value ?? "") : (section.Value ?? "").Split(',');
        return values.Select(v => v.Trim()).Where(v => v.Length > 0).ToList();
    }
}
