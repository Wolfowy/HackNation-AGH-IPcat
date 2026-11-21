using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WebScan.Agent.Inventory;
using WebScan.Agent.Storage;
using WebScan.Agent.Tools;
using WebScan.Contracts;

namespace WebScan.Agent.Communication;

/// <summary>Registration state shared by the agent loops.</summary>
public sealed class AgentState
{
    private int _reRegister;

    public bool IsRegistered { get; set; }
    public AgentStatus? Status { get; set; }
    public int HeartbeatIntervalSeconds { get; set; } = 30;
    public int JobPollIntervalSeconds { get; set; } = 5;
    public string? RegisteredInventoryHash { get; set; }

    public bool CanClaim => IsRegistered && Status == AgentStatus.Active;

    public void RequestReRegistration() => Interlocked.Exchange(ref _reRegister, 1);
    public bool ConsumeReRegistration() => Interlocked.Exchange(ref _reRegister, 0) == 1;
}

/// <summary>Enrollment, (re-)registration and credential rotation.</summary>
public sealed class AgentRegistrar(
    AgentApiClient api,
    CredentialStore credentials,
    ToolRegistry tools,
    NetworkInventory inventory,
    AgentState state,
    IOptionsMonitor<AgentOptions> options,
    ILogger<AgentRegistrar> logger)
{
    public static readonly string AgentVersion =
        typeof(AgentRegistrar).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "0.0.0";

    public async Task<AgentRegistration> BuildRegistrationAsync(CancellationToken ct)
    {
        var o = options.CurrentValue;
        var (platform, description) = NetworkInventory.OperatingSystemInfo();
        return new AgentRegistration
        {
            AgentId = credentials.Current?.AgentId ?? AgentPaths.DefaultAgentId(o),
            Hostname = Environment.MachineName,
            OsPlatform = platform,
            OsDescription = description,
            AgentVersion = AgentVersion,
            Tools = tools.Descriptors(),
            Interfaces = inventory.GetInterfaces(),
            Routes = await inventory.GetRoutesAsync(ct),
            DeclaredZones = [.. o.DeclaredZones],
            Resources = NetworkInventory.Resources(),
            Limits = new AgentLimits { MaxConcurrentJobs = o.MaxConcurrentJobs, MaxRatePerSecond = o.MaxRatePerSecond },
        };
    }

    /// <summary>
    /// Lowercase hex SHA-256 of the <see cref="ContractJson"/> serialization of <c>{ tools, interfaces, routes }</c> of a registration.
    /// Sent with every heartbeat; the agent re-registers by itself when it changes.
    /// </summary>
    public static string InventoryHash(AgentRegistration r) =>
        Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new { tools = r.Tools, interfaces = r.Interfaces, routes = r.Routes }, ContractJson.Options)));

    /// <summary>Registers with stored credentials, or enrolls with <c>Agent:EnrollmentToken</c>. Returns false when it cannot.</summary>
    public async Task<bool> RegisterAsync(CancellationToken ct)
    {
        var token = options.CurrentValue.EnrollmentToken;
        var stored = credentials.Current;
        if (stored is null && string.IsNullOrWhiteSpace(token))
        {
            logger.LogError("No stored agent credentials and no Agent:EnrollmentToken configured; cannot register.");
            return false;
        }

        var registration = await BuildRegistrationAsync(ct);
        AgentRegistrationResponse response;
        try
        {
            response = await api.RegisterAsync(registration, stored is null ? token : null, ct);
        }
        catch (AgentApiException ex) when (ex.IsAuthenticationFailure && stored is not null && !string.IsNullOrWhiteSpace(token))
        {
            logger.LogWarning("Stored credentials were rejected; enrolling again with the enrollment token.");
            credentials.Clear();
            response = await api.RegisterAsync(registration, token, ct);
        }

        if (response.AgentSecret is { Length: > 0 } secret) credentials.Save(new AgentCredentials(response.AgentId, secret));
        else if (credentials.Current is null)
        {
            logger.LogError("Enrollment succeeded but the server returned no agent secret.");
            return false;
        }

        state.IsRegistered = true;
        state.Status = response.Status;
        state.HeartbeatIntervalSeconds = Math.Max(1, options.CurrentValue.HeartbeatIntervalSeconds ?? response.HeartbeatIntervalSeconds);
        state.JobPollIntervalSeconds = Math.Max(1, response.JobPollIntervalSeconds);
        state.RegisteredInventoryHash = InventoryHash(registration);
        logger.LogInformation("Registered as {AgentId} (status {Status}) with {Tools} tool(s).", response.AgentId, response.Status, registration.Tools.Count);
        if (response.UnapprovedTools.Count > 0)
            logger.LogWarning("Tools awaiting approval on the server (no jobs until approved): {Tools}.", string.Join(", ", response.UnapprovedTools));
        return true;
    }

    public async Task RotateCredentialsAsync(CancellationToken ct)
    {
        var current = credentials.Current ?? throw new InvalidOperationException("No credentials to rotate.");
        var response = await api.RotateCredentialsAsync(ct);
        credentials.Save(current with { Secret = response.AgentSecret });
        logger.LogInformation("Agent credentials rotated; previous secret valid until {Until}.", response.PreviousSecretValidUntil);
    }

    /// <summary>True when tools/interfaces/routes changed since the last registration.</summary>
    public async Task<bool> InventoryChangedAsync(CancellationToken ct) =>
        state.RegisteredInventoryHash is { } registered && InventoryHash(await BuildRegistrationAsync(ct)) != registered;
}
