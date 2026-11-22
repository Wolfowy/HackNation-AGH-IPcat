using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;

namespace WebScan.Server.Modules.Agents;

/// <summary><c>Agents</c> configuration section (+ <c>Tools:AutoApprove</c>).</summary>
public sealed class AgentsOptions
{
    public int HeartbeatTimeoutSeconds { get; set; } = 90;
    public int HeartbeatIntervalSeconds { get; set; } = 30;
    public int JobPollIntervalSeconds { get; set; } = 5;
    public int OfflineCheckIntervalSeconds { get; set; } = 15;
    public int SecretRotationGraceMinutes { get; set; } = 60;

    /// <summary>Dev/compose convenience: an enrollment token seeded (or refreshed) at startup.</summary>
    public string? BootstrapEnrollmentToken { get; set; }

    public bool BootstrapEnrollmentAutoApprove { get; set; } = true;
    public List<string> BootstrapEnrollmentZones { get; set; } = [];

    /// <summary>Tool ids approved on first sight (<c>Tools:AutoApprove</c>).</summary>
    public List<string> AutoApproveTools { get; set; } = [];

    public TimeSpan HeartbeatTimeout => TimeSpan.FromSeconds(HeartbeatTimeoutSeconds);

    internal static void Bind(AgentsOptions options, IConfiguration configuration)
    {
        configuration.GetSection("Agents").Bind(options);
        options.BootstrapEnrollmentZones = ReadList(configuration.GetSection("Agents:BootstrapEnrollmentZones"), []);
        options.AutoApproveTools = ReadList(configuration.GetSection("Tools:AutoApprove"), ["nmap", "naabu", "masscan", "httpx", "nuclei"]);
    }

    /// <summary>Accepts either a JSON array / indexed keys or a comma-separated string (handy in environment variables).</summary>
    private static List<string> ReadList(IConfigurationSection section, List<string> defaults)
    {
        var items = section.GetChildren().Any()
            ? section.GetChildren().Select(c => c.Value)
            : section.Value?.Split(',') ?? defaults.ToArray();
        return items.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s!.Trim()).Distinct().ToList();
    }
}

/// <summary>256-bit random secrets/tokens, stored only as SHA-256.</summary>
internal static class AgentSecrets
{
    public static string NewSecret() => Base64Url(RandomNumberGenerator.GetBytes(32));

    public static byte[] Hash(string secret) => SHA256.HashData(Encoding.UTF8.GetBytes(secret));

    public static bool Matches(string secret, byte[]? expectedHash) =>
        expectedHash is { Length: 32 } && CryptographicOperations.FixedTimeEquals(Hash(secret), expectedHash);

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
