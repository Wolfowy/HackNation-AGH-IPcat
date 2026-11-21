using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using WebScan.Contracts;

namespace WebScan.Agent.Storage;

public sealed record AgentCredentials(string AgentId, string Secret);

public static partial class AgentPaths
{
    public static string DataDirectory(AgentOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.DataDirectory)) return Path.GetFullPath(options.DataDirectory);
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return string.IsNullOrEmpty(local) ? Path.Combine(AppContext.BaseDirectory, "data") : Path.Combine(local, "webscan-agent");
    }

    /// <summary>Configured id, else the hostname reduced to <see cref="AgentRegistration.AgentIdPattern"/>.</summary>
    public static string DefaultAgentId(AgentOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.AgentId)) return options.AgentId.Trim();
        var id = Invalid().Replace(Environment.MachineName.ToLowerInvariant(), "-").Trim('-', '.', '_');
        if (id.Length > 64) id = id[..64];
        return Regex.IsMatch(id, AgentRegistration.AgentIdPattern) ? id : $"agent-{id}".TrimEnd('-');
    }

    [GeneratedRegex("[^a-z0-9_.-]+")]
    private static partial Regex Invalid();
}

/// <summary>Agent id + secret in <c>{DataDirectory}/credentials.json</c>, written atomically with mode 600 on Unix.</summary>
public sealed class CredentialStore(IOptions<AgentOptions> options)
{
    private readonly Lock _lock = new();
    private AgentCredentials? _cached;
    private bool _loaded;

    private string FilePath => Path.Combine(AgentPaths.DataDirectory(options.Value), "credentials.json");

    public AgentCredentials? Current
    {
        get
        {
            lock (_lock)
            {
                if (_loaded) return _cached;
                _loaded = true;
                if (!File.Exists(FilePath)) return null;
                _cached = JsonSerializer.Deserialize<AgentCredentials>(File.ReadAllText(FilePath), ContractJson.Options);
                return _cached;
            }
        }
    }

    public void Save(AgentCredentials credentials)
    {
        lock (_lock)
        {
            var path = FilePath;
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var temp = path + ".tmp";
            var fileOptions = new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write };
            if (!OperatingSystem.IsWindows()) fileOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using (var stream = new FileStream(temp, fileOptions))
                JsonSerializer.Serialize(stream, credentials, ContractJson.Options);
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            File.Move(temp, path, overwrite: true);
            _cached = credentials;
            _loaded = true;
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            if (File.Exists(FilePath)) File.Delete(FilePath);
            _cached = null;
            _loaded = true;
        }
    }
}
