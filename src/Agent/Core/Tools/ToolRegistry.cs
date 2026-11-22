using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WebScan.Agent.Tools.Abstractions;
using WebScan.Contracts;

namespace WebScan.Agent.Tools;

/// <summary>A manifest whose executable was found and whose version was detected.</summary>
public sealed record RegisteredTool(ToolManifest Manifest, string ManifestPath, string ManifestSha256, string? ExecutablePath, string Version)
{
    public string Id => Manifest.Id;

    public ToolDescriptor ToDescriptor() => new()
    {
        Id = Manifest.Id,
        Version = Version,
        Capabilities = [.. Manifest.Capabilities.Keys.Order(StringComparer.Ordinal)],
        SupportedParameters = [.. SupportedParameters().Order(StringComparer.Ordinal)],
        Parser = string.Join(",", Manifest.Capabilities.Values.Select(c => c.Parser).OfType<string>().Distinct()) is { Length: > 0 } p ? p : null,
        ManifestSha256 = ManifestSha256,
        MaxConcurrency = Manifest.MaxConcurrency,
        RequiresRawSockets = Manifest.RequiresRawSockets,
        AcceptsHostnames = Manifest.AcceptsHostnames,
    };

    private IEnumerable<string> SupportedParameters()
    {
        var result = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (capability, def) in Manifest.Capabilities)
        {
            if (def.Adapter != ToolCapabilityDefinition.ManifestAdapterId)
            {
                // Built-in/plugin adapters interpret the operation's parameters themselves.
                result.UnionWith(OperationCatalog.All.Values.Where(o => o.RequiredCapability == capability).SelectMany(o => o.Parameters).Select(p => p.Name));
                continue;
            }
            result.UnionWith(def.ParameterArguments.Keys);
            var templates = def.Arguments.Concat(def.ParameterArguments.Values.SelectMany(m => m.AllTemplates()).SelectMany(t => t)).ToList();
            if (templates.Any(a => a.Contains(ToolPlaceholders.Rate, StringComparison.Ordinal) || a.Contains(ToolPlaceholders.ThreadDelayMs, StringComparison.Ordinal)))
                result.Add("rate");
            result.UnionWith(templates.SelectMany(ToolManifestLoader.Placeholders).Select(ToolPlaceholders.ParameterName).OfType<string>());
        }
        return result;
    }
}

/// <summary>
/// Tools available on this agent, keyed by id. Built at startup: plugins → manifests (validated) → probing (executable + version).
/// Tools that fail probing are excluded (logged), so the server never sees tools the agent cannot run.
/// </summary>
public sealed partial class ToolRegistry(
    IOptions<AgentOptions> options,
    ToolComponentRegistry components,
    PluginLoader plugins,
    IToolProcessRunner processRunner,
    ILogger<ToolRegistry> logger)
{
    private readonly SemaphoreSlim _init = new(1, 1);
    private IReadOnlyList<RegisteredTool> _tools = [];
    private bool _initialized;

    public IReadOnlyList<RegisteredTool> Tools => _tools;
    public IReadOnlyList<string> Problems { get; private set; } = [];

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        await _init.WaitAsync(cancellationToken);
        try
        {
            if (_initialized) return;
            var o = options.Value;
            plugins.Load(o.PluginPaths, o.TrustedPluginSha256);

            var dirs = o.ToolManifestPaths.Count > 0 ? o.ToolManifestPaths : [Path.Combine(AppContext.BaseDirectory, "tools.d")];
            var result = ToolManifestLoader.Load(dirs, components);
            foreach (var error in result.Errors) logger.LogError("Tool manifest rejected: {Error}", error);
            foreach (var skip in result.Skipped) logger.LogInformation("Tool manifest skipped: {Reason}", skip);

            var problems = new List<string>(result.Errors);
            var tools = new List<RegisteredTool>();
            foreach (var loaded in result.Manifests)
            {
                var (tool, problem) = await ProbeAsync(loaded, cancellationToken);
                if (tool is not null)
                {
                    tools.Add(tool);
                    logger.LogInformation("Tool {Id} {Version} registered ({Executable}); capabilities: {Capabilities}.",
                        tool.Id, tool.Version, tool.ExecutablePath ?? "built-in", string.Join(", ", tool.Manifest.Capabilities.Keys));
                }
                else
                {
                    problems.Add($"{loaded.Manifest.Id}: {problem}");
                    logger.LogWarning("Tool {Id} not registered: {Problem}", loaded.Manifest.Id, problem);
                }
            }
            _tools = tools;
            Problems = problems;
            _initialized = true;
        }
        finally { _init.Release(); }
    }

    /// <summary>The job's preferred tool if it is local and has the capability, otherwise any local tool with the capability.</summary>
    public (RegisteredTool Tool, ToolCapabilityDefinition Definition)? Resolve(ToolSelection selection)
    {
        var tool = (selection.ToolId is null ? null : _tools.FirstOrDefault(t => t.Id == selection.ToolId && t.Manifest.Capabilities.ContainsKey(selection.Capability)))
                   ?? _tools.FirstOrDefault(t => t.Manifest.Capabilities.ContainsKey(selection.Capability));
        return tool is null ? null : (tool, tool.Manifest.Capabilities[selection.Capability]);
    }

    public IReadOnlyList<ToolDescriptor> Descriptors() => [.. _tools.Select(t => t.ToDescriptor())];

    private async Task<(RegisteredTool? Tool, string? Problem)> ProbeAsync(LoadedManifest loaded, CancellationToken ct)
    {
        var m = loaded.Manifest;
        if (string.IsNullOrWhiteSpace(m.Executable))
            return (new RegisteredTool(m, loaded.Path, loaded.Sha256, null, m.Version!), null);

        var executable = new[] { m.Executable }.Concat(m.ExecutableCandidates).Select(ResolveExecutable).FirstOrDefault(p => p is not null);
        if (executable is null) return (null, $"executable '{m.Executable}' not found on PATH.");

        var workDir = Directory.CreateTempSubdirectory("webscan-probe-").FullName;
        try
        {
            var run = await processRunner.RunAsync(new ProcessRunRequest
            {
                Executable = executable,
                Arguments = m.VersionArgs,
                WorkingDirectory = workDir,
                Environment = m.Environment,
                Timeout = TimeSpan.FromSeconds(20),
            }, ct);
            var output = Ansi().Replace(run.StdoutTail + "\n" + run.StderrTail, "");
            if (run.Killed) return (null, "version command timed out.");
            if (m.VersionRegex is null) return (new RegisteredTool(m, loaded.Path, loaded.Sha256, executable, m.Version ?? "unknown"), null);

            var match = Regex.Match(output, m.VersionRegex, RegexOptions.Multiline, TimeSpan.FromSeconds(1));
            if (!match.Success) return (null, $"version not detected (exit code {run.ExitCode}).");
            var version = match.Groups["version"].Success ? match.Groups["version"].Value : match.Groups.Count > 1 ? match.Groups[1].Value : match.Value;
            return (new RegisteredTool(m, loaded.Path, loaded.Sha256, executable, version.Trim()), null);
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or UnauthorizedAccessException)
        {
            return (null, $"version command failed: {ex.Message}");
        }
        finally
        {
            TryDeleteDirectory(workDir);
        }
    }

    /// <summary>Absolute path for an absolute/relative-to-PATH executable name, or null.</summary>
    public static string? ResolveExecutable(string nameOrPath)
    {
        if (Path.IsPathFullyQualified(nameOrPath)) return IsExecutableFile(nameOrPath) ? nameOrPath : null;
        if (nameOrPath.Contains(Path.DirectorySeparatorChar) || nameOrPath.Contains(Path.AltDirectorySeparatorChar)) return null;
        var names = OperatingSystem.IsWindows() ? [nameOrPath, nameOrPath + ".exe"] : new[] { nameOrPath };
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            foreach (var name in names)
            {
                var candidate = Path.Combine(dir, name);
                if (Path.IsPathFullyQualified(candidate) && IsExecutableFile(candidate)) return candidate;
            }
        return null;
    }

    private static bool IsExecutableFile(string path) =>
        File.Exists(path) && (OperatingSystem.IsWindows() || (File.GetUnixFileMode(path) & (UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute)) != 0);

    internal static void TryDeleteDirectory(string path)
    {
        try { if (Directory.Exists(path)) Directory.Delete(path, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    [GeneratedRegex(@"\x1B\[[0-9;]*[A-Za-z]")]
    private static partial Regex Ansi();
}
