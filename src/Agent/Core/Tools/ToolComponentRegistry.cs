using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WebScan.Agent.Tools.Abstractions;

namespace WebScan.Agent.Tools;

/// <summary>Parsers and adapters by id: built-ins from DI plus types found in plugin assemblies. First registration of an id wins.</summary>
public sealed class ToolComponentRegistry
{
    private readonly Dictionary<string, IToolOutputParser> _parsers = new(StringComparer.Ordinal);
    private readonly Dictionary<string, IToolAdapter> _adapters = new(StringComparer.Ordinal);
    private readonly Lock _lock = new();

    public ToolComponentRegistry(IEnumerable<IToolOutputParser> parsers, IEnumerable<IToolAdapter> adapters)
    {
        foreach (var p in parsers) TryAddParser(p);
        foreach (var a in adapters) TryAddAdapter(a);
    }

    public bool TryAddParser(IToolOutputParser parser) { lock (_lock) return _parsers.TryAdd(parser.Id, parser); }
    public bool TryAddAdapter(IToolAdapter adapter) { lock (_lock) return _adapters.TryAdd(adapter.Id, adapter); }

    public IToolOutputParser? GetParser(string id) { lock (_lock) return _parsers.GetValueOrDefault(id); }
    public IToolAdapter? GetAdapter(string id) { lock (_lock) return _adapters.GetValueOrDefault(id); }

    public IReadOnlyList<string> ParserIds { get { lock (_lock) return [.. _parsers.Keys.Order(StringComparer.Ordinal)]; } }
    public IReadOnlyList<string> AdapterIds { get { lock (_lock) return [.. _adapters.Keys.Order(StringComparer.Ordinal)]; } }
}

/// <summary>
/// Loads operator-installed plugin assemblies (never downloaded) into isolated load contexts and registers their
/// <see cref="IToolOutputParser"/>/<see cref="IToolAdapter"/> implementations. The SDK and contracts assemblies are shared
/// with the agent so plugin types implement the agent's interfaces.
/// </summary>
public sealed class PluginLoader(ToolComponentRegistry registry, IServiceProvider services, ILogger<PluginLoader> logger)
{
    public IReadOnlyList<string> Load(IEnumerable<string> paths, IReadOnlyCollection<string> trustedSha256)
    {
        var loaded = new List<string>();
        var trusted = trustedSha256.Select(h => h.Trim().ToLowerInvariant()).ToHashSet(StringComparer.Ordinal);
        foreach (var file in paths.SelectMany(ExpandPath))
        {
            var hash = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(file)));
            if (trusted.Count > 0 && !trusted.Contains(hash))
            {
                logger.LogWarning("Plugin {Path} (sha256 {Sha256}) is not in Agent:TrustedPluginSha256; skipped.", file, hash);
                continue;
            }
            try
            {
                var context = new PluginLoadContext(file);
                var assembly = context.LoadFromAssemblyPath(file);
                var count = RegisterTypes(assembly);
                logger.LogInformation("Loaded plugin {Path} (sha256 {Sha256}): {Count} component(s).", file, hash, count);
                loaded.Add(file);
            }
            catch (Exception ex) when (ex is BadImageFormatException or FileLoadException or ReflectionTypeLoadException or MissingMethodException or InvalidOperationException)
            {
                logger.LogError(ex, "Failed to load plugin {Path}.", file);
            }
        }
        return loaded;
    }

    private int RegisterTypes(Assembly assembly)
    {
        var count = 0;
        foreach (var type in assembly.GetExportedTypes().Where(t => t is { IsClass: true, IsAbstract: false }))
        {
            if (typeof(IToolOutputParser).IsAssignableFrom(type))
            {
                var parser = (IToolOutputParser)ActivatorUtilities.CreateInstance(services, type);
                if (registry.TryAddParser(parser)) count++;
                else logger.LogWarning("Plugin parser id '{Id}' from {Type} is already registered; ignored.", parser.Id, type.FullName);
            }
            if (typeof(IToolAdapter).IsAssignableFrom(type))
            {
                var adapter = (IToolAdapter)ActivatorUtilities.CreateInstance(services, type);
                if (registry.TryAddAdapter(adapter)) count++;
                else logger.LogWarning("Plugin adapter id '{Id}' from {Type} is already registered; ignored.", adapter.Id, type.FullName);
            }
        }
        return count;
    }

    private IEnumerable<string> ExpandPath(string path)
    {
        if (File.Exists(path)) return [Path.GetFullPath(path)];
        if (Directory.Exists(path)) return Directory.EnumerateFiles(path, "*.dll").Order(StringComparer.Ordinal).Select(Path.GetFullPath);
        logger.LogWarning("Plugin path {Path} does not exist.", path);
        return [];
    }

    private sealed class PluginLoadContext(string pluginPath) : AssemblyLoadContext($"plugin:{Path.GetFileName(pluginPath)}")
    {
        private readonly AssemblyDependencyResolver _resolver = new(pluginPath);

        private static readonly HashSet<string> Shared = new(StringComparer.OrdinalIgnoreCase)
        {
            typeof(IToolOutputParser).Assembly.GetName().Name!,
            typeof(WebScan.Contracts.DiscoveryObservation).Assembly.GetName().Name!,
        };

        protected override Assembly? Load(AssemblyName assemblyName)
        {
            // SDK, contracts and DI/logging abstractions come from the agent's (default) context so types are shared.
            if (Shared.Contains(assemblyName.Name!) || assemblyName.Name!.StartsWith("Microsoft.Extensions.", StringComparison.Ordinal)) return null;
            var path = _resolver.ResolveAssemblyToPath(assemblyName);
            return path is null ? null : LoadFromAssemblyPath(path);
        }

        protected override IntPtr LoadUnmanagedDll(string unmanagedDllName)
        {
            var path = _resolver.ResolveUnmanagedDllToPath(unmanagedDllName);
            return path is null ? IntPtr.Zero : LoadUnmanagedDllFromPath(path);
        }
    }
}
