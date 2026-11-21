using System.Text.Json;
using System.Text.Json.Serialization;
using WebScan.Contracts;

namespace WebScan.Agent.Tools.Abstractions;

/// <summary>
/// Declarative description of a scanning tool, loaded from <c>tools.d/*.json</c>.
/// The agent never hardcodes tool names: everything it knows about a tool comes from its manifest.
/// </summary>
public sealed record ToolManifest
{
    /// <summary>Tool id reported to the server, pattern <see cref="IdPattern"/>.</summary>
    public required string Id { get; init; }

    public string? DisplayName { get; init; }

    /// <summary>Executable name (resolved on PATH) or absolute path. May be omitted only when no capability uses the "manifest" adapter.</summary>
    public string? Executable { get; init; }

    /// <summary>Alternative names/paths tried in order when <see cref="Executable"/> is not found.</summary>
    public IReadOnlyList<string> ExecutableCandidates { get; init; } = [];

    public IReadOnlyList<string> VersionArgs { get; init; } = ["--version"];

    /// <summary>Regex applied to stdout+stderr of the version command; named group "version" or group 1 is the version.</summary>
    public string? VersionRegex { get; init; }

    /// <summary>Fixed version for tools without an executable (plugin/built-in adapters that do not spawn processes).</summary>
    public string? Version { get; init; }

    public bool Enabled { get; init; } = true;
    public int MaxConcurrency { get; init; } = 1;
    public int DefaultTimeoutSeconds { get; init; } = 3600;

    /// <summary>Fixed environment variables for the tool process (no expansion, no placeholders).</summary>
    public IReadOnlyDictionary<string, string> Environment { get; init; } = new Dictionary<string, string>();

    /// <summary>Capability id (e.g. "port-scan") → how to run the tool for it.</summary>
    public required IReadOnlyDictionary<string, ToolCapabilityDefinition> Capabilities { get; init; }

    public const string IdPattern = "^[a-z0-9][a-z0-9_.-]{0,63}$";
}

public sealed record ToolCapabilityDefinition
{
    /// <summary>Adapter id: <see cref="ManifestAdapterId"/> (generic argv-template runner) or a built-in/plugin adapter id.</summary>
    public string Adapter { get; init; } = ManifestAdapterId;

    /// <summary>Output parser id (required for the manifest adapter).</summary>
    public string? Parser { get; init; }

    /// <summary>Parser-specific options (e.g. the field mapping of <c>generic-jsonl</c>).</summary>
    public JsonElement? ParserOptions { get; init; }

    public ToolInputDefinition Input { get; init; } = new();
    public ToolOutputDefinition Output { get; init; } = new();

    /// <summary>argv template; each element is substituted separately (values are never split or merged).</summary>
    public IReadOnlyList<string> Arguments { get; init; } = [];

    /// <summary>Operation parameter name → arguments appended when the (validated) parameter has a value.</summary>
    public IReadOnlyDictionary<string, ParameterArgumentMapping> ParameterArguments { get; init; } = new Dictionary<string, ParameterArgumentMapping>();

    /// <summary>Appended when the job pins a network interface (only place where <c>{interface}</c> is allowed).</summary>
    public IReadOnlyList<string> InterfaceArguments { get; init; } = [];

    public const string ManifestAdapterId = "manifest";
}

public sealed record ToolInputDefinition
{
    public ToolInputMode Mode { get; init; } = ToolInputMode.File;
    public ToolInputFormat Format { get; init; } = ToolInputFormat.Hosts;
}

public sealed record ToolOutputDefinition
{
    public ToolOutputMode Mode { get; init; } = ToolOutputMode.File;
}

public enum ToolInputMode { File, Stdin }

/// <summary>
/// How targets are written, one per line: <c>Hosts</c> = IPs/CIDRs/hostnames (unique endpoint addresses for endpoint jobs),
/// <c>Endpoints</c> = <c>addr:port</c> (<c>[v6]:port</c>), <c>Urls</c> = <c>scheme://addr:port</c> when the scheme is known, else <c>addr:port</c>.
/// </summary>
public enum ToolInputFormat { Hosts, Endpoints, Urls }

public enum ToolOutputMode { File, Stdout }

/// <summary>
/// Arguments for one operation parameter. JSON: either an argv template array (<c>["-p", "{value}"]</c>) or a value map
/// (<c>{"connect": ["-sT"], "top-*": ["--top-ports", "{value}"], "*": ["-p", "{value}"]}</c>). Value-map keys match exactly first,
/// then by prefix (<c>"top-*"</c>, longest first), then <c>"*"</c>. <c>{value}</c> is the part matched by <c>*</c> (whole value for exact keys).
/// A value that matches no key contributes no arguments.
/// </summary>
[JsonConverter(typeof(ParameterArgumentMappingConverter))]
public sealed record ParameterArgumentMapping
{
    public IReadOnlyList<string>? Template { get; init; }
    public IReadOnlyDictionary<string, IReadOnlyList<string>>? Values { get; init; }

    /// <summary>Resolves the argv template and the <c>{value}</c> substitution for a parameter value; null when nothing applies.</summary>
    public (IReadOnlyList<string> Template, string Value)? Resolve(string value)
    {
        if (Template is not null) return (Template, value);
        if (Values is null) return null;
        if (Values.TryGetValue(value, out var exact)) return (exact, value);
        foreach (var (key, template) in Values.Where(kv => kv.Key.Length > 1 && kv.Key.EndsWith('*')).OrderByDescending(kv => kv.Key.Length))
        {
            var prefix = key[..^1];
            if (value.StartsWith(prefix, StringComparison.Ordinal) && value.Length > prefix.Length) return (template, value[prefix.Length..]);
        }
        return Values.TryGetValue("*", out var fallback) ? (fallback, value) : null;
    }

    public IEnumerable<IReadOnlyList<string>> AllTemplates() => Template is not null ? [Template] : Values?.Values ?? [];
}

public sealed class ParameterArgumentMappingConverter : JsonConverter<ParameterArgumentMapping>
{
    public override ParameterArgumentMapping Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        reader.TokenType switch
        {
            JsonTokenType.StartArray => new() { Template = JsonSerializer.Deserialize<List<string>>(ref reader, options) },
            JsonTokenType.StartObject => new() { Values = JsonSerializer.Deserialize<Dictionary<string, IReadOnlyList<string>>>(ref reader, options) },
            _ => throw new JsonException("Parameter argument mapping must be an array (argv template) or an object (value → argv)."),
        };

    public override void Write(Utf8JsonWriter writer, ParameterArgumentMapping value, JsonSerializerOptions options)
    {
        if (value.Template is not null) JsonSerializer.Serialize(writer, value.Template, options);
        else JsonSerializer.Serialize(writer, value.Values ?? new Dictionary<string, IReadOnlyList<string>>(), options);
    }
}

/// <summary>Placeholders allowed in argv templates. Anything else in braces is rejected when the manifest is loaded.</summary>
public static class ToolPlaceholders
{
    public const string Input = "{input}";
    public const string Output = "{output}";
    public const string Rate = "{rate}";
    public const string Timeout = "{timeout}";
    public const string Parallelism = "{parallelism}";
    public const string Interface = "{interface}";
    public const string TemplatesDir = "{templatesDir}";
    public const string Value = "{value}";

    /// <summary>Comma separated ports of an endpoint job; the adapter runs one invocation per group of hosts sharing a port set (no cross-product over-scan).</summary>
    public const string Ports = "{ports}";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
    {
        Input, Output, Rate, Timeout, Parallelism, Interface, TemplatesDir, Value, Ports,
    };
}

/// <summary>JSON options for manifests: contract wire options plus comments and trailing commas for hand-written files.</summary>
public static class ToolManifestJson
{
    public static readonly JsonSerializerOptions Options = new(ContractJson.Options)
    {
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };
}
