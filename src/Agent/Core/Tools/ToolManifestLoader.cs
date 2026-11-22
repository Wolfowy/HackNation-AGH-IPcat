using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using WebScan.Agent.Tools.Abstractions;
using WebScan.Contracts;

namespace WebScan.Agent.Tools;

public sealed record LoadedManifest(ToolManifest Manifest, string Path, string Sha256);

public sealed record ManifestLoadResult(IReadOnlyList<LoadedManifest> Manifests, IReadOnlyList<string> Errors, IReadOnlyList<string> Skipped);

/// <summary>Loads <c>*.json</c> manifests from directories and validates them against the registered parsers/adapters.</summary>
public static partial class ToolManifestLoader
{
    public static ManifestLoadResult Load(IEnumerable<string> directories, ToolComponentRegistry components)
    {
        var manifests = new List<LoadedManifest>();
        var errors = new List<string>();
        var skipped = new List<string>();
        var ids = new HashSet<string>(StringComparer.Ordinal);

        foreach (var dir in directories)
        {
            if (!Directory.Exists(dir)) { skipped.Add($"Manifest directory '{dir}' does not exist."); continue; }
            foreach (var path in Directory.EnumerateFiles(dir, "*.json").Order(StringComparer.Ordinal))
            {
                var bytes = File.ReadAllBytes(path);
                ToolManifest? manifest;
                try { manifest = JsonSerializer.Deserialize<ToolManifest>(bytes, ToolManifestJson.Options); }
                catch (JsonException ex) { errors.Add($"{path}: invalid JSON: {ex.Message}"); continue; }
                if (manifest is null) { errors.Add($"{path}: empty manifest."); continue; }

                var unavailable = manifest.Capabilities.Values.Select(c => c.Adapter).Distinct().Where(a => components.GetAdapter(a) is null).ToList();
                if (unavailable.Count > 0) { skipped.Add($"{path}: adapter(s) {string.Join(", ", unavailable)} not available; tool '{manifest.Id}' skipped."); continue; }

                var problems = Validate(manifest, components);
                if (!ids.Add(manifest.Id)) problems.Add($"duplicate tool id '{manifest.Id}'.");
                if (problems.Count > 0) { errors.AddRange(problems.Select(p => $"{path}: {p}")); continue; }

                if (!manifest.Enabled) { skipped.Add($"{path}: tool '{manifest.Id}' disabled."); continue; }
                manifests.Add(new LoadedManifest(manifest, path, Convert.ToHexStringLower(SHA256.HashData(bytes))));
            }
        }
        return new ManifestLoadResult(manifests, errors, skipped);
    }

    public static List<string> Validate(ToolManifest m, ToolComponentRegistry components)
    {
        var errors = new List<string>();
        if (!Regex.IsMatch(m.Id ?? "", ToolManifest.IdPattern)) errors.Add($"invalid id '{m.Id}'.");
        if (m.Capabilities is null || m.Capabilities.Count == 0) { errors.Add("at least one capability is required."); return errors; }
        if (m.MaxConcurrency < 1) errors.Add("maxConcurrency must be >= 1.");
        if (m.DefaultTimeoutSeconds < 1) errors.Add("defaultTimeoutSeconds must be >= 1.");

        var usesProcess = m.Capabilities.Values.Any(c => c.Adapter == ToolCapabilityDefinition.ManifestAdapterId);
        if (string.IsNullOrWhiteSpace(m.Executable))
        {
            if (usesProcess) errors.Add("executable is required for capabilities using the 'manifest' adapter.");
            if (string.IsNullOrWhiteSpace(m.Version)) errors.Add("version is required when no executable is declared.");
        }
        else if (m.VersionRegex is not null && !IsValidRegex(m.VersionRegex)) errors.Add("versionRegex is not a valid regular expression.");

        foreach (var key in m.Environment.Keys.Where(k => !EnvName().IsMatch(k))) errors.Add($"invalid environment variable name '{key}'.");

        foreach (var (capability, def) in m.Capabilities)
        {
            var at = $"capability '{capability}'";
            if (!Regex.IsMatch(capability, ToolCapabilities.Pattern)) errors.Add($"{at}: invalid capability id.");
            if (def.Parser is not null)
            {
                var parser = components.GetParser(def.Parser);
                if (parser is null) errors.Add($"{at}: unknown parser '{def.Parser}'.");
                else errors.AddRange(parser.ValidateOptions(def.ParserOptions).Select(e => $"{at}: parser options: {e}"));
            }
            if (def.Adapter != ToolCapabilityDefinition.ManifestAdapterId) continue;

            if (def.Parser is null) errors.Add($"{at}: parser is required for the manifest adapter.");
            if (def.Arguments.Count == 0) errors.Add($"{at}: arguments are required for the manifest adapter.");

            var all = new List<string>();
            CheckTemplate(def.Arguments, at + " arguments", allowValue: false, allowInterface: false, errors, all);
            CheckTemplate(def.InterfaceArguments, at + " interfaceArguments", allowValue: false, allowInterface: true, errors, all);
            foreach (var (param, mapping) in def.ParameterArguments)
            {
                if (!KnownParameters.Contains(param)) errors.Add($"{at}: parameterArguments: '{param}' is not an operation parameter.");
                if (mapping.Template is null && mapping.Values is null) errors.Add($"{at}: parameterArguments '{param}' is empty.");
                foreach (var template in mapping.AllTemplates())
                    CheckTemplate(template, $"{at} parameterArguments '{param}'", allowValue: true, allowInterface: false, errors, all);
            }

            if (def.Input.Mode == ToolInputMode.File && !all.Contains(ToolPlaceholders.Input)) errors.Add($"{at}: input mode 'file' requires {ToolPlaceholders.Input}.");
            if (def.Input.Mode != ToolInputMode.File && all.Contains(ToolPlaceholders.Input)) errors.Add($"{at}: {ToolPlaceholders.Input} requires input mode 'file'.");
            if (def.Output.Mode == ToolOutputMode.File && !all.Contains(ToolPlaceholders.Output)) errors.Add($"{at}: output mode 'file' requires {ToolPlaceholders.Output}.");
            if (def.Output.Mode != ToolOutputMode.File && all.Contains(ToolPlaceholders.Output)) errors.Add($"{at}: {ToolPlaceholders.Output} requires output mode 'file'.");
        }
        return errors;
    }

    /// <summary>Placeholders used in an argv template; anything in braces that is not whitelisted is reported.</summary>
    internal static IEnumerable<string> Placeholders(string element) => Placeholder().Matches(element).Select(m => m.Value);

    private static void CheckTemplate(IReadOnlyList<string> template, string at, bool allowValue, bool allowInterface, List<string> errors, List<string> used)
    {
        foreach (var element in template)
        {
            if (element is null) { errors.Add($"{at}: null argument."); continue; }
            var stripped = Placeholder().Replace(element, "");
            if (stripped.Contains('{') || stripped.Contains('}')) errors.Add($"{at}: unbalanced braces in '{element}'.");
            foreach (var p in Placeholders(element))
            {
                used.Add(p);
                if (ToolPlaceholders.ParameterName(p) is { } param)
                {
                    if (!allowValue) errors.Add($"{at}: {p} is only allowed in parameterArguments.");
                    else if (!KnownParameters.Contains(param)) errors.Add($"{at}: {p}: '{param}' is not an operation parameter.");
                }
                else if (!ToolPlaceholders.All.Contains(p)) errors.Add($"{at}: unknown placeholder {p}.");
                else if (p == ToolPlaceholders.Value && !allowValue) errors.Add($"{at}: {p} is only allowed in parameterArguments.");
                else if (p == ToolPlaceholders.Interface && !allowInterface) errors.Add($"{at}: {p} is only allowed in interfaceArguments.");
            }
        }
    }

    private static bool IsValidRegex(string pattern)
    {
        try { _ = new Regex(pattern); return true; }
        catch (ArgumentException) { return false; }
    }

    private static readonly HashSet<string> KnownParameters =
        OperationCatalog.All.Values.SelectMany(o => o.Parameters).Select(p => p.Name).ToHashSet(StringComparer.Ordinal);

    [GeneratedRegex(@"\{[^{}]*\}")]
    private static partial Regex Placeholder();

    [GeneratedRegex(@"^[A-Za-z_][A-Za-z0-9_]*$")]
    private static partial Regex EnvName();
}
