using System.Text.RegularExpressions;
using WebScan.Server.Kernel.Discovery;
using WebScan.Server.Modules.Signatures.Domain;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace WebScan.Server.Modules.Signatures.Validation;

/// <summary>
/// Safety gate for Nuclei templates: only passive/non-intrusive detection is accepted.
/// Rejects code/headless/javascript/file/workflow protocols, OAST (interactsh), payload/fuzzing sections,
/// state-changing HTTP methods and intrusive tags.
/// </summary>
public static partial class NucleiTemplateValidator
{
    public const int MaxContentLength = 256 * 1024;

    /// <summary>Top-level sections that execute code, drive browsers, read local files or chain templates.</summary>
    private static readonly HashSet<string> ForbiddenSections = new(StringComparer.OrdinalIgnoreCase)
    {
        "code", "headless", "javascript", "file", "workflow", "workflows", "flow", "multi-protocol",
    };

    /// <summary>Keys (at any depth) that turn a template into a brute-force or fuzzing run.</summary>
    private static readonly HashSet<string> ForbiddenKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "payloads", "fuzzing", "attack",
    };

    private static readonly HashSet<string> ForbiddenTags = new(StringComparer.OrdinalIgnoreCase)
    {
        "intrusive", "dos", "fuzz", "fuzzing", "exploit", "rce", "sqli", "xss", "lfi", "rfi", "ssrf", "ssti", "xxe",
        "brute-force", "bruteforce", "default-login", "oast", "oob",
    };

    private static readonly HashSet<string> SafeMethods = new(StringComparer.OrdinalIgnoreCase) { "GET", "HEAD", "OPTIONS" };

    [GeneratedRegex("interactsh|oast\\.(fun|live|site|online|me|pro)", RegexOptions.IgnoreCase)]
    private static partial Regex Interactsh();

    public static SignatureValidationResult Validate(string content)
    {
        var errors = new List<string>();
        var warnings = new List<string>();
        if (string.IsNullOrWhiteSpace(content)) return SignatureValidationResult.Invalid("Template content is empty.");
        if (content.Length > MaxContentLength) return SignatureValidationResult.Invalid($"Template exceeds {MaxContentLength} characters.");

        YamlMappingNode root;
        try
        {
            var stream = new YamlStream();
            stream.Load(new StringReader(content));
            if (stream.Documents.Count != 1 || stream.Documents[0].RootNode is not YamlMappingNode mapping)
                return SignatureValidationResult.Invalid("Template must be a single YAML mapping document.");
            root = mapping;
        }
        catch (YamlException ex)
        {
            return SignatureValidationResult.Invalid($"Invalid YAML: {ex.Message}");
        }

        var id = Scalar(root, "id");
        if (string.IsNullOrWhiteSpace(id)) errors.Add("'id' is required.");
        else if (!Regex.IsMatch(id, Signature.IdPattern)) errors.Add($"'id' must match {Signature.IdPattern}.");

        var info = Child(root, "info") as YamlMappingNode;
        string? severity = null;
        var tags = new List<string>();
        if (info is null) errors.Add("'info' section is required.");
        else
        {
            if (string.IsNullOrWhiteSpace(Scalar(info, "name"))) errors.Add("'info.name' is required.");
            severity = Scalar(info, "severity")?.Trim().ToLowerInvariant();
            if (string.IsNullOrEmpty(severity)) errors.Add("'info.severity' is required.");
            else if (!Severities.IsValid(severity)) errors.Add($"'info.severity' must be one of {string.Join(", ", Severities.All)}.");
            tags = ReadTags(Child(info, "tags"));
        }

        foreach (var key in root.Children.Keys.OfType<YamlScalarNode>().Select(k => k.Value ?? ""))
            if (ForbiddenSections.Contains(key)) errors.Add($"Protocol/section '{key}' is not allowed.");

        foreach (var tag in tags.Where(ForbiddenTags.Contains))
            errors.Add($"Tag '{tag}' marks an intrusive template and is not allowed.");

        if (Interactsh().IsMatch(content)) errors.Add("Out-of-band interaction (interactsh/OAST) is not allowed.");

        Walk(root, errors);

        var requiresNote = Severities.Rank(severity) > Severities.Rank("medium");
        if (requiresNote)
            warnings.Add($"Severity '{severity}' is above medium: approval requires an explicit justification note.");

        return new SignatureValidationResult(errors.Count == 0, errors.Distinct().ToList(), warnings, severity, tags, requiresNote, id);
    }

    private static void Walk(YamlNode node, List<string> errors)
    {
        switch (node)
        {
            case YamlMappingNode map:
                foreach (var (keyNode, value) in map.Children)
                {
                    var key = (keyNode as YamlScalarNode)?.Value ?? "";
                    if (ForbiddenKeys.Contains(key)) errors.Add($"'{key}' (payload/fuzzing) sections are not allowed.");
                    if (key.Equals("method", StringComparison.OrdinalIgnoreCase) && value is YamlScalarNode m && !SafeMethods.Contains(m.Value ?? ""))
                        errors.Add($"HTTP method '{m.Value}' is not allowed (only GET, HEAD, OPTIONS).");
                    if (key.Equals("raw", StringComparison.OrdinalIgnoreCase) && value is YamlSequenceNode raws)
                        foreach (var raw in raws.OfType<YamlScalarNode>())
                        {
                            var method = (raw.Value ?? "").TrimStart().Split(' ', 2)[0];
                            if (!SafeMethods.Contains(method)) errors.Add($"Raw request method '{method}' is not allowed (only GET, HEAD, OPTIONS).");
                        }
                    Walk(value, errors);
                }
                break;
            case YamlSequenceNode seq:
                foreach (var child in seq.Children) Walk(child, errors);
                break;
        }
    }

    private static List<string> ReadTags(YamlNode? node) => node switch
    {
        YamlScalarNode s => (s.Value ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(t => t.ToLowerInvariant()).ToList(),
        YamlSequenceNode seq => seq.Children.OfType<YamlScalarNode>().Select(t => (t.Value ?? "").Trim().ToLowerInvariant())
            .Where(t => t.Length > 0).ToList(),
        _ => [],
    };

    private static YamlNode? Child(YamlMappingNode map, string key) =>
        map.Children.TryGetValue(new YamlScalarNode(key), out var value) ? value : null;

    private static string? Scalar(YamlMappingNode map, string key) => (Child(map, key) as YamlScalarNode)?.Value;
}
