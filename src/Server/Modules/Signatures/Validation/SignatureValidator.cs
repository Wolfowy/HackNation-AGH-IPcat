using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using WebScan.Contracts;
using WebScan.Server.Kernel.Discovery;
using WebScan.Server.Modules.Signatures.Domain;

namespace WebScan.Server.Modules.Signatures.Validation;

public sealed record SignatureValidationResult(
    bool Valid,
    IReadOnlyList<string> Errors,
    IReadOnlyList<string> Warnings,
    string? Severity,
    IReadOnlyList<string> Tags,
    bool RequiresApprovalNote,
    string? TemplateId = null)
{
    public static SignatureValidationResult Invalid(params string[] errors) => new(false, errors, [], null, [], false);
}

/// <summary>JSON classification rule: <c>{ "when": ConditionExpression, "outcome": {...}, "tags": [...] }</c>.</summary>
public sealed record ClassificationRuleDocument
{
    public string? Description { get; init; }
    public ConditionExpression? When { get; init; }
    public ClassificationOutcomeDocument? Outcome { get; init; }
    public IReadOnlyList<string>? Tags { get; init; }
}

public sealed record ClassificationOutcomeDocument
{
    public TechnologyOutcomeDocument? Technology { get; init; }
    public string? ClassificationTag { get; init; }

    /// <summary>0–1; default 0.8.</summary>
    public double? Confidence { get; init; }
}

public sealed record TechnologyOutcomeDocument
{
    public string? Name { get; init; }
    public string? Version { get; init; }

    /// <summary>Observation field whose value becomes the version (e.g. "service.version").</summary>
    public string? VersionField { get; init; }

    public string? Category { get; init; }
}

/// <summary>JSON change rule: <c>{ "changeTypes": ["NewPort"], "when": ConditionExpression?, "severity": "medium" }</c>.</summary>
public sealed record ChangeRuleDocument
{
    public string? Description { get; init; }
    public IReadOnlyList<AssetChangeType>? ChangeTypes { get; init; }
    public ConditionExpression? When { get; init; }
    public string? Severity { get; init; }
    public IReadOnlyList<string>? Tags { get; init; }
}

public static partial class SignatureValidator
{
    public const double DefaultRuleConfidence = 0.8;

    /// <summary>Fields a change rule may test (change events are mapped onto these observation field names).</summary>
    public static readonly IReadOnlySet<string> ChangeRuleFields = new HashSet<string>(StringComparer.Ordinal)
    {
        ConditionFields.Address, ConditionFields.Hostname, ConditionFields.Port, ConditionFields.Transport,
        ConditionFields.ServiceName, ConditionFields.ServiceProduct, ConditionFields.ServiceVersion,
        ConditionFields.TechnologyName, ConditionFields.TechnologyCategory,
    };

    public static readonly JsonSerializerOptions RuleJson = CreateRuleJson();

    [GeneratedRegex("^[a-z0-9][a-z0-9_-]{0,63}$")]
    private static partial Regex TagPattern();

    public static SignatureValidationResult Validate(SignatureKind kind, string? content) => kind switch
    {
        SignatureKind.NucleiTemplate => NucleiTemplateValidator.Validate(content ?? ""),
        SignatureKind.ClassificationRule => ValidateClassification(content),
        SignatureKind.ChangeRule => ValidateChangeRule(content),
        _ => SignatureValidationResult.Invalid($"Unknown kind '{kind}'."),
    };

    public static bool TryParse<T>(string? content, out T? document, out string? error) where T : class
    {
        document = null;
        error = null;
        if (string.IsNullOrWhiteSpace(content)) { error = "Rule content is empty."; return false; }
        if (content.Length > NucleiTemplateValidator.MaxContentLength) { error = "Rule content is too large."; return false; }
        try
        {
            document = JsonSerializer.Deserialize<T>(content, RuleJson);
            if (document is null) error = "Rule content must be a JSON object.";
        }
        catch (JsonException ex)
        {
            error = $"Invalid JSON: {ex.Message}";
        }
        return document is not null;
    }

    private static SignatureValidationResult ValidateClassification(string? content)
    {
        if (!TryParse<ClassificationRuleDocument>(content, out var doc, out var parseError))
            return SignatureValidationResult.Invalid(parseError!);

        var errors = ConditionEvaluator.Validate(doc!.When, "when").ToList();
        var outcome = doc.Outcome;
        if (outcome is null) errors.Add("outcome is required.");
        else
        {
            var tech = outcome.Technology;
            if (tech is null && string.IsNullOrWhiteSpace(outcome.ClassificationTag))
                errors.Add("outcome needs a technology or a classificationTag.");
            if (tech is not null)
            {
                if (string.IsNullOrWhiteSpace(tech.Name) || tech.Name.Length > 100) errors.Add("outcome.technology.name is required (max 100 chars).");
                if (tech.VersionField is not null && !ConditionFields.All.Contains(tech.VersionField))
                    errors.Add($"outcome.technology.versionField: unknown field '{tech.VersionField}'.");
            }
            if (outcome.ClassificationTag is not null && !TagPattern().IsMatch(outcome.ClassificationTag))
                errors.Add("outcome.classificationTag must match ^[a-z0-9][a-z0-9_-]{0,63}$.");
            if (outcome.Confidence is < 0 or > 1) errors.Add("outcome.confidence must be between 0 and 1.");
        }

        var tags = ValidateTags(doc.Tags, errors);
        return new SignatureValidationResult(errors.Count == 0, errors, [], "info", tags, false);
    }

    private static SignatureValidationResult ValidateChangeRule(string? content)
    {
        if (!TryParse<ChangeRuleDocument>(content, out var doc, out var parseError))
            return SignatureValidationResult.Invalid(parseError!);

        var errors = new List<string>();
        var warnings = new List<string>();
        if (doc!.ChangeTypes is not { Count: > 0 }) errors.Add("changeTypes must list at least one change type.");
        if (doc.When is not null)
        {
            errors.AddRange(ConditionEvaluator.Validate(doc.When, "when"));
            foreach (var field in ConditionEvaluator.ReferencedFields(doc.When).Where(f => !ChangeRuleFields.Contains(f)))
                errors.Add($"when: field '{field}' is not available for change rules.");
        }

        var severity = doc.Severity?.Trim().ToLowerInvariant();
        if (!Severities.IsValid(severity)) errors.Add($"severity must be one of {string.Join(", ", Severities.All)}.");
        var requiresNote = Severities.Rank(severity) > Severities.Rank("medium");
        if (requiresNote) warnings.Add($"Severity '{severity}' is above medium: approval requires an explicit justification note.");

        var tags = ValidateTags(doc.Tags, errors);
        return new SignatureValidationResult(errors.Count == 0, errors, warnings, severity, tags, requiresNote);
    }

    private static List<string> ValidateTags(IReadOnlyList<string>? tags, List<string> errors)
    {
        var result = (tags ?? []).Select(t => t.Trim().ToLowerInvariant()).Distinct().ToList();
        foreach (var tag in result.Where(t => !TagPattern().IsMatch(t))) errors.Add($"Invalid tag '{tag}'.");
        return result;
    }

    private static JsonSerializerOptions CreateRuleJson()
    {
        var options = ContractJson.Configure(new JsonSerializerOptions(JsonSerializerDefaults.Web));
        options.UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow;
        return options;
    }
}
