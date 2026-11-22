using System.Globalization;
using WebScan.Contracts;

namespace WebScan.Server.Kernel.Discovery;

/// <summary>
/// Validates and evaluates <see cref="ConditionExpression"/> trees over whitelisted observation fields
/// (<see cref="ConditionFields"/>). Pure data interpretation — nothing is compiled or executed.
/// </summary>
public static class ConditionEvaluator
{
    public const int MaxDepth = 8;

    private static readonly HashSet<string> NumericFields = new(StringComparer.Ordinal)
    {
        ConditionFields.Port, ConditionFields.HttpStatusCode, ConditionFields.ConfidenceScore,
    };

    /// <summary>Structural validation: one of leaf/all/any/not, whitelisted fields, operator arguments, depth ≤ 8.</summary>
    public static IReadOnlyList<string> Validate(ConditionExpression? expression, string path = "condition")
    {
        var errors = new List<string>();
        Validate(expression, path, 1, errors);
        return errors;
    }

    private static void Validate(ConditionExpression? e, string path, int depth, List<string> errors)
    {
        if (e is null) { errors.Add($"{path}: expression is required."); return; }
        if (depth > MaxDepth) { errors.Add($"{path}: maximum depth {MaxDepth} exceeded."); return; }

        var forms = (e.Field is not null ? 1 : 0) + (e.All is not null ? 1 : 0) + (e.Any is not null ? 1 : 0) + (e.Not is not null ? 1 : 0);
        if (forms != 1) { errors.Add($"{path}: exactly one of field, all, any, not must be set."); return; }

        if (e.All is not null || e.Any is not null)
        {
            var (name, items) = e.All is not null ? ("all", e.All) : ("any", e.Any!);
            if (items.Count == 0) errors.Add($"{path}.{name}: must not be empty.");
            for (var i = 0; i < items.Count; i++) Validate(items[i], $"{path}.{name}[{i}]", depth + 1, errors);
            return;
        }

        if (e.Not is not null) { Validate(e.Not, $"{path}.not", depth + 1, errors); return; }

        if (!ConditionFields.IsValid(e.Field)) { errors.Add($"{path}: unknown field '{e.Field}'."); return; }
        if (e.Operator is not { } op) { errors.Add($"{path}: operator is required."); return; }

        var values = e.Values ?? [];
        switch (op)
        {
            case ConditionOperator.Exists or ConditionOperator.NotExists:
                return;
            case ConditionOperator.Equals or ConditionOperator.NotEquals or ConditionOperator.GreaterThan or ConditionOperator.LessThan:
                if (values.Count != 1) errors.Add($"{path}: operator {op} requires exactly one value.");
                break;
            default:
                if (values.Count == 0) errors.Add($"{path}: operator {op} requires at least one value.");
                break;
        }

        if (op is ConditionOperator.GreaterThan or ConditionOperator.LessThan)
        {
            if (!NumericFields.Contains(e.Field!)) errors.Add($"{path}: operator {op} needs a numeric field.");
            else if (values.Any(v => !TryNumber(v, out _))) errors.Add($"{path}: value must be numeric.");
        }
    }

    public static bool Evaluate(ConditionExpression e, DiscoveryObservation o) => EvaluateValues(e, f => GetValues(o, f));

    /// <summary>Evaluates against any field source (e.g. change events mapped onto observation field names).</summary>
    public static bool Evaluate(ConditionExpression e, Func<string, string?> field) => EvaluateValues(e, f => field(f) is { } v ? [v] : []);

    /// <summary>
    /// Every field yields a list of values (scalars: zero or one). Missing/empty values are ignored. Positive operators match when
    /// ANY value matches; NotEquals/NotIn match when NO value matches (so a missing field satisfies them). In, NotIn, Contains and
    /// StartsWith take one or more comparison values (any of them).
    /// </summary>
    private static bool EvaluateValues(ConditionExpression e, Func<string, IReadOnlyList<string>> field)
    {
        if (e.All is not null) return e.All.All(x => EvaluateValues(x, field));
        if (e.Any is not null) return e.Any.Any(x => EvaluateValues(x, field));
        if (e.Not is not null) return !EvaluateValues(e.Not, field);
        if (e.Field is null || e.Operator is null) return false;

        var actual = field(e.Field).Where(v => !string.IsNullOrEmpty(v)).ToList();
        var values = e.Values ?? [];
        var first = values.Count > 0 ? values[0] : "";
        return e.Operator switch
        {
            ConditionOperator.Exists => actual.Count > 0,
            ConditionOperator.NotExists => actual.Count == 0,
            ConditionOperator.Equals => actual.Any(a => Same(a, first)),
            ConditionOperator.NotEquals => !actual.Any(a => Same(a, first)),
            ConditionOperator.In => actual.Any(a => values.Any(v => Same(a, v))),
            ConditionOperator.NotIn => !actual.Any(a => values.Any(v => Same(a, v))),
            ConditionOperator.Contains => actual.Any(a => values.Any(v => a.Contains(v, StringComparison.OrdinalIgnoreCase))),
            ConditionOperator.StartsWith => actual.Any(a => values.Any(v => a.StartsWith(v, StringComparison.OrdinalIgnoreCase))),
            ConditionOperator.GreaterThan => actual.Any(a => TryNumber(a, out var x) && TryNumber(first, out var y) && x > y),
            ConditionOperator.LessThan => actual.Any(a => TryNumber(a, out var x) && TryNumber(first, out var y) && x < y),
            _ => false,
        };
    }

    /// <summary>Fields referenced by leaves of the expression (used to build human-readable evidence).</summary>
    public static IEnumerable<string> ReferencedFields(ConditionExpression e) =>
        (e.All ?? []).Concat(e.Any ?? []).Concat(e.Not is null ? [] : [e.Not]).SelectMany(ReferencedFields)
            .Concat(e.Field is null ? [] : [e.Field]).Distinct();

    /// <summary>Values of a field: the elements of a list field (<see cref="ConditionFields.Lists"/>), else the scalar value (0 or 1 item).</summary>
    public static IReadOnlyList<string> GetValues(DiscoveryObservation o, string field) => field switch
    {
        ConditionFields.HttpCookieNames => o.Http?.CookieNames ?? [],
        ConditionFields.HttpRedirectChain => o.Http?.RedirectChain ?? [],
        ConditionFields.HttpTechnologies => o.Http?.Technologies ?? [],
        ConditionFields.TlsSubjectAlternativeNames => o.Tls?.SubjectAlternativeNames ?? [],
        _ => GetField(o, field) is { } v ? [v] : [],
    };

    /// <summary>Scalar value of a field; list fields are joined with ", " (for evidence and version extraction).</summary>
    public static string? GetField(DiscoveryObservation o, string field) => field switch
    {
        ConditionFields.Kind => o.Kind.ToString(),
        ConditionFields.Address => o.Address,
        ConditionFields.Hostname => o.Hostname,
        ConditionFields.Port => o.Port?.ToString(CultureInfo.InvariantCulture),
        ConditionFields.Transport => o.Transport?.ToString().ToLowerInvariant(),
        ConditionFields.ToolId => o.Source.ToolId,
        ConditionFields.HostStatus => o.Host?.Status,
        ConditionFields.PortState => o.PortState?.State,
        ConditionFields.ServiceName => o.Service?.Name,
        ConditionFields.ServiceProduct => o.Service?.Product,
        ConditionFields.ServiceVersion => o.Service?.Version,
        ConditionFields.ServiceTunnel => o.Service?.Tunnel,
        ConditionFields.HttpScheme => o.Http?.Scheme,
        ConditionFields.HttpUrl => o.Http?.Url,
        ConditionFields.HttpStatusCode => o.Http?.StatusCode?.ToString(CultureInfo.InvariantCulture),
        ConditionFields.HttpTitle => o.Http?.Title,
        ConditionFields.HttpWebServer => o.Http?.WebServer,
        ConditionFields.TlsSubjectCn => o.Tls?.SubjectCommonName,
        ConditionFields.TlsIssuer => o.Tls?.Issuer,
        ConditionFields.TechnologyName => o.Technology?.Name,
        ConditionFields.TechnologyCategory => o.Technology?.Category,
        ConditionFields.SignatureId => o.Signature?.SignatureId,
        ConditionFields.SignatureSeverity => o.Signature?.Severity,
        ConditionFields.ConfidenceScore => o.Confidence?.Score.ToString(CultureInfo.InvariantCulture),
        ConditionFields.ServiceBanner => o.Service?.Banner,
        ConditionFields.HttpContentType => o.Http?.ContentType,
        ConditionFields.HttpFinalUrl => o.Http?.FinalUrl,
        ConditionFields.HttpFaviconHash => o.Http?.FaviconHash,
        _ when ConditionFields.Lists.Contains(field) => GetValues(o, field) is { Count: > 0 } list ? string.Join(", ", list) : null,
        _ when ConditionFields.HeaderName(field) is { } name =>
            o.Http?.Headers?.FirstOrDefault(h => string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase)).Value,
        _ => null,
    };

    private static bool Same(string a, string b) => string.Equals(a.Trim(), b.Trim(), StringComparison.OrdinalIgnoreCase);

    private static bool TryNumber(string s, out double d) =>
        double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out d);
}
