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

        if (!ConditionFields.All.Contains(e.Field!)) { errors.Add($"{path}: unknown field '{e.Field}'."); return; }
        if (e.Operator is not { } op) { errors.Add($"{path}: operator is required."); return; }

        var values = e.Values ?? [];
        switch (op)
        {
            case ConditionOperator.Exists or ConditionOperator.NotExists:
                return;
            case ConditionOperator.Equals or ConditionOperator.NotEquals or ConditionOperator.Contains
                or ConditionOperator.StartsWith or ConditionOperator.GreaterThan or ConditionOperator.LessThan:
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

    public static bool Evaluate(ConditionExpression e, DiscoveryObservation o) => Evaluate(e, f => GetField(o, f));

    /// <summary>Evaluates against any field source (e.g. change events mapped onto observation field names).</summary>
    public static bool Evaluate(ConditionExpression e, Func<string, string?> field)
    {
        if (e.All is not null) return e.All.All(x => Evaluate(x, field));
        if (e.Any is not null) return e.Any.Any(x => Evaluate(x, field));
        if (e.Not is not null) return !Evaluate(e.Not, field);
        if (e.Field is null || e.Operator is null) return false;

        var value = field(e.Field);
        var values = e.Values ?? [];
        var first = values.Count > 0 ? values[0] : "";
        return e.Operator switch
        {
            ConditionOperator.Exists => !string.IsNullOrEmpty(value),
            ConditionOperator.NotExists => string.IsNullOrEmpty(value),
            _ when value is null => e.Operator is ConditionOperator.NotEquals or ConditionOperator.NotIn,
            ConditionOperator.Equals => Same(value, first),
            ConditionOperator.NotEquals => !Same(value, first),
            ConditionOperator.In => values.Any(v => Same(value, v)),
            ConditionOperator.NotIn => !values.Any(v => Same(value, v)),
            ConditionOperator.Contains => value.Contains(first, StringComparison.OrdinalIgnoreCase),
            ConditionOperator.StartsWith => value.StartsWith(first, StringComparison.OrdinalIgnoreCase),
            ConditionOperator.GreaterThan => TryNumber(value, out var a) && TryNumber(first, out var b) && a > b,
            ConditionOperator.LessThan => TryNumber(value, out var c) && TryNumber(first, out var d) && c < d,
            _ => false,
        };
    }

    /// <summary>Fields referenced by leaves of the expression (used to build human-readable evidence).</summary>
    public static IEnumerable<string> ReferencedFields(ConditionExpression e) =>
        (e.All ?? []).Concat(e.Any ?? []).Concat(e.Not is null ? [] : [e.Not]).SelectMany(ReferencedFields)
            .Concat(e.Field is null ? [] : [e.Field]).Distinct();

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
        _ => null,
    };

    private static bool Same(string a, string b) => string.Equals(a.Trim(), b.Trim(), StringComparison.OrdinalIgnoreCase);

    private static bool TryNumber(string s, out double d) =>
        double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out d);
}
