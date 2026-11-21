using System.Globalization;
using WebScan.Contracts;

namespace WebScan.Server.Modules.Workflows.Conditions;

/// <summary>Field types of <see cref="ConditionFields"/> (decides which operators and values are valid).</summary>
public static class ConditionFieldTypes
{
    public static readonly IReadOnlySet<string> Numeric = new HashSet<string>(StringComparer.Ordinal)
        { ConditionFields.Port, ConditionFields.HttpStatusCode, ConditionFields.ConfidenceScore };

    public static readonly IReadOnlyDictionary<string, string[]> Enums = new Dictionary<string, string[]>(StringComparer.Ordinal)
    {
        [ConditionFields.Kind] = Enum.GetNames<ObservationKind>(),
        [ConditionFields.Transport] = Enum.GetNames<TransportProtocol>(),
    };
}

/// <summary>Typed evaluation of a <see cref="ConditionExpression"/> against one observation. Strings compare case-insensitively.</summary>
public static class ConditionEvaluator
{
    public static bool Evaluate(ConditionExpression condition, DiscoveryObservation o)
    {
        if (condition.All is { } all) return all.All(c => Evaluate(c, o));
        if (condition.Any is { } any) return any.Any(c => Evaluate(c, o));
        if (condition.Not is { } not) return !Evaluate(not, o);

        var field = condition.Field ?? throw new InvalidOperationException("Condition has no field.");
        var value = GetField(o, field);
        var values = condition.Values ?? [];
        var numeric = ConditionFieldTypes.Numeric.Contains(field);
        bool Same(string candidate) => numeric
            ? TryNumber(value, out var a) && TryNumber(candidate, out var b) && a == b
            : string.Equals(value, candidate, StringComparison.OrdinalIgnoreCase);

        return condition.Operator switch
        {
            ConditionOperator.Exists => value is not null,
            ConditionOperator.NotExists => value is null,
            ConditionOperator.Equals => value is not null && Same(values[0]),
            ConditionOperator.NotEquals => value is null || !Same(values[0]),
            ConditionOperator.In => value is not null && values.Any(Same),
            ConditionOperator.NotIn => value is null || !values.Any(Same),
            ConditionOperator.Contains => value?.Contains(values[0], StringComparison.OrdinalIgnoreCase) == true,
            ConditionOperator.StartsWith => value?.StartsWith(values[0], StringComparison.OrdinalIgnoreCase) == true,
            ConditionOperator.GreaterThan => TryNumber(value, out var g) && TryNumber(values[0], out var gv) && g > gv,
            ConditionOperator.LessThan => TryNumber(value, out var l) && TryNumber(values[0], out var lv) && l < lv,
            _ => throw new InvalidOperationException($"Unsupported operator {condition.Operator}."),
        };
    }

    public static string? GetField(DiscoveryObservation o, string field) => field switch
    {
        ConditionFields.Kind => o.Kind.ToString(),
        ConditionFields.Address => o.Address,
        ConditionFields.Hostname => o.Hostname,
        ConditionFields.Port => o.Port?.ToString(CultureInfo.InvariantCulture),
        ConditionFields.Transport => o.Transport?.ToString(),
        ConditionFields.ToolId => o.Source?.ToolId,
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
        ConditionFields.ConfidenceScore => o.Confidence?.Score.ToString("R", CultureInfo.InvariantCulture),
        _ => throw new ArgumentOutOfRangeException(nameof(field), field, "Unknown condition field."),
    };

    public static bool TryNumber(string? s, out double value) =>
        double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out value);
}
