using System.Text.RegularExpressions;

namespace WebScan.Contracts;

/// <summary>
/// Validates string parameters against <see cref="ParameterDescriptor"/> schemas.
/// Shared by server (workflow/job validation) and agent (defence in depth before building tool arguments).
/// Unknown parameters are rejected: nothing reaches a tool command line unless the schema declares it.
/// </summary>
public static class ParameterValidator
{
    public sealed record Result(IReadOnlyDictionary<string, string> Values, IReadOnlyList<string> Errors)
    {
        public bool IsValid => Errors.Count == 0;
    }

    private static readonly Regex PortItem = new(@"^(\d{1,5})(-(\d{1,5}))?$", RegexOptions.Compiled);
    private static readonly Regex TopPorts = new(@"^top-(\d{1,5})$", RegexOptions.Compiled);

    /// <summary>Validates and returns values with defaults applied.</summary>
    public static Result Validate(IReadOnlyList<ParameterDescriptor> schema, IReadOnlyDictionary<string, string>? input)
    {
        input ??= new Dictionary<string, string>();
        var errors = new List<string>();
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var known = schema.ToDictionary(p => p.Name, StringComparer.Ordinal);

        foreach (var key in input.Keys.Where(k => !known.ContainsKey(k)))
            errors.Add($"Unknown parameter '{key}'.");

        foreach (var p in schema)
        {
            if (!input.TryGetValue(p.Name, out var raw) || string.IsNullOrWhiteSpace(raw))
            {
                if (p.Default is not null) values[p.Name] = p.Default;
                else if (p.Required) errors.Add($"Parameter '{p.Name}' is required.");
                continue;
            }

            raw = raw.Trim();
            if (raw.Length > 4096) { errors.Add($"Parameter '{p.Name}' is too long."); continue; }

            var error = ValidateValue(p, raw);
            if (error is null) values[p.Name] = raw;
            else errors.Add(error);
        }

        return new Result(values, errors);
    }

    public static string? ValidateValue(ParameterDescriptor p, string raw)
    {
        switch (p.Type)
        {
            case ParameterType.Integer:
                if (!long.TryParse(raw, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var n))
                    return $"Parameter '{p.Name}' must be an integer.";
                if (p.Min is { } min && n < min) return $"Parameter '{p.Name}' must be >= {min}.";
                if (p.Max is { } max && n > max) return $"Parameter '{p.Name}' must be <= {max}.";
                return null;
            case ParameterType.Boolean:
                return raw is "true" or "false" ? null : $"Parameter '{p.Name}' must be 'true' or 'false'.";
            case ParameterType.Enum:
                return p.AllowedValues?.Contains(raw, StringComparer.Ordinal) == true ? null : $"Parameter '{p.Name}' must be one of: {string.Join(", ", p.AllowedValues ?? [])}.";
            case ParameterType.PortSpec:
                if (!IsValidPortSpec(raw)) return $"Parameter '{p.Name}' is not a valid port specification.";
                return p.Pattern is null || Regex.IsMatch(raw, p.Pattern, RegexOptions.None, TimeSpan.FromMilliseconds(100))
                    ? null : $"Parameter '{p.Name}' does not accept '{raw}' (allowed: {p.Description ?? p.Pattern}).";
            case ParameterType.StringList:
                foreach (var item in SplitList(raw))
                {
                    var ok = (p.AllowedValues?.Contains(item, StringComparer.Ordinal) ?? false)
                             || (p.Pattern is not null && Regex.IsMatch(item, p.Pattern, RegexOptions.None, TimeSpan.FromMilliseconds(100)));
                    if (!ok) return $"Parameter '{p.Name}' contains invalid item '{item}'.";
                }
                return null;
            case ParameterType.String:
                if (p.Pattern is null) return $"Parameter '{p.Name}' has no validation pattern; free strings are not allowed.";
                return Regex.IsMatch(raw, p.Pattern, RegexOptions.None, TimeSpan.FromMilliseconds(100)) ? null : $"Parameter '{p.Name}' has an invalid format.";
            default:
                return $"Parameter '{p.Name}' has unsupported type.";
        }
    }

    public static IReadOnlyList<string> SplitList(string raw) =>
        raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// <summary>"80", "1-1024", "22,80,8000-8100", "top-100" (1..65535).</summary>
    public static bool IsValidPortSpec(string spec)
    {
        var top = TopPorts.Match(spec);
        if (top.Success) return int.Parse(top.Groups[1].Value) is >= 1 and <= 65535;

        var items = SplitList(spec);
        if (items.Count == 0) return false;
        foreach (var item in items)
        {
            var m = PortItem.Match(item);
            if (!m.Success) return false;
            var from = int.Parse(m.Groups[1].Value);
            var to = m.Groups[3].Success ? int.Parse(m.Groups[3].Value) : from;
            if (from is < 1 or > 65535 || to is < 1 or > 65535 || to < from) return false;
        }
        return true;
    }
}
