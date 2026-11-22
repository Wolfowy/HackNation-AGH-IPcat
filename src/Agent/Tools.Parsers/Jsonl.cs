using System.Globalization;
using System.Net;
using System.Runtime.CompilerServices;
using System.Text.Json;

namespace WebScan.Agent.Tools.Parsers;

/// <summary>Helpers for JSON-lines tool output: tolerant line reader (truncated/invalid lines skipped) and dotted-path access.</summary>
internal static class Jsonl
{
    public static async IAsyncEnumerable<JsonElement> ReadAsync(Stream stream, [EnumeratorCancellation] CancellationToken ct)
    {
        using var reader = new StreamReader(stream);
        while (await reader.ReadLineAsync(ct) is { } line)
        {
            if (string.IsNullOrWhiteSpace(line) || line[0] != '{') continue;
            JsonElement element;
            try
            {
                using var doc = JsonDocument.Parse(line);
                element = doc.RootElement.Clone();
            }
            catch (JsonException) { continue; } // e.g. last line cut off when the tool was killed
            yield return element;
        }
    }

    /// <summary>Resolves "a.b.c" (object properties only).</summary>
    public static JsonElement? Get(this JsonElement element, string path)
    {
        var current = element;
        foreach (var part in path.Split('.'))
        {
            if (current.ValueKind != JsonValueKind.Object || !current.TryGetProperty(part, out current)) return null;
        }
        return current.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined ? null : current;
    }

    public static string? Str(this JsonElement element, string path) => element.Get(path)?.AsString();

    public static string? AsString(this JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.String => e.GetString() is { Length: > 0 } s ? s : null,
        JsonValueKind.Number => e.GetRawText(),
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        JsonValueKind.Array => string.Join(",", e.EnumerateArray().Select(AsString).OfType<string>()) is { Length: > 0 } joined ? joined : null,
        _ => null,
    };

    public static long? AsLong(this JsonElement? e) => e switch
    {
        { ValueKind: JsonValueKind.Number } n when n.TryGetInt64(out var v) => v,
        { ValueKind: JsonValueKind.String } s when long.TryParse(s.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) => v,
        _ => null,
    };

    public static int? AsInt(this JsonElement? e) => e.AsLong() is { } v && v is >= int.MinValue and <= int.MaxValue ? (int)v : null;

    public static bool? AsBool(this JsonElement? e) => e switch
    {
        { ValueKind: JsonValueKind.True } => true,
        { ValueKind: JsonValueKind.False } => false,
        { ValueKind: JsonValueKind.String } s when bool.TryParse(s.GetString(), out var b) => b,
        _ => null,
    };

    public static DateTimeOffset? AsDate(this JsonElement? e) =>
        e?.AsString() is { } s && DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var d) ? d : null;

    public static IReadOnlyList<string> AsList(this JsonElement? e) => e switch
    {
        { ValueKind: JsonValueKind.Array } a => [.. a.EnumerateArray().Select(AsString).OfType<string>()],
        { ValueKind: JsonValueKind.String } s when s.GetString() is { Length: > 0 } v => v.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
        _ => [],
    };

    public static bool IsIp(string? value) => value is not null && IPAddress.TryParse(value, out _);

    /// <summary>Host and port of an absolute URL or "host:port" string.</summary>
    public static (string? Host, int? Port) HostPort(string? value)
    {
        if (string.IsNullOrEmpty(value)) return (null, null);
        if (!value.Contains("://", StringComparison.Ordinal)) value = "tcp://" + value;
        return Uri.TryCreate(value, UriKind.Absolute, out var uri)
            ? (uri.Host.Trim('[', ']'), uri.IsDefaultPort && uri.Scheme == "tcp" ? null : uri.Port)
            : (null, null);
    }
}
