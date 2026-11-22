using System.Globalization;
using System.Net;
using System.Net.Sockets;
using WebScan.Agent.Tools.Abstractions;
using WebScan.Contracts;

namespace WebScan.Agent.Tools;

/// <summary>Values substituted into argv templates. Every value comes from validated job data or agent-generated paths.</summary>
public sealed record ArgumentValues
{
    public string? Input { get; init; }
    public string? Output { get; init; }
    public int Rate { get; init; }
    public int TimeoutSeconds { get; init; }
    public int Parallelism { get; init; }
    public string? Interface { get; init; }
    public string? Gateway { get; init; }
    public string? TemplatesDir { get; init; }
    public string? Ports { get; init; }

    /// <summary>Delay per thread so that <see cref="Parallelism"/> threads make about <see cref="Rate"/> connections per second.</summary>
    public int ThreadDelayMs => Math.Max(1, (int)Math.Ceiling(Math.Max(1, Parallelism) * 1000.0 / Math.Max(1, Rate)));
}

/// <summary>
/// Builds argv from a capability's templates. Each template element yields exactly one argument: values are substituted
/// inside the element and never split, joined or interpreted by a shell.
/// </summary>
public static class ArgumentBuilder
{
    public static List<string> Build(ToolCapabilityDefinition definition, ArgumentValues values, IReadOnlyDictionary<string, string> parameters)
    {
        var argv = new List<string>();
        foreach (var element in definition.Arguments) argv.Add(Substitute(element, values, null, parameters));

        foreach (var (name, mapping) in definition.ParameterArguments)
        {
            if (!parameters.TryGetValue(name, out var raw) || mapping.Resolve(raw) is not { } resolved) continue;
            if (resolved.Value.StartsWith('-'))
                throw new ArgumentException($"Parameter '{name}' value must not start with '-'."); // defence against option injection
            foreach (var element in resolved.Template) argv.Add(Substitute(element, values, resolved.Value, parameters));
        }

        if (values.Interface is not null)
            foreach (var element in definition.InterfaceArguments) argv.Add(Substitute(element, values, null, parameters));
        return argv;
    }

    /// <summary>True when any template of the capability references <paramref name="placeholder"/>.</summary>
    public static bool Uses(ToolCapabilityDefinition definition, string placeholder) =>
        definition.Arguments.Concat(definition.InterfaceArguments)
            .Concat(definition.ParameterArguments.Values.SelectMany(m => m.AllTemplates()).SelectMany(t => t))
            .Any(e => e.Contains(placeholder, StringComparison.Ordinal));

    private static string Substitute(string element, ArgumentValues v, string? parameterValue, IReadOnlyDictionary<string, string> parameters)
    {
        var result = element;
        foreach (var placeholder in ToolManifestLoader.Placeholders(element))
        {
            if (ToolPlaceholders.ParameterName(placeholder) is { } name)
            {
                if (!parameters.TryGetValue(name, out var referenced)) throw new InvalidOperationException($"No value available for placeholder {placeholder}.");
                if (referenced.StartsWith('-')) throw new ArgumentException($"Parameter '{name}' value must not start with '-'.");
                result = result.Replace(placeholder, referenced, StringComparison.Ordinal);
                continue;
            }
            var value = placeholder switch
            {
                ToolPlaceholders.Input => v.Input,
                ToolPlaceholders.Output => v.Output,
                ToolPlaceholders.Rate => v.Rate.ToString(CultureInfo.InvariantCulture),
                ToolPlaceholders.Timeout => v.TimeoutSeconds.ToString(CultureInfo.InvariantCulture),
                ToolPlaceholders.Parallelism => v.Parallelism.ToString(CultureInfo.InvariantCulture),
                ToolPlaceholders.Interface => v.Interface,
                ToolPlaceholders.Gateway => v.Gateway,
                ToolPlaceholders.TemplatesDir => v.TemplatesDir,
                ToolPlaceholders.Ports => v.Ports,
                ToolPlaceholders.ThreadDelayMs => v.ThreadDelayMs.ToString(CultureInfo.InvariantCulture),
                ToolPlaceholders.Value => parameterValue,
                _ => throw new InvalidOperationException($"Unknown placeholder {placeholder}."),
            } ?? throw new InvalidOperationException($"No value available for placeholder {placeholder}.");
            result = result.Replace(placeholder, value, StringComparison.Ordinal);
        }
        return result;
    }
}

/// <summary>
/// Writes job targets in the input format a tool expects. Endpoints are addressed by <see cref="ScanEndpoint.Hostname"/> when known
/// (URL host, SNI and Host header of virtual hosts), else by <see cref="ScanEndpoint.Address"/>; lines are deduplicated.
/// </summary>
public static class TargetFormatter
{
    public static IEnumerable<string> Lines(JobTargets targets, ToolInputFormat format)
    {
        if (targets.Endpoints.Count == 0) return targets.Hosts;
        return format switch
        {
            ToolInputFormat.Hosts => targets.Endpoints.Select(Host).Distinct(StringComparer.OrdinalIgnoreCase),
            ToolInputFormat.Endpoints => targets.Endpoints.Select(Endpoint).Distinct(StringComparer.OrdinalIgnoreCase),
            _ => targets.Endpoints.Select(e => e.Scheme is "http" or "https" ? $"{e.Scheme}://{Endpoint(e)}" : Endpoint(e)).Distinct(StringComparer.OrdinalIgnoreCase),
        };
    }

    /// <summary>The name a tool connects to: hostname when known (virtual host), else the address.</summary>
    public static string Host(ScanEndpoint e) => e.Hostname ?? e.Address;

    public static string Endpoint(ScanEndpoint e) => $"{HostPart(Host(e))}:{e.Port}";

    public static string HostPart(string address) =>
        IPAddress.TryParse(address, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{address}]" : address;

    /// <summary>
    /// Splits an endpoint job into invocations whose hosts share the same port set, so tools that take "hosts × ports"
    /// scan exactly the requested endpoints (no cross-product over-scan).
    /// </summary>
    public static IReadOnlyList<JobTargets> GroupByPortSet(JobTargets targets)
    {
        if (targets.Endpoints.Count == 0) return [targets];
        return targets.Endpoints
            .GroupBy(Host, StringComparer.OrdinalIgnoreCase)
            .GroupBy(g => string.Join(",", g.Select(e => e.Port).Distinct().Order()))
            .Select(group => new JobTargets { Endpoints = [.. group.SelectMany(g => g)], Count = group.Sum(g => g.Count()) })
            .ToList();
    }

    public static string Ports(JobTargets targets) => string.Join(",", targets.Endpoints.Select(e => e.Port).Distinct().Order());
}
