using System.Net;
using System.Runtime.CompilerServices;
using System.Text.Json;
using WebScan.Agent.Tools.Abstractions;
using WebScan.Contracts;

namespace WebScan.Agent.Tools.Parsers;

/// <summary>
/// <c>nerva --json</c> (Praetorian, maintained fork of fingerprintx): one identified service per line,
/// <c>{"host","ip","port","protocol","tls","transport","version","metadata":{…}}</c>. Emits a Service observation per line
/// (protocol → name, <c>tls</c> → tunnel "ssl", version, <c>metadata.cpes/technologies/banner</c>, other scalar metadata as masked
/// <c>nerva.*</c> attributes) and a Technology observation per <c>metadata.technologies</c> entry. The address is taken from the job
/// endpoint the line belongs to, so name-addressed targets (virtual hosts) keep the address the server planned.
/// </summary>
public sealed class NervaJsonlParser : IToolOutputParser
{
    public string Id => "nerva-jsonl";

    private const int MaxAttributes = 24;
    private static readonly HashSet<string> Mapped = new(StringComparer.Ordinal) { "technologies", "cpes", "banner", "product" };

    public async IAsyncEnumerable<DiscoveryObservation> ParseAsync(Stream output, ParseContext context, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (var line in Jsonl.ReadAsync(output, cancellationToken))
        {
            var protocol = line.Str("protocol")?.ToLowerInvariant();
            if (protocol is null || line.Get("port").AsInt() is not { } port) continue;
            var host = line.Str("host");
            var hostname = host is not null && !Jsonl.IsIp(host) ? host.TrimEnd('.').ToLowerInvariant() : null;
            // Hostname targets are dialled late; an unspecified ip ("0.0.0.0") is no address.
            var ip = line.Str("ip") is { } raw && IPAddress.TryParse(raw, out var parsed) && !parsed.Equals(IPAddress.Any) && !parsed.Equals(IPAddress.IPv6Any) ? raw : null;
            var endpoint = context.Job.Targets.Endpoints.FirstOrDefault(e => e.Port == port && (hostname is not null
                ? string.Equals(e.Hostname, hostname, StringComparison.OrdinalIgnoreCase)
                : e.Hostname is null && string.Equals(e.Address, ip ?? host, StringComparison.OrdinalIgnoreCase)));
            var address = endpoint?.Address ?? ip ?? host;
            if (address is null) continue;

            var transport = string.Equals(line.Str("transport"), "udp", StringComparison.OrdinalIgnoreCase) ? TransportProtocol.Udp : TransportProtocol.Tcp;
            var tls = line.Get("tls").AsBool() is true;
            var metadata = line.Get("metadata") is { ValueKind: JsonValueKind.Object } m ? m : (JsonElement?)null;
            var technologies = metadata?.Get("technologies").AsList() ?? [];
            var firstTech = technologies.Count > 0 ? HttpxJsonlParser.SplitTechnology(technologies[0]) : default;

            yield return context.NewObservation(ObservationKind.Service, address, port, transport, hostname) with
            {
                Hostname = hostname,
                Service = new ServiceDetails
                {
                    Name = tls && protocol == "http" ? "https" : protocol,
                    Product = metadata?.Str("product") ?? firstTech.Name,
                    Version = line.Str("version") ?? firstTech.Version,
                    Banner = ParseContext.MaskText(metadata?.Str("banner"), ParseContext.MaxBannerLength),
                    Tunnel = tls ? "ssl" : null,
                    Cpe = metadata?.Get("cpes").AsList() ?? [],
                },
                Confidence = new Confidence { Score = 0.9, Method = "version-probe" },
                Attributes = Attributes(line, metadata),
            };

            foreach (var entry in technologies)
            {
                var (name, version) = HttpxJsonlParser.SplitTechnology(entry);
                yield return context.NewObservation(ObservationKind.Technology, address, port, transport, $"{name.ToLowerInvariant()}|{hostname}") with
                {
                    Hostname = hostname,
                    Technology = new TechnologyDetails { Name = name, Version = version },
                    Confidence = new Confidence { Score = 0.8, Method = "tool-reported" },
                };
            }
        }
    }

    /// <summary>Scalar metadata (e.g. SMB/RDP host names, LDAP contexts, HTTP status/title), masked; headers and nested objects are skipped.</summary>
    private static Dictionary<string, string>? Attributes(JsonElement line, JsonElement? metadata)
    {
        var attributes = new Dictionary<string, string>(StringComparer.Ordinal);
        if (line.Get("anonymous_access").AsBool() is true) attributes["nerva.anonymousAccess"] = "true";
        if (metadata is { } md)
        {
            foreach (var p in md.EnumerateObject())
            {
                if (attributes.Count >= MaxAttributes) break;
                if (Mapped.Contains(p.Name) || p.Name.Contains("header", StringComparison.OrdinalIgnoreCase) || p.Name.Contains("cookie", StringComparison.OrdinalIgnoreCase)) continue;
                if (p.Value.ValueKind is not (JsonValueKind.String or JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False)) continue;
                if (ParseContext.MaskText(p.Value.AsString(), ParseContext.MaxEvidenceLength) is { } value) attributes[$"nerva.{p.Name}"] = value;
            }
        }
        return attributes.Count > 0 ? attributes : null;
    }
}
