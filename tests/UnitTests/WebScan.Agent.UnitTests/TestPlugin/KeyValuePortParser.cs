using System.Runtime.CompilerServices;
using WebScan.Agent.Tools.Abstractions;
using WebScan.Contracts;

namespace WebScan.Agent.TestPlugin;

/// <summary>Plugin parser for a made-up tool printing "address port" lines.</summary>
public sealed class KeyValuePortParser : IToolOutputParser
{
    public string Id => "test-plugin-ports";

    public async IAsyncEnumerable<DiscoveryObservation> ParseAsync(Stream output, ParseContext context, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        using var reader = new StreamReader(output);
        while (await reader.ReadLineAsync(cancellationToken) is { } line)
        {
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 2 || !int.TryParse(parts[1], out var port)) continue;
            yield return context.NewObservation(ObservationKind.PortOpen, parts[0], port, TransportProtocol.Tcp) with
            {
                PortState = new PortDetails { State = "open", Reason = "plugin" },
            };
        }
    }
}
