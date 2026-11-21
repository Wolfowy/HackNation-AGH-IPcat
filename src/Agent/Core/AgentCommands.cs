using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using WebScan.Agent.Execution;
using WebScan.Agent.Tools;
using WebScan.Agent.Tools.Abstractions;
using WebScan.Contracts;

namespace WebScan.Agent;

/// <summary>Operator commands of the agent executable (no server connection).</summary>
public static class AgentCommands
{
    /// <summary><c>--list-tools</c>: probes manifests and prints the tool registry. Exit code 0 when at least one tool is available.</summary>
    public static async Task<int> ListToolsAsync(IServiceProvider services, TextWriter output, CancellationToken ct = default)
    {
        var registry = services.GetRequiredService<ToolRegistry>();
        var components = services.GetRequiredService<ToolComponentRegistry>();
        await registry.InitializeAsync(ct);

        await output.WriteLineAsync($"Parsers:  {string.Join(", ", components.ParserIds)}");
        await output.WriteLineAsync($"Adapters: {string.Join(", ", components.AdapterIds)}");
        await output.WriteLineAsync($"Tools ({registry.Tools.Count}):");
        foreach (var tool in registry.Tools)
        {
            var d = tool.ToDescriptor();
            await output.WriteLineAsync($"  {d.Id,-10} {d.Version,-10} {tool.ExecutablePath ?? "(built-in)"}");
            await output.WriteLineAsync($"             capabilities: {string.Join(", ", d.Capabilities)}");
            await output.WriteLineAsync($"             parameters:   {string.Join(", ", d.SupportedParameters)}");
            await output.WriteLineAsync($"             manifest:     {tool.ManifestPath} (sha256 {d.ManifestSha256})");
        }
        foreach (var problem in registry.Problems) await output.WriteLineAsync($"  not available: {problem}");
        return registry.Tools.Count > 0 ? 0 : 1;
    }

    /// <summary>
    /// <c>--run-job &lt;job.json&gt;</c>: validates and executes one <see cref="ScanJob"/> locally and prints its observations as
    /// JSON lines (for testing manifests against a lab). Exit code 0 when the tool completed successfully.
    /// </summary>
    public static async Task<int> RunJobAsync(IServiceProvider services, string jobFile, TextWriter output, TextWriter error, CancellationToken ct = default)
    {
        var job = JsonSerializer.Deserialize<ScanJob>(await File.ReadAllTextAsync(jobFile, ct), ContractJson.Options)
                  ?? throw new InvalidOperationException("Job file is empty.");
        await services.GetRequiredService<ToolRegistry>().InitializeAsync(ct);
        var validation = services.GetRequiredService<JobValidator>().Validate(job);
        if (!validation.IsValid)
        {
            await error.WriteLineAsync($"Job rejected ({validation.Reason}): {validation.Error}");
            return 2;
        }

        var writer = new JsonLinesWriter(output);
        using var timeout = new CancellationTokenSource(validation.Job!.Timeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);
        var result = await services.GetRequiredService<ToolExecutor>().RunAsync(validation.Job, writer, linked.Token);
        await error.WriteLineAsync($"tool={validation.Job.Tool.Id} version={validation.Job.Tool.Version} exit={result.ExitCode?.ToString() ?? "killed"} " +
                                   $"duration={result.Duration.TotalSeconds:F1}s observations={writer.Count}");
        if (result.ExitCode != 0 && !string.IsNullOrWhiteSpace(result.StderrTail)) await error.WriteLineAsync(result.StderrTail);
        return result.ExitCode == 0 ? 0 : 1;
    }

    private sealed class JsonLinesWriter(TextWriter output) : IObservationWriter
    {
        private readonly SemaphoreSlim _lock = new(1, 1);
        public int Count { get; private set; }

        public async ValueTask WriteAsync(DiscoveryObservation observation, CancellationToken cancellationToken)
        {
            await _lock.WaitAsync(CancellationToken.None);
            try
            {
                await output.WriteLineAsync(JsonSerializer.Serialize(observation, ContractJson.Options));
                Count++;
            }
            finally { _lock.Release(); }
        }
    }
}
