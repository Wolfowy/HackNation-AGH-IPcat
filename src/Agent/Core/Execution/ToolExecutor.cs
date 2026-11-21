using Microsoft.Extensions.Logging;
using WebScan.Agent.Storage;
using WebScan.Agent.Tools;
using WebScan.Agent.Tools.Abstractions;
using Microsoft.Extensions.Options;

namespace WebScan.Agent.Execution;

/// <summary>Runs the adapter of a validated job in a per-job temporary directory (signature templates written there), then deletes it.</summary>
public sealed class ToolExecutor(
    ToolComponentRegistry components,
    IToolProcessRunner processRunner,
    CredentialStore credentials,
    IOptions<AgentOptions> options,
    TimeProvider time,
    ILogger<ToolExecutor> logger)
{
    public async Task<ToolExecutionResult> RunAsync(ValidatedJob job, IObservationWriter writer, CancellationToken cancellationToken)
    {
        var def = job.Definition;
        var adapter = components.GetAdapter(def.Adapter) ?? throw new InvalidOperationException($"Adapter '{def.Adapter}' is not registered.");
        var parser = def.Parser is null ? null : components.GetParser(def.Parser) ?? throw new InvalidOperationException($"Parser '{def.Parser}' is not registered.");

        var workDir = Directory.CreateTempSubdirectory($"webscan-job-{job.Job.JobId:N}-").FullName;
        try
        {
            string? templatesDir = null;
            if (job.Job.Signatures is { } bundle)
            {
                templatesDir = Path.Combine(workDir, "templates");
                SignatureBundles.WriteTemplates(bundle, templatesDir);
            }

            var request = new ToolExecutionRequest
            {
                Job = job.Job,
                AgentId = credentials.Current?.AgentId ?? AgentPaths.DefaultAgentId(options.Value),
                Manifest = job.Tool.Manifest,
                Capability = job.Job.Tool.Capability,
                Definition = def,
                Executable = job.Tool.ExecutablePath,
                ToolVersion = job.Tool.Version,
                Parameters = job.Parameters,
                RatePerSecond = job.RatePerSecond,
                Parallelism = job.Parallelism,
                Timeout = job.Timeout,
                InterfaceName = job.Job.InterfaceName,
                WorkingDirectory = workDir,
                TemplatesDirectory = templatesDir,
                Parser = parser,
                ProcessRunner = processRunner,
                TimeProvider = time,
            };
            logger.LogInformation("Job {JobId}: {Operation} via {Tool} {Version} ({Adapter}), rate {Rate}/s, timeout {Timeout}.",
                job.Job.JobId, job.Job.Operation, job.Tool.Id, job.Tool.Version, def.Adapter, job.RatePerSecond, job.Timeout);
            return await adapter.RunAsync(request, writer, cancellationToken);
        }
        finally
        {
            ToolRegistry.TryDeleteDirectory(workDir);
        }
    }
}
