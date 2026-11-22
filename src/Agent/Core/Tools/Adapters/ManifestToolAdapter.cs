using Microsoft.Extensions.Logging;
using WebScan.Agent.Tools.Abstractions;
using WebScan.Contracts;

namespace WebScan.Agent.Tools.Adapters;

/// <summary>
/// Generic CLI runner driven entirely by the manifest: writes the targets, builds argv from the templates, runs the
/// executable through the process runner and streams its output through the configured parser.
/// </summary>
public sealed class ManifestToolAdapter(ILogger<ManifestToolAdapter> logger) : IToolAdapter
{
    public string Id => ToolCapabilityDefinition.ManifestAdapterId;

    public async Task<ToolExecutionResult> RunAsync(ToolExecutionRequest request, IObservationWriter writer, CancellationToken cancellationToken)
    {
        var def = request.Definition;
        var parser = request.Parser ?? throw new InvalidOperationException($"Capability '{request.Capability}' of tool '{request.Manifest.Id}' has no parser.");
        var executable = request.Executable ?? throw new InvalidOperationException($"Tool '{request.Manifest.Id}' has no executable.");
        var context = request.CreateParseContext();

        // Tools that take "hosts × ports" run once per group of hosts sharing a port set.
        var invocations = ArgumentBuilder.Uses(def, ToolPlaceholders.Ports) ? TargetFormatter.GroupByPortSet(request.Job.Targets) : [request.Job.Targets];
        var total = TimeSpan.Zero;
        ProcessRunResult? last = null;
        Exception? parseError = null;

        for (var i = 0; i < invocations.Count; i++)
        {
            if (cancellationToken.IsCancellationRequested) break;
            var targets = invocations[i];
            var inputFile = Path.Combine(request.WorkingDirectory, $"input-{i}.txt");
            var outputFile = Path.Combine(request.WorkingDirectory, $"output-{i}.out");
            await File.WriteAllLinesAsync(inputFile, TargetFormatter.Lines(targets, def.Input.Format), CancellationToken.None);

            var argv = ArgumentBuilder.Build(def, new ArgumentValues
            {
                Input = def.Input.Mode == ToolInputMode.File ? inputFile : null,
                Output = def.Output.Mode == ToolOutputMode.File ? outputFile : null,
                Rate = request.RatePerSecond,
                TimeoutSeconds = (int)Math.Ceiling(request.Timeout.TotalSeconds),
                Parallelism = request.Parallelism,
                Interface = request.InterfaceName,
                Gateway = request.InterfaceGateway,
                TemplatesDir = request.TemplatesDirectory,
                Ports = targets.Endpoints.Count > 0 ? TargetFormatter.Ports(targets) : null,
            }, request.Parameters);

            logger.LogInformation("Job {JobId}: running {Tool} ({Capability}) invocation {Index}/{Count} on {Targets} target line(s).",
                request.Job.JobId, request.Manifest.Id, request.Capability, i + 1, invocations.Count, targets.Endpoints.Count + targets.Hosts.Count);

            var run = await request.ProcessRunner.RunAsync(new ProcessRunRequest
            {
                Executable = executable,
                Arguments = argv,
                WorkingDirectory = request.WorkingDirectory,
                Environment = request.Manifest.Environment,
                StandardInputFile = def.Input.Mode == ToolInputMode.Stdin ? inputFile : null,
                StandardOutputHandler = def.Output.Mode == ToolOutputMode.Stdout ? async (stdout, ct) => parseError ??= await ParseAsync(parser, stdout, context, writer, ct) : null,
            }, cancellationToken);

            // Output files are parsed even after a kill: partial results are kept (coverage reports the rest).
            if (def.Output.Mode == ToolOutputMode.File && File.Exists(outputFile))
            {
                await using var output = File.OpenRead(outputFile);
                parseError ??= await ParseAsync(parser, output, context, writer, CancellationToken.None);
            }

            total += run.Duration;
            last = run;
            if (run.ExitCode != 0) break;
        }

        // Unparseable output means coverage cannot be trusted: fail the job (observations parsed so far are kept).
        if (parseError is not null && !cancellationToken.IsCancellationRequested)
            throw new InvalidOperationException($"Parser '{parser.Id}' failed: {parseError.Message}", parseError);
        return new ToolExecutionResult { ExitCode = last?.ExitCode, Duration = total, StderrTail = last?.StderrTail };
    }

    private async Task<Exception?> ParseAsync(IToolOutputParser parser, Stream output, ParseContext context, IObservationWriter writer, CancellationToken ct)
    {
        try
        {
            await foreach (var observation in parser.ParseAsync(output, context, ct)) await writer.WriteAsync(observation, ct);
            return null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Parser {Parser} failed on output of job {JobId}.", parser.Id, context.Job.JobId);
            return ex;
        }
    }
}
