using System.Text.Json;
using WebScan.Contracts;

namespace WebScan.Agent.Tools.Abstractions;

/// <summary>
/// Turns native tool output into normalized observations. Registered by <see cref="Id"/> (built-in or plugin assembly)
/// and referenced from manifests via <c>capabilities.*.parser</c>.
/// </summary>
public interface IToolOutputParser
{
    string Id { get; }

    /// <summary>Streams observations; must tolerate truncated output (tool killed on timeout) by yielding what was complete.</summary>
    IAsyncEnumerable<DiscoveryObservation> ParseAsync(Stream output, ParseContext context, CancellationToken cancellationToken);

    /// <summary>Validates <c>parserOptions</c> of a manifest at load time; returns error messages (empty = valid).</summary>
    IReadOnlyList<string> ValidateOptions(JsonElement? options) => [];
}

/// <summary>
/// Runs a tool for one job. The generic "manifest" adapter covers CLI tools; plugins may implement other execution models.
/// Cancellation (timeout, window end, server cancel, shutdown) is signalled through the token; adapters should still
/// write observations already parsed and then return.
/// </summary>
public interface IToolAdapter
{
    string Id { get; }

    Task<ToolExecutionResult> RunAsync(ToolExecutionRequest request, IObservationWriter writer, CancellationToken cancellationToken);
}

public interface IObservationWriter
{
    ValueTask WriteAsync(DiscoveryObservation observation, CancellationToken cancellationToken);
}

/// <summary>Everything an adapter needs; all values are validated by the agent before the adapter sees them.</summary>
public sealed record ToolExecutionRequest
{
    public required ScanJob Job { get; init; }
    public required string AgentId { get; init; }
    public required ToolManifest Manifest { get; init; }
    public required string Capability { get; init; }
    public required ToolCapabilityDefinition Definition { get; init; }

    /// <summary>Absolute path of the resolved executable (null for executable-less tools).</summary>
    public string? Executable { get; init; }

    public string? ToolVersion { get; init; }

    /// <summary>Job parameters validated against <see cref="OperationCatalog"/>, defaults applied.</summary>
    public required IReadOnlyDictionary<string, string> Parameters { get; init; }

    /// <summary>Effective packets/requests per second (min of job, parameter and agent share).</summary>
    public required int RatePerSecond { get; init; }

    public required int Parallelism { get; init; }
    public required TimeSpan Timeout { get; init; }

    /// <summary>Local interface to scan from (verified to exist), or null for the OS default.</summary>
    public string? InterfaceName { get; init; }

    /// <summary>Gateway of <see cref="InterfaceName"/> (route gateway or first subnet address), null without an interface.</summary>
    public string? InterfaceGateway { get; init; }

    /// <summary>Per-job temporary directory, deleted after the job.</summary>
    public required string WorkingDirectory { get; init; }

    /// <summary>Directory with the verified signature templates of the job (signature jobs only).</summary>
    public string? TemplatesDirectory { get; init; }

    /// <summary>Parser configured for the capability (null if none).</summary>
    public IToolOutputParser? Parser { get; init; }

    public required IToolProcessRunner ProcessRunner { get; init; }
    public required TimeProvider TimeProvider { get; init; }

    public ParseContext CreateParseContext() => new()
    {
        Job = Job,
        Source = new ObservationSource { ToolId = Manifest.Id, ToolVersion = ToolVersion, AgentId = AgentId, InterfaceName = InterfaceName, JobId = Job.JobId },
        ParserOptions = Definition.ParserOptions,
        TimeProvider = TimeProvider,
    };
}

public sealed record ToolExecutionResult
{
    /// <summary>Null when the process was killed or never started.</summary>
    public int? ExitCode { get; init; }

    public required TimeSpan Duration { get; init; }

    /// <summary>Masked tail of stderr (max 4 KB).</summary>
    public string? StderrTail { get; init; }
}

/// <summary>Context for parsers: who/what produced the output and helpers for consistent observations.</summary>
public sealed record ParseContext
{
    public required ScanJob Job { get; init; }
    public required ObservationSource Source { get; init; }
    public JsonElement? ParserOptions { get; init; }
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    public const int MaxEvidenceLength = 2048;
    public const int MaxBannerLength = 1024;

    /// <summary>New observation with deterministic id (see <see cref="ObservationIds.Compute"/>); set the kind-specific section with <c>with</c>.</summary>
    public DiscoveryObservation NewObservation(ObservationKind kind, string address, int? port = null, TransportProtocol? transport = null,
        string? discriminator = null, DateTimeOffset? observedAt = null) => new()
    {
        ObservationId = ObservationIds.Compute(Job.JobId, kind, address, port, transport, discriminator),
        Kind = kind,
        Address = address,
        Port = port,
        Transport = transport,
        ObservedAt = observedAt ?? TimeProvider.GetUtcNow(),
        Source = Source,
    };

    /// <summary>Masks tokens/secrets in free text and truncates it.</summary>
    public static string? MaskText(string? text, int maxLength)
    {
        if (string.IsNullOrEmpty(text)) return text;
        var masked = SensitiveDataMasker.MaskTokens(text);
        return masked.Length <= maxLength ? masked : masked[..maxLength];
    }

    /// <summary>Masks a raw HTTP message (header lines through <see cref="SensitiveDataMasker.MaskHeader"/>, body tokens) and truncates it.</summary>
    public static string? MaskHttpMessage(string? message, int maxLength)
    {
        if (string.IsNullOrEmpty(message)) return message;
        var lines = message.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var colon = line.IndexOf(':');
            if (colon > 0 && !line[..colon].Contains(' '))
                lines[i] = line[..colon] + ": " + SensitiveDataMasker.MaskHeader(line[..colon], line[(colon + 1)..].Trim());
        }
        return MaskText(string.Join('\n', lines), maxLength);
    }
}

/// <summary>Safe process execution offered to adapters (no shell, sanitized environment, process tree killed on cancellation).</summary>
public interface IToolProcessRunner
{
    Task<ProcessRunResult> RunAsync(ProcessRunRequest request, CancellationToken cancellationToken);
}

public sealed record ProcessRunRequest
{
    /// <summary>Absolute path of the executable.</summary>
    public required string Executable { get; init; }

    /// <summary>Passed via <c>ProcessStartInfo.ArgumentList</c>: each element is exactly one argv entry.</summary>
    public required IReadOnlyList<string> Arguments { get; init; }

    public required string WorkingDirectory { get; init; }

    /// <summary>Extra environment on top of the sanitized base (PATH, HOME/TMPDIR = working directory, LANG=C).</summary>
    public IReadOnlyDictionary<string, string> Environment { get; init; } = new Dictionary<string, string>();

    /// <summary>File streamed to stdin (null = stdin closed immediately).</summary>
    public string? StandardInputFile { get; init; }

    /// <summary>Consumes stdout while the process runs (e.g. a streaming parser). Null = drained and discarded.</summary>
    public Func<Stream, CancellationToken, Task>? StandardOutputHandler { get; init; }

    /// <summary>Hard limit on the run, in addition to the cancellation token. Null = token only.</summary>
    public TimeSpan? Timeout { get; init; }

    public long MaxStdoutBytes { get; init; } = 512L * 1024 * 1024;
    public int StderrTailBytes { get; init; } = 4096;
}

public sealed record ProcessRunResult
{
    /// <summary>Null when the process was killed (timeout/cancellation).</summary>
    public int? ExitCode { get; init; }

    public bool Killed { get; init; }
    public bool TimedOut { get; init; }
    public bool StdoutTruncated { get; init; }
    public required TimeSpan Duration { get; init; }

    /// <summary>Masked tail of stderr.</summary>
    public required string StderrTail { get; init; }

    /// <summary>Full stdout+stderr text is not kept; this is the stdout tail when no handler consumed it (used for version probes).</summary>
    public string? StdoutTail { get; init; }
}
