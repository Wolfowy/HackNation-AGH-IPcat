using System.Diagnostics;
using System.Text;
using Microsoft.Extensions.Logging;
using WebScan.Agent.Tools.Abstractions;
using WebScan.Contracts;

namespace WebScan.Agent.Execution;

/// <summary>
/// Runs tool processes without a shell: resolved absolute executable, argv via <see cref="ProcessStartInfo.ArgumentList"/>,
/// sanitized environment, bounded output capture, and the whole process tree killed on timeout or cancellation.
/// </summary>
public sealed class ProcessRunner(ILogger<ProcessRunner> logger, TimeProvider timeProvider) : IToolProcessRunner
{
    private const int StdoutTailChars = 64 * 1024;

    public async Task<ProcessRunResult> RunAsync(ProcessRunRequest request, CancellationToken cancellationToken)
    {
        if (!Path.IsPathFullyQualified(request.Executable)) throw new ArgumentException("Executable must be an absolute path.", nameof(request));

        var psi = new ProcessStartInfo(request.Executable)
        {
            WorkingDirectory = request.WorkingDirectory,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var arg in request.Arguments) psi.ArgumentList.Add(arg);
        ApplyEnvironment(psi, request);

        using var process = new Process { StartInfo = psi };
        var started = timeProvider.GetTimestamp();
        process.Start();
        logger.LogDebug("Started {Executable} (pid {Pid}) with {Count} argument(s).", request.Executable, process.Id, request.Arguments.Count);

        var stderrTail = new TailBuffer(request.StderrTailBytes);
        var stdoutTail = request.StandardOutputHandler is null ? new TailBuffer(StdoutTailChars) : null;
        var capped = new CappedReadStream(process.StandardOutput.BaseStream, request.MaxStdoutBytes);

        using var pumpCts = new CancellationTokenSource();
        var stderrTask = PumpTextAsync(process.StandardError, stderrTail, pumpCts.Token);
        var stdoutTask = ConsumeStdoutAsync(request.StandardOutputHandler ?? ((s, ct) => PumpTextAsync(new StreamReader(s), stdoutTail!, ct)), capped, pumpCts.Token);
        var stdinTask = FeedStdinAsync(process, request.StandardInputFile);

        using var timeoutCts = request.Timeout is { } t ? new CancellationTokenSource(t, timeProvider) : new CancellationTokenSource();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
        var killed = false;
        try
        {
            await process.WaitForExitAsync(linked.Token);
        }
        catch (OperationCanceledException)
        {
            killed = true;
            KillTree(process);
            await process.WaitForExitAsync(CancellationToken.None);
        }

        // Pipes close when the tree is gone; bound the wait in case an orphan still holds them.
        var pumps = Task.WhenAll(stdoutTask, stderrTask, stdinTask);
        if (await Task.WhenAny(pumps, Task.Delay(TimeSpan.FromSeconds(10), timeProvider, CancellationToken.None)) != pumps)
        {
            pumpCts.Cancel();
            logger.LogWarning("Output of {Executable} still open after exit; stopped reading.", request.Executable);
        }
        await pumps.ContinueWith(_ => { }, TaskScheduler.Default);
        if (stdoutTask.Exception is { } stdoutError) logger.LogWarning(stdoutError.GetBaseException(), "Stdout consumer of {Executable} failed.", request.Executable);

        return new ProcessRunResult
        {
            ExitCode = killed ? null : process.ExitCode,
            Killed = killed,
            TimedOut = killed && timeoutCts.IsCancellationRequested,
            StdoutTruncated = capped.Truncated,
            Duration = timeProvider.GetElapsedTime(started),
            StderrTail = SensitiveDataMasker.MaskTokens(stderrTail.ToString()),
            StdoutTail = stdoutTail is null ? null : SensitiveDataMasker.MaskTokens(stdoutTail.ToString()),
        };
    }

    private static void ApplyEnvironment(ProcessStartInfo psi, ProcessRunRequest request)
    {
        var path = Environment.GetEnvironmentVariable("PATH");
        var systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
        psi.Environment.Clear();
        if (path is not null) psi.Environment["PATH"] = path;
        if (OperatingSystem.IsWindows() && systemRoot is not null) psi.Environment["SystemRoot"] = systemRoot;
        psi.Environment["HOME"] = request.WorkingDirectory;
        psi.Environment["TMPDIR"] = request.WorkingDirectory;
        psi.Environment["TMP"] = request.WorkingDirectory;
        psi.Environment["TEMP"] = request.WorkingDirectory;
        psi.Environment["LANG"] = "C";
        foreach (var (key, value) in request.Environment) psi.Environment[key] = value;
    }

    private static async Task ConsumeStdoutAsync(Func<Stream, CancellationToken, Task> handler, CappedReadStream stdout, CancellationToken ct)
    {
        try { await handler(stdout, ct); }
        finally { await stdout.DrainAsync(ct); } // keep the pipe flowing so the tool never blocks on a full buffer
    }

    private static async Task FeedStdinAsync(Process process, string? inputFile)
    {
        try
        {
            if (inputFile is not null)
            {
                await using var file = File.OpenRead(inputFile);
                await file.CopyToAsync(process.StandardInput.BaseStream);
            }
        }
        catch (IOException) { } // process exited before reading all input
        finally
        {
            try { process.StandardInput.Close(); } catch (IOException) { }
        }
    }

    private static async Task PumpTextAsync(StreamReader reader, TailBuffer tail, CancellationToken ct)
    {
        var buffer = new char[8192];
        int read;
        while ((read = await reader.ReadAsync(buffer, ct)) > 0) tail.Append(buffer.AsSpan(0, read));
    }

    private void KillTree(Process process)
    {
        try { process.Kill(entireProcessTree: true); }
        catch (InvalidOperationException) { } // already exited
        catch (Exception ex) { logger.LogWarning(ex, "Failed to kill process tree of pid {Pid}.", process.Id); }
    }

    /// <summary>Keeps the last <c>capacity</c> characters.</summary>
    private sealed class TailBuffer(int capacity)
    {
        private readonly StringBuilder _sb = new();
        private readonly Lock _lock = new();

        public void Append(ReadOnlySpan<char> chars)
        {
            lock (_lock)
            {
                _sb.Append(chars);
                if (_sb.Length > capacity * 2) _sb.Remove(0, _sb.Length - capacity);
            }
        }

        public override string ToString()
        {
            lock (_lock) return _sb.Length <= capacity ? _sb.ToString() : _sb.ToString(_sb.Length - capacity, capacity);
        }
    }
}

/// <summary>Read-only wrapper that reports end-of-stream after <c>maxBytes</c>.</summary>
internal sealed class CappedReadStream(Stream inner, long maxBytes) : Stream
{
    private long _read;
    public bool Truncated { get; private set; }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        var allowed = Allowed(buffer.Length);
        if (allowed == 0) return 0;
        var n = inner.Read(buffer[..allowed]);
        _read += n;
        return n;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var allowed = Allowed(buffer.Length);
        if (allowed == 0) return 0;
        var n = await inner.ReadAsync(buffer[..allowed], cancellationToken);
        _read += n;
        return n;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public async Task DrainAsync(CancellationToken ct)
    {
        var buffer = new byte[16384];
        try
        {
            while (await inner.ReadAsync(buffer, ct) > 0)
                if (_read >= maxBytes) Truncated = true;
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or OperationCanceledException) { }
    }

    private int Allowed(int requested)
    {
        var remaining = maxBytes - _read;
        if (remaining <= 0) { Truncated = true; return 0; }
        return (int)Math.Min(requested, remaining);
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => _read; set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
