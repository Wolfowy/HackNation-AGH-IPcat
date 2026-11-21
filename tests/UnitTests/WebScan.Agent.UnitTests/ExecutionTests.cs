using System.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using WebScan.Agent.Execution;
using WebScan.Agent.Tools;
using WebScan.Agent.Tools.Abstractions;
using WebScan.Contracts;

namespace WebScan.Agent.UnitTests;

public class ProcessRunnerTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly ProcessRunner _runner = new(NullLogger<ProcessRunner>.Instance, TimeProvider.System);

    public void Dispose() => _dir.Dispose();

    private ProcessRunRequest Request(string executable, params string[] args) => new() { Executable = executable, Arguments = args, WorkingDirectory = _dir.Path };

    [Fact]
    public async Task Arguments_are_passed_literally_without_a_shell()
    {
        var result = await _runner.RunAsync(Request("/bin/echo", "a; rm -rf /", "$(id)", "`id`", "x y"), CancellationToken.None);

        Assert.Equal(0, result.ExitCode);
        Assert.Equal("a; rm -rf / $(id) `id` x y\n", result.StdoutTail);
    }

    [Fact]
    public async Task Timeout_kills_the_process()
    {
        var sw = Stopwatch.StartNew();
        var result = await _runner.RunAsync(Request("/bin/sleep", "30") with { Timeout = TimeSpan.FromMilliseconds(300) }, CancellationToken.None);

        Assert.True(result.Killed);
        Assert.True(result.TimedOut);
        Assert.Null(result.ExitCode);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), $"took {sw.Elapsed}");
    }

    [Fact]
    public async Task Cancellation_kills_the_whole_process_tree()
    {
        var marker = Path.Combine(_dir.Path, "child-survived");
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));
        // Test-only shell: a child that would create the marker after 2 s unless it is killed with its parent.
        var result = await _runner.RunAsync(Request("/bin/sh", "-c", $"(sleep 2; touch '{marker}') & wait"), cts.Token);

        Assert.True(result.Killed);
        Assert.False(result.TimedOut);
        await Task.Delay(2500);
        Assert.False(File.Exists(marker));
    }

    [Fact]
    public async Task Environment_is_sanitized()
    {
        Environment.SetEnvironmentVariable("WEBSCAN_TEST_SECRET", "s3cr3t");
        try
        {
            var result = await _runner.RunAsync(Request("/usr/bin/env") with { Environment = new Dictionary<string, string> { ["TOOL_FLAG"] = "1" } }, CancellationToken.None);

            Assert.DoesNotContain("WEBSCAN_TEST_SECRET", result.StdoutTail);
            Assert.Contains($"HOME={_dir.Path}", result.StdoutTail);
            Assert.Contains("TOOL_FLAG=1", result.StdoutTail);
            Assert.Contains("PATH=", result.StdoutTail);
        }
        finally { Environment.SetEnvironmentVariable("WEBSCAN_TEST_SECRET", null); }
    }

    [Fact]
    public async Task Stdin_file_and_stdout_handler_stream_data_with_cap()
    {
        var input = _dir.File("in.txt", string.Concat(Enumerable.Repeat("0123456789", 1000)));
        string? received = null;
        var result = await _runner.RunAsync(Request("/bin/cat") with
        {
            StandardInputFile = input,
            MaxStdoutBytes = 100,
            StandardOutputHandler = async (stream, ct) => received = await new StreamReader(stream).ReadToEndAsync(ct),
        }, CancellationToken.None);

        Assert.Equal(0, result.ExitCode);
        Assert.Equal(100, received!.Length);
        Assert.True(result.StdoutTruncated);
    }

    [Fact]
    public async Task Stderr_tail_is_masked_and_bounded()
    {
        var result = await _runner.RunAsync(Request("/bin/sh", "-c", "i=0; while [ $i -lt 2000 ]; do echo 'noise line' >&2; i=$((i+1)); done; echo 'password=hunter2' >&2; exit 3")
            with { StderrTailBytes = 256 }, CancellationToken.None);

        Assert.Equal(3, result.ExitCode);
        Assert.True(result.StderrTail.Length <= 256);
        Assert.Contains("password=***", result.StderrTail);
        Assert.DoesNotContain("hunter2", result.StderrTail);
    }

    [Fact]
    public async Task Relative_executables_are_refused()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => _runner.RunAsync(Request("echo", "x"), CancellationToken.None));
    }
}

public class JobValidatorTests : IAsyncLifetime
{
    private AgentHarness _agent = null!;
    private JobValidator _validator = null!;

    public async Task InitializeAsync()
    {
        _agent = new AgentHarness();
        await _agent.Get<ToolRegistry>().InitializeAsync(CancellationToken.None);
        _validator = _agent.Get<JobValidator>();
    }

    public async Task DisposeAsync() => await _agent.DisposeAsync();

    private static ScanJob PortScan(IReadOnlyList<string> hosts, IReadOnlyList<string> scope, Dictionary<string, string>? parameters = null) =>
        Jobs.Hosts(ScanOperation.ScanPorts, ToolCapabilities.PortScan, hosts, scope, parameters ?? new() { ["ports"] = "top-100" });

    [Fact]
    public void Valid_job_is_accepted_with_effective_limits()
    {
        var result = _validator.Validate(PortScan(["10.0.0.0/25", "10.0.0.200", "app.example.com"], ["10.0.0.0/24", "*.example.com"]) with
        {
            Parameters = new Dictionary<string, string> { ["ports"] = "22,80", ["rate"] = "50" },
        });

        Assert.True(result.IsValid, result.Error);
        Assert.Equal("fake", result.Job!.Tool.Id);
        Assert.Equal(50, result.Job.RatePerSecond); // min(job 100, agent share 1000/2, parameter 50)
        Assert.Equal("connect", result.Job.Parameters["scanType"]); // defaults applied
        Assert.Equal(TimeSpan.FromSeconds(60), result.Job.Timeout);
    }

    [Theory]
    [InlineData("10.0.1.5")]
    [InlineData("10.0.0.0/23")] // larger than the authorized /24
    [InlineData("evil.com")]
    [InlineData("example.com")] // "*.example.com" covers subdomains only
    [InlineData("-oX/etc/passwd")]
    public void Out_of_scope_or_malformed_targets_are_rejected(string target)
    {
        var result = _validator.Validate(PortScan(["10.0.0.1", target], ["10.0.0.0/24", "*.example.com"]));

        Assert.False(result.IsValid);
        Assert.Equal(JobFailureReason.InvalidJob, result.Reason);
        Assert.False(result.Retryable);
    }

    [Fact]
    public void Out_of_scope_endpoint_is_rejected()
    {
        var job = Jobs.Endpoints(ScanOperation.HttpProbe, ToolCapabilities.HttpProbe,
            [new ScanEndpoint { Address = "10.0.0.5", Port = 80 }, new ScanEndpoint { Address = "192.168.1.1", Port = 80 }], ["10.0.0.0/24"]);
        Assert.Contains("outside the authorized scope", _validator.Validate(job).Error);
    }

    [Fact]
    public void Unknown_parameter_is_rejected()
    {
        var result = _validator.Validate(PortScan(["10.0.0.1"], ["10.0.0.0/24"], new() { ["ports"] = "80", ["extraArgs"] = "--script=evil" }));

        Assert.Equal(JobFailureReason.InvalidJob, result.Reason);
        Assert.Contains("extraArgs", result.Error);
    }

    [Fact]
    public void NotAfter_in_the_past_is_rejected()
    {
        var result = _validator.Validate(PortScan(["10.0.0.1"], ["10.0.0.0/24"]) with { NotAfter = DateTimeOffset.UtcNow.AddSeconds(-1) });

        Assert.Equal(JobFailureReason.WindowExpired, result.Reason);
        Assert.False(result.Retryable);
    }

    [Fact]
    public void Timeout_is_capped_by_the_window_end()
    {
        var result = _validator.Validate(PortScan(["10.0.0.1"], ["10.0.0.0/24"]) with { NotAfter = DateTimeOffset.UtcNow.AddSeconds(20) });

        Assert.True(result.Job!.TimeoutIsWindowEnd);
        Assert.InRange(result.Job.Timeout.TotalSeconds, 15, 20);
    }

    [Fact]
    public void Server_plane_operations_unknown_interfaces_and_missing_tools_are_rejected()
    {
        Assert.Equal(JobFailureReason.InvalidJob, _validator.Validate(Jobs.Hosts(ScanOperation.PersistObservations, "x", ["10.0.0.1"])).Reason);
        Assert.Contains("Interface", _validator.Validate(PortScan(["10.0.0.1"], ["10.0.0.0/24"]) with { InterfaceName = "eth9" }).Error);
        Assert.True(_validator.Validate(PortScan(["10.0.0.1"], ["10.0.0.0/24"]) with { InterfaceName = "lab0" }).IsValid);

        var noTool = _validator.Validate(PortScan(["10.0.0.1"], ["10.0.0.0/24"]) with { Tool = new ToolSelection { Capability = "dns-resolve" } });
        Assert.Equal((JobFailureReason.ToolNotAvailable, true), (noTool.Reason, noTool.Retryable));
    }

    [Fact]
    public void Tampered_signature_bundle_is_rejected()
    {
        var items = new List<SignatureContent> { new() { Id = "sig-a", Version = 1, Format = "nuclei-yaml", Content = "id: sig-a" } };
        var job = Jobs.Endpoints(ScanOperation.ExecuteSignatures, ToolCapabilities.SignatureScan, [new ScanEndpoint { Address = "10.0.0.5", Port = 80 }], ["10.0.0.0/24"]);

        Assert.True(_validator.Validate(job with { Signatures = new SignatureBundle { Sha256 = SignatureBundles.ComputeSha256(items), Items = items } }).IsValid);
        var tampered = _validator.Validate(job with { Signatures = new SignatureBundle { Sha256 = new string('0', 64), Items = items } });
        Assert.Contains("SHA-256 mismatch", tampered.Error);
    }
}

public class SignatureBundleTests
{
    [Fact]
    public void Hash_is_sha256_over_id_version_content_lines_in_order()
    {
        // Reference value computed independently (Python): sha256(b"".join(f"{id}\n{version}\n{content}\n".encode() for ...)).
        var items = new List<SignatureContent>
        {
            new() { Id = "sig-a", Version = 1, Format = "nuclei-yaml", Content = "id: sig-a\ninfo: {}\n" },
            new() { Id = "sig-b", Version = 3, Format = "nuclei-yaml", Content = "zażółć" },
        };
        Assert.Equal("e857c239fb283f925731d519c23e3d86c727e0c5f04ea61dfa55ee69cb11cf17", SignatureBundles.ComputeSha256(items));
        Assert.NotEqual(SignatureBundles.ComputeSha256(items), SignatureBundles.ComputeSha256([items[1], items[0]]));
    }

    [Fact]
    public void Only_nuclei_yaml_with_safe_ids_is_accepted_and_written()
    {
        SignatureBundle Bundle(params SignatureContent[] items) => new() { Sha256 = SignatureBundles.ComputeSha256(items), Items = items };

        Assert.Contains("unsupported format", SignatureBundles.Validate(Bundle(new SignatureContent { Id = "a", Version = 1, Format = "lua", Content = "" })));
        Assert.Contains("not allowed", SignatureBundles.Validate(Bundle(new SignatureContent { Id = "../../etc/x", Version = 1, Format = "nuclei-yaml", Content = "" })));

        using var dir = new TempDir();
        var ok = Bundle(new SignatureContent { Id = "webscan-testlab-admin-panel", Version = 2, Format = "nuclei-yaml", Content = "id: x" });
        Assert.Null(SignatureBundles.Validate(ok));
        SignatureBundles.WriteTemplates(ok, Path.Combine(dir.Path, "t"));
        Assert.Equal("id: x", File.ReadAllText(Path.Combine(dir.Path, "t", "webscan-testlab-admin-panel.yaml")));
    }
}

public class TargetsTests
{
    [Theory]
    [InlineData("10.0.0.0/30", "10.0.0.0,10.0.0.1,10.0.0.2,10.0.0.3")]
    [InlineData("10.0.0.7", "10.0.0.7")]
    [InlineData("fd00::/127", "fd00::,fd00::1")]
    [InlineData("10.0.0.0/8", "10.0.0.0/8")] // too large to expand
    [InlineData("host.example.com", "host.example.com")]
    public void Expansion(string entry, string expected) => Assert.Equal(expected, string.Join(",", Targets.Expand(entry)));

    [Fact]
    public void Scope_checks_handle_ipv6_and_host_bits()
    {
        Assert.True(Targets.IsInScope("fd00::1", ["fd00::/64"]));
        Assert.True(Targets.IsInScope("10.0.0.0/26", ["10.0.0.1/24"]));
        Assert.False(Targets.IsInScope("10.0.0.0/26", ["fd00::/64"]));
        Assert.True(Targets.IsInScope("a.b.example.com", ["*.example.com"]));
    }
}
