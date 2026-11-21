using System.Text.Json;
using WebScan.Agent.Tools;
using WebScan.Agent.Tools.Abstractions;
using WebScan.Contracts;

namespace WebScan.Agent.UnitTests;

public class ManifestTests
{
    private static ToolManifest Parse(string json) => JsonSerializer.Deserialize<ToolManifest>(json, ToolManifestJson.Options)!;

    private static string Manifest(string capabilityJson) => $$"""
        { "id": "mytool", "executable": "mytool", "versionRegex": "v(\\d+)", "capabilities": { "port-scan": {{capabilityJson}} } }
        """;

    [Fact]
    public void Shipped_manifests_are_valid()
    {
        var result = ToolManifestLoader.Load([TestPaths.ShippedManifests], Parsing.BuiltInRegistry());

        Assert.Empty(result.Errors);
        Assert.Equal(["fake", "httpx", "naabu", "nmap", "nuclei", "tlsx"], result.Manifests.Select(m => m.Manifest.Id).Order());
        Assert.All(result.Manifests, m => Assert.Matches("^[0-9a-f]{64}$", m.Sha256));
    }

    [Fact]
    public void Manifests_with_unavailable_adapters_are_skipped_not_rejected()
    {
        var result = ToolManifestLoader.Load([TestPaths.ShippedManifests], Parsing.BuiltInRegistry(withFake: false));

        Assert.Empty(result.Errors);
        Assert.DoesNotContain(result.Manifests, m => m.Manifest.Id == "fake");
        Assert.Contains(result.Skipped, s => s.Contains("fake"));
    }

    [Fact]
    public void Unknown_placeholder_is_rejected()
    {
        var errors = ToolManifestLoader.Validate(Parse(Manifest("""{ "parser": "naabu-jsonl", "arguments": ["-l", "{input}", "-o", "{output}", "--cmd", "{shell}"] }""")), Parsing.BuiltInRegistry());
        Assert.Contains(errors, e => e.Contains("unknown placeholder {shell}"));
    }

    [Fact]
    public void Unknown_parser_is_rejected()
    {
        var errors = ToolManifestLoader.Validate(Parse(Manifest("""{ "parser": "does-not-exist", "arguments": ["-l", "{input}", "-o", "{output}"] }""")), Parsing.BuiltInRegistry());
        Assert.Contains(errors, e => e.Contains("unknown parser 'does-not-exist'"));
    }

    [Theory]
    [InlineData("""{ "parser": "naabu-jsonl", "arguments": ["-l", "{input}", "-o", "{output}", "-p", "{value}"] }""", "only allowed in parameterArguments")]
    [InlineData("""{ "parser": "naabu-jsonl", "arguments": ["-l", "{input}", "-o", "{output}", "-e", "{interface}"] }""", "only allowed in interfaceArguments")]
    [InlineData("""{ "parser": "naabu-jsonl", "arguments": ["-l", "{input}"] }""", "requires {output}")]
    [InlineData("""{ "parser": "naabu-jsonl", "arguments": ["-o", "{output}"] }""", "requires {input}")]
    [InlineData("""{ "parser": "naabu-jsonl", "arguments": ["-l", "{input}", "-o", "{output}"], "parameterArguments": { "extraArgs": ["{value}"] } }""", "not an operation parameter")]
    [InlineData("""{ "parser": "naabu-jsonl", "arguments": ["-l", "{input}", "-o", "{output}", "{rate"] }""", "unbalanced braces")]
    [InlineData("""{ "parser": "generic-jsonl", "arguments": ["-l", "{input}", "-o", "{output}"] }""", "parserOptions are required")]
    public void Invalid_capability_definitions_are_rejected(string capability, string expectedError)
    {
        var errors = ToolManifestLoader.Validate(Parse(Manifest(capability)), Parsing.BuiltInRegistry());
        Assert.Contains(errors, e => e.Contains(expectedError));
    }

    [Fact]
    public void Unknown_manifest_properties_are_rejected_at_load()
    {
        using var dir = new TempDir();
        dir.File("typo.json", """{ "id": "typo", "executable": "x", "capabilites": {} }""");
        var result = ToolManifestLoader.Load([dir.Path], Parsing.BuiltInRegistry());
        Assert.Single(result.Errors);
        Assert.Empty(result.Manifests);
    }
}

public class ArgumentBuilderTests
{
    private static ToolCapabilityDefinition Nmap(string capability) =>
        JsonSerializer.Deserialize<ToolManifest>(File.ReadAllText(Path.Combine(TestPaths.ShippedManifests, "nmap.json")), ToolManifestJson.Options)!.Capabilities[capability];

    private static readonly ArgumentValues Values = new() { Input = "/tmp/job dir/in;put.txt", Output = "/tmp/job dir/out.xml", Rate = 250, Parallelism = 10, TimeoutSeconds = 60 };

    [Fact]
    public void Each_template_element_becomes_exactly_one_argument()
    {
        var argv = ArgumentBuilder.Build(Nmap("port-scan"), Values, new Dictionary<string, string> { ["ports"] = "22,80,8000-8100", ["scanType"] = "connect", ["retries"] = "1" });

        Assert.Equal(
            ["-n", "-Pn", "-T4", "--open", "--max-rate", "250", "-oX", "/tmp/job dir/out.xml", "-iL", "/tmp/job dir/in;put.txt", "-p", "22,80,8000-8100", "-sT", "--max-retries", "1"],
            argv);
    }

    [Theory]
    [InlineData("top-100", new[] { "--top-ports", "100" })]
    [InlineData("top-1000", new[] { "--top-ports", "1000" })]
    [InlineData("443", new[] { "-p", "443" })]
    public void Value_maps_select_arguments_with_prefix_wildcards(string ports, string[] expected)
    {
        var argv = ArgumentBuilder.Build(Nmap("port-scan"), Values, new Dictionary<string, string> { ["ports"] = ports });
        Assert.Equal(expected, argv[^2..]);
    }

    [Fact]
    public void Boolean_maps_add_or_omit_arguments()
    {
        var def = Nmap("service-detection");
        var values = Values with { Ports = "80,443" };
        var on = ArgumentBuilder.Build(def, values, new Dictionary<string, string> { ["grabBanner"] = "true", ["versionIntensity"] = "5" });
        var off = ArgumentBuilder.Build(def, values, new Dictionary<string, string> { ["grabBanner"] = "false" });

        Assert.Contains("banner", on);
        Assert.DoesNotContain("banner", off);
        Assert.Equal("80,443", on[on.IndexOf("-p") + 1]);
        Assert.Equal("5", on[on.IndexOf("--version-intensity") + 1]);
    }

    [Fact]
    public void Injection_strings_stay_single_literal_arguments()
    {
        var def = new ToolCapabilityDefinition
        {
            Parser = "naabu-jsonl",
            Arguments = ["-l", "{input}", "-o", "{output}"],
            ParameterArguments = new Dictionary<string, ParameterArgumentMapping> { ["paths"] = new() { Template = ["-path", "{value}"] } },
        };
        var evil = "/x; rm -rf / $(id) `id` && echo";
        var argv = ArgumentBuilder.Build(def, Values with { Input = "a b;c|d" }, new Dictionary<string, string> { ["paths"] = evil });

        Assert.Equal(["-l", "a b;c|d", "-o", "/tmp/job dir/out.xml", "-path", evil], argv);
    }

    [Fact]
    public void Values_that_look_like_options_are_refused()
    {
        var def = new ToolCapabilityDefinition
        {
            Parser = "naabu-jsonl", Arguments = ["{input}", "{output}"],
            ParameterArguments = new Dictionary<string, ParameterArgumentMapping> { ["ports"] = new() { Template = ["-p", "{value}"] } },
        };
        Assert.Throws<ArgumentException>(() => ArgumentBuilder.Build(def, Values, new Dictionary<string, string> { ["ports"] = "-oX/etc/passwd" }));
    }

    [Fact]
    public void Interface_arguments_only_when_the_job_pins_an_interface()
    {
        var def = Nmap("host-discovery");
        var parameters = new Dictionary<string, string> { ["method"] = "icmp", ["probePorts"] = "22,80" };

        var without = ArgumentBuilder.Build(def, Values, parameters);
        var with = ArgumentBuilder.Build(def, Values with { Interface = "eth1" }, parameters);

        Assert.DoesNotContain("-e", without);
        Assert.Equal(["-e", "eth1"], with[^2..]);
        Assert.Contains("-PS22,80", without);
        Assert.Contains("-PE", without);
    }

    [Fact]
    public void Missing_placeholder_value_fails()
    {
        var def = new ToolCapabilityDefinition { Parser = "nuclei-jsonl", Arguments = ["-t", "{templatesDir}"] };
        Assert.Throws<InvalidOperationException>(() => ArgumentBuilder.Build(def, Values, new Dictionary<string, string>()));
    }

    [Fact]
    public void Endpoints_are_grouped_by_port_set_without_cross_product()
    {
        var targets = new JobTargets
        {
            Endpoints =
            [
                new ScanEndpoint { Address = "10.0.0.1", Port = 22 }, new ScanEndpoint { Address = "10.0.0.1", Port = 80 },
                new ScanEndpoint { Address = "10.0.0.2", Port = 80 }, new ScanEndpoint { Address = "10.0.0.3", Port = 22 },
                new ScanEndpoint { Address = "10.0.0.3", Port = 80 }, new ScanEndpoint { Address = "fd00::1", Port = 443 },
            ],
        };
        var groups = TargetFormatter.GroupByPortSet(targets)
            .Select(g => $"{string.Join(",", TargetFormatter.Lines(g, ToolInputFormat.Hosts))}|{TargetFormatter.Ports(g)}").Order().ToList();

        Assert.Equal(["10.0.0.1,10.0.0.3|22,80", "10.0.0.2|80", "fd00::1|443"], groups);
        Assert.Contains("[fd00::1]:443", TargetFormatter.Lines(targets, ToolInputFormat.Endpoints));
    }

    [Fact]
    public void Url_format_uses_known_schemes()
    {
        var targets = new JobTargets { Endpoints = [new ScanEndpoint { Address = "10.0.0.1", Port = 8443, Scheme = "https" }, new ScanEndpoint { Address = "10.0.0.2", Port = 8080 }] };
        Assert.Equal(["https://10.0.0.1:8443", "10.0.0.2:8080"], TargetFormatter.Lines(targets, ToolInputFormat.Urls));
    }
}
