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
        Assert.Equal(["fake", "httpx", "masscan", "naabu", "nerva", "nmap", "nuclei", "tlsx"], result.Manifests.Select(m => m.Manifest.Id).Order());
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
    [InlineData("""{ "parser": "naabu-jsonl", "arguments": ["-l", "{input}", "-o", "{output}", "-p", "{param:ports}"] }""", "only allowed in parameterArguments")]
    [InlineData("""{ "parser": "naabu-jsonl", "arguments": ["-l", "{input}", "-o", "{output}"], "parameterArguments": { "ports": ["{param:secret}"] } }""", "'secret' is not an operation parameter")]
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
    [Fact]
    public void Masscan_sweeps_through_the_job_interface_and_its_gateway()
    {
        var masscan = ToolManifestLoader.Load([TestPaths.ShippedManifests], Parsing.BuiltInRegistry()).Manifests.Single(m => m.Manifest.Id == "masscan").Manifest;
        Assert.True(masscan.RequiresRawSockets);
        Assert.False(masscan.AcceptsHostnames);
        var def = masscan.Capabilities["port-scan"];
        var values = new ArgumentValues { Input = "in", Output = "out", Rate = 5000, Parallelism = 1, Interface = "eth1", Gateway = "172.24.0.1" };

        var argv = ArgumentBuilder.Build(def, values, new Dictionary<string, string> { ["ports"] = "22,80,5672" });
        Assert.Equal(["-iL", "in", "-oX", "out", "--rate", "5000", "--wait", "3", "-p", "22,80,5672", "-e", "eth1", "--router-ip", "172.24.0.1"], argv);
        Assert.Contains("--top-ports", ArgumentBuilder.Build(def, values, new Dictionary<string, string> { ["ports"] = "top-100" }));
    }

    [Theory]
    [InlineData("eth0", "172.27.0.1")] // gateway of a route on the interface
    [InlineData("eth1", "172.24.0.1")] // no route gateway: first address of the subnet (Docker bridges, most LANs)
    [InlineData("eth9", null)]
    public void Gateway_of_an_interface(string nic, string? expected)
    {
        NetworkInterfaceInfo[] interfaces =
        [
            new() { Name = "eth0", Addresses = ["172.27.0.8/16"] },
            new() { Name = "eth1", Addresses = ["fe80::1/64", "172.24.0.8/16"] },
        ];
        RouteInfo[] routes = [new() { Destination = "0.0.0.0/0", Gateway = "172.27.0.1", InterfaceName = "eth0" }, new() { Destination = "172.24.0.0/16", InterfaceName = "eth1" }];
        Assert.Equal(expected, WebScan.Agent.Inventory.NetworkInventory.GatewayFor(nic, interfaces, routes));
    }

    [Fact]
    public void Tools_without_a_rate_limit_get_a_per_thread_delay_that_holds_the_rate_and_count_as_rate_support()
    {
        var tlsx = ToolManifestLoader.Load([TestPaths.ShippedManifests], Parsing.BuiltInRegistry()).Manifests.Single(m => m.Manifest.Id == "tlsx").Manifest;
        var argv = ArgumentBuilder.Build(tlsx.Capabilities["tls-probe"], new ArgumentValues { Input = "in", Output = "out", Rate = 50, Parallelism = 10 }, new Dictionary<string, string>());
        Assert.Equal("200ms", argv[argv.IndexOf("-delay") + 1]); // 10 threads x 1 connection / 200 ms = 50/s
        Assert.Contains("rate", new RegisteredTool(tlsx, "tlsx.json", new string('0', 64), "/usr/bin/tlsx", "1.0").ToDescriptor().SupportedParameters);
    }

    [Fact]
    public void Nerva_fingerprints_endpoints_without_intrusive_probes()
    {
        var nerva = ToolManifestLoader.Load([TestPaths.ShippedManifests], Parsing.BuiltInRegistry()).Manifests.Single(m => m.Manifest.Id == "nerva").Manifest;
        var definition = nerva.Capabilities[ToolCapabilities.ServiceDetection];
        var argv = ArgumentBuilder.Build(definition, new ArgumentValues { Input = "in", Output = "out", Rate = 50, Parallelism = 10 },
            new Dictionary<string, string> { ["versionIntensity"] = "5", ["grabBanner"] = "true" });

        Assert.Equal(["-l", "in", "--json", "-o", "out", "--rate-limit", "50", "--workers", "10", "--timeout", "3000"], argv);
        Assert.DoesNotContain(argv, a => a is "--deep" or "--misconfigs" or "--proxy");
        Assert.Equal(ToolInputFormat.Endpoints, definition.Input.Format);
        // Only rate is supported: a step that sets versionIntensity/grabBanner explicitly keeps nmap.
        Assert.Equal(["rate"], new RegisteredTool(nerva, "nerva.json", new string('0', 64), "/usr/local/bin/nerva", "unknown").ToDescriptor().SupportedParameters);
    }

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
        Assert.Contains("-PE", without);
        Assert.DoesNotContain(without, a => a.StartsWith("-PS", StringComparison.Ordinal)); // icmp means ICMP only
    }

    [Fact]
    public void Tcp_ping_methods_use_the_probe_ports_through_a_parameter_reference()
    {
        var def = Nmap("host-discovery");
        Assert.Contains("-PS22,80", ArgumentBuilder.Build(def, Values, new Dictionary<string, string> { ["method"] = "default", ["probePorts"] = "22,80" }));
        Assert.Contains("-PA443", ArgumentBuilder.Build(def, Values, new Dictionary<string, string> { ["method"] = "tcp-ack", ["probePorts"] = "443" }));
        Assert.Throws<InvalidOperationException>(() => ArgumentBuilder.Build(def, Values, new Dictionary<string, string> { ["method"] = "tcp-syn" }));
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

    [Fact]
    public void Virtual_hosts_are_probed_by_name_with_ip_fallback_and_no_duplicates()
    {
        var targets = new JobTargets
        {
            Endpoints =
            [
                new ScanEndpoint { Address = "203.0.113.7", Port = 443, Hostname = "app.example.com", Scheme = "https" },
                new ScanEndpoint { Address = "203.0.113.7", Port = 443, Hostname = "api.example.com", Scheme = "https" },
                new ScanEndpoint { Address = "203.0.113.8", Port = 443, Hostname = "APP.example.com", Scheme = "https" }, // same name, other address
                new ScanEndpoint { Address = "10.0.0.2", Port = 80, Scheme = "http" },
            ],
        };

        Assert.Equal(["https://app.example.com:443", "https://api.example.com:443", "http://10.0.0.2:80"], TargetFormatter.Lines(targets, ToolInputFormat.Urls));
        Assert.Equal(["app.example.com:443", "api.example.com:443", "10.0.0.2:80"], TargetFormatter.Lines(targets, ToolInputFormat.Endpoints));
        Assert.Equal(["app.example.com", "api.example.com", "10.0.0.2"], TargetFormatter.Lines(targets, ToolInputFormat.Hosts));
        Assert.Equal(["api.example.com,app.example.com|443", "10.0.0.2|80"],
            TargetFormatter.GroupByPortSet(targets).Select(g => $"{string.Join(",", TargetFormatter.Lines(g, ToolInputFormat.Hosts).Order())}|{TargetFormatter.Ports(g)}"));
    }
}
