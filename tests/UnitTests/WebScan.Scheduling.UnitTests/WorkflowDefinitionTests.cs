using System.Text.Json;
using WebScan.Contracts;
using WebScan.Scheduling.UnitTests.Support;
using WebScan.Server.Modules.Workflows.Conditions;
using WebScan.Server.Modules.Workflows.Definitions;
using WebScan.Server.Modules.Workflows.Execution;
using WebScan.Server.Modules.Workflows.Persistence;
using WebScan.Server.Modules.Workflows.Runtime;

namespace WebScan.Scheduling.UnitTests;

public sealed class WorkflowValidatorTests
{
    private static ScanWorkflowDefinition Workflow(params WorkflowStep[] steps) => new() { Key = "test-flow", Name = "Test", Steps = steps };

    private static ConditionExpression Leaf(string field, ConditionOperator op, params string[] values) => new() { Field = field, Operator = op, Values = values };

    [Fact]
    public void Standard_discovery_is_valid_and_survives_a_json_round_trip()
    {
        Assert.Empty(WorkflowValidator.Validate(StandardWorkflows.StandardDiscovery));
        var json = JsonSerializer.Serialize(StandardWorkflows.StandardDiscovery, ContractJson.Options);
        Assert.Empty(WorkflowValidator.Validate(JsonSerializer.Deserialize<ScanWorkflowDefinition>(json, ContractJson.Options)));
    }

    [Fact]
    public void Endpoint_steps_need_a_source_with_ports_also_through_conditions()
    {
        static StepInput From(params string[] steps) => new() { FromSteps = steps };
        var hostsOnly = WorkflowValidator.Validate(Workflow(
            new() { Id = "discover", Operation = ScanOperation.DiscoverHosts },
            new() { Id = "live", Operation = ScanOperation.EvaluateCondition, DependsOn = ["discover"], Input = From("discover") },
            new() { Id = "services", Operation = ScanOperation.DetectService, DependsOn = ["live"], Input = From("live") }));
        Assert.Contains(hostsOnly, e => e.Contains("'services'") && e.Contains("needs endpoints"));

        var alsoBadParameters = WorkflowValidator.Validate(Workflow(
            new() { Id = "discover", Operation = ScanOperation.DiscoverHosts, Parameters = new Dictionary<string, string> { ["probePorts"] = "top-100" } },
            new() { Id = "services", Operation = ScanOperation.DetectService, DependsOn = ["discover"], Input = From("discover") }));
        Assert.Contains(alsoBadParameters, e => e.Contains("probePorts"));
        Assert.Contains(alsoBadParameters, e => e.Contains("needs endpoints")); // reported in the same pass

        var withPorts = WorkflowValidator.Validate(Workflow(
            new() { Id = "ports", Operation = ScanOperation.ScanPorts, Parameters = new Dictionary<string, string> { ["ports"] = "80" } },
            new() { Id = "web", Operation = ScanOperation.EvaluateCondition, DependsOn = ["ports"], Input = From("ports") },
            new() { Id = "http", Operation = ScanOperation.HttpProbe, DependsOn = ["web"], Input = From("web") }));
        Assert.Empty(withPorts);
    }

    [Fact]
    public void Inputs_from_server_steps_and_misplaced_closing_steps_are_rejected()
    {
        var errors = WorkflowValidator.Validate(Workflow(
            new() { Id = "discover", Operation = ScanOperation.DiscoverHosts },
            new() { Id = "persist", Operation = ScanOperation.PersistObservations, DependsOn = ["discover"] },
            new() { Id = "ports", Operation = ScanOperation.ScanPorts, DependsOn = ["persist"], Input = new StepInput { FromSteps = ["persist"] } },
            new() { Id = "publish", Operation = ScanOperation.PublishFinding, DependsOn = ["discover"] },
            new() { Id = "compare", Operation = ScanOperation.ComparePreviousScan, DependsOn = ["ports"] }));

        Assert.Contains(errors, e => e.Contains("'ports' reads input from 'persist'") && e.Contains("produces no observations"));
        Assert.Contains(errors, e => e.Contains("'persist' (PersistObservations) must run after every agent step") && e.Contains("ports"));
        Assert.Contains(errors, e => e.Contains("'publish' (PublishFinding) must run after every agent step"));
        Assert.Contains(errors, e => e.Contains("'publish' (PublishFinding) needs a PersistObservations step before it"));
        Assert.DoesNotContain(errors, e => e.Contains("'compare'")); // after ports, which is after persist
    }

    [Fact]
    public void RecheckMissing_runs_after_every_other_agent_step_and_takes_no_input()
    {
        var errors = WorkflowValidator.Validate(Workflow(
            new() { Id = "discover", Operation = ScanOperation.DiscoverHosts },
            new() { Id = "recheck", Operation = ScanOperation.RecheckMissing, DependsOn = ["discover"], Input = new StepInput { FromSteps = ["discover"] } },
            new() { Id = "ports", Operation = ScanOperation.ScanPorts, DependsOn = ["discover"], Input = new StepInput { FromSteps = ["discover"] } },
            new() { Id = "persist", Operation = ScanOperation.PersistObservations, DependsOn = ["recheck", "ports"] }));
        Assert.Contains(errors, e => e.Contains("'recheck' (RecheckMissing) must run after every other agent step") && e.Contains("ports"));
        Assert.Contains(errors, e => e.Contains("'recheck'") && e.Contains("input is not allowed"));

        var bad = WorkflowValidator.Validate(Workflow(
            new WorkflowStep { Id = "recheck", Operation = ScanOperation.RecheckMissing, Parameters = new Dictionary<string, string> { ["attempts"] = "9" } }));
        Assert.Contains(bad, e => e.Contains("attempts"));
    }

    [Fact]
    public void Cycles_are_rejected()
    {
        var errors = WorkflowValidator.Validate(Workflow(
            new() { Id = "a", Operation = ScanOperation.DiscoverHosts, DependsOn = ["c"] },
            new() { Id = "b", Operation = ScanOperation.PersistObservations, DependsOn = ["a"] },
            new() { Id = "c", Operation = ScanOperation.ComparePreviousScan, DependsOn = ["b"] }));
        Assert.Contains(errors, e => e.Contains("cycle") && e.Contains("a, b, c"));
    }

    [Fact]
    public void Duplicate_ids_unknown_dependencies_and_non_ancestor_inputs_are_rejected()
    {
        var errors = WorkflowValidator.Validate(Workflow(
            new() { Id = "a", Operation = ScanOperation.DiscoverHosts },
            new() { Id = "a", Operation = ScanOperation.DiscoverHosts },
            new() { Id = "b", Operation = ScanOperation.ScanPorts, DependsOn = ["missing"] }));
        Assert.Contains(errors, e => e.Contains("Duplicate step id 'a'"));
        Assert.Contains(errors, e => e.Contains("unknown step 'missing'"));

        errors = WorkflowValidator.Validate(Workflow(
            new() { Id = "a", Operation = ScanOperation.DiscoverHosts },
            new() { Id = "b", Operation = ScanOperation.DiscoverHosts },
            new() { Id = "c", Operation = ScanOperation.ScanPorts, DependsOn = ["a"], Input = new StepInput { FromSteps = ["b"] } }));
        Assert.Contains(errors, e => e.Contains("reads input from 'b'"));
    }

    [Fact]
    public void Bad_parameters_are_rejected()
    {
        var errors = WorkflowValidator.Validate(Workflow(new WorkflowStep
        {
            Id = "a", Operation = ScanOperation.ScanPorts,
            Parameters = new Dictionary<string, string> { ["ports"] = "1-99999", ["rate"] = "0", ["command"] = "rm -rf /" },
        }));
        Assert.Contains(errors, e => e.Contains("Unknown parameter 'command'"));
        Assert.Contains(errors, e => e.Contains("'ports' is not a valid port specification"));
        Assert.Contains(errors, e => e.Contains("'rate' must be >= 1"));
    }

    [Fact]
    public void Conditions_need_known_fields_and_operators_valid_for_the_field_type()
    {
        var steps = new Func<ConditionExpression, ScanWorkflowDefinition>(c => Workflow(
            new() { Id = "a", Operation = ScanOperation.DiscoverHosts },
            new() { Id = "b", Operation = ScanOperation.ScanPorts, DependsOn = ["a"], Input = new StepInput { FromSteps = ["a"], Filter = c } }));

        Assert.Contains(WorkflowValidator.Validate(steps(Leaf("body.raw", ConditionOperator.Equals, "x"))), e => e.Contains("unknown field 'body.raw'"));
        Assert.Contains(WorkflowValidator.Validate(steps(Leaf(ConditionFields.ServiceName, ConditionOperator.GreaterThan, "1"))), e => e.Contains("numeric field"));
        Assert.Contains(WorkflowValidator.Validate(steps(Leaf(ConditionFields.Port, ConditionOperator.Contains, "44"))), e => e.Contains("only valid for text"));
        Assert.Contains(WorkflowValidator.Validate(steps(Leaf(ConditionFields.Port, ConditionOperator.Equals, "https"))), e => e.Contains("not a number"));
        Assert.Contains(WorkflowValidator.Validate(steps(Leaf(ConditionFields.Kind, ConditionOperator.Equals, "Banana"))), e => e.Contains("not a valid kind"));
        Assert.Contains(WorkflowValidator.Validate(steps(Leaf(ConditionFields.Port, ConditionOperator.Exists, "1"))), e => e.Contains("takes no values"));
        Assert.Contains(WorkflowValidator.Validate(steps(new ConditionExpression { Field = ConditionFields.Port, Operator = ConditionOperator.In, Values = [], All = [] })),
            e => e.Contains("exactly one of"));
        Assert.Empty(WorkflowValidator.Validate(steps(Leaf(ConditionFields.HttpStatusCode, ConditionOperator.LessThan, "400"))));
    }

    [Fact]
    public void Passive_fields_dynamic_headers_and_multi_value_contains_are_validated()
    {
        var steps = new Func<ConditionExpression, ScanWorkflowDefinition>(c => Workflow(
            new() { Id = "a", Operation = ScanOperation.DiscoverHosts },
            new() { Id = "b", Operation = ScanOperation.ScanPorts, DependsOn = ["a"], Input = new StepInput { FromSteps = ["a"], Filter = c } }));

        Assert.Empty(WorkflowValidator.Validate(steps(Leaf("http.header.X-Powered-By", ConditionOperator.StartsWith, "PHP", "ASP.NET"))));
        Assert.Empty(WorkflowValidator.Validate(steps(Leaf(ConditionFields.HttpCookieNames, ConditionOperator.In, "PHPSESSID"))));
        Assert.Empty(WorkflowValidator.Validate(steps(Leaf(ConditionFields.TlsSubjectAlternativeNames, ConditionOperator.Contains, ".staging.", ".dev."))));
        Assert.Contains(WorkflowValidator.Validate(steps(Leaf("http.header.", ConditionOperator.Exists))), e => e.Contains("unknown field 'http.header.'"));
        Assert.Contains(WorkflowValidator.Validate(steps(Leaf("http.header.Bad Name", ConditionOperator.Exists))), e => e.Contains("unknown field"));
        Assert.Contains(WorkflowValidator.Validate(steps(Leaf("http.header.a:b", ConditionOperator.Exists))), e => e.Contains("unknown field"));
        Assert.Contains(WorkflowValidator.Validate(steps(Leaf(ConditionFields.HttpTitle, ConditionOperator.Contains))), e => e.Contains("needs at least one value"));
        Assert.Contains(WorkflowValidator.Validate(steps(Leaf(ConditionFields.HttpCookieNames, ConditionOperator.GreaterThan, "1"))), e => e.Contains("numeric field"));
    }

    [Fact]
    public void Condition_depth_is_limited_to_eight()
    {
        var condition = Leaf(ConditionFields.Port, ConditionOperator.Exists);
        for (var i = 0; i < 8; i++) condition = new ConditionExpression { Not = condition };
        var errors = WorkflowValidator.Validate(Workflow(
            new() { Id = "a", Operation = ScanOperation.DiscoverHosts },
            new() { Id = "b", Operation = ScanOperation.ScanPorts, DependsOn = ["a"], Input = new StepInput { FromSteps = ["a"], Filter = condition } }));
        Assert.Contains(errors, e => e.Contains("depth 8"));
    }

    [Fact]
    public void Server_steps_have_no_targets_and_bounds_are_checked()
    {
        var errors = WorkflowValidator.Validate(Workflow(
            new() { Id = "a", Operation = ScanOperation.DiscoverHosts, Retry = new RetryPolicy { MaxAttempts = 0 }, TimeoutSeconds = 0 },
            new() { Id = "p", Operation = ScanOperation.PersistObservations, DependsOn = ["a"], Input = new StepInput { FromSteps = ["a"] }, ToolId = "nmap" },
            new() { Id = "h", Operation = ScanOperation.HttpProbe, DependsOn = ["a"], MaxConcurrency = 5000 }));
        Assert.Contains(errors, e => e.Contains("server step PersistObservations has no targets"));
        Assert.Contains(errors, e => e.Contains("server steps cannot pin a toolId"));
        Assert.Contains(errors, e => e.Contains("HttpProbe needs endpoints"));
        Assert.Contains(errors, e => e.Contains("retry.maxAttempts"));
        Assert.Contains(errors, e => e.Contains("timeoutSeconds"));
        Assert.Contains(errors, e => e.Contains("maxConcurrency"));
    }

    [Fact]
    public void Key_and_step_ids_follow_their_patterns()
    {
        var errors = WorkflowValidator.Validate(new ScanWorkflowDefinition { Key = "Bad Key", Name = "", Steps = [new() { Id = "1st", Operation = ScanOperation.DiscoverHosts }] });
        Assert.Contains(errors, e => e.StartsWith("key", StringComparison.Ordinal));
        Assert.Contains(errors, e => e.StartsWith("name", StringComparison.Ordinal));
        Assert.Contains(errors, e => e.Contains("Step id '1st'"));
    }
}

public sealed class ConditionEvaluatorTests
{
    private static readonly Guid Job = Guid.NewGuid();

    private static ConditionExpression Leaf(string field, ConditionOperator op, params string[] values) => new() { Field = field, Operator = op, Values = values };

    [Fact]
    public void Typed_comparisons_over_observation_fields()
    {
        var https = Observations.Make(Job, ObservationKind.Service, "10.0.0.1", 8443, service: new ServiceDetails { Name = "HTTP", Tunnel = "ssl", Product = "nginx" });

        Assert.True(ConditionEvaluator.Evaluate(Leaf(ConditionFields.Kind, ConditionOperator.Equals, "service"), https));
        Assert.True(ConditionEvaluator.Evaluate(Leaf(ConditionFields.ServiceName, ConditionOperator.In, "http", "https"), https));
        Assert.True(ConditionEvaluator.Evaluate(Leaf(ConditionFields.Port, ConditionOperator.GreaterThan, "1024"), https));
        Assert.False(ConditionEvaluator.Evaluate(Leaf(ConditionFields.Port, ConditionOperator.LessThan, "1024"), https));
        Assert.True(ConditionEvaluator.Evaluate(Leaf(ConditionFields.Port, ConditionOperator.In, "443", "08443"), https)); // numeric equality
        Assert.True(ConditionEvaluator.Evaluate(Leaf(ConditionFields.ServiceProduct, ConditionOperator.StartsWith, "NGI"), https));
        Assert.True(ConditionEvaluator.Evaluate(Leaf(ConditionFields.HttpStatusCode, ConditionOperator.NotExists), https));
        Assert.True(ConditionEvaluator.Evaluate(Leaf(ConditionFields.HttpTitle, ConditionOperator.NotEquals, "x"), https)); // missing ≠ x
        Assert.False(ConditionEvaluator.Evaluate(Leaf(ConditionFields.HttpTitle, ConditionOperator.Contains, "x"), https));
        Assert.True(ConditionEvaluator.Evaluate(Leaf(ConditionFields.ToolId, ConditionOperator.Equals, "fake"), https));
    }

    [Fact]
    public void List_fields_match_any_element_and_headers_are_case_insensitive()
    {
        var http = Observations.Make(Job, ObservationKind.HttpResponse, "10.0.0.1", 443) with
        {
            Http = new HttpDetails
            {
                Url = "https://10.0.0.1/", Scheme = "https", CookieNames = ["lang", "PHPSESSID"], FaviconHash = "-297069493",
                Headers = new Dictionary<string, string> { ["x-powered-by"] = "PHP/8.2.1" },
            },
        };

        Assert.True(ConditionEvaluator.Evaluate(Leaf(ConditionFields.HttpCookieNames, ConditionOperator.In, "phpsessid"), http));
        Assert.True(ConditionEvaluator.Evaluate(Leaf(ConditionFields.HttpCookieNames, ConditionOperator.Equals, "lang"), http));
        Assert.False(ConditionEvaluator.Evaluate(Leaf(ConditionFields.HttpCookieNames, ConditionOperator.NotIn, "PHPSESSID"), http)); // no element may match
        Assert.True(ConditionEvaluator.Evaluate(Leaf(ConditionFields.HttpCookieNames, ConditionOperator.NotEquals, "JSESSIONID"), http));
        Assert.True(ConditionEvaluator.Evaluate(Leaf(ConditionFields.HttpRedirectChain, ConditionOperator.NotExists), http)); // empty list
        Assert.True(ConditionEvaluator.Evaluate(Leaf("http.header.X-Powered-By", ConditionOperator.StartsWith, "ASP", "php/"), http));
        Assert.True(ConditionEvaluator.Evaluate(Leaf(ConditionFields.HttpFaviconHash, ConditionOperator.In, "-297069493"), http));
        Assert.False(ConditionEvaluator.Evaluate(Leaf("http.header.Server", ConditionOperator.Exists), http));
        Assert.False(ConditionEvaluator.Evaluate(Leaf("http.header.Server", ConditionOperator.Exists), Observations.Make(Job, ObservationKind.HostUp, "10.0.0.1", null)));
    }

    [Fact]
    public void Combinators_all_any_not()
    {
        var ssh = Observations.Make(Job, ObservationKind.Service, "10.0.0.1", 22, service: new ServiceDetails { Name = "ssh" });
        var tls = StandardWorkflows.StandardDiscovery.Steps.First(s => s.Id == "tls").When!;
        var http = StandardWorkflows.StandardDiscovery.Steps.First(s => s.Id == "http").When!;

        Assert.False(ConditionEvaluator.Evaluate(tls, ssh));
        Assert.False(ConditionEvaluator.Evaluate(http, ssh));
        Assert.True(ConditionEvaluator.Evaluate(tls, ssh with { Port = 443 }));
        Assert.True(ConditionEvaluator.Evaluate(new ConditionExpression { Not = http }, ssh));
        Assert.True(ConditionEvaluator.Evaluate(new ConditionExpression { All = [] }, ssh));
        Assert.False(ConditionEvaluator.Evaluate(new ConditionExpression { Any = [] }, ssh));
    }
}

public sealed class DagAndInputTests
{
    private static readonly Guid Job = Guid.NewGuid();

    [Fact]
    public void Ready_steps_follow_dependencies_and_failure_policies()
    {
        var def = StandardWorkflows.StandardDiscovery;
        var status = def.Steps.ToDictionary(s => s.Id, _ => StepStatus.Pending);
        Assert.Equal(["discover"], DagScheduler.ReadySteps(def, status).Select(s => s.Id));

        foreach (var id in new[] { "discover", "ports", "services" }) status[id] = StepStatus.Completed;
        Assert.Equal(["http", "tls"], DagScheduler.ReadySteps(def, status).Select(s => s.Id)); // parallel branches

        status["http"] = StepStatus.Failed; // OnFailure = Continue
        status["tls"] = StepStatus.Skipped;
        Assert.Equal(["signatures"], DagScheduler.ReadySteps(def, status).Select(s => s.Id));
        Assert.Null(DagScheduler.FatalFailure(def, status));

        status["ports"] = StepStatus.Failed; // OnFailure = FailWorkflow
        Assert.Equal("ports", DagScheduler.FatalFailure(def, status)?.Id);
    }

    [Fact]
    public void Ancestors_are_transitive()
    {
        var ancestors = DagScheduler.Ancestors(StandardWorkflows.StandardDiscovery.Steps, "persist");
        Assert.Equal(["discover", "http", "ports", "recheck", "services", "signatures", "tls"], ancestors.Order());
    }

    [Fact]
    public void Endpoints_are_derived_with_schemes_and_hosts_from_live_observations()
    {
        var observations = new[]
        {
            Observations.Make(Job, ObservationKind.PortOpen, "10.0.0.1", 80),
            Observations.Make(Job, ObservationKind.Service, "10.0.0.1", 80, service: new ServiceDetails { Name = "http" }),
            Observations.Make(Job, ObservationKind.Service, "10.0.0.2", 8443, service: new ServiceDetails { Name = "unknown", Tunnel = "ssl" }),
            Observations.Make(Job, ObservationKind.HttpResponse, "10.0.0.3", 8080, http: new HttpDetails { Url = "http://10.0.0.3:8080/", Scheme = "HTTP" }),
            Observations.Make(Job, ObservationKind.PortOpen, "10.0.0.4", 22),
            Observations.Make(Job, ObservationKind.HostDown, "10.0.0.9"),
        };

        var endpoints = StepInputs.Endpoints(observations).ToDictionary(e => $"{e.Address}:{e.Port}");
        Assert.Equal(4, endpoints.Count);
        Assert.Equal("http", endpoints["10.0.0.1:80"].Scheme);
        Assert.Equal("https", endpoints["10.0.0.2:8443"].Scheme);
        Assert.Equal("http", endpoints["10.0.0.3:8080"].Scheme);
        Assert.Null(endpoints["10.0.0.4:22"].Scheme);
        Assert.Equal(["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"], StepInputs.Hosts(observations).Order());
    }

    [Fact]
    public void Hostnames_of_observations_stay_in_the_chain_as_hosts_and_virtual_host_endpoints()
    {
        var observations = new[]
        {
            Observations.Make(Job, ObservationKind.HostUp, "203.0.113.7") with { Hostname = "app.example.com" },
            Observations.Make(Job, ObservationKind.PortOpen, "203.0.113.7", 443) with { Hostname = "app.example.com" },
            Observations.Make(Job, ObservationKind.PortOpen, "203.0.113.7", 443) with { Hostname = "api.example.com" },
            Observations.Make(Job, ObservationKind.Service, "203.0.113.7", 443, service: new ServiceDetails { Name = "https" }) with { Hostname = "APP.example.com" },
        };

        Assert.Equal(["203.0.113.7", "api.example.com", "app.example.com"], StepInputs.Hosts(observations).Order());
        Assert.Equal(["api.example.com", "app.example.com"], StepInputs.HostAliases(observations)["203.0.113.7"].Order());
        Assert.Equal(["203.0.113.7"], StepInputs.HostAliases(observations)["app.example.com"]);

        var endpoints = StepInputs.Endpoints(observations).ToDictionary(e => e.Hostname!);
        Assert.Equal(2, endpoints.Count); // one per virtual host, names case-insensitive
        Assert.Equal("https", endpoints["app.example.com"].Scheme);
    }
}
