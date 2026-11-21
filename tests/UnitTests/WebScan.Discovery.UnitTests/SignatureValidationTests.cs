using WebScan.Contracts;
using WebScan.Server.Kernel.Discovery;
using WebScan.Server.Modules.Signatures;
using WebScan.Server.Modules.Signatures.Domain;
using WebScan.Server.Modules.Signatures.Persistence;
using WebScan.Server.Modules.Signatures.Validation;

namespace WebScan.Discovery.UnitTests;

public class SignatureValidationTests
{
    private const string Safe = """
        id: robots-txt
        info:
          name: robots.txt present
          author: test
          severity: info
          tags: tech,discovery
        http:
          - method: GET
            path:
              - "{{BaseURL}}/robots.txt"
            matchers:
              - type: status
                status: [200]
        """;

    [Fact]
    public void Accepts_safe_template()
    {
        var result = NucleiTemplateValidator.Validate(Safe);
        Assert.True(result.Valid, string.Join("; ", result.Errors));
        Assert.Equal("info", result.Severity);
        Assert.Equal(["tech", "discovery"], result.Tags);
        Assert.Equal("robots-txt", result.TemplateId);
        Assert.False(result.RequiresApprovalNote);
    }

    [Fact]
    public void Built_in_signatures_are_valid() =>
        Assert.All(BuiltInSignatures.All, s => Assert.True(SignatureValidator.Validate(s.Kind, s.Content).Valid, s.Id));

    [Theory]
    [InlineData("code:\n  - engine: [sh]\n    source: id\n", "code")]
    [InlineData("headless:\n  - steps: []\n", "headless")]
    [InlineData("javascript:\n  - code: 'x'\n", "javascript")]
    [InlineData("file:\n  - extensions: [all]\n", "file")]
    [InlineData("workflows:\n  - template: x.yaml\n", "workflows")]
    public void Rejects_dangerous_protocols(string section, string name)
    {
        var template = $"id: bad\ninfo:\n  name: bad\n  severity: info\n{section}";
        var result = NucleiTemplateValidator.Validate(template);
        Assert.False(result.Valid);
        Assert.Contains(result.Errors, e => e.Contains($"'{name}'"));
    }

    [Fact]
    public void Rejects_interactsh()
    {
        var result = NucleiTemplateValidator.Validate(Safe.Replace("{{BaseURL}}/robots.txt", "{{BaseURL}}/?u={{interactsh-url}}"));
        Assert.False(result.Valid);
        Assert.Contains(result.Errors, e => e.Contains("interactsh"));
    }

    [Theory]
    [InlineData("intrusive")]
    [InlineData("dos")]
    [InlineData("fuzz")]
    [InlineData("rce")]
    [InlineData("sqli")]
    [InlineData("brute-force")]
    public void Rejects_intrusive_tags(string tag)
    {
        var result = NucleiTemplateValidator.Validate(Safe.Replace("tags: tech,discovery", $"tags: tech,{tag}"));
        Assert.False(result.Valid);
        Assert.Contains(result.Errors, e => e.Contains($"'{tag}'"));
    }

    [Fact]
    public void Rejects_state_changing_methods_and_payloads()
    {
        Assert.False(NucleiTemplateValidator.Validate(Safe.Replace("method: GET", "method: POST")).Valid);
        Assert.False(NucleiTemplateValidator.Validate(Safe.Replace("    matchers:", "    payloads:\n      user: users.txt\n    matchers:")).Valid);
        var raw = Safe.Replace("  - method: GET\n    path:\n      - \"{{BaseURL}}/robots.txt\"", "  - raw:\n      - \"DELETE /api HTTP/1.1\"");
        Assert.Contains("DELETE", raw);
        Assert.Contains(NucleiTemplateValidator.Validate(raw).Errors, e => e.Contains("'DELETE'"));
    }

    [Theory]
    [InlineData("id: x\n", "'info' section is required.")]
    [InlineData("info:\n  name: n\n  severity: info\n", "'id' is required.")]
    [InlineData("id: x\ninfo:\n  severity: info\n", "'info.name' is required.")]
    [InlineData("id: x\ninfo:\n  name: n\n", "'info.severity' is required.")]
    [InlineData("id: x\ninfo:\n  name: n\n  severity: extreme\n", "'info.severity' must be one of")]
    [InlineData("id: [unclosed\n", "Invalid YAML")]
    public void Requires_id_name_and_severity(string template, string error) =>
        Assert.Contains(NucleiTemplateValidator.Validate(template).Errors, e => e.StartsWith(error));

    [Fact]
    public void Severity_above_medium_is_flagged_for_an_approval_note()
    {
        var result = NucleiTemplateValidator.Validate(Safe.Replace("severity: info", "severity: high"));
        Assert.True(result.Valid);
        Assert.True(result.RequiresApprovalNote);
        Assert.Single(result.Warnings);
    }

    [Fact]
    public void Classification_rule_fields_are_whitelisted()
    {
        const string rule = """{ "when": { "field": "http.body", "operator": "Contains", "values": ["x"] }, "outcome": { "classificationTag": "x" } }""";
        var result = SignatureValidator.Validate(SignatureKind.ClassificationRule, rule);
        Assert.False(result.Valid);
        Assert.Contains(result.Errors, e => e.Contains("unknown field 'http.body'"));
    }

    [Fact]
    public void Rule_json_rejects_unknown_members_and_bad_structure()
    {
        Assert.False(SignatureValidator.Validate(SignatureKind.ClassificationRule, """{ "when": { "field": "port", "operator": "Equals", "values": ["80"] }, "script": "x", "outcome": { "classificationTag": "x" } }""").Valid);
        Assert.False(SignatureValidator.Validate(SignatureKind.ClassificationRule, """{ "when": { "field": "port", "operator": "GreaterThan", "values": ["abc"] }, "outcome": { "classificationTag": "x" } }""").Valid);
        Assert.False(SignatureValidator.Validate(SignatureKind.ChangeRule, """{ "changeTypes": ["NewPort"], "when": { "field": "http.title", "operator": "Exists" }, "severity": "low" }""").Valid);
        Assert.True(SignatureValidator.Validate(SignatureKind.ChangeRule, """{ "changeTypes": ["NewPort"], "when": { "field": "port", "operator": "In", "values": ["23"] }, "severity": "low" }""").Valid);
    }

    [Fact]
    public void Condition_evaluator_handles_combinators_and_numbers()
    {
        var o = new DiscoveryObservation
        {
            ObservationId = "x", Kind = ObservationKind.HttpResponse, Address = "10.0.0.1", Port = 8080, ObservedAt = DateTimeOffset.UnixEpoch,
            Source = new ObservationSource { ToolId = "httpx", AgentId = "a", JobId = Guid.Empty },
            Http = new HttpDetails { Url = "http://10.0.0.1:8080/", Scheme = "http", StatusCode = 200, Title = "Router Admin" },
        };
        var e = new ConditionExpression
        {
            All =
            [
                new() { Field = ConditionFields.HttpTitle, Operator = ConditionOperator.Contains, Values = ["admin"] },
                new() { Field = ConditionFields.Port, Operator = ConditionOperator.GreaterThan, Values = ["1024"] },
                new() { Not = new() { Field = ConditionFields.ServiceName, Operator = ConditionOperator.Exists } },
            ],
        };
        Assert.True(ConditionEvaluator.Evaluate(e, o));
        Assert.False(ConditionEvaluator.Evaluate(e, o with { Port = 80 }));
    }

    [Fact]
    public void Bundle_hash_uses_the_shared_byte_format()
    {
        SignatureContent[] items =
        [
            new() { Id = "a", Version = 2, Format = "nuclei-yaml", Content = "x: 1" },
            new() { Id = "b", Version = 1, Format = "nuclei-yaml", Content = "ü" },
        ];
        var expected = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("a\n2\nx: 1\nb\n1\nü\n")));
        Assert.Equal(expected, SignatureHashing.BundleSha256(items));
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", SignatureHashing.BundleSha256([]));
    }
}
