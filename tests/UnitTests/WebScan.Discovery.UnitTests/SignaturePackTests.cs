using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using WebScan.Contracts;
using WebScan.Discovery.UnitTests.Infrastructure;
using WebScan.Server.Kernel.Discovery;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Signatures;
using WebScan.Server.Modules.Signatures.Domain;
using WebScan.Server.Modules.Signatures.Persistence;
using WebScan.Server.Modules.Signatures.Validation;

namespace WebScan.Discovery.UnitTests;

public class PassiveRuleFieldTests
{
    private static DiscoveryObservation Http(HttpDetails http, string? hostname = null) => new()
    {
        ObservationId = "x", Kind = ObservationKind.HttpResponse, Address = "10.0.0.1", Port = 443, Hostname = hostname, ObservedAt = DateTimeOffset.UnixEpoch,
        Source = new ObservationSource { ToolId = "httpx", AgentId = "a", JobId = Guid.Empty }, Http = http,
    };

    private static ConditionExpression Leaf(string field, ConditionOperator op, params string[] values) => new() { Field = field, Operator = op, Values = values };

    [Fact]
    public void Dynamic_headers_lists_and_multi_value_operators()
    {
        var o = Http(new HttpDetails
        {
            Url = "https://10.0.0.1/admin", Scheme = "https", Title = "Router Admin", CookieNames = ["pma_lang", "phpMyAdmin"],
            RedirectChain = ["https://10.0.0.1/", "https://10.0.0.1/login"], FinalUrl = "https://10.0.0.1/login", ContentType = "text/html",
            Headers = new Dictionary<string, string> { ["X-Jenkins"] = "2.401.3", ["server"] = "nginx" }, Technologies = ["Nginx:1.25", "PHP"],
        });

        Assert.True(ConditionEvaluator.Evaluate(Leaf("http.header.x-jenkins", ConditionOperator.Exists), o));
        Assert.Equal("2.401.3", ConditionEvaluator.GetField(o, "http.header.X-JENKINS"));
        Assert.True(ConditionEvaluator.Evaluate(Leaf("http.header.Server", ConditionOperator.Equals, "NGINX"), o));
        Assert.True(ConditionEvaluator.Evaluate(Leaf("http.header.X-Powered-By", ConditionOperator.NotExists), o));
        Assert.True(ConditionEvaluator.Evaluate(Leaf(ConditionFields.HttpCookieNames, ConditionOperator.In, "phpmyadmin"), o));
        Assert.False(ConditionEvaluator.Evaluate(Leaf(ConditionFields.HttpCookieNames, ConditionOperator.NotIn, "phpMyAdmin", "x"), o));
        Assert.True(ConditionEvaluator.Evaluate(Leaf(ConditionFields.HttpRedirectChain, ConditionOperator.Contains, "/signin", "/login"), o));
        Assert.True(ConditionEvaluator.Evaluate(Leaf(ConditionFields.HttpTechnologies, ConditionOperator.StartsWith, "nginx"), o));
        Assert.True(ConditionEvaluator.Evaluate(Leaf(ConditionFields.HttpTitle, ConditionOperator.Contains, "foo", "admin"), o));
        Assert.True(ConditionEvaluator.Evaluate(Leaf(ConditionFields.HttpUrl, ConditionOperator.Contains, "/admin"), o));
        Assert.True(ConditionEvaluator.Evaluate(Leaf(ConditionFields.HttpContentType, ConditionOperator.StartsWith, "text/"), o));
        Assert.True(ConditionEvaluator.Evaluate(Leaf(ConditionFields.TlsSubjectAlternativeNames, ConditionOperator.NotExists), o));
        Assert.Equal("pma_lang, phpMyAdmin", ConditionEvaluator.GetField(o, ConditionFields.HttpCookieNames));

        var banner = o with { Kind = ObservationKind.Service, Http = null, Service = new ServiceDetails { Name = "ftp", Banner = "220 MikroTik FTP server ready" } };
        Assert.True(ConditionEvaluator.Evaluate(Leaf(ConditionFields.ServiceBanner, ConditionOperator.Contains, "mikrotik"), banner));
        Assert.False(ConditionEvaluator.Evaluate(Leaf("http.header.Server", ConditionOperator.Exists), banner));
    }

    [Fact]
    public void Validator_accepts_header_tokens_and_list_fields_only()
    {
        Assert.Empty(ConditionEvaluator.Validate(Leaf("http.header.X-AspNet-Version", ConditionOperator.Exists)));
        Assert.Empty(ConditionEvaluator.Validate(Leaf(ConditionFields.HttpCookieNames, ConditionOperator.In, "a", "b")));
        Assert.Empty(ConditionEvaluator.Validate(Leaf(ConditionFields.HttpTitle, ConditionOperator.Contains, "a", "b")));
        Assert.NotEmpty(ConditionEvaluator.Validate(Leaf("http.header.", ConditionOperator.Exists)));
        Assert.NotEmpty(ConditionEvaluator.Validate(Leaf("http.header.X Y", ConditionOperator.Exists)));
        Assert.NotEmpty(ConditionEvaluator.Validate(Leaf("http.header.X:Y", ConditionOperator.Exists)));
        Assert.NotEmpty(ConditionEvaluator.Validate(Leaf("http.headers", ConditionOperator.Exists)));
        Assert.NotEmpty(ConditionEvaluator.Validate(Leaf(ConditionFields.HttpTitle, ConditionOperator.Contains)));
        Assert.True(SignatureValidator.Validate(SignatureKind.ClassificationRule,
            """{ "when": { "field": "http.header.X-Jenkins", "operator": "Exists" }, "outcome": { "technology": { "name": "Jenkins", "versionField": "http.header.X-Jenkins" } } }""").Valid);
        Assert.False(SignatureValidator.Validate(SignatureKind.ClassificationRule,
            """{ "when": { "field": "http.title", "operator": "Exists" }, "outcome": { "technology": { "name": "X", "versionField": "http.header.a b" } } }""").Valid);
        // Change events carry no HTTP data: the new fields stay unavailable to change rules.
        Assert.False(SignatureValidator.Validate(SignatureKind.ChangeRule,
            """{ "changeTypes": ["NewPort"], "when": { "field": "http.header.Server", "operator": "Exists" }, "severity": "low" }""").Valid);
    }
}

public class SignaturePackContentTests
{
    private static readonly IReadOnlyList<SignaturePack> Packs = SignaturePacks.LoadEmbedded();

    private static readonly string[] ExcludedTags =
    [
        "intrusive", "vuln", "unauth", "exposure", "default-login", "oast", "rce", "lfi", "sqli", "xss", "dos", "fuzz", "bruteforce", "cve",
        "exploit", "takeover", "ssrf", "ssti", "xxe", "rfi", "traversal", "injection", "auth-bypass", "c2",
    ];

    private static SignaturePack Pack(string name) => Packs.Single(p => p.Name == name);

    [Fact]
    public void Every_shipped_signature_passes_the_validator_and_carries_the_pack_tag()
    {
        Assert.Equal(["nuclei-safe", "webscan-default"], Packs.Select(p => p.Name).Order());
        var ids = Packs.SelectMany(p => p.Signatures).Select(s => s.Id).ToList();
        Assert.Equal(ids.Count, ids.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Empty(ids.Intersect(BuiltInSignatures.All.Select(b => b.Id), StringComparer.OrdinalIgnoreCase));
        foreach (var pack in Packs)
        foreach (var s in pack.Signatures)
        {
            var v = SignatureValidator.Validate(s.Kind, s.Content);
            Assert.True(v.Valid, $"{s.Id}: {string.Join("; ", v.Errors)}");
            Assert.Contains(pack.Tag, v.Tags);
            Assert.Matches(Signature.IdPattern, s.Id);
        }
    }

    [Fact]
    public void Nuclei_pack_is_curated_passive_and_small_enough_for_job_bundles()
    {
        var pack = Pack("nuclei-safe");
        Assert.Equal("v10.5.2", pack.Version);
        Assert.InRange(pack.Signatures.Count, 300, 600);
        foreach (var s in pack.Signatures)
        {
            var v = NucleiTemplateValidator.Validate(s.Content);
            Assert.Equal(s.Id, v.TemplateId);
            Assert.Contains(v.Severity, new[] { "info", "low" });
            Assert.Empty(v.Tags.Intersect(ExcludedTags));
            Assert.DoesNotContain("method: OPTIONS", s.Content, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("# digest:", s.Content);
        }

        var json = JsonSerializer.Serialize(pack.Signatures.Select(s => new SignatureContent { Id = s.Id, Version = 1, Format = "nuclei-yaml", Content = s.Content }),
            ContractJson.Options);
        Assert.True(json.Length < 1024 * 1024, $"bundle is {json.Length} bytes");
        Assert.Contains("Packs/nuclei-safe/LICENSE.md", typeof(SignaturePacks).Assembly.GetManifestResourceNames().Select(n => n.Replace('\\', '/')));
    }

    [Fact]
    public void Default_rules_classify_typical_observations_and_ignore_plain_ones()
    {
        var rules = Pack("webscan-default").Signatures.ToDictionary(s => s.Id, s =>
        {
            Assert.True(SignatureValidator.TryParse<ClassificationRuleDocument>(s.Content, out var doc, out _));
            Assert.NotNull(doc!.Outcome!.Confidence);
            return doc;
        });
        IEnumerable<string> Matches(DiscoveryObservation o) => rules.Where(r => ConditionEvaluator.Evaluate(r.Value.When!, o)).Select(r => r.Key).Order();

        var source = new ObservationSource { ToolId = "httpx", AgentId = "a", JobId = Guid.Empty };
        DiscoveryObservation Http(HttpDetails? http = null, string? hostname = null) => new()
        {
            ObservationId = "x", Kind = ObservationKind.HttpResponse, Address = "10.0.0.5", Port = 443, Hostname = hostname, ObservedAt = DateTimeOffset.UnixEpoch,
            Source = source, Http = (http ?? new HttpDetails { Url = "https://10.0.0.5/", Scheme = "https" }) with { Url = "https://10.0.0.5/", Scheme = "https" },
        };

        Assert.Empty(Matches(Http(new HttpDetails { Url = "", Scheme = "", Title = "Welcome", WebServer = "nginx" }, "www.example.com")));
        Assert.Empty(Matches(Http(hostname: "devices.example.com")));
        Assert.Equal(["webscan-staging-environment"], Matches(Http(hostname: "shop.staging.example.com")));
        Assert.Equal(["webscan-staging-environment"], Matches(Http(hostname: "uat-api.example.com")));
        Assert.Equal(["webscan-staging-environment"], Matches(Http() with
        {
            Kind = ObservationKind.TlsCertificate, Http = null, Tls = new TlsDetails { SubjectCommonName = "www.example.com", SubjectAlternativeNames = ["www.example.com", "qa.example.com"] },
        }));
        Assert.Equal(["webscan-jenkins"], Matches(Http(new HttpDetails { Url = "", Scheme = "", Headers = new Dictionary<string, string> { ["x-jenkins"] = "2.401.3" } })));
        Assert.Equal(["webscan-phpmyadmin"], Matches(Http(new HttpDetails { Url = "", Scheme = "", CookieNames = ["pma_lang", "phpMyAdmin"] })));
        Assert.Equal(["webscan-hikvision"], Matches(Http(new HttpDetails { Url = "", Scheme = "", WebServer = "App-webs/" })));
        Assert.Equal(["webscan-wordpress"], Matches(Http(new HttpDetails { Url = "", Scheme = "", CookieNames = ["wordpress_test_cookie"] })));
        Assert.Equal(["webscan-admin-path", "webscan-login-page"], Matches(Http(new HttpDetails
        {
            Url = "", Scheme = "", StatusCode = 200, RedirectChain = ["https://10.0.0.5/admin/"], FinalUrl = "https://10.0.0.5/admin/login.php",
        })));
        Assert.Equal(["webscan-mikrotik"], Matches(Http() with { Kind = ObservationKind.Service, Port = 21, Http = null, Service = new ServiceDetails { Name = "ftp", Banner = "220 MikroTik FTP server (MikroTik 6.48) ready" } }));
    }
}

[Collection(DbCollection.Name)]
public class SignaturePackSeedingTests(TestApp app) : IAsyncLifetime
{
    public Task InitializeAsync() => app.ResetAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private Task<PackSeedResult> SeedAsync(SignaturePack pack) =>
        app.WithScopeAsync(sp => SignaturePacks.SeedAsync(sp.GetRequiredService<SignaturesDbContext>(), pack, app.Clock.GetUtcNow(), NullLogger.Instance));

    private static PackSignature Rule(string id, string title) => new(id, $"Rule {id}", SignatureKind.ClassificationRule,
        $$"""{ "when": { "field": "http.title", "operator": "Contains", "values": ["{{title}}"] }, "outcome": { "classificationTag": "x" }, "tags": ["pack-test"] }""");

    private Task<SignatureDetailDto?> GetAsync(string id) => app.Client(Roles.Viewer).GetFromJsonAsync<SignatureDetailDto>($"/api/signatures/{id}", ContractJson.Options);

    [Fact]
    public async Task Shipped_packs_seed_as_approved_and_reseeding_changes_nothing()
    {
        foreach (var pack in SignaturePacks.LoadEmbedded())
        {
            Assert.Equal(new PackSeedResult(pack.Signatures.Count, 0, 0, 0, 0, 0), await SeedAsync(pack));
            Assert.Equal(new PackSeedResult(0, 0, 0, pack.Signatures.Count, 0, 0), await SeedAsync(pack));
        }

        var nuclei = SignaturePacks.LoadEmbedded().Single(p => p.Name == "nuclei-safe");
        var bundle = await app.WithScopeAsync(sp => sp.GetRequiredService<ISignatureCatalog>().GetApprovedBundleAsync([], ["pack-nuclei-safe"], ["info", "low"]));
        Assert.Equal(nuclei.Signatures.Count, bundle.Items.Count);
        var rules = await app.WithScopeAsync(sp => sp.GetRequiredService<IInterpretationRuleProvider>().GetApprovedClassificationRulesAsync());
        Assert.Contains(rules, r => r.SignatureId == "webscan-jenkins" && r.Outcome.TechnologyVersionField == "http.header.X-Jenkins");
        var detail = await GetAsync("webscan-jenkins");
        Assert.Equal((SignatureStatus.Approved, 1, "pack:webscan-default"), (detail!.Status, detail.ApprovedVersion, detail.Versions[0].ApprovedBy));
    }

    [Fact]
    public async Task Pack_updates_are_versioned_and_never_override_admin_decisions()
    {
        var v1 = new SignaturePack("test", "1", "pack-test", [Rule("pt-a", "alpha"), Rule("pt-b", "beta"), Rule("pt-c", "gamma")]);
        Assert.Equal(new PackSeedResult(3, 0, 0, 0, 0, 0), await SeedAsync(v1));

        // Admin retires pt-b and edits pt-c: the pack must leave both alone from now on.
        Assert.Equal(HttpStatusCode.OK, (await app.Client(Roles.Manager).PostAsync("/api/signatures/pt-b/retire", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await app.Client(Roles.Manager).PostAsJsonAsync("/api/signatures/pt-c/versions",
            new { content = Rule("pt-c", "gamma-admin").Content }, ContractJson.Options)).StatusCode);

        var v2 = new SignaturePack("test", "2", "pack-test",
            [Rule("pt-a", "alpha-2"), Rule("pt-b", "beta-2"), Rule("pt-c", "gamma-2"), Rule("pt-d", "delta"), new("pt-bad", "Bad", SignatureKind.ClassificationRule, "{}")]);
        Assert.Equal(new PackSeedResult(Created: 1, Updated: 1, Retired: 0, Unchanged: 0, Skipped: 2, Invalid: 1), await SeedAsync(v2));
        Assert.Equal(new PackSeedResult(0, 0, 0, 2, 2, 1), await SeedAsync(v2));

        var a = await GetAsync("pt-a");
        Assert.Equal((SignatureStatus.Approved, 2, 2), (a!.Status, a.ApprovedVersion, a.LatestVersion));
        Assert.Contains("alpha-2", a.Versions[1].Content);
        Assert.Equal(SignatureStatus.Retired, (await GetAsync("pt-b"))!.Status);
        Assert.Equal((1, 2), ((await GetAsync("pt-c"))!.ApprovedVersion, (await GetAsync("pt-c"))!.LatestVersion));
        Assert.Equal(HttpStatusCode.NotFound, (await app.Client(Roles.Viewer).GetAsync("/api/signatures/pt-bad")).StatusCode);

        // Dropped from the pack: retired (pt-a); signatures the pack no longer owns stay as they are.
        var v3 = new SignaturePack("test", "3", "pack-test", [Rule("pt-d", "delta")]);
        Assert.Equal(new PackSeedResult(0, 0, Retired: 1, Unchanged: 1, 0, 0), await SeedAsync(v3));
        Assert.Equal(SignatureStatus.Retired, (await GetAsync("pt-a"))!.Status);
        Assert.Equal(SignatureStatus.Approved, (await GetAsync("pt-c"))!.Status);
    }
}
