using Csv = WebScan.Server.Modules.Networks.Csv;
using Microsoft.Extensions.Configuration;
using WebScan.Contracts;
using WebScan.Server.Infrastructure.Http;
using WebScan.Server.Modules.Agents;
using WebScan.Server.Modules.Agents.Persistence;
using WebScan.Server.Modules.Identity.Persistence;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Modules.Networks;
using WebScan.Server.Modules.Networks.Persistence;
using AgentEntity = WebScan.Server.Modules.Agents.Persistence.Agent;

namespace WebScan.Server.UnitTests;

public sealed class ScopeRulesTests
{
    private static readonly ScopeRules Rules = ScopeRules.Create(
        ["10.0.0.0/8", "2001:db8::/32", "example.com", "*.corp.example"], ["10.9.0.0/16", "secret.corp.example"]);

    [Theory]
    [InlineData("10.1.2.3", true)]
    [InlineData("10.1.0.0/16", true)]
    [InlineData("10.0.0.1-10.0.0.255", true)]
    [InlineData("10.9.1.0/24", true)] // exclusions do not block network ranges (subtracted at resolve time)
    [InlineData("11.0.0.0/24", false)]
    [InlineData("9.255.255.255-10.0.0.5", false)]
    [InlineData("2001:db8:1::/48", true)]
    [InlineData("example.com", true)]
    [InlineData("www.example.com", false)] // exact domain entry does not cover subdomains
    [InlineData("app.corp.example", true)]
    [InlineData("corp.example", false)] // wildcard covers subdomains only
    [InlineData("APP.Corp.Example.", true)]
    [InlineData("not valid", false)]
    public void Covers(string entry, bool expected) => Assert.Equal(expected, Rules.Covers(entry));

    [Theory]
    [InlineData("10.1.2.3", true)]
    [InlineData("10.9.0.5", false)]
    [InlineData("10.8.0.0/15", false)] // partially excluded
    [InlineData("secret.corp.example", false)]
    [InlineData("public.corp.example", true)]
    [InlineData("*.corp.example", false)]
    public void IsAuthorized(string target, bool expected) => Assert.Equal(expected, Rules.IsAuthorized(target));

    [Fact]
    public void Empty_policy_authorizes_nothing()
    {
        var empty = ScopeRules.Create([], []);
        Assert.False(empty.Covers("10.0.0.1"));
        Assert.False(empty.IsAuthorized("example.com"));
    }

    [Fact]
    public void Restrict_keeps_covered_entries_clips_partial_ones_and_drops_the_rest()
    {
        var rules = ScopeRules.Create(["10.0.0.0/24", "*.example.com"], []);
        Assert.Equal(["10.0.0.5", "10.0.0.0/24", "a.example.com"],
            rules.Restrict(["10.0.0.5", "10.0.0.0/23", "192.168.0.1", "a.example.com", "b.example.org"]));
    }

    [Fact]
    public void Address_count_subtracts_exclusions_and_counts_hostnames()
    {
        Assert.Equal(256 - 16 + 2, ScopeRules.CountAddresses(["10.0.0.0/24", "a.example.com", "b.example.com"], ["10.0.0.0/28", "x.example.com"]));
        Assert.Equal(1, ScopeRules.CountAddresses(["a.example.com", "b.example.com"], ["b.example.com"]));
        Assert.Equal(long.MaxValue, ScopeRules.CountAddresses(["2001:db8::/32"], []));
    }

    [Fact]
    public void Validation_rejects_invalid_entries_and_wildcards_outside_the_policy()
    {
        var errors = new ValidationErrors();
        ScopeRules.ValidateEntries(errors, "ranges", ["10.0.0.0/24", "10.0.0.0/40", "*.example.com", "bad host!"], allowWildcards: false, required: true);
        Assert.Equal(3, errors.ToDictionary()["ranges"].Length);

        var required = new ValidationErrors();
        ScopeRules.ValidateEntries(required, "ranges", [], allowWildcards: false, required: true);
        Assert.False(required.IsValid);
    }

    [Fact]
    public void Normalize_trims_lowercases_hostnames_and_deduplicates()
    {
        Assert.Equal(["10.0.0.0/24", "app.example.com"], ScopeRules.Normalize([" 10.0.0.0/24 ", "App.Example.COM.", "app.example.com", ""]));
    }
}

public sealed class CsvTests
{
    [Fact]
    public void Parses_quoted_fields_with_separators_quotes_and_line_breaks()
    {
        var rows = Csv.Parse("a,b,c\r\n\"x, y\",\"say \"\"hi\"\"\",\"line1\nline2\"\n\nlast,,\r\n");
        Assert.Equal(3, rows.Count);
        Assert.Equal(["x, y", "say \"hi\"", "line1\nline2"], rows[1]);
        Assert.Equal(["last", "", ""], rows[2]);
    }

    [Fact]
    public void Write_then_parse_round_trips()
    {
        IReadOnlyList<string?>[] rows = [["name", "description"], ["n1", "Office, \"HQ\"\r\nsecond line"], ["n2", " padded "], ["n3", null]];
        var parsed = Csv.Parse(Csv.Write(rows));
        Assert.Equal(rows.Select(r => r.Select(v => v ?? "")), parsed);
    }

    [Fact]
    public void Unterminated_quote_is_a_format_error() => Assert.Throws<FormatException>(() => Csv.Parse("a,\"b"));
}

public sealed class UserLockoutTests
{
    [Fact]
    public void Locks_after_five_failures_and_resets_on_success()
    {
        var now = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
        var user = new User { UserName = "u", NormalizedUserName = "U", DisplayName = "U" };
        for (var i = 0; i < 4; i++) user.RegisterFailedLogin(now);
        Assert.False(user.IsLockedOut(now));

        user.RegisterFailedLogin(now);
        Assert.True(user.IsLockedOut(now.AddMinutes(14)));
        Assert.False(user.IsLockedOut(now.AddMinutes(15)));

        user.RegisterSuccessfulLogin(now.AddMinutes(16));
        Assert.Equal(0, user.FailedLoginCount);
        Assert.Null(user.LockoutEndAt);
        Assert.Equal(now.AddMinutes(16), user.LastLoginAt);
    }
}

public sealed class AgentLogicTests
{
    [Fact]
    public void Effective_limits_are_the_minimum_of_reported_and_override()
    {
        var agent = new AgentEntity
        {
            AgentId = "a1", Hostname = "h", OsPlatform = "linux", OsDescription = "", AgentVersion = "1",
            ReportedMaxConcurrentJobs = 4, ReportedMaxRatePerSecond = 1000, MaxConcurrentJobsOverride = 8, MaxRatePerSecondOverride = 200,
        };
        Assert.Equal(new AgentLimits { MaxConcurrentJobs = 4, MaxRatePerSecond = 200 }, agent.EffectiveLimits);
    }

    [Fact]
    public void Online_requires_flag_and_recent_heartbeat()
    {
        var now = DateTimeOffset.UtcNow;
        var agent = new AgentEntity { AgentId = "a1", Hostname = "h", OsPlatform = "linux", OsDescription = "", AgentVersion = "1", IsOnline = true, LastHeartbeatAt = now.AddSeconds(-60) };
        Assert.True(agent.IsOnlineAt(now, TimeSpan.FromSeconds(90)));
        Assert.False(agent.IsOnlineAt(now.AddSeconds(31), TimeSpan.FromSeconds(90)));
        agent.IsOnline = false;
        Assert.False(agent.IsOnlineAt(now, TimeSpan.FromSeconds(90)));
    }

    [Fact]
    public void Secrets_are_256_bit_and_verified_by_hash()
    {
        var secret = AgentSecrets.NewSecret();
        Assert.Equal(43, secret.Length);
        Assert.True(AgentSecrets.Matches(secret, AgentSecrets.Hash(secret)));
        Assert.False(AgentSecrets.Matches(secret + "x", AgentSecrets.Hash(secret)));
        Assert.False(AgentSecrets.Matches(secret, null));
    }

    [Fact]
    public void Options_accept_arrays_or_comma_separated_lists_with_defaults()
    {
        AgentsOptions Bind(Dictionary<string, string?> values)
        {
            var options = new AgentsOptions();
            AgentsOptions.Bind(options, new ConfigurationBuilder().AddInMemoryCollection(values).Build());
            return options;
        }

        Assert.Equal(["nmap", "naabu", "httpx", "nuclei"], Bind([]).AutoApproveTools);
        Assert.Equal(["nmap", "custom"], Bind(new() { ["Tools:AutoApprove"] = "nmap, custom" }).AutoApproveTools);
        Assert.Empty(Bind(new() { ["Tools:AutoApprove"] = "" }).AutoApproveTools);
        var zones = Bind(new() { ["Agents:BootstrapEnrollmentZones:0"] = "lab", ["Agents:BootstrapEnrollmentZones:1"] = "dmz", ["Agents:HeartbeatTimeoutSeconds"] = "30" });
        Assert.Equal(["lab", "dmz"], zones.BootstrapEnrollmentZones);
        Assert.Equal(30, zones.HeartbeatTimeoutSeconds);
    }

    [Fact]
    public void Registration_validation_rejects_bad_ids_tools_and_limits()
    {
        var registration = new AgentRegistration
        {
            AgentId = "x", Hostname = "h", OsPlatform = "linux", OsDescription = "", AgentVersion = "1",
            Tools = [new ToolDescriptor { Id = "bad tool", Version = "1", Capabilities = ["Port Scan"] }],
            Interfaces = [], Resources = new AgentResources { CpuCores = 1, MemoryTotalMb = 1 },
            Limits = new AgentLimits { MaxConcurrentJobs = 0, MaxRatePerSecond = 1 },
        };
        var errors = AgentApiEndpoints.Validate(registration).ToDictionary();
        Assert.Contains("agentId", errors.Keys);
        Assert.Equal(2, errors["tools"].Length);
        Assert.Contains("limits", errors.Keys);
    }
}

public sealed class AgentSubnetsTests
{
    private static AgentSnapshot Agent(string id, string zone, string? connectedFrom, NetworkInterfaceInfo[] interfaces, RouteInfo[]? routes = null) => new()
    {
        AgentId = id, Status = AgentStatus.Active, IsOnline = true, ApprovedTools = [], Interfaces = interfaces, Routes = routes ?? [],
        AuthorizedZones = [zone], ConnectedFrom = connectedFrom, Limits = new AgentLimits { MaxConcurrentJobs = 4, MaxRatePerSecond = 1000 },
    };

    private static NetworkInterfaceInfo Nic(string name, params string[] addresses) => new() { Name = name, Addresses = addresses };

    [Fact]
    public void Interface_subnets_become_proposals_and_noise_is_skipped()
    {
        // Docker-style lab agents: eth0 = link to the server (management), eth1 = scanned network. Both see the same lab subnet.
        var lab1 = Agent("agent-1", "lab", "172.23.0.7", [Nic("eth0", "172.23.0.7/16"), Nic("eth1", "172.30.0.100/24")]);
        var lab2 = Agent("agent-2", "lab", "172.23.0.5", [Nic("eth0", "172.23.0.5/16"), Nic("eth1", "172.30.0.101/24")]);
        // Laptop: one LAN, link-local/VPN noise, a /32 tunnel; the server is reached through Docker NAT (not the LAN).
        var home = Agent("home-agent", "home", "192.168.65.1",
            [Nic("en8", "fe80::1/64", "10.250.169.79/20", "2001:db8::5/64"), Nic("utun0", "fe80::2/64"), Nic("utun9", "10.8.0.2/32"), Nic("lo0", "127.0.0.1/8")]);
        var rules = ScopeRules.Create(["10.250.169.0/24", "172.30.0.0/16", "172.23.0.0/16"], []);

        var subnets = AgentSubnets.Suggest([lab1, lab2, home], [], rules);

        Assert.Equal(["10.250.160.0/20", "172.23.0.0/16", "172.30.0.0/24"], subnets.Select(s => s.Cidr));
        var lan = subnets[0];
        Assert.Equal(("home", "interface", "partial", 4096L), (lan.Zone, lan.Source, lan.Scope, lan.AddressCount));
        Assert.Equal(["10.250.169.0/24"], lan.ProposedRanges);
        Assert.False(lan.Management); // single subnet: the LAN the agent is there to scan

        var management = subnets[1];
        Assert.True(management.Management);
        Assert.False(management.Large); // exactly /16 is not flagged

        var lab = subnets[2];
        Assert.Equal(["agent-1", "agent-2"], lab.SeenBy.Select(s => s.AgentId));
        Assert.Equal("full", lab.Scope);
        Assert.False(lab.Management);
    }

    [Fact]
    public void Existing_networks_and_policy_shape_the_proposed_ranges()
    {
        var home = Agent("home-agent", "home", null, [Nic("en0", "192.168.1.20/24"), Nic("en1", "172.16.0.5/12")],
            [new RouteInfo { Destination = "10.20.0.0/16", Gateway = "192.168.1.1", InterfaceName = "en0" },
             new RouteInfo { Destination = "10.30.0.0/16", Gateway = "0.0.0.0", InterfaceName = "en0" },
             new RouteInfo { Destination = "0.0.0.0/0", Gateway = "192.168.1.1", InterfaceName = "en0" }]);
        var networks = new List<Network>
        {
            new() { Name = "home-dhcp", Zone = "home", Ranges = ["192.168.1.0/26", "printer.local"] },
            new() { Name = "other-zone", Zone = "lab", Ranges = ["192.168.1.0/24"] },
        };
        var rules = ScopeRules.Create(["192.168.1.0/24"], []);

        var subnets = AgentSubnets.Suggest([home], networks, rules).ToDictionary(s => s.Cidr);

        Assert.Equal(["home-dhcp"], subnets["192.168.1.0/24"].ExistingNetworks); // other zones are other address spaces
        Assert.Equal(["192.168.1.64/26", "192.168.1.128/25"], subnets["192.168.1.0/24"].ProposedRanges);
        Assert.True(subnets["172.16.0.0/12"].Large);
        Assert.Equal("none", subnets["172.16.0.0/12"].Scope);
        Assert.Empty(subnets["172.16.0.0/12"].ProposedRanges);
        // Gateway routes are a second level of breadth; on-link routes and the default route are not.
        Assert.Equal("route", subnets["10.20.0.0/16"].Source);
        Assert.Equal("192.168.1.1", subnets["10.20.0.0/16"].SeenBy.Single().Gateway);
        Assert.False(subnets.ContainsKey("10.30.0.0/16"));
        Assert.Equal(3, subnets.Count);
    }

    [Fact]
    public void Agents_without_a_single_zone_need_a_zone_choice()
    {
        var multi = Agent("edge", "dmz", null, [Nic("eth0", "10.1.0.5/24")]) with { AuthorizedZones = ["dmz", "corp"] };
        var none = Agent("new", "x", null, [Nic("eth0", "10.2.0.5/24")]) with { AuthorizedZones = [] };

        var subnet = Assert.Single(AgentSubnets.Suggest([multi, none], [], ScopeRules.Create(["10.0.0.0/8"], [])));

        Assert.Null(subnet.Zone);
        Assert.Equal(["corp", "dmz"], subnet.CandidateZones);
    }
}
