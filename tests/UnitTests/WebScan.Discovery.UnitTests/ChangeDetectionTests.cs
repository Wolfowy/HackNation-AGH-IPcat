using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WebScan.Contracts;
using WebScan.Discovery.UnitTests.Infrastructure;
using WebScan.Server.Kernel.Discovery;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Modules.Discovery.Domain;
using static WebScan.Server.Kernel.Discovery.AssetChangeType;

namespace WebScan.Discovery.UnitTests;

[Collection(DbCollection.Name)]
public class ChangeDetectionTests(TestApp app) : IAsyncLifetime
{
    private readonly Scenario _s = new(app);

    public Task InitializeAsync() => app.ResetAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private static RunCoverage Full(string range) => Scenario.Coverage([range]);

    private static List<AssetChangeType> Types(IEnumerable<ChangeEvent> changes) => changes.Select(c => c.Type).Order().ToList();

    [Fact]
    public async Task New_host_ports_then_service_identified_then_changed()
    {
        var run1 = await _s.RunAsync(Full("10.2.0.0/24"), 3, _s.HostUp("10.2.0.1"), _s.Port("10.2.0.1", 22), _s.Port("10.2.0.1", 3389));
        Assert.Equal([NewHost, NewPort, NewPort], Types(run1));
        var rdp = run1.Single(c => c.Port == 3389);
        Assert.Equal("medium", rdp.Severity); // raised by the seeded change rule
        Assert.Equal(["sensitive-port-exposed@v1"], rdp.RaisedBy);
        Assert.Equal("low", run1.Single(c => c.Port == 22).Severity);

        _s.NextRun();
        var run2 = await _s.RunAsync(Full("10.2.0.0/24"), 3, _s.HostUp("10.2.0.1"), _s.Port("10.2.0.1", 3389),
            _s.Service("10.2.0.1", 22, "ssh", "OpenSSH", "9.6"));
        Assert.Equal([NewService, TechnologyChanged], Types(run2));
        Assert.Equal("ssh OpenSSH 9.6", run2.Single(c => c.Type == NewService).After);

        _s.NextRun();
        var run3 = await _s.RunAsync(Full("10.2.0.0/24"), 3, _s.HostUp("10.2.0.1"), _s.Port("10.2.0.1", 3389),
            _s.Service("10.2.0.1", 22, "ssh", "OpenSSH", "9.7"));
        Assert.Equal([ServiceChanged, TechnologyChanged], Types(run3));
        var changed = run3.Single(c => c.Type == ServiceChanged);
        Assert.Equal(("ssh OpenSSH 9.6", "ssh OpenSSH 9.7"), (changed.Before, changed.After));
        var tech = run3.Single(c => c.Type == TechnologyChanged);
        Assert.Equal(("OpenSSH 9.6", "OpenSSH 9.7"), (tech.Before, tech.After));
    }

    [Fact]
    public async Task Technology_certificate_and_http_changes()
    {
        await _s.RunAsync(Full("10.2.1.0/24"), 3, _s.HostUp("10.2.1.1"), _s.Port("10.2.1.1", 443), _s.Tls("10.2.1.1", 443, "aa11", "shop.lab"),
            _s.Http("10.2.1.1", 443, 200, "Shop", "Apache"), _s.Technology("10.2.1.1", 443, "PHP", "8.1"));

        _s.NextRun();
        var run2 = await _s.RunAsync(Full("10.2.1.0/24"), 3, _s.HostUp("10.2.1.1"), _s.Port("10.2.1.1", 443), _s.Tls("10.2.1.1", 443, "bb22", "shop.lab"),
            _s.Http("10.2.1.1", 443, 200, "Shop v2", "Apache"), _s.Technology("10.2.1.1", 443, "PHP", "8.2"));

        Assert.Equal([TechnologyChanged, TlsCertificateChanged, HttpResponseChanged], Types(run2));
        var tls = run2.Single(c => c.Type == TlsCertificateChanged);
        Assert.StartsWith("CN=shop.lab, sha256 aa11", tls.Before);
        Assert.StartsWith("CN=shop.lab, sha256 bb22", tls.After);
        var http = run2.Single(c => c.Type == HttpResponseChanged);
        Assert.Equal(("200 'Shop' Apache", "200 'Shop v2' Apache"), (http.Before, http.After));
        Assert.Equal(("PHP 8.1", "PHP 8.2"), (run2.Single(c => c.Type == TechnologyChanged).Before, run2.Single(c => c.Type == TechnologyChanged).After));

        _s.NextRun();
        var run3 = await _s.RunAsync(Full("10.2.1.0/24"), 3, _s.HostUp("10.2.1.1"), _s.Port("10.2.1.1", 443), _s.Tls("10.2.1.1", 443, "bb22", "shop.lab"),
            _s.Http("10.2.1.1", 443, 200, "Shop v2", "Apache"), _s.Technology("10.2.1.1", 443, "PHP", "8.2"));
        Assert.Empty(run3);
    }

    [Fact]
    public async Task Port_gone_only_after_threshold_of_covering_complete_runs()
    {
        await _s.RunAsync(Full("10.2.2.0/24"), 2, _s.HostUp("10.2.2.1"), _s.Port("10.2.2.1", 80), _s.Port("10.2.2.1", 8080));

        _s.NextRun();
        Assert.Empty(await _s.RunAsync(Full("10.2.2.0/24"), 2, _s.HostUp("10.2.2.1"), _s.Port("10.2.2.1", 80)));
        var service = await _s.QueryAsync(db => db.Services.SingleAsync(s => s.Port == 8080));
        Assert.Equal((ServiceState.Open, 1), (service.State, service.ConsecutiveMisses));

        _s.NextRun();
        var run3 = await _s.RunAsync(Full("10.2.2.0/24"), 2, _s.HostUp("10.2.2.1"), _s.Port("10.2.2.1", 80));
        Assert.Equal([PortGone], Types(run3));
        Assert.Equal(8080, run3[0].Port);
        Assert.Equal(ServiceState.Gone, (await _s.QueryAsync(db => db.Services.SingleAsync(s => s.Port == 8080))).State);

        _s.NextRun();
        Assert.Empty(await _s.RunAsync(Full("10.2.2.0/24"), 2, _s.HostUp("10.2.2.1"), _s.Port("10.2.2.1", 80)));
    }

    [Fact]
    public async Task Incomplete_uncovered_or_wrong_operation_runs_never_count_as_missing()
    {
        await _s.RunAsync(Full("10.2.3.0/24"), 1, _s.HostUp("10.2.3.1"), _s.Port("10.2.3.1", 80));

        _s.NextRun();
        Assert.Empty(await _s.RunAsync(Scenario.Coverage(["10.2.3.0/24"], complete: false), 1));
        _s.NextRun();
        Assert.Empty(await _s.RunAsync(Full("10.9.0.0/24"), 1));
        _s.NextRun();
        Assert.Empty(await _s.RunAsync(Scenario.Coverage(["10.2.3.0/24"], [ScanOperation.HttpProbe, ScanOperation.TlsProbe]), 1));

        var host = await _s.QueryAsync(db => db.Hosts.SingleAsync());
        Assert.Equal((HostStatus.Active, 0), (host.Status, host.ConsecutiveMisses));
        Assert.Equal(ServiceState.Open, (await _s.QueryAsync(db => db.Services.SingleAsync())).State);

        _s.NextRun();
        var gone = await _s.RunAsync(Full("10.2.3.0/24"), 1);
        Assert.Equal([HostGone], Types(gone)); // its port is closed silently with the host
        Assert.Equal(ServiceState.Gone, (await _s.QueryAsync(db => db.Services.SingleAsync())).State);
    }

    [Fact]
    public async Task Compare_is_idempotent_for_a_retried_step()
    {
        await _s.RunAsync(Full("10.2.4.0/24"), 1, _s.HostUp("10.2.4.1"));
        _s.NextRun();
        Assert.Equal([HostGone], Types(await _s.RunAsync(Full("10.2.4.0/24"), 1)));

        var retry = await app.WithScopeAsync(sp => sp.GetRequiredService<IDiscoveryRunProcessor>().CompareWithPreviousAsync(_s.RunId, 1));
        Assert.Equal(1, retry.ChangesDetected);
        Assert.Equal(1, (await _s.QueryAsync(db => db.Hosts.SingleAsync())).ConsecutiveMisses);
    }

    [Fact]
    public async Task Host_reappears_after_being_gone()
    {
        await _s.RunAsync(Full("10.2.5.0/24"), 1, _s.HostUp("10.2.5.1"));
        _s.NextRun();
        await _s.RunAsync(Full("10.2.5.0/24"), 1, _s.HostDown("10.2.5.1"));
        Assert.Equal(HostStatus.Gone, (await _s.QueryAsync(db => db.Hosts.SingleAsync())).Status);

        _s.NextRun();
        var back = await _s.RunAsync(Full("10.2.5.0/24"), 1, _s.HostUp("10.2.5.1"));
        Assert.Equal([HostReappeared], Types(back));
        Assert.Equal(HostStatus.Active, (await _s.QueryAsync(db => db.Hosts.SingleAsync())).Status);
    }

    [Fact]
    public async Task Flapping_host_is_flagged_unstable_instead_of_producing_noise()
    {
        var events = new List<List<ChangeEvent>>();
        for (var i = 0; i < 7; i++)
        {
            if (i > 0) _s.NextRun();
            events.Add(i % 2 == 0
                ? await _s.RunAsync(Full("10.2.6.0/24"), 1, _s.HostUp("10.2.6.1"))
                : await _s.RunAsync(Full("10.2.6.0/24"), 1));
        }

        Assert.Equal([NewHost], Types(events[0]));
        Assert.Equal([HostGone], Types(events[1]));
        Assert.Equal([HostReappeared], Types(events[2]));
        Assert.Equal([HostGone], Types(events[3]));
        Assert.All(events.Skip(4), Assert.Empty); // 4th transition → unstable → suppressed
        var host = await _s.QueryAsync(db => db.Hosts.SingleAsync());
        Assert.True(host.Unstable);
        Assert.Equal(6, host.StateChangeCount);
        Assert.Equal("UDUDUDU", host.StateHistory);
    }

    [Fact]
    public async Task Time_of_day_variance_is_detected_once_and_suppresses_repeated_http_changes()
    {
        var start = new DateTimeOffset(2026, 11, 10, 0, 0, 0, TimeSpan.Zero);
        var events = new List<List<ChangeEvent>>();
        for (var day = 0; day < 4; day++)
        foreach (var (hour, status, title) in new[] { (3, 503, "Maintenance"), (14, 200, "App") })
        {
            _s.NextRun(TimeSpan.Zero);
            app.Clock.Now = start.AddDays(day).AddHours(hour);
            events.Add(await _s.RunAsync(Full("10.2.7.0/24"), 3, _s.HostUp("10.2.7.1"), _s.Http("10.2.7.1", 80, status, title)));
        }

        Assert.Equal([HttpResponseChanged], Types(events[1])); // first time the afternoon response is seen
        Assert.All(new[] { 2, 3, 4, 6, 7 }, i => Assert.Empty(events[i]));
        var variance = Assert.Single(events[5]); // 6th observation
        Assert.Equal(TimeOfDayVariance, variance.Type);
        Assert.Equal("/ → 03h UTC: 503 'Maintenance'; 14h UTC: 200 'App'", variance.After);
        Assert.True((await _s.QueryAsync(db => db.Services.SingleAsync())).TimeOfDayVariance);
    }

    [Fact]
    public async Task Detection_findings_resolve_after_covering_signature_runs()
    {
        await _s.RunAsync(Full("10.2.8.0/24"), 1, _s.HostUp("10.2.8.1"), _s.Port("10.2.8.1", 80), _s.Signature("10.2.8.1", 80, "exposed-git", "medium"));
        Assert.Equal(FindingStatus.Open, (await _s.QueryAsync(db => db.SignatureMatches.SingleAsync())).Status);

        _s.NextRun();
        await _s.RunAsync(Scenario.Coverage(["10.2.8.0/24"], [ScanOperation.DiscoverHosts, ScanOperation.ScanPorts]), 1, _s.HostUp("10.2.8.1"), _s.Port("10.2.8.1", 80));
        Assert.Equal(FindingStatus.Open, (await _s.QueryAsync(db => db.SignatureMatches.SingleAsync())).Status); // signatures did not run

        _s.NextRun();
        await _s.RunAsync(Full("10.2.8.0/24"), 1, _s.HostUp("10.2.8.1"), _s.Port("10.2.8.1", 80));
        var finding = await _s.QueryAsync(db => db.SignatureMatches.SingleAsync());
        Assert.Equal(FindingStatus.Resolved, finding.Status);
        Assert.Equal(app.Clock.GetUtcNow(), finding.ResolvedAt);
    }
}
