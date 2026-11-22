using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WebScan.Contracts;
using WebScan.Discovery.UnitTests.Infrastructure;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Kernel.Scanning;
using WebScan.Server.Modules.Discovery.Api;
using WebScan.Server.Modules.Discovery.Domain;

namespace WebScan.Discovery.UnitTests;

/// <summary>RecheckMissing targets and miss accounting, time-of-day visibility, interest scores and the dashboard insights API.</summary>
[Collection(DbCollection.Name)]
public class InsightsTests(TestApp app) : IAsyncLifetime
{
    private readonly Scenario _s = new(app);

    public Task InitializeAsync() => app.ResetAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private Task<RecheckTargets> RecheckTargetsAsync(RunCoverage coverage) =>
        app.WithScopeAsync(sp => sp.GetRequiredService<IRecheckTargetSource>().FindRecheckTargetsAsync(_s.RunId, coverage));

    private Task<Host> HostAsync(string address) => _s.QueryAsync(db => db.Hosts.SingleAsync(h => h.Address == address));

    [Fact]
    public async Task Recheck_targets_known_unobserved_assets_inside_coverage_and_an_answer_is_not_a_miss()
    {
        await _s.RunAsync(Scenario.Coverage(["10.7.0.0/24", "10.8.0.0/24"]), 2,
            _s.HostUp("10.7.0.1"), _s.Port("10.7.0.1", 22), _s.HostUp("10.7.0.2"), _s.Port("10.7.0.2", 80), _s.Port("10.7.0.2", 443),
            _s.HostUp("10.7.0.3"), _s.Port("10.7.0.3", 8080), _s.HostUp("10.8.0.1"), _s.Port("10.8.0.1", 22));

        _s.NextRun();
        var coverage = Scenario.Coverage(["10.7.0.0/24"]); // 10.8.0.0/24 is not part of this run
        await _s.IngestAsync(_s.HostUp("10.7.0.1"), _s.Port("10.7.0.1", 22), _s.Port("10.7.0.2", 80));

        var targets = await RecheckTargetsAsync(coverage);
        Assert.Equal(["10.7.0.3"], targets.Hosts);
        Assert.Equal(["10.7.0.2:443", "10.7.0.3:8080"], targets.Endpoints.Select(e => $"{e.Address}:{e.Port}").Order());
        var incomplete = await RecheckTargetsAsync(coverage with { Complete = false }); // misses would not count anyway
        Assert.Empty(incomplete.Hosts);
        Assert.Empty(incomplete.Endpoints);

        await _s.IngestAsync(_s.HostUp("10.7.0.3"), _s.Port("10.7.0.3", 8080)); // the re-check round answers
        targets = await RecheckTargetsAsync(coverage);
        Assert.Empty(targets.Hosts);
        Assert.Equal(["10.7.0.2:443"], targets.Endpoints.Select(e => $"{e.Address}:{e.Port}"));

        await _s.RunAsync(coverage, 2);
        var answered = await HostAsync("10.7.0.3");
        Assert.Equal((HostStatus.Active, 0, "UU"), (answered.Status, answered.ConsecutiveMisses, answered.StateHistory));
        Assert.Equal(1, await _s.QueryAsync(db => db.Services.Where(s => s.Port == 443).Select(s => s.ConsecutiveMisses).SingleAsync()));
        Assert.Equal(0, (await HostAsync("10.8.0.1")).ConsecutiveMisses); // outside the run: never re-checked, never missed
    }

    [Fact]
    public async Task Unstable_hosts_are_rechecked_first_even_when_gone_or_coverage_is_incomplete()
    {
        await _s.RunAsync(Scenario.Coverage(["10.7.1.0/24"]), 2, _s.HostUp("10.7.1.5"), _s.HostUp("10.7.1.9"), _s.Port("10.7.1.9", 22));
        await _s.QueryAsync(db => db.Hosts.Where(h => h.Address == "10.7.1.9")
            .ExecuteUpdateAsync(s => s.SetProperty(h => h.Unstable, true).SetProperty(h => h.Status, HostStatus.Gone)));

        _s.NextRun();
        var incomplete = await RecheckTargetsAsync(Scenario.Coverage(["10.7.1.0/24"], complete: false));
        Assert.Equal(["10.7.1.9"], incomplete.Hosts);
        Assert.Equal(1, incomplete.UnstableHosts);
        Assert.Equal(["10.7.1.9:22"], incomplete.Endpoints.Select(e => $"{e.Address}:{e.Port}"));

        var complete = await RecheckTargetsAsync(Scenario.Coverage(["10.7.1.0/24"]));
        Assert.Equal(["10.7.1.9", "10.7.1.5"], complete.Hosts); // unstable first
        Assert.Empty((await RecheckTargetsAsync(Scenario.Coverage(["10.9.9.0/24"], complete: false))).Hosts); // not targeted by the run
    }

    [Fact]
    public async Task Hourly_visibility_and_responses_explain_time_of_day_variance()
    {
        var start = new DateTimeOffset(2026, 11, 10, 0, 0, 0, TimeSpan.Zero);
        for (var day = 0; day < 4; day++)
        foreach (var (hour, status, title) in new[] { (3, 503, "Maintenance"), (14, 200, "App") })
        {
            _s.NextRun(TimeSpan.Zero);
            app.Clock.Now = start.AddDays(day).AddHours(hour);
            await _s.RunAsync(Scenario.Coverage(["10.2.7.0/24"]), 3, _s.HostUp("10.2.7.1"), _s.Http("10.2.7.1", 80, status, title));
        }
        _s.NextRun(TimeSpan.Zero);
        app.Clock.Now = start.AddDays(5).AddHours(3);
        await _s.RunAsync(Scenario.Coverage(["10.2.7.0/24"]), 3); // missed at 03h

        var host = await HostAsync("10.2.7.1");
        var detail = await app.Client().GetFromJsonAsync<HostDetailDto>($"/api/assets/hosts/{host.Id}", ContractJson.Options);
        Assert.Equal(24, detail!.HourlyVisibility.Count);
        Assert.Equal((4, 1), (detail.HourlyVisibility[3].Seen, detail.HourlyVisibility[3].Missed));
        Assert.Equal((4, 0), (detail.HourlyVisibility[14].Seen, detail.HourlyVisibility[14].Missed));
        Assert.Equal(0, detail.HourlyVisibility[10].Seen + detail.HourlyVisibility[10].Missed);

        var service = detail.Services.Single();
        Assert.True(service.TimeOfDayVariance);
        Assert.Equal([(3, 4, "503 'Maintenance'"), (14, 4, "200 'App'")], service.HourlyResponses!.Select(h => (h.Hour, h.Seen, h.Response)));
        Assert.Contains("Responds differently by time of day", service.InterestReasons!);
    }

    [Fact]
    public async Task Insights_rank_findings_and_services_count_changes_per_day_and_list_recent_scans()
    {
        await _s.RunAsync(Scenario.Coverage(["10.9.0.0/24"]), 3,
            _s.HostUp("10.9.0.1"), _s.Port("10.9.0.1", 3306), _s.Http("10.9.0.1", 8888, 200, "Admin console"),
            _s.Signature("10.9.0.1", 8888, "exposed-panel", "high"), _s.Signature("10.9.0.1", 8888, "tech-banner", "info"),
            _s.HostUp("10.9.0.2"), _s.Port("10.9.0.2", 80));
        app.RecentScans.Runs.Add(new ScanRunSummary(_s.RunId, "nightly", "Completed", "standard-discovery", app.Clock.GetUtcNow().AddMinutes(-20),
            app.Clock.GetUtcNow().AddMinutes(-15), app.Clock.GetUtcNow(), true));
        app.Clock.Advance(TimeSpan.FromDays(2));

        var insights = await app.Client().GetFromJsonAsync<DashboardInsightsDto>("/api/dashboard/insights?days=7", ContractJson.Options);

        Assert.Equal(["high", "info", "info"], insights!.TopFindings.Select(f => f.Severity)); // classification (admin-panel) is info too
        Assert.Equal("exposed-panel", insights.TopFindings[0].SignatureId);

        var top = insights.TopServices[0];
        Assert.Equal(8888, top.Port);
        Assert.StartsWith("Open high finding: Finding exposed-panel (+1 more)", top.InterestReasons![0]);
        Assert.Contains("Classified as admin-panel", top.InterestReasons);
        Assert.Contains("Web interface on non-standard port 8888", top.InterestReasons);
        Assert.Contains(insights.TopServices, s => s.Port == 3306 && s.InterestReasons!.Contains("MySQL exposed on port 3306"));
        Assert.True(insights.TopServices.Zip(insights.TopServices.Skip(1)).All(p => p.First.InterestScore >= p.Second.InterestScore));

        Assert.Equal(7, insights.ChangesByDay.Count);
        Assert.Equal(app.Clock.GetUtcNow().ToString("yyyy-MM-dd"), insights.ChangesByDay[^1].Date);
        var scanDay = insights.ChangesByDay[^3];
        var changes = await _s.QueryAsync(db => db.Changes.CountAsync());
        Assert.Equal(changes, scanDay.Total);
        Assert.Equal(2, scanDay.ByType["NewHost"]);
        Assert.Equal(changes, insights.ChangesByDay.Sum(d => d.Total));

        var scan = Assert.Single(insights.RecentScans);
        Assert.Equal(((double?)900, (int?)changes), (scan.DurationSeconds, scan.ChangesDetected));
    }

    [Fact]
    public async Task Lists_sort_and_filter_by_interest_and_exports_carry_the_score()
    {
        DiscoveryObservation[] Lab() =>
            [_s.HostUp("10.9.1.1"), _s.Port("10.9.1.1", 80), _s.HostUp("10.9.1.2"), _s.Port("10.9.1.2", 6379), _s.Port("10.9.1.2", 22)];
        await _s.RunAsync(Scenario.Coverage(["10.9.1.0/24"]), 3, Lab());
        _s.NextRun(TimeSpan.FromDays(10));
        await _s.RunAsync(Scenario.Coverage(["10.9.1.0/24"]), 3, Lab()); // no longer new: only the port signals remain
        var client = app.Client();

        var services = await client.GetFromJsonAsync<PagedResult<ServiceDto>>("/api/assets/services?sort=interest", ContractJson.Options);
        Assert.Equal([6379, 22, 80], services!.Items.Select(s => s.Port));
        Assert.Equal(["Redis exposed on port 6379"], services.Items[0].InterestReasons);

        var filtered = await client.GetFromJsonAsync<PagedResult<ServiceDto>>("/api/assets/services?minInterest=10&pageSize=1", ContractJson.Options);
        Assert.Equal((1, 1, 6379), (filtered!.Total, filtered.Items.Count, filtered.Items[0].Port));

        var hosts = await client.GetFromJsonAsync<PagedResult<HostListItemDto>>("/api/assets/hosts?sort=interest", ContractJson.Options);
        Assert.Equal(["10.9.1.2", "10.9.1.1"], hosts!.Items.Select(h => h.Address));
        Assert.Equal(20, hosts.Items[0].InterestScore); // max over services, not their sum

        var csv = await client.GetStringAsync("/api/export/services?format=csv");
        Assert.Contains("interestScore,interestReasons", csv.Split("\r\n")[0]);
        Assert.Contains("Redis exposed on port 6379", csv);
    }
}

public class InterestScorerTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 22, 12, 0, 0, TimeSpan.Zero);
    private static readonly InterestInput Old = new() { FirstSeenAt = Now.AddDays(-60) };

    [Fact]
    public void Quiet_service_scores_zero()
    {
        var score = InterestScorer.Score(Old with { Port = 443, Http = true }, Now);
        Assert.Equal(InterestScore.None.Score, score.Score);
        Assert.Empty(score.Reasons);
    }

    [Fact]
    public void Signals_add_up_with_reasons_ordered_by_weight_and_cap_at_100()
    {
        var score = InterestScorer.Score(Old with
        {
            Port = 8080, Http = true, Findings = [("medium", "Exposed .git")], Classifications = ["staging"],
            VersionedTechnologies = ["nginx 1.18.0"], CertNotAfter = Now.AddDays(10), SelfSigned = true, HostUnstable = true,
        }, Now);
        Assert.Equal(20 + 15 + 5 + 8 + 8 + 5, score.Score);
        Assert.Equal(["Open medium finding: Exposed .git", "Classified as staging (non-production)", "TLS certificate expires in 10 day(s)",
            "Self-signed TLS certificate", "Version disclosed: nginx 1.18.0", "Host is unstable (flapping up/down)"], score.Reasons);

        var max = InterestScorer.Score(Old with
        {
            Port = 2375, Http = true, Findings = [("critical", "RCE"), ("high", "x"), ("high", "y")], Classifications = ["admin-panel", "iot-camera"],
            NewInLastRun = true, CertNotAfter = Now.AddDays(-1), TimeOfDayVariance = true,
        }, Now);
        Assert.Equal(100, max.Score);
        Assert.Equal("Open critical finding: RCE (+2 more)", max.Reasons[0]);
        Assert.Contains("TLS certificate expired on 2026-11-21", max.Reasons);
        Assert.Contains("Classified as iot-camera (device)", max.Reasons);
    }

    [Fact]
    public void Recent_services_and_extra_artifact_signals_count()
    {
        var recent = InterestScorer.Score(new InterestInput { FirstSeenAt = Now.AddDays(-2), Extra = [new(12, "Debug header X-Debug-Token"), new(0, "ignored")] }, Now);
        Assert.Equal(12 + 8, recent.Score);
        Assert.Equal(["Debug header X-Debug-Token", "First seen 2 day(s) ago"], recent.Reasons);
        Assert.Equal(["New in the last scan"], InterestScorer.Score(Old with { NewInLastRun = true }, Now).Reasons);
    }

    [Fact]
    public void Only_open_findings_count()
    {
        var counts = InterestScorer.CountsFinding.Compile();
        SignatureMatch Match(FindingStatus status) => new()
        {
            Address = "10.0.0.1", SignatureId = "s", Name = "n", Severity = "high", Source = "nuclei", ConfidenceMethod = "m", Status = status,
        };
        Assert.True(counts(Match(FindingStatus.Open)));
        Assert.False(counts(Match(FindingStatus.Resolved)));
    }
}
