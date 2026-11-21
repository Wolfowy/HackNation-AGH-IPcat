using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WebScan.Contracts;
using WebScan.Discovery.UnitTests.Infrastructure;
using WebScan.Server.Kernel.Messaging;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Discovery.Api;
using WebScan.Server.Modules.Discovery.Domain;
using Wolverine;

namespace WebScan.Discovery.UnitTests;

[Collection(DbCollection.Name)]
public class IngestionTests(TestApp app) : IAsyncLifetime
{
    private readonly Scenario _s = new(app);

    public Task InitializeAsync() => app.ResetAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Same_batch_twice_is_ingested_once()
    {
        var batchId = Guid.NewGuid();
        DiscoveryObservation[] observations = [_s.HostUp("10.1.0.5"), _s.Port("10.1.0.5", 80), _s.Http("10.1.0.5", 80, 200, "Home")];

        await _s.IngestBatchAsync(batchId, observations);
        await _s.IngestBatchAsync(batchId, observations);

        Assert.Equal(3, await _s.QueryAsync(db => db.Observations.CountAsync()));
        Assert.Equal(1, await _s.QueryAsync(db => db.ProcessedBatches.CountAsync()));
        var snapshot = await _s.QueryAsync(db => db.HttpSnapshots.SingleAsync());
        Assert.Equal(1, snapshot.ObservationCount);
    }

    [Fact]
    public async Task Overlapping_observation_ids_in_a_retried_batch_are_deduplicated()
    {
        var host = _s.HostUp("10.1.0.6");
        var http = _s.Http("10.1.0.6", 8080, 200, "Panel");
        await _s.IngestAsync(host, http);
        await _s.IngestAsync(http, _s.Port("10.1.0.6", 22)); // new batch id, one observation re-sent

        Assert.Equal(3, await _s.QueryAsync(db => db.Observations.CountAsync()));
        Assert.Equal([1, 2], await _s.QueryAsync(db => db.ProcessedBatches.OrderBy(b => b.ObservationsAccepted).Select(b => b.ObservationsAccepted).ToListAsync()));
        Assert.Equal(1, (await _s.QueryAsync(db => db.HttpSnapshots.SingleAsync())).ObservationCount);
        Assert.Equal(2, await _s.QueryAsync(db => db.Services.CountAsync()));
    }

    [Fact]
    public async Task Ingestion_updates_live_state_but_never_marks_anything_gone()
    {
        await _s.RunAsync(Scenario.Coverage(["10.1.1.0/24"]), 1, _s.HostUp("10.1.1.1"), _s.Port("10.1.1.1", 443));

        _s.NextRun();
        await _s.IngestAsync(_s.HostDown("10.1.1.1"), _s.HostUp("::ffff:10.1.1.2", "Web.Lab."), _s.Port("10.1.1.2", 80));

        var hosts = await _s.QueryAsync(db => db.Hosts.OrderBy(h => h.Address).ToListAsync());
        Assert.Equal(["10.1.1.1", "10.1.1.2"], hosts.Select(h => h.Address));
        Assert.All(hosts, h => Assert.Equal(HostStatus.Active, h.Status));
        Assert.Equal(["web.lab"], hosts[1].Hostnames);
        Assert.Equal(app.Clock.GetUtcNow(), hosts[1].LastSeenAt);
        Assert.Equal("lab", hosts[1].Zone);
        Assert.All(await _s.QueryAsync(db => db.Services.ToListAsync()), s => Assert.Equal(ServiceState.Open, s.State));
    }

    [Fact]
    public async Task HostUp_stores_the_latest_normalized_mac_and_vendor_and_keeps_history_in_observations()
    {
        await _s.IngestAsync(_s.HostUpWithMac("10.1.6.1", "aa-bb-cc-dd-ee-0f", " Dell Inc. "));
        var host = await _s.QueryAsync(db => db.Hosts.SingleAsync());
        Assert.Equal(("AA:BB:CC:DD:EE:0F", "Dell Inc."), (host.MacAddress, host.MacVendor));

        // The same MAC on another IP (e.g. a router answering for hosts behind it) never merges hosts; no MAC keeps the last value.
        _s.NextRun();
        await _s.IngestAsync(_s.HostUpWithMac("10.1.6.2", "aabb.ccdd.ee0f"), _s.HostUp("10.1.6.1"), _s.HostUpWithMac("10.1.6.3", "not-a-mac"));
        var hosts = await _s.QueryAsync(db => db.Hosts.OrderBy(h => h.Address).ToListAsync());
        Assert.Equal([("10.1.6.1", "AA:BB:CC:DD:EE:0F", "Dell Inc."), ("10.1.6.2", "AA:BB:CC:DD:EE:0F", null), ("10.1.6.3", null, null)],
            hosts.Select(h => (h.Address, h.MacAddress, h.MacVendor)));

        // A new MAC (randomized/private address, replaced NIC) replaces the value and drops the stale vendor.
        _s.NextRun();
        await _s.IngestAsync(_s.HostUpWithMac("10.1.6.1", "02:00:5e:10:00:01"));
        host = await _s.QueryAsync(db => db.Hosts.SingleAsync(h => h.Address == "10.1.6.1"));
        Assert.Equal(("02:00:5E:10:00:01", (string?)null), (host.MacAddress, host.MacVendor));

        var history = await app.Client(Roles.Viewer).GetFromJsonAsync<PagedResult<ObservationDto>>(
            $"/api/observations?hostId={host.Id}&kind=HostUp", ContractJson.Options);
        Assert.Equal(["02:00:5e:10:00:01", null, "aa-bb-cc-dd-ee-0f"], history!.Items.Select(o => o.Observation.Host!.MacAddress));
    }

    [Fact]
    public async Task Merges_service_facts_from_different_tools_by_confidence()
    {
        await _s.IngestAsync(
            _s.Service("10.1.2.1", 8443, "ssl/http-alt"),
            _s.Service("10.1.2.1", 8443, "https", "nginx", "1.24.0") with { ObservationId = "second" },
            _s.Technology("10.1.2.1", 8443, "Nginx:1.24.0"));

        var service = await _s.QueryAsync(db => db.Services.SingleAsync());
        Assert.Equal(("https", "nginx", "1.24.0", "version-probe"), (service.ServiceName, service.Product, service.Version, service.ConfidenceMethod));
        var tech = await _s.QueryAsync(db => db.Technologies.SingleAsync());
        Assert.Equal(("nginx", "1.24.0", "web-server"), (tech.Name, tech.Version, tech.Category));
        Assert.Equal("tool-reported+version-probe", tech.ConfidenceMethod);
        Assert.Equal(0.92, tech.Confidence); // 1 - 0.2 * 0.4
        Assert.Equal(["nmap", "httpx"], tech.Sources);
    }

    [Fact]
    public async Task Wolverine_handler_ingests_ScanResultBatchReceived()
    {
        var batch = new ScanResultBatch
        {
            BatchId = Guid.NewGuid(), JobId = _s.JobId, LeaseId = Guid.NewGuid(), Sequence = 0, CreatedAt = app.Clock.GetUtcNow(),
            Observations = [_s.HostUp("10.1.3.1")],
        };
        await app.WithScopeAsync(sp => sp.GetRequiredService<IMessageBus>().InvokeAsync(new ScanResultBatchReceived(_s.Context(), batch)));

        Assert.Equal("10.1.3.1", (await _s.QueryAsync(db => db.Hosts.SingleAsync())).Address);
    }

    [Fact]
    public async Task Signature_results_without_a_version_get_the_approved_version()
    {
        var o = _s.Signature("10.1.5.1", 80, "nginx-default-page", "info");
        await _s.IngestAsync(o with { Signature = o.Signature! with { SignatureVersion = null } }, _s.Signature("10.1.5.1", 80, "unknown-template", "low") with
        {
            Signature = o.Signature with { SignatureId = "unknown-template", SignatureVersion = null },
        });

        var matches = await _s.QueryAsync(db => db.SignatureMatches.OrderBy(m => m.SignatureId).ToListAsync());
        Assert.Equal([("nginx-default-page", (int?)1), ("unknown-template", null)], matches.Select(m => (m.SignatureId, m.SignatureVersion)));
        Assert.All(matches, m => Assert.Equal(("nuclei", "signature-match"), (m.Source, m.ConfidenceMethod)));
    }

    [Fact]
    public async Task Raw_observations_are_masked_before_storage()
    {
        await _s.IngestAsync(_s.Signature("10.1.4.1", 80, "token-leak", "low", "Authorization: Bearer secret-token-value-123"));
        var payload = await _s.QueryAsync(db => db.Observations.Select(o => o.Payload).SingleAsync());
        Assert.DoesNotContain("secret-token-value-123", payload);
        Assert.DoesNotContain("secret-token-value-123", (await _s.QueryAsync(db => db.SignatureMatches.SingleAsync())).Evidence);
    }
}
