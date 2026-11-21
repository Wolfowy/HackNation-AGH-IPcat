using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using WebScan.Contracts;
using WebScan.Scheduling.UnitTests.Support;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Scanning.Api;
using WebScan.Server.Modules.Scanning.Events;
using WebScan.Server.Modules.Scanning.Planning;
using WebScan.Server.Modules.Workflows.Api;
using WebScan.Server.Modules.Workflows.Definitions;

namespace WebScan.Scheduling.UnitTests;

[Collection(DbCollection.Name)]
public sealed class ApiTests(TestHost host) : DbTestBase(host)
{
    private static JsonContent Json<T>(T value) => JsonContent.Create(value, options: ContractJson.Options);

    [Fact]
    public async Task Operations_expose_catalog_and_effective_capability_mapping()
    {
        var body = await Host.UserClient(Roles.Viewer).GetFromJsonAsync<JsonElement>("/api/operations");
        Assert.Equal(10, body.GetProperty("operations").GetArrayLength());
        Assert.Equal("port-scan", body.GetProperty("capabilityMapping").GetProperty("ScanPorts").GetString());
        Assert.False(body.GetProperty("capabilityMapping").TryGetProperty("PersistObservations", out _));
    }

    [Fact]
    public async Task Workflow_definitions_are_versioned_validated_and_role_protected()
    {
        var key = $"api-{Guid.NewGuid():N}"[..16];
        var definition = new ScanWorkflowDefinition { Key = key, Name = "API flow", Steps = [new() { Id = "discover", Operation = ScanOperation.DiscoverHosts }] };
        var manager = Host.UserClient(Roles.Manager);

        Assert.Equal(HttpStatusCode.Forbidden, (await Host.UserClient(Roles.Editor).PostAsync("/api/workflows", Json(definition))).StatusCode);
        var created = await manager.PostAsync("/api/workflows", Json(definition));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.Equal(1, (await created.Content.ReadFromJsonAsync<WorkflowVersionDto>(ContractJson.Options))!.Version);
        Assert.Equal(HttpStatusCode.Conflict, (await manager.PostAsync("/api/workflows", Json(definition))).StatusCode);

        var v2 = definition with { Name = "API flow v2", Steps = [.. definition.Steps, new() { Id = "persist", Operation = ScanOperation.PersistObservations, DependsOn = ["discover"] }] };
        Assert.Equal(HttpStatusCode.Created, (await manager.PostAsync($"/api/workflows/{key}/versions", Json(v2))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await manager.PostAsync("/api/workflows/does-not-exist/versions", Json(v2))).StatusCode);

        var viewer = Host.UserClient(Roles.Viewer);
        var latest = await viewer.GetFromJsonAsync<WorkflowVersionDto>($"/api/workflows/{key}", ContractJson.Options);
        Assert.Equal(2, latest!.Version);
        Assert.Equal("tester", latest.CreatedBy);
        Assert.Equal(2, (await viewer.GetFromJsonAsync<List<WorkflowVersionDto>>($"/api/workflows/{key}/versions", ContractJson.Options))!.Count);
        Assert.Equal("API flow", (await viewer.GetFromJsonAsync<WorkflowVersionDto>($"/api/workflows/{key}/versions/1", ContractJson.Options))!.Definition.Name);
        var list = await viewer.GetFromJsonAsync<List<WorkflowSummary>>("/api/workflows", ContractJson.Options);
        Assert.Contains(list!, w => w.Key == StandardWorkflows.StandardDiscoveryKey);
        Assert.Contains(list!, w => w.Key == key && w.LatestVersion == 2);

        var cyclic = definition with { Steps = [new() { Id = "a", Operation = ScanOperation.DiscoverHosts, DependsOn = ["a"] }] };
        var rejected = await manager.PostAsync($"/api/workflows/{key}/versions", Json(cyclic));
        Assert.Equal(HttpStatusCode.UnprocessableEntity, rejected.StatusCode);
        var validation = await viewer.PostAsync("/api/workflows/validate", Json(cyclic));
        var result = await validation.Content.ReadFromJsonAsync<ValidationResultDto>(ContractJson.Options);
        Assert.False(result!.Valid);
        Assert.Contains(result.Errors, e => e.Contains("depends on itself"));
        var malformed = await viewer.PostAsync("/api/workflows/validate", new StringContent("{\"key\":\"x\",\"steps\":[{\"id\":\"a\",\"operation\":\"RunShell\"}]}", System.Text.Encoding.UTF8, "application/json"));
        Assert.False((await malformed.Content.ReadFromJsonAsync<ValidationResultDto>(ContractJson.Options))!.Valid);
        Assert.Contains(Host.Audit.Entries, e => e.Action == "workflow.version-created" && e.EntityId == $"{key}:2");
    }

    [Fact]
    public async Task Scans_can_be_started_inspected_and_followed_through_events()
    {
        var net = Host.Scope.Add(Zone, ["10.100.0.0/28"]);
        var editor = Host.UserClient(Roles.Editor);
        var invalid = await editor.PostAsync("/api/scans", Json(new StartScanDto("x", StandardWorkflows.StandardDiscoveryKey, null, [Guid.NewGuid()], null, null, null)));
        Assert.Equal(HttpStatusCode.UnprocessableEntity, invalid.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await Host.UserClient(Roles.Viewer).PostAsync("/api/scans", Json(new StartScanDto("x", "k", null, [net], null, null, null)))).StatusCode);

        var response = await editor.PostAsync("/api/scans", Json(new StartScanDto($"api-{Zone}", StandardWorkflows.StandardDiscoveryKey, null, [net], 70, 300, 60)));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var run = (await response.Content.ReadFromJsonAsync<ScanRunDto>(ContractJson.Options))!;
        Assert.Equal(WebScan.Server.Modules.Scanning.Persistence.ScanRunStatus.Running, run.Status);
        Assert.Equal(1, run.Progress.JobsTotal);
        Assert.Equal(1, run.Progress.JobsQueued);
        Assert.Equal(run.CreatedAt.AddMinutes(60), run.NotAfter!.Value, TimeSpan.FromSeconds(5));

        var viewer = Host.UserClient(Roles.Viewer);
        var page = await viewer.GetFromJsonAsync<Paged<ScanRunDto>>("/api/scans?status=Running&pageSize=200", ContractJson.Options);
        Assert.Contains(page!.Items, r => r.Id == run.Id);
        var detail = await viewer.GetFromJsonAsync<ScanRunDto>($"/api/scans/{run.Id}", ContractJson.Options);
        Assert.Equal(9, detail!.Steps!.Count);
        Assert.Equal("discover", detail.Steps[0].StepId);
        Assert.Equal(WebScan.Server.Modules.Workflows.Persistence.StepStatus.Running, detail.Steps[0].Status);
        Assert.Equal(1, detail.Steps[0].JobsTotal);

        var jobs = await viewer.GetFromJsonAsync<Paged<JobDto>>($"/api/scans/{run.Id}/jobs", ContractJson.Options);
        var job = Assert.Single(jobs!.Items);
        Assert.Equal("10.100.0.0/28", job.TargetSummary);
        Assert.Equal(300, (await viewer.GetFromJsonAsync<JobDetailDto>($"/api/jobs/{job.Id}", ContractJson.Options))!.Payload.Limits.RatePerSecond);
        Assert.Contains((await viewer.GetFromJsonAsync<Paged<JobDto>>($"/api/jobs?scanRunId={run.Id}&status=Queued", ContractJson.Options))!.Items, j => j.Id == job.Id);
        Assert.Equal(HttpStatusCode.Conflict, (await editor.PostAsync($"/api/jobs/{job.Id}/retry", null)).StatusCode);

        var events = await viewer.GetFromJsonAsync<List<ScanExecutionEvent>>($"/api/scans/{run.Id}/events", ContractJson.Options);
        Assert.Contains(events!, e => e.Type == ScanExecutionEventType.RunCreated);
        Assert.Contains(events!, e => e.Type == ScanExecutionEventType.JobQueued);
        var later = await viewer.GetFromJsonAsync<List<ScanExecutionEvent>>($"/api/scans/{run.Id}/events?after={events![0].EventId}", ContractJson.Options);
        Assert.Equal(events.Count - 1, later!.Count);

        var stats = await viewer.GetFromJsonAsync<PlannerStatsDto>("/api/stats/planner", ContractJson.Options);
        Assert.True(stats!.Queue.Queued >= 1);
    }

    [Fact]
    public async Task Scan_limits_are_admin_only_and_validated()
    {
        var admin = Host.UserClient(Roles.Administrator);
        var current = await Host.UserClient(Roles.Viewer).GetFromJsonAsync<ScanLimits>("/api/scan-limits", ContractJson.Options);
        Assert.Equal(HttpStatusCode.Forbidden, (await Host.UserClient(Roles.Manager).PutAsync("/api/scan-limits", Json(current))).StatusCode);
        var invalid = await admin.PutAsync("/api/scan-limits", Json(current! with { DefaultBatchSize = 5000, SubnetPrefixLength = 2 }));
        Assert.Equal(HttpStatusCode.UnprocessableEntity, invalid.StatusCode);
        var body = await invalid.Content.ReadAsStringAsync();
        Assert.Contains("defaultBatchSize", body);
        Assert.Contains("subnetPrefixLength", body);

        Assert.Equal(HttpStatusCode.OK, (await admin.PutAsync("/api/scan-limits", Json(current with { LeaseDurationSeconds = 300 }))).StatusCode);
        Assert.Equal(300, (await admin.GetFromJsonAsync<ScanLimits>("/api/scan-limits", ContractJson.Options))!.LeaseDurationSeconds);
        Assert.Equal(HttpStatusCode.OK, (await admin.PutAsync("/api/scan-limits", Json(current))).StatusCode);
    }

    [Fact]
    public async Task SignalR_hub_pushes_run_events_to_joined_clients()
    {
        var runId = Guid.NewGuid();
        var server = Host.App.GetTestServer();
        await using var connection = new HubConnectionBuilder()
            .WithUrl(new Uri(server.BaseAddress, ScanHub.Path), o =>
            {
                o.Transports = Microsoft.AspNetCore.Http.Connections.HttpTransportType.LongPolling;
                o.HttpMessageHandlerFactory = _ => server.CreateHandler();
                o.Headers[TestAuthHandler.RolesHeader] = Roles.Viewer;
            })
            .AddJsonProtocol(o => ContractJson.Configure(o.PayloadSerializerOptions))
            .Build();
        var received = new TaskCompletionSource<ScanExecutionEvent>(TaskCreationOptions.RunContinuationsAsynchronously);
        connection.On<ScanExecutionEvent>(ScanHub.EventMethod, e => { if (e.ScanRunId == runId) received.TrySetResult(e); });
        await connection.StartAsync();
        await connection.InvokeAsync(ScanHub.JoinRunMethod, runId);

        await Host.App.Services.GetRequiredService<IScanEventPublisher>().PublishAsync(Host.Time, ScanExecutionEventType.JobProgress, runId, "half way", progress: 50);

        var evt = await received.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(50, evt.Progress);
        Assert.Equal(ScanExecutionEventType.JobProgress, evt.Type);
    }
}
