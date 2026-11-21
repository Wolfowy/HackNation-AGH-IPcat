using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http.Connections;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.DependencyInjection;
using WebScan.Contracts;

namespace WebScan.E2ETests.Infrastructure;

/// <summary>Common setup + API steps shared by the E2E scenarios.</summary>
public abstract class Scenario(PostgresFixture postgres) : IAsyncLifetime
{
    protected E2EServerFactory Server { get; private set; } = null!;
    protected ApiClient Admin { get; private set; } = null!;
    protected List<InProcessAgent> Agents { get; } = [];

    protected virtual IReadOnlyDictionary<string, string?>? ServerOverrides => null;

    public virtual async Task InitializeAsync()
    {
        Server = new E2EServerFactory(postgres.NewDatabase(), ServerOverrides);
        Admin = await Server.AdminClientAsync();
    }

    public virtual async Task DisposeAsync()
    {
        foreach (var agent in Agents) await agent.DisposeAsync();
        await Server.DisposeAsync();
        // Quartz keeps a process-wide static logger provider bound to the first host; reset it for the next host.
        Quartz.Logging.LogContext.SetCurrentLogProvider(Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance);
    }

    protected async Task<InProcessAgent> StartAgentAsync(string id, string interfaceCidr, IReadOnlyDictionary<string, string?>? extra = null)
    {
        var agent = await InProcessAgent.StartAsync(Server, id, interfaceCidr, extra);
        Agents.Add(agent);
        return agent;
    }

    protected Task<JsonNode> WaitForAgentsOnlineAsync(params string[] ids) =>
        ApiClient.EventuallyAsync(() => Admin.GetAsync("/api/agents"),
            list => ids.All(id => list.Items().Any(a => a.Str("agentId") == id && a["isOnline"]!.GetValue<bool>()
                                                        && a.Str("status") == "Active")),
            TimeSpan.FromSeconds(30), $"agents {string.Join(", ", ids)} online and active");

    protected async Task ApproveToolAsync(string toolId) =>
        await Admin.PutAsync($"/api/tools/{toolId}", new { approved = true, enabled = true });

    protected async Task<Guid> CreateNetworkAsync(string name, string zone, string[] ranges, string[]? exclusions = null)
    {
        var created = await Admin.PostAsync("/api/networks", new { name, zone, ranges, exclusions = exclusions ?? [], tags = Array.Empty<string>(), enabled = true });
        return Guid.Parse(created!.Str("id"));
    }

    protected async Task SetScanLimitsAsync(Action<JsonObject> change)
    {
        var limits = (await Admin.GetAsync("/api/scan-limits")).AsObject();
        change(limits);
        await Admin.PutAsync("/api/scan-limits", limits);
    }

    protected async Task<Guid> StartScanAsync(string name, IEnumerable<Guid> networkIds, int? windowMinutes = null, string workflow = "standard-discovery")
    {
        var run = await Admin.PostAsync("/api/scans", new { name, workflowKey = workflow, networkIds, windowMinutes });
        return Guid.Parse(run!.Str("id"));
    }

    protected Task<JsonNode> WaitForRunAsync(Guid runId, TimeSpan timeout, params string[] terminalStatuses) =>
        ApiClient.EventuallyAsync(() => Admin.GetAsync($"/api/scans/{runId}"),
            run => terminalStatuses.Contains(run.Str("status")),
            timeout, $"scan {runId} reaching {string.Join("/", terminalStatuses)}");

    protected async Task<List<JsonNode>> AllPagesAsync(string url)
    {
        var items = new List<JsonNode>();
        for (var page = 1; ; page++)
        {
            var sep = url.Contains('?') ? '&' : '?';
            var body = await Admin.GetAsync($"{url}{sep}page={page}&pageSize=200");
            var batch = body.Items().ToList();
            items.AddRange(batch);
            if (batch.Count == 0 || items.Count >= body["total"]!.GetValue<int>()) return items;
        }
    }

    protected async Task<HubConnection> ConnectHubAsync(Action<ScanExecutionEvent> onEvent)
    {
        var hub = new HubConnectionBuilder()
            .WithUrl(new Uri(Server.Server.BaseAddress, ScanHub.Path), o =>
            {
                o.HttpMessageHandlerFactory = _ => Server.Server.CreateHandler();
                o.AccessTokenProvider = () => Task.FromResult(Admin.AccessToken);
                o.Transports = HttpTransportType.LongPolling;
            })
            .AddJsonProtocol(o => ContractJson.Configure(o.PayloadSerializerOptions))
            .Build();
        hub.On<ScanExecutionEvent>(ScanHub.EventMethod, onEvent);
        await hub.StartAsync();
        return hub;
    }
}
