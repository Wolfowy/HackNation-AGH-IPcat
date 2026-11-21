using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.DependencyInjection;
using WebScan.Contracts;
using WebScan.Server.Kernel.Messaging;
using WebScan.Server.Kernel.Ports;
using WebScan.Server.Modules.Agents;
using Wolverine.Tracking;

namespace WebScan.Server.UnitTests.Integration;

[Collection("server")]
public sealed class AgentTests(WebScanFactory factory)
{
    private static ToolDescriptor Tool(string id, params string[] capabilities) =>
        new() { Id = id, Version = "1.0", Capabilities = capabilities.Length > 0 ? capabilities : [ToolCapabilities.PortScan] };

    private static AgentRegistration Registration(string agentId, params ToolDescriptor[] tools) => new()
    {
        AgentId = agentId,
        Hostname = $"{agentId}.lab",
        OsPlatform = "linux",
        OsDescription = "Alpine Linux",
        AgentVersion = "1.0.0",
        Tools = tools.Length > 0 ? tools : [Tool("nmap", ToolCapabilities.HostDiscovery, ToolCapabilities.PortScan)],
        Interfaces = [new NetworkInterfaceInfo { Name = "eth0", Addresses = ["172.30.0.100/24"] }],
        DeclaredZones = ["lab"],
        Resources = new AgentResources { CpuCores = 2, MemoryTotalMb = 2048 },
        Limits = new AgentLimits { MaxConcurrentJobs = 4, MaxRatePerSecond = 1000 },
    };

    private static string NewAgentId() => $"agent-{Guid.NewGuid():N}"[..24];

    private HttpClient AgentClient(string agentId, string secret)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Agent", $"{agentId}:{secret}");
        return client;
    }

    private async Task<HttpResponseMessage> EnrollAsync(AgentRegistration registration, string token)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add(AgentApiRoutes.EnrollmentTokenHeader, token);
        return await client.PostJsonAsync(AgentApiRoutes.Register, registration);
    }

    /// <summary>Enrolls with the bootstrap token (auto-approve, zone "lab") and returns an authenticated agent client.</summary>
    private async Task<(HttpClient Client, string Secret)> EnrollActiveAsync(string agentId, params ToolDescriptor[] tools)
    {
        var response = await EnrollAsync(Registration(agentId, tools), WebScanFactory.BootstrapEnrollmentToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.ReadAsync<AgentRegistrationResponse>();
        Assert.Equal(AgentStatus.Active, body.Status);
        return (AgentClient(agentId, body.AgentSecret!), body.AgentSecret!);
    }

    private static Task<HttpResponseMessage> HeartbeatAsync(HttpClient agent, string agentId, string? inventoryHash = null) =>
        agent.PostJsonAsync(AgentApiRoutes.Heartbeat, new AgentHeartbeat
        {
            AgentId = agentId,
            Timestamp = DateTimeOffset.UtcNow,
            Load = new AgentLoad { CpuPercent = 12.5, RunningJobs = 1 },
            InventoryHash = inventoryHash,
        });

    [Fact]
    public async Task Enrollment_token_register_heartbeat_and_approval_flow()
    {
        var admin = await factory.AdminAsync();
        var created = await admin.PostJsonAsync("/api/enrollment-tokens",
            new { name = "dmz agents", expiresInHours = 1, maxUses = 1, autoApprove = false, zones = new[] { "dmz" } });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var token = await created.ReadAsync<CreatedEnrollmentTokenDto>();

        var agentId = NewAgentId();
        var registered = await (await EnrollAsync(Registration(agentId), token.Token)).ReadAsync<AgentRegistrationResponse>();
        Assert.Equal(AgentStatus.PendingApproval, registered.Status);
        Assert.NotNull(registered.AgentSecret);
        Assert.True(registered.AgentSecret!.Length >= 43); // 256-bit, base64url

        // Single-use token is exhausted; a wrong token is rejected.
        Assert.Equal(HttpStatusCode.Unauthorized, (await EnrollAsync(Registration(NewAgentId()), token.Token)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await EnrollAsync(Registration(NewAgentId()), "not-a-token")).StatusCode);
        // An enrolled id cannot be taken over with another token.
        Assert.Equal(HttpStatusCode.Conflict, (await EnrollAsync(Registration(agentId), WebScanFactory.BootstrapEnrollmentToken)).StatusCode);

        var agent = AgentClient(agentId, registered.AgentSecret);
        var pendingBeat = await HeartbeatAsync(agent, agentId, "hash-1");
        Assert.Equal(HttpStatusCode.OK, pendingBeat.StatusCode);
        Assert.Equal(AgentStatus.PendingApproval, (await pendingBeat.ReadAsync<AgentHeartbeatResponse>()).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await agent.PostAsync(AgentApiRoutes.RotateCredentials, null)).StatusCode);

        var detail = await (await admin.GetAsync($"/api/agents/{agentId}")).ReadAsync<AgentDto>();
        Assert.Equal(["dmz"], detail.AuthorizedZones);
        Assert.True(detail.IsOnline);
        Assert.Equal(12.5, detail.Load!.CpuPercent);

        Assert.Equal(HttpStatusCode.NoContent, (await admin.PostJsonAsync($"/api/agents/{agentId}/status", new { status = "Active" })).StatusCode);
        var activeBeat = await (await HeartbeatAsync(agent, agentId, "hash-1")).ReadAsync<AgentHeartbeatResponse>();
        Assert.Equal(AgentStatus.Active, activeBeat.Status);
        Assert.False(activeBeat.ReRegisterRequired);

        // Inventory changed on the agent → re-register with the agent key (no token, no new secret).
        Assert.True((await (await HeartbeatAsync(agent, agentId, "hash-2")).ReadAsync<AgentHeartbeatResponse>()).ReRegisterRequired);
        var reRegistered = await agent.PostJsonAsync(AgentApiRoutes.Register, Registration(agentId) with { AgentVersion = "1.1.0" });
        Assert.Equal(HttpStatusCode.OK, reRegistered.StatusCode);
        Assert.Null((await reRegistered.ReadAsync<AgentRegistrationResponse>()).AgentSecret);
        Assert.False((await (await HeartbeatAsync(agent, agentId, "hash-2")).ReadAsync<AgentHeartbeatResponse>()).ReRegisterRequired);

        // Re-registration without any credentials, or for another agent id, is refused.
        Assert.Equal(HttpStatusCode.Unauthorized, (await factory.CreateClient().PostJsonAsync(AgentApiRoutes.Register, Registration(agentId))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await agent.PostJsonAsync(AgentApiRoutes.Register, Registration(NewAgentId()))).StatusCode);
    }

    [Fact]
    public async Task Invalid_disabled_and_blocked_agents_are_rejected()
    {
        var admin = await factory.AdminAsync();
        var agentId = NewAgentId();
        var (agent, _) = await EnrollActiveAsync(agentId);

        Assert.Equal(HttpStatusCode.Unauthorized, (await HeartbeatAsync(AgentClient(agentId, "wrong-secret"), agentId)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await HeartbeatAsync(AgentClient("unknown-agent", "x"), "unknown-agent")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await HeartbeatAsync(agent, "someone-else")).StatusCode);
        // A user JWT is not an agent credential.
        Assert.Equal(HttpStatusCode.Unauthorized, (await HeartbeatAsync(admin, agentId)).StatusCode);

        await admin.PostJsonAsync($"/api/agents/{agentId}/status", new { status = "Disabled" });
        Assert.Equal(HttpStatusCode.Forbidden, (await HeartbeatAsync(agent, agentId)).StatusCode);

        await admin.PostJsonAsync($"/api/agents/{agentId}/status", new { status = "Blocked" });
        Assert.Equal(HttpStatusCode.Forbidden, (await HeartbeatAsync(agent, agentId)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await agent.PostJsonAsync(AgentApiRoutes.Register, Registration(agentId))).StatusCode);

        await admin.PostJsonAsync($"/api/agents/{agentId}/status", new { status = "Active" });
        Assert.Equal(HttpStatusCode.OK, (await HeartbeatAsync(agent, agentId)).StatusCode);

        Assert.Equal(HttpStatusCode.UnprocessableEntity,
            (await admin.PostJsonAsync($"/api/agents/{agentId}/status", new { status = "PendingApproval" })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync($"/api/agents/{agentId}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await HeartbeatAsync(agent, agentId)).StatusCode);
    }

    [Fact]
    public async Task Credential_rotation_keeps_previous_secret_valid_for_the_grace_period()
    {
        var admin = await factory.AdminAsync();
        var agentId = NewAgentId();
        var (oldClient, oldSecret) = await EnrollActiveAsync(agentId);

        Assert.False((await (await HeartbeatAsync(oldClient, agentId)).ReadAsync<AgentHeartbeatResponse>()).RotateCredentials);
        Assert.Equal(HttpStatusCode.Accepted, (await admin.PostAsync($"/api/agents/{agentId}/rotate-credentials", null)).StatusCode);
        Assert.True((await (await HeartbeatAsync(oldClient, agentId)).ReadAsync<AgentHeartbeatResponse>()).RotateCredentials);

        var rotated = await (await oldClient.PostAsync(AgentApiRoutes.RotateCredentials, null)).ReadAsync<AgentCredentialRotationResponse>();
        Assert.NotEqual(oldSecret, rotated.AgentSecret);
        Assert.InRange(rotated.PreviousSecretValidUntil, DateTimeOffset.UtcNow.AddMinutes(59), DateTimeOffset.UtcNow.AddMinutes(61));

        var newClient = AgentClient(agentId, rotated.AgentSecret);
        var beat = await (await HeartbeatAsync(newClient, agentId)).ReadAsync<AgentHeartbeatResponse>();
        Assert.False(beat.RotateCredentials);
        Assert.Equal(HttpStatusCode.OK, (await HeartbeatAsync(oldClient, agentId)).StatusCode); // grace period

        try
        {
            factory.Time.Offset = TimeSpan.FromMinutes(61);
            Assert.Equal(HttpStatusCode.Unauthorized, (await HeartbeatAsync(oldClient, agentId)).StatusCode);
            Assert.Equal(HttpStatusCode.OK, (await HeartbeatAsync(newClient, agentId)).StatusCode);
        }
        finally
        {
            factory.Time.Offset = TimeSpan.Zero;
        }
    }

    [Fact]
    public async Task Unapproved_tools_are_hidden_from_the_agent_directory_until_approved()
    {
        var admin = await factory.AdminAsync();
        var agentId = NewAgentId();
        var customTool = $"custom-{Guid.NewGuid():N}"[..20];
        var response = await EnrollAsync(Registration(agentId, Tool("nmap", ToolCapabilities.PortScan), Tool(customTool, "dns-resolve")),
            WebScanFactory.BootstrapEnrollmentToken);
        Assert.Contains(customTool, (await response.ReadAsync<AgentRegistrationResponse>()).UnapprovedTools);

        async Task<AgentSnapshot> SnapshotAsync()
        {
            await using var scope = factory.Services.CreateAsyncScope();
            return (await scope.ServiceProvider.GetRequiredService<IAgentDirectory>().GetAsync(agentId))!;
        }

        Assert.Equal(["nmap"], (await SnapshotAsync()).ApprovedTools.Select(t => t.Id));
        var tools = await (await admin.GetAsync("/api/tools")).ReadAsync<List<ToolDto>>();
        var entry = tools.Single(t => t.ToolId == customTool);
        Assert.False(entry.Approved);
        Assert.Equal(1, entry.AgentCount);
        Assert.Equal(["dns-resolve"], entry.Capabilities);
        Assert.True(tools.Single(t => t.ToolId == "nmap").Approved); // Tools:AutoApprove default

        Assert.Equal(HttpStatusCode.NoContent, (await admin.PutJsonAsync($"/api/tools/{customTool}", new { approved = true, enabled = true })).StatusCode);
        Assert.Equal(["nmap", customTool], (await SnapshotAsync()).ApprovedTools.Select(t => t.Id));

        await admin.PutJsonAsync($"/api/tools/{customTool}", new { approved = true, enabled = false });
        Assert.Equal(["nmap"], (await SnapshotAsync()).ApprovedTools.Select(t => t.Id));
    }

    [Fact]
    public async Task Assignment_overrides_lower_effective_limits_and_set_zones()
    {
        var admin = await factory.AdminAsync();
        var agentId = NewAgentId();
        await EnrollActiveAsync(agentId);
        var networkId = Guid.NewGuid();

        var put = await admin.PutJsonAsync($"/api/agents/{agentId}/assignment",
            new { authorizedZones = new[] { "lab", "dmz" }, authorizedNetworkIds = new[] { networkId }, maxConcurrentJobs = 2, maxRatePerSecond = 5000 });
        Assert.Equal(HttpStatusCode.NoContent, put.StatusCode);

        await using var scope = factory.Services.CreateAsyncScope();
        var directory = scope.ServiceProvider.GetRequiredService<IAgentDirectory>();
        var snapshot = (await directory.GetActiveAgentsAsync()).Single(a => a.AgentId == agentId);
        Assert.Equal(2, snapshot.Limits.MaxConcurrentJobs);
        Assert.Equal(1000, snapshot.Limits.MaxRatePerSecond); // override above the reported value never raises it
        Assert.Equal(["lab", "dmz"], snapshot.AuthorizedZones);
        Assert.Equal([networkId], snapshot.AuthorizedNetworkIds);
        Assert.True(snapshot.IsOnline);
    }

    [Fact]
    public async Task Revoked_enrollment_tokens_cannot_be_used()
    {
        var admin = await factory.AdminAsync();
        var token = await (await admin.PostJsonAsync("/api/enrollment-tokens", new { name = "revoke-me", maxUses = 5 })).ReadAsync<CreatedEnrollmentTokenDto>();
        Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync($"/api/enrollment-tokens/{token.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await EnrollAsync(Registration(NewAgentId()), token.Token)).StatusCode);

        var tokens = await (await admin.GetAsync("/api/enrollment-tokens")).ReadAsync<List<EnrollmentTokenDto>>();
        Assert.True(tokens.Single(t => t.Id == token.Id).Revoked);
        Assert.Contains(tokens, t => t.Name.StartsWith("bootstrap", StringComparison.Ordinal) && t.Zones.SequenceEqual(["lab"]));
        Assert.Equal(HttpStatusCode.UnprocessableEntity, (await admin.PostJsonAsync("/api/enrollment-tokens", new { name = "", maxUses = 0 })).StatusCode);
    }

    [Fact]
    public async Task Offline_detector_publishes_AgentWentOffline_once()
    {
        var admin = await factory.AdminAsync();
        var agentId = NewAgentId();
        var (agent, _) = await EnrollActiveAsync(agentId);
        var detector = factory.Services.GetRequiredService<AgentOfflineDetector>();

        IReadOnlyList<string> offline = [];
        ITrackedSession session;
        try
        {
            factory.Time.Offset = TimeSpan.FromSeconds(120); // > Agents:HeartbeatTimeoutSeconds (90)
            session = await factory.Services.TrackActivity().Timeout(TimeSpan.FromSeconds(30))
                .ExecuteAndWaitAsync((Func<Wolverine.IMessageContext, Task>)(async _ => offline = await detector.CheckAsync(CancellationToken.None)));
            Assert.DoesNotContain(agentId, await detector.CheckAsync(CancellationToken.None)); // only once
        }
        finally
        {
            factory.Time.Offset = TimeSpan.Zero;
        }

        Assert.Contains(agentId, offline);
        var published = session.Sent.MessagesOf<AgentWentOffline>().ToList();
        Assert.Contains(published, m => m.AgentId == agentId);

        Assert.False((await (await admin.GetAsync($"/api/agents/{agentId}")).ReadAsync<AgentDto>()).IsOnline);
        Assert.Equal(HttpStatusCode.OK, (await HeartbeatAsync(agent, agentId)).StatusCode);
        Assert.True((await (await admin.GetAsync($"/api/agents/{agentId}")).ReadAsync<AgentDto>()).IsOnline);
    }
}
