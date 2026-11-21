using System.Net;
using System.Net.Http.Json;
using WebScan.Server.Infrastructure.Http;
using WebScan.Server.Kernel.Security;
using WebScan.Server.Modules.Identity;
using WebScan.Server.Modules.Networks;

namespace WebScan.Server.UnitTests.Integration;

[Collection("server")]
public sealed class IdentityTests(WebScanFactory factory)
{
    [Fact]
    public async Task Bootstrap_admin_can_log_in_and_read_profile()
    {
        var login = await factory.CreateClient().PostAsJsonAsync("/api/auth/login",
            new { userName = "ADMIN", password = WebScanFactory.AdminPassword }); // user names are case-insensitive
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var body = await login.ReadAsync<LoginResponse>();
        Assert.Contains(Roles.Administrator, body.User.Roles);
        Assert.True(body.ExpiresAt > DateTimeOffset.UtcNow);

        var me = await factory.CreateClient(body.AccessToken).GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        Assert.Equal(WebScanFactory.AdminUserName, (await me.ReadAsync<UserDto>()).UserName);
    }

    [Fact]
    public async Task Invalid_credentials_and_tampered_tokens_are_rejected()
    {
        var bad = await factory.CreateClient().PostAsJsonAsync("/api/auth/login", new { userName = "admin", password = "wrong-password-123" });
        Assert.Equal(HttpStatusCode.Unauthorized, bad.StatusCode);

        var unknown = await factory.CreateClient().PostAsJsonAsync("/api/auth/login", new { userName = "nobody-here", password = "whatever-password" });
        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await factory.CreateClient("not.a.jwt").GetAsync("/api/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await factory.CreateClient().GetAsync("/api/auth/me")).StatusCode);
    }

    [Fact]
    public async Task Access_token_in_query_is_accepted_only_for_hub_paths()
    {
        var login = await (await factory.CreateClient().PostAsJsonAsync("/api/auth/login",
            new { userName = WebScanFactory.AdminUserName, password = WebScanFactory.AdminPassword })).ReadAsync<LoginResponse>();
        var anonymous = factory.CreateClient();

        Assert.Equal(HttpStatusCode.OK, (await anonymous.GetAsync($"/hubs/probe?access_token={login.AccessToken}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync("/hubs/probe")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync($"/api/auth/me?access_token={login.AccessToken}")).StatusCode);
    }

    [Fact]
    public async Task Account_locks_after_five_failures_for_fifteen_minutes()
    {
        var admin = await factory.AdminAsync();
        const string password = "Lockout-Password-1";
        var userName = $"lock-{Guid.NewGuid():N}"[..20];
        (await admin.PostJsonAsync("/api/users", new { userName, password, roles = new[] { Roles.Viewer } })).EnsureSuccessStatusCode();

        var anonymous = factory.CreateClient();
        for (var i = 0; i < 5; i++)
            await anonymous.PostAsJsonAsync("/api/auth/login", new { userName, password = "wrong-password-xx" });

        var locked = await anonymous.PostAsJsonAsync("/api/auth/login", new { userName, password });
        Assert.Equal(HttpStatusCode.Unauthorized, locked.StatusCode);

        try
        {
            factory.Time.Offset = TimeSpan.FromMinutes(16);
            Assert.Equal(HttpStatusCode.OK, (await anonymous.PostAsJsonAsync("/api/auth/login", new { userName, password })).StatusCode);
        }
        finally
        {
            factory.Time.Offset = TimeSpan.Zero;
        }

        var audit = await (await admin.GetAsync("/api/audit?action=auth.login_failed&pageSize=20")).ReadAsync<PagedResult<WebScan.Server.Infrastructure.AuditEntryDto>>();
        Assert.Contains(audit.Items, e => e.Details!.Value.GetProperty("reason").GetString() == "bad_password_locked");
    }

    [Fact]
    public async Task User_management_validates_and_protects_the_last_administrator()
    {
        var admin = await factory.AdminAsync();

        var weak = await admin.PostJsonAsync("/api/users", new { userName = "weak-user", password = "short", roles = new[] { Roles.Viewer } });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, weak.StatusCode);
        var badRole = await admin.PostJsonAsync("/api/users", new { userName = "role-user", password = "Long-Enough-Pass-1", roles = new[] { "Root" } });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, badRole.StatusCode);

        var userName = $"mgmt-{Guid.NewGuid():N}"[..20];
        var created = await (await admin.PostJsonAsync("/api/users",
            new { userName, displayName = "Managed", password = "Initial-Password-1", roles = new[] { Roles.Editor } })).ReadAsync<UserDto>();
        Assert.Equal(HttpStatusCode.Conflict,
            (await admin.PostJsonAsync("/api/users", new { userName = userName.ToUpperInvariant(), password = "Initial-Password-1", roles = new[] { Roles.Editor } })).StatusCode);

        var updated = await (await admin.PutJsonAsync($"/api/users/{created.Id}", new { roles = new[] { Roles.Manager }, isActive = true })).ReadAsync<UserDto>();
        Assert.Equal([Roles.Manager], updated.Roles);

        Assert.Equal(HttpStatusCode.NoContent, (await admin.PostJsonAsync($"/api/users/{created.Id}/password", new { password = "Changed-Password-1" })).StatusCode);
        await factory.LoginAsync(userName, "Changed-Password-1");

        var users = await (await admin.GetAsync("/api/users")).ReadAsync<List<UserDto>>();
        var adminUser = users.Single(u => u.UserName == WebScanFactory.AdminUserName);
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PutJsonAsync($"/api/users/{adminUser.Id}", new { isActive = false })).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await admin.DeleteAsync($"/api/users/{adminUser.Id}")).StatusCode);

        Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync($"/api/users/{created.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.DeleteAsync($"/api/users/{created.Id}")).StatusCode);
    }

    [Fact]
    public async Task Rbac_matrix_is_enforced()
    {
        var admin = await factory.AdminAsync();
        var viewer = await factory.UserWithRoleAsync(Roles.Viewer);
        var editor = await factory.UserWithRoleAsync(Roles.Editor);
        var manager = await factory.UserWithRoleAsync(Roles.Manager);

        NetworkInput Net(string name) => new() { Name = name, Zone = "rbac", Ranges = ["10.10.0.0/24"] };

        // Viewer: read only.
        Assert.Equal(HttpStatusCode.OK, (await viewer.GetAsync("/api/networks")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.PostJsonAsync("/api/networks", Net("viewer-net"))).StatusCode);

        // Manager: create; Editor: modify existing but not create/delete.
        var create = await manager.PostJsonAsync("/api/networks", Net($"rbac-{Guid.NewGuid():N}"));
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        var network = await create.ReadAsync<NetworkDto>();

        Assert.Equal(HttpStatusCode.OK, (await editor.PutJsonAsync($"/api/networks/{network.Id}", Net(network.Name) with { Description = "edited" })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await editor.PostJsonAsync("/api/networks", Net("editor-net"))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await editor.DeleteAsync($"/api/networks/{network.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.PutJsonAsync($"/api/networks/{network.Id}", Net(network.Name))).StatusCode);

        // AdminOnly: settings, users, audit, scope policy changes, agent administration.
        foreach (var client in new[] { viewer, editor, manager })
        {
            Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/settings")).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/users")).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/audit")).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/enrollment-tokens")).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await client.PutJsonAsync("/api/scope-policy", new { allowed = new[] { "10.0.0.0/8" } })).StatusCode);
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/agents")).StatusCode);
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/auth/me")).StatusCode);
        }
        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync("/api/settings")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync("/api/users")).StatusCode);

        Assert.Equal(HttpStatusCode.NoContent, (await manager.DeleteAsync($"/api/networks/{network.Id}")).StatusCode);
    }
}
