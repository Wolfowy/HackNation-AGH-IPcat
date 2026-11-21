using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using WebScan.Agent.Storage;
using WebScan.Contracts;

namespace WebScan.Agent.Communication;

/// <summary>Non-success response from the server (after transient retries of the resilience pipeline).</summary>
public sealed class AgentApiException(HttpStatusCode statusCode, string message) : Exception(message)
{
    public HttpStatusCode StatusCode { get; } = statusCode;

    /// <summary>409/404 on job calls: the lease is stale or the job is gone — results must be dropped.</summary>
    public bool IsStaleJob => StatusCode is HttpStatusCode.Conflict or HttpStatusCode.NotFound;

    public bool IsAuthenticationFailure => StatusCode is HttpStatusCode.Unauthorized;

    /// <summary>Client errors that will never succeed on retry (except 408/429).</summary>
    public bool IsPermanent => (int)StatusCode is >= 400 and < 500 && StatusCode is not (HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests);
}

/// <summary>Typed client for the agent API (<see cref="AgentApiRoutes"/>). Auth: <c>Authorization: Agent {id}:{secret}</c> or the enrollment token header.</summary>
public sealed class AgentApiClient(HttpClient http, CredentialStore credentials)
{
    public Task<AgentRegistrationResponse> RegisterAsync(AgentRegistration registration, string? enrollmentToken, CancellationToken ct) =>
        SendAsync<AgentRegistrationResponse>(AgentApiRoutes.Register, Json(registration), ct, enrollmentToken);

    public Task<AgentHeartbeatResponse> HeartbeatAsync(AgentHeartbeat heartbeat, CancellationToken ct) =>
        SendAsync<AgentHeartbeatResponse>(AgentApiRoutes.Heartbeat, Json(heartbeat), ct);

    public Task<AgentCredentialRotationResponse> RotateCredentialsAsync(CancellationToken ct) =>
        SendAsync<AgentCredentialRotationResponse>(AgentApiRoutes.RotateCredentials, Json(new { }), ct);

    public Task<JobClaimResponse> ClaimAsync(JobClaimRequest request, CancellationToken ct) =>
        SendAsync<JobClaimResponse>(AgentApiRoutes.Claim, Json(request), ct);

    public Task<JobHeartbeatResponse> JobHeartbeatAsync(Guid jobId, JobHeartbeatRequest request, CancellationToken ct) =>
        SendAsync<JobHeartbeatResponse>(AgentApiRoutes.JobHeartbeat(jobId), Json(request), ct);

    /// <summary>Sends a stored batch exactly as buffered (gzip JSON) with <c>Content-Encoding: gzip</c>.</summary>
    public Task<ResultBatchAck> SendResultsAsync(Guid jobId, byte[] gzipJson, CancellationToken ct)
    {
        var content = new ByteArrayContent(gzipJson);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
        content.Headers.ContentEncoding.Add("gzip");
        return SendAsync<ResultBatchAck>(AgentApiRoutes.JobResults(jobId), content, ct);
    }

    public Task SendFinalAsync(Guid jobId, FinalKind kind, string payloadJson, CancellationToken ct)
    {
        var content = new StringContent(payloadJson, Encoding.UTF8, "application/json");
        return SendAsync<JsonElement?>(kind == FinalKind.Complete ? AgentApiRoutes.JobComplete(jobId) : AgentApiRoutes.JobFail(jobId), content, ct);
    }

    private async Task<T> SendAsync<T>(string path, HttpContent content, CancellationToken ct, string? enrollmentToken = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = content };
        if (enrollmentToken is not null)
            request.Headers.Add(AgentApiRoutes.EnrollmentTokenHeader, enrollmentToken);
        else if (credentials.Current is { } c)
            request.Headers.Authorization = new AuthenticationHeaderValue(AgentApiRoutes.AuthorizationScheme, $"{c.AgentId}:{c.Secret}");

        using var response = await http.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(ct);
            throw new AgentApiException(response.StatusCode, $"{path} returned {(int)response.StatusCode}: {Truncate(SensitiveDataMasker.MaskTokens(body), 500)}");
        }
        if (response.Content.Headers.ContentLength == 0 || response.StatusCode == HttpStatusCode.NoContent) return default!;
        var text = await response.Content.ReadAsStringAsync(ct);
        return string.IsNullOrWhiteSpace(text) ? default! : JsonSerializer.Deserialize<T>(text, ContractJson.Options)!;
    }

    private static JsonContent Json<T>(T value) => JsonContent.Create(value, options: ContractJson.Options);

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max];
}
