using System.Collections.Concurrent;
using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.Json;
using WebScan.Contracts;

namespace WebScan.Agent.UnitTests;

/// <summary>In-memory implementation of the agent API (§12) for communication tests, with fault injection.</summary>
internal sealed class FakeAgentServer : HttpMessageHandler
{
    private readonly Lock _lock = new();
    private string? _secret;
    private string? _previousSecret;
    private int _secretCounter;

    public string EnrollmentToken { get; set; } = "enroll-123";
    public AgentStatus Status { get; set; } = AgentStatus.Active;
    public ConcurrentQueue<JobAssignment> PendingAssignments { get; } = new();

    public List<(AgentRegistration Registration, string? EnrollmentToken, string? Authorization)> Registrations { get; } = [];
    public List<AgentHeartbeat> Heartbeats { get; } = [];
    public List<ScanResultBatch> Batches { get; } = [];
    public List<(Guid JobId, JobCompletionRequest Request)> Completions { get; } = [];
    public List<(Guid JobId, JobFailureRequest Request)> Failures { get; } = [];
    public List<(Guid JobId, JobHeartbeatRequest Request)> JobHeartbeats { get; } = [];
    public List<string> Rotations { get; } = [];
    public List<string> UnauthorizedRequests { get; } = [];

    /// <summary>One-shot flags returned by the next agent heartbeat.</summary>
    public bool RequestReRegistration { get; set; }
    public bool RequestRotation { get; set; }
    public HashSet<Guid> CancelJobIds { get; } = [];
    public HashSet<Guid> CancelRequestedJobs { get; } = [];

    /// <summary>Fault injection: return a response to short-circuit the request (null = normal handling).</summary>
    public Func<HttpRequestMessage, HttpResponseMessage?>? Fault { get; set; }

    public string? CurrentSecret { get { lock (_lock) return _secret; } }

    /// <summary>Reads recorded state under the server lock (the handler runs on other threads).</summary>
    public T Read<T>(Func<FakeAgentServer, T> read) { lock (_lock) return read(this); }
    public int RequestCount;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref RequestCount);
        if (Fault?.Invoke(request) is { } faulted) return faulted;

        var path = request.RequestUri!.AbsolutePath;
        var auth = request.Headers.Authorization is { } a ? $"{a.Scheme} {a.Parameter}" : null;
        var body = await ReadBodyAsync(request, cancellationToken);

        if (path == AgentApiRoutes.Register)
        {
            var registration = Deserialize<AgentRegistration>(body);
            var token = request.Headers.TryGetValues(AgentApiRoutes.EnrollmentTokenHeader, out var values) ? values.Single() : null;
            lock (_lock) Registrations.Add((registration, token, auth));
            if (token is not null)
            {
                if (token != EnrollmentToken) return Status401();
                string secret;
                lock (_lock) { secret = NewSecret(); _secret = secret; }
                return Json(new AgentRegistrationResponse { AgentId = registration.AgentId, Status = Status, AgentSecret = secret, HeartbeatIntervalSeconds = 1, JobPollIntervalSeconds = 1 });
            }
            if (!Authorized(auth, path)) return Status401();
            return Json(new AgentRegistrationResponse { AgentId = registration.AgentId, Status = Status, HeartbeatIntervalSeconds = 1, JobPollIntervalSeconds = 1 });
        }

        if (!Authorized(auth, path)) return Status401();

        if (path == AgentApiRoutes.Heartbeat)
        {
            var heartbeat = Deserialize<AgentHeartbeat>(body);
            lock (_lock)
            {
                Heartbeats.Add(heartbeat);
                var response = new AgentHeartbeatResponse
                {
                    Status = Status, ServerTime = DateTimeOffset.UtcNow, ReRegisterRequired = RequestReRegistration, RotateCredentials = RequestRotation,
                    CancelJobIds = [.. CancelJobIds],
                };
                RequestReRegistration = false;
                RequestRotation = false;
                CancelJobIds.Clear();
                return Json(response);
            }
        }
        if (path == AgentApiRoutes.RotateCredentials)
        {
            lock (_lock)
            {
                _previousSecret = _secret;
                _secret = NewSecret();
                Rotations.Add(_secret);
                return Json(new AgentCredentialRotationResponse { AgentSecret = _secret, PreviousSecretValidUntil = DateTimeOffset.UtcNow.AddMinutes(5) });
            }
        }
        if (path == AgentApiRoutes.Claim)
        {
            var claim = Deserialize<JobClaimRequest>(body);
            var assignments = new List<JobAssignment>();
            while (assignments.Count < claim.MaxJobs && PendingAssignments.TryDequeue(out var next)) assignments.Add(next);
            return Json(new JobClaimResponse { Assignments = assignments, NextPollSeconds = 1 });
        }

        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries); // api/agents/jobs/{id}/{action}
        if (segments.Length == 5 && segments[2] == "jobs" && Guid.TryParse(segments[3], out var jobId))
        {
            switch (segments[4])
            {
                case "heartbeat":
                    var hb = Deserialize<JobHeartbeatRequest>(body);
                    lock (_lock) JobHeartbeats.Add((jobId, hb));
                    return Json(new JobHeartbeatResponse { LeaseExpiresAt = DateTimeOffset.UtcNow.AddMinutes(1), CancelRequested = CancelRequestedJobs.Contains(jobId) });
                case "results":
                    var batch = Deserialize<ScanResultBatch>(body);
                    lock (_lock)
                    {
                        var duplicate = Batches.Any(b => b.BatchId == batch.BatchId);
                        if (!duplicate) Batches.Add(batch);
                        return Json(new ResultBatchAck { BatchId = batch.BatchId, Accepted = true, Duplicate = duplicate, ObservationsAccepted = batch.Observations.Count });
                    }
                case "complete":
                    lock (_lock) Completions.Add((jobId, Deserialize<JobCompletionRequest>(body)));
                    return new HttpResponseMessage(HttpStatusCode.OK);
                case "fail":
                    lock (_lock) Failures.Add((jobId, Deserialize<JobFailureRequest>(body)));
                    return new HttpResponseMessage(HttpStatusCode.OK);
            }
        }
        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    public static HttpResponseMessage StatusCode(HttpStatusCode code) => new(code) { Content = new StringContent("{}", Encoding.UTF8, "application/json") };

    private bool Authorized(string? auth, string path)
    {
        lock (_lock)
        {
            var ok = auth is not null && _secret is not null && auth.StartsWith("Agent ", StringComparison.Ordinal)
                     && (auth.EndsWith(":" + _secret, StringComparison.Ordinal) || (_previousSecret is not null && auth.EndsWith(":" + _previousSecret, StringComparison.Ordinal)));
            if (!ok) UnauthorizedRequests.Add(path);
            return ok;
        }
    }

    private string NewSecret() => $"secret-{++_secretCounter}-{Guid.NewGuid():N}";

    private static async Task<string> ReadBodyAsync(HttpRequestMessage request, CancellationToken ct)
    {
        if (request.Content is null) return "";
        var bytes = await request.Content.ReadAsByteArrayAsync(ct);
        if (request.Content.Headers.ContentEncoding.Contains("gzip"))
        {
            using var gzip = new GZipStream(new MemoryStream(bytes), CompressionMode.Decompress);
            using var ms = new MemoryStream();
            await gzip.CopyToAsync(ms, ct);
            bytes = ms.ToArray();
        }
        return Encoding.UTF8.GetString(bytes);
    }

    private static T Deserialize<T>(string json) => JsonSerializer.Deserialize<T>(json, ContractJson.Options)!;

    private static HttpResponseMessage Json<T>(T value) =>
        new(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(value, ContractJson.Options), Encoding.UTF8, "application/json") };

    private static HttpResponseMessage Status401() => StatusCode(HttpStatusCode.Unauthorized);
}
