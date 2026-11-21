using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;

namespace WebScan.Server.UnitTests.Integration;

/// <summary>
/// Testcontainers defaults to Docker API 1.44; older engines (e.g. Docker 20.10 → 1.41) reject it. When
/// <c>DOCKER_API_VERSION</c> is not set, ask the local engine for its version and use it if it is older.
/// </summary>
internal static class DockerApiVersion
{
    internal static void Configure()
    {
        if (Environment.GetEnvironmentVariable("DOCKER_API_VERSION") is { Length: > 0 }) return;
        const string socket = "/var/run/docker.sock";
        if (!File.Exists(socket)) return;
        try
        {
            using var http = new HttpClient(new SocketsHttpHandler
            {
                ConnectCallback = async (_, ct) =>
                {
                    var s = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                    await s.ConnectAsync(new UnixDomainSocketEndPoint(socket), ct);
                    return new NetworkStream(s, ownsSocket: true);
                },
            }) { Timeout = TimeSpan.FromSeconds(5) };
            var version = http.GetFromJsonAsync<JsonElement>("http://docker/version").GetAwaiter().GetResult();
            if (Version.TryParse(version.GetProperty("ApiVersion").GetString(), out var api) && api < new Version(1, 44))
                Environment.SetEnvironmentVariable("DOCKER_API_VERSION", api.ToString());
        }
        catch (Exception ex) when (ex is HttpRequestException or SocketException or JsonException or TaskCanceledException or KeyNotFoundException)
        {
            // No reachable engine: Testcontainers reports the problem itself.
        }
    }
}
