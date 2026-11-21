using System.Net.Http.Json;
using System.Text.Json;

namespace WebScan.Server.Modules.Integrations.DefectDojo;

public sealed class DefectDojoApiException(string message) : Exception(message);

/// <summary>
/// Minimal DefectDojo API v2 client (typed HttpClient). Findings are created through <c>POST /api/v2/findings/</c> inside a
/// dedicated WebScan test of the configured engagement, which returns the finding id directly (stored as external id);
/// changed findings are updated with <c>PATCH /api/v2/findings/{id}/</c>.
/// </summary>
public sealed class DefectDojoClient(HttpClient http)
{
    public const string VerifiedTlsClient = "defectdojo";
    public const string InsecureTlsClient = "defectdojo-insecure";

    /// <summary>Built-in DefectDojo test type used for the WebScan test.</summary>
    public const string TestTypeName = "Generic Findings Import";

    private Uri _baseUrl = new("http://localhost/");
    private string _apiKey = "";

    public DefectDojoClient Connect(string baseUrl, string apiKey)
    {
        _baseUrl = new Uri(baseUrl.EndsWith('/') ? baseUrl : baseUrl + "/");
        _apiKey = apiKey;
        return this;
    }

    public async Task<int> FindTestTypeIdAsync(CancellationToken ct)
    {
        var json = await SendAsync(HttpMethod.Get, $"api/v2/test_types/?name={Uri.EscapeDataString(TestTypeName)}", null, ct);
        var results = json.GetProperty("results");
        return results.GetArrayLength() > 0
            ? results[0].GetProperty("id").GetInt32()
            : throw new DefectDojoApiException($"DefectDojo test type '{TestTypeName}' not found.");
    }

    public async Task<int> CreateTestAsync(int engagementId, int testTypeId, DateTimeOffset now, CancellationToken ct)
    {
        var json = await SendAsync(HttpMethod.Post, "api/v2/tests/", new Dictionary<string, object?>
        {
            ["engagement"] = engagementId,
            ["test_type"] = testTypeId,
            ["title"] = "WebScan",
            ["target_start"] = now.ToString("O"),
            ["target_end"] = now.ToString("O"),
        }, ct);
        return json.GetProperty("id").GetInt32();
    }

    public async Task<int> CreateFindingAsync(IReadOnlyDictionary<string, object?> finding, CancellationToken ct) =>
        (await SendAsync(HttpMethod.Post, "api/v2/findings/", finding, ct)).GetProperty("id").GetInt32();

    public Task UpdateFindingAsync(int findingId, IReadOnlyDictionary<string, object?> finding, CancellationToken ct) =>
        SendAsync(HttpMethod.Patch, $"api/v2/findings/{findingId}/", finding, ct);

    /// <summary>Connectivity/credential check: reads the configured engagement.</summary>
    public Task CheckEngagementAsync(int engagementId, CancellationToken ct) => SendAsync(HttpMethod.Get, $"api/v2/engagements/{engagementId}/", null, ct);

    private async Task<JsonElement> SendAsync(HttpMethod method, string path, object? body, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(method, new Uri(_baseUrl, path));
        request.Headers.TryAddWithoutValidation("Authorization", $"Token {_apiKey}");
        request.Headers.Accept.ParseAdd("application/json");
        if (body is not null) request.Content = JsonContent.Create(body);

        using var response = await http.SendAsync(request, ct);
        var text = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode)
            throw new DefectDojoApiException($"DefectDojo {method} {path} failed: {(int)response.StatusCode} {Truncate(text)}");
        if (string.IsNullOrWhiteSpace(text)) return default;
        using var doc = JsonDocument.Parse(text);
        return doc.RootElement.Clone();
    }

    private static string Truncate(string s) => s.Length > 300 ? s[..300] : s;
}
