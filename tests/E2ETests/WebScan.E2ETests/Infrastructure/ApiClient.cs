using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using WebScan.Contracts;

namespace WebScan.E2ETests.Infrastructure;

/// <summary>Thin JSON client for the UI-facing API (ARCHITECTURE §11). Uses JsonNode to stay contract-agnostic.</summary>
public sealed class ApiClient(HttpClient http)
{
    public HttpClient Http { get; } = http;
    public string? AccessToken { get; private set; }

    public async Task LoginAsync(string userName, string password)
    {
        var response = await Http.PostAsJsonAsync("/api/auth/login", new { userName, password }, ContractJson.Options);
        await EnsureSuccess(response);
        var body = await response.Content.ReadFromJsonAsync<JsonObject>(ContractJson.Options);
        AccessToken = body!["accessToken"]!.GetValue<string>();
        Http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", AccessToken);
    }

    public async Task<JsonNode> GetAsync(string url)
    {
        var response = await Http.GetAsync(url);
        await EnsureSuccess(response);
        return (await response.Content.ReadFromJsonAsync<JsonNode>(ContractJson.Options))!;
    }

    public async Task<string> GetStringAsync(string url)
    {
        var response = await Http.GetAsync(url);
        await EnsureSuccess(response);
        return await response.Content.ReadAsStringAsync();
    }

    public async Task<JsonNode?> PostAsync(string url, object? body = null) => await SendAsync(HttpMethod.Post, url, body);
    public async Task<JsonNode?> PutAsync(string url, object? body = null) => await SendAsync(HttpMethod.Put, url, body);
    public async Task DeleteAsync(string url) => await EnsureSuccess(await Http.DeleteAsync(url));

    public async Task<HttpStatusCode> StatusOfAsync(HttpMethod method, string url, object? body = null)
    {
        using var request = new HttpRequestMessage(method, url);
        if (body is not null) request.Content = JsonContent.Create(body, options: ContractJson.Options);
        using var response = await Http.SendAsync(request);
        return response.StatusCode;
    }

    public async Task<JsonNode?> PostRawAsync(string url, string content, string mediaType)
    {
        var response = await Http.PostAsync(url, new StringContent(content, System.Text.Encoding.UTF8, mediaType));
        await EnsureSuccess(response);
        var text = await response.Content.ReadAsStringAsync();
        return string.IsNullOrWhiteSpace(text) ? null : JsonNode.Parse(text);
    }

    private async Task<JsonNode?> SendAsync(HttpMethod method, string url, object? body)
    {
        using var request = new HttpRequestMessage(method, url);
        if (body is not null) request.Content = JsonContent.Create(body, options: ContractJson.Options);
        var response = await Http.SendAsync(request);
        await EnsureSuccess(response);
        var text = await response.Content.ReadAsStringAsync();
        return string.IsNullOrWhiteSpace(text) ? null : JsonNode.Parse(text);
    }

    private static async Task EnsureSuccess(HttpResponseMessage response)
    {
        if (response.IsSuccessStatusCode) return;
        var body = await response.Content.ReadAsStringAsync();
        throw new HttpRequestException($"{(int)response.StatusCode} {response.RequestMessage?.Method} {response.RequestMessage?.RequestUri}: {body}", null, response.StatusCode);
    }

    /// <summary>Polls until <paramref name="condition"/> holds or the timeout elapses.</summary>
    public static async Task<T> EventuallyAsync<T>(Func<Task<T>> probe, Func<T, bool> condition, TimeSpan timeout, string because)
    {
        var deadline = DateTime.UtcNow + timeout;
        T last = default!;
        Exception? lastError = null;
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                last = await probe();
                if (condition(last)) return last;
            }
            catch (Exception ex) { lastError = ex; }
            await Task.Delay(500);
        }
        throw new TimeoutException($"Timed out waiting for: {because}. Last value: {Describe(last)}", lastError);
    }

    private static string Describe<T>(T value) => value switch
    {
        JsonNode n => n.ToJsonString().Length > 2000 ? n.ToJsonString()[..2000] : n.ToJsonString(),
        null => "null",
        System.Collections.IEnumerable e => $"[{string.Join(", ", e.Cast<object>().Take(50))}]",
        _ => value.ToString() ?? "",
    };
}

public static class JsonNodeExtensions
{
    public static IEnumerable<JsonNode> Items(this JsonNode node) =>
        (node is JsonArray arr ? arr : node["items"]!.AsArray()).Select(n => n!);

    public static string Str(this JsonNode node, string property) => node[property]!.GetValue<string>();
}
