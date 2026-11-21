using System.Text.RegularExpressions;

namespace WebScan.Contracts;

/// <summary>
/// Masks secrets (cookie values, tokens, auth headers) before data leaves the agent and again on the server.
/// </summary>
public static partial class SensitiveDataMasker
{
    public const string Mask = "***";

    private static readonly HashSet<string> SensitiveHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "set-cookie", "cookie", "authorization", "proxy-authorization", "x-api-key", "x-auth-token", "x-csrf-token",
        "x-xsrf-token", "www-authenticate",
    };

    /// <summary>Masks a single header value. <c>Set-Cookie: sid=abc; Path=/</c> becomes <c>sid=***; Path=/</c>.</summary>
    public static string MaskHeader(string name, string value)
    {
        if (name.Equals("set-cookie", StringComparison.OrdinalIgnoreCase) || name.Equals("cookie", StringComparison.OrdinalIgnoreCase))
            return MaskCookieString(value);
        if (name.Equals("www-authenticate", StringComparison.OrdinalIgnoreCase))
            return value; // challenge, not a secret
        return SensitiveHeaders.Contains(name) ? Mask : MaskTokens(value);
    }

    public static IReadOnlyDictionary<string, string> MaskHeaders(IReadOnlyDictionary<string, string> headers) =>
        headers.ToDictionary(h => h.Key, h => MaskHeader(h.Key, h.Value), StringComparer.OrdinalIgnoreCase);

    /// <summary>Keeps cookie names and attributes, replaces values.</summary>
    public static string MaskCookieString(string cookie) =>
        CookiePair().Replace(cookie, m =>
        {
            var name = m.Groups["name"].Value;
            return IsCookieAttribute(name) ? m.Value : $"{m.Groups["pre"].Value}{name}={Mask}";
        });

    /// <summary>Masks bearer tokens, JWTs and key=value secrets inside free text (banners, evidence, stderr).</summary>
    public static string MaskTokens(string text)
    {
        if (string.IsNullOrEmpty(text)) return text;
        text = Bearer().Replace(text, "${scheme} " + Mask);
        text = Jwt().Replace(text, Mask);
        text = SecretKv().Replace(text, "${key}${sep}" + Mask);
        return text;
    }

    private static bool IsCookieAttribute(string name) =>
        name.Equals("path", StringComparison.OrdinalIgnoreCase) || name.Equals("domain", StringComparison.OrdinalIgnoreCase)
        || name.Equals("expires", StringComparison.OrdinalIgnoreCase) || name.Equals("max-age", StringComparison.OrdinalIgnoreCase)
        || name.Equals("samesite", StringComparison.OrdinalIgnoreCase) || name.Equals("priority", StringComparison.OrdinalIgnoreCase);

    [GeneratedRegex(@"(?<pre>^|;\s*|,\s*)(?<name>[^=;,\s]+)=(?<value>[^;,]*)")]
    private static partial Regex CookiePair();

    [GeneratedRegex(@"(?<scheme>Bearer|Basic|Token)\s+[A-Za-z0-9\-._~+/=]{8,}", RegexOptions.IgnoreCase)]
    private static partial Regex Bearer();

    [GeneratedRegex(@"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")]
    private static partial Regex Jwt();

    [GeneratedRegex(@"(?<key>(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|session(?:id)?)\b)(?<sep>\s*[=:]\s*)[^\s&;,""']+", RegexOptions.IgnoreCase)]
    private static partial Regex SecretKv();
}
