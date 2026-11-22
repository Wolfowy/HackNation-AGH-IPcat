using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace WebScan.Contracts;

/// <summary>Parses <c>Set-Cookie</c> header values into <see cref="HttpCookie"/> records; cookie values are dropped.</summary>
public static partial class HttpCookies
{
    /// <summary>
    /// Parses a header value that may hold several cookies joined with ", " (httpx joins repeated headers); the comma inside an
    /// <c>Expires</c> date is not a separator. Works on masked values too (<c>sid=***; HttpOnly</c>), only BIG-IP decoding needs the value.
    /// </summary>
    public static IReadOnlyList<HttpCookie> Parse(string? setCookie)
    {
        if (string.IsNullOrWhiteSpace(setCookie)) return [];
        var result = new List<HttpCookie>();
        foreach (var cookie in Separator().Split(setCookie))
        {
            var parts = cookie.Split(';', StringSplitOptions.TrimEntries);
            var eq = parts[0].IndexOf('=');
            if (eq <= 0) continue;
            var name = parts[0][..eq].Trim();
            var value = parts[0][(eq + 1)..].Trim().Trim('"');
            bool secure = false, httpOnly = false;
            string? sameSite = null, domain = null, path = null;
            foreach (var attribute in parts.Skip(1))
            {
                var aeq = attribute.IndexOf('=');
                var attrValue = aeq < 0 ? null : attribute[(aeq + 1)..].Trim() is { Length: > 0 } v ? v : null;
                switch ((aeq < 0 ? attribute : attribute[..aeq]).Trim().ToLowerInvariant())
                {
                    case "secure": secure = true; break;
                    case "httponly": httpOnly = true; break;
                    case "samesite": sameSite = attrValue is null ? null : char.ToUpperInvariant(attrValue[0]) + attrValue[1..].ToLowerInvariant(); break;
                    case "domain": domain = attrValue; break;
                    case "path": path = attrValue; break;
                }
            }
            result.Add(new HttpCookie
            {
                Name = name, Secure = secure, HttpOnly = httpOnly, SameSite = sameSite, Domain = domain, Path = path,
                DecodedValue = name.StartsWith("BIGipServer", StringComparison.OrdinalIgnoreCase) ? DecodeBigIp(value) : null,
            });
        }
        return result;
    }

    /// <summary>
    /// Decodes an unencrypted F5 BIG-IP persistence cookie value (F5 K6917) to the internal pool member:
    /// "1677787402.36895.0000" → "10.1.1.100:8080"; route domain "rd5o00000000000000000000ffffc0000201o80" → "192.0.2.1:80";
    /// IPv6 "vi20010112000000000000000000000030.20480" → "[2001:112::30]:80". Null for encrypted or unknown values.
    /// </summary>
    public static string? DecodeBigIp(string value)
    {
        if (BigIpV4().Match(value) is { Success: true } v4
            && uint.TryParse(v4.Groups[1].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var ip)
            && ushort.TryParse(v4.Groups[2].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var swapped))
            return $"{new IPAddress(ip)}:{BinaryPrimitives.ReverseEndianness(swapped)}"; // address bytes and port are little-endian
        if (BigIpRouteDomain().Match(value) is { Success: true } rd && ushort.TryParse(rd.Groups[2].Value, CultureInfo.InvariantCulture, out var rdPort))
            return Endpoint(rd.Groups[1].Value, rdPort);
        if (BigIpV6().Match(value) is { Success: true } v6 && ushort.TryParse(v6.Groups[2].Value, CultureInfo.InvariantCulture, out var v6Swapped))
            return Endpoint(v6.Groups[1].Value, BinaryPrimitives.ReverseEndianness(v6Swapped));
        return null;
    }

    private static string Endpoint(string hex, ushort port)
    {
        var address = new IPAddress(Convert.FromHexString(hex));
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        return address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{address}]:{port}" : $"{address}:{port}";
    }

    [GeneratedRegex(@",\s*(?=[!#$%&'*+\-.^_`|~0-9A-Za-z]+=)")]
    private static partial Regex Separator();

    [GeneratedRegex(@"^(\d{1,10})\.(\d{1,5})\.0{4}$")]
    private static partial Regex BigIpV4();

    [GeneratedRegex(@"^rd\d+o([0-9a-fA-F]{32})o(\d{1,5})$")]
    private static partial Regex BigIpRouteDomain();

    [GeneratedRegex(@"^vi([0-9a-fA-F]{32})\.(\d{1,5})$")]
    private static partial Regex BigIpV6();
}
