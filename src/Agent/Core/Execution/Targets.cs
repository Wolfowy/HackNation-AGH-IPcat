using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Text.RegularExpressions;
using WebScan.Contracts;

namespace WebScan.Agent.Execution;

/// <summary>Parsing, scope checks and expansion of job targets (IPs, CIDRs, hostnames, endpoints).</summary>
public static partial class Targets
{
    /// <summary>Upper bound for expanding a CIDR into single addresses (larger blocks are treated as one entry).</summary>
    public const int MaxExpansion = 65536;

    public static bool TryParseNetwork(string value, out IPNetwork network)
    {
        network = default;
        var slash = value.IndexOf('/');
        if (slash < 0)
        {
            if (!IPAddress.TryParse(value, out var ip)) return false;
            network = new IPNetwork(ip, ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128);
            return true;
        }
        if (!IPAddress.TryParse(value.AsSpan(0, slash), out var baseAddress) || !int.TryParse(value.AsSpan(slash + 1), out var prefix)) return false;
        var bits = baseAddress.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (prefix < 0 || prefix > bits) return false;
        network = new IPNetwork(Mask(baseAddress, prefix), prefix); // tolerate host bits ("10.0.0.1/24")
        return true;
    }

    public static bool IsHostname(string value) => HostnameRegex().IsMatch(value);

    /// <summary>True when the host entry (IP, CIDR or hostname) lies entirely inside one scope entry.</summary>
    public static bool IsInScope(string target, IReadOnlyList<string> scope)
    {
        if (TryParseNetwork(target, out var t))
        {
            foreach (var entry in scope)
                if (TryParseNetwork(entry, out var s) && s.BaseAddress.AddressFamily == t.BaseAddress.AddressFamily
                    && s.PrefixLength <= t.PrefixLength && s.Contains(t.BaseAddress))
                    return true;
            return false;
        }
        if (!IsHostname(target) || target.StartsWith("*.", StringComparison.Ordinal)) return false;
        var name = target.TrimEnd('.');
        foreach (var raw in scope)
        {
            var entry = raw.TrimEnd('.');
            if (entry.StartsWith("*.", StringComparison.Ordinal))
            {
                if (name.EndsWith(entry[1..], StringComparison.OrdinalIgnoreCase) && name.Length > entry.Length - 1) return true;
            }
            else if (string.Equals(entry, name, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    /// <summary>Single addresses of an IP/CIDR entry (hostnames and oversized blocks are returned unchanged).</summary>
    public static IEnumerable<string> Expand(string entry)
    {
        if (!TryParseNetwork(entry, out var net)) { yield return entry; yield break; }
        var bits = net.BaseAddress.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        var hostBits = bits - net.PrefixLength;
        if (hostBits > 16) { yield return entry; yield break; } // > MaxExpansion
        var start = ToNumber(net.BaseAddress);
        var count = UInt128.One << hostBits;
        for (UInt128 i = 0; i < count; i++) yield return ToAddress(start + i, net.BaseAddress.AddressFamily).ToString();
    }

    /// <summary>Coverage keys of a job: single addresses for host jobs, "addr:port" for endpoint jobs.</summary>
    public static IEnumerable<string> CoverageKeys(JobTargets targets) =>
        targets.Endpoints.Count > 0
            ? targets.Endpoints.Select(e => EndpointKey(e.Address, e.Port)).Distinct()
            : targets.Hosts.SelectMany(Expand).Distinct(StringComparer.OrdinalIgnoreCase);

    public static string EndpointKey(string address, int port) => $"{address.ToLowerInvariant()}:{port}";

    private static IPAddress Mask(IPAddress address, int prefix)
    {
        var bytes = address.GetAddressBytes();
        for (var i = 0; i < bytes.Length; i++)
        {
            var keep = Math.Clamp(prefix - i * 8, 0, 8);
            bytes[i] &= (byte)(0xFF << (8 - keep));
        }
        return new IPAddress(bytes);
    }

    private static UInt128 ToNumber(IPAddress ip) => (UInt128)new BigInteger(ip.GetAddressBytes(), isUnsigned: true, isBigEndian: true);

    private static IPAddress ToAddress(UInt128 value, AddressFamily family)
    {
        var length = family == AddressFamily.InterNetwork ? 4 : 16;
        var bytes = new byte[length];
        for (var i = length - 1; i >= 0; i--) { bytes[i] = (byte)(value & 0xFF); value >>= 8; }
        return new IPAddress(bytes);
    }

    [GeneratedRegex(@"^(?=.{1,253}$)(\*\.)?([a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?$")]
    private static partial Regex HostnameRegex();
}
