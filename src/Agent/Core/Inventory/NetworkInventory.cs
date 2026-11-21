using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Numerics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WebScan.Agent.Tools.Abstractions;
using WebScan.Contracts;

namespace WebScan.Agent.Inventory;

/// <summary>
/// Interfaces, routes, OS and resources of the agent host, reported at registration. <c>Agent:StaticInterfaces</c> /
/// <c>Agent:StaticRoutes</c> replace detection (simulated agents, multi-perspective demos).
/// </summary>
public sealed class NetworkInventory(IOptionsMonitor<AgentOptions> options, IToolProcessRunner processRunner, ILogger<NetworkInventory> logger)
{
    private readonly Lock _cpuLock = new();
    private (ulong Busy, ulong Total)? _lastSystemCpu;
    private (TimeSpan Cpu, DateTime At)? _lastProcessCpu;

    public IReadOnlyList<NetworkInterfaceInfo> GetInterfaces()
    {
        var o = options.CurrentValue;
        IEnumerable<NetworkInterfaceInfo> interfaces = o.StaticInterfaces.Count > 0
            ? o.StaticInterfaces.Select(s => new NetworkInterfaceInfo
            {
                Name = s.Name, Description = s.Description, MacAddress = s.MacAddress, IsUp = s.IsUp, Addresses = [.. s.Addresses], SpeedMbps = s.SpeedMbps,
            })
            : DetectInterfaces();
        if (o.Interfaces.Include.Count > 0) interfaces = interfaces.Where(i => o.Interfaces.Include.Contains(i.Name, StringComparer.Ordinal));
        return [.. interfaces.Where(i => !o.Interfaces.Exclude.Contains(i.Name, StringComparer.Ordinal)).OrderBy(i => i.Name, StringComparer.Ordinal)];
    }

    public async Task<IReadOnlyList<RouteInfo>> GetRoutesAsync(CancellationToken ct)
    {
        var o = options.CurrentValue;
        if (o.StaticRoutes.Count > 0)
            return [.. o.StaticRoutes.Select(r => new RouteInfo { Destination = r.Destination, Gateway = r.Gateway, InterfaceName = r.InterfaceName, Metric = r.Metric })];
        if (o.StaticInterfaces.Count > 0) return []; // simulated agent: never mix in the host's real routes

        try
        {
            IReadOnlyList<RouteInfo> routes = [];
            if (OperatingSystem.IsLinux())
                routes = [.. ParseLinuxRoutes(ReadIfExists("/proc/net/route")), .. ParseLinuxIpv6Routes(ReadIfExists("/proc/net/ipv6_route"))];
            else if (OperatingSystem.IsMacOS() && File.Exists("/usr/sbin/netstat"))
                routes = ParseNetstat(await RunNetstatAsync(ct));
            var names = GetInterfaces().Select(i => i.Name).ToHashSet(StringComparer.Ordinal);
            return [.. routes.Where(r => names.Contains(r.InterfaceName))];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            logger.LogWarning(ex, "Route detection failed; reporting no routes.");
            return [];
        }
    }

    public static (string Platform, string Description) OperatingSystemInfo() =>
        (OperatingSystem.IsLinux() ? "linux" : OperatingSystem.IsWindows() ? "windows" : OperatingSystem.IsMacOS() ? "osx" : RuntimeInformation.OSDescription.ToLowerInvariant(),
         RuntimeInformation.OSDescription);

    public static AgentResources Resources() => new()
    {
        CpuCores = Environment.ProcessorCount,
        MemoryTotalMb = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / (1024 * 1024),
    };

    /// <summary>CPU % since the previous call (system-wide on Linux, this process elsewhere) and used memory.</summary>
    public (double CpuPercent, long MemoryUsedMb) SampleLoad()
    {
        double cpu = 0;
        lock (_cpuLock)
        {
            if (OperatingSystem.IsLinux() && ReadIfExists("/proc/stat").Split('\n').FirstOrDefault() is { } line && line.StartsWith("cpu ", StringComparison.Ordinal))
            {
                var values = line.Split(' ', StringSplitOptions.RemoveEmptyEntries).Skip(1).Select(v => ulong.Parse(v, CultureInfo.InvariantCulture)).ToArray();
                var idle = values[3] + (values.Length > 4 ? values[4] : 0);
                var total = values.Aggregate(0UL, (a, b) => a + b);
                if (_lastSystemCpu is { } last && total > last.Total) cpu = 100.0 * ((total - idle) - last.Busy) / (total - last.Total);
                _lastSystemCpu = (total - idle, total);
            }
            else
            {
                var now = DateTime.UtcNow;
                var used = System.Diagnostics.Process.GetCurrentProcess().TotalProcessorTime;
                if (_lastProcessCpu is { } last && now > last.At)
                    cpu = 100.0 * (used - last.Cpu).TotalMilliseconds / ((now - last.At).TotalMilliseconds * Environment.ProcessorCount);
                _lastProcessCpu = (used, now);
            }
        }

        long memoryUsed;
        var meminfo = OperatingSystem.IsLinux() ? ReadIfExists("/proc/meminfo") : "";
        long Kb(string key) => meminfo.Split('\n').FirstOrDefault(l => l.StartsWith(key + ":", StringComparison.Ordinal)) is { } l
            ? long.Parse(l.Split(' ', StringSplitOptions.RemoveEmptyEntries)[1], CultureInfo.InvariantCulture) : 0;
        if (meminfo.Length > 0) memoryUsed = (Kb("MemTotal") - Kb("MemAvailable")) / 1024;
        else memoryUsed = Environment.WorkingSet / (1024 * 1024);
        return (Math.Round(Math.Clamp(cpu, 0, 100), 1), memoryUsed);
    }

    private static IEnumerable<NetworkInterfaceInfo> DetectInterfaces()
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            var addresses = nic.GetIPProperties().UnicastAddresses
                .Select(a => $"{new IPAddress(a.Address.GetAddressBytes())}/{a.PrefixLength}") // drops IPv6 scope ids
                .ToList();
            if (addresses.Count == 0) continue;
            var mac = nic.GetPhysicalAddress().GetAddressBytes();
            long? speed = null;
            try { speed = nic.Speed > 0 ? nic.Speed / 1_000_000 : null; } catch (PlatformNotSupportedException) { }
            yield return new NetworkInterfaceInfo
            {
                Name = nic.Name,
                Description = nic.Description,
                MacAddress = mac.Length == 6 ? string.Join(":", mac.Select(b => b.ToString("X2"))) : null,
                IsUp = nic.OperationalStatus == OperationalStatus.Up,
                Addresses = addresses,
                SpeedMbps = speed,
            };
        }
    }

    /// <summary><c>/proc/net/route</c>: little-endian hex IPv4 destination/gateway/mask.</summary>
    internal static IEnumerable<RouteInfo> ParseLinuxRoutes(string content)
    {
        foreach (var line in content.Split('\n').Skip(1))
        {
            var f = line.Split((char[])['\t', ' '], StringSplitOptions.RemoveEmptyEntries);
            if (f.Length < 8 || f[0] == "lo") continue;
            var flags = int.Parse(f[3], NumberStyles.HexNumber);
            if ((flags & 0x1) == 0) continue; // RTF_UP
            var destination = new IPAddress(uint.Parse(f[1], NumberStyles.HexNumber));
            var gateway = uint.Parse(f[2], NumberStyles.HexNumber);
            var prefix = BitOperations.PopCount(uint.Parse(f[7], NumberStyles.HexNumber));
            yield return new RouteInfo
            {
                Destination = $"{destination}/{prefix}",
                Gateway = gateway == 0 ? null : new IPAddress(gateway).ToString(),
                InterfaceName = f[0],
                Metric = int.Parse(f[6], CultureInfo.InvariantCulture),
            };
        }
    }

    /// <summary><c>/proc/net/ipv6_route</c>: dest prefix src srcprefix nexthop metric refcnt use flags iface.</summary>
    internal static IEnumerable<RouteInfo> ParseLinuxIpv6Routes(string content)
    {
        foreach (var line in content.Split('\n'))
        {
            var f = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (f.Length < 10 || f[9] == "lo") continue;
            var flags = int.Parse(f[8], NumberStyles.HexNumber);
            if ((flags & 0x1) == 0 || (flags & 0x200) != 0) continue; // RTF_UP, skip RTF_REJECT
            var gateway = new IPAddress(Convert.FromHexString(f[4]));
            yield return new RouteInfo
            {
                Destination = $"{new IPAddress(Convert.FromHexString(f[0]))}/{int.Parse(f[1], NumberStyles.HexNumber)}",
                Gateway = gateway.Equals(IPAddress.IPv6Any) ? null : gateway.ToString(),
                InterfaceName = f[9],
                Metric = (int)Math.Min(uint.Parse(f[5], NumberStyles.HexNumber), int.MaxValue),
            };
        }
    }

    /// <summary>macOS <c>netstat -rn</c> (Internet and Internet6 sections).</summary>
    internal static IReadOnlyList<RouteInfo> ParseNetstat(string output)
    {
        var routes = new List<RouteInfo>();
        AddressFamily? family = null;
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            if (line == "Internet:") { family = AddressFamily.InterNetwork; continue; }
            if (line == "Internet6:") { family = AddressFamily.InterNetworkV6; continue; }
            var f = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (family is null || f.Length < 4 || f[0] == "Destination") continue;
            var netif = f[3];
            if (netif.StartsWith("lo", StringComparison.Ordinal) || NetstatDestination(f[0], f[2], family.Value) is not { } destination) continue;
            var gateway = StripScope(f[1]);
            routes.Add(new RouteInfo
            {
                Destination = destination,
                Gateway = IPAddress.TryParse(gateway, out var gw) ? gw.ToString() : null, // "link#11" / MAC = directly connected
                InterfaceName = netif,
            });
        }
        return routes;
    }

    private static string? NetstatDestination(string dest, string flags, AddressFamily family)
    {
        if (dest == "default") return family == AddressFamily.InterNetwork ? "0.0.0.0/0" : "::/0";
        var parts = StripScope(dest).Split('/');
        if (family == AddressFamily.InterNetworkV6)
            return IPAddress.TryParse(parts[0], out var v6) ? $"{v6}/{(parts.Length > 1 ? parts[1] : "128")}" : null;

        var octets = parts[0].Split('.');
        if (octets.Length is < 1 or > 4 || !octets.All(o => byte.TryParse(o, out _))) return null;
        var address = string.Join(".", octets.Concat(Enumerable.Repeat("0", 4 - octets.Length)));
        var prefix = parts.Length > 1 ? parts[1] : (octets.Length == 4 && flags.Contains('H') ? "32" : (octets.Length * 8).ToString(CultureInfo.InvariantCulture));
        return $"{address}/{prefix}";
    }

    private static string StripScope(string value)
    {
        var percent = value.IndexOf('%');
        if (percent < 0) return value;
        var slash = value.IndexOf('/', percent);
        return value[..percent] + (slash >= 0 ? value[slash..] : "");
    }

    private async Task<string> RunNetstatAsync(CancellationToken ct)
    {
        var dir = Directory.CreateTempSubdirectory("webscan-netstat-").FullName;
        try
        {
            var result = await processRunner.RunAsync(new ProcessRunRequest
            {
                Executable = "/usr/sbin/netstat", Arguments = ["-rn"], WorkingDirectory = dir, Timeout = TimeSpan.FromSeconds(10),
            }, ct);
            return result.StdoutTail ?? "";
        }
        finally { Tools.ToolRegistry.TryDeleteDirectory(dir); }
    }

    private static string ReadIfExists(string path) => File.Exists(path) ? File.ReadAllText(path) : "";
}
