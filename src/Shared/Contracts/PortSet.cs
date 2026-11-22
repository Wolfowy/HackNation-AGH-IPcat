using System.Globalization;

namespace WebScan.Contracts;

/// <summary>
/// Immutable set of port numbers (1-65535) as sorted, merged ranges. Used for the scope policy's port allowlist/denylist:
/// the server clips port parameters and endpoints to it, the agent re-checks <see cref="ScanJob.AuthorizedPorts"/>.
/// </summary>
public sealed class PortSet
{
    public const int MinPort = 1;
    public const int MaxPort = 65535;

    public static readonly PortSet All = new([(MinPort, MaxPort)]);
    public static readonly PortSet Empty = new([]);

    private readonly (int From, int To)[] _ranges;

    private PortSet((int From, int To)[] ranges) => _ranges = ranges;

    public IReadOnlyList<(int From, int To)> Ranges => _ranges;
    public bool IsEmpty => _ranges.Length == 0;
    public bool IsAll => _ranges is [(MinPort, MaxPort)];
    public int Count => _ranges.Sum(r => r.To - r.From + 1);

    public static PortSet FromPorts(IEnumerable<int> ports) => Normalize(ports.Select(p => (p, p)));

    /// <summary>One item: "80" or "8000-8100" (no "top-N", no lists).</summary>
    public static bool TryParseItem(string? item, out (int From, int To) range)
    {
        range = default;
        if (string.IsNullOrWhiteSpace(item)) return false;
        var parts = item.Trim().Split('-');
        if (parts.Length > 2 || !TryPort(parts[0], out var from)) return false;
        var to = from;
        if (parts.Length == 2 && !TryPort(parts[1], out to)) return false;
        if (to < from) return false;
        range = (from, to);
        return true;
    }

    /// <summary>Comma-separated items ("22,80,8000-8100"); "top-N" and empty specs are rejected (they cannot be checked).</summary>
    public static bool TryParse(string? spec, out PortSet set)
    {
        set = Empty;
        if (string.IsNullOrWhiteSpace(spec)) return false;
        var ranges = new List<(int, int)>();
        foreach (var item in spec.Split(','))
        {
            if (!TryParseItem(item, out var range)) return false;
            ranges.Add(range);
        }
        set = Normalize(ranges);
        return true;
    }

    /// <summary>Union of valid items; invalid items are ignored (input is validated at the API boundary).</summary>
    public static PortSet Parse(IEnumerable<string> items) =>
        Normalize(items.Select(i => TryParseItem(i, out var r) ? r : (0, -1)).Where(r => r.Item2 >= r.Item1));

    public bool Contains(int port)
    {
        foreach (var (from, to) in _ranges)
        {
            if (port < from) return false;
            if (port <= to) return true;
        }
        return false;
    }

    public bool ContainsAll(PortSet other) => other.Except(this).IsEmpty;

    public PortSet Intersect(PortSet other)
    {
        var result = new List<(int, int)>();
        int i = 0, j = 0;
        while (i < _ranges.Length && j < other._ranges.Length)
        {
            var (a, b) = (_ranges[i], other._ranges[j]);
            var from = Math.Max(a.From, b.From);
            var to = Math.Min(a.To, b.To);
            if (from <= to) result.Add((from, to));
            if (a.To < b.To) i++; else j++;
        }
        return new PortSet([.. result]);
    }

    public PortSet Except(PortSet other)
    {
        var result = new List<(int, int)>();
        foreach (var (from, to) in _ranges)
        {
            var start = from;
            foreach (var (xFrom, xTo) in other._ranges)
            {
                if (xTo < start || xFrom > to) continue;
                if (xFrom > start) result.Add((start, xFrom - 1));
                start = xTo + 1;
                if (start > to) break;
            }
            if (start <= to) result.Add((start, to));
        }
        return new PortSet([.. result]);
    }

    /// <summary>Port spec accepted by <see cref="ParameterValidator"/> ("22,80,8000-8100"); empty string for an empty set.</summary>
    public override string ToString() =>
        string.Join(",", _ranges.Select(r => r.From == r.To
            ? r.From.ToString(CultureInfo.InvariantCulture)
            : $"{r.From.ToString(CultureInfo.InvariantCulture)}-{r.To.ToString(CultureInfo.InvariantCulture)}"));

    private static bool TryPort(string value, out int port) =>
        int.TryParse(value.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out port) && port is >= MinPort and <= MaxPort;

    private static PortSet Normalize(IEnumerable<(int From, int To)> ranges)
    {
        var result = new List<(int From, int To)>();
        foreach (var r in ranges.OrderBy(r => r.From))
        {
            if (result.Count > 0 && r.From <= result[^1].To + 1) result[^1] = (result[^1].From, Math.Max(result[^1].To, r.To));
            else result.Add(r);
        }
        return new PortSet([.. result]);
    }
}

/// <summary>Port rules of the scope policy shared by planner and agent.</summary>
public static class PortScope
{
    /// <summary>Allowed (empty = every port) minus excluded.</summary>
    public static PortSet Effective(IEnumerable<string> allowed, IEnumerable<string> excluded)
    {
        var allowedList = allowed.ToList();
        return (allowedList.Count == 0 ? PortSet.All : PortSet.Parse(allowedList)).Except(PortSet.Parse(excluded));
    }

    /// <summary>
    /// Port-spec parameters that decide which ports a job touches: <c>ports</c>, and <c>probePorts</c> only for the TCP ping
    /// methods of host discovery (icmp/arp/none never use it).
    /// </summary>
    public static IEnumerable<string> ParametersInEffect(ScanOperation operation, IReadOnlyDictionary<string, string> values) =>
        OperationCatalog.Get(operation).Parameters
            .Where(p => p.Type == ParameterType.PortSpec && values.ContainsKey(p.Name))
            .Where(p => p.Name != "probePorts" || values.GetValueOrDefault("method") is null or "default" or "tcp-syn" or "tcp-ack")
            .Select(p => p.Name);
}
