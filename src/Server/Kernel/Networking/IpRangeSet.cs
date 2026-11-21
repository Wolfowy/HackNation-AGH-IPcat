using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Text.RegularExpressions;

namespace WebScan.Server.Kernel.Networking;

public enum TargetEntryKind
{
    Invalid,
    Address,
    Cidr,
    Range,
    Hostname,
}

/// <summary>Inclusive address interval within one address family.</summary>
public readonly record struct IpRange(AddressFamily Family, UInt128 Start, UInt128 End)
{
    public int Bits => Family == AddressFamily.InterNetwork ? 32 : 128;
    public UInt128 Count => End - Start + 1; // wraps to 0 only for the full IPv6 space
    public override string ToString() => Start == End ? IpRangeSet.ToAddress(Family, Start).ToString()
        : $"{IpRangeSet.ToAddress(Family, Start)}-{IpRangeSet.ToAddress(Family, End)}";
}

/// <summary>
/// Normalized (sorted, merged) set of IPv4/IPv6 intervals. Parses "10.0.0.1", "10.0.0.0/24", "10.0.0.5-10.0.0.20",
/// IPv6 equivalents; supports union, subtraction (exclusions), containment and CIDR-aligned batch splitting.
/// Hostnames are not part of the set — classify them with <see cref="Classify"/>.
/// </summary>
public sealed partial class IpRangeSet
{
    private readonly List<IpRange> _ranges;

    public IpRangeSet() => _ranges = [];
    private IpRangeSet(List<IpRange> normalized) => _ranges = normalized;

    public IReadOnlyList<IpRange> Ranges => _ranges;
    public bool IsEmpty => _ranges.Count == 0;

    /// <summary>Total number of addresses (saturates at UInt128.MaxValue).</summary>
    public UInt128 Count
    {
        get
        {
            UInt128 total = 0;
            foreach (var r in _ranges)
            {
                var c = r.Count;
                if (c == 0 || UInt128.MaxValue - total < c) return UInt128.MaxValue;
                total += c;
            }
            return total;
        }
    }

    [GeneratedRegex(@"^(?=.{1,253}$)(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\.?$")]
    private static partial Regex HostnameRegex();

    public static TargetEntryKind Classify(string? entry)
    {
        if (string.IsNullOrWhiteSpace(entry)) return TargetEntryKind.Invalid;
        entry = entry.Trim();
        if (TryParseRange(entry, out _, out var kind)) return kind;
        return HostnameRegex().IsMatch(entry) ? TargetEntryKind.Hostname : TargetEntryKind.Invalid;
    }

    public static bool TryParseRange(string entry, out IpRange range) => TryParseRange(entry, out range, out _);

    private static bool TryParseRange(string entry, out IpRange range, out TargetEntryKind kind)
    {
        range = default;
        kind = TargetEntryKind.Invalid;
        entry = entry.Trim();

        var slash = entry.IndexOf('/');
        if (slash > 0)
        {
            if (!IPAddress.TryParse(entry[..slash], out var baseAddr)) return false;
            if (!int.TryParse(entry[(slash + 1)..], out var prefix)) return false;
            baseAddr = Normalize(baseAddr);
            var bits = baseAddr.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            if (prefix < 0 || prefix > bits) return false;
            var value = ToUInt128(baseAddr);
            var hostBits = bits - prefix;
            var mask = hostBits == 128 ? UInt128.MaxValue : (UInt128.One << hostBits) - 1;
            var start = value & ~mask;
            if (bits == 32) start &= uint.MaxValue;
            range = new IpRange(baseAddr.AddressFamily, start, start | mask);
            kind = TargetEntryKind.Cidr;
            return true;
        }

        var dash = entry.IndexOf('-');
        if (dash > 0 && IPAddress.TryParse(entry[..dash], out var a) && IPAddress.TryParse(entry[(dash + 1)..], out var b))
        {
            a = Normalize(a);
            b = Normalize(b);
            if (a.AddressFamily != b.AddressFamily) return false;
            var (s, e) = (ToUInt128(a), ToUInt128(b));
            if (e < s) return false;
            range = new IpRange(a.AddressFamily, s, e);
            kind = TargetEntryKind.Range;
            return true;
        }

        if (IPAddress.TryParse(entry, out var single) && !entry.Contains('-'))
        {
            single = Normalize(single);
            var v = ToUInt128(single);
            range = new IpRange(single.AddressFamily, v, v);
            kind = TargetEntryKind.Address;
            return true;
        }

        return false;
    }

    /// <summary>Parses IP/CIDR/range entries; throws <see cref="FormatException"/> on anything else (incl. hostnames).</summary>
    public static IpRangeSet Parse(IEnumerable<string> entries)
    {
        var list = new List<IpRange>();
        foreach (var e in entries)
        {
            if (!TryParseRange(e, out var r)) throw new FormatException($"'{e}' is not an IP address, CIDR or range.");
            list.Add(r);
        }
        return new IpRangeSet(Merge(list));
    }

    public static IpRangeSet FromRanges(IEnumerable<IpRange> ranges) => new(Merge(ranges.ToList()));

    public IpRangeSet Union(IpRangeSet other) => new(Merge([.. _ranges, .. other._ranges]));

    public IpRangeSet Subtract(IpRangeSet other)
    {
        var result = new List<IpRange>();
        foreach (var r in _ranges)
        {
            var pieces = new List<IpRange> { r };
            foreach (var x in other._ranges.Where(x => x.Family == r.Family && x.End >= r.Start && x.Start <= r.End))
            {
                var next = new List<IpRange>();
                foreach (var p in pieces)
                {
                    if (x.End < p.Start || x.Start > p.End) { next.Add(p); continue; }
                    if (x.Start > p.Start) next.Add(p with { End = x.Start - 1 });
                    if (x.End < p.End) next.Add(p with { Start = x.End + 1 });
                }
                pieces = next;
            }
            result.AddRange(pieces);
        }
        return new IpRangeSet(Merge(result));
    }

    public IpRangeSet Intersect(IpRangeSet other) => Subtract(Subtract(other));

    public bool Contains(IPAddress address)
    {
        address = Normalize(address);
        var v = ToUInt128(address);
        return _ranges.Any(r => r.Family == address.AddressFamily && r.Start <= v && v <= r.End);
    }

    public bool Contains(IpRange range) =>
        _ranges.Any(r => r.Family == range.Family && r.Start <= range.Start && range.End <= r.End);

    /// <summary>True when every address of <paramref name="other"/> is in this set.</summary>
    public bool IsSupersetOf(IpRangeSet other) => other.Subtract(this).IsEmpty;

    public bool Overlaps(IpRangeSet other) => !Intersect(other).IsEmpty;

    /// <summary>Minimal list of CIDR blocks exactly covering the set.</summary>
    public IEnumerable<string> ToCidrs() =>
        _ranges.SelectMany(ToBlocks).Select(b => FormatBlock(b.Family, b.Start, b.PrefixLength));

    /// <summary>
    /// Splits the set into batches of at most <paramref name="maxAddresses"/> addresses (rounded down to a power of two),
    /// each batch a list of CIDR-aligned blocks. Deterministic: same set + size → same batches.
    /// </summary>
    public IEnumerable<IReadOnlyList<string>> SplitIntoBatches(int maxAddresses)
    {
        if (maxAddresses < 1) throw new ArgumentOutOfRangeException(nameof(maxAddresses));
        var batchBits = BitOperations.Log2((uint)maxAddresses);
        var batchSize = UInt128.One << batchBits;

        var current = new List<string>();
        UInt128 currentCount = 0;
        foreach (var range in _ranges)
        {
            foreach (var block in ToBlocks(range))
            {
                var bits = range.Bits;
                var blockHostBits = bits - block.PrefixLength;
                if (blockHostBits > batchBits)
                {
                    // Large block: emit full sub-blocks of batchSize directly (it is aligned by construction).
                    if (current.Count > 0) { yield return current; current = []; currentCount = 0; }
                    var subPrefix = bits - batchBits;
                    var subCount = UInt128.One << (blockHostBits - batchBits);
                    for (UInt128 i = 0; i < subCount; i++)
                        yield return [FormatBlock(block.Family, block.Start + i * batchSize, subPrefix)];
                    continue;
                }

                var size = UInt128.One << blockHostBits;
                if (currentCount + size > batchSize) { yield return current; current = []; currentCount = 0; }
                current.Add(FormatBlock(block.Family, block.Start, block.PrefixLength));
                currentCount += size;
            }
        }
        if (current.Count > 0) yield return current;
    }

    public override string ToString() => string.Join(", ", _ranges);

    // ---- helpers ----

    private readonly record struct Block(AddressFamily Family, UInt128 Start, int PrefixLength);

    private static IEnumerable<Block> ToBlocks(IpRange range)
    {
        var bits = range.Bits;
        var max = bits == 32 ? (UInt128)uint.MaxValue : UInt128.MaxValue;
        var s = range.Start;
        while (true)
        {
            var hostBits = s == 0 ? bits : Math.Min(bits, (int)UInt128.TrailingZeroCount(s));
            while (hostBits > 0 && (hostBits == 128 ? max : s + ((UInt128.One << hostBits) - 1)) > range.End) hostBits--;
            var blockEnd = hostBits == 128 ? max : s + ((UInt128.One << hostBits) - 1);
            yield return new Block(range.Family, s, bits - hostBits);
            if (blockEnd >= range.End) yield break;
            s = blockEnd + 1;
        }
    }

    private static string FormatBlock(AddressFamily family, UInt128 start, int prefix)
    {
        var bits = family == AddressFamily.InterNetwork ? 32 : 128;
        var addr = ToAddress(family, start).ToString();
        return prefix == bits ? addr : $"{addr}/{prefix}";
    }

    private static List<IpRange> Merge(List<IpRange> ranges)
    {
        ranges.Sort((x, y) => x.Family != y.Family ? x.Family.CompareTo(y.Family) : x.Start.CompareTo(y.Start));
        var merged = new List<IpRange>();
        foreach (var r in ranges)
        {
            if (merged.Count > 0)
            {
                var last = merged[^1];
                if (last.Family == r.Family && (last.End == UInt128.MaxValue || r.Start <= last.End + 1))
                {
                    if (r.End > last.End) merged[^1] = last with { End = r.End };
                    continue;
                }
            }
            merged.Add(r);
        }
        return merged;
    }

    public static IPAddress Normalize(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    public static UInt128 ToUInt128(IPAddress address)
    {
        Span<byte> bytes = stackalloc byte[16];
        address.TryWriteBytes(bytes, out var written);
        UInt128 v = 0;
        for (var i = 0; i < written; i++) v = (v << 8) | bytes[i];
        return v;
    }

    public static IPAddress ToAddress(AddressFamily family, UInt128 value)
    {
        var len = family == AddressFamily.InterNetwork ? 4 : 16;
        var bytes = new byte[len];
        for (var i = len - 1; i >= 0; i--) { bytes[i] = (byte)(value & 0xFF); value >>= 8; }
        return new IPAddress(bytes);
    }
}
