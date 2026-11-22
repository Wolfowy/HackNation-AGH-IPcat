using System.Globalization;
using Quartz;
using WebScan.Server.Modules.Scheduling.Persistence;

namespace WebScan.Server.Modules.Scheduling;

/// <summary>Pure schedule math: cron (Quartz syntax) in an IANA time zone, allowed windows (possibly crossing midnight), scan window end.</summary>
public static class ScheduleCalculator
{
    public static TimeZoneInfo? FindTimeZone(string? id)
    {
        if (string.IsNullOrWhiteSpace(id)) return null;
        try { return TimeZoneInfo.FindSystemTimeZoneById(id); }
        catch (Exception ex) when (ex is TimeZoneNotFoundException or InvalidTimeZoneException) { return null; }
    }

    public static bool TryParseTime(string? hhmm, out TimeSpan time) =>
        TimeSpan.TryParseExact(hhmm, @"hh\:mm", CultureInfo.InvariantCulture, out time) && time < TimeSpan.FromDays(1);

    public static IReadOnlyList<string> ValidateWindows(IReadOnlyList<AllowedWindow>? windows)
    {
        var errors = new List<string>();
        foreach (var (w, i) in (windows ?? []).Select((w, i) => (w, i)))
        {
            if (w is null) { errors.Add($"allowedWindows[{i}] must not be null."); continue; }
            if (w.DaysOfWeek is null || w.DaysOfWeek.Count == 0 || w.DaysOfWeek.Any(d => !Enum.IsDefined(d)))
                errors.Add($"allowedWindows[{i}].daysOfWeek must list at least one valid day.");
            if (!TryParseTime(w.Start, out _) || !TryParseTime(w.End, out _))
                errors.Add($"allowedWindows[{i}] start/end must be HH:mm.");
        }
        return errors;
    }

    /// <summary>
    /// True when <paramref name="instant"/> lies inside an allowed window (always true without windows).
    /// <paramref name="windowEnd"/> is the end of the containing window (latest one if several overlap), null without windows.
    /// </summary>
    public static bool IsInsideWindows(IReadOnlyList<AllowedWindow> windows, TimeZoneInfo zone, DateTimeOffset instant, out DateTimeOffset? windowEnd)
    {
        windowEnd = null;
        if (windows.Count == 0) return true;
        var local = TimeZoneInfo.ConvertTime(instant, zone);
        var date = local.Date;
        var timeOfDay = local.TimeOfDay;
        var inside = false;
        foreach (var w in windows)
        {
            if (!TryParseTime(w.Start, out var start) || !TryParseTime(w.End, out var end)) continue;
            DateTime? endLocal = null;
            if (start < end)
            {
                if (w.DaysOfWeek.Contains(local.DayOfWeek) && timeOfDay >= start && timeOfDay < end) endLocal = date + end;
            }
            else // crosses midnight (start == end: a 24h window)
            {
                if (w.DaysOfWeek.Contains(local.DayOfWeek) && timeOfDay >= start) endLocal = date.AddDays(1) + end;
                else if (w.DaysOfWeek.Contains(date.AddDays(-1).DayOfWeek) && timeOfDay < end) endLocal = date + end;
            }
            if (endLocal is null) continue;
            var endInstant = ToInstant(endLocal.Value, zone);
            if (!inside || endInstant > windowEnd) windowEnd = endInstant;
            inside = true;
        }
        return inside;
    }

    /// <summary>Scan window end for a fire: min(end of the allowed window, fire + window duration); null = unbounded.</summary>
    public static DateTimeOffset? NotAfter(DateTimeOffset fireTime, DateTimeOffset? windowEnd, int? windowDurationMinutes)
    {
        var byDuration = windowDurationMinutes is { } m ? fireTime.AddMinutes(m) : (DateTimeOffset?)null;
        if (windowEnd is null) return byDuration;
        if (byDuration is null) return windowEnd;
        return windowEnd < byDuration ? windowEnd : byDuration;
    }

    /// <summary>Next cron fire after <paramref name="after"/> that falls inside an allowed window (null if none soon).</summary>
    public static DateTimeOffset? NextFire(string cronExpression, TimeZoneInfo zone, IReadOnlyList<AllowedWindow> windows, DateTimeOffset after, int maxCandidates = 20_000)
    {
        var cron = new CronExpression(cronExpression) { TimeZone = zone };
        var candidate = after;
        for (var i = 0; i < maxCandidates; i++)
        {
            var next = cron.GetNextValidTimeAfter(candidate);
            if (next is null) return null;
            if (IsInsideWindows(windows, zone, next.Value, out _)) return next.Value.ToUniversalTime();
            candidate = next.Value;
        }
        return null;
    }

    /// <summary>Earliest start of an allowed window strictly after <paramref name="after"/> (null without windows).</summary>
    public static DateTimeOffset? NextWindowStart(IReadOnlyList<AllowedWindow> windows, TimeZoneInfo zone, DateTimeOffset after)
    {
        var today = TimeZoneInfo.ConvertTime(after, zone).Date;
        DateTimeOffset? next = null;
        for (var d = 0; d <= 7; d++)
            foreach (var w in windows)
            {
                var day = today.AddDays(d);
                if (!w.DaysOfWeek.Contains(day.DayOfWeek) || !TryParseTime(w.Start, out var start)) continue;
                var instant = ToInstant(day + start, zone);
                if (instant > after && (next is null || instant < next)) next = instant;
            }
        return next;
    }

    /// <summary>Local wall-clock time to an instant; a time skipped by a DST jump moves forward by the gap.</summary>
    private static DateTimeOffset ToInstant(DateTime local, TimeZoneInfo zone)
    {
        local = DateTime.SpecifyKind(local, DateTimeKind.Unspecified);
        while (zone.IsInvalidTime(local)) local = local.AddMinutes(30);
        return new DateTimeOffset(local, zone.GetUtcOffset(local)).ToUniversalTime();
    }
}
