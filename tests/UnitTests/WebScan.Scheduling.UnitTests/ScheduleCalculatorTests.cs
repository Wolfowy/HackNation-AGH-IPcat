using WebScan.Server.Modules.Scheduling;
using WebScan.Server.Modules.Scheduling.Persistence;

namespace WebScan.Scheduling.UnitTests;

public sealed class ScheduleCalculatorTests
{
    private static readonly TimeZoneInfo Warsaw = ScheduleCalculator.FindTimeZone("Europe/Warsaw")!;
    private static readonly AllowedWindow MondayNight = new([DayOfWeek.Monday], "22:00", "06:00");

    private static DateTimeOffset Utc(string iso) => DateTimeOffset.Parse(iso, System.Globalization.CultureInfo.InvariantCulture);

    [Theory]
    [InlineData("2026-11-23T22:00:00Z", true, "2026-11-24T05:00:00Z")]  // Mon 23:00 CET
    [InlineData("2026-11-24T04:00:00Z", true, "2026-11-24T05:00:00Z")]  // Tue 05:00, window started Monday
    [InlineData("2026-11-23T20:59:00Z", false, null)]                   // Mon 21:59
    [InlineData("2026-11-24T06:00:00Z", false, null)]                   // Tue 07:00
    [InlineData("2026-11-24T22:00:00Z", false, null)]                   // Tue 23:00 (Tuesday not allowed)
    [InlineData("2026-11-22T22:00:00Z", false, null)]                   // Sun 23:00
    public void Window_crossing_midnight_in_the_schedule_time_zone(string instant, bool inside, string? end)
    {
        Assert.Equal(inside, ScheduleCalculator.IsInsideWindows([MondayNight], Warsaw, Utc(instant), out var windowEnd));
        Assert.Equal(end is null ? null : Utc(end), windowEnd);
    }

    [Theory]
    [InlineData("2026-11-23T22:00:00Z", "2026-11-30T21:00:00Z")] // inside Monday's window: next Monday 22:00 CET
    [InlineData("2026-11-24T05:00:00Z", "2026-11-30T21:00:00Z")] // window end (Tue 06:00 CET)
    [InlineData("2026-11-22T12:00:00Z", "2026-11-23T21:00:00Z")] // Sunday: the coming Monday
    public void Next_window_start_is_the_next_allowed_window_opening(string after, string expected) =>
        Assert.Equal(Utc(expected), ScheduleCalculator.NextWindowStart([MondayNight], Warsaw, Utc(after)));

    [Fact]
    public void Next_window_start_picks_the_earliest_of_several_windows_and_needs_windows()
    {
        var weekday = new AllowedWindow([DayOfWeek.Tuesday, DayOfWeek.Wednesday], "01:00", "04:00");
        Assert.Equal(Utc("2026-11-24T00:00:00Z"), ScheduleCalculator.NextWindowStart([MondayNight, weekday], Warsaw, Utc("2026-11-23T22:00:00Z")));
        Assert.Null(ScheduleCalculator.NextWindowStart([], Warsaw, Utc("2026-11-23T22:00:00Z")));
    }

    [Fact]
    public void No_windows_means_always_allowed_and_unbounded()
    {
        Assert.True(ScheduleCalculator.IsInsideWindows([], Warsaw, Utc("2026-11-24T12:00:00Z"), out var end));
        Assert.Null(end);
    }

    [Fact]
    public void Other_time_zones_use_their_own_offsets()
    {
        var newYork = ScheduleCalculator.FindTimeZone("America/New_York")!;
        Assert.True(ScheduleCalculator.IsInsideWindows([new([DayOfWeek.Monday], "09:00", "17:00")], newYork, Utc("2026-11-23T14:00:00Z"), out var end));
        Assert.Equal(Utc("2026-11-23T22:00:00Z"), end);
    }

    [Fact]
    public void Window_end_inside_a_dst_gap_moves_past_the_gap()
    {
        // 29 March 2026, Warsaw jumps 02:00 CET → 03:00 CEST; a window ending 02:30 ends at 03:00 CEST = 01:00Z.
        var window = new AllowedWindow(Enum.GetValues<DayOfWeek>(), "01:00", "02:30");
        Assert.True(ScheduleCalculator.IsInsideWindows([window], Warsaw, Utc("2026-03-29T00:30:00Z"), out var end));
        Assert.Equal(Utc("2026-03-29T01:00:00Z"), end);
    }

    [Fact]
    public void Scan_window_end_is_the_earlier_of_window_end_and_duration()
    {
        var fire = Utc("2026-11-23T22:00:00Z");
        var windowEnd = Utc("2026-11-24T05:00:00Z");
        Assert.Equal(fire.AddMinutes(30), ScheduleCalculator.NotAfter(fire, windowEnd, 30));
        Assert.Equal(windowEnd, ScheduleCalculator.NotAfter(fire, windowEnd, 600));
        Assert.Equal(windowEnd, ScheduleCalculator.NotAfter(fire, windowEnd, null));
        Assert.Null(ScheduleCalculator.NotAfter(fire, null, null));
    }

    [Fact]
    public void Next_fire_skips_cron_times_outside_the_windows()
    {
        const string hourly = "0 0 * * * ?";
        Assert.Equal(Utc("2026-11-23T21:00:00Z"), ScheduleCalculator.NextFire(hourly, Warsaw, [MondayNight], Utc("2026-11-23T11:00:00Z")));
        Assert.Equal(Utc("2026-11-30T21:00:00Z"), ScheduleCalculator.NextFire(hourly, Warsaw, [MondayNight], Utc("2026-11-24T05:30:00Z")));
        Assert.Equal(Utc("2026-11-23T12:00:00Z"), ScheduleCalculator.NextFire(hourly, Warsaw, [], Utc("2026-11-23T11:00:00Z")));
        // Daily 02:00 local: winter offset +1.
        Assert.Equal(Utc("2026-11-24T01:00:00Z"), ScheduleCalculator.NextFire("0 0 2 * * ?", Warsaw, [], Utc("2026-11-23T12:00:00Z")));
    }

    [Fact]
    public void Invalid_time_zones_and_windows_are_reported()
    {
        Assert.Null(ScheduleCalculator.FindTimeZone("Mars/Olympus_Mons"));
        var errors = ScheduleCalculator.ValidateWindows([new([], "22:00", "06:00"), new([DayOfWeek.Friday], "25:00", "6")]);
        Assert.Contains(errors, e => e.Contains("daysOfWeek"));
        Assert.Contains(errors, e => e.Contains("HH:mm"));
    }
}
