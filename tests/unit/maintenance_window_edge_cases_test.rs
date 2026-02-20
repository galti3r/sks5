//! Edge case tests for MaintenanceWindowConfig::is_active() and parse_hhmm().
//!
//! Covers boundary conditions, malformed input, and all day-of-week variants.

use chrono::TimeZone;
use sks5::config::types::MaintenanceWindowConfig;

fn make_window(schedule: &str) -> MaintenanceWindowConfig {
    MaintenanceWindowConfig {
        schedule: schedule.to_string(),
        message: "test maintenance".to_string(),
        disconnect_existing: false,
    }
}

// ---------------------------------------------------------------------------
// 1. Midnight boundary and full-day windows
// ---------------------------------------------------------------------------

#[test]
fn daily_window_spanning_midnight_start_00_00() {
    let window = make_window("daily 00:00-06:00");
    let now = chrono::Utc.with_ymd_and_hms(2026, 2, 12, 3, 0, 0).unwrap();
    assert!(window.is_active(&now));
}

#[test]
fn daily_window_at_exactly_midnight() {
    let window = make_window("daily 00:00-01:00");
    let now = chrono::Utc.with_ymd_and_hms(2026, 2, 12, 0, 0, 0).unwrap();
    assert!(window.is_active(&now));
}

#[test]
fn daily_window_23_59_end_exclusive() {
    // Window from 23:00 to 23:59 -- at 23:59 it should still be active
    let window = make_window("daily 23:00-23:59");
    let at_23_58 = chrono::Utc
        .with_ymd_and_hms(2026, 2, 12, 23, 58, 0)
        .unwrap();
    assert!(window.is_active(&at_23_58));

    // At 23:59 it should still be active (23:59 < 23:59 is false -> not active)
    let at_23_59 = chrono::Utc
        .with_ymd_and_hms(2026, 2, 12, 23, 59, 0)
        .unwrap();
    assert!(!window.is_active(&at_23_59)); // end is exclusive
}

// ---------------------------------------------------------------------------
// 2. All weekday names (case insensitive)
// ---------------------------------------------------------------------------

#[test]
fn all_weekdays_case_insensitive() {
    // Feb 9=Mon, Feb 10=Tue, Feb 11=Wed, Feb 12=Thu, Feb 13=Fri, Feb 14=Sat, Feb 15=Sun (2026)
    let cases = vec![
        ("Mon 10:00-11:00", 2026, 2, 9),
        ("TUE 10:00-11:00", 2026, 2, 10),
        ("Wed 10:00-11:00", 2026, 2, 11),
        ("thu 10:00-11:00", 2026, 2, 12),
        ("FRI 10:00-11:00", 2026, 2, 13),
        ("Sat 10:00-11:00", 2026, 2, 14),
        ("SUN 10:00-11:00", 2026, 2, 15),
    ];

    for (schedule, year, month, day) in cases {
        let window = make_window(schedule);
        let now = chrono::Utc
            .with_ymd_and_hms(year, month, day, 10, 30, 0)
            .unwrap();
        assert!(
            window.is_active(&now),
            "Expected {} to be active on {}-{:02}-{:02} 10:30",
            schedule,
            year,
            month,
            day
        );
    }
}

#[test]
fn weekday_wrong_day_not_active() {
    // Tuesday Feb 10 should NOT match a Monday window
    let window = make_window("Mon 10:00-11:00");
    let tuesday = chrono::Utc
        .with_ymd_and_hms(2026, 2, 10, 10, 30, 0)
        .unwrap();
    assert!(!window.is_active(&tuesday));
}

// ---------------------------------------------------------------------------
// 3. Malformed schedule strings
// ---------------------------------------------------------------------------

#[test]
fn empty_schedule_not_active() {
    let window = make_window("");
    let now = chrono::Utc::now();
    assert!(!window.is_active(&now));
}

#[test]
fn schedule_with_only_day_no_time_range() {
    let window = make_window("daily");
    let now = chrono::Utc::now();
    assert!(!window.is_active(&now));
}

#[test]
fn schedule_missing_dash_in_time_range() {
    let window = make_window("daily 10:00+11:00");
    let now = chrono::Utc
        .with_ymd_and_hms(2026, 2, 12, 10, 30, 0)
        .unwrap();
    assert!(!window.is_active(&now));
}

#[test]
fn schedule_with_invalid_hour() {
    let window = make_window("daily 25:00-26:00");
    let now = chrono::Utc.with_ymd_and_hms(2026, 2, 12, 10, 0, 0).unwrap();
    assert!(!window.is_active(&now));
}

#[test]
fn schedule_with_invalid_minute() {
    let window = make_window("daily 10:60-11:00");
    let now = chrono::Utc
        .with_ymd_and_hms(2026, 2, 12, 10, 30, 0)
        .unwrap();
    assert!(!window.is_active(&now));
}

#[test]
fn schedule_with_non_numeric_time() {
    let window = make_window("daily ab:cd-ef:gh");
    let now = chrono::Utc::now();
    assert!(!window.is_active(&now));
}

#[test]
fn schedule_with_extra_spaces_in_time() {
    // The parser uses splitn(2, ' '), so "daily  10:00-11:00" should parse
    // day_spec="daily", time_range=" 10:00-11:00" which has leading space
    let window = make_window("daily  10:00-11:00");
    let now = chrono::Utc
        .with_ymd_and_hms(2026, 2, 12, 10, 30, 0)
        .unwrap();
    // The trim() in parse_hhmm should handle leading spaces
    assert!(window.is_active(&now));
}

#[test]
fn schedule_with_three_parts() {
    // "daily 10:00 11:00" -- splitn(2, ' ') gives ["daily", "10:00 11:00"]
    // Then split('-') on "10:00 11:00" gives only one part -- invalid
    let window = make_window("daily 10:00 11:00");
    let now = chrono::Utc
        .with_ymd_and_hms(2026, 2, 12, 10, 30, 0)
        .unwrap();
    assert!(!window.is_active(&now));
}

// ---------------------------------------------------------------------------
// 4. Boundary: start == end (zero-width window -- nothing should match)
// ---------------------------------------------------------------------------

#[test]
fn zero_width_window_never_active() {
    let window = make_window("daily 10:00-10:00");
    let at_10 = chrono::Utc.with_ymd_and_hms(2026, 2, 12, 10, 0, 0).unwrap();
    // 10:00 >= 10:00 && 10:00 < 10:00 -> false
    assert!(!window.is_active(&at_10));
}

// ---------------------------------------------------------------------------
// 5. One-minute window
// ---------------------------------------------------------------------------

#[test]
fn one_minute_window_active() {
    let window = make_window("daily 10:00-10:01");
    let at_10_00 = chrono::Utc.with_ymd_and_hms(2026, 2, 12, 10, 0, 0).unwrap();
    assert!(window.is_active(&at_10_00));
}

#[test]
fn one_minute_window_end_exclusive() {
    let window = make_window("daily 10:00-10:01");
    let at_10_01 = chrono::Utc.with_ymd_and_hms(2026, 2, 12, 10, 1, 0).unwrap();
    assert!(!window.is_active(&at_10_01));
}

// ---------------------------------------------------------------------------
// 6. Daily window is day-agnostic
// ---------------------------------------------------------------------------

#[test]
fn daily_window_active_on_any_day_of_week() {
    let window = make_window("daily 08:00-09:00");

    // Test on Monday through Sunday
    for day in 9..=15u32 {
        let now = chrono::Utc
            .with_ymd_and_hms(2026, 2, day, 8, 30, 0)
            .unwrap();
        assert!(
            window.is_active(&now),
            "daily window should be active on Feb {}",
            day
        );
    }
}

// ---------------------------------------------------------------------------
// 7. Unknown day name
// ---------------------------------------------------------------------------

#[test]
fn unknown_day_name_never_active() {
    let window = make_window("xyz 10:00-11:00");
    // Even at 10:30 on any day, "xyz" doesn't match any weekday
    let now = chrono::Utc
        .with_ymd_and_hms(2026, 2, 12, 10, 30, 0)
        .unwrap();
    assert!(!window.is_active(&now));
}
