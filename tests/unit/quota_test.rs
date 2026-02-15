use sks5::config::types::{LimitsConfig, QuotaConfig, RateLimitsConfig};
use sks5::quota::{QuotaResult, QuotaTracker};
use std::time::Duration;

fn test_limits() -> LimitsConfig {
    LimitsConfig {
        max_bandwidth_mbps: 0,
        max_new_connections_per_second: 0,
        max_new_connections_per_minute: 0,
        ..LimitsConfig::default()
    }
}

// ---------------------------------------------------------------------------
// Rolling window + basic QuotaTracker
// ---------------------------------------------------------------------------

#[test]
fn quota_tracker_new_user_has_zero_usage() {
    let tracker = QuotaTracker::new(&test_limits());
    let usage = tracker.get_user_usage("newuser");
    assert_eq!(usage.daily_bytes, 0);
    assert_eq!(usage.daily_connections, 0);
    assert_eq!(usage.monthly_bytes, 0);
    assert_eq!(usage.monthly_connections, 0);
    assert_eq!(usage.current_rate_bps, 0);
    assert_eq!(usage.hourly_bytes, 0);
}

#[test]
fn record_connection_increments_counters() {
    let tracker = QuotaTracker::new(&test_limits());
    tracker.record_connection("alice", None).unwrap();
    tracker.record_connection("alice", None).unwrap();
    let usage = tracker.get_user_usage("alice");
    assert_eq!(usage.daily_connections, 2);
    assert_eq!(usage.monthly_connections, 2);
}

#[test]
fn record_bytes_increments_counters() {
    let tracker = QuotaTracker::new(&test_limits());
    match tracker.record_bytes("alice", 1024, 0, 0, None) {
        QuotaResult::Ok(d) => assert_eq!(d, Duration::ZERO),
        QuotaResult::Exceeded(r) => panic!("should not exceed: {r}"),
    }
    match tracker.record_bytes("alice", 2048, 0, 0, None) {
        QuotaResult::Ok(d) => assert_eq!(d, Duration::ZERO),
        QuotaResult::Exceeded(r) => panic!("should not exceed: {r}"),
    }
    let usage = tracker.get_user_usage("alice");
    assert_eq!(usage.daily_bytes, 3072);
    assert_eq!(usage.monthly_bytes, 3072);
}

// ---------------------------------------------------------------------------
// Daily connection quota
// ---------------------------------------------------------------------------

#[test]
fn daily_connection_quota_enforced() {
    let tracker = QuotaTracker::new(&test_limits());
    let quota = QuotaConfig {
        daily_connection_limit: 3,
        ..Default::default()
    };
    assert!(tracker.record_connection("alice", Some(&quota)).is_ok());
    assert!(tracker.record_connection("alice", Some(&quota)).is_ok());
    assert!(tracker.record_connection("alice", Some(&quota)).is_ok());
    let err = tracker
        .record_connection("alice", Some(&quota))
        .unwrap_err();
    assert!(err.contains("daily connection quota"));
}

#[test]
fn monthly_connection_quota_enforced() {
    let tracker = QuotaTracker::new(&test_limits());
    let quota = QuotaConfig {
        monthly_connection_limit: 2,
        ..Default::default()
    };
    assert!(tracker.record_connection("bob", Some(&quota)).is_ok());
    assert!(tracker.record_connection("bob", Some(&quota)).is_ok());
    let err = tracker.record_connection("bob", Some(&quota)).unwrap_err();
    assert!(err.contains("monthly connection quota"));
}

// ---------------------------------------------------------------------------
// Daily / monthly / hourly bandwidth quotas
// ---------------------------------------------------------------------------

#[test]
fn daily_bandwidth_quota_enforced() {
    let tracker = QuotaTracker::new(&test_limits());
    let quota = QuotaConfig {
        daily_bandwidth_bytes: 1000,
        ..Default::default()
    };
    match tracker.record_bytes("alice", 500, 0, 0, Some(&quota)) {
        QuotaResult::Ok(_) => {}
        QuotaResult::Exceeded(r) => panic!("should not exceed: {r}"),
    }
    match tracker.record_bytes("alice", 600, 0, 0, Some(&quota)) {
        QuotaResult::Exceeded(r) => assert!(r.contains("daily bandwidth")),
        QuotaResult::Ok(_) => panic!("should have exceeded daily bandwidth"),
    }
}

#[test]
fn monthly_bandwidth_quota_enforced() {
    let tracker = QuotaTracker::new(&test_limits());
    let quota = QuotaConfig {
        monthly_bandwidth_bytes: 2000,
        ..Default::default()
    };
    match tracker.record_bytes("alice", 1500, 0, 0, Some(&quota)) {
        QuotaResult::Ok(_) => {}
        QuotaResult::Exceeded(r) => panic!("should not exceed: {r}"),
    }
    match tracker.record_bytes("alice", 600, 0, 0, Some(&quota)) {
        QuotaResult::Exceeded(r) => assert!(r.contains("monthly bandwidth")),
        QuotaResult::Ok(_) => panic!("should have exceeded monthly bandwidth"),
    }
}

// ---------------------------------------------------------------------------
// Multi-window rate limiting
// ---------------------------------------------------------------------------

#[test]
fn per_user_per_second_rate_limit() {
    let limits = test_limits();
    let tracker = QuotaTracker::new(&limits);
    let rate = RateLimitsConfig {
        connections_per_second: 2,
        connections_per_minute: 0,
        connections_per_hour: 0,
    };
    // Record 2 connections
    tracker.record_connection("alice", None).unwrap();
    tracker.record_connection("alice", None).unwrap();
    // Third should be rate-limited
    let err = tracker
        .check_connection_rate("alice", &rate, &limits)
        .unwrap_err();
    assert!(err.contains("per-second"));
}

#[test]
fn per_user_per_minute_rate_limit() {
    let limits = test_limits();
    let tracker = QuotaTracker::new(&limits);
    let rate = RateLimitsConfig {
        connections_per_second: 0,
        connections_per_minute: 3,
        connections_per_hour: 0,
    };
    tracker.record_connection("alice", None).unwrap();
    tracker.record_connection("alice", None).unwrap();
    tracker.record_connection("alice", None).unwrap();
    let err = tracker
        .check_connection_rate("alice", &rate, &limits)
        .unwrap_err();
    assert!(err.contains("per-minute"));
}

#[test]
fn per_user_per_hour_rate_limit() {
    let limits = test_limits();
    let tracker = QuotaTracker::new(&limits);
    let rate = RateLimitsConfig {
        connections_per_second: 0,
        connections_per_minute: 0,
        connections_per_hour: 1,
    };
    tracker.record_connection("alice", None).unwrap();
    let err = tracker
        .check_connection_rate("alice", &rate, &limits)
        .unwrap_err();
    assert!(err.contains("per-hour"));
}

#[test]
fn zero_rate_limit_means_unlimited() {
    let limits = test_limits();
    let tracker = QuotaTracker::new(&limits);
    let rate = RateLimitsConfig {
        connections_per_second: 0,
        connections_per_minute: 0,
        connections_per_hour: 0,
    };
    // Record many connections — should all be allowed
    for _ in 0..100 {
        tracker.record_connection("alice", None).unwrap();
    }
    assert!(tracker
        .check_connection_rate("alice", &rate, &limits)
        .is_ok());
}

// ---------------------------------------------------------------------------
// Server-level rate limiting
// ---------------------------------------------------------------------------

#[test]
fn server_per_second_rate_limit() {
    let limits = LimitsConfig {
        max_new_connections_per_second: 2,
        max_new_connections_per_minute: 0,
        max_bandwidth_mbps: 0,
        ..LimitsConfig::default()
    };
    let tracker = QuotaTracker::new(&limits);
    let rate = RateLimitsConfig::default();
    tracker.record_connection("alice", None).unwrap();
    tracker.record_connection("bob", None).unwrap();
    let err = tracker
        .check_connection_rate("carol", &rate, &limits)
        .unwrap_err();
    assert!(err.contains("server connection rate limit"));
    assert!(err.contains("per-second"));
}

#[test]
fn server_per_minute_rate_limit() {
    let limits = LimitsConfig {
        max_new_connections_per_second: 0,
        max_new_connections_per_minute: 3,
        max_bandwidth_mbps: 0,
        ..LimitsConfig::default()
    };
    let tracker = QuotaTracker::new(&limits);
    let rate = RateLimitsConfig::default();
    tracker.record_connection("a", None).unwrap();
    tracker.record_connection("b", None).unwrap();
    tracker.record_connection("c", None).unwrap();
    let err = tracker
        .check_connection_rate("d", &rate, &limits)
        .unwrap_err();
    assert!(err.contains("server connection rate limit"));
    assert!(err.contains("per-minute"));
}

// ---------------------------------------------------------------------------
// Reset and cleanup
// ---------------------------------------------------------------------------

#[test]
fn reset_user_clears_counters() {
    let tracker = QuotaTracker::new(&test_limits());
    tracker.record_connection("alice", None).unwrap();
    match tracker.record_bytes("alice", 1000, 0, 0, None) {
        QuotaResult::Ok(_) => {}
        QuotaResult::Exceeded(_) => panic!(),
    }
    tracker.reset_user("alice");
    let usage = tracker.get_user_usage("alice");
    assert_eq!(usage.daily_bytes, 0);
    assert_eq!(usage.daily_connections, 0);
    assert_eq!(usage.monthly_bytes, 0);
    assert_eq!(usage.monthly_connections, 0);
}

#[test]
fn reset_nonexistent_user_is_noop() {
    let tracker = QuotaTracker::new(&test_limits());
    tracker.reset_user("nonexistent"); // should not panic
}

#[test]
fn cleanup_stale_removes_inactive_users() {
    let tracker = QuotaTracker::new(&test_limits());
    tracker.record_connection("alice", None).unwrap();
    tracker.record_connection("bob", None).unwrap();
    assert_eq!(tracker.tracked_users().len(), 2);
    // Cleanup with max_idle_secs=0 removes everything
    tracker.cleanup_stale(0);
    assert!(tracker.tracked_users().is_empty());
}

#[test]
fn cleanup_stale_preserves_recent_users() {
    let tracker = QuotaTracker::new(&test_limits());
    tracker.record_connection("alice", None).unwrap();
    // Cleanup with large max_idle keeps recent entries
    tracker.cleanup_stale(3600);
    assert_eq!(tracker.tracked_users().len(), 1);
    assert!(tracker.tracked_users().contains(&"alice".to_string()));
}

// ---------------------------------------------------------------------------
// Multiple users are independent
// ---------------------------------------------------------------------------

#[test]
fn different_users_have_independent_counters() {
    let tracker = QuotaTracker::new(&test_limits());
    tracker.record_connection("alice", None).unwrap();
    tracker.record_connection("alice", None).unwrap();
    tracker.record_connection("bob", None).unwrap();

    let alice = tracker.get_user_usage("alice");
    let bob = tracker.get_user_usage("bob");
    assert_eq!(alice.daily_connections, 2);
    assert_eq!(bob.daily_connections, 1);
}

#[test]
fn different_users_quota_limits_are_independent() {
    let tracker = QuotaTracker::new(&test_limits());
    let quota = QuotaConfig {
        daily_connection_limit: 1,
        ..Default::default()
    };
    assert!(tracker.record_connection("alice", Some(&quota)).is_ok());
    assert!(tracker.record_connection("alice", Some(&quota)).is_err());
    // Bob should still be able to connect
    assert!(tracker.record_connection("bob", Some(&quota)).is_ok());
}

// ---------------------------------------------------------------------------
// Throttle computation
// ---------------------------------------------------------------------------

#[test]
fn no_throttle_when_no_limits() {
    let tracker = QuotaTracker::new(&test_limits());
    match tracker.record_bytes("alice", 10_000, 0, 0, None) {
        QuotaResult::Ok(d) => assert_eq!(d, Duration::ZERO),
        QuotaResult::Exceeded(r) => panic!("unexpected: {r}"),
    }
}

// ---------------------------------------------------------------------------
// UserQuotaUsage serialization
// ---------------------------------------------------------------------------

#[test]
fn user_quota_usage_serializes() {
    let tracker = QuotaTracker::new(&test_limits());
    tracker.record_connection("alice", None).unwrap();
    match tracker.record_bytes("alice", 512, 0, 0, None) {
        QuotaResult::Ok(_) => {}
        QuotaResult::Exceeded(_) => panic!(),
    }
    let usage = tracker.get_user_usage("alice");
    let json = serde_json::to_string(&usage).unwrap();
    assert!(json.contains("daily_bytes"));
    assert!(json.contains("512"));
}

// ---------------------------------------------------------------------------
// update_config
// ---------------------------------------------------------------------------

#[test]
fn update_config_changes_server_bandwidth_limit() {
    let mut limits = test_limits();
    limits.max_bandwidth_mbps = 100;
    let tracker = QuotaTracker::new(&limits);

    // Update to new limit
    let mut new_limits = test_limits();
    new_limits.max_bandwidth_mbps = 200;
    tracker.update_config(&new_limits);
    // Should not panic; verifies the update mechanism works
}
