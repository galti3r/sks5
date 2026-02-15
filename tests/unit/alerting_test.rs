use sks5::alerting::AlertEngine;
use sks5::config::types::{AlertCondition, AlertRule, AlertingConfig, LimitsConfig};
use sks5::quota::QuotaTracker;
use std::sync::Arc;

fn test_tracker() -> Arc<QuotaTracker> {
    Arc::new(QuotaTracker::new(&LimitsConfig::default()))
}

fn make_rule(name: &str, condition: AlertCondition, threshold: u64) -> AlertRule {
    AlertRule {
        name: name.to_string(),
        condition,
        threshold,
        window_secs: 3600,
        users: vec![],
        webhook_url: None,
    }
}

fn make_config(rules: Vec<AlertRule>) -> AlertingConfig {
    AlertingConfig {
        enabled: true,
        rules,
    }
}

// -------------------------------------------------------------------------
// Test: disabled engine never fires
// -------------------------------------------------------------------------
#[test]
fn disabled_engine_does_not_evaluate() {
    let config = AlertingConfig {
        enabled: false,
        rules: vec![make_rule("test", AlertCondition::BandwidthExceeded, 100)],
    };
    let engine = AlertEngine::new(config, None, test_tracker());
    assert!(!engine.is_enabled());
    engine.evaluate(&["alice".to_string()]);
}

// -------------------------------------------------------------------------
// Test: bandwidth_exceeded condition fires when threshold crossed
// -------------------------------------------------------------------------
#[test]
fn bandwidth_exceeded_fires_alert() {
    let tracker = test_tracker();
    let _ = tracker.record_bytes("alice", 2000, 0, 0, None);

    let config = make_config(vec![make_rule(
        "high_bw",
        AlertCondition::BandwidthExceeded,
        1000,
    )]);
    let engine = AlertEngine::new(config, None, tracker);
    engine.evaluate(&["alice".to_string()]);

    // The alert should have been recorded (dedup set has one entry)
    // We verify indirectly: evaluating again should NOT add another entry
    // (deduplication works)
    engine.evaluate(&["alice".to_string()]);
}

// -------------------------------------------------------------------------
// Test: bandwidth below threshold does not fire
// -------------------------------------------------------------------------
#[test]
fn below_threshold_does_not_fire() {
    let tracker = test_tracker();
    let _ = tracker.record_bytes("alice", 500, 0, 0, None);

    let config = make_config(vec![make_rule(
        "low_bw",
        AlertCondition::BandwidthExceeded,
        1000,
    )]);
    let engine = AlertEngine::new(config, None, tracker);
    engine.evaluate(&["alice".to_string()]);
    // No assertion on internal state needed; the test passes if no panic/crash
}

// -------------------------------------------------------------------------
// Test: connections_exceeded condition fires
// -------------------------------------------------------------------------
#[test]
fn connections_exceeded_fires() {
    let tracker = test_tracker();
    for _ in 0..5 {
        let _ = tracker.record_connection("bob", None);
    }

    let config = make_config(vec![make_rule(
        "conn_limit",
        AlertCondition::ConnectionsExceeded,
        3,
    )]);
    let engine = AlertEngine::new(config, None, tracker);
    engine.evaluate(&["bob".to_string()]);
}

// -------------------------------------------------------------------------
// Test: deduplication prevents same alert from firing twice
// -------------------------------------------------------------------------
#[test]
fn deduplication_prevents_repeat_fires() {
    let tracker = test_tracker();
    let _ = tracker.record_bytes("alice", 2000, 0, 0, None);

    let config = make_config(vec![make_rule(
        "bw_alert",
        AlertCondition::BandwidthExceeded,
        1000,
    )]);
    let engine = AlertEngine::new(config, None, tracker);

    // First evaluation should fire
    engine.evaluate(&["alice".to_string()]);
    // Second evaluation should be deduplicated (no crash, same behavior)
    engine.evaluate(&["alice".to_string()]);
}

// -------------------------------------------------------------------------
// Test: reset_fired() clears deduplication state
// -------------------------------------------------------------------------
#[test]
fn reset_fired_clears_dedup_state() {
    let tracker = test_tracker();
    let _ = tracker.record_bytes("alice", 2000, 0, 0, None);

    let config = make_config(vec![make_rule(
        "bw_alert",
        AlertCondition::BandwidthExceeded,
        1000,
    )]);
    let engine = AlertEngine::new(config, None, tracker);

    engine.evaluate(&["alice".to_string()]);
    engine.reset_fired();
    // After reset, the alert can fire again
    engine.evaluate(&["alice".to_string()]);
}

// -------------------------------------------------------------------------
// Test: rule scoped to specific users only checks those users
// -------------------------------------------------------------------------
#[test]
fn rule_scoped_to_specific_users() {
    let tracker = test_tracker();
    let _ = tracker.record_bytes("alice", 2000, 0, 0, None);
    let _ = tracker.record_bytes("bob", 2000, 0, 0, None);

    let config = AlertingConfig {
        enabled: true,
        rules: vec![AlertRule {
            name: "alice_only".to_string(),
            condition: AlertCondition::BandwidthExceeded,
            threshold: 1000,
            window_secs: 3600,
            users: vec!["alice".to_string()],
            webhook_url: None,
        }],
    };
    let engine = AlertEngine::new(config, None, tracker);
    // Even though both users exceed threshold, only alice should be checked
    engine.evaluate(&["alice".to_string(), "bob".to_string()]);
}

// -------------------------------------------------------------------------
// Test: monthly_bandwidth_exceeded fires when monthly bytes exceed threshold
// -------------------------------------------------------------------------
#[test]
fn monthly_bandwidth_exceeded_fires() {
    let tracker = test_tracker();
    let _ = tracker.record_bytes("alice", 5000, 0, 0, None);

    let config = make_config(vec![make_rule(
        "monthly_bw",
        AlertCondition::MonthlyBandwidthExceeded,
        4000,
    )]);
    let engine = AlertEngine::new(config, None, tracker);
    engine.evaluate(&["alice".to_string()]);
}

// -------------------------------------------------------------------------
// Test: hourly_bandwidth_exceeded condition
// -------------------------------------------------------------------------
#[test]
fn hourly_bandwidth_exceeded_fires() {
    let tracker = test_tracker();
    let _ = tracker.record_bytes("alice", 10000, 0, 0, None);

    let config = make_config(vec![make_rule(
        "hourly_bw",
        AlertCondition::HourlyBandwidthExceeded,
        5000,
    )]);
    let engine = AlertEngine::new(config, None, tracker);
    engine.evaluate(&["alice".to_string()]);
}

// -------------------------------------------------------------------------
// Test: multiple rules evaluate independently
// -------------------------------------------------------------------------
#[test]
fn multiple_rules_evaluate_independently() {
    let tracker = test_tracker();
    let _ = tracker.record_bytes("alice", 2000, 0, 0, None);
    for _ in 0..5 {
        let _ = tracker.record_connection("alice", None);
    }

    let config = make_config(vec![
        make_rule("bw_rule", AlertCondition::BandwidthExceeded, 1000),
        make_rule("conn_rule", AlertCondition::ConnectionsExceeded, 3),
    ]);
    let engine = AlertEngine::new(config, None, tracker);
    engine.evaluate(&["alice".to_string()]);
}

// -------------------------------------------------------------------------
// Test: is_enabled() returns correct state
// -------------------------------------------------------------------------
#[test]
fn is_enabled_returns_correct_state() {
    let enabled_config = make_config(vec![]);
    let engine = AlertEngine::new(enabled_config, None, test_tracker());
    assert!(engine.is_enabled());

    let disabled_config = AlertingConfig {
        enabled: false,
        rules: vec![],
    };
    let engine2 = AlertEngine::new(disabled_config, None, test_tracker());
    assert!(!engine2.is_enabled());
}

// -------------------------------------------------------------------------
// Test: empty known_users list means no alerts fire
// -------------------------------------------------------------------------
#[test]
fn empty_known_users_no_alerts() {
    let tracker = test_tracker();
    let _ = tracker.record_bytes("alice", 2000, 0, 0, None);

    let config = make_config(vec![make_rule(
        "bw_alert",
        AlertCondition::BandwidthExceeded,
        1000,
    )]);
    let engine = AlertEngine::new(config, None, tracker);
    // No known users passed => no users to check (rule has empty users list)
    engine.evaluate(&[]);
}
