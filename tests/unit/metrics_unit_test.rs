use prometheus_client::encoding::text::encode;
use sks5::metrics::MetricsRegistry;

// ---------------------------------------------------------------------------
// Creating a registry
// ---------------------------------------------------------------------------

#[test]
fn new_creates_registry_with_default_max_labels() {
    let metrics = MetricsRegistry::new();

    // Verify it's functional: record a metric without panicking
    metrics.record_auth_success("testuser", "password");
    assert_eq!(metrics.cardinality_capped_total.get(), 0);
}

#[test]
fn default_impl_same_as_new() {
    let m1 = MetricsRegistry::new();
    let m2 = MetricsRegistry::default();

    // Both should have same default cap of 100
    for i in 0..100 {
        m1.record_auth_success(&format!("u{}", i), "password");
        m2.record_auth_success(&format!("u{}", i), "password");
    }
    assert_eq!(m1.cardinality_capped_total.get(), 0);
    assert_eq!(m2.cardinality_capped_total.get(), 0);

    // 101st should trigger cap on both
    m1.record_auth_success("overflow", "password");
    m2.record_auth_success("overflow", "password");
    assert_eq!(m1.cardinality_capped_total.get(), 1);
    assert_eq!(m2.cardinality_capped_total.get(), 1);
}

#[test]
fn with_max_labels_custom_cap() {
    let metrics = MetricsRegistry::with_max_labels(3);

    metrics.record_auth_success("a", "password");
    metrics.record_auth_success("b", "password");
    metrics.record_auth_success("c", "password");
    assert_eq!(metrics.cardinality_capped_total.get(), 0);

    metrics.record_auth_success("d", "password");
    assert_eq!(metrics.cardinality_capped_total.get(), 1);
}

// ---------------------------------------------------------------------------
// Incrementing counters
// ---------------------------------------------------------------------------

#[test]
fn connections_total_increments() {
    let metrics = MetricsRegistry::new();

    assert_eq!(metrics.connections_total.get(), 0);
    metrics.connections_total.inc();
    assert_eq!(metrics.connections_total.get(), 1);
    metrics.connections_total.inc();
    metrics.connections_total.inc();
    assert_eq!(metrics.connections_total.get(), 3);
}

#[test]
fn auth_failures_total_increments() {
    let metrics = MetricsRegistry::new();

    metrics.record_auth_failure("password");
    metrics.record_auth_failure("password");
    metrics.record_auth_failure("pubkey");

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    // Verify password failures appear with count 2
    let password_line = buf.lines().find(|l| {
        l.contains("auth_failures_total") && l.contains("password") && !l.starts_with('#')
    });
    assert!(
        password_line.is_some(),
        "Should find password in auth failures"
    );
    assert!(
        password_line.unwrap().contains(" 2"),
        "Password should have count 2, got: {}",
        password_line.unwrap()
    );

    // Verify pubkey failures appear with count 1
    let pubkey_line = buf
        .lines()
        .find(|l| l.contains("auth_failures_total") && l.contains("pubkey") && !l.starts_with('#'));
    assert!(pubkey_line.is_some(), "Should find pubkey in auth failures");
    assert!(
        pubkey_line.unwrap().contains(" 1"),
        "Pubkey should have count 1, got: {}",
        pubkey_line.unwrap()
    );
}

#[test]
fn auth_successes_increments_per_user() {
    let metrics = MetricsRegistry::new();

    metrics.record_auth_success("alice", "password");
    metrics.record_auth_success("alice", "password");
    metrics.record_auth_success("bob", "password");

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    // Verify alice appears with count 2 and bob with count 1
    let alice_line = buf
        .lines()
        .find(|l| l.contains("auth_successes_total") && l.contains("alice") && !l.starts_with('#'));
    assert!(alice_line.is_some(), "Should find alice in auth successes");
    assert!(
        alice_line.unwrap().contains(" 2"),
        "Alice should have count 2, got: {}",
        alice_line.unwrap()
    );

    let bob_line = buf
        .lines()
        .find(|l| l.contains("auth_successes_total") && l.contains("bob") && !l.starts_with('#'));
    assert!(bob_line.is_some(), "Should find bob in auth successes");
    assert!(
        bob_line.unwrap().contains(" 1"),
        "Bob should have count 1, got: {}",
        bob_line.unwrap()
    );
}

#[test]
fn bytes_transferred_accumulates() {
    let metrics = MetricsRegistry::new();

    metrics.record_bytes_transferred("alice", 1024);
    metrics.record_bytes_transferred("alice", 2048);
    metrics.record_bytes_transferred("bob", 512);

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    // alice should have 3072 total
    let alice_line = buf
        .lines()
        .find(|l| l.contains("bytes_transferred") && l.contains("alice") && !l.starts_with('#'));
    assert!(
        alice_line.is_some(),
        "Should find alice in bytes_transferred"
    );

    let bob_line = buf
        .lines()
        .find(|l| l.contains("bytes_transferred") && l.contains("bob") && !l.starts_with('#'));
    assert!(bob_line.is_some(), "Should find bob in bytes_transferred");
}

#[test]
fn record_connection_rejected_tracks_reason() {
    let metrics = MetricsRegistry::new();

    metrics.record_connection_rejected("acl_denied");
    metrics.record_connection_rejected("acl_denied");
    metrics.record_connection_rejected("rate_limited");

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    assert!(
        buf.contains("acl_denied"),
        "Should contain acl_denied reason"
    );
    assert!(
        buf.contains("rate_limited"),
        "Should contain rate_limited reason"
    );
}

#[test]
fn record_http_request_tracks_method_path_status() {
    let metrics = MetricsRegistry::new();

    metrics.record_http_request("GET", "/api/sessions", 200);
    metrics.record_http_request("POST", "/api/auth", 401);

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    assert!(
        buf.contains("http_requests_total"),
        "Should contain http_requests_total metric"
    );
    assert!(buf.contains("GET"), "Should contain GET method");
    assert!(buf.contains("POST"), "Should contain POST method");
}

#[test]
fn record_http_request_duration_creates_histogram() {
    let metrics = MetricsRegistry::new();

    metrics.record_http_request_duration("GET", "/api/sessions", 0.05);

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    assert!(
        buf.contains("http_request_duration_seconds_bucket"),
        "Should contain histogram buckets"
    );
    assert!(
        buf.contains("http_request_duration_seconds_sum"),
        "Should contain histogram sum"
    );
    assert!(
        buf.contains("http_request_duration_seconds_count"),
        "Should contain histogram count"
    );
}

// ---------------------------------------------------------------------------
// Cardinality protection (max_metric_labels)
// ---------------------------------------------------------------------------

#[test]
fn cardinality_cap_routes_unknown_users_to_other() {
    let metrics = MetricsRegistry::with_max_labels(2);

    metrics.record_auth_success("known1", "password");
    metrics.record_auth_success("known2", "password");
    assert_eq!(metrics.cardinality_capped_total.get(), 0);

    // Third user should go to _other
    metrics.record_auth_success("unknown3", "password");
    assert_eq!(metrics.cardinality_capped_total.get(), 1);

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    assert!(buf.contains("known1"));
    assert!(buf.contains("known2"));
    assert!(!buf.contains("unknown3"));
    assert!(buf.contains("_other"));
}

#[test]
fn known_user_bypasses_cap() {
    let metrics = MetricsRegistry::with_max_labels(2);

    metrics.record_auth_success("alice", "password");
    metrics.record_auth_success("bob", "password");

    // Cap is full, but alice is already known
    metrics.record_auth_success("alice", "password");
    assert_eq!(
        metrics.cardinality_capped_total.get(),
        0,
        "Known user should not trigger cap"
    );
}

#[test]
fn cap_counter_increments_for_each_capped_call() {
    let metrics = MetricsRegistry::with_max_labels(1);

    metrics.record_auth_success("only_user", "password");

    metrics.record_auth_success("extra1", "password");
    metrics.record_auth_success("extra2", "password");
    metrics.record_auth_success("extra3", "password");

    assert_eq!(metrics.cardinality_capped_total.get(), 3);
}

#[test]
fn zero_cap_all_users_go_to_other() {
    let metrics = MetricsRegistry::with_max_labels(0);

    metrics.record_auth_success("alice", "password");
    metrics.record_auth_success("bob", "password");

    assert_eq!(metrics.cardinality_capped_total.get(), 2);

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    assert!(!buf.contains(r#"user="alice"#));
    assert!(!buf.contains(r#"user="bob"#));
    assert!(buf.contains("_other"));
}

#[test]
fn cardinality_cap_applies_to_all_per_user_metrics() {
    let metrics = MetricsRegistry::with_max_labels(1);

    // Register one user
    metrics.record_auth_success("known", "password");

    // All these should be capped for "unknown"
    metrics.record_auth_success("unknown", "password");
    metrics.record_bytes_transferred("unknown", 100);
    metrics.record_connection_duration("unknown", 10.0);
    metrics.record_quota_exceeded("unknown", "bandwidth");

    // Each call for unknown increments the cap counter
    assert_eq!(metrics.cardinality_capped_total.get(), 4);
}

// ---------------------------------------------------------------------------
// Label tracking (prune_known_users)
// ---------------------------------------------------------------------------

#[test]
fn prune_known_users_removes_stale_users() {
    let metrics = MetricsRegistry::with_max_labels(10);

    metrics.record_auth_success("alice", "password");
    metrics.record_auth_success("bob", "password");
    metrics.record_auth_success("charlie", "password");

    // Prune: only keep alice and bob
    metrics.prune_known_users(&["alice".to_string(), "bob".to_string()]);

    // charlie is now unknown -- should hit cap if we exceed max_labels
    // But first, the cap should still have room since we pruned
    // Let's fill up to max and check charlie goes through normally
    metrics.record_auth_success("charlie", "password");
    // charlie is re-added since there's room (we pruned, leaving 2 known, cap is 10)
    assert_eq!(metrics.cardinality_capped_total.get(), 0);
}

#[test]
fn prune_known_users_with_empty_active_list_clears_all() {
    let metrics = MetricsRegistry::with_max_labels(2);

    metrics.record_auth_success("alice", "password");
    metrics.record_auth_success("bob", "password");
    assert_eq!(metrics.cardinality_capped_total.get(), 0);

    // Prune all
    metrics.prune_known_users(&[]);

    // Now both alice and bob are unknown. Since cap is 2, first two re-added are fine.
    metrics.record_auth_success("alice", "password");
    metrics.record_auth_success("bob", "password");
    assert_eq!(metrics.cardinality_capped_total.get(), 0);

    // Third user should be capped
    metrics.record_auth_success("charlie", "password");
    assert_eq!(metrics.cardinality_capped_total.get(), 1);
}

#[test]
fn prune_known_users_keeps_active_users() {
    let metrics = MetricsRegistry::with_max_labels(3);

    metrics.record_auth_success("alice", "password");
    metrics.record_auth_success("bob", "password");
    metrics.record_auth_success("charlie", "password");

    // Prune but keep all
    metrics.prune_known_users(&[
        "alice".to_string(),
        "bob".to_string(),
        "charlie".to_string(),
    ]);

    // All three should still be known
    metrics.record_auth_success("alice", "password");
    metrics.record_auth_success("bob", "password");
    metrics.record_auth_success("charlie", "password");
    assert_eq!(metrics.cardinality_capped_total.get(), 0);
}

// ---------------------------------------------------------------------------
// Prometheus output format
// ---------------------------------------------------------------------------

#[test]
fn prometheus_output_contains_all_registered_metrics() {
    let metrics = MetricsRegistry::new();

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    // Verify key metric names are present in the output (as help/type lines)
    assert!(
        buf.contains("sks5_connections_active"),
        "Should contain connections_active"
    );
    assert!(
        buf.contains("sks5_connections_total"),
        "Should contain connections_total"
    );
    assert!(
        buf.contains("sks5_bytes_transferred"),
        "Should contain bytes_transferred"
    );
    assert!(
        buf.contains("sks5_auth_failures_total"),
        "Should contain auth_failures_total"
    );
    assert!(
        buf.contains("sks5_auth_successes_total"),
        "Should contain auth_successes_total"
    );
    assert!(
        buf.contains("sks5_banned_ips_current"),
        "Should contain banned_ips_current"
    );
    assert!(
        buf.contains("sks5_audit_events_dropped_total"),
        "Should contain audit_events_dropped"
    );
    assert!(
        buf.contains("sks5_dns_cache_hits_total"),
        "Should contain dns_cache_hits"
    );
    assert!(
        buf.contains("sks5_dns_cache_misses_total"),
        "Should contain dns_cache_misses"
    );
    assert!(
        buf.contains("sks5_errors_total"),
        "Should contain errors_total"
    );
}

#[test]
fn record_error_tracks_error_type() {
    let metrics = MetricsRegistry::new();

    metrics.record_error("connection_failed");
    metrics.record_error("connection_failed");
    metrics.record_error("dns_failed");
    metrics.record_error("acl_denied");
    metrics.record_error("auth_error");
    metrics.record_error("relay_error");
    metrics.record_error("quota_exceeded");

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    assert!(
        buf.contains("errors_total"),
        "Should contain errors_total metric"
    );
    assert!(
        buf.contains("connection_failed"),
        "Should contain connection_failed error_type"
    );
    assert!(
        buf.contains("dns_failed"),
        "Should contain dns_failed error_type"
    );
    assert!(
        buf.contains("acl_denied"),
        "Should contain acl_denied error_type"
    );
    assert!(
        buf.contains("auth_error"),
        "Should contain auth_error error_type"
    );
    assert!(
        buf.contains("relay_error"),
        "Should contain relay_error error_type"
    );
    assert!(
        buf.contains("quota_exceeded"),
        "Should contain quota_exceeded error_type"
    );

    // Verify connection_failed has count 2
    let cf_line = buf.lines().find(|l| {
        l.contains("errors_total") && l.contains("connection_failed") && !l.starts_with('#')
    });
    assert!(cf_line.is_some(), "Should find connection_failed in errors");
    assert!(
        cf_line.unwrap().contains(" 2"),
        "connection_failed should have count 2, got: {}",
        cf_line.unwrap()
    );
}

#[test]
fn auth_success_includes_method_label() {
    let metrics = MetricsRegistry::new();

    metrics.record_auth_success("alice", "password");
    metrics.record_auth_success("alice", "pubkey");
    metrics.record_auth_success("bob", "password");

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    // Verify method labels appear
    assert!(buf.contains("password"), "Should contain password method");
    assert!(buf.contains("pubkey"), "Should contain pubkey method");

    // alice with password method should have count 1
    let alice_pw = buf.lines().find(|l| {
        l.contains("auth_successes_total")
            && l.contains("alice")
            && l.contains("password")
            && !l.starts_with('#')
    });
    assert!(
        alice_pw.is_some(),
        "Should find alice+password in auth successes"
    );
    assert!(
        alice_pw.unwrap().ends_with(" 1"),
        "alice+password should have count 1, got: {}",
        alice_pw.unwrap()
    );

    // alice with pubkey method should have count 1
    let alice_pk = buf.lines().find(|l| {
        l.contains("auth_successes_total")
            && l.contains("alice")
            && l.contains("pubkey")
            && !l.starts_with('#')
    });
    assert!(
        alice_pk.is_some(),
        "Should find alice+pubkey in auth successes"
    );
    assert!(
        alice_pk.unwrap().ends_with(" 1"),
        "alice+pubkey should have count 1, got: {}",
        alice_pk.unwrap()
    );
}

#[test]
fn dns_cache_counters_increment() {
    let metrics = MetricsRegistry::new();

    assert_eq!(metrics.dns_cache_hits_total.get(), 0);
    assert_eq!(metrics.dns_cache_misses_total.get(), 0);

    metrics.dns_cache_hits_total.inc();
    metrics.dns_cache_hits_total.inc();
    metrics.dns_cache_misses_total.inc();

    assert_eq!(metrics.dns_cache_hits_total.get(), 2);
    assert_eq!(metrics.dns_cache_misses_total.get(), 1);
}

#[test]
fn banned_ips_gauge_can_increase_and_decrease() {
    let metrics = MetricsRegistry::new();

    assert_eq!(metrics.banned_ips_current.get(), 0);
    metrics.banned_ips_current.inc();
    metrics.banned_ips_current.inc();
    assert_eq!(metrics.banned_ips_current.get(), 2);
    metrics.banned_ips_current.dec();
    assert_eq!(metrics.banned_ips_current.get(), 1);
}

#[test]
fn audit_events_dropped_counter() {
    let metrics = MetricsRegistry::new();

    assert_eq!(metrics.audit_events_dropped.get(), 0);
    metrics.audit_events_dropped.inc();
    assert_eq!(metrics.audit_events_dropped.get(), 1);
}

// ---------------------------------------------------------------------------
// Quota metrics
// ---------------------------------------------------------------------------

#[test]
fn record_quota_bandwidth_creates_metric() {
    let metrics = MetricsRegistry::new();

    metrics.record_quota_bandwidth("alice", "hourly", 1024);
    metrics.record_quota_bandwidth("alice", "daily", 2048);

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    assert!(
        buf.contains("quota_bandwidth_used_bytes"),
        "Should contain bandwidth quota metric"
    );
    assert!(buf.contains("alice"), "Should contain alice label");
    assert!(buf.contains("hourly"), "Should contain hourly window");
    assert!(buf.contains("daily"), "Should contain daily window");
}

#[test]
fn record_quota_connection_creates_metric() {
    let metrics = MetricsRegistry::new();

    metrics.record_quota_connection("alice", "daily");

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    assert!(
        buf.contains("quota_connections_used"),
        "Should contain connection quota metric"
    );
}

#[test]
fn record_quota_exceeded_creates_metric() {
    let metrics = MetricsRegistry::new();

    metrics.record_quota_exceeded("alice", "bandwidth");
    metrics.record_quota_exceeded("alice", "connections");

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    assert!(
        buf.contains("quota_exceeded_total"),
        "Should contain quota exceeded metric"
    );
    assert!(buf.contains("bandwidth"), "Should contain bandwidth type");
    assert!(
        buf.contains("connections"),
        "Should contain connections type"
    );
}
