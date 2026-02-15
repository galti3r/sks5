use sks5::audit::AuditLogger;
use sks5::config::parse_config;
use sks5::metrics::MetricsRegistry;
use sks5::proxy::ProxyEngine;
use std::sync::Arc;

const FAKE_HASH: &str = "argon2id-fakehash-for-testing";

fn create_test_config(
    max_connections: u32,
    max_connections_per_user: u32,
) -> Arc<sks5::config::types::AppConfig> {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[limits]
max_connections = {max_connections}
max_connections_per_user = {max_connections_per_user}

[[users]]
username = "alice"
password_hash = "{FAKE_HASH}"

[[users]]
username = "bob"
password_hash = "{FAKE_HASH}"

[[users]]
username = "charlie"
password_hash = "{FAKE_HASH}"
"##
    );
    Arc::new(parse_config(&toml).expect("Failed to parse test config"))
}

fn create_engine(config: Arc<sks5::config::types::AppConfig>) -> ProxyEngine {
    let audit = Arc::new(AuditLogger::new_noop());
    ProxyEngine::new(config, audit)
}

// ---------------------------------------------------------------------------
// ProxyEngine creation
// ---------------------------------------------------------------------------

#[test]
fn new_proxy_engine_starts_with_zero_connections() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);
    assert_eq!(engine.active_connections(), 0);
}

#[test]
fn new_proxy_engine_reports_zero_user_connections_for_any_user() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);
    assert_eq!(engine.user_connections("alice"), 0);
    assert_eq!(engine.user_connections("bob"), 0);
    assert_eq!(engine.user_connections("unknown"), 0);
}

#[test]
fn new_proxy_engine_has_empty_sessions() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);
    assert!(engine.get_sessions().is_empty());
}

// ---------------------------------------------------------------------------
// register_session / unregister_session
// ---------------------------------------------------------------------------

#[test]
fn register_session_returns_arc_with_correct_fields() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    let session = engine.register_session("alice", "example.com", 443, "10.0.0.1", "ssh");
    assert_eq!(session.username, "alice");
    assert_eq!(session.target_host, "example.com");
    assert_eq!(session.target_port, 443);
    assert_eq!(session.source_ip, "10.0.0.1");
    assert_eq!(session.protocol, "ssh");
    assert_eq!(
        session.bytes_up.load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    assert_eq!(
        session
            .bytes_down
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[test]
fn register_session_generates_unique_session_ids() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    let s1 = engine.register_session("alice", "host1", 80, "10.0.0.1", "ssh");
    let s2 = engine.register_session("bob", "host2", 443, "10.0.0.2", "socks");
    let s3 = engine.register_session("alice", "host3", 8080, "10.0.0.1", "ssh");

    assert_ne!(s1.session_id, s2.session_id);
    assert_ne!(s2.session_id, s3.session_id);
    assert_ne!(s1.session_id, s3.session_id);
}

#[test]
fn register_session_appears_in_get_sessions() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    engine.register_session("alice", "example.com", 443, "10.0.0.1", "ssh");
    let sessions = engine.get_sessions();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].username, "alice");
    assert_eq!(sessions[0].target_host, "example.com");
    assert_eq!(sessions[0].target_port, 443);
}

#[test]
fn register_multiple_sessions_all_appear() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    engine.register_session("alice", "host1", 80, "10.0.0.1", "ssh");
    engine.register_session("bob", "host2", 443, "10.0.0.2", "socks");
    engine.register_session("alice", "host3", 8080, "10.0.0.1", "ssh");

    let sessions = engine.get_sessions();
    assert_eq!(sessions.len(), 3);
}

#[test]
fn unregister_session_removes_it_from_get_sessions() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    let s1 = engine.register_session("alice", "host1", 80, "10.0.0.1", "ssh");
    let _s2 = engine.register_session("bob", "host2", 443, "10.0.0.2", "socks");

    assert_eq!(engine.get_sessions().len(), 2);

    engine.unregister_session(&s1.session_id);
    let sessions = engine.get_sessions();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].username, "bob");
}

#[test]
fn unregister_nonexistent_session_does_not_panic() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    // Should not panic or error
    engine.unregister_session("nonexistent-session-id");
    assert!(engine.get_sessions().is_empty());
}

#[test]
fn unregister_all_sessions_leaves_empty_list() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    let s1 = engine.register_session("alice", "host1", 80, "10.0.0.1", "ssh");
    let s2 = engine.register_session("bob", "host2", 443, "10.0.0.2", "socks");

    engine.unregister_session(&s1.session_id);
    engine.unregister_session(&s2.session_id);

    assert!(engine.get_sessions().is_empty());
}

// ---------------------------------------------------------------------------
// get_user_sessions
// ---------------------------------------------------------------------------

#[test]
fn get_user_sessions_filters_by_username() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    engine.register_session("alice", "host1", 80, "10.0.0.1", "ssh");
    engine.register_session("bob", "host2", 443, "10.0.0.2", "socks");
    engine.register_session("alice", "host3", 8080, "10.0.0.1", "ssh");

    let alice_sessions = engine.get_user_sessions("alice");
    assert_eq!(alice_sessions.len(), 2);
    assert!(alice_sessions.iter().all(|s| s.username == "alice"));

    let bob_sessions = engine.get_user_sessions("bob");
    assert_eq!(bob_sessions.len(), 1);
    assert_eq!(bob_sessions[0].username, "bob");
}

#[test]
fn get_user_sessions_returns_empty_for_unknown_user() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    engine.register_session("alice", "host1", 80, "10.0.0.1", "ssh");

    let sessions = engine.get_user_sessions("unknown");
    assert!(sessions.is_empty());
}

#[test]
fn get_user_sessions_returns_empty_when_no_sessions() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    let sessions = engine.get_user_sessions("alice");
    assert!(sessions.is_empty());
}

// ---------------------------------------------------------------------------
// Connection counting
// ---------------------------------------------------------------------------

#[test]
fn acquire_connection_increments_both_counters() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    let _guard = engine.acquire_connection("alice", 10).unwrap();
    assert_eq!(engine.active_connections(), 1);
    assert_eq!(engine.user_connections("alice"), 1);
}

#[test]
fn acquire_multiple_connections_for_same_user() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    let _g1 = engine.acquire_connection("alice", 10).unwrap();
    let _g2 = engine.acquire_connection("alice", 10).unwrap();
    let _g3 = engine.acquire_connection("alice", 10).unwrap();

    assert_eq!(engine.active_connections(), 3);
    assert_eq!(engine.user_connections("alice"), 3);
}

#[test]
fn acquire_connections_for_different_users() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    let _a = engine.acquire_connection("alice", 10).unwrap();
    let _b = engine.acquire_connection("bob", 10).unwrap();
    let _c = engine.acquire_connection("charlie", 10).unwrap();

    assert_eq!(engine.active_connections(), 3);
    assert_eq!(engine.user_connections("alice"), 1);
    assert_eq!(engine.user_connections("bob"), 1);
    assert_eq!(engine.user_connections("charlie"), 1);
}

#[test]
fn acquire_connection_unlimited_per_user_when_zero() {
    let config = create_test_config(100, 0);
    let engine = create_engine(config);

    // max_per_user=0 means unlimited, should allow many connections
    let mut guards = Vec::new();
    for _ in 0..20 {
        guards.push(engine.acquire_connection("alice", 0).unwrap());
    }
    assert_eq!(engine.active_connections(), 20);
    assert_eq!(engine.user_connections("alice"), 20);
}

#[test]
fn acquire_connection_global_limit_enforced() {
    let config = create_test_config(2, 10);
    let engine = create_engine(config);

    let _g1 = engine.acquire_connection("alice", 10).unwrap();
    let _g2 = engine.acquire_connection("bob", 10).unwrap();

    let result = engine.acquire_connection("charlie", 10);
    assert!(result.is_err());
    assert_eq!(engine.active_connections(), 2);
}

#[test]
fn acquire_connection_per_user_limit_enforced() {
    let config = create_test_config(100, 2);
    let engine = create_engine(config);

    let _g1 = engine.acquire_connection("alice", 2).unwrap();
    let _g2 = engine.acquire_connection("alice", 2).unwrap();

    let result = engine.acquire_connection("alice", 2);
    assert!(result.is_err());
    // Global counter should have been rolled back
    assert_eq!(engine.active_connections(), 2);
    assert_eq!(engine.user_connections("alice"), 2);
}

#[test]
fn acquire_connection_per_user_override_limit() {
    // Config has max_connections_per_user=5, but we pass max_per_user=1
    let config = create_test_config(100, 5);
    let engine = create_engine(config);

    let _g1 = engine.acquire_connection("alice", 1).unwrap();
    let result = engine.acquire_connection("alice", 1);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// ConnectionGuard (RAII session cleanup)
// ---------------------------------------------------------------------------

#[test]
fn connection_guard_drop_decrements_global_counter() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    let guard = engine.acquire_connection("alice", 10).unwrap();
    assert_eq!(engine.active_connections(), 1);

    drop(guard);
    assert_eq!(engine.active_connections(), 0);
}

#[test]
fn connection_guard_drop_decrements_user_counter() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    let guard = engine.acquire_connection("alice", 10).unwrap();
    assert_eq!(engine.user_connections("alice"), 1);

    drop(guard);
    assert_eq!(engine.user_connections("alice"), 0);
}

#[test]
fn connection_guard_drop_cleans_dashmap_entry_on_last_connection() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    {
        let _g1 = engine.acquire_connection("alice", 10).unwrap();
        let _g2 = engine.acquire_connection("alice", 10).unwrap();
        assert_eq!(engine.user_connections("alice"), 2);
        // Drop g2 first
    }
    // Both guards dropped
    assert_eq!(engine.user_connections("alice"), 0);

    // Verify we can acquire again (entry was cleaned up)
    let _g = engine.acquire_connection("alice", 10).unwrap();
    assert_eq!(engine.user_connections("alice"), 1);
}

#[test]
fn connection_guard_drop_allows_new_connection_within_limit() {
    let config = create_test_config(1, 1);
    let engine = create_engine(config);

    let guard = engine.acquire_connection("alice", 1).unwrap();
    // Global limit 1 reached
    assert!(engine.acquire_connection("bob", 1).is_err());

    drop(guard);
    // Now bob can connect
    let _bob = engine.acquire_connection("bob", 1).unwrap();
    assert_eq!(engine.active_connections(), 1);
}

#[test]
fn multiple_guards_dropped_in_order() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    let g1 = engine.acquire_connection("alice", 10).unwrap();
    let g2 = engine.acquire_connection("alice", 10).unwrap();
    let g3 = engine.acquire_connection("alice", 10).unwrap();

    assert_eq!(engine.active_connections(), 3);
    assert_eq!(engine.user_connections("alice"), 3);

    drop(g1);
    assert_eq!(engine.active_connections(), 2);
    assert_eq!(engine.user_connections("alice"), 2);

    drop(g2);
    assert_eq!(engine.active_connections(), 1);
    assert_eq!(engine.user_connections("alice"), 1);

    drop(g3);
    assert_eq!(engine.active_connections(), 0);
    assert_eq!(engine.user_connections("alice"), 0);
}

// ---------------------------------------------------------------------------
// Session snapshots
// ---------------------------------------------------------------------------

#[test]
fn session_snapshot_captures_correct_fields() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    let session = engine.register_session("alice", "example.com", 443, "10.0.0.1", "ssh");

    // Update byte counters
    session
        .bytes_up
        .store(1024, std::sync::atomic::Ordering::Relaxed);
    session
        .bytes_down
        .store(2048, std::sync::atomic::Ordering::Relaxed);

    let snapshots = engine.get_sessions();
    assert_eq!(snapshots.len(), 1);
    let snap = &snapshots[0];
    assert_eq!(snap.username, "alice");
    assert_eq!(snap.target_host, "example.com");
    assert_eq!(snap.target_port, 443);
    assert_eq!(snap.source_ip, "10.0.0.1");
    assert_eq!(snap.protocol, "ssh");
    assert_eq!(snap.bytes_up, 1024);
    assert_eq!(snap.bytes_down, 2048);
}

#[test]
fn session_snapshot_reflects_atomic_counter_updates() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    let session = engine.register_session("alice", "host", 80, "10.0.0.1", "ssh");

    // Initial snapshot: zero bytes
    let snap1 = engine.get_sessions();
    assert_eq!(snap1[0].bytes_up, 0);
    assert_eq!(snap1[0].bytes_down, 0);

    // Update counters
    session
        .bytes_up
        .fetch_add(100, std::sync::atomic::Ordering::Relaxed);
    session
        .bytes_down
        .fetch_add(200, std::sync::atomic::Ordering::Relaxed);

    // New snapshot should reflect updates
    let snap2 = engine.get_sessions();
    assert_eq!(snap2[0].bytes_up, 100);
    assert_eq!(snap2[0].bytes_down, 200);
}

#[test]
fn live_session_snapshot_method_creates_independent_copy() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    let session = engine.register_session("alice", "host", 80, "10.0.0.1", "ssh");
    let snapshot = session.snapshot();

    // Modify atomic counters after snapshot
    session
        .bytes_up
        .store(999, std::sync::atomic::Ordering::Relaxed);

    // Snapshot should retain original value (it's a copy)
    assert_eq!(snapshot.bytes_up, 0);
}

// ---------------------------------------------------------------------------
// active_connection_details
// ---------------------------------------------------------------------------

#[test]
fn active_connection_details_returns_per_user_counts() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    let _a1 = engine.acquire_connection("alice", 10).unwrap();
    let _a2 = engine.acquire_connection("alice", 10).unwrap();
    let _b1 = engine.acquire_connection("bob", 10).unwrap();

    let details = engine.active_connection_details();
    assert_eq!(details.len(), 2);

    let alice_count = details.iter().find(|(u, _)| u == "alice").map(|(_, c)| *c);
    let bob_count = details.iter().find(|(u, _)| u == "bob").map(|(_, c)| *c);

    assert_eq!(alice_count, Some(2));
    assert_eq!(bob_count, Some(1));
}

#[test]
fn active_connection_details_excludes_zero_count_users() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    let g = engine.acquire_connection("alice", 10).unwrap();
    drop(g);

    let details = engine.active_connection_details();
    assert!(details.is_empty() || details.iter().all(|(_, c)| *c > 0));
}

#[test]
fn active_connection_details_empty_when_no_connections() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    let details = engine.active_connection_details();
    assert!(details.is_empty());
}

// ---------------------------------------------------------------------------
// Metrics integration (connections_total counter)
// ---------------------------------------------------------------------------

#[test]
fn register_session_increments_connections_total_when_metrics_set() {
    let config = create_test_config(100, 10);
    let audit = Arc::new(AuditLogger::new_noop());
    let mut engine = ProxyEngine::new(config, audit);
    let metrics = Arc::new(MetricsRegistry::new());
    engine.set_metrics(metrics.clone());

    assert_eq!(metrics.connections_total.get(), 0);

    engine.register_session("alice", "host1", 80, "10.0.0.1", "ssh");
    assert_eq!(metrics.connections_total.get(), 1);

    engine.register_session("bob", "host2", 443, "10.0.0.2", "socks");
    assert_eq!(metrics.connections_total.get(), 2);
}

#[test]
fn register_session_does_not_panic_without_metrics() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    // No metrics set -- should not panic
    engine.register_session("alice", "host1", 80, "10.0.0.1", "ssh");
    assert_eq!(engine.get_sessions().len(), 1);
}

// ---------------------------------------------------------------------------
// Session ID format
// ---------------------------------------------------------------------------

#[test]
fn session_ids_start_with_s_prefix() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    let s1 = engine.register_session("alice", "host", 80, "10.0.0.1", "ssh");
    let s2 = engine.register_session("bob", "host", 443, "10.0.0.2", "socks");

    assert!(s1.session_id.starts_with('s'));
    assert!(s2.session_id.starts_with('s'));
}

#[test]
fn session_ids_are_sequential() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    let s1 = engine.register_session("alice", "host", 80, "10.0.0.1", "ssh");
    let s2 = engine.register_session("bob", "host", 443, "10.0.0.2", "socks");

    // Extract numeric part
    let n1: u64 = s1.session_id[1..].parse().unwrap();
    let n2: u64 = s2.session_id[1..].parse().unwrap();
    assert_eq!(n2, n1 + 1);
}
