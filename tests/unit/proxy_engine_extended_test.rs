use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::Utc;

use sks5::audit::AuditLogger;
use sks5::config::parse_config;
use sks5::proxy::{LiveSession, ProxyEngine, SessionSnapshot};

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
"##
    );
    Arc::new(parse_config(&toml).expect("Failed to parse test config"))
}

fn create_engine(config: Arc<sks5::config::types::AppConfig>) -> ProxyEngine {
    let audit = Arc::new(AuditLogger::new_noop());
    ProxyEngine::new(config, audit)
}

// ---------------------------------------------------------------------------
// ConnectionGuard drop behavior
// ---------------------------------------------------------------------------

#[test]
fn connection_guard_acquire_increments_active_connections() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    assert_eq!(engine.active_connections(), 0);

    let _guard1 = engine.acquire_connection("alice", 10).unwrap();
    assert_eq!(engine.active_connections(), 1);

    let _guard2 = engine.acquire_connection("alice", 10).unwrap();
    assert_eq!(engine.active_connections(), 2);
}

#[test]
fn connection_guard_drop_decrements_active_connections() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    let guard = engine.acquire_connection("alice", 10).unwrap();
    assert_eq!(engine.active_connections(), 1);
    assert_eq!(engine.user_connections("alice"), 1);

    drop(guard);
    assert_eq!(engine.active_connections(), 0);
    assert_eq!(engine.user_connections("alice"), 0);
}

#[test]
fn connection_guard_drop_partial_release() {
    let config = create_test_config(100, 10);
    let engine = create_engine(config);

    let guard1 = engine.acquire_connection("alice", 10).unwrap();
    let _guard2 = engine.acquire_connection("alice", 10).unwrap();
    let _guard3 = engine.acquire_connection("bob", 10).unwrap();

    assert_eq!(engine.active_connections(), 3);
    assert_eq!(engine.user_connections("alice"), 2);
    assert_eq!(engine.user_connections("bob"), 1);

    // Drop only guard1 - alice should go from 2 to 1, global from 3 to 2
    drop(guard1);
    assert_eq!(engine.active_connections(), 2);
    assert_eq!(engine.user_connections("alice"), 1);
    assert_eq!(engine.user_connections("bob"), 1);
}

#[test]
fn connection_guard_drop_frees_slot_for_reuse() {
    let config = create_test_config(1, 1);
    let engine = create_engine(config);

    let guard = engine.acquire_connection("alice", 1).unwrap();
    // Global limit of 1 reached
    assert!(engine.acquire_connection("bob", 1).is_err());

    drop(guard);

    // Slot freed, bob can now connect
    let _bob_guard = engine.acquire_connection("bob", 1).unwrap();
    assert_eq!(engine.active_connections(), 1);
    assert_eq!(engine.user_connections("bob"), 1);
}

// ---------------------------------------------------------------------------
// LiveSession snapshot
// ---------------------------------------------------------------------------

#[test]
fn live_session_snapshot_captures_initial_values() {
    let session = LiveSession {
        session_id: "s42".to_string(),
        username: "alice".to_string(),
        target_host: "example.com".to_string(),
        target_port: 443,
        source_ip: "10.0.0.1".to_string(),
        started_at: Utc::now(),
        bytes_up: AtomicU64::new(0),
        bytes_down: AtomicU64::new(0),
        protocol: "ssh".to_string(),
    };

    let snap = session.snapshot();
    assert_eq!(snap.session_id, "s42");
    assert_eq!(snap.username, "alice");
    assert_eq!(snap.target_host, "example.com");
    assert_eq!(snap.target_port, 443);
    assert_eq!(snap.source_ip, "10.0.0.1");
    assert_eq!(snap.protocol, "ssh");
    assert_eq!(snap.bytes_up, 0);
    assert_eq!(snap.bytes_down, 0);
}

#[test]
fn live_session_snapshot_reflects_updated_atomic_counters() {
    let session = LiveSession {
        session_id: "s99".to_string(),
        username: "bob".to_string(),
        target_host: "proxy.test".to_string(),
        target_port: 8080,
        source_ip: "172.16.0.5".to_string(),
        started_at: Utc::now(),
        bytes_up: AtomicU64::new(0),
        bytes_down: AtomicU64::new(0),
        protocol: "socks".to_string(),
    };

    // Simulate traffic
    session.bytes_up.fetch_add(4096, Ordering::Relaxed);
    session.bytes_down.fetch_add(8192, Ordering::Relaxed);

    let snap = session.snapshot();
    assert_eq!(snap.bytes_up, 4096);
    assert_eq!(snap.bytes_down, 8192);
}

#[test]
fn live_session_snapshot_is_independent_copy() {
    let session = LiveSession {
        session_id: "s1".to_string(),
        username: "alice".to_string(),
        target_host: "host.test".to_string(),
        target_port: 80,
        source_ip: "10.0.0.1".to_string(),
        started_at: Utc::now(),
        bytes_up: AtomicU64::new(100),
        bytes_down: AtomicU64::new(200),
        protocol: "ssh".to_string(),
    };

    let snap = session.snapshot();

    // Modify counters after taking snapshot
    session.bytes_up.store(9999, Ordering::Relaxed);
    session.bytes_down.store(8888, Ordering::Relaxed);

    // Snapshot should retain the original values
    assert_eq!(snap.bytes_up, 100);
    assert_eq!(snap.bytes_down, 200);
}

#[test]
fn live_session_snapshot_with_incremental_updates() {
    let session = LiveSession {
        session_id: "s7".to_string(),
        username: "charlie".to_string(),
        target_host: "api.example.com".to_string(),
        target_port: 443,
        source_ip: "192.168.1.10".to_string(),
        started_at: Utc::now(),
        bytes_up: AtomicU64::new(0),
        bytes_down: AtomicU64::new(0),
        protocol: "socks".to_string(),
    };

    // First snapshot: zero
    let snap1 = session.snapshot();
    assert_eq!(snap1.bytes_up, 0);
    assert_eq!(snap1.bytes_down, 0);

    // Add some traffic
    session.bytes_up.fetch_add(512, Ordering::Relaxed);
    session.bytes_down.fetch_add(1024, Ordering::Relaxed);

    let snap2 = session.snapshot();
    assert_eq!(snap2.bytes_up, 512);
    assert_eq!(snap2.bytes_down, 1024);

    // Add more traffic
    session.bytes_up.fetch_add(256, Ordering::Relaxed);
    session.bytes_down.fetch_add(2048, Ordering::Relaxed);

    let snap3 = session.snapshot();
    assert_eq!(snap3.bytes_up, 768);
    assert_eq!(snap3.bytes_down, 3072);

    // Earlier snapshots should be unchanged
    assert_eq!(snap1.bytes_up, 0);
    assert_eq!(snap2.bytes_up, 512);
}

// ---------------------------------------------------------------------------
// SessionSnapshot serialization
// ---------------------------------------------------------------------------

#[test]
fn session_snapshot_serializes_to_json_with_all_fields() {
    let started = Utc::now();
    let snap = SessionSnapshot {
        session_id: "s123".to_string(),
        username: "alice".to_string(),
        target_host: "example.com".to_string(),
        target_port: 443,
        source_ip: "10.0.0.1".to_string(),
        started_at: started,
        bytes_up: 1024,
        bytes_down: 2048,
        protocol: "ssh".to_string(),
    };

    let json_value = serde_json::to_value(&snap).expect("Serialization should succeed");
    let obj = json_value.as_object().expect("Should be a JSON object");

    assert_eq!(obj.get("session_id").unwrap().as_str().unwrap(), "s123");
    assert_eq!(obj.get("username").unwrap().as_str().unwrap(), "alice");
    assert_eq!(
        obj.get("target_host").unwrap().as_str().unwrap(),
        "example.com"
    );
    assert_eq!(obj.get("target_port").unwrap().as_u64().unwrap(), 443);
    assert_eq!(obj.get("source_ip").unwrap().as_str().unwrap(), "10.0.0.1");
    assert_eq!(obj.get("bytes_up").unwrap().as_u64().unwrap(), 1024);
    assert_eq!(obj.get("bytes_down").unwrap().as_u64().unwrap(), 2048);
    assert_eq!(obj.get("protocol").unwrap().as_str().unwrap(), "ssh");
    // started_at should be present as a string (ISO 8601 via chrono serde)
    assert!(
        obj.get("started_at").unwrap().is_string(),
        "started_at should serialize as a string"
    );
}

#[test]
fn session_snapshot_serializes_zero_bytes() {
    let snap = SessionSnapshot {
        session_id: "s0".to_string(),
        username: "bob".to_string(),
        target_host: "localhost".to_string(),
        target_port: 80,
        source_ip: "127.0.0.1".to_string(),
        started_at: Utc::now(),
        bytes_up: 0,
        bytes_down: 0,
        protocol: "socks".to_string(),
    };

    let json_value = serde_json::to_value(&snap).expect("Serialization should succeed");
    let obj = json_value.as_object().expect("Should be a JSON object");

    assert_eq!(obj.get("bytes_up").unwrap().as_u64().unwrap(), 0);
    assert_eq!(obj.get("bytes_down").unwrap().as_u64().unwrap(), 0);
}

#[test]
fn session_snapshot_serializes_large_byte_counts() {
    let snap = SessionSnapshot {
        session_id: "s999".to_string(),
        username: "heavyuser".to_string(),
        target_host: "cdn.example.com".to_string(),
        target_port: 443,
        source_ip: "10.0.0.1".to_string(),
        started_at: Utc::now(),
        bytes_up: u64::MAX,
        bytes_down: u64::MAX,
        protocol: "ssh".to_string(),
    };

    let json_str = serde_json::to_string(&snap).expect("Serialization should succeed");
    assert!(
        json_str.contains(&u64::MAX.to_string()),
        "Should handle u64::MAX byte counts"
    );
}

#[test]
fn session_snapshot_json_has_exactly_expected_fields() {
    let snap = SessionSnapshot {
        session_id: "s1".to_string(),
        username: "test".to_string(),
        target_host: "host".to_string(),
        target_port: 22,
        source_ip: "1.2.3.4".to_string(),
        started_at: Utc::now(),
        bytes_up: 0,
        bytes_down: 0,
        protocol: "ssh".to_string(),
    };

    let json_value = serde_json::to_value(&snap).expect("Serialization should succeed");
    let obj = json_value.as_object().expect("Should be a JSON object");

    let expected_fields = [
        "session_id",
        "username",
        "target_host",
        "target_port",
        "source_ip",
        "started_at",
        "bytes_up",
        "bytes_down",
        "protocol",
    ];

    assert_eq!(
        obj.len(),
        expected_fields.len(),
        "JSON should have exactly {} fields, got {}",
        expected_fields.len(),
        obj.len()
    );

    for field in &expected_fields {
        assert!(
            obj.contains_key(*field),
            "JSON should contain field '{field}'"
        );
    }
}
