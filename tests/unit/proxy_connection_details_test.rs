use sks5::audit::AuditLogger;
use sks5::config::parse_config;
use sks5::proxy::ProxyEngine;
use std::sync::Arc;

const FAKE_HASH: &str = "argon2id-fakehash-for-testing";

fn make_engine() -> ProxyEngine {
    let config_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"

[limits]
max_connections = 100
max_connections_per_user = 50

[security]
ban_enabled = false

[[users]]
username = "alice"
password_hash = "{FAKE_HASH}"

[[users]]
username = "bob"
password_hash = "{FAKE_HASH}"
"##
    );
    let config = parse_config(&config_str).expect("Failed to parse test config");
    let audit = Arc::new(AuditLogger::new(None, 0, 0, None));
    ProxyEngine::new(Arc::new(config), audit)
}

// ---------------------------------------------------------------------------
// Test 1: No connections -> empty details vec
// ---------------------------------------------------------------------------
#[tokio::test]
async fn active_connection_details_empty_initially() {
    let engine = make_engine();
    let details = engine.active_connection_details();
    assert!(
        details.is_empty(),
        "details should be empty with no connections, got: {:?}",
        details
    );
}

// ---------------------------------------------------------------------------
// Test 2: Acquire connections for alice and bob, verify both appear
// ---------------------------------------------------------------------------
#[tokio::test]
async fn active_connection_details_shows_users() {
    let engine = make_engine();

    let _alice_guard = engine
        .acquire_connection("alice", 0)
        .expect("alice connection should succeed");
    let _bob_guard = engine
        .acquire_connection("bob", 0)
        .expect("bob connection should succeed");

    let details = engine.active_connection_details();
    assert_eq!(details.len(), 2, "should have details for 2 users");

    let alice_count = details
        .iter()
        .find(|(name, _)| name == "alice")
        .map(|(_, c)| *c);
    let bob_count = details
        .iter()
        .find(|(name, _)| name == "bob")
        .map(|(_, c)| *c);

    assert_eq!(alice_count, Some(1), "alice should have 1 connection");
    assert_eq!(bob_count, Some(1), "bob should have 1 connection");
}

// ---------------------------------------------------------------------------
// Test 3: Acquire connection, drop guard, verify details is empty
// ---------------------------------------------------------------------------
#[tokio::test]
async fn active_connection_details_after_drop() {
    let engine = make_engine();

    {
        let _guard = engine
            .acquire_connection("alice", 0)
            .expect("alice connection should succeed");

        let details = engine.active_connection_details();
        assert_eq!(details.len(), 1, "should have 1 entry while guard is held");
        assert_eq!(details[0].0, "alice");
        assert_eq!(details[0].1, 1);
    }
    // guard dropped here

    let details = engine.active_connection_details();
    assert!(
        details.is_empty(),
        "details should be empty after dropping the guard, got: {:?}",
        details
    );
}

// ---------------------------------------------------------------------------
// Test 4: Multiple connections per user - 3 for alice, 2 for bob
// ---------------------------------------------------------------------------
#[tokio::test]
async fn active_connection_details_multiple_connections() {
    let engine = make_engine();

    let _a1 = engine.acquire_connection("alice", 0).expect("alice conn 1");
    let _a2 = engine.acquire_connection("alice", 0).expect("alice conn 2");
    let _a3 = engine.acquire_connection("alice", 0).expect("alice conn 3");

    let _b1 = engine.acquire_connection("bob", 0).expect("bob conn 1");
    let _b2 = engine.acquire_connection("bob", 0).expect("bob conn 2");

    let details = engine.active_connection_details();
    assert_eq!(details.len(), 2, "should have details for 2 users");

    let alice_count = details
        .iter()
        .find(|(name, _)| name == "alice")
        .map(|(_, c)| *c);
    let bob_count = details
        .iter()
        .find(|(name, _)| name == "bob")
        .map(|(_, c)| *c);

    assert_eq!(alice_count, Some(3), "alice should have 3 connections");
    assert_eq!(bob_count, Some(2), "bob should have 2 connections");
}
