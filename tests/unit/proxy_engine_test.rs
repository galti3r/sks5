use sks5::audit::AuditLogger;
use sks5::config::parse_config;
use sks5::proxy::ip_guard::is_dangerous_ip;
use sks5::proxy::ProxyEngine;
use std::net::IpAddr;
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
"##
    );
    Arc::new(parse_config(&toml).expect("Failed to parse test config"))
}

fn create_engine(config: Arc<sks5::config::types::AppConfig>) -> ProxyEngine {
    let audit = Arc::new(AuditLogger::new(None, 0, 0, None));
    ProxyEngine::new(config, audit)
}

#[tokio::test]
async fn test_acquire_connection_succeeds_under_global_limit() {
    let config = create_test_config(3, 2);
    let engine = create_engine(config);

    let guard1 = engine
        .acquire_connection("alice", 2)
        .expect("First connection should succeed");
    assert_eq!(engine.active_connections(), 1);
    assert_eq!(engine.user_connections("alice"), 1);

    let guard2 = engine
        .acquire_connection("alice", 2)
        .expect("Second connection should succeed");
    assert_eq!(engine.active_connections(), 2);
    assert_eq!(engine.user_connections("alice"), 2);

    drop(guard1);
    drop(guard2);
}

#[tokio::test]
async fn test_acquire_connection_fails_at_global_limit() {
    let config = create_test_config(2, 5);
    let engine = create_engine(config);

    let _guard1 = engine
        .acquire_connection("alice", 5)
        .expect("First connection should succeed");
    let _guard2 = engine
        .acquire_connection("bob", 5)
        .expect("Second connection should succeed");

    assert_eq!(engine.active_connections(), 2);

    // Third connection should fail - global limit reached
    let result = engine.acquire_connection("alice", 5);
    assert!(result.is_err());
    assert_eq!(engine.active_connections(), 2); // Should remain at 2
}

#[tokio::test]
async fn test_acquire_connection_fails_at_per_user_limit() {
    let config = create_test_config(10, 2);
    let engine = create_engine(config);

    let _guard1 = engine
        .acquire_connection("alice", 2)
        .expect("First connection should succeed");
    let _guard2 = engine
        .acquire_connection("alice", 2)
        .expect("Second connection should succeed");

    assert_eq!(engine.user_connections("alice"), 2);

    // Third connection for alice should fail - per-user limit reached
    let result = engine.acquire_connection("alice", 2);
    assert!(result.is_err());
    assert_eq!(engine.user_connections("alice"), 2); // Should remain at 2
}

#[tokio::test]
async fn test_acquire_connection_rollback_on_per_user_failure() {
    let config = create_test_config(10, 1);
    let engine = create_engine(config);

    let _guard1 = engine
        .acquire_connection("alice", 1)
        .expect("First connection should succeed");
    assert_eq!(engine.active_connections(), 1);
    assert_eq!(engine.user_connections("alice"), 1);

    // Second connection for alice should fail at per-user limit
    let result = engine.acquire_connection("alice", 1);
    assert!(result.is_err());

    // Global counter should have been rolled back
    assert_eq!(engine.active_connections(), 1);
    assert_eq!(engine.user_connections("alice"), 1);
}

#[tokio::test]
async fn test_connection_guard_drop_decrements_counters() {
    let config = create_test_config(10, 5);
    let engine = create_engine(config);

    let guard1 = engine
        .acquire_connection("alice", 5)
        .expect("Connection should succeed");
    let guard2 = engine
        .acquire_connection("alice", 5)
        .expect("Connection should succeed");

    assert_eq!(engine.active_connections(), 2);
    assert_eq!(engine.user_connections("alice"), 2);

    drop(guard1);

    assert_eq!(engine.active_connections(), 1);
    assert_eq!(engine.user_connections("alice"), 1);

    drop(guard2);

    assert_eq!(engine.active_connections(), 0);
    assert_eq!(engine.user_connections("alice"), 0);
}

#[tokio::test]
async fn test_connection_guard_drop_cleans_up_dashmap_entry() {
    let config = create_test_config(10, 5);
    let engine = create_engine(config);

    {
        let _guard = engine
            .acquire_connection("alice", 5)
            .expect("Connection should succeed");
        assert_eq!(engine.user_connections("alice"), 1);
        // DashMap entry should exist
    }

    // After dropping the last connection, the entry should be cleaned up
    assert_eq!(engine.user_connections("alice"), 0);

    // Verify we can still acquire new connections for this user
    let _guard = engine
        .acquire_connection("alice", 5)
        .expect("Connection should succeed");
    assert_eq!(engine.user_connections("alice"), 1);
}

#[tokio::test]
async fn test_multiple_users_can_acquire_separate_slots() {
    let config = create_test_config(10, 3);
    let engine = create_engine(config);

    let _alice1 = engine
        .acquire_connection("alice", 3)
        .expect("Alice connection 1 should succeed");
    let _alice2 = engine
        .acquire_connection("alice", 3)
        .expect("Alice connection 2 should succeed");
    let _bob1 = engine
        .acquire_connection("bob", 3)
        .expect("Bob connection 1 should succeed");
    let _bob2 = engine
        .acquire_connection("bob", 3)
        .expect("Bob connection 2 should succeed");

    assert_eq!(engine.active_connections(), 4);
    assert_eq!(engine.user_connections("alice"), 2);
    assert_eq!(engine.user_connections("bob"), 2);
}

#[tokio::test]
async fn test_mixed_global_and_per_user_limits() {
    let config = create_test_config(3, 2);
    let engine = create_engine(config);

    let _alice1 = engine
        .acquire_connection("alice", 2)
        .expect("Alice connection 1 should succeed");
    let _alice2 = engine
        .acquire_connection("alice", 2)
        .expect("Alice connection 2 should succeed");

    // Alice hits per-user limit
    assert!(engine.acquire_connection("alice", 2).is_err());

    let _bob1 = engine
        .acquire_connection("bob", 2)
        .expect("Bob connection 1 should succeed");

    // Global limit reached (3 total)
    assert_eq!(engine.active_connections(), 3);
    assert!(engine.acquire_connection("bob", 2).is_err());

    drop(_alice1);

    // Now bob can get one more (global has space, bob has per-user space)
    let _bob2 = engine
        .acquire_connection("bob", 2)
        .expect("Bob connection 2 should succeed");
    assert_eq!(engine.active_connections(), 3);
}

// IP Guard Tests

#[test]
fn test_is_dangerous_ip_blocks_loopback_ipv4() {
    let loopback = "127.0.0.1".parse::<IpAddr>().unwrap();
    assert!(is_dangerous_ip(&loopback), "Should block IPv4 loopback");

    let loopback_other = "127.0.0.100".parse::<IpAddr>().unwrap();
    assert!(
        is_dangerous_ip(&loopback_other),
        "Should block IPv4 loopback range"
    );
}

#[test]
fn test_is_dangerous_ip_blocks_loopback_ipv6() {
    let loopback = "::1".parse::<IpAddr>().unwrap();
    assert!(is_dangerous_ip(&loopback), "Should block IPv6 loopback");
}

#[test]
fn test_is_dangerous_ip_blocks_private_ranges_ipv4() {
    let private_10 = "10.0.0.1".parse::<IpAddr>().unwrap();
    assert!(is_dangerous_ip(&private_10), "Should block 10.0.0.0/8");

    let private_172 = "172.16.0.1".parse::<IpAddr>().unwrap();
    assert!(is_dangerous_ip(&private_172), "Should block 172.16.0.0/12");

    let private_192 = "192.168.1.1".parse::<IpAddr>().unwrap();
    assert!(is_dangerous_ip(&private_192), "Should block 192.168.0.0/16");
}

#[test]
fn test_is_dangerous_ip_blocks_link_local() {
    let link_local_v4 = "169.254.1.1".parse::<IpAddr>().unwrap();
    assert!(
        is_dangerous_ip(&link_local_v4),
        "Should block IPv4 link-local"
    );

    let link_local_v6 = "fe80::1".parse::<IpAddr>().unwrap();
    assert!(
        is_dangerous_ip(&link_local_v6),
        "Should block IPv6 link-local"
    );
}

#[test]
fn test_is_dangerous_ip_blocks_multicast() {
    let multicast_v4 = "224.0.0.1".parse::<IpAddr>().unwrap();
    assert!(
        is_dangerous_ip(&multicast_v4),
        "Should block IPv4 multicast"
    );

    let multicast_v6 = "ff00::1".parse::<IpAddr>().unwrap();
    assert!(
        is_dangerous_ip(&multicast_v6),
        "Should block IPv6 multicast"
    );
}

#[test]
fn test_is_dangerous_ip_allows_public_ipv4() {
    let public_ip = "8.8.8.8".parse::<IpAddr>().unwrap();
    assert!(!is_dangerous_ip(&public_ip), "Should allow public IPv4");

    let cloudflare = "1.1.1.1".parse::<IpAddr>().unwrap();
    assert!(!is_dangerous_ip(&cloudflare), "Should allow public IPv4");
}

#[test]
fn test_is_dangerous_ip_allows_public_ipv6() {
    let public_ipv6 = "2606:4700:4700::1111".parse::<IpAddr>().unwrap();
    assert!(!is_dangerous_ip(&public_ipv6), "Should allow public IPv6");
}

#[test]
fn test_is_dangerous_ip_blocks_unspecified() {
    let unspecified_v4 = "0.0.0.0".parse::<IpAddr>().unwrap();
    assert!(is_dangerous_ip(&unspecified_v4), "Should block 0.0.0.0");

    let unspecified_v6 = "::".parse::<IpAddr>().unwrap();
    assert!(is_dangerous_ip(&unspecified_v6), "Should block ::");
}

#[test]
fn test_is_dangerous_ip_blocks_broadcast() {
    let broadcast = "255.255.255.255".parse::<IpAddr>().unwrap();
    assert!(
        is_dangerous_ip(&broadcast),
        "Should block broadcast address"
    );
}
