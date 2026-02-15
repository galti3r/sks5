use sks5::config::parse_config;
use sks5::security::ban::BanManager;
use sks5::security::ip_filter;
use sks5::security::SecurityManager;
use std::net::IpAddr;
use std::time::Duration;

const FAKE_HASH: &str = "argon2id-fakehash-for-testing";

fn create_test_config(security_section: &str) -> sks5::config::types::AppConfig {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

{security_section}

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    parse_config(&toml).unwrap()
}

#[test]
fn test_check_source_ip_allows_ip_in_range() {
    let config = create_test_config(
        r##"
[security]
allowed_source_ips = ["192.168.0.0/24"]
"##,
    );
    let security = SecurityManager::new(&config);

    let ip: IpAddr = "192.168.0.100".parse().unwrap();
    assert!(security.check_source_ip(&ip));
}

#[test]
fn test_check_source_ip_blocks_ip_not_in_range() {
    let config = create_test_config(
        r##"
[security]
allowed_source_ips = ["192.168.0.0/24"]
"##,
    );
    let security = SecurityManager::new(&config);

    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    assert!(!security.check_source_ip(&ip));
}

#[test]
fn test_check_source_ip_allows_all_when_list_is_empty() {
    let config = create_test_config("");
    let security = SecurityManager::new(&config);

    let ip1: IpAddr = "192.168.0.1".parse().unwrap();
    let ip2: IpAddr = "10.0.0.1".parse().unwrap();
    let ip3: IpAddr = "8.8.8.8".parse().unwrap();

    assert!(security.check_source_ip(&ip1));
    assert!(security.check_source_ip(&ip2));
    assert!(security.check_source_ip(&ip3));
}

#[test]
fn test_check_rate_limit_passes_under_limit() {
    let config = create_test_config(
        r##"
[security]
ban_enabled = false
"##,
    );
    let security = SecurityManager::new(&config);

    // Test rate limit of 5 per minute
    for _ in 0..4 {
        assert!(security.check_rate_limit("testuser", 5));
    }
}

#[test]
fn test_check_rate_limit_fails_over_limit() {
    let config = create_test_config(
        r##"
[security]
ban_enabled = false
"##,
    );
    let security = SecurityManager::new(&config);

    // Exhaust the limit (5 per minute)
    for _ in 0..5 {
        security.check_rate_limit("testuser", 5);
    }

    // Next one should fail
    assert!(!security.check_rate_limit("testuser", 5));
}

#[test]
fn test_check_rate_limit_unlimited_when_max_is_zero() {
    let config = create_test_config(
        r##"
[security]
ban_enabled = false
"##,
    );
    let security = SecurityManager::new(&config);

    // Should allow unlimited connections
    for _ in 0..100 {
        assert!(security.check_rate_limit("testuser", 0));
    }
}

#[test]
fn test_ban_manager_toctou_fix() {
    // Create ban manager with very short duration (1 second)
    let mgr = BanManager::new(true, 1, 300, 1, vec![]);
    let ip: IpAddr = "1.2.3.4".parse().unwrap();

    // Trigger a ban
    mgr.record_failure(&ip);
    assert!(mgr.is_banned(&ip));

    // Wait for ban to expire
    std::thread::sleep(Duration::from_secs(2));

    // The TOCTOU fix ensures is_banned atomically removes expired bans
    // and returns false, not true followed by a separate removal
    assert!(!mgr.is_banned(&ip));

    // Verify ban was actually removed (not just expired check)
    assert!(!mgr.is_banned(&ip));
}

#[test]
fn test_record_auth_failure_triggers_ban_after_threshold() {
    let config = create_test_config(
        r##"
[security]
ban_enabled = true
ban_threshold = 3
ban_window = 300
ban_duration = 60
"##,
    );
    let security = SecurityManager::new(&config);
    let ip: IpAddr = "203.0.113.50".parse().unwrap();

    // Should not be banned initially
    assert!(!security.is_banned(&ip));

    // Record failures below threshold
    security.record_auth_failure(&ip);
    security.record_auth_failure(&ip);
    assert!(!security.is_banned(&ip));

    // Third failure should trigger ban
    security.record_auth_failure(&ip);
    assert!(security.is_banned(&ip));
}

#[test]
fn test_ip_filter_multiple_ranges() {
    let networks: Vec<ipnet::IpNet> = vec![
        "10.0.0.0/8".parse().unwrap(),
        "192.168.0.0/16".parse().unwrap(),
        "172.16.0.0/12".parse().unwrap(),
    ];

    // IPs in allowed ranges
    assert!(ip_filter::is_allowed(
        &"10.1.2.3".parse().unwrap(),
        &networks
    ));
    assert!(ip_filter::is_allowed(
        &"192.168.100.1".parse().unwrap(),
        &networks
    ));
    assert!(ip_filter::is_allowed(
        &"172.16.0.1".parse().unwrap(),
        &networks
    ));

    // IP not in any range
    assert!(!ip_filter::is_allowed(
        &"8.8.8.8".parse().unwrap(),
        &networks
    ));
}

#[test]
fn test_ban_manager_whitelist_never_bans() {
    let mgr = BanManager::new(true, 1, 300, 60, vec!["127.0.0.1".to_string()]);
    let ip: IpAddr = "127.0.0.1".parse().unwrap();

    // Even with threshold of 1, whitelisted IP should never be banned
    mgr.record_failure(&ip);
    mgr.record_failure(&ip);
    mgr.record_failure(&ip);

    assert!(!mgr.is_banned(&ip));
}

// ---------------------------------------------------------------------------
// L-4: Ban whitelist CIDR range support
// ---------------------------------------------------------------------------

#[test]
fn test_ban_whitelist_cidr_range() {
    // Whitelist entire 10.0.0.0/8 range
    let mgr = BanManager::new(true, 1, 300, 60, vec!["10.0.0.0/8".to_string()]);

    let ip1: IpAddr = "10.1.2.3".parse().unwrap();
    let ip2: IpAddr = "10.255.255.254".parse().unwrap();
    let ip3: IpAddr = "11.0.0.1".parse().unwrap();

    // IPs within the CIDR range should never be banned
    mgr.record_failure(&ip1);
    assert!(
        !mgr.is_banned(&ip1),
        "10.1.2.3 should be whitelisted by 10.0.0.0/8"
    );

    mgr.record_failure(&ip2);
    assert!(
        !mgr.is_banned(&ip2),
        "10.255.255.254 should be whitelisted by 10.0.0.0/8"
    );

    // IP outside the range should be banned after 1 failure
    mgr.record_failure(&ip3);
    assert!(mgr.is_banned(&ip3), "11.0.0.1 should NOT be whitelisted");
}

#[test]
fn test_ban_whitelist_mixed_ip_and_cidr() {
    let mgr = BanManager::new(
        true,
        1,
        300,
        60,
        vec!["127.0.0.1".to_string(), "192.168.0.0/16".to_string()],
    );

    let loopback: IpAddr = "127.0.0.1".parse().unwrap();
    let private: IpAddr = "192.168.50.100".parse().unwrap();
    let public: IpAddr = "8.8.8.8".parse().unwrap();

    mgr.record_failure(&loopback);
    assert!(
        !mgr.is_banned(&loopback),
        "127.0.0.1 whitelisted as single IP"
    );

    mgr.record_failure(&private);
    assert!(
        !mgr.is_banned(&private),
        "192.168.50.100 whitelisted by CIDR"
    );

    mgr.record_failure(&public);
    assert!(mgr.is_banned(&public), "8.8.8.8 not whitelisted");
}

#[test]
fn test_ban_whitelist_cidr_ipv6() {
    let mgr = BanManager::new(true, 1, 300, 60, vec!["fd00::/8".to_string()]);

    let ip_in: IpAddr = "fd12:3456:789a::1".parse().unwrap();
    let ip_out: IpAddr = "2001:db8::1".parse().unwrap();

    mgr.record_failure(&ip_in);
    assert!(
        !mgr.is_banned(&ip_in),
        "fd12::1 should be whitelisted by fd00::/8"
    );

    mgr.record_failure(&ip_out);
    assert!(
        mgr.is_banned(&ip_out),
        "2001:db8::1 should NOT be whitelisted"
    );
}

#[test]
fn test_ban_whitelist_invalid_entries_skipped() {
    // Invalid entries should be silently skipped, valid ones should work
    let mgr = BanManager::new(
        true,
        1,
        300,
        60,
        vec![
            "not-an-ip".to_string(),
            "192.168.1.0/24".to_string(),
            "also-invalid".to_string(),
        ],
    );

    let ip_in: IpAddr = "192.168.1.50".parse().unwrap();
    let ip_out: IpAddr = "192.168.2.50".parse().unwrap();

    mgr.record_failure(&ip_in);
    assert!(
        !mgr.is_banned(&ip_in),
        "192.168.1.50 whitelisted despite invalid entries"
    );

    mgr.record_failure(&ip_out);
    assert!(mgr.is_banned(&ip_out), "192.168.2.50 not in whitelist");
}

#[test]
fn test_security_manager_pre_auth_check_ban_whitelist_cidr() {
    let config = create_test_config(
        r##"
[security]
ban_enabled = true
ban_threshold = 1
ban_window = 300
ban_duration = 600
ban_whitelist = ["10.0.0.0/8"]
"##,
    );
    let security = SecurityManager::new(&config);

    let whitelisted_ip: IpAddr = "10.1.2.3".parse().unwrap();
    let normal_ip: IpAddr = "203.0.113.50".parse().unwrap();

    // Whitelisted IP should never be banned even after failures
    security.record_auth_failure(&whitelisted_ip);
    security.record_auth_failure(&whitelisted_ip);
    assert!(!security.is_banned(&whitelisted_ip));

    // Non-whitelisted IP should be banned after threshold
    security.record_auth_failure(&normal_ip);
    assert!(security.is_banned(&normal_ip));
}
