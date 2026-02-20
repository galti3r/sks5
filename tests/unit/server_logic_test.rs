//! Tests for server-adjacent logic: config validation edge cases,
//! proxy engine session management under stress, and connection guard
//! atomicity.
//!
//! These cover paths in server.rs-related code that are testable without
//! launching a real server: maintenance windows, config validation,
//! proxy engine edge behaviors, and redaction correctness.

use sks5::audit::AuditLogger;
use sks5::config::parse_config;
use sks5::config::redact::redact_config;
use sks5::config::types::*;
use sks5::proxy::ProxyEngine;
use std::sync::Arc;

const FAKE_HASH: &str = "argon2id-fakehash-for-testing";

fn make_engine_with_limits(max_global: u32, max_per_user: u32) -> ProxyEngine {
    let toml = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"

[limits]
max_connections = {max_global}
max_connections_per_user = {max_per_user}

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
    let config = parse_config(&toml).expect("test config");
    let audit = Arc::new(AuditLogger::new_noop());
    ProxyEngine::new(Arc::new(config), audit)
}

// ---------------------------------------------------------------------------
// 1. Config validation: SOCKS5 handshake timeout bounds
// ---------------------------------------------------------------------------

#[test]
fn socks5_handshake_timeout_below_min_rejected() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[limits]
socks5_handshake_timeout = 4

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    let err = parse_config(&toml).unwrap_err();
    assert!(err.to_string().contains("socks5_handshake_timeout"));
}

#[test]
fn socks5_handshake_timeout_above_max_rejected() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[limits]
socks5_handshake_timeout = 121

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    let err = parse_config(&toml).unwrap_err();
    assert!(err.to_string().contains("socks5_handshake_timeout"));
}

#[test]
fn socks5_handshake_timeout_at_boundaries_accepted() {
    let toml_min = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[limits]
socks5_handshake_timeout = 5

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    assert!(parse_config(&toml_min).is_ok());

    let toml_max = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[limits]
socks5_handshake_timeout = 120

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    assert!(parse_config(&toml_max).is_ok());
}

// ---------------------------------------------------------------------------
// 2. Config validation: API token length check
// ---------------------------------------------------------------------------

#[test]
fn api_token_too_short_rejected() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[api]
enabled = true
token = "short"

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    let err = parse_config(&toml).unwrap_err();
    assert!(err.to_string().contains("too short"));
}

#[test]
fn api_token_exactly_16_chars_accepted() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[api]
enabled = true
token = "0123456789abcdef"

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    assert!(parse_config(&toml).is_ok());
}

// ---------------------------------------------------------------------------
// 3. Config validation: SOCKS5 TLS cert/key pairing
// ---------------------------------------------------------------------------

#[test]
fn socks5_tls_cert_without_key_rejected() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"
socks5_tls_cert = "/tmp/cert.pem"

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    let err = parse_config(&toml).unwrap_err();
    assert!(err
        .to_string()
        .contains("socks5_tls_cert and socks5_tls_key"));
}

#[test]
fn socks5_tls_key_without_cert_rejected() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"
socks5_tls_key = "/tmp/key.pem"

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    let err = parse_config(&toml).unwrap_err();
    assert!(err
        .to_string()
        .contains("socks5_tls_cert and socks5_tls_key"));
}

// ---------------------------------------------------------------------------
// 4. Config validation: ban_threshold must be >= 1 when bans enabled
// ---------------------------------------------------------------------------

#[test]
fn ban_threshold_zero_with_ban_enabled_rejected() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[security]
ban_enabled = true
ban_threshold = 0

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    let err = parse_config(&toml).unwrap_err();
    assert!(err.to_string().contains("ban_threshold"));
}

#[test]
fn ban_threshold_zero_with_ban_disabled_ok() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[security]
ban_enabled = false
ban_threshold = 0

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    assert!(parse_config(&toml).is_ok());
}

// ---------------------------------------------------------------------------
// 5. Config validation: webhook URL validation
// ---------------------------------------------------------------------------

#[test]
fn webhook_with_invalid_url_rejected() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[webhooks]]
url = "not-a-valid-url"
events = ["auth_failure"]

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    assert!(parse_config(&toml).is_err());
}

#[test]
fn webhook_with_ftp_scheme_rejected() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[webhooks]]
url = "ftp://example.com/hook"
events = ["auth_failure"]

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    let err = parse_config(&toml).unwrap_err();
    assert!(err.to_string().contains("http"));
}

#[test]
fn webhook_pointing_to_localhost_rejected_by_default() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[webhooks]]
url = "http://localhost:8080/hook"
events = ["auth_failure"]

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    let err = parse_config(&toml).unwrap_err();
    assert!(err.to_string().contains("localhost"));
}

#[test]
fn webhook_pointing_to_localhost_allowed_with_flag() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[webhooks]]
url = "http://localhost:8080/hook"
events = ["auth_failure"]
allow_private_ips = true

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    assert!(parse_config(&toml).is_ok());
}

// ---------------------------------------------------------------------------
// 6. Config validation: global ACL rule validation
// ---------------------------------------------------------------------------

#[test]
fn global_acl_invalid_deny_rule_rejected() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[acl]
default_policy = "deny"
deny = ["host:not-a-port"]

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    assert!(parse_config(&toml).is_err());
}

#[test]
fn global_acl_inverted_port_range_rejected() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[acl]
default_policy = "deny"
allow = ["example.com:443-80"]

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    assert!(parse_config(&toml).is_err());
}

// ---------------------------------------------------------------------------
// 7. Redaction: no sensitive fields leak
// ---------------------------------------------------------------------------

#[test]
fn redact_config_handles_no_sensitive_data() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "alice"
password_hash = "{FAKE_HASH}"
"##
    );
    let config = parse_config(&toml).unwrap();
    let redacted = redact_config(&config);
    // password_hash should be redacted
    assert_eq!(redacted.users[0].password_hash.as_deref(), Some("***"));
    // api token is empty, should not become ***
    assert_eq!(redacted.api.token, "");
    // Non-sensitive fields preserved
    assert_eq!(redacted.server.ssh_listen, "0.0.0.0:2222");
}

#[test]
fn redact_config_redacts_all_sensitive_fields() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[api]
enabled = true
token = "super-secret-api-token"

[[webhooks]]
url = "https://example.com/hook"
secret = "webhook-secret"
allow_private_ips = true

[[users]]
username = "alice"
password_hash = "{FAKE_HASH}"
totp_secret = "JBSWY3DPEHPK3PXP"
totp_enabled = true
"##
    );
    let config = parse_config(&toml).unwrap();
    let redacted = redact_config(&config);

    assert_eq!(redacted.api.token, "***");
    assert_eq!(redacted.users[0].password_hash.as_deref(), Some("***"));
    assert_eq!(redacted.users[0].totp_secret.as_deref(), Some("***"));
    assert_eq!(redacted.webhooks[0].secret.as_deref(), Some("***"));
}

// ---------------------------------------------------------------------------
// 8. ProxyEngine: concurrent acquire/release stress (single-threaded)
// ---------------------------------------------------------------------------

#[test]
fn proxy_engine_rapid_acquire_release_cycle() {
    let engine = make_engine_with_limits(10, 5);

    // Rapidly acquire and release connections
    for _ in 0..100 {
        let guard = engine.acquire_connection("alice", 5).unwrap();
        assert_eq!(engine.active_connections(), 1);
        drop(guard);
        assert_eq!(engine.active_connections(), 0);
    }
}

#[test]
fn proxy_engine_interleaved_users_acquire_release() {
    let engine = make_engine_with_limits(10, 5);

    let a1 = engine.acquire_connection("alice", 5).unwrap();
    let b1 = engine.acquire_connection("bob", 5).unwrap();
    let a2 = engine.acquire_connection("alice", 5).unwrap();

    assert_eq!(engine.active_connections(), 3);
    assert_eq!(engine.user_connections("alice"), 2);
    assert_eq!(engine.user_connections("bob"), 1);

    drop(a1);
    assert_eq!(engine.active_connections(), 2);
    assert_eq!(engine.user_connections("alice"), 1);

    drop(b1);
    assert_eq!(engine.active_connections(), 1);
    assert_eq!(engine.user_connections("bob"), 0);

    drop(a2);
    assert_eq!(engine.active_connections(), 0);
    assert_eq!(engine.user_connections("alice"), 0);
}

// ---------------------------------------------------------------------------
// 9. ProxyEngine: session register/unregister ordering
// ---------------------------------------------------------------------------

#[test]
fn proxy_engine_unregister_middle_session_preserves_others() {
    let engine = make_engine_with_limits(100, 50);

    let s1 = engine.register_session("alice", "host1", 80, "10.0.0.1", "ssh");
    let s2 = engine.register_session("alice", "host2", 443, "10.0.0.1", "ssh");
    let s3 = engine.register_session("bob", "host3", 8080, "10.0.0.2", "socks");

    assert_eq!(engine.get_sessions().len(), 3);

    // Remove the middle session
    engine.unregister_session(&s2.session_id);

    let sessions = engine.get_sessions();
    assert_eq!(sessions.len(), 2);
    let ids: Vec<&str> = sessions.iter().map(|s| s.session_id.as_str()).collect();
    assert!(ids.contains(&s1.session_id.as_str()));
    assert!(!ids.contains(&s2.session_id.as_str()));
    assert!(ids.contains(&s3.session_id.as_str()));
}

#[test]
fn proxy_engine_double_unregister_is_safe() {
    let engine = make_engine_with_limits(100, 50);

    let s1 = engine.register_session("alice", "host1", 80, "10.0.0.1", "ssh");
    engine.unregister_session(&s1.session_id);
    // Double unregister should not panic
    engine.unregister_session(&s1.session_id);
    assert!(engine.get_sessions().is_empty());
}

// ---------------------------------------------------------------------------
// 10. Config parsing: groups with ACL overrides
// ---------------------------------------------------------------------------

#[test]
fn group_config_parses_with_acl_overrides() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[groups]]
name = "developers"
max_connections_per_user = 10
max_bandwidth_kbps = 5000
allow_shell = true

[groups.acl]
default_policy = "deny"
allow = ["*.dev.internal:*", "github.com:443"]
deny = ["169.254.169.254:*"]

[[users]]
username = "dev1"
password_hash = "{FAKE_HASH}"
group = "developers"
"##
    );
    let config = parse_config(&toml).unwrap();
    assert_eq!(config.groups.len(), 1);
    assert_eq!(config.groups[0].name, "developers");
    assert_eq!(config.groups[0].max_connections_per_user, Some(10));
    assert_eq!(config.groups[0].acl.allow.len(), 2);
    assert_eq!(config.groups[0].acl.deny.len(), 1);
    assert_eq!(config.users[0].group.as_deref(), Some("developers"));
}

// ---------------------------------------------------------------------------
// 11. Config: maintenance windows parse correctly
// ---------------------------------------------------------------------------

#[test]
fn maintenance_window_config_parses() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[maintenance_windows]]
schedule = "Sun 02:00-04:00"
message = "Weekly maintenance"
disconnect_existing = true

[[maintenance_windows]]
schedule = "daily 03:00-03:30"
message = "Daily health check"

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    let config = parse_config(&toml).unwrap();
    assert_eq!(config.maintenance_windows.len(), 2);
    assert_eq!(config.maintenance_windows[0].schedule, "Sun 02:00-04:00");
    assert!(config.maintenance_windows[0].disconnect_existing);
    assert_eq!(config.maintenance_windows[1].schedule, "daily 03:00-03:30");
    assert!(!config.maintenance_windows[1].disconnect_existing);
}

// ---------------------------------------------------------------------------
// 12. Config: connection pool defaults
// ---------------------------------------------------------------------------

#[test]
fn connection_pool_config_defaults() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    let config = parse_config(&toml).unwrap();
    assert!(!config.connection_pool.enabled);
    assert_eq!(config.connection_pool.max_idle_per_host, 10);
    assert_eq!(config.connection_pool.idle_timeout_secs, 60);
}

#[test]
fn connection_pool_config_custom_values() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[connection_pool]
enabled = true
max_idle_per_host = 20
idle_timeout_secs = 120

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    let config = parse_config(&toml).unwrap();
    assert!(config.connection_pool.enabled);
    assert_eq!(config.connection_pool.max_idle_per_host, 20);
    assert_eq!(config.connection_pool.idle_timeout_secs, 120);
}

// ---------------------------------------------------------------------------
// 13. Config: alerting rules parse
// ---------------------------------------------------------------------------

#[test]
fn alerting_config_parses_with_rules() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[alerting]
enabled = true

[[alerting.rules]]
name = "bandwidth-alert"
condition = "bandwidth_exceeded"
threshold = 1073741824
window_secs = 3600
users = ["alice", "bob"]
webhook_url = "https://example.com/alert"

[[alerting.rules]]
name = "connections-alert"
condition = "connections_exceeded"
threshold = 100
window_secs = 60

[[users]]
username = "alice"
password_hash = "{FAKE_HASH}"

[[users]]
username = "bob"
password_hash = "{FAKE_HASH}"
"##
    );
    let config = parse_config(&toml).unwrap();
    assert!(config.alerting.enabled);
    assert_eq!(config.alerting.rules.len(), 2);
    assert_eq!(config.alerting.rules[0].name, "bandwidth-alert");
    assert_eq!(
        config.alerting.rules[0].condition,
        AlertCondition::BandwidthExceeded
    );
    assert_eq!(config.alerting.rules[0].users, vec!["alice", "bob"]);
    assert_eq!(config.alerting.rules[1].name, "connections-alert");
    assert_eq!(
        config.alerting.rules[1].condition,
        AlertCondition::ConnectionsExceeded
    );
}

// ---------------------------------------------------------------------------
// 14. Config: user aliases and rate limits
// ---------------------------------------------------------------------------

#[test]
fn user_aliases_parse() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "alice"
password_hash = "{FAKE_HASH}"

[users.aliases]
db = "test prod-db:5432"
status = "show status"
"##
    );
    let config = parse_config(&toml).unwrap();
    assert_eq!(config.users[0].aliases.len(), 2);
    assert_eq!(
        config.users[0].aliases.get("db").unwrap(),
        "test prod-db:5432"
    );
    assert_eq!(
        config.users[0].aliases.get("status").unwrap(),
        "show status"
    );
}

#[test]
fn user_rate_limits_parse() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "alice"
password_hash = "{FAKE_HASH}"

[users.rate_limits]
connections_per_second = 5
connections_per_minute = 30
connections_per_hour = 500
"##
    );
    let config = parse_config(&toml).unwrap();
    let rl = config.users[0].rate_limits.as_ref().unwrap();
    assert_eq!(rl.connections_per_second, 5);
    assert_eq!(rl.connections_per_minute, 30);
    assert_eq!(rl.connections_per_hour, 500);
}

// ---------------------------------------------------------------------------
// 15. Config: quota configuration
// ---------------------------------------------------------------------------

#[test]
fn user_quota_config_parses() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "alice"
password_hash = "{FAKE_HASH}"

[users.quotas]
daily_bandwidth_bytes = 1073741824
daily_connection_limit = 100
monthly_bandwidth_bytes = 10737418240
monthly_connection_limit = 3000
bandwidth_per_hour_bytes = 536870912
total_bandwidth_bytes = 107374182400
"##
    );
    let config = parse_config(&toml).unwrap();
    let q = config.users[0].quotas.as_ref().unwrap();
    assert_eq!(q.daily_bandwidth_bytes, 1_073_741_824);
    assert_eq!(q.daily_connection_limit, 100);
    assert_eq!(q.monthly_bandwidth_bytes, 10_737_418_240);
    assert_eq!(q.monthly_connection_limit, 3000);
    assert_eq!(q.bandwidth_per_hour_bytes, 536_870_912);
    assert_eq!(q.total_bandwidth_bytes, 107_374_182_400);
}

// ---------------------------------------------------------------------------
// 16. Display implementations for enums
// ---------------------------------------------------------------------------

#[test]
fn log_level_display() {
    assert_eq!(LogLevel::Trace.to_string(), "trace");
    assert_eq!(LogLevel::Debug.to_string(), "debug");
    assert_eq!(LogLevel::Info.to_string(), "info");
    assert_eq!(LogLevel::Warn.to_string(), "warn");
    assert_eq!(LogLevel::Error.to_string(), "error");
}

#[test]
fn log_format_display() {
    assert_eq!(LogFormat::Pretty.to_string(), "pretty");
    assert_eq!(LogFormat::Json.to_string(), "json");
}

#[test]
fn acl_policy_config_display() {
    assert_eq!(AclPolicyConfig::Allow.to_string(), "allow");
    assert_eq!(AclPolicyConfig::Deny.to_string(), "deny");
}

#[test]
fn user_role_display() {
    assert_eq!(UserRole::User.to_string(), "user");
    assert_eq!(UserRole::Admin.to_string(), "admin");
}

#[test]
fn alert_condition_display() {
    assert_eq!(
        AlertCondition::BandwidthExceeded.to_string(),
        "bandwidth_exceeded"
    );
    assert_eq!(
        AlertCondition::ConnectionsExceeded.to_string(),
        "connections_exceeded"
    );
    assert_eq!(
        AlertCondition::MonthlyBandwidthExceeded.to_string(),
        "monthly_bandwidth_exceeded"
    );
    assert_eq!(
        AlertCondition::HourlyBandwidthExceeded.to_string(),
        "hourly_bandwidth_exceeded"
    );
    assert_eq!(AlertCondition::AuthFailures.to_string(), "auth_failures");
}
