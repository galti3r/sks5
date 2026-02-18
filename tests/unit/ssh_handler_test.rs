// Unit tests for src/ssh/handler.rs
//
// Tests cover:
// - SshHandler struct creation and field initialization
// - Session state management (auth, username, fingerprint)
// - Auth attempt tracking
// - Channel limit enforcement (MAX_CHANNELS_PER_CONNECTION)
// - classify_relay_error() error classification
// - record_auth_failure() behavior (below/at/above max attempts)
// - validate_forwarding_request() for various conditions

use sks5::audit::AuditLogger;
use sks5::auth::AuthService;
use sks5::config::types::AppConfig;
use sks5::context::AppContext;
use sks5::metrics::MetricsRegistry;
use sks5::proxy::ProxyEngine;
use sks5::quota::QuotaTracker;
use sks5::security::SecurityManager;
use sks5::ssh::handler::{classify_relay_error, SshHandler, MAX_CHANNELS_PER_CONNECTION};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const FAKE_HASH: &str = "argon2id-fakehash-for-testing";

/// Build a config with the default [limits] max_auth_attempts = 3.
/// `extra` is inserted AFTER all standard sections and before [[users]].
/// It must NOT re-declare existing TOML sections like [limits] or [security].
fn make_config(extra: &str) -> AppConfig {
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:2222"
host_key_path = "/tmp/sks5-test-host-key"

[limits]
max_auth_attempts = 3

[security]
ban_enabled = false

{extra}

[[users]]
username = "alice"
password_hash = "{FAKE_HASH}"
allow_forwarding = true
allow_shell = true
"##
    );
    toml::from_str(&toml_str).unwrap()
}

/// Build a config with a custom max_auth_attempts value.
fn make_config_max_auth(max_auth: u32) -> AppConfig {
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:2222"
host_key_path = "/tmp/sks5-test-host-key"

[limits]
max_auth_attempts = {max_auth}

[security]
ban_enabled = false

[[users]]
username = "alice"
password_hash = "{FAKE_HASH}"
allow_forwarding = true
allow_shell = true
"##
    );
    toml::from_str(&toml_str).unwrap()
}

fn make_config_with_source_ips() -> AppConfig {
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:2222"
host_key_path = "/tmp/sks5-test-host-key"

[limits]
max_auth_attempts = 3

[security]
ban_enabled = false

[[users]]
username = "alice"
password_hash = "{FAKE_HASH}"
allow_forwarding = true
allow_shell = true
source_ips = ["10.0.0.0/8"]
"##
    );
    toml::from_str(&toml_str).unwrap()
}

/// Create an AppContext. Must be called inside a tokio runtime
/// (AuditLogger::new spawns a background task).
fn setup(app_config: AppConfig) -> Arc<AppContext> {
    let config = Arc::new(app_config);
    let audit = Arc::new(AuditLogger::new(None, 0, 0, None));
    Arc::new(AppContext {
        config: config.clone(),
        auth_service: Arc::new(RwLock::new(AuthService::new(&config).unwrap())),
        proxy_engine: Arc::new(ProxyEngine::new(config.clone(), audit.clone())),
        security: Arc::new(RwLock::new(SecurityManager::new(&config))),
        audit,
        metrics: Arc::new(MetricsRegistry::new()),
        quota_tracker: Arc::new(QuotaTracker::new(&config.limits)),
        webhook_dispatcher: None,
        alert_engine: None,
        start_time: std::time::Instant::now(),
        kick_tokens: std::sync::Arc::new(dashmap::DashMap::new()),
        userdata_store: None,
    })
}

fn default_peer_addr() -> SocketAddr {
    "127.0.0.1:54321".parse().unwrap()
}

fn make_handler(ctx: Arc<AppContext>) -> SshHandler {
    SshHandler::new(ctx, default_peer_addr())
}

// ===========================================================================
// 1. SshHandler creation and initialization
// ===========================================================================

#[tokio::test]
async fn new_handler_starts_unauthenticated() {
    let ctx = setup(make_config(""));
    let handler = make_handler(ctx);

    assert!(!handler.is_authenticated());
}

#[tokio::test]
async fn new_handler_has_no_username() {
    let ctx = setup(make_config(""));
    let handler = make_handler(ctx);

    assert!(handler.session_username().is_none());
}

#[tokio::test]
async fn new_handler_has_zero_auth_attempts() {
    let ctx = setup(make_config(""));
    let handler = make_handler(ctx);

    assert_eq!(handler.total_auth_attempts(), 0);
}

#[tokio::test]
async fn new_handler_has_zero_shells() {
    let ctx = setup(make_config(""));
    let handler = make_handler(ctx);

    assert_eq!(handler.shell_count(), 0);
}

#[tokio::test]
async fn new_handler_generates_uuid_conn_id() {
    let ctx = setup(make_config(""));
    let handler = make_handler(ctx);

    let conn_id = handler.conn_id();
    // Compact correlation ID: 8 hex characters
    assert_eq!(conn_id.len(), 8);
    assert!(conn_id.chars().all(|c| c.is_ascii_hexdigit()));
}

#[tokio::test]
async fn new_handler_stores_peer_addr() {
    let ctx = setup(make_config(""));
    let handler = make_handler(ctx);

    assert_eq!(handler.peer_addr(), default_peer_addr());
}

#[tokio::test]
async fn new_handler_has_empty_auth_method() {
    let ctx = setup(make_config(""));
    let handler = make_handler(ctx);

    assert!(handler.auth_method().is_empty());
}

#[tokio::test]
async fn new_handler_has_no_ssh_key_fingerprint() {
    let ctx = setup(make_config(""));
    let handler = make_handler(ctx);

    assert!(handler.ssh_key_fingerprint().is_none());
}

// ===========================================================================
// 2. Multiple handlers get distinct connection IDs
// ===========================================================================

#[tokio::test]
async fn multiple_handlers_get_unique_conn_ids() {
    let ctx = setup(make_config(""));
    let h1 = SshHandler::new(ctx.clone(), "127.0.0.1:1111".parse().unwrap());
    let h2 = SshHandler::new(ctx.clone(), "127.0.0.1:2222".parse().unwrap());
    let h3 = SshHandler::new(ctx, "127.0.0.1:3333".parse().unwrap());

    assert_ne!(h1.conn_id(), h2.conn_id());
    assert_ne!(h2.conn_id(), h3.conn_id());
    assert_ne!(h1.conn_id(), h3.conn_id());
}

// ===========================================================================
// 3. Session state management
// ===========================================================================

#[tokio::test]
async fn set_authenticated_updates_state() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);

    handler.set_authenticated("alice", "password");

    assert!(handler.is_authenticated());
    assert_eq!(handler.session_username(), Some("alice"));
    assert_eq!(handler.auth_method(), "password");
}

#[tokio::test]
async fn set_authenticated_with_publickey() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);

    handler.set_authenticated("bob", "publickey");

    assert!(handler.is_authenticated());
    assert_eq!(handler.session_username(), Some("bob"));
    assert_eq!(handler.auth_method(), "publickey");
}

#[tokio::test]
async fn set_authenticated_with_password_plus_totp() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);

    handler.set_authenticated("alice", "password+totp");

    assert!(handler.is_authenticated());
    assert_eq!(handler.auth_method(), "password+totp");
}

#[tokio::test]
async fn set_unauthenticated_clears_state() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);

    // First authenticate
    handler.set_authenticated("alice", "password");
    assert!(handler.is_authenticated());

    // Then clear
    handler.set_unauthenticated();

    assert!(!handler.is_authenticated());
    assert!(handler.session_username().is_none());
    assert!(handler.auth_method().is_empty());
}

#[tokio::test]
async fn set_ssh_key_fingerprint_stores_value() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);

    handler.set_ssh_key_fingerprint("SHA256:abc123def456");

    assert_eq!(handler.ssh_key_fingerprint(), Some("SHA256:abc123def456"));
}

#[tokio::test]
async fn ssh_key_fingerprint_survives_auth_state_change() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);

    handler.set_authenticated("alice", "publickey");
    handler.set_ssh_key_fingerprint("SHA256:testfp");

    // Fingerprint persists even though auth state was set
    assert_eq!(handler.ssh_key_fingerprint(), Some("SHA256:testfp"));
}

// ===========================================================================
// 4. Auth attempt tracking
// ===========================================================================

#[tokio::test]
async fn increment_auth_attempts_increments_counter() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);

    assert_eq!(handler.total_auth_attempts(), 0);

    handler.increment_auth_attempts();
    assert_eq!(handler.total_auth_attempts(), 1);

    handler.increment_auth_attempts();
    assert_eq!(handler.total_auth_attempts(), 2);

    handler.increment_auth_attempts();
    assert_eq!(handler.total_auth_attempts(), 3);
}

// ===========================================================================
// 5. Channel limit constant
// ===========================================================================

#[test]
fn max_channels_per_connection_is_ten() {
    assert_eq!(MAX_CHANNELS_PER_CONNECTION, 10);
}

#[tokio::test]
async fn new_handler_would_accept_new_channel() {
    let ctx = setup(make_config(""));
    let handler = make_handler(ctx);

    // Fresh handler with 0 shells should accept new channels
    assert!(handler.would_accept_new_channel());
}

// ===========================================================================
// 6. classify_relay_error - ACL denied
// ===========================================================================

#[test]
fn classify_relay_error_acl_denied() {
    let err = anyhow::anyhow!("ACL denied for target example.com:443");
    assert_eq!(classify_relay_error(&err), "acl_denied");
}

#[test]
fn classify_relay_error_acl_denied_embedded() {
    let err = anyhow::anyhow!("request failed: ACL denied by user rule");
    assert_eq!(classify_relay_error(&err), "acl_denied");
}

// ===========================================================================
// 7. classify_relay_error - connection limit
// ===========================================================================

#[test]
fn classify_relay_error_connection_limit() {
    let err = anyhow::anyhow!("connection limit exceeded for user alice");
    assert_eq!(classify_relay_error(&err), "connection_refused");
}

// ===========================================================================
// 8. classify_relay_error - DNS failures
// ===========================================================================

#[test]
fn classify_relay_error_dns_uppercase() {
    let err = anyhow::anyhow!("DNS resolution failed for example.com");
    assert_eq!(classify_relay_error(&err), "dns_failure");
}

#[test]
fn classify_relay_error_dns_lowercase() {
    let err = anyhow::anyhow!("dns lookup timed out");
    assert_eq!(classify_relay_error(&err), "dns_failure");
}

#[test]
fn classify_relay_error_lookup() {
    let err = anyhow::anyhow!("lookup failed for hostname");
    assert_eq!(classify_relay_error(&err), "dns_failure");
}

// ===========================================================================
// 9. classify_relay_error - IO errors
// ===========================================================================

#[test]
fn classify_relay_error_connection_refused_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
    let err = anyhow::Error::from(io_err);
    assert_eq!(classify_relay_error(&err), "connection_refused");
}

#[test]
fn classify_relay_error_connection_reset_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset");
    let err = anyhow::Error::from(io_err);
    assert_eq!(classify_relay_error(&err), "relay_error");
}

#[test]
fn classify_relay_error_connection_aborted_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "aborted");
    let err = anyhow::Error::from(io_err);
    assert_eq!(classify_relay_error(&err), "relay_error");
}

#[test]
fn classify_relay_error_timed_out_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out");
    let err = anyhow::Error::from(io_err);
    assert_eq!(classify_relay_error(&err), "connection_timeout");
}

#[test]
fn classify_relay_error_other_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken pipe");
    let err = anyhow::Error::from(io_err);
    assert_eq!(classify_relay_error(&err), "relay_error");
}

// ===========================================================================
// 10. classify_relay_error - generic / relay error
// ===========================================================================

#[test]
fn classify_relay_error_generic_error() {
    let err = anyhow::anyhow!("something unexpected happened");
    assert_eq!(classify_relay_error(&err), "relay_error");
}

#[test]
fn classify_relay_error_empty_message() {
    let err = anyhow::anyhow!("");
    assert_eq!(classify_relay_error(&err), "relay_error");
}

// ===========================================================================
// 11. classify_relay_error - priority checks (ACL > connection limit > DNS > IO)
// ===========================================================================

#[test]
fn classify_relay_error_acl_takes_priority_over_dns() {
    // If message contains both "ACL denied" and "DNS", ACL should match first
    let err = anyhow::anyhow!("ACL denied DNS resolution attempt");
    assert_eq!(classify_relay_error(&err), "acl_denied");
}

#[test]
fn classify_relay_error_connection_limit_takes_priority_over_dns() {
    let err = anyhow::anyhow!("connection limit dns lookup");
    assert_eq!(classify_relay_error(&err), "connection_refused");
}

// ===========================================================================
// 12. record_auth_failure - below max_auth_attempts
// ===========================================================================

#[tokio::test]
async fn record_auth_failure_below_max_allows_retry() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);

    // max_auth_attempts = 3, so attempt 1 should allow retry
    let result = handler
        .test_record_auth_failure("alice", "password", 1)
        .await;

    match result {
        russh::server::Auth::Reject {
            proceed_with_methods,
            ..
        } => {
            assert!(
                proceed_with_methods.is_some(),
                "should offer methods for retry below max"
            );
            let methods = proceed_with_methods.unwrap();
            assert!(
                methods.contains(&russh::MethodKind::Password),
                "should include PASSWORD method"
            );
            assert!(
                methods.contains(&russh::MethodKind::PublicKey),
                "should include PUBLICKEY method"
            );
        }
        _ => panic!("expected Auth::Reject"),
    }
}

#[tokio::test]
async fn record_auth_failure_attempt_2_still_allows_retry() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);

    let result = handler
        .test_record_auth_failure("alice", "password", 2)
        .await;

    match result {
        russh::server::Auth::Reject {
            proceed_with_methods,
            ..
        } => {
            assert!(
                proceed_with_methods.is_some(),
                "attempt 2 of 3 should still allow retry"
            );
        }
        _ => panic!("expected Auth::Reject"),
    }
}

// ===========================================================================
// 13. record_auth_failure - at max_auth_attempts
// ===========================================================================

#[tokio::test]
async fn record_auth_failure_at_max_rejects_completely() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);

    // max_auth_attempts = 3, so attempt 3 should reject completely
    let result = handler
        .test_record_auth_failure("alice", "password", 3)
        .await;

    match result {
        russh::server::Auth::Reject {
            proceed_with_methods,
            ..
        } => {
            assert!(
                proceed_with_methods.is_none(),
                "at max attempts, should reject with no methods"
            );
        }
        _ => panic!("expected Auth::Reject"),
    }
}

// ===========================================================================
// 14. record_auth_failure - above max_auth_attempts
// ===========================================================================

#[tokio::test]
async fn record_auth_failure_above_max_rejects_completely() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);

    let result = handler
        .test_record_auth_failure("alice", "password", 10)
        .await;

    match result {
        russh::server::Auth::Reject {
            proceed_with_methods,
            ..
        } => {
            assert!(
                proceed_with_methods.is_none(),
                "above max attempts, should reject with no methods"
            );
        }
        _ => panic!("expected Auth::Reject"),
    }
}

// ===========================================================================
// 15. record_auth_failure - metric method mapping
// ===========================================================================

#[tokio::test]
async fn record_auth_failure_publickey_method_label() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);

    // Should not panic; internally maps "publickey" to "pubkey" for metrics
    let result = handler
        .test_record_auth_failure("alice", "publickey", 1)
        .await;

    // Verify it still returns a retry-able reject
    match result {
        russh::server::Auth::Reject {
            proceed_with_methods,
            ..
        } => {
            assert!(proceed_with_methods.is_some());
        }
        _ => panic!("expected Auth::Reject"),
    }
}

// ===========================================================================
// 16. record_auth_failure with custom max_auth_attempts
// ===========================================================================

#[tokio::test]
async fn record_auth_failure_custom_max_attempts_5() {
    let ctx = setup(make_config_max_auth(5));
    let mut handler = make_handler(ctx);

    // Attempt 4 of 5 should still allow retry
    let result = handler
        .test_record_auth_failure("alice", "password", 4)
        .await;
    match result {
        russh::server::Auth::Reject {
            proceed_with_methods,
            ..
        } => {
            assert!(proceed_with_methods.is_some());
        }
        _ => panic!("expected Auth::Reject"),
    }

    // Attempt 5 of 5 should reject completely
    let result = handler
        .test_record_auth_failure("alice", "password", 5)
        .await;
    match result {
        russh::server::Auth::Reject {
            proceed_with_methods,
            ..
        } => {
            assert!(proceed_with_methods.is_none());
        }
        _ => panic!("expected Auth::Reject"),
    }
}

// ===========================================================================
// 17. validate_forwarding_request - unauthenticated
// ===========================================================================

#[tokio::test]
async fn validate_forwarding_unauthenticated_returns_none() {
    let ctx = setup(make_config(""));
    let handler = make_handler(ctx);
    // Not authenticated

    let result = handler
        .test_validate_forwarding_request("example.com", 443)
        .await
        .unwrap();

    assert!(result.is_none(), "unauthenticated should return None");
}

// ===========================================================================
// 18. validate_forwarding_request - no username set
// ===========================================================================

#[tokio::test]
async fn validate_forwarding_no_username_returns_none() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);

    // Explicitly unauthenticated
    handler.set_unauthenticated();

    let result = handler
        .test_validate_forwarding_request("example.com", 443)
        .await
        .unwrap();

    assert!(result.is_none());
}

// ===========================================================================
// 19. validate_forwarding_request - unknown user
// ===========================================================================

#[tokio::test]
async fn validate_forwarding_unknown_user_returns_none() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);

    handler.set_authenticated("nobody", "password");

    let result = handler
        .test_validate_forwarding_request("example.com", 443)
        .await
        .unwrap();

    assert!(result.is_none(), "unknown user should return None");
}

// ===========================================================================
// 21. validate_forwarding_request - source IP not allowed
// ===========================================================================

#[tokio::test]
async fn validate_forwarding_source_ip_not_allowed() {
    let ctx = setup(make_config_with_source_ips());
    // Handler peer is 192.168.1.100, but user only allows 10.0.0.0/8
    let handler_addr: SocketAddr = "192.168.1.100:54321".parse().unwrap();
    let mut handler = SshHandler::new(ctx, handler_addr);

    handler.set_authenticated("alice", "password");

    let result = handler
        .test_validate_forwarding_request("example.com", 443)
        .await
        .unwrap();

    assert!(
        result.is_none(),
        "IP 192.168.1.100 not in 10.0.0.0/8 should return None"
    );
}

// ===========================================================================
// 22. validate_forwarding_request - invalid port
// ===========================================================================

#[tokio::test]
async fn validate_forwarding_invalid_port_returns_none() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);

    handler.set_authenticated("alice", "password");

    // u32::MAX exceeds u16 range
    let result = handler
        .test_validate_forwarding_request("example.com", u32::MAX)
        .await
        .unwrap();

    assert!(result.is_none(), "port exceeding u16 should return None");
}

#[tokio::test]
async fn validate_forwarding_port_just_above_u16_returns_none() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);

    handler.set_authenticated("alice", "password");

    let result = handler
        .test_validate_forwarding_request("example.com", 65536)
        .await
        .unwrap();

    assert!(result.is_none(), "port 65536 exceeds u16::MAX (65535)");
}

// ===========================================================================
// 23. validate_forwarding_request - valid request
// ===========================================================================

#[tokio::test]
async fn validate_forwarding_valid_request_returns_user_and_port() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);

    handler.set_authenticated("alice", "password");

    let result = handler
        .test_validate_forwarding_request("example.com", 443)
        .await
        .unwrap();

    assert!(result.is_some(), "valid request should return Some");
    let (user, username, port) = result.unwrap();
    assert_eq!(username, "alice");
    assert_eq!(port, 443);
    assert_eq!(user.username, "alice");
}

#[tokio::test]
async fn validate_forwarding_valid_with_port_80() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);

    handler.set_authenticated("alice", "password");

    let result = handler
        .test_validate_forwarding_request("example.com", 80)
        .await
        .unwrap();

    let (_user, _username, port) = result.unwrap();
    assert_eq!(port, 80);
}

#[tokio::test]
async fn validate_forwarding_valid_with_max_u16_port() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);

    handler.set_authenticated("alice", "password");

    let result = handler
        .test_validate_forwarding_request("example.com", 65535)
        .await
        .unwrap();

    let (_user, _username, port) = result.unwrap();
    assert_eq!(port, 65535);
}

// ===========================================================================
// 24. validate_forwarding_request - source IP allowed
// ===========================================================================

#[tokio::test]
async fn validate_forwarding_source_ip_allowed() {
    let ctx = setup(make_config_with_source_ips());
    // Use IP from the allowed 10.0.0.0/8 range
    let handler_addr: SocketAddr = "10.0.0.50:54321".parse().unwrap();
    let mut handler = SshHandler::new(ctx, handler_addr);

    handler.set_authenticated("alice", "password");

    let result = handler
        .test_validate_forwarding_request("example.com", 443)
        .await
        .unwrap();

    assert!(
        result.is_some(),
        "IP 10.0.0.50 in 10.0.0.0/8 should be allowed"
    );
}

// ===========================================================================
// 25. Handler with different peer addresses
// ===========================================================================

#[tokio::test]
async fn handler_stores_ipv6_peer_addr() {
    let ctx = setup(make_config(""));
    let addr: SocketAddr = "[::1]:12345".parse().unwrap();
    let handler = SshHandler::new(ctx, addr);

    assert_eq!(handler.peer_addr(), addr);
}

#[tokio::test]
async fn handler_stores_ipv4_peer_addr() {
    let ctx = setup(make_config(""));
    let addr: SocketAddr = "192.168.1.100:9999".parse().unwrap();
    let handler = SshHandler::new(ctx, addr);

    assert_eq!(handler.peer_addr(), addr);
}

// ===========================================================================
// 26. classify_relay_error - edge cases
// ===========================================================================

#[test]
fn classify_relay_error_case_sensitivity_dns() {
    // "DNS" uppercase matches
    let err = anyhow::anyhow!("DNS failure");
    assert_eq!(classify_relay_error(&err), "dns_failure");

    // "dns" lowercase matches
    let err2 = anyhow::anyhow!("dns failure");
    assert_eq!(classify_relay_error(&err2), "dns_failure");

    // "Dns" mixed case does NOT match (neither "DNS" nor "dns" substring)
    let err3 = anyhow::anyhow!("Dns failure");
    assert_eq!(classify_relay_error(&err3), "relay_error");
}

#[test]
fn classify_relay_error_lookup_substring() {
    // "lookup" at the start
    let err = anyhow::anyhow!("lookup of host failed");
    assert_eq!(classify_relay_error(&err), "dns_failure");

    // "lookup" in the middle
    let err2 = anyhow::anyhow!("reverse lookup failed for 1.2.3.4");
    assert_eq!(classify_relay_error(&err2), "dns_failure");
}

// ===========================================================================
// 27. classify_relay_error - all error_types constants
// ===========================================================================

#[test]
fn classify_relay_error_returns_known_constants() {
    // Verify the returned strings match the known error_types constants
    use sks5::metrics::error_types;

    let acl_err = anyhow::anyhow!("ACL denied");
    assert_eq!(classify_relay_error(&acl_err), error_types::ACL_DENIED);

    let conn_limit = anyhow::anyhow!("connection limit");
    assert_eq!(
        classify_relay_error(&conn_limit),
        error_types::CONNECTION_REFUSED
    );

    let dns_err = anyhow::anyhow!("DNS failed");
    assert_eq!(classify_relay_error(&dns_err), error_types::DNS_FAILURE);

    let io_refused = anyhow::Error::from(std::io::Error::new(
        std::io::ErrorKind::ConnectionRefused,
        "refused",
    ));
    assert_eq!(
        classify_relay_error(&io_refused),
        error_types::CONNECTION_REFUSED
    );

    let io_timeout =
        anyhow::Error::from(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"));
    assert_eq!(
        classify_relay_error(&io_timeout),
        error_types::CONNECTION_TIMEOUT
    );

    let io_reset = anyhow::Error::from(std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "reset",
    ));
    assert_eq!(classify_relay_error(&io_reset), error_types::RELAY_ERROR);

    let generic = anyhow::anyhow!("random error");
    assert_eq!(classify_relay_error(&generic), error_types::RELAY_ERROR);
}

// ===========================================================================
// 28. record_auth_failure - boundary: max_auth_attempts = 1
// ===========================================================================

#[tokio::test]
async fn record_auth_failure_max_attempts_one() {
    let ctx = setup(make_config_max_auth(1));
    let mut handler = make_handler(ctx);

    // First attempt (attempt 1) at max 1 should reject completely
    let result = handler
        .test_record_auth_failure("alice", "password", 1)
        .await;
    match result {
        russh::server::Auth::Reject {
            proceed_with_methods,
            ..
        } => {
            assert!(
                proceed_with_methods.is_none(),
                "with max_auth_attempts=1, first attempt should reject completely"
            );
        }
        _ => panic!("expected Auth::Reject"),
    }
}

// ===========================================================================
// 29. Handler with custom max_auth_attempts = 10
// ===========================================================================

#[tokio::test]
async fn record_auth_failure_max_attempts_ten() {
    let ctx = setup(make_config_max_auth(10));
    let mut handler = make_handler(ctx);

    // Attempt 9 of 10 should still allow retry
    let result = handler
        .test_record_auth_failure("alice", "password", 9)
        .await;
    match result {
        russh::server::Auth::Reject {
            proceed_with_methods,
            ..
        } => {
            assert!(proceed_with_methods.is_some());
        }
        _ => panic!("expected Auth::Reject"),
    }

    // Attempt 10 of 10 should reject completely
    let result = handler
        .test_record_auth_failure("alice", "password", 10)
        .await;
    match result {
        russh::server::Auth::Reject {
            proceed_with_methods,
            ..
        } => {
            assert!(proceed_with_methods.is_none());
        }
        _ => panic!("expected Auth::Reject"),
    }
}

// ===========================================================================
// 30. Handler session state transitions
// ===========================================================================

#[tokio::test]
async fn handler_auth_state_transitions() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);

    // Start unauthenticated
    assert!(!handler.is_authenticated());
    assert!(handler.session_username().is_none());

    // Authenticate with password
    handler.set_authenticated("alice", "password");
    assert!(handler.is_authenticated());
    assert_eq!(handler.session_username(), Some("alice"));
    assert_eq!(handler.auth_method(), "password");

    // Can override (simulates re-auth or state change)
    handler.set_authenticated("bob", "publickey");
    assert!(handler.is_authenticated());
    assert_eq!(handler.session_username(), Some("bob"));
    assert_eq!(handler.auth_method(), "publickey");

    // Logout
    handler.set_unauthenticated();
    assert!(!handler.is_authenticated());
    assert!(handler.session_username().is_none());
    assert!(handler.auth_method().is_empty());
}

// ===========================================================================
// 31. validate_forwarding_request - port boundary values
// ===========================================================================

#[tokio::test]
async fn validate_forwarding_port_zero() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);
    handler.set_authenticated("alice", "password");

    let result = handler
        .test_validate_forwarding_request("example.com", 0)
        .await
        .unwrap();

    // Port 0 is a valid u16 value, should pass port validation
    assert!(result.is_some());
    let (_user, _username, port) = result.unwrap();
    assert_eq!(port, 0);
}

#[tokio::test]
async fn validate_forwarding_port_one() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);
    handler.set_authenticated("alice", "password");

    let result = handler
        .test_validate_forwarding_request("example.com", 1)
        .await
        .unwrap();

    assert!(result.is_some());
    let (_user, _username, port) = result.unwrap();
    assert_eq!(port, 1);
}

// ===========================================================================
// 32. Multiple handlers sharing same AppContext
// ===========================================================================

#[tokio::test]
async fn multiple_handlers_share_context() {
    let ctx = setup(make_config(""));

    let mut h1 = SshHandler::new(ctx.clone(), "10.0.0.1:1111".parse().unwrap());
    let mut h2 = SshHandler::new(ctx.clone(), "10.0.0.2:2222".parse().unwrap());

    // Each handler has independent state
    h1.set_authenticated("alice", "password");

    assert!(h1.is_authenticated());
    assert!(!h2.is_authenticated());

    h2.increment_auth_attempts();
    assert_eq!(h1.total_auth_attempts(), 0);
    assert_eq!(h2.total_auth_attempts(), 1);
}

// ===========================================================================
// 33. classify_relay_error - chained/contextual errors
// ===========================================================================

#[test]
fn classify_relay_error_io_without_acl_keywords() {
    // IO error whose to_string() does not contain ACL/DNS keywords
    // is classified by downcast_ref to io::Error
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "nope");
    let err = anyhow::Error::from(io_err);
    assert_eq!(classify_relay_error(&err), "connection_refused");
}

#[test]
fn classify_relay_error_context_adds_string_but_preserves_io_downcast() {
    // When context() wraps an io error, the string representation includes
    // the context message. downcast_ref may or may not find the inner error.
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "nope");
    let err = anyhow::anyhow!(io_err).context("wrapped error");

    // The to_string() of a context-wrapped error is "wrapped error"
    // which does not contain ACL/DNS keywords. The io error downcast
    // through anyhow's chain should still work for downcast_ref.
    let classification = classify_relay_error(&err);
    // With anyhow's context, downcast_ref traverses the chain,
    // so io::Error should still be found.
    assert_eq!(classification, "connection_refused");
}

// ===========================================================================
// 34. Handler with IPv6 peer address for forwarding
// ===========================================================================

#[tokio::test]
async fn validate_forwarding_with_ipv6_peer() {
    let ctx = setup(make_config(""));
    let addr: SocketAddr = "[::1]:54321".parse().unwrap();
    let mut handler = SshHandler::new(ctx, addr);

    handler.set_authenticated("alice", "password");

    let result = handler
        .test_validate_forwarding_request("example.com", 443)
        .await
        .unwrap();

    assert!(
        result.is_some(),
        "IPv6 peer with no source IP restriction should work"
    );
}

// ===========================================================================
// 35. validate_forwarding_request returns correct user data
// ===========================================================================

#[tokio::test]
async fn validate_forwarding_returns_user_with_correct_permissions() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);
    handler.set_authenticated("alice", "password");

    let result = handler
        .test_validate_forwarding_request("example.com", 8080)
        .await
        .unwrap();

    let (user, username, port) = result.unwrap();
    assert_eq!(username, "alice");
    assert_eq!(port, 8080);
    assert!(user.allow_shell);
    assert_eq!(user.username, "alice");
}

// ===========================================================================
// 36. classify_relay_error - IO error kinds exhaustive coverage
// ===========================================================================

#[test]
fn classify_relay_error_permission_denied_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
    let err = anyhow::Error::from(io_err);
    // PermissionDenied is not specifically handled, should fall to default relay_error
    assert_eq!(classify_relay_error(&err), "relay_error");
}

#[test]
fn classify_relay_error_not_found_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
    let err = anyhow::Error::from(io_err);
    assert_eq!(classify_relay_error(&err), "relay_error");
}

#[test]
fn classify_relay_error_addr_in_use_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::AddrInUse, "in use");
    let err = anyhow::Error::from(io_err);
    assert_eq!(classify_relay_error(&err), "relay_error");
}

// ===========================================================================
// 37. record_auth_failure always returns Reject (never Accept)
// ===========================================================================

#[tokio::test]
async fn record_auth_failure_never_returns_accept() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);

    // Test multiple attempt values: all should be Reject
    for attempt in [1, 2, 3, 4, 5, 100] {
        let result = handler
            .test_record_auth_failure("alice", "password", attempt)
            .await;
        assert!(
            matches!(result, russh::server::Auth::Reject { .. }),
            "record_auth_failure should always return Reject, got {:?} for attempt {}",
            result,
            attempt
        );
    }
}

// ===========================================================================
// 38. validate_forwarding with various host formats
// ===========================================================================

#[tokio::test]
async fn validate_forwarding_ip_address_host() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);
    handler.set_authenticated("alice", "password");

    let result = handler
        .test_validate_forwarding_request("192.168.1.1", 80)
        .await
        .unwrap();

    assert!(result.is_some());
    let (_user, _username, port) = result.unwrap();
    assert_eq!(port, 80);
}

#[tokio::test]
async fn validate_forwarding_ipv6_host() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);
    handler.set_authenticated("alice", "password");

    let result = handler
        .test_validate_forwarding_request("::1", 443)
        .await
        .unwrap();

    assert!(result.is_some());
}

#[tokio::test]
async fn validate_forwarding_long_hostname() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);
    handler.set_authenticated("alice", "password");

    let long_host = "subdomain.very.long.hostname.example.com";
    let result = handler
        .test_validate_forwarding_request(long_host, 443)
        .await
        .unwrap();

    assert!(result.is_some());
}

// ===========================================================================
// 39. Handler initial shell_count and channel acceptance
// ===========================================================================

#[tokio::test]
async fn handler_initial_state_accepts_channels() {
    let ctx = setup(make_config(""));
    let handler = make_handler(ctx);

    assert_eq!(handler.shell_count(), 0);
    assert!(handler.would_accept_new_channel());
}

// ===========================================================================
// 40. record_auth_failure with various auth methods
// ===========================================================================

#[tokio::test]
async fn record_auth_failure_password_method() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);

    let result = handler
        .test_record_auth_failure("alice", "password", 1)
        .await;

    // Should not panic, should return Reject with methods
    match result {
        russh::server::Auth::Reject {
            proceed_with_methods,
            ..
        } => {
            assert!(proceed_with_methods.is_some());
        }
        _ => panic!("expected Auth::Reject"),
    }
}

#[tokio::test]
async fn record_auth_failure_keyboard_interactive_method() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);

    // "keyboard-interactive" is not "publickey", so metric_method stays the same
    let result = handler
        .test_record_auth_failure("alice", "keyboard-interactive", 1)
        .await;

    match result {
        russh::server::Auth::Reject {
            proceed_with_methods,
            ..
        } => {
            assert!(proceed_with_methods.is_some());
        }
        _ => panic!("expected Auth::Reject"),
    }
}

// ===========================================================================
// 41. Auth timeout - not timed out when freshly connected
// ===========================================================================

#[tokio::test]
async fn auth_timeout_not_exceeded_on_fresh_connection() {
    let ctx = setup(make_config(""));
    let handler = make_handler(ctx);

    assert!(!handler.test_is_auth_timed_out());
}

// ===========================================================================
// 42. Auth timeout - not timed out when authenticated
// ===========================================================================

#[tokio::test]
async fn auth_timeout_not_exceeded_when_authenticated() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);

    handler.set_connected_at(std::time::Instant::now() - std::time::Duration::from_secs(999));
    handler.set_authenticated("alice", "password");

    assert!(!handler.test_is_auth_timed_out());
}

// ===========================================================================
// 43. Auth timeout - timed out when connection is old and unauthenticated
// ===========================================================================

#[tokio::test]
async fn auth_timeout_exceeded_when_old_unauthenticated() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);

    handler.set_connected_at(std::time::Instant::now() - std::time::Duration::from_secs(200));

    assert!(handler.test_is_auth_timed_out());
}

// ===========================================================================
// 44. Auth timeout - custom timeout from config
// ===========================================================================

#[tokio::test]
async fn auth_timeout_custom_value() {
    let ctx = setup(make_config(""));
    let mut handler = make_handler(ctx);

    // 100 seconds < 120s default timeout: should NOT be timed out
    handler.set_connected_at(std::time::Instant::now() - std::time::Duration::from_secs(100));
    assert!(!handler.test_is_auth_timed_out());

    // 130 seconds > 120s default timeout: should be timed out
    handler.set_connected_at(std::time::Instant::now() - std::time::Duration::from_secs(130));
    assert!(handler.test_is_auth_timed_out());
}

// ===========================================================================
// 45. Auth timeout - clamped to minimum 10 seconds
// ===========================================================================

#[tokio::test]
async fn auth_timeout_clamped_minimum() {
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:2222"
host_key_path = "/tmp/sks5-test-host-key"
ssh_auth_timeout = 1

[limits]
max_auth_attempts = 3

[security]
ban_enabled = false

[[users]]
username = "alice"
password_hash = "{FAKE_HASH}"
allow_forwarding = true
allow_shell = true
"##
    );
    let config: AppConfig = toml::from_str(&toml_str).unwrap();
    let ctx = setup(config);
    let mut handler = make_handler(ctx);

    // 5 seconds < clamped minimum of 10s: should NOT be timed out
    handler.set_connected_at(std::time::Instant::now() - std::time::Duration::from_secs(5));
    assert!(!handler.test_is_auth_timed_out());

    // 15 seconds > clamped minimum of 10s: should be timed out
    handler.set_connected_at(std::time::Instant::now() - std::time::Duration::from_secs(15));
    assert!(handler.test_is_auth_timed_out());
}

// ===========================================================================
// 46. validate_forwarding_request - ACL checks happen later in proxy engine
// ===========================================================================

#[tokio::test]
async fn validate_forwarding_denied_by_acl_deny_rule() {
    // ACL deny rules are now enforced at the SSH handler level via pre-check.
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:2222"
host_key_path = "/tmp/sks5-test-host-key"

[limits]
max_auth_attempts = 3

[security]
ban_enabled = false

[acl]
default_policy = "allow"
deny = ["evil.com:*"]

[[users]]
username = "alice"
password_hash = "{FAKE_HASH}"
allow_forwarding = true
allow_shell = true
"##
    );
    let config: AppConfig = toml::from_str(&toml_str).unwrap();
    let ctx = setup(config);
    let mut handler = make_handler(ctx);
    handler.set_authenticated("alice", "password");

    // validate_forwarding_request returns None (ACL pre-check denies)
    let result = handler
        .test_validate_forwarding_request("evil.com", 443)
        .await
        .unwrap();
    assert!(
        result.is_none(),
        "handler should deny forwarding when ACL deny rule matches"
    );
}

// ===========================================================================
// 47. validate_forwarding_request - user with per-user rate limits
// ===========================================================================

#[tokio::test]
async fn validate_forwarding_with_rate_limit_config() {
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:2222"
host_key_path = "/tmp/sks5-test-host-key"

[limits]
max_auth_attempts = 3

[security]
ban_enabled = false

[[users]]
username = "alice"
password_hash = "{FAKE_HASH}"
allow_forwarding = true
allow_shell = true
max_new_connections_per_minute = 100
"##
    );
    let config: AppConfig = toml::from_str(&toml_str).unwrap();
    let ctx = setup(config);
    let mut handler = make_handler(ctx);
    handler.set_authenticated("alice", "password");

    // First request should pass (rate limit not exceeded)
    let result = handler
        .test_validate_forwarding_request("example.com", 443)
        .await
        .unwrap();
    assert!(result.is_some());
}
