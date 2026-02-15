use sks5::audit::events::AuditEvent;
use sks5::audit::AuditLogger;
use std::net::SocketAddr;
use tempfile::TempDir;
use tokio::time::{sleep, Duration};

// ===========================================================================
// AuditLogger construction
// ===========================================================================

#[tokio::test]
async fn new_logger_with_path_creates_file() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("audit.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);

    let source: SocketAddr = "192.168.1.1:12345".parse().unwrap();
    logger.log_auth_success("test", &source, "password").await;

    sleep(Duration::from_millis(100)).await;

    assert!(audit_path.exists(), "audit log file should be created");
}

#[tokio::test]
async fn new_logger_with_none_path_does_not_panic() {
    let logger = AuditLogger::new(None, 0, 0, None);

    let source: SocketAddr = "10.0.0.1:54321".parse().unwrap();
    logger.log_auth_success("user1", &source, "pubkey").await;
    logger.log_auth_failure("user2", &source, "password").await;
    logger
        .log_proxy_complete("user1", "example.com", 443, 512, 512, 100, &source, None)
        .await;

    sleep(Duration::from_millis(50)).await;
    // Test passes if no panic occurred
}

#[tokio::test]
async fn new_noop_logger_does_not_panic() {
    let logger = AuditLogger::new_noop();
    let source: SocketAddr = "10.0.0.1:1234".parse().unwrap();

    // All of these should silently drop events without panic
    logger.log_auth_success("user", &source, "password").await;
    logger.log_auth_failure("user", &source, "password").await;
    logger.log_connection_new(&source, "ssh");
    logger.log_connection_closed(&source, "ssh");
    logger.log_config_reload(5, true, None);
}

#[tokio::test]
async fn new_logger_creates_parent_directories() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("sub").join("dir").join("audit.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);

    let source: SocketAddr = "1.2.3.4:5678".parse().unwrap();
    logger.log_auth_success("test", &source, "password").await;

    sleep(Duration::from_millis(100)).await;
    assert!(audit_path.exists(), "nested directories should be created");
}

// ===========================================================================
// Event logging and serialization
// ===========================================================================

#[tokio::test]
async fn log_auth_success_writes_correct_json() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("auth_success.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);

    let source: SocketAddr = "192.168.1.100:12345".parse().unwrap();
    logger.log_auth_success("alice", &source, "password").await;

    sleep(Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();

    assert_eq!(parsed["event_type"], "auth.success");
    assert_eq!(parsed["username"], "alice");
    assert_eq!(parsed["source_ip"], "192.168.1.100");
    assert_eq!(parsed["method"], "password");
    assert!(parsed["timestamp"].is_string());
}

#[tokio::test]
async fn log_auth_failure_writes_correct_json() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("auth_failure.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);

    let source: SocketAddr = "10.0.0.1:9999".parse().unwrap();
    logger.log_auth_failure("attacker", &source, "pubkey").await;

    sleep(Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();

    assert_eq!(parsed["event_type"], "auth.failure");
    assert_eq!(parsed["username"], "attacker");
    assert_eq!(parsed["source_ip"], "10.0.0.1");
    assert_eq!(parsed["method"], "pubkey");
}

#[tokio::test]
async fn log_proxy_complete_writes_correct_json() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("proxy.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);

    let source: SocketAddr = "203.0.113.25:9999".parse().unwrap();
    logger
        .log_proxy_complete(
            "bob",
            "example.org",
            443,
            1024,
            2048,
            500,
            &source,
            Some("93.184.216.34".to_string()),
        )
        .await;

    sleep(Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();

    assert_eq!(parsed["event_type"], "proxy.complete");
    assert_eq!(parsed["username"], "bob");
    assert_eq!(parsed["target_host"], "example.org");
    assert_eq!(parsed["target_port"], 443);
    assert_eq!(parsed["bytes_uploaded"], 1024);
    assert_eq!(parsed["bytes_downloaded"], 2048);
    assert_eq!(parsed["bytes_transferred"], 3072);
    assert_eq!(parsed["duration_ms"], 500);
    assert_eq!(parsed["resolved_ip"], "93.184.216.34");
}

#[tokio::test]
async fn log_connection_events_write_correct_json() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("connection.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);

    let source: SocketAddr = "172.16.0.5:8080".parse().unwrap();
    logger.log_connection_new(&source, "ssh");
    logger.log_connection_closed(&source, "ssh");

    sleep(Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 2);

    let event1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(event1["event_type"], "connection.new");
    assert_eq!(event1["source_ip"], "172.16.0.5");
    assert_eq!(event1["protocol"], "ssh");

    let event2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(event2["event_type"], "connection.closed");
}

#[tokio::test]
async fn log_acl_deny_writes_correct_json() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("acl.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);

    logger.log_acl_deny(
        "eve",
        "evil.com",
        80,
        Some("1.2.3.4".to_string()),
        "10.0.0.1",
        Some("deny *.evil.com".to_string()),
        "hostname blocked",
    );

    sleep(Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();

    assert_eq!(parsed["event_type"], "acl.deny");
    assert_eq!(parsed["username"], "eve");
    assert_eq!(parsed["target_host"], "evil.com");
    assert_eq!(parsed["target_port"], 80);
    assert_eq!(parsed["resolved_ip"], "1.2.3.4");
    assert_eq!(parsed["source_ip"], "10.0.0.1");
    assert_eq!(parsed["reason"], "hostname blocked");
}

#[tokio::test]
async fn log_config_reload_writes_correct_json() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("reload.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);

    logger.log_config_reload(5, true, None);
    logger.log_config_reload(0, false, Some("parse error".to_string()));

    sleep(Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 2);

    let event1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(event1["event_type"], "config.reload");
    assert_eq!(event1["users_count"], 5);
    assert_eq!(event1["success"], true);
    assert!(event1.get("error").is_none() || event1["error"].is_null());

    let event2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(event2["event_type"], "config.reload");
    assert_eq!(event2["success"], false);
    assert_eq!(event2["error"], "parse error");
}

#[tokio::test]
async fn log_quota_exceeded_writes_correct_json() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("quota.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);

    logger.log_quota_exceeded("alice", "bandwidth", 1_000_000, 500_000);

    sleep(Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();

    assert_eq!(parsed["event_type"], "quota.exceeded");
    assert_eq!(parsed["username"], "alice");
    assert_eq!(parsed["quota_type"], "bandwidth");
    assert_eq!(parsed["current_usage"], 1_000_000);
    assert_eq!(parsed["limit"], 500_000);
}

#[tokio::test]
async fn log_session_authenticated_writes_correct_json() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("session_auth.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);

    let source: SocketAddr = "10.0.0.1:1234".parse().unwrap();
    logger.log_session_authenticated("alice", &source, "ssh", "password+totp");

    sleep(Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();

    assert_eq!(parsed["event_type"], "session.authenticated");
    assert_eq!(parsed["username"], "alice");
    assert_eq!(parsed["protocol"], "ssh");
    assert_eq!(parsed["method"], "password+totp");
}

#[tokio::test]
async fn log_session_ended_writes_correct_json() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("session_end.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);

    let source: SocketAddr = "10.0.0.1:1234".parse().unwrap();
    logger.log_session_ended("alice", &source, "ssh", 3600, 1_000_000);

    sleep(Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();

    assert_eq!(parsed["event_type"], "session.ended");
    assert_eq!(parsed["username"], "alice");
    assert_eq!(parsed["duration_secs"], 3600);
    assert_eq!(parsed["total_bytes"], 1_000_000);
}

#[tokio::test]
async fn log_rate_limit_exceeded_writes_correct_json() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("rate_limit.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);

    let source: SocketAddr = "10.0.0.1:1234".parse().unwrap();
    logger.log_rate_limit_exceeded("alice", &source, "per_user");

    sleep(Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();

    assert_eq!(parsed["event_type"], "rate_limit.exceeded");
    assert_eq!(parsed["username"], "alice");
    assert_eq!(parsed["limit_type"], "per_user");
}

#[tokio::test]
async fn log_maintenance_toggled_writes_correct_json() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("maintenance.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);

    logger.log_maintenance_toggled(true, "api");
    logger.log_maintenance_toggled(false, "config_reload");

    sleep(Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 2);

    let event1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(event1["event_type"], "maintenance.toggled");
    assert_eq!(event1["enabled"], true);
    assert_eq!(event1["source"], "api");

    let event2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(event2["enabled"], false);
}

// ===========================================================================
// log_event (direct event submission)
// ===========================================================================

#[tokio::test]
async fn log_event_accepts_custom_event() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("custom.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);

    let source: SocketAddr = "172.16.0.5:8080".parse().unwrap();
    let event = AuditEvent::auth_failure("hacker", &source, "password");
    logger.log_event(event);

    sleep(Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    assert!(content.contains("auth.failure"));
    assert!(content.contains("hacker"));
}

// ===========================================================================
// Dropped event counter
// ===========================================================================

#[tokio::test]
async fn dropped_count_starts_at_zero() {
    let logger = AuditLogger::new(None, 0, 0, None);
    assert_eq!(logger.dropped_count(), 0);
}

#[tokio::test]
async fn dropped_count_stays_zero_under_normal_load() {
    let logger = AuditLogger::new(None, 0, 0, None);

    let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();
    logger.log_auth_success("test", &addr, "password").await;

    // Give the async writer time
    sleep(Duration::from_millis(50)).await;

    assert_eq!(logger.dropped_count(), 0);
}

#[tokio::test]
async fn noop_logger_dropped_count_increments() {
    let logger = AuditLogger::new_noop();
    let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();

    // noop logger has capacity 1 and receiver is dropped
    // Send events that will be dropped
    for _ in 0..10 {
        logger.log_connection_new(&addr, "ssh");
    }

    // Some events should have been dropped (channel closed)
    // The exact count depends on timing, but should be > 0
    // The first event might succeed (buffer capacity 1), rest should fail
    let dropped = logger.dropped_count();
    assert!(
        dropped > 0,
        "noop logger should drop events, got {}",
        dropped
    );
}

// ===========================================================================
// Event criticality classification
// ===========================================================================

#[test]
fn critical_events_classified_correctly() {
    let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();

    // Critical events
    assert!(AuditEvent::auth_failure("u", &addr, "pw").is_critical());
    assert!(AuditEvent::acl_deny("u", "h", 80, None, "1.2.3.4", None, "r").is_critical());
    assert!(AuditEvent::config_reload(5, true, None).is_critical());
    assert!(AuditEvent::quota_exceeded("u", "bw", 100, 50).is_critical());
    assert!(AuditEvent::rate_limit_exceeded("u", &addr, "per_user").is_critical());
    assert!(AuditEvent::maintenance_toggled(true, "api").is_critical());

    // Non-critical events
    assert!(!AuditEvent::auth_success("u", &addr, "pw").is_critical());
    assert!(!AuditEvent::connection_new(&addr, "ssh").is_critical());
    assert!(!AuditEvent::connection_closed(&addr, "ssh").is_critical());
    assert!(!AuditEvent::proxy_complete("u", "h", 80, 0, 0, 0, &addr, None).is_critical());
    assert!(!AuditEvent::session_authenticated("u", &addr, "ssh", "pw").is_critical());
    assert!(!AuditEvent::session_ended("u", &addr, "ssh", 0, 0).is_critical());
}

// ===========================================================================
// Event type strings
// ===========================================================================

#[test]
fn event_type_returns_correct_strings() {
    let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();

    assert_eq!(
        AuditEvent::auth_success("u", &addr, "pw").event_type(),
        "auth.success"
    );
    assert_eq!(
        AuditEvent::auth_failure("u", &addr, "pw").event_type(),
        "auth.failure"
    );
    assert_eq!(
        AuditEvent::proxy_complete("u", "h", 80, 0, 0, 0, &addr, None).event_type(),
        "proxy.complete"
    );
    assert_eq!(
        AuditEvent::acl_deny("u", "h", 80, None, "1.2.3.4", None, "r").event_type(),
        "acl.deny"
    );
    assert_eq!(
        AuditEvent::connection_new(&addr, "ssh").event_type(),
        "connection.new"
    );
    assert_eq!(
        AuditEvent::connection_closed(&addr, "ssh").event_type(),
        "connection.closed"
    );
    assert_eq!(
        AuditEvent::config_reload(0, true, None).event_type(),
        "config.reload"
    );
    assert_eq!(
        AuditEvent::quota_exceeded("u", "bw", 0, 0).event_type(),
        "quota.exceeded"
    );
    assert_eq!(
        AuditEvent::session_authenticated("u", &addr, "ssh", "pw").event_type(),
        "session.authenticated"
    );
    assert_eq!(
        AuditEvent::session_ended("u", &addr, "ssh", 0, 0).event_type(),
        "session.ended"
    );
    assert_eq!(
        AuditEvent::rate_limit_exceeded("u", &addr, "per_user").event_type(),
        "rate_limit.exceeded"
    );
    assert_eq!(
        AuditEvent::maintenance_toggled(true, "api").event_type(),
        "maintenance.toggled"
    );
}

// ===========================================================================
// Multiple events written in order
// ===========================================================================

#[tokio::test]
async fn multiple_events_written_in_order() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("multi.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);

    let source: SocketAddr = "203.0.113.25:9999".parse().unwrap();

    logger.log_auth_success("alice", &source, "password").await;
    logger.log_auth_failure("bob", &source, "password").await;
    logger.log_connection_new(&source, "ssh");
    logger.log_config_reload(3, true, None);

    sleep(Duration::from_millis(200)).await;

    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let lines: Vec<&str> = content.lines().collect();

    assert_eq!(lines.len(), 4, "should have 4 events");

    let event1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(event1["event_type"], "auth.success");

    let event2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(event2["event_type"], "auth.failure");

    let event3: serde_json::Value = serde_json::from_str(lines[2]).unwrap();
    assert_eq!(event3["event_type"], "connection.new");

    let event4: serde_json::Value = serde_json::from_str(lines[3]).unwrap();
    assert_eq!(event4["event_type"], "config.reload");
}

// ===========================================================================
// Prometheus metric wiring
// ===========================================================================

#[tokio::test]
async fn set_dropped_metric_does_not_panic() {
    let logger = AuditLogger::new(None, 0, 0, None);
    let counter = prometheus_client::metrics::counter::Counter::default();
    logger.set_dropped_metric(counter);
    // Should not panic, and subsequent drops should increment the metric
}

#[tokio::test]
async fn set_dropped_metric_second_call_is_ignored() {
    let logger = AuditLogger::new(None, 0, 0, None);
    let counter1 = prometheus_client::metrics::counter::Counter::default();
    let counter2 = prometheus_client::metrics::counter::Counter::default();
    logger.set_dropped_metric(counter1);
    // OnceLock: second set is silently ignored
    logger.set_dropped_metric(counter2);
}

// ===========================================================================
// IPv6 source addresses
// ===========================================================================

#[tokio::test]
async fn log_with_ipv6_source() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("ipv6.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);

    let source: SocketAddr = "[2001:db8::1]:12345".parse().unwrap();
    logger.log_auth_success("alice", &source, "password").await;

    sleep(Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();

    assert_eq!(parsed["source_ip"], "2001:db8::1");
}
