use sks5::audit::AuditLogger;
use std::net::SocketAddr;
use tempfile::TempDir;
use tokio::time::{sleep, Duration};

// ===========================================================================
// Log rotation: file rolls over when max_size_bytes is exceeded
// ===========================================================================

#[tokio::test]
async fn rotation_creates_rotated_file_when_size_exceeded() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("audit.json");

    // max_size_bytes = 200 bytes, max_files = 3
    // Each JSON event is roughly ~100-200 bytes, so a few events should trigger rotation
    let logger = AuditLogger::new(Some(audit_path.clone()), 200, 3, None);

    let source: SocketAddr = "10.0.0.1:1234".parse().unwrap();

    // Send enough events to trigger rotation
    for i in 0..10 {
        logger
            .log_auth_success(&format!("user{i}"), &source, "password")
            .await;
    }

    // Give the async writer time to process
    sleep(Duration::from_millis(500)).await;

    // The main audit file should exist
    assert!(audit_path.exists(), "audit.json should exist");

    // At least one rotated file should exist
    let rotated_1 = temp_dir.path().join("audit.json.1");
    assert!(
        rotated_1.exists(),
        "audit.json.1 should exist after rotation"
    );
}

#[tokio::test]
async fn rotation_shifts_files_to_higher_numbers() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("audit.json");

    // Very small max_size to trigger multiple rotations
    let logger = AuditLogger::new(Some(audit_path.clone()), 100, 5, None);

    let source: SocketAddr = "10.0.0.1:1234".parse().unwrap();

    // Send many events to trigger multiple rotations
    for i in 0..30 {
        logger
            .log_auth_success(&format!("user{i}"), &source, "password")
            .await;
    }

    sleep(Duration::from_millis(800)).await;

    // Main file should exist
    assert!(audit_path.exists());

    // At least .1 should exist
    let rotated_1 = temp_dir.path().join("audit.json.1");
    assert!(rotated_1.exists(), "audit.json.1 should exist");
}

#[tokio::test]
async fn rotation_respects_max_files_limit() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("audit.json");

    // max_files = 2, so .3 and above should never appear
    let logger = AuditLogger::new(Some(audit_path.clone()), 100, 2, None);

    let source: SocketAddr = "10.0.0.1:1234".parse().unwrap();

    // Send many events to trigger multiple rotations
    for i in 0..30 {
        logger
            .log_auth_success(&format!("user{i}"), &source, "password")
            .await;
    }

    sleep(Duration::from_millis(800)).await;

    // Files beyond max_files should not be created
    // With max_files=2, rotation shifts .1 -> .2 -> .3 won't happen beyond .2
    let rotated_3 = temp_dir.path().join("audit.json.3");
    assert!(
        !rotated_3.exists(),
        "audit.json.3 should not exist with max_files=2"
    );
}

#[tokio::test]
async fn no_rotation_when_max_size_is_zero() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("audit.json");

    // max_size_bytes = 0 disables rotation
    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 3, None);

    let source: SocketAddr = "10.0.0.1:1234".parse().unwrap();

    for i in 0..20 {
        logger
            .log_auth_success(&format!("user{i}"), &source, "password")
            .await;
    }

    sleep(Duration::from_millis(500)).await;

    // Main file should exist with all events
    assert!(audit_path.exists());

    // No rotation files should exist
    let rotated_1 = temp_dir.path().join("audit.json.1");
    assert!(
        !rotated_1.exists(),
        "No rotation files when max_size_bytes=0"
    );
}

// ===========================================================================
// CID (Correlation ID) variant methods
// ===========================================================================

#[tokio::test]
async fn cid_auth_success_includes_correlation_id() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("cid_auth.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);
    let source: SocketAddr = "10.0.0.1:1234".parse().unwrap();

    logger
        .log_auth_success_cid("alice", &source, "password", "cid-abc-123")
        .await;

    sleep(Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();

    assert_eq!(parsed["event_type"], "auth.success");
    assert_eq!(parsed["username"], "alice");
    assert_eq!(parsed["correlation_id"], "cid-abc-123");
}

#[tokio::test]
async fn cid_auth_failure_includes_correlation_id() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("cid_auth_fail.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);
    let source: SocketAddr = "10.0.0.1:1234".parse().unwrap();

    logger
        .log_auth_failure_cid("attacker", &source, "password", "cid-def-456")
        .await;

    sleep(Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();

    assert_eq!(parsed["event_type"], "auth.failure");
    assert_eq!(parsed["correlation_id"], "cid-def-456");
}

#[tokio::test]
async fn cid_proxy_complete_includes_correlation_id() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("cid_proxy.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);
    let source: SocketAddr = "10.0.0.1:1234".parse().unwrap();

    logger
        .log_proxy_complete_cid(
            "alice",
            "example.com",
            443,
            1024,
            2048,
            500,
            &source,
            Some("93.184.216.34".to_string()),
            "cid-proxy-789",
        )
        .await;

    sleep(Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();

    assert_eq!(parsed["event_type"], "proxy.complete");
    assert_eq!(parsed["correlation_id"], "cid-proxy-789");
    assert_eq!(parsed["bytes_uploaded"], 1024);
    assert_eq!(parsed["bytes_downloaded"], 2048);
}

#[tokio::test]
async fn cid_connection_new_includes_correlation_id() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("cid_conn.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);
    let source: SocketAddr = "10.0.0.1:1234".parse().unwrap();

    logger.log_connection_new_cid(&source, "ssh", "cid-conn-001");

    sleep(Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();

    assert_eq!(parsed["event_type"], "connection.new");
    assert_eq!(parsed["correlation_id"], "cid-conn-001");
}

#[tokio::test]
async fn cid_connection_closed_includes_correlation_id() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("cid_conn_close.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);
    let source: SocketAddr = "10.0.0.1:1234".parse().unwrap();

    logger.log_connection_closed_cid(&source, "socks5", "cid-conn-002");

    sleep(Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();

    assert_eq!(parsed["event_type"], "connection.closed");
    assert_eq!(parsed["protocol"], "socks5");
    assert_eq!(parsed["correlation_id"], "cid-conn-002");
}

#[tokio::test]
async fn cid_acl_deny_includes_correlation_id() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("cid_acl.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);

    logger.log_acl_deny_cid(
        "eve",
        "blocked.com",
        80,
        Some("1.2.3.4".to_string()),
        "10.0.0.1",
        Some("deny *.blocked.com".to_string()),
        "hostname blocked",
        "cid-acl-003",
    );

    sleep(Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();

    assert_eq!(parsed["event_type"], "acl.deny");
    assert_eq!(parsed["correlation_id"], "cid-acl-003");
    assert_eq!(parsed["reason"], "hostname blocked");
}

#[tokio::test]
async fn cid_session_authenticated_includes_correlation_id() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("cid_session.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);
    let source: SocketAddr = "10.0.0.1:1234".parse().unwrap();

    logger.log_session_authenticated_cid("alice", &source, "ssh", "password+totp", "cid-sess-004");

    sleep(Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();

    assert_eq!(parsed["event_type"], "session.authenticated");
    assert_eq!(parsed["correlation_id"], "cid-sess-004");
    assert_eq!(parsed["method"], "password+totp");
}

#[tokio::test]
async fn cid_rate_limit_exceeded_includes_correlation_id() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("cid_rate.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);
    let source: SocketAddr = "10.0.0.1:1234".parse().unwrap();

    logger.log_rate_limit_exceeded_cid("alice", &source, "per_user", "cid-rate-005");

    sleep(Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();

    assert_eq!(parsed["event_type"], "rate_limit.exceeded");
    assert_eq!(parsed["correlation_id"], "cid-rate-005");
}

// ===========================================================================
// Ban CID events
// ===========================================================================

#[tokio::test]
async fn ban_created_logged_with_ipv4() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("ban.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);
    let ip: std::net::IpAddr = "192.168.1.100".parse().unwrap();

    logger.log_ban_created(&ip, 600);

    sleep(Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();

    assert_eq!(parsed["event_type"], "ban.created");
    assert_eq!(parsed["ip"], "192.168.1.100");
    assert_eq!(parsed["duration_secs"], 600);
}

#[tokio::test]
async fn ban_expired_logged_with_ipv6() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("ban_exp.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);
    let ip: std::net::IpAddr = "2001:db8::1".parse().unwrap();

    logger.log_ban_expired(&ip);

    sleep(Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();

    assert_eq!(parsed["event_type"], "ban.expired");
    assert_eq!(parsed["ip"], "2001:db8::1");
}
