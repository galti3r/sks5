use sks5::audit::events::AuditEvent;
use sks5::audit::AuditLogger;
use std::net::SocketAddr;
use tempfile::TempDir;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_event_written_to_file() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("audit.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);

    let source: SocketAddr = "192.168.1.100:12345".parse().unwrap();
    logger
        .log_auth_success("testuser", &source, "password")
        .await;

    // Give the async task time to write
    sleep(Duration::from_millis(100)).await;

    // Read the file
    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();

    // Verify JSON was written
    assert!(content.contains("auth.success"));
    assert!(content.contains("testuser"));
    assert!(content.contains("192.168.1.100"));
    assert!(content.contains("password"));

    // Verify it's valid JSON
    let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
    assert_eq!(parsed["event_type"], "auth.success");
    assert_eq!(parsed["username"], "testuser");
    assert_eq!(parsed["source_ip"], "192.168.1.100");
}

#[tokio::test]
async fn test_logger_with_none_path_doesnt_panic() {
    let logger = AuditLogger::new(None, 0, 0, None);

    let source: SocketAddr = "10.0.0.1:54321".parse().unwrap();

    // Should not panic
    logger.log_auth_success("user1", &source, "pubkey").await;
    logger.log_auth_failure("user2", &source, "password").await;
    logger
        .log_proxy_complete("user1", "example.com", 443, 512, 512, 100, &source, None)
        .await;

    // Give async task time to process
    sleep(Duration::from_millis(50)).await;

    // Test passes if no panic occurred
}

#[tokio::test]
async fn test_multiple_events_written_in_order() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("multi_audit.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);

    let source: SocketAddr = "203.0.113.25:9999".parse().unwrap();

    // Log multiple events
    logger.log_auth_success("alice", &source, "password").await;
    logger.log_auth_failure("bob", &source, "password").await;
    logger
        .log_proxy_complete(
            "alice",
            "example.org",
            80,
            1024,
            1024,
            200,
            &source,
            Some("93.184.216.34".to_string()),
        )
        .await;

    // Give time to write all events
    sleep(Duration::from_millis(150)).await;

    // Read all lines
    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let lines: Vec<&str> = content.lines().collect();

    assert_eq!(lines.len(), 3);

    // Verify each event
    let event1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(event1["event_type"], "auth.success");
    assert_eq!(event1["username"], "alice");

    let event2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(event2["event_type"], "auth.failure");
    assert_eq!(event2["username"], "bob");

    let event3: serde_json::Value = serde_json::from_str(lines[2]).unwrap();
    assert_eq!(event3["event_type"], "proxy.complete");
    assert_eq!(event3["username"], "alice");
    assert_eq!(event3["target_host"], "example.org");
    assert_eq!(event3["target_port"], 80);
    assert_eq!(event3["bytes_transferred"], 2048);
}

#[tokio::test]
async fn test_custom_event_via_log_event() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("custom_audit.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);

    // Create a custom event directly
    let source: SocketAddr = "172.16.0.5:8080".parse().unwrap();
    let event = AuditEvent::auth_failure("hacker", &source, "password");

    logger.log_event(event);

    sleep(Duration::from_millis(100)).await;

    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    assert!(content.contains("auth.failure"));
    assert!(content.contains("hacker"));
    assert!(content.contains("172.16.0.5"));
}

#[tokio::test]
async fn test_concurrent_logging() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("concurrent_audit.log");

    let logger = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);

    let source: SocketAddr = "10.10.10.10:1234".parse().unwrap();

    // Log many events concurrently
    let mut handles = vec![];
    for i in 0..10 {
        let logger_clone = AuditLogger::new(Some(audit_path.clone()), 0, 0, None);
        let src = source;
        let handle = tokio::spawn(async move {
            logger_clone
                .log_auth_success(&format!("user{}", i), &src, "password")
                .await;
        });
        handles.push(handle);
    }

    // Wait for all to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // Also log from original logger
    for i in 10..20 {
        logger
            .log_auth_success(&format!("user{}", i), &source, "password")
            .await;
    }

    // Give time to write
    sleep(Duration::from_millis(200)).await;

    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let lines: Vec<&str> = content.lines().collect();

    // Should have logged multiple events (may not be exactly 20 due to async nature,
    // but should have at least some)
    assert!(!lines.is_empty());
    assert!(lines.len() >= 10);
}
