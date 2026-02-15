use sks5::config::types::WebhookConfig;
use sks5::webhooks::types::WebhookPayload;

// ---------------------------------------------------------------------------
// Test 1: WebhookPayload serializes to valid JSON with all fields
// ---------------------------------------------------------------------------
#[test]
fn payload_serializes_to_json() {
    let payload = WebhookPayload {
        event_type: "auth_success".to_string(),
        timestamp: chrono::Utc::now(),
        data: serde_json::json!({"user": "alice", "ip": "1.2.3.4"}),
    };

    let json = serde_json::to_string(&payload).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["event_type"], "auth_success");
    assert!(parsed["timestamp"].is_string());
    assert_eq!(parsed["data"]["user"], "alice");
    assert_eq!(parsed["data"]["ip"], "1.2.3.4");
}

// ---------------------------------------------------------------------------
// Test 2: WebhookPayload clone works
// ---------------------------------------------------------------------------
#[test]
fn payload_clone() {
    let payload = WebhookPayload {
        event_type: "proxy_complete".to_string(),
        timestamp: chrono::Utc::now(),
        data: serde_json::json!({"bytes": 1024}),
    };

    let cloned = payload.clone();
    assert_eq!(cloned.event_type, payload.event_type);
    assert_eq!(cloned.data, payload.data);
}

// ---------------------------------------------------------------------------
// Test 3: WebhookPayload Debug format
// ---------------------------------------------------------------------------
#[test]
fn payload_debug() {
    let payload = WebhookPayload {
        event_type: "test".to_string(),
        timestamp: chrono::Utc::now(),
        data: serde_json::json!(null),
    };

    let debug = format!("{:?}", payload);
    assert!(debug.contains("test"));
}

// ---------------------------------------------------------------------------
// Test 4: WebhookConfig Debug redacts secret
// ---------------------------------------------------------------------------
#[test]
fn webhook_config_debug_redacts_secret() {
    let config = WebhookConfig {
        url: "https://example.com/webhook".to_string(),
        events: vec!["auth_success".to_string()],
        secret: Some("super-secret-key".to_string()),
        allow_private_ips: false,
        max_retries: 3,
        retry_delay_ms: 1000,
        max_retry_delay_ms: 30000,
    };

    let debug = format!("{:?}", config);
    assert!(debug.contains("example.com"));
    assert!(debug.contains("***"), "secret should be redacted");
    assert!(
        !debug.contains("super-secret-key"),
        "secret value must not appear"
    );
}

// ---------------------------------------------------------------------------
// Test 5: WebhookConfig without secret shows None
// ---------------------------------------------------------------------------
#[test]
fn webhook_config_debug_no_secret() {
    let config = WebhookConfig {
        url: "https://example.com/hook".to_string(),
        events: vec![],
        secret: None,
        allow_private_ips: false,
        max_retries: 3,
        retry_delay_ms: 1000,
        max_retry_delay_ms: 30000,
    };

    let debug = format!("{:?}", config);
    assert!(debug.contains("None"));
}

// ---------------------------------------------------------------------------
// Test 6: HMAC signature generation is correct
// ---------------------------------------------------------------------------
#[test]
fn hmac_signature_matches_expected() {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let secret = "my-webhook-secret";
    let body = r#"{"event_type":"test","timestamp":"2026-01-01T00:00:00Z","data":null}"#;

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    // Verify signature is a 64-char hex string (SHA256)
    assert_eq!(signature.len(), 64);
    assert!(signature.chars().all(|c| c.is_ascii_hexdigit()));

    // Verify same input produces same output (deterministic)
    let mut mac2 = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac2.update(body.as_bytes());
    let signature2 = hex::encode(mac2.finalize().into_bytes());
    assert_eq!(signature, signature2);
}

// ---------------------------------------------------------------------------
// Test 7: Different secrets produce different signatures
// ---------------------------------------------------------------------------
#[test]
fn different_secrets_different_signatures() {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let body = r#"{"event":"test"}"#;

    let mut mac1 = Hmac::<Sha256>::new_from_slice(b"secret1").unwrap();
    mac1.update(body.as_bytes());
    let sig1 = hex::encode(mac1.finalize().into_bytes());

    let mut mac2 = Hmac::<Sha256>::new_from_slice(b"secret2").unwrap();
    mac2.update(body.as_bytes());
    let sig2 = hex::encode(mac2.finalize().into_bytes());

    assert_ne!(sig1, sig2);
}

// ---------------------------------------------------------------------------
// Test 8: WebhookDispatcher creation with empty configs
// ---------------------------------------------------------------------------
#[tokio::test]
async fn dispatcher_empty_configs() {
    let dispatcher = sks5::webhooks::WebhookDispatcher::new(vec![]);
    // dispatch with empty configs should not panic
    dispatcher.dispatch("test_event", serde_json::json!({"key": "value"}));
    // Allow spawned tasks to run (there shouldn't be any)
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
}

// ---------------------------------------------------------------------------
// Test 9: WebhookDispatcher with event filter skips non-matching events
// ---------------------------------------------------------------------------
#[tokio::test]
async fn dispatcher_event_filter_skips_nonmatching() {
    // Create a webhook that only listens for "auth_success" events
    // The URL is invalid so if it tries to send, it will fail silently
    let config = WebhookConfig {
        url: "http://127.0.0.1:1/nonexistent".to_string(),
        events: vec!["auth_success".to_string()],
        secret: None,
        allow_private_ips: true,
        max_retries: 0,
        retry_delay_ms: 1000,
        max_retry_delay_ms: 30000,
    };

    let dispatcher = sks5::webhooks::WebhookDispatcher::new(vec![config]);
    // This event should be filtered out (not "auth_success")
    dispatcher.dispatch("proxy_complete", serde_json::json!({"test": true}));
    // Short wait - nothing should be sent
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
}

// ---------------------------------------------------------------------------
// Test 10: Webhook delivery to local server with HMAC verification
// ---------------------------------------------------------------------------
#[tokio::test]
async fn dispatcher_delivers_to_local_server() {
    use std::sync::Arc;
    use tokio::sync::Mutex;

    let received = Arc::new(Mutex::new(Vec::<(String, Option<String>)>::new()));
    let received_clone = received.clone();

    // Start a local HTTP server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/hook",
            axum::routing::post(move |headers: axum::http::HeaderMap, body: String| {
                let recv = received_clone.clone();
                async move {
                    let sig = headers
                        .get("X-Signature-256")
                        .map(|v| v.to_str().unwrap().to_string());
                    recv.lock().await.push((body, sig));
                    "ok"
                }
            }),
        );
        axum::serve(listener, app).await.unwrap();
    });

    // Give the server time to start
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let secret = "test-secret-123";
    let config = WebhookConfig {
        url: format!("http://127.0.0.1:{}/hook", port),
        events: vec![], // empty = all events
        secret: Some(secret.to_string()),
        allow_private_ips: true,
        max_retries: 0,
        retry_delay_ms: 1000,
        max_retry_delay_ms: 30000,
    };

    let dispatcher = sks5::webhooks::WebhookDispatcher::new(vec![config]);
    dispatcher.dispatch("auth_success", serde_json::json!({"user": "alice"}));

    // Wait for the async delivery
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let reqs = received.lock().await;
    assert_eq!(reqs.len(), 1, "should have received exactly one webhook");

    // Verify body contains event_type
    let body = &reqs[0].0;
    let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(parsed["event_type"], "auth_success");
    assert_eq!(parsed["data"]["user"], "alice");

    // Verify HMAC signature
    let sig_header = reqs[0]
        .1
        .as_ref()
        .expect("should have X-Signature-256 header");
    assert!(sig_header.starts_with("sha256="));

    // Recompute HMAC and compare
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body.as_bytes());
    let expected_sig = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
    assert_eq!(sig_header, &expected_sig);
}
