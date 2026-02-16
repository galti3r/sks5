#[allow(dead_code, unused_imports)]
mod helpers;

use sks5::config::types::WebhookConfig;
use sks5::webhooks::WebhookDispatcher;

use axum::{routing::post, Json, Router};
use std::sync::{Arc, Mutex};
use tokio::time::{sleep, Duration};

/// Shared state for the webhook receiver
#[derive(Clone, Default)]
struct ReceivedWebhooks {
    events: Arc<Mutex<Vec<serde_json::Value>>>,
}

/// Mini webhook receiver handler
async fn receive_webhook(
    state: axum::extract::State<ReceivedWebhooks>,
    Json(payload): Json<serde_json::Value>,
) -> &'static str {
    state.events.lock().unwrap().push(payload);
    "ok"
}

/// Start a mini webhook receiver server, returns (port, state)
async fn start_webhook_receiver() -> (u16, ReceivedWebhooks) {
    let state = ReceivedWebhooks::default();
    let app = Router::new()
        .route("/webhook", post(receive_webhook))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    sleep(Duration::from_millis(50)).await;
    (port, state)
}

// ---------------------------------------------------------------------------
// Test 1: Webhook receives auth_success and auth_failure events
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_webhook_receives_events() {
    let (webhook_port, receiver) = start_webhook_receiver().await;

    let webhook_configs = vec![WebhookConfig {
        url: format!("http://127.0.0.1:{}/webhook", webhook_port),
        events: vec!["auth_success".to_string(), "auth_failure".to_string()],
        secret: None,
        allow_private_ips: true,
        max_retries: 0,
        retry_delay_ms: 1000,
        max_retry_delay_ms: 30000,
        format: Default::default(),
        template: None,
    }];

    let dispatcher = WebhookDispatcher::new(webhook_configs);

    // Dispatch auth_success event
    dispatcher.dispatch(
        "auth_success",
        serde_json::json!({
            "username": "testuser",
            "ip": "127.0.0.1",
            "method": "password"
        }),
    );

    // Dispatch auth_failure event
    dispatcher.dispatch(
        "auth_failure",
        serde_json::json!({
            "username": "baduser",
            "ip": "127.0.0.1",
            "method": "password"
        }),
    );

    // Wait for async webhook delivery
    sleep(Duration::from_millis(500)).await;

    let events = receiver.events.lock().unwrap();
    assert_eq!(
        events.len(),
        2,
        "Expected 2 webhook events, got {}",
        events.len()
    );
    assert_eq!(events[0]["event_type"], "auth_success");
    assert_eq!(events[1]["event_type"], "auth_failure");
    assert_eq!(events[0]["data"]["username"], "testuser");
    assert_eq!(events[1]["data"]["username"], "baduser");
}

// ---------------------------------------------------------------------------
// Test 2: Webhook sends HMAC signature header when secret is configured
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_webhook_hmac_signature() {
    let (_webhook_port, _receiver) = start_webhook_receiver().await;

    // Create receiver that captures the HMAC signature header
    let signature_state: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sig_clone = signature_state.clone();

    let sig_app = Router::new().route(
        "/webhook-sig",
        post(move |headers: axum::http::HeaderMap, _body: String| {
            let sig_state = sig_clone.clone();
            async move {
                let sig = headers
                    .get("x-signature-256")
                    .map(|v| v.to_str().unwrap_or("").to_string())
                    .unwrap_or_default();
                sig_state.lock().unwrap().push(sig);
                "ok"
            }
        }),
    );

    let sig_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sig_port = sig_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(sig_listener, sig_app).await.unwrap();
    });
    sleep(Duration::from_millis(50)).await;

    let webhook_configs = vec![WebhookConfig {
        url: format!("http://127.0.0.1:{}/webhook-sig", sig_port),
        events: vec![],
        secret: Some("test-secret-key".to_string()),
        allow_private_ips: true,
        max_retries: 0,
        retry_delay_ms: 1000,
        max_retry_delay_ms: 30000,
        format: Default::default(),
        template: None,
    }];

    let dispatcher = WebhookDispatcher::new(webhook_configs);
    dispatcher.dispatch("test_event", serde_json::json!({"key": "value"}));

    sleep(Duration::from_millis(500)).await;

    let sigs = signature_state.lock().unwrap();
    assert_eq!(sigs.len(), 1, "Expected 1 signature");
    assert!(
        sigs[0].starts_with("sha256="),
        "Signature should start with sha256="
    );
    assert!(sigs[0].len() > 7, "Signature should contain hex hash");
}

// ---------------------------------------------------------------------------
// Test 3: Webhook event filtering only delivers matching events
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_webhook_event_filter() {
    let (webhook_port, receiver) = start_webhook_receiver().await;

    let webhook_configs = vec![WebhookConfig {
        url: format!("http://127.0.0.1:{}/webhook", webhook_port),
        events: vec!["auth_success".to_string()], // Only auth_success
        secret: None,
        allow_private_ips: true,
        max_retries: 0,
        retry_delay_ms: 1000,
        max_retry_delay_ms: 30000,
        format: Default::default(),
        template: None,
    }];

    let dispatcher = WebhookDispatcher::new(webhook_configs);

    // This should be delivered (matches filter)
    dispatcher.dispatch("auth_success", serde_json::json!({"user": "alice"}));
    // This should NOT be delivered (doesn't match filter)
    dispatcher.dispatch("auth_failure", serde_json::json!({"user": "bob"}));

    sleep(Duration::from_millis(500)).await;

    let events = receiver.events.lock().unwrap();
    assert_eq!(
        events.len(),
        1,
        "Expected 1 event (filtered), got {}",
        events.len()
    );
    assert_eq!(events[0]["event_type"], "auth_success");
}

// ---------------------------------------------------------------------------
// Test 4: Webhook dispatch is non-blocking (fire and forget)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_webhook_timeout_does_not_block() {
    // Create a slow server that delays response
    let slow_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let slow_port = slow_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = slow_listener.accept().await {
                tokio::spawn(async move {
                    // Read the request but wait 30s before responding
                    let mut buf = vec![0u8; 4096];
                    let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await;
                    sleep(Duration::from_secs(30)).await;
                    let _ = tokio::io::AsyncWriteExt::write_all(
                        &mut socket,
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                    )
                    .await;
                });
            }
        }
    });

    let webhook_configs = vec![WebhookConfig {
        url: format!("http://127.0.0.1:{}/webhook", slow_port),
        events: vec![],
        secret: None,
        allow_private_ips: true,
        max_retries: 0,
        retry_delay_ms: 1000,
        max_retry_delay_ms: 30000,
        format: Default::default(),
        template: None,
    }];

    let dispatcher = WebhookDispatcher::new(webhook_configs);

    let start = std::time::Instant::now();
    dispatcher.dispatch("test_event", serde_json::json!({}));
    let elapsed = start.elapsed();

    // dispatch() should return immediately (fire and forget)
    assert!(
        elapsed.as_millis() < 100,
        "dispatch should not block, took {}ms",
        elapsed.as_millis()
    );
}
