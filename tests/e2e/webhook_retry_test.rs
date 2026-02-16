#[allow(dead_code, unused_imports)]
mod helpers;

use sks5::config::types::WebhookConfig;
use sks5::webhooks::WebhookDispatcher;

use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

// ---------------------------------------------------------------------------
// Helper: start a mini axum server that fails `fail_count` times then succeeds
// Returns (port, attempt_counter)
// ---------------------------------------------------------------------------
async fn start_flaky_server(fail_count: u32) -> (u16, Arc<AtomicU32>) {
    let attempt_count = Arc::new(AtomicU32::new(0));
    let count_clone = attempt_count.clone();

    let app = Router::new().route(
        "/hook",
        post(move || {
            let count = count_clone.clone();
            async move {
                let n = count.fetch_add(1, Ordering::SeqCst);
                if n < fail_count {
                    (StatusCode::INTERNAL_SERVER_ERROR, "fail")
                } else {
                    (StatusCode::OK, "ok")
                }
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    sleep(Duration::from_millis(50)).await;

    (port, attempt_count)
}

// ---------------------------------------------------------------------------
// Helper: start a server that always fails (500)
// Returns (port, attempt_counter)
// ---------------------------------------------------------------------------
async fn start_always_failing_server() -> (u16, Arc<AtomicU32>) {
    start_flaky_server(u32::MAX).await
}

// ---------------------------------------------------------------------------
// Helper: start a server that records request timestamps
// Returns (port, timestamps_vec)
// ---------------------------------------------------------------------------
async fn start_timing_server() -> (u16, Arc<Mutex<Vec<Instant>>>) {
    let timestamps = Arc::new(Mutex::new(Vec::<Instant>::new()));
    let ts_clone = timestamps.clone();

    let app = Router::new().route(
        "/hook",
        post(move || {
            let ts = ts_clone.clone();
            async move {
                ts.lock().await.push(Instant::now());
                (StatusCode::INTERNAL_SERVER_ERROR, "fail")
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    sleep(Duration::from_millis(50)).await;

    (port, timestamps)
}

// ---------------------------------------------------------------------------
// Helper: start a simple server that always returns 200
// Returns (port, attempt_counter)
// ---------------------------------------------------------------------------
async fn start_ok_server() -> (u16, Arc<AtomicU32>) {
    start_flaky_server(0).await
}

// ===========================================================================
// RETRY TESTS
// ===========================================================================

// ---------------------------------------------------------------------------
// Test 1: Webhook retry succeeds after initial failures
// Server fails the first 2 requests (500), then succeeds on the 3rd.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn webhook_retry_succeeds_after_failures() {
    let (port, attempt_count) = start_flaky_server(2).await;

    let config = vec![WebhookConfig {
        url: format!("http://127.0.0.1:{}/hook", port),
        events: vec![],
        secret: None,
        allow_private_ips: true,
        max_retries: 3,
        retry_delay_ms: 50,
        max_retry_delay_ms: 500,
        format: Default::default(),
        template: None,
    }];

    let dispatcher = WebhookDispatcher::new(config);
    dispatcher.dispatch("test_event", serde_json::json!({"key": "value"}));

    // Wait enough time for retries (50ms + 100ms + margin)
    sleep(Duration::from_millis(1000)).await;

    let total_attempts = attempt_count.load(Ordering::SeqCst);
    assert_eq!(
        total_attempts, 3,
        "Expected 3 attempts (1 initial + 2 retries that failed, then 3rd succeeds), got {}",
        total_attempts
    );
}

// ---------------------------------------------------------------------------
// Test 2: Webhook gives up after max retries exhausted
// Server always returns 500. Config: max_retries=2.
// Expects exactly 3 requests (1 initial + 2 retries).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn webhook_gives_up_after_max_retries() {
    let (port, attempt_count) = start_always_failing_server().await;

    let config = vec![WebhookConfig {
        url: format!("http://127.0.0.1:{}/hook", port),
        events: vec![],
        secret: None,
        allow_private_ips: true,
        max_retries: 2,
        retry_delay_ms: 50,
        max_retry_delay_ms: 500,
        format: Default::default(),
        template: None,
    }];

    let dispatcher = WebhookDispatcher::new(config);
    dispatcher.dispatch("test_event", serde_json::json!({"data": "test"}));

    // Wait for all retries: 50ms + 100ms + generous margin
    sleep(Duration::from_millis(1500)).await;

    let total_attempts = attempt_count.load(Ordering::SeqCst);
    assert_eq!(
        total_attempts, 3,
        "Expected exactly 3 attempts (1 initial + 2 retries), got {}",
        total_attempts
    );
}

// ---------------------------------------------------------------------------
// Test 3: No retry when max_retries is 0
// Server returns 500. Only 1 request should be made.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn webhook_no_retry_when_max_zero() {
    let (port, attempt_count) = start_always_failing_server().await;

    let config = vec![WebhookConfig {
        url: format!("http://127.0.0.1:{}/hook", port),
        events: vec![],
        secret: None,
        allow_private_ips: true,
        max_retries: 0,
        retry_delay_ms: 50,
        max_retry_delay_ms: 500,
        format: Default::default(),
        template: None,
    }];

    let dispatcher = WebhookDispatcher::new(config);
    dispatcher.dispatch("test_event", serde_json::json!({"data": "no_retry"}));

    // Give time for the single attempt plus margin
    sleep(Duration::from_millis(500)).await;

    let total_attempts = attempt_count.load(Ordering::SeqCst);
    assert_eq!(
        total_attempts, 1,
        "Expected exactly 1 attempt (no retries), got {}",
        total_attempts
    );
}

// ---------------------------------------------------------------------------
// Test 4: Exponential backoff timing verification
// Track timestamps of requests. Config: retry_delay_ms=100, max_retries=2.
// Delays should be approximately 100ms then 200ms (with +/- 50ms tolerance).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn webhook_backoff_timing() {
    let (port, timestamps) = start_timing_server().await;

    let config = vec![WebhookConfig {
        url: format!("http://127.0.0.1:{}/hook", port),
        events: vec![],
        secret: None,
        allow_private_ips: true,
        max_retries: 2,
        retry_delay_ms: 100,
        max_retry_delay_ms: 5000,
        format: Default::default(),
        template: None,
    }];

    let dispatcher = WebhookDispatcher::new(config);
    dispatcher.dispatch("test_event", serde_json::json!({"timing": true}));

    // Wait for all retries: 100ms + 200ms + generous margin
    sleep(Duration::from_millis(2000)).await;

    let ts = timestamps.lock().await;
    assert_eq!(
        ts.len(),
        3,
        "Expected 3 timestamp entries (1 initial + 2 retries), got {}",
        ts.len()
    );

    // First retry delay: retry_delay_ms * 2^0 = 100ms
    let delay1 = ts[1].duration_since(ts[0]);
    assert!(
        delay1.as_millis() >= 50 && delay1.as_millis() <= 250,
        "First retry delay should be ~100ms (tolerance +/-50ms), got {}ms",
        delay1.as_millis()
    );

    // Second retry delay: retry_delay_ms * 2^1 = 200ms
    let delay2 = ts[2].duration_since(ts[1]);
    assert!(
        delay2.as_millis() >= 150 && delay2.as_millis() <= 350,
        "Second retry delay should be ~200ms (tolerance +/-50ms), got {}ms",
        delay2.as_millis()
    );

    // Verify exponential growth: second delay should be roughly 2x the first
    let ratio = delay2.as_millis() as f64 / delay1.as_millis() as f64;
    assert!(
        (1.3..=3.0).contains(&ratio),
        "Delay ratio (2nd/1st) should be ~2.0, got {:.2}",
        ratio
    );
}

// ===========================================================================
// DNS REBINDING PROTECTION TESTS
// ===========================================================================

// ---------------------------------------------------------------------------
// Test 5: Webhook blocks private IP when allow_private_ips=false
// URL uses http://127.0.0.1:PORT/hook with allow_private_ips=false.
// The webhook should NOT be delivered.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn webhook_blocks_private_ip_url() {
    let (port, attempt_count) = start_ok_server().await;

    let config = vec![WebhookConfig {
        url: format!("http://127.0.0.1:{}/hook", port),
        events: vec![],
        secret: None,
        allow_private_ips: false, // Block private IPs
        max_retries: 0,
        retry_delay_ms: 50,
        max_retry_delay_ms: 500,
        format: Default::default(),
        template: None,
    }];

    let dispatcher = WebhookDispatcher::new(config);
    dispatcher.dispatch("test_event", serde_json::json!({"should": "not arrive"}));

    // Wait generously for any delivery attempt
    sleep(Duration::from_millis(1000)).await;

    let total_attempts = attempt_count.load(Ordering::SeqCst);
    assert_eq!(
        total_attempts, 0,
        "Expected 0 attempts (private IP should be blocked), got {}",
        total_attempts
    );
}

// ---------------------------------------------------------------------------
// Test 6: Webhook allows private IP when allow_private_ips=true
// URL uses http://127.0.0.1:PORT/hook with allow_private_ips=true.
// The webhook should be delivered successfully.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn webhook_allows_private_ip_when_configured() {
    let (port, attempt_count) = start_ok_server().await;

    let config = vec![WebhookConfig {
        url: format!("http://127.0.0.1:{}/hook", port),
        events: vec![],
        secret: None,
        allow_private_ips: true, // Allow private IPs
        max_retries: 0,
        retry_delay_ms: 50,
        max_retry_delay_ms: 500,
        format: Default::default(),
        template: None,
    }];

    let dispatcher = WebhookDispatcher::new(config);
    dispatcher.dispatch("test_event", serde_json::json!({"should": "arrive"}));

    // Wait for delivery
    sleep(Duration::from_millis(1000)).await;

    let total_attempts = attempt_count.load(Ordering::SeqCst);
    assert_eq!(
        total_attempts, 1,
        "Expected 1 attempt (private IP allowed), got {}",
        total_attempts
    );
}

// ---------------------------------------------------------------------------
// Test 7: Webhook blocks loopback hostname (localhost)
// URL uses http://localhost:PORT/hook with allow_private_ips=false.
// "localhost" resolves to 127.0.0.1 which is a private/loopback IP.
// The webhook should NOT be delivered.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn webhook_blocks_loopback_hostname() {
    let (port, attempt_count) = start_ok_server().await;

    let config = vec![WebhookConfig {
        url: format!("http://localhost:{}/hook", port),
        events: vec![],
        secret: None,
        allow_private_ips: false, // Block private IPs
        max_retries: 0,
        retry_delay_ms: 50,
        max_retry_delay_ms: 500,
        format: Default::default(),
        template: None,
    }];

    let dispatcher = WebhookDispatcher::new(config);
    dispatcher.dispatch("test_event", serde_json::json!({"should": "not arrive"}));

    // Wait generously for any delivery attempt
    sleep(Duration::from_millis(1000)).await;

    let total_attempts = attempt_count.load(Ordering::SeqCst);
    assert_eq!(
        total_attempts, 0,
        "Expected 0 attempts (localhost resolves to loopback, should be blocked), got {}",
        total_attempts
    );
}
