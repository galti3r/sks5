#[allow(dead_code, unused_imports)]
mod helpers;

use helpers::*;
use sks5::audit::AuditLogger;
use sks5::auth::AuthService;
use sks5::config::types::{QuotaConfig, RateLimitsConfig};
use sks5::metrics::MetricsRegistry;
use sks5::proxy::ProxyEngine;
use sks5::quota::{QuotaResult, QuotaTracker};
use sks5::security::SecurityManager;
use std::sync::Arc;
use tokio::sync::RwLock;

fn make_config(api_port: u16, hash: &str) -> sks5::config::types::AppConfig {
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
host_key_path = "/tmp/sks5-e2e-quota-api-key"

[api]
enabled = true
listen = "127.0.0.1:{api_port}"
token = "quota-test-token"

[security]
ban_enabled = false

[logging]
level = "debug"

[[users]]
username = "alice"
password_hash = "{hash}"
allow_forwarding = true
allow_shell = true
"##
    );
    toml::from_str(&toml_str).unwrap()
}

async fn start_api_with_quota(config: sks5::config::types::AppConfig) -> (u16, Arc<QuotaTracker>) {
    let api_addr = config.api.listen.clone();
    let port: u16 = api_addr.split(':').next_back().unwrap().parse().unwrap();
    let config = Arc::new(config);

    let audit = Arc::new(AuditLogger::new(None, 0, 0, None));
    let quota_tracker = Arc::new(QuotaTracker::new(&config.limits));

    let state = sks5::api::AppState {
        auth_service: Arc::new(RwLock::new(AuthService::new(&config).unwrap())),
        proxy_engine: Arc::new(ProxyEngine::new(config.clone(), audit.clone())),
        security: Arc::new(RwLock::new(SecurityManager::new(&config))),
        metrics: Arc::new(MetricsRegistry::new()),
        api_token: config.api.token.clone(),
        maintenance: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        start_time: std::time::Instant::now(),
        config_path: None,
        audit: Some(audit),
        broadcast_tx: None,
        ssh_listen_addr: None,
        quota_tracker: Some(quota_tracker.clone()),
        webhook_dispatcher: None,
    };

    let _task = tokio::spawn(async move {
        let _ = sks5::api::start_api_server(
            &api_addr,
            state,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    (port, quota_tracker)
}

// ---------------------------------------------------------------------------
// Test 1: GET /api/quotas returns empty when no activity
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_quota_list_empty() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let (port, _qt) = start_api_with_quota(make_config(port, &hash)).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/quotas"))
        .header("Authorization", "Bearer quota-test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    let data = body["data"].as_array().unwrap();
    assert!(data.is_empty(), "no tracked users yet");
}

// ---------------------------------------------------------------------------
// Test 2: GET /api/quotas returns user data after activity
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_quota_list_after_activity() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let (port, qt) = start_api_with_quota(make_config(port, &hash)).await;

    // Simulate some activity
    qt.record_connection("alice", None).unwrap();
    match qt.record_bytes("alice", 5000, 0, 0, None) {
        sks5::quota::QuotaResult::Ok(_) => {}
        sks5::quota::QuotaResult::Exceeded(r) => panic!("unexpected: {r}"),
    }

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/quotas"))
        .header("Authorization", "Bearer quota-test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    let data = body["data"].as_array().unwrap();
    assert_eq!(data.len(), 1);
    assert_eq!(data[0]["username"], "alice");
    assert_eq!(data[0]["daily_connections"], 1);
    assert_eq!(data[0]["daily_bytes"], 5000);
}

// ---------------------------------------------------------------------------
// Test 3: GET /api/quotas/:username returns user detail
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_quota_user_detail() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let (port, qt) = start_api_with_quota(make_config(port, &hash)).await;

    qt.record_connection("alice", None).unwrap();
    qt.record_connection("alice", None).unwrap();
    match qt.record_bytes("alice", 1024, 0, 0, None) {
        sks5::quota::QuotaResult::Ok(_) => {}
        sks5::quota::QuotaResult::Exceeded(r) => panic!("unexpected: {r}"),
    }

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/quotas/alice"))
        .header("Authorization", "Bearer quota-test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    let data = &body["data"];
    assert_eq!(data["username"], "alice");
    assert_eq!(data["daily_connections"], 2);
    assert_eq!(data["daily_bytes"], 1024);
    assert_eq!(data["monthly_connections"], 2);
    assert_eq!(data["monthly_bytes"], 1024);
}

// ---------------------------------------------------------------------------
// Test 4: POST /api/quotas/:username/reset clears counters
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_quota_reset() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let (port, qt) = start_api_with_quota(make_config(port, &hash)).await;

    qt.record_connection("alice", None).unwrap();
    match qt.record_bytes("alice", 9999, 0, 0, None) {
        sks5::quota::QuotaResult::Ok(_) => {}
        sks5::quota::QuotaResult::Exceeded(r) => panic!("unexpected: {r}"),
    }

    let client = reqwest::Client::new();

    // Reset
    let resp = client
        .post(format!("http://127.0.0.1:{port}/api/quotas/alice/reset"))
        .header("Authorization", "Bearer quota-test-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert_eq!(body["data"]["reset"], true);

    // Verify counters are zeroed
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/quotas/alice"))
        .header("Authorization", "Bearer quota-test-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let data = &body["data"];
    assert_eq!(data["daily_bytes"], 0);
    assert_eq!(data["daily_connections"], 0);
    assert_eq!(data["monthly_bytes"], 0);
    assert_eq!(data["monthly_connections"], 0);
}

// ---------------------------------------------------------------------------
// Test 5: Quota API requires auth
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_quota_api_requires_auth() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let (port, _qt) = start_api_with_quota(make_config(port, &hash)).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/quotas"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ---------------------------------------------------------------------------
// Test 6: Daily bandwidth quota enforcement blocks excess bytes
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_quota_daily_bandwidth_enforcement() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let (port, qt) = start_api_with_quota(make_config(port, &hash)).await;

    let quota = QuotaConfig {
        daily_bandwidth_bytes: 1000,
        ..Default::default()
    };

    // First batch: within quota
    match qt.record_bytes("alice", 800, 0, 0, Some(&quota)) {
        QuotaResult::Ok(_) => {}
        QuotaResult::Exceeded(r) => panic!("should not exceed: {r}"),
    }

    // Second batch: exceeds daily quota
    match qt.record_bytes("alice", 500, 0, 0, Some(&quota)) {
        QuotaResult::Exceeded(r) => assert!(r.contains("daily bandwidth"), "reason: {r}"),
        QuotaResult::Ok(_) => panic!("should have exceeded daily bandwidth"),
    }

    // Verify via API — record_bytes uses record-then-check, so both batches are counted
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/quotas/alice"))
        .header("Authorization", "Bearer quota-test-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"]["daily_bytes"], 1300); // both batches recorded, caller disconnects on Exceeded
}

// ---------------------------------------------------------------------------
// Test 7: Monthly connection quota enforcement
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_quota_monthly_connection_enforcement() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let (port, qt) = start_api_with_quota(make_config(port, &hash)).await;

    let quota = QuotaConfig {
        monthly_connection_limit: 3,
        ..Default::default()
    };

    qt.record_connection("alice", Some(&quota)).unwrap();
    qt.record_connection("alice", Some(&quota)).unwrap();
    qt.record_connection("alice", Some(&quota)).unwrap();

    // 4th connection should be rejected
    let err = qt.record_connection("alice", Some(&quota)).unwrap_err();
    assert!(err.contains("monthly connection quota"), "err: {err}");

    // Verify via API shows 3 connections
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/quotas/alice"))
        .header("Authorization", "Bearer quota-test-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"]["monthly_connections"], 3);
}

// ---------------------------------------------------------------------------
// Test 8: Multi-window rate limiting blocks excess connections
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_rate_limiting_per_second() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let (_port, qt) = start_api_with_quota(make_config(port, &hash)).await;

    let rate = RateLimitsConfig {
        connections_per_second: 2,
        connections_per_minute: 0,
        connections_per_hour: 0,
    };

    qt.record_connection("alice", None).unwrap();
    qt.record_connection("alice", None).unwrap();

    // 3rd should be rate-limited
    let config = make_config(0, &hash);
    let err = qt
        .check_connection_rate("alice", &rate, &config.limits)
        .unwrap_err();
    assert!(err.contains("per-second"), "err: {err}");
}

// ---------------------------------------------------------------------------
// Test 9: Multiple users tracked independently via API
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_quota_multiple_users_independent() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let (port, qt) = start_api_with_quota(make_config(port, &hash)).await;

    qt.record_connection("alice", None).unwrap();
    qt.record_connection("alice", None).unwrap();
    qt.record_connection("bob", None).unwrap();
    match qt.record_bytes("alice", 1000, 0, 0, None) {
        QuotaResult::Ok(_) => {}
        QuotaResult::Exceeded(r) => panic!("unexpected: {r}"),
    }
    match qt.record_bytes("bob", 2000, 0, 0, None) {
        QuotaResult::Ok(_) => {}
        QuotaResult::Exceeded(r) => panic!("unexpected: {r}"),
    }

    let client = reqwest::Client::new();

    // Check list endpoint
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/quotas"))
        .header("Authorization", "Bearer quota-test-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    let data = body["data"].as_array().unwrap();
    assert_eq!(data.len(), 2);

    // Check alice detail
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/quotas/alice"))
        .header("Authorization", "Bearer quota-test-token")
        .send()
        .await
        .unwrap();
    let alice: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(alice["data"]["daily_connections"], 2);
    assert_eq!(alice["data"]["daily_bytes"], 1000);

    // Check bob detail
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/quotas/bob"))
        .header("Authorization", "Bearer quota-test-token")
        .send()
        .await
        .unwrap();
    let bob: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(bob["data"]["daily_connections"], 1);
    assert_eq!(bob["data"]["daily_bytes"], 2000);
}

// ---------------------------------------------------------------------------
// Test 10: Prometheus metrics include quota data
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_prometheus_quota_metrics() {
    let port = free_port().await;
    let hash = hash_pass("pass");

    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
host_key_path = "/tmp/sks5-e2e-quota-metrics-key"

[metrics]
enabled = true
listen = "127.0.0.1:{port}"

[logging]
level = "debug"

[[users]]
username = "testuser"
password_hash = "{hash}"
"##
    );
    let config: sks5::config::types::AppConfig = toml::from_str(&toml_str).unwrap();

    let metrics = Arc::new(MetricsRegistry::new());
    let maintenance = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Record quota metrics
    metrics.record_quota_bandwidth("alice", "daily", 1024);
    metrics.record_quota_connection("alice", "daily");
    metrics.record_quota_exceeded("alice", "daily_bandwidth");

    let metrics_addr = config.metrics.listen.clone();
    let m = metrics.clone();
    let maint = maintenance.clone();
    let _task = tokio::spawn(async move {
        let _ = sks5::api::start_metrics_server(
            &metrics_addr,
            m,
            maint,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{port}/metrics"))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("sks5_quota_bandwidth_used_bytes"),
        "should have quota bandwidth metric"
    );
    assert!(
        body.contains("sks5_quota_connections_used"),
        "should have quota connections metric"
    );
    assert!(
        body.contains("sks5_quota_exceeded_total"),
        "should have quota exceeded metric"
    );
}
