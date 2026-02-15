#[allow(dead_code, unused_imports)]
mod helpers;

use helpers::*;
use sks5::audit::AuditLogger;
use sks5::auth::AuthService;
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
host_key_path = "/tmp/sks5-e2e-backup-restore-key"

[api]
enabled = true
listen = "127.0.0.1:{api_port}"
token = "backup-test-token"

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
// Test 1: Backup with no bans or quota data returns empty arrays
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_backup_empty_state() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let (port, _qt) = start_api_with_quota(make_config(port, &hash)).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/backup"))
        .header("Authorization", "Bearer backup-test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);

    let data = &body["data"];
    assert!(data["version"].is_string(), "version should be a string");
    assert!(
        data["timestamp"].is_string(),
        "timestamp should be a string"
    );
    let bans = data["bans"].as_array().unwrap();
    assert!(bans.is_empty(), "bans should be empty");
    let quotas = data["quotas"].as_object().unwrap();
    assert!(quotas.is_empty(), "quotas should be empty");
}

// ---------------------------------------------------------------------------
// Test 2: Backup includes quota data after recording bytes
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_backup_with_quota_data() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let (port, qt) = start_api_with_quota(make_config(port, &hash)).await;

    // Record some activity for alice
    qt.record_connection("alice", None).unwrap();
    match qt.record_bytes("alice", 5000, 0, 0, None) {
        QuotaResult::Ok(_) => {}
        QuotaResult::Exceeded(r) => panic!("unexpected: {r}"),
    }

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/backup"))
        .header("Authorization", "Bearer backup-test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);

    let data = &body["data"];
    let quotas = data["quotas"].as_object().unwrap();
    assert!(quotas.contains_key("alice"), "quotas should contain alice");

    let alice_quota = &quotas["alice"];
    assert_eq!(alice_quota["daily_bytes"], 5000);
    assert_eq!(alice_quota["daily_connections"], 1);
    assert_eq!(alice_quota["monthly_bytes"], 5000);
    assert_eq!(alice_quota["monthly_connections"], 1);
    assert_eq!(alice_quota["total_bytes"], 5000);
}

// ---------------------------------------------------------------------------
// Test 3: Backup, reset quotas, restore, verify data is back
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_backup_restore_roundtrip() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let (port, qt) = start_api_with_quota(make_config(port, &hash)).await;

    // Record some activity
    qt.record_connection("alice", None).unwrap();
    match qt.record_bytes("alice", 4096, 0, 0, None) {
        QuotaResult::Ok(_) => {}
        QuotaResult::Exceeded(r) => panic!("unexpected: {r}"),
    }

    let client = reqwest::Client::new();

    // Step 1: Backup
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/backup"))
        .header("Authorization", "Bearer backup-test-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let backup_body: serde_json::Value = resp.json().await.unwrap();
    let backup_data = backup_body["data"].clone();

    // Step 2: Reset alice's quotas
    qt.reset_user("alice");
    let usage = qt.get_user_usage("alice");
    assert_eq!(usage.daily_bytes, 0, "should be zero after reset");

    // Step 3: Restore from backup
    let resp = client
        .post(format!("http://127.0.0.1:{port}/api/restore"))
        .header("Authorization", "Bearer backup-test-token")
        .header("Content-Type", "application/json")
        .json(&backup_data)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let restore_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(restore_body["success"], true);
    assert_eq!(restore_body["data"]["restored_quotas"], 1);

    // Step 4: Verify via quota API that data is back
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/quotas/alice"))
        .header("Authorization", "Bearer backup-test-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let quota_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(quota_body["data"]["daily_bytes"], 4096);
    assert_eq!(quota_body["data"]["daily_connections"], 1);
    assert_eq!(quota_body["data"]["monthly_bytes"], 4096);
    assert_eq!(quota_body["data"]["monthly_connections"], 1);
    assert_eq!(quota_body["data"]["total_bytes"], 4096);
}

// ---------------------------------------------------------------------------
// Test 4: POST restore with fabricated quota data, verify via GET quota API
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_restore_quota_data() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let (port, _qt) = start_api_with_quota(make_config(port, &hash)).await;

    let client = reqwest::Client::new();

    // Fabricate a backup payload with quota data for "bob"
    let payload = serde_json::json!({
        "version": "0.1.0",
        "timestamp": "2026-01-01T00:00:00Z",
        "bans": [],
        "quotas": {
            "bob": {
                "daily_bytes": 10000,
                "daily_connections": 5,
                "monthly_bytes": 50000,
                "monthly_connections": 20,
                "total_bytes": 100000
            }
        }
    });

    // Restore the fabricated backup
    let resp = client
        .post(format!("http://127.0.0.1:{port}/api/restore"))
        .header("Authorization", "Bearer backup-test-token")
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert_eq!(body["data"]["restored_quotas"], 1);
    assert_eq!(body["data"]["restored_bans"], 0);

    // Verify via quota API that bob's data was restored
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/quotas/bob"))
        .header("Authorization", "Bearer backup-test-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let quota_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(quota_body["data"]["username"], "bob");
    assert_eq!(quota_body["data"]["daily_bytes"], 10000);
    assert_eq!(quota_body["data"]["daily_connections"], 5);
    assert_eq!(quota_body["data"]["monthly_bytes"], 50000);
    assert_eq!(quota_body["data"]["monthly_connections"], 20);
    assert_eq!(quota_body["data"]["total_bytes"], 100000);
}

// ---------------------------------------------------------------------------
// Test 5: Backup requires authentication
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_backup_requires_auth() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let (port, _qt) = start_api_with_quota(make_config(port, &hash)).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/backup"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ---------------------------------------------------------------------------
// Test 6: Restore requires authentication
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_restore_requires_auth() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let (port, _qt) = start_api_with_quota(make_config(port, &hash)).await;

    let payload = serde_json::json!({
        "version": "0.1.0",
        "timestamp": "2026-01-01T00:00:00Z",
        "bans": [],
        "quotas": {}
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{port}/api/restore"))
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}
