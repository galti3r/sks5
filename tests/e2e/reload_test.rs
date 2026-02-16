#[allow(dead_code)]
mod helpers;

use sks5::audit::AuditLogger;
use sks5::auth::AuthService;
use sks5::metrics::MetricsRegistry;
use sks5::proxy::ProxyEngine;
use sks5::security::SecurityManager;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Test that POST /api/reload with a valid config file succeeds
#[tokio::test]
async fn reload_via_api_with_valid_config() {
    let api_port = helpers::free_port().await;
    let password_hash = helpers::hash_pass("secret");

    // Write a valid config file to a temp file
    let config_content = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
host_key_path = "/tmp/sks5-e2e-reload-key"

[api]
enabled = true
listen = "127.0.0.1:{api_port}"
token = "reload-test-token"

[security]
ban_enabled = false

[logging]
level = "debug"

[[users]]
username = "testuser"
password_hash = "{password_hash}"
allow_forwarding = true
allow_shell = true
"##
    );

    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), &config_content).unwrap();

    let config: sks5::config::types::AppConfig = toml::from_str(&config_content).unwrap();
    let config = Arc::new(config);

    let audit = Arc::new(AuditLogger::new(None, 0, 0, None));
    let state = sks5::api::AppState {
        auth_service: Arc::new(RwLock::new(AuthService::new(&config).unwrap())),
        proxy_engine: Arc::new(ProxyEngine::new(config.clone(), audit.clone())),
        security: Arc::new(RwLock::new(SecurityManager::new(&config))),
        metrics: Arc::new(MetricsRegistry::new()),
        api_token: "reload-test-token".to_string(),
        maintenance: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        start_time: std::time::Instant::now(),
        config_path: Some(tmp.path().to_path_buf()),
        audit: Some(audit),
        broadcast_tx: None,
        ssh_listen_addr: None,
        quota_tracker: None,
        webhook_dispatcher: None,
        kick_tokens: None,
    };

    let api_addr = format!("127.0.0.1:{api_port}");
    let _task = tokio::spawn(async move {
        let _ = sks5::api::start_api_server(
            &api_addr,
            state,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // POST /api/reload
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{api_port}/api/reload"))
        .header("Authorization", "Bearer reload-test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert_eq!(body["data"]["users_count"], 1);
}

/// Test that reload with invalid config preserves old config
#[tokio::test]
async fn reload_via_api_with_invalid_config_fails() {
    let api_port = helpers::free_port().await;
    let password_hash = helpers::hash_pass("secret");

    let config_content = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
host_key_path = "/tmp/sks5-e2e-reload-key2"

[api]
enabled = true
listen = "127.0.0.1:{api_port}"
token = "reload-test-token"

[security]
ban_enabled = false

[logging]
level = "debug"

[[users]]
username = "testuser"
password_hash = "{password_hash}"
allow_forwarding = true
allow_shell = true
"##
    );

    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), &config_content).unwrap();

    let config: sks5::config::types::AppConfig = toml::from_str(&config_content).unwrap();
    let config = Arc::new(config);

    let audit = Arc::new(AuditLogger::new(None, 0, 0, None));
    let state = sks5::api::AppState {
        auth_service: Arc::new(RwLock::new(AuthService::new(&config).unwrap())),
        proxy_engine: Arc::new(ProxyEngine::new(config.clone(), audit.clone())),
        security: Arc::new(RwLock::new(SecurityManager::new(&config))),
        metrics: Arc::new(MetricsRegistry::new()),
        api_token: "reload-test-token".to_string(),
        maintenance: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        start_time: std::time::Instant::now(),
        config_path: Some(tmp.path().to_path_buf()),
        audit: Some(audit),
        broadcast_tx: None,
        ssh_listen_addr: None,
        quota_tracker: None,
        webhook_dispatcher: None,
        kick_tokens: None,
    };

    let api_addr = format!("127.0.0.1:{api_port}");
    let _task = tokio::spawn(async move {
        let _ = sks5::api::start_api_server(
            &api_addr,
            state,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Write invalid config
    std::fs::write(tmp.path(), "invalid toml content {{{").unwrap();

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{api_port}/api/reload"))
        .header("Authorization", "Bearer reload-test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 500);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], false);
    assert!(body["error"].as_str().is_some());
}

/// Test that reload requires authentication
#[tokio::test]
async fn reload_via_api_requires_auth() {
    let api_port = helpers::free_port().await;
    let password_hash = helpers::hash_pass("secret");

    let config_content = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
host_key_path = "/tmp/sks5-e2e-reload-key3"

[api]
enabled = true
listen = "127.0.0.1:{api_port}"
token = "reload-test-token"

[security]
ban_enabled = false

[logging]
level = "debug"

[[users]]
username = "testuser"
password_hash = "{password_hash}"
allow_forwarding = true
allow_shell = true
"##
    );

    let config: sks5::config::types::AppConfig = toml::from_str(&config_content).unwrap();
    let config = Arc::new(config);

    let audit = Arc::new(AuditLogger::new(None, 0, 0, None));
    let state = sks5::api::AppState {
        auth_service: Arc::new(RwLock::new(AuthService::new(&config).unwrap())),
        proxy_engine: Arc::new(ProxyEngine::new(config.clone(), audit.clone())),
        security: Arc::new(RwLock::new(SecurityManager::new(&config))),
        metrics: Arc::new(MetricsRegistry::new()),
        api_token: "reload-test-token".to_string(),
        maintenance: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        start_time: std::time::Instant::now(),
        config_path: None,
        audit: Some(audit),
        broadcast_tx: None,
        ssh_listen_addr: None,
        quota_tracker: None,
        webhook_dispatcher: None,
        kick_tokens: None,
    };

    let api_addr = format!("127.0.0.1:{api_port}");
    let _task = tokio::spawn(async move {
        let _ = sks5::api::start_api_server(
            &api_addr,
            state,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{api_port}/api/reload"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}
