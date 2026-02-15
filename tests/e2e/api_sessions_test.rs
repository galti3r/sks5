#[allow(dead_code, unused_imports)]
mod helpers;

use helpers::*;

use sks5::audit::AuditLogger;
use sks5::auth::AuthService;
use sks5::metrics::MetricsRegistry;
use sks5::proxy::ProxyEngine;
use sks5::security::SecurityManager;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Start the API server and return both the port and the ProxyEngine handle,
/// so tests can register sessions directly on the engine.
async fn start_api_with_engine(config: sks5::config::types::AppConfig) -> (u16, Arc<ProxyEngine>) {
    let api_addr = config.api.listen.clone();
    let port: u16 = api_addr.split(':').next_back().unwrap().parse().unwrap();
    let config = Arc::new(config);
    let audit = Arc::new(AuditLogger::new(None, 0, 0, None));
    let engine = Arc::new(ProxyEngine::new(config.clone(), audit.clone()));

    let state = sks5::api::AppState {
        auth_service: Arc::new(RwLock::new(AuthService::new(&config).unwrap())),
        proxy_engine: engine.clone(),
        security: Arc::new(RwLock::new(SecurityManager::new(&config))),
        metrics: Arc::new(MetricsRegistry::new()),
        api_token: config.api.token.clone(),
        maintenance: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        start_time: std::time::Instant::now(),
        config_path: None,
        audit: Some(audit),
        broadcast_tx: None,
        ssh_listen_addr: None,
        quota_tracker: None,
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
    (port, engine)
}

// ---------------------------------------------------------------------------
// Test 1: GET /api/sessions with no active sessions returns empty array
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_sessions_list_empty() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "test-token", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/sessions", port))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    let sessions = body["data"].as_array().unwrap();
    assert!(
        sessions.is_empty(),
        "expected empty sessions list, got {} entries",
        sessions.len()
    );
}

// ---------------------------------------------------------------------------
// Test 2: GET /api/sessions/:username with no activity returns empty array
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_sessions_user_empty() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "test-token", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/sessions/alice", port))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    let sessions = body["data"].as_array().unwrap();
    assert!(
        sessions.is_empty(),
        "expected empty sessions list for alice, got {} entries",
        sessions.len()
    );
}

// ---------------------------------------------------------------------------
// Test 3: GET /api/sessions without auth token returns 401
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_sessions_requires_auth() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "secret-token", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();

    // No auth header at all
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/sessions", port))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Wrong token
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/sessions", port))
        .header("Authorization", "Bearer wrong-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Per-user endpoint also requires auth
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/sessions/alice", port))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ---------------------------------------------------------------------------
// Test 4: Register a session on ProxyEngine, then GET /api/sessions returns
//         the session with all expected fields
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_sessions_list_with_registered_session() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "test-token", &hash);
    let (port, engine) = start_api_with_engine(config).await;

    // Register a session directly on the proxy engine
    let session = engine.register_session("alice", "example.com", 8080, "192.168.1.42", "socks5");
    let expected_id = session.session_id.clone();

    let client = reqwest::Client::new();

    // --- GET /api/sessions should return the registered session ---
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/sessions", port))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);

    let sessions = body["data"].as_array().unwrap();
    assert_eq!(sessions.len(), 1, "expected exactly 1 session");

    let s = &sessions[0];
    assert_eq!(s["session_id"], expected_id);
    assert_eq!(s["username"], "alice");
    assert_eq!(s["target_host"], "example.com");
    assert_eq!(s["target_port"], 8080);
    assert_eq!(s["source_ip"], "192.168.1.42");
    assert_eq!(s["protocol"], "socks5");
    assert!(
        s["started_at"].as_str().is_some(),
        "started_at should be a string"
    );
    assert!(
        s["bytes_up"].as_u64().is_some(),
        "bytes_up should be a number"
    );
    assert!(
        s["bytes_down"].as_u64().is_some(),
        "bytes_down should be a number"
    );
    assert!(
        s["duration_secs"].as_u64().is_some(),
        "duration_secs should be a number"
    );

    // Initially bytes should be zero
    assert_eq!(s["bytes_up"].as_u64().unwrap(), 0);
    assert_eq!(s["bytes_down"].as_u64().unwrap(), 0);

    // --- GET /api/sessions/alice should also return this session ---
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/sessions/alice", port))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    let user_sessions = body["data"].as_array().unwrap();
    assert_eq!(user_sessions.len(), 1);
    assert_eq!(user_sessions[0]["session_id"], expected_id);

    // --- GET /api/sessions/bob should return empty (different user) ---
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/sessions/bob", port))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    let bob_sessions = body["data"].as_array().unwrap();
    assert!(bob_sessions.is_empty(), "bob should have no sessions");

    // --- Unregister and confirm it disappears ---
    engine.unregister_session(&expected_id);

    let resp = client
        .get(format!("http://127.0.0.1:{}/api/sessions", port))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let sessions = body["data"].as_array().unwrap();
    assert!(
        sessions.is_empty(),
        "sessions should be empty after unregister"
    );
}
