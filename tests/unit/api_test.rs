use sks5::api::ApiResponse;
use sks5::metrics::MetricsRegistry;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

async fn setup_server() -> (u16, Arc<MetricsRegistry>, Arc<AtomicBool>) {
    let metrics = Arc::new(MetricsRegistry::new());
    let maintenance = Arc::new(AtomicBool::new(false));

    // Bind to a random available port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let m = metrics.clone();
    let maint = maintenance.clone();

    // Start server on the listener
    tokio::spawn(async move {
        let app = axum::Router::new()
            .route("/metrics", axum::routing::get(metrics_handler))
            .route("/health", axum::routing::get(health_handler))
            .with_state((m, maint));
        axum::serve(listener, app).await.unwrap();
    });

    // Give server a moment to start
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    (port, metrics, maintenance)
}

async fn metrics_handler(
    axum::extract::State((metrics, _)): axum::extract::State<(
        Arc<MetricsRegistry>,
        Arc<AtomicBool>,
    )>,
) -> impl axum::response::IntoResponse {
    let mut buffer = String::new();
    if prometheus_client::encoding::text::encode(&mut buffer, &metrics.registry).is_err() {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "encoding error".to_string(),
        );
    }
    (axum::http::StatusCode::OK, buffer)
}

async fn health_handler(
    axum::extract::State((_, maintenance)): axum::extract::State<(
        Arc<MetricsRegistry>,
        Arc<AtomicBool>,
    )>,
) -> impl axum::response::IntoResponse {
    if maintenance.load(Ordering::Relaxed) {
        (axum::http::StatusCode::SERVICE_UNAVAILABLE, "maintenance")
    } else {
        (axum::http::StatusCode::OK, "ok")
    }
}

#[tokio::test]
async fn test_health_ok() {
    let (port, _metrics, _maintenance) = setup_server().await;

    let resp = reqwest::get(&format!("http://127.0.0.1:{}/health", port))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
}

#[tokio::test]
async fn test_health_maintenance() {
    let (port, _metrics, maintenance) = setup_server().await;

    maintenance.store(true, Ordering::Relaxed);

    let resp = reqwest::get(&format!("http://127.0.0.1:{}/health", port))
        .await
        .unwrap();
    assert_eq!(resp.status(), 503);
    assert_eq!(resp.text().await.unwrap(), "maintenance");
}

#[tokio::test]
async fn test_metrics_prometheus_format() {
    let (port, metrics, _maintenance) = setup_server().await;

    // Record some metrics
    metrics.record_auth_success("testuser", "password");
    metrics.record_auth_failure("password");

    let resp = reqwest::get(&format!("http://127.0.0.1:{}/metrics", port))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body = resp.text().await.unwrap();
    // Should contain our registered metrics
    assert!(body.contains("sks5_auth_failures_total"));
    assert!(body.contains("sks5_auth_successes_total"));
}

// ---------------------------------------------------------------------------
// ApiResponse envelope tests
// ---------------------------------------------------------------------------

#[test]
fn api_response_ok_returns_200_with_success_true() {
    let (status, json) = ApiResponse::ok("hello");
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(json.0.success);
    assert!(json.0.data.is_some());
    assert!(json.0.error.is_none());

    // Verify serialization
    let serialized = serde_json::to_value(&json.0).unwrap();
    assert_eq!(serialized["success"], true);
    assert_eq!(serialized["data"], "hello");
}

#[test]
fn api_response_ok_with_status_200() {
    let (status, json) = ApiResponse::ok_with_status(axum::http::StatusCode::OK, 42);
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(json.0.success);

    let serialized = serde_json::to_value(&json.0).unwrap();
    assert_eq!(serialized["data"], 42);
}

#[test]
fn api_response_ok_with_status_503_sets_success_false() {
    let (status, json) =
        ApiResponse::ok_with_status(axum::http::StatusCode::SERVICE_UNAVAILABLE, "maintenance");
    assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
    assert!(!json.0.success, "503 should have success=false");

    let serialized = serde_json::to_value(&json.0).unwrap();
    assert_eq!(serialized["success"], false);
    assert_eq!(serialized["data"], "maintenance");
}

#[test]
fn api_response_err_returns_error_envelope() {
    let (status, json) = ApiResponse::<()>::err(axum::http::StatusCode::NOT_FOUND, "not found");
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    assert!(!json.0.success);
    assert!(json.0.data.is_none());

    let serialized = serde_json::to_value(&json.0).unwrap();
    assert_eq!(serialized["success"], false);
    assert_eq!(serialized["error"], "not found");
    assert!(
        serialized.get("data").is_none(),
        "data should be absent when None"
    );
}

#[test]
fn api_response_ok_with_status_201_sets_success_true() {
    let (status, json) = ApiResponse::ok_with_status(axum::http::StatusCode::CREATED, "created");
    assert_eq!(status, axum::http::StatusCode::CREATED);
    assert!(json.0.success, "201 is a success status");

    let serialized = serde_json::to_value(&json.0).unwrap();
    assert_eq!(serialized["success"], true);
    assert_eq!(serialized["data"], "created");
}

// ---------------------------------------------------------------------------
// is_truthy tests
// ---------------------------------------------------------------------------

#[test]
fn is_truthy_none_returns_false() {
    assert!(!sks5::api::is_truthy(None));
}

#[test]
fn is_truthy_true_returns_true() {
    assert!(sks5::api::is_truthy(Some("true")));
}

#[test]
fn is_truthy_one_returns_true() {
    assert!(sks5::api::is_truthy(Some("1")));
}

#[test]
fn is_truthy_yes_returns_true() {
    assert!(sks5::api::is_truthy(Some("yes")));
}

#[test]
fn is_truthy_false_returns_false() {
    assert!(!sks5::api::is_truthy(Some("false")));
}

#[test]
fn is_truthy_zero_returns_false() {
    assert!(!sks5::api::is_truthy(Some("0")));
}

#[test]
fn is_truthy_empty_returns_false() {
    assert!(!sks5::api::is_truthy(Some("")));
}

#[test]
fn is_truthy_no_returns_false() {
    assert!(!sks5::api::is_truthy(Some("no")));
}

#[test]
fn is_truthy_uppercase_true_returns_false() {
    // is_truthy is case-sensitive: "TRUE" is not recognized
    assert!(!sks5::api::is_truthy(Some("TRUE")));
}

// ---------------------------------------------------------------------------
// verify_sse_ticket replay protection
// ---------------------------------------------------------------------------

fn make_ticket(api_token: &str, timestamp: u64) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let nonce: u128 = rand::random();
    let signing_key = format!("sks5-sse-ticket:{}", api_token);
    let mut mac = Hmac::<Sha256>::new_from_slice(signing_key.as_bytes()).unwrap();
    mac.update(format!("{}:{}", timestamp, nonce).as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    format!("{}:{}:{}", timestamp, nonce, sig)
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn verify_sse_ticket_replay_protection() {
    let token = "replay-test-token";
    let ts = current_timestamp();
    let ticket = make_ticket(token, ts);

    // First use should succeed
    assert!(
        sks5::api::verify_sse_ticket(&ticket, token),
        "first verification should succeed"
    );

    // Second use of the same ticket should fail (replay protection)
    assert!(
        !sks5::api::verify_sse_ticket(&ticket, token),
        "second verification should fail (replay)"
    );
}

// ---------------------------------------------------------------------------
// Auth middleware tests
// ---------------------------------------------------------------------------

/// Build a minimal AppState for auth middleware tests.
fn build_test_app_state(api_token: &str) -> sks5::api::AppState {
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
host_key_path = "/tmp/sks5-unit-api-test-key"

[api]
enabled = true
listen = "127.0.0.1:0"
token = "{api_token}"

[security]
ban_enabled = false

[logging]
level = "error"

[[users]]
username = "testuser"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$+gVb4WOMEuMQxSgOBapKnZaHMIDjQJF3Tv7RCyKp9Bo"
allow_shell = true
"##
    );
    let config: sks5::config::types::AppConfig = toml::from_str(&toml_str).unwrap();
    let config = Arc::new(config);
    let audit = Arc::new(sks5::audit::AuditLogger::new(None, 0, 0, None));

    sks5::api::AppState {
        auth_service: Arc::new(tokio::sync::RwLock::new(
            sks5::auth::AuthService::new(&config).unwrap(),
        )),
        proxy_engine: Arc::new(sks5::proxy::ProxyEngine::new(config.clone(), audit)),
        security: Arc::new(tokio::sync::RwLock::new(
            sks5::security::SecurityManager::new(&config),
        )),
        metrics: Arc::new(MetricsRegistry::new()),
        api_token: api_token.to_string(),
        maintenance: Arc::new(AtomicBool::new(false)),
        start_time: std::time::Instant::now(),
        config_path: None,
        audit: None,
        broadcast_tx: None,
        ssh_listen_addr: None,
        quota_tracker: None,
        webhook_dispatcher: None,
        kick_tokens: None,
    }
}

/// Start the full API server on a random port and return the port.
/// Waits until the server is actually accepting connections.
async fn start_full_api_server(api_token: &str) -> (u16, tokio_util::sync::CancellationToken) {
    // Bind to get a free port, then drop the listener so start_api_server can use it.
    let port = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    };
    let addr = format!("127.0.0.1:{}", port);
    let cancel = tokio_util::sync::CancellationToken::new();
    let state = build_test_app_state(api_token);

    let cancel_clone = cancel.clone();
    let addr_clone = addr.clone();
    tokio::spawn(async move {
        let _ = sks5::api::start_api_server(&addr_clone, state, cancel_clone).await;
    });

    // Poll until the server is accepting connections (up to 2 seconds)
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if tokio::net::TcpStream::connect(&addr).await.is_ok() {
            return (port, cancel);
        }
    }
    panic!("API server did not start within 2 seconds on {}", addr);
}

#[tokio::test]
async fn auth_middleware_bearer_token_accepted() {
    let token = "test-bearer-accepted";
    let (port, _cancel) = start_full_api_server(token).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/status", port))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200, "correct Bearer token should return 200");
}

#[tokio::test]
async fn auth_middleware_wrong_bearer_token_rejected() {
    let token = "test-bearer-wrong";
    let (port, _cancel) = start_full_api_server(token).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/status", port))
        .header("Authorization", "Bearer wrong-token-value")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401, "wrong Bearer token should return 401");
}

#[tokio::test]
async fn auth_middleware_no_auth_header_rejected() {
    let token = "test-bearer-none";
    let (port, _cancel) = start_full_api_server(token).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/status", port))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401, "request without auth should return 401");
}

// ---------------------------------------------------------------------------
// Full API router: /readyz and /livez endpoints
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_api_readyz_returns_ready_json() {
    let token = "test-readyz-token";
    let (port, _cancel) = start_full_api_server(token).await;

    let resp = reqwest::get(&format!("http://127.0.0.1:{}/readyz", port))
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ready"], true, "/readyz should report ready=true");
    assert_eq!(body["checks"]["auth"], "ok");
    assert_eq!(body["checks"]["metrics"], "ok");
    assert_eq!(body["checks"]["maintenance"], "disabled");
}

#[tokio::test]
async fn full_api_livez_returns_ok() {
    let token = "test-livez-token";
    let (port, _cancel) = start_full_api_server(token).await;

    let resp = reqwest::get(&format!("http://127.0.0.1:{}/livez", port))
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
}
