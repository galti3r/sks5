//! E2E tests for audit improvements:
//! - Phase 1.1: Empty API token → 503
//! - Phase 1.3: Body > 64KB → 413
//! - Phase 4.3: /livez liveness probe (unauthenticated)
//! - Phase 4.4: /api/health enriched JSON
//! - Phase 3.1: API envelope consistency

#[allow(dead_code, unused_imports)]
mod helpers;

use helpers::*;

// ---------------------------------------------------------------------------
// 1.1: Empty API token → 503 (defense-in-depth)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn empty_api_token_returns_503() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();

    // All endpoints behind auth should return 503
    for path in &["/api/users", "/api/bans", "/api/connections", "/api/health"] {
        let resp = client
            .get(format!("http://127.0.0.1:{port}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            503,
            "expected 503 for {path} with empty token, got {}",
            resp.status()
        );
    }
}

// ---------------------------------------------------------------------------
// 1.3: Body > 64KB → 413 (payload too large)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn body_over_64kb_returns_413() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "test-token", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();

    // 80KB body should be rejected
    let big_body = "x".repeat(80 * 1024);
    let resp = client
        .post(format!("http://127.0.0.1:{port}/api/broadcast"))
        .header("Authorization", "Bearer test-token")
        .header("Content-Type", "application/json")
        .body(big_body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        413,
        "expected 413 Payload Too Large, got {}",
        resp.status()
    );
}

// ---------------------------------------------------------------------------
// 4.3: /livez returns 200 without authentication
// ---------------------------------------------------------------------------
#[tokio::test]
async fn livez_returns_ok_without_auth() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "secret-token", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();

    // /livez should NOT require a token
    let resp = client
        .get(format!("http://127.0.0.1:{port}/livez"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
}

// ---------------------------------------------------------------------------
// 4.3: /livez on metrics server also works without auth
// ---------------------------------------------------------------------------
#[tokio::test]
async fn livez_on_metrics_server_returns_ok() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
host_key_path = "/tmp/sks5-e2e-livez-metrics-key"

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
    let (_port, _task) = start_metrics(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/livez"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
}

// ---------------------------------------------------------------------------
// 4.4: /api/health returns enriched JSON
// ---------------------------------------------------------------------------
#[tokio::test]
async fn api_health_returns_json_with_details() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "test-token", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/health"))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();

    // Response is wrapped in ApiResponse envelope
    assert_eq!(body["success"], true);
    let data = &body["data"];
    assert_eq!(data["status"], "ok");
    assert_eq!(data["maintenance"], false);
    assert!(
        data["active_connections"].is_number(),
        "active_connections must be a number"
    );
    assert!(
        data["uptime_secs"].is_number(),
        "uptime_secs must be a number"
    );
}

// ---------------------------------------------------------------------------
// 4.4: /api/health returns 503 in maintenance mode
// ---------------------------------------------------------------------------
#[tokio::test]
async fn api_health_returns_503_in_maintenance() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "test-token", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();

    // Enable maintenance
    client
        .post(format!("http://127.0.0.1:{port}/api/maintenance"))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .unwrap();

    // Health should now return 503 with maintenance status
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/health"))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 503);
    let body: serde_json::Value = resp.json().await.unwrap();
    let data = &body["data"];
    assert_eq!(data["status"], "maintenance");
    assert_eq!(data["maintenance"], true);
}

// ---------------------------------------------------------------------------
// 3.1: API envelope consistency - all data endpoints return envelope
// ---------------------------------------------------------------------------
#[tokio::test]
async fn api_envelope_consistency() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "test-token", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();

    // GET endpoints that must return {success: true, data: ...}
    let get_endpoints = vec!["/api/users", "/api/connections", "/api/bans"];

    for path in &get_endpoints {
        let resp = client
            .get(format!("http://127.0.0.1:{port}{path}"))
            .header("Authorization", "Bearer test-token")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "GET {path} should return 200");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body["success"], true,
            "GET {path} response should have success: true"
        );
        assert!(
            body.get("data").is_some(),
            "GET {path} response should contain data field"
        );
    }

    // POST /api/maintenance
    let resp = client
        .post(format!("http://127.0.0.1:{port}/api/maintenance"))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert!(body.get("data").is_some());
    assert!(body["data"].get("maintenance").is_some());
}

// ---------------------------------------------------------------------------
// 3.1: Error responses use envelope with success: false
// ---------------------------------------------------------------------------
#[tokio::test]
async fn api_error_envelope() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "test-token", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();

    // POST /api/broadcast with invalid JSON body → 422 (axum's deserialization error)
    let resp = client
        .post(format!("http://127.0.0.1:{port}/api/broadcast"))
        .header("Authorization", "Bearer test-token")
        .header("Content-Type", "application/json")
        .body("{invalid json}")
        .send()
        .await
        .unwrap();
    // axum returns 400 for invalid JSON bodies
    assert_eq!(
        resp.status(),
        400,
        "invalid JSON body should return 400, got {}",
        resp.status()
    );

    // GET /api/quotas/:username → 404 when quota_tracker is None (default test config)
    let resp = client
        .get(format!(
            "http://127.0.0.1:{port}/api/quotas/nonexistent_user"
        ))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], false);
    assert!(
        body["error"].is_string(),
        "error should be a string message, got: {body}"
    );
}
