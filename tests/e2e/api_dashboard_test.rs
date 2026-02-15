#[allow(dead_code, unused_imports)]
mod helpers;

use helpers::*;

// ---------------------------------------------------------------------------
// Test 1: API health endpoint (returns JSON with status details)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_api_health() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "test-token", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/health", port))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    let data = &body["data"];
    assert_eq!(data["status"], "ok");
    assert_eq!(data["maintenance"], false);
    assert!(data["active_connections"].as_u64().is_some());
    assert!(data["uptime_secs"].as_u64().is_some());
}

// ---------------------------------------------------------------------------
// Test 2: API users list (wrapped in ApiResponse envelope)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_api_users_list() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "test-token", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/users", port))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    let users = body["data"].as_array().unwrap();
    assert!(!users.is_empty(), "should have at least one user");
    assert_eq!(users[0]["username"], "testuser");
    // Ensure password hash is NOT exposed
    assert!(
        users[0].get("password_hash").is_none(),
        "password_hash should not be in response"
    );
}

// ---------------------------------------------------------------------------
// Test 3: API connections (wrapped in ApiResponse envelope)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_api_connections() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "test-token", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/connections", port))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert_eq!(body["data"]["active_connections"], 0);
}

// ---------------------------------------------------------------------------
// Test 4: API bans list (wrapped in ApiResponse envelope)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_api_bans_list() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "test-token", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/bans", port))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    let bans = body["data"].as_array().unwrap();
    assert!(bans.is_empty(), "should have no bans initially");
}

// ---------------------------------------------------------------------------
// Test 5: API maintenance toggle (wrapped in ApiResponse envelope)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_api_maintenance_toggle() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "test-token", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();

    // Toggle on
    let resp = client
        .post(format!("http://127.0.0.1:{}/api/maintenance", port))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert_eq!(body["data"]["maintenance"], true);

    // Toggle off
    let resp = client
        .post(format!("http://127.0.0.1:{}/api/maintenance", port))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert_eq!(body["data"]["maintenance"], false);
}

// ---------------------------------------------------------------------------
// Test 6: API auth required (no token = 401)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_api_auth_required() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "secret-token", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();

    // No auth header
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/users", port))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Wrong token
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/users", port))
        .header("Authorization", "Bearer wrong-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ---------------------------------------------------------------------------
// Test 7: API status endpoint
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_api_status() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "test-token", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/status", port))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    let data = &body["data"];
    assert_eq!(data["status"], "ok");
    assert!(data["uptime_secs"].as_u64().is_some());
    assert_eq!(data["active_connections"], 0);
    assert!(data["total_users"].as_u64().unwrap() >= 1);
    assert_eq!(data["maintenance"], false);
}

// ---------------------------------------------------------------------------
// Test 8: API bans delete (non-existent IP = 404)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_api_bans_delete_not_found() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "test-token", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .delete(format!("http://127.0.0.1:{}/api/bans/1.2.3.4", port))
        .header("Authorization", "Bearer test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

// ---------------------------------------------------------------------------
// Test 9: Dashboard returns HTML
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_dashboard_returns_html() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "test-token", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/dashboard"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let content_type = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        content_type.contains("text/html"),
        "expected text/html, got {content_type}"
    );
    let body = resp.text().await.unwrap();
    assert!(body.contains("sks5 Dashboard"));
    assert!(body.contains("<script>"));
}

// ---------------------------------------------------------------------------
// Test 10: SSE endpoint requires token
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_sse_events_requires_token() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "sse-token", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/events"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

// ---------------------------------------------------------------------------
// Test 11: SSE endpoint returns event stream with valid token
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_sse_events_returns_stream() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "sse-token", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/events"))
        .header("Authorization", "Bearer sse-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let content_type = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        content_type.contains("text/event-stream"),
        "expected text/event-stream, got {content_type}"
    );
}

// ---------------------------------------------------------------------------
// Test 12: Empty API token returns 503 (defense-in-depth)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_empty_api_token_returns_503() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/events"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 503);
}
