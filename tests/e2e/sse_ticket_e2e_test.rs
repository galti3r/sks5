#[allow(dead_code, unused_imports)]
mod helpers;
use helpers::{api_config, free_port, hash_pass, start_api};

// ---------------------------------------------------------------------------
// Test 1: SSE ticket endpoint returns ticket with Bearer auth
// ---------------------------------------------------------------------------
#[tokio::test]
async fn sse_ticket_endpoint_returns_ticket() {
    let api_port = free_port().await;
    let hash = hash_pass("pass");
    let token = "test-api-token";
    let config = api_config(api_port, token, &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{}/api/sse-ticket", api_port))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    let data = &body["data"];
    let ticket = data["ticket"].as_str().unwrap();
    assert!(!ticket.is_empty(), "ticket should not be empty");
    assert!(
        ticket.contains(':'),
        "ticket should contain timestamp:signature format"
    );
    assert!(
        data["expires_in"].as_u64().unwrap() > 0,
        "expires_in should be positive"
    );
}

// ---------------------------------------------------------------------------
// Test 2: SSE ticket endpoint requires auth (401 without Bearer)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn sse_ticket_endpoint_requires_auth() {
    let api_port = free_port().await;
    let hash = hash_pass("pass");
    let token = "secret-token";
    let config = api_config(api_port, token, &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();

    // No auth header at all
    let resp = client
        .post(format!("http://127.0.0.1:{}/api/sse-ticket", api_port))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "POST without auth should return 401");

    // Wrong token
    let resp = client
        .post(format!("http://127.0.0.1:{}/api/sse-ticket", api_port))
        .header("Authorization", "Bearer wrong-token")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "POST with wrong token should return 401"
    );
}

// ---------------------------------------------------------------------------
// Test 3: SSE ticket can authenticate SSE stream
// ---------------------------------------------------------------------------
#[tokio::test]
async fn sse_ticket_can_authenticate_sse() {
    let api_port = free_port().await;
    let hash = hash_pass("pass");
    let token = "sse-test-token";
    let config = api_config(api_port, token, &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();

    // Step 1: Get a ticket
    let resp = client
        .post(format!("http://127.0.0.1:{}/api/sse-ticket", api_port))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let ticket = body["data"]["ticket"].as_str().unwrap().to_string();

    // Step 2: Use the ticket to connect to SSE endpoint
    let resp = client
        .get(format!(
            "http://127.0.0.1:{}/api/events?ticket={}",
            api_port, ticket
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "SSE with valid ticket should return 200"
    );

    let content_type = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        content_type.contains("text/event-stream"),
        "expected text/event-stream, got {}",
        content_type
    );
}

// ---------------------------------------------------------------------------
// Test 4: Invalid/bogus ticket is rejected by SSE endpoint
// ---------------------------------------------------------------------------
#[tokio::test]
async fn sse_invalid_ticket_rejected() {
    let api_port = free_port().await;
    let hash = hash_pass("pass");
    let token = "sse-test-token";
    let config = api_config(api_port, token, &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();

    // Try with a completely bogus ticket
    let resp = client
        .get(format!(
            "http://127.0.0.1:{}/api/events?ticket=bogus",
            api_port
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "SSE with bogus ticket should return 401"
    );
}
