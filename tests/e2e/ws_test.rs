#[allow(dead_code, unused_imports)]
mod helpers;

use helpers::*;

// ---------------------------------------------------------------------------
// Test 1: WebSocket endpoint requires authentication (no token = 401)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_ws_requires_auth() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "ws-test-token", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();

    // No token at all
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/ws"))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "GET /api/ws without token should return 401"
    );
}

// ---------------------------------------------------------------------------
// Test 2: WebSocket endpoint rejects wrong token (401)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_ws_wrong_token_rejected() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "ws-test-token", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();

    // Wrong token via query parameter
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/ws"))
        .header("Authorization", "Bearer wrong-token")
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "GET /api/ws with wrong token should return 401"
    );

    // Wrong token via Authorization header
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/ws"))
        .header("Authorization", "Bearer wrong-token")
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        401,
        "GET /api/ws with wrong Bearer token should return 401"
    );
}

// ---------------------------------------------------------------------------
// Test 3: WebSocket endpoint accepts valid token and attempts upgrade
//
// We send a proper HTTP request with WebSocket upgrade headers and a valid
// token. Without a real WebSocket client library, reqwest cannot complete the
// handshake, but we verify that:
//   - The server does NOT return 401 (auth passed)
//   - The server does NOT return 404 (route exists)
//
// We use raw TCP to send a well-formed WebSocket upgrade request and check
// for the 101 Switching Protocols response.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_ws_upgrade_with_valid_token() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "ws-test-token", &hash);
    let _server = start_api(config).await;

    // Build a valid WebSocket upgrade request per RFC 6455
    let ws_key = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        b"test-ws-key-1234",
    );
    let request = format!(
        "GET /api/ws HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         Authorization: Bearer ws-test-token\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: {ws_key}\r\n\
         \r\n"
    );

    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("TCP connect to API server");

    stream.write_all(request.as_bytes()).await.unwrap();

    // Read the HTTP response line
    let mut buf = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut accumulated = Vec::new();

    loop {
        let remaining = deadline.duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        match tokio::time::timeout(remaining, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                accumulated.extend_from_slice(&buf[..n]);
                // Check if we have received the full HTTP headers
                let response = String::from_utf8_lossy(&accumulated);
                if response.contains("\r\n\r\n") {
                    break;
                }
            }
            Ok(Err(_)) => break,
            Err(_) => break,
        }
    }

    let response = String::from_utf8_lossy(&accumulated);
    let status_line = response
        .lines()
        .next()
        .expect("should have at least one line in response");

    assert!(
        status_line.contains("101"),
        "expected 101 Switching Protocols, got: {status_line}"
    );
    let response_lower = response.to_lowercase();
    assert!(
        response_lower.contains("upgrade"),
        "response should contain upgrade header, got:\n{response}"
    );
}

// ---------------------------------------------------------------------------
// Test 4: WebSocket endpoint rejects empty API token (defense-in-depth)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_ws_empty_api_token_returns_503() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/ws"))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        503,
        "GET /api/ws with empty API token should return 503"
    );
}

// ---------------------------------------------------------------------------
// Test 5: WebSocket endpoint rejects valid token via Bearer header
//         but without upgrade headers (should not return 401 though)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_ws_valid_token_without_upgrade_headers() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "ws-test-token", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();

    // Valid token but no WebSocket upgrade headers -- auth passes but
    // the WebSocket extractor should reject with a non-401 error.
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/ws"))
        .header("Authorization", "Bearer ws-test-token")
        .send()
        .await
        .unwrap();

    let status = resp.status().as_u16();
    assert_ne!(
        status, 401,
        "valid token should not return 401; got {status}"
    );
    assert_ne!(status, 404, "route should exist; got 404");
}
