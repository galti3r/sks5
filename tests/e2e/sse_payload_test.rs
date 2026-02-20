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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;

/// Build a config with groups for SSE payload tests.
fn sse_config_with_groups(
    api_port: u16,
    token: &str,
    hash: &str,
) -> sks5::config::types::AppConfig {
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
host_key_path = "/tmp/sks5-e2e-sse-payload-key"

[api]
enabled = true
listen = "127.0.0.1:{api_port}"
token = "{token}"

[security]
ban_enabled = false

[logging]
level = "debug"

[[users]]
username = "alice"
password_hash = "{hash}"
allow_shell = true
group = "team1"

[[users]]
username = "bob"
password_hash = "{hash}"
allow_shell = true
group = "team1"

[[users]]
username = "charlie"
password_hash = "{hash}"
allow_shell = true
group = "team2"
"##
    );
    toml::from_str(&toml_str).unwrap()
}

/// Start the API server with a QuotaTracker attached, returning port and tracker handle.
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
        kick_tokens: None,
    };

    let _task = tokio::spawn(async move {
        let _ = sks5::api::start_api_server(
            &api_addr,
            state,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    (port, quota_tracker)
}

/// Connect to the SSE endpoint via raw TCP, accumulate reads until we find
/// a `data: ` line, parse the JSON payload, and return it.
/// Panics if no valid SSE data line is received within the timeout.
async fn read_first_sse_event(port: u16, token: &str) -> serde_json::Value {
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("TCP connect to API server");

    let request = format!(
        "GET /api/events HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {}\r\nAccept: text/event-stream\r\n\r\n",
        port, token
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    // The SSE stream uses chunked transfer encoding. The first event arrives
    // after the 2-second interval, so we need to keep reading in a loop.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    let mut accumulated = Vec::new();
    let mut buf = vec![0u8; 32768];

    loop {
        let remaining = deadline.duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        match tokio::time::timeout(remaining, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => accumulated.extend_from_slice(&buf[..n]),
            Ok(Err(_)) => break, // read error
            Err(_) => break,     // timeout
        }

        // Check if we have a data line yet
        let response = String::from_utf8_lossy(&accumulated);
        if response.lines().any(|l| l.starts_with("data: ")) {
            break;
        }
    }

    let response = String::from_utf8_lossy(&accumulated);

    // Find the first "data: " line in the SSE stream.
    // With chunked encoding, the data line may be prefixed by a chunk-size
    // line (e.g. "1a3\r\ndata: {...}\r\n"). We search for a line that
    // contains "data: {" to handle both cases.
    let json_str = response
        .lines()
        .find_map(|line| line.find("data: {").map(|idx| &line[idx + 6..]))
        .unwrap_or_else(|| {
            panic!(
                "no SSE data line found in response (got {} bytes):\n{}",
                accumulated.len(),
                &response[..std::cmp::min(response.len(), 2000)]
            )
        });

    serde_json::from_str(json_str)
        .unwrap_or_else(|e| panic!("failed to parse SSE JSON payload: {}\nraw: {}", e, json_str))
}

// ---------------------------------------------------------------------------
// Test 1: SSE payload contains `groups` array with correct structure
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_sse_payload_contains_groups() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let token = "sse-groups-token";
    let config = sse_config_with_groups(port, token, &hash);
    let (port, _qt) = start_api_with_quota(config).await;

    let payload = read_first_sse_event(port, token).await;

    // Verify `groups` field exists and is an array
    assert!(
        payload.get("groups").is_some(),
        "SSE payload should contain 'groups' field"
    );
    let groups = payload["groups"].as_array().unwrap();

    // We configured team1 (alice, bob) and team2 (charlie)
    assert_eq!(groups.len(), 2, "should have 2 groups: team1 and team2");

    // Find team1 and team2
    let team1 = groups
        .iter()
        .find(|g| g["name"] == "team1")
        .expect("should have team1 group");
    let team2 = groups
        .iter()
        .find(|g| g["name"] == "team2")
        .expect("should have team2 group");

    // Verify group structure
    assert_eq!(team1["member_count"], 2, "team1 has alice and bob");
    assert_eq!(team2["member_count"], 1, "team2 has charlie");
    assert!(
        team1.get("active_connections").is_some(),
        "group should have active_connections"
    );
    assert!(
        team1.get("total_daily_bytes").is_some(),
        "group should have total_daily_bytes"
    );
    assert!(
        team1.get("total_monthly_bytes").is_some(),
        "group should have total_monthly_bytes"
    );
}

// ---------------------------------------------------------------------------
// Test 2: SSE payload contains `sessions` object with correct structure
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_sse_payload_contains_sessions() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let token = "sse-sessions-token";
    let config = sse_config_with_groups(port, token, &hash);
    let (port, _qt) = start_api_with_quota(config).await;

    let payload = read_first_sse_event(port, token).await;

    // Verify `sessions` field exists and is an object
    assert!(
        payload.get("sessions").is_some(),
        "SSE payload should contain 'sessions' field"
    );
    let sessions = &payload["sessions"];

    // Verify structure: total_active + sessions array
    assert!(
        sessions.get("total_active").is_some(),
        "sessions should have 'total_active' field"
    );
    assert_eq!(
        sessions["total_active"].as_u64().unwrap(),
        0,
        "should have 0 active sessions initially"
    );
    assert!(
        sessions.get("sessions").is_some(),
        "sessions should have 'sessions' array"
    );
    assert!(
        sessions["sessions"].is_array(),
        "'sessions.sessions' should be an array"
    );
    assert!(
        sessions["sessions"].as_array().unwrap().is_empty(),
        "sessions array should be empty initially"
    );
}

// ---------------------------------------------------------------------------
// Test 3: SSE quotas include `total_bytes` field after recording usage
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_sse_payload_quotas_have_total_bytes() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let token = "sse-quotas-token";
    let config = sse_config_with_groups(port, token, &hash);
    let (port, qt) = start_api_with_quota(config).await;

    // Record some usage so quota data appears in SSE
    qt.record_connection("alice", None).unwrap();
    match qt.record_bytes("alice", 4096, 0, 0, None) {
        QuotaResult::Ok(_) => {}
        QuotaResult::Exceeded(r) => panic!("unexpected quota exceeded: {}", r),
    }

    let payload = read_first_sse_event(port, token).await;

    // Verify `quotas` field exists and is an array
    assert!(
        payload.get("quotas").is_some(),
        "SSE payload should contain 'quotas' field"
    );
    let quotas = payload["quotas"].as_array().unwrap();
    assert!(
        !quotas.is_empty(),
        "quotas should have at least one entry after recording usage"
    );

    // Find alice's quota entry
    let alice_quota = quotas
        .iter()
        .find(|q| q["username"] == "alice")
        .expect("should have alice in quotas");

    // Verify total_bytes is present and correct
    assert!(
        alice_quota.get("total_bytes").is_some(),
        "quota should have 'total_bytes' field"
    );
    assert_eq!(
        alice_quota["total_bytes"].as_u64().unwrap(),
        4096,
        "total_bytes should be 4096"
    );

    // Verify other expected quota fields
    assert_eq!(alice_quota["daily_bytes"].as_u64().unwrap(), 4096);
    assert_eq!(alice_quota["daily_connections"].as_u64().unwrap(), 1);
    assert!(
        alice_quota.get("monthly_bytes").is_some(),
        "quota should have monthly_bytes"
    );
    assert!(
        alice_quota.get("current_rate_bps").is_some(),
        "quota should have current_rate_bps"
    );
}
