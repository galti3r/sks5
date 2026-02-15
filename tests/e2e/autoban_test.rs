use sks5::audit::AuditLogger;
use sks5::auth::password;
use sks5::auth::AuthService;
use sks5::config::types::AppConfig;
use sks5::context::AppContext;
use sks5::metrics::MetricsRegistry;
use sks5::proxy::ProxyEngine;
use sks5::quota::QuotaTracker;
use sks5::security::SecurityManager;
use sks5::socks::protocol;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};

async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

fn make_ban_config(socks_port: u16, password_hash: &str, threshold: u32) -> AppConfig {
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
socks5_listen = "127.0.0.1:{socks_port}"
host_key_path = "/tmp/sks5-e2e-ban-key"

[limits]
max_connections = 100
connection_timeout = 5

[security]
ban_enabled = true
ban_threshold = {threshold}
ban_window = 300
ban_duration = 300

[logging]
level = "debug"

[[users]]
username = "alice"
password_hash = "{password_hash}"
allow_forwarding = true
allow_shell = true
"##
    );
    toml::from_str(&toml_str).unwrap()
}

struct TestServer {
    _task: tokio::task::JoinHandle<()>,
    port: u16,
}

async fn start_socks5(config: AppConfig) -> TestServer {
    let socks_addr = config.server.socks5_listen.clone().unwrap();
    let port: u16 = socks_addr.split(':').next_back().unwrap().parse().unwrap();
    let config = Arc::new(config);
    let audit = Arc::new(AuditLogger::new(None, 0, 0, None));
    let ctx = Arc::new(AppContext {
        config: config.clone(),
        auth_service: Arc::new(RwLock::new(AuthService::new(&config).unwrap())),
        proxy_engine: Arc::new(ProxyEngine::new(config.clone(), audit.clone())),
        security: Arc::new(RwLock::new(SecurityManager::new(&config))),
        audit,
        metrics: Arc::new(MetricsRegistry::new()),
        quota_tracker: Arc::new(QuotaTracker::new(&config.limits)),
        webhook_dispatcher: None,
        alert_engine: None,
        start_time: std::time::Instant::now(),
    });

    let task = tokio::spawn(async move {
        let _ = sks5::socks::start_socks5_server(
            &socks_addr,
            ctx,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
    });

    sleep(Duration::from_millis(100)).await;
    TestServer { _task: task, port }
}

/// Do a full SOCKS5 auth attempt and return the auth result byte
async fn attempt_auth(port: u16, user: &str, pass: &str) -> u8 {
    let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    // Greeting
    client
        .write_all(&[0x05, 0x01, protocol::AUTH_PASSWORD])
        .await
        .unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();

    if resp[1] == protocol::AUTH_NO_ACCEPTABLE {
        // IP is banned - server sent NO_ACCEPTABLE instead of AUTH_PASSWORD
        return 0xFF; // sentinel for "banned"
    }

    assert_eq!(resp[1], protocol::AUTH_PASSWORD);

    // Credentials
    let mut buf = vec![0x01];
    buf.push(user.len() as u8);
    buf.extend_from_slice(user.as_bytes());
    buf.push(pass.len() as u8);
    buf.extend_from_slice(pass.as_bytes());
    client.write_all(&buf).await.unwrap();

    let mut auth_resp = [0u8; 2];
    client.read_exact(&mut auth_resp).await.unwrap();
    auth_resp[1]
}

// ---------------------------------------------------------------------------
// Test 1: Auto-ban triggers after ban_threshold failed auths
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_autoban_triggers_after_threshold() {
    let port = free_port().await;
    let hash = password::hash_password("correctpassword").unwrap();
    let server = start_socks5(make_ban_config(port, &hash, 3)).await;

    // 3 failed auth attempts (wrong password)
    for i in 0..3 {
        let result = attempt_auth(server.port, "alice", "wrong").await;
        assert_eq!(result, 0x01, "attempt {} should get AUTH_FAILURE", i + 1);
        // Small delay to ensure sequential processing
        sleep(Duration::from_millis(50)).await;
    }

    // 4th attempt: IP should be banned
    sleep(Duration::from_millis(100)).await;
    let result = attempt_auth(server.port, "alice", "wrong").await;
    assert_eq!(result, 0xFF, "4th attempt should be rejected (IP banned)");
}

// ---------------------------------------------------------------------------
// Test 2: Banned IP also rejected with correct password
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_banned_ip_rejected_even_with_correct_password() {
    let port = free_port().await;
    let hash = password::hash_password("mypassword").unwrap();
    let server = start_socks5(make_ban_config(port, &hash, 3)).await;

    // Trigger ban with 3 wrong attempts
    for _ in 0..3 {
        attempt_auth(server.port, "alice", "wrong").await;
        sleep(Duration::from_millis(50)).await;
    }

    sleep(Duration::from_millis(100)).await;

    // Even correct password should be rejected (IP is banned)
    let result = attempt_auth(server.port, "alice", "mypassword").await;
    assert_eq!(
        result, 0xFF,
        "banned IP rejected even with correct password"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Successful auth resets failure count (no ban after mixed results)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_successful_auth_does_not_trigger_ban() {
    let port = free_port().await;
    let hash = password::hash_password("correctpass").unwrap();
    // Threshold = 5
    let server = start_socks5(make_ban_config(port, &hash, 5)).await;

    // 2 failures
    for _ in 0..2 {
        let result = attempt_auth(server.port, "alice", "wrong").await;
        assert_eq!(result, 0x01);
        sleep(Duration::from_millis(50)).await;
    }

    // 1 success (doesn't reset, but we're below threshold)
    let result = attempt_auth(server.port, "alice", "correctpass").await;
    assert_eq!(result, 0x00, "correct password should succeed");
    sleep(Duration::from_millis(50)).await;

    // 2 more failures (total failures = 4, still below threshold of 5)
    for _ in 0..2 {
        let result = attempt_auth(server.port, "alice", "wrong").await;
        assert_eq!(result, 0x01);
        sleep(Duration::from_millis(50)).await;
    }

    // Should NOT be banned yet (4 failures < 5 threshold)
    let result = attempt_auth(server.port, "alice", "correctpass").await;
    assert_eq!(result, 0x00, "should still be able to auth (not banned)");
}
