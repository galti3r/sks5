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

fn make_socks_config(socks_port: u16, password_hash: &str, max_conns: u32) -> AppConfig {
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
socks5_listen = "127.0.0.1:{socks_port}"
host_key_path = "/tmp/sks5-e2e-socks-key"

[limits]
max_connections = {max_conns}
max_connections_per_user = {max_conns}
connection_timeout = 5
idle_timeout = 5

[security]
ban_enabled = false

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
        kick_tokens: std::sync::Arc::new(dashmap::DashMap::new()),
    });

    let task = tokio::spawn(async move {
        let _ = sks5::socks::start_socks5_server(
            &socks_addr,
            ctx,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
    });

    // Wait for server to bind and start accepting
    sleep(Duration::from_millis(100)).await;

    TestServer { _task: task, port }
}

/// Send SOCKS5 greeting with password auth method, read method selection
async fn socks5_greeting(stream: &mut tokio::net::TcpStream) -> [u8; 2] {
    stream
        .write_all(&[0x05, 0x01, protocol::AUTH_PASSWORD])
        .await
        .unwrap();
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.unwrap();
    resp
}

/// Send RFC 1929 credentials, read auth result
async fn socks5_auth(stream: &mut tokio::net::TcpStream, user: &str, pass: &str) -> u8 {
    let mut buf = vec![0x01];
    buf.push(user.len() as u8);
    buf.extend_from_slice(user.as_bytes());
    buf.push(pass.len() as u8);
    buf.extend_from_slice(pass.as_bytes());
    stream.write_all(&buf).await.unwrap();
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.unwrap();
    resp[1]
}

/// Send SOCKS5 CONNECT to IPv4, read reply code
async fn socks5_connect_ipv4(stream: &mut tokio::net::TcpStream, ip: [u8; 4], port: u16) -> u8 {
    let mut buf = vec![0x05, 0x01, 0x00, 0x01];
    buf.extend_from_slice(&ip);
    buf.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&buf).await.unwrap();
    let mut resp = [0u8; 10];
    let n = stream.read(&mut resp).await.unwrap();
    assert!(n >= 2, "expected at least 2 bytes reply, got {}", n);
    resp[1]
}

// ---------------------------------------------------------------------------
// Test 1: Full SOCKS5 handshake through the server accept loop
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_socks5_server_full_handshake() {
    let port = free_port().await;
    let hash = password::hash_password("secret123").unwrap();
    let server = start_socks5(make_socks_config(port, &hash, 100)).await;

    let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port))
        .await
        .unwrap();

    let resp = socks5_greeting(&mut client).await;
    assert_eq!(resp[0], 0x05);
    assert_eq!(resp[1], protocol::AUTH_PASSWORD);

    let auth_result = socks5_auth(&mut client, "alice", "secret123").await;
    assert_eq!(auth_result, 0x00, "auth should succeed");
}

// ---------------------------------------------------------------------------
// Test 2: Multiple clients connect concurrently through the accept loop
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_socks5_server_concurrent_clients() {
    let port = free_port().await;
    let hash = password::hash_password("pass").unwrap();
    let server = start_socks5(make_socks_config(port, &hash, 100)).await;

    let mut handles = vec![];
    for i in 0..5 {
        let p = server.port;
        let handle = tokio::spawn(async move {
            let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", p))
                .await
                .unwrap();
            let resp = socks5_greeting(&mut client).await;
            assert_eq!(resp[1], protocol::AUTH_PASSWORD, "client {} greeting", i);
            let auth = socks5_auth(&mut client, "alice", "pass").await;
            assert_eq!(auth, 0x00, "client {} auth", i);
        });
        handles.push(handle);
    }

    for h in handles {
        h.await.unwrap();
    }
}

// ---------------------------------------------------------------------------
// Test 3: Connection limit enforced via semaphore
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_socks5_server_connection_limit() {
    let port = free_port().await;
    let hash = password::hash_password("pass").unwrap();
    // max_connections = 3
    let server = start_socks5(make_socks_config(port, &hash, 3)).await;

    // Hold 3 connections open (greeting done, waiting for credentials)
    let mut held = vec![];
    for _ in 0..3 {
        let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port))
            .await
            .unwrap();
        socks5_greeting(&mut client).await;
        // Don't send credentials - handler is blocked, permit held
        held.push(client);
    }

    // Give server time to process all 3 connections
    sleep(Duration::from_millis(100)).await;

    // 4th connection should be dropped (semaphore exhausted)
    let result = tokio::time::timeout(Duration::from_secs(2), async {
        let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port))
            .await
            .unwrap();
        let mut buf = [0u8; 1];
        client.read(&mut buf).await.unwrap()
    })
    .await
    .unwrap();

    assert_eq!(result, 0, "4th connection should be dropped (EOF)");

    // Drop held connections, verify server accepts new ones
    drop(held);
    sleep(Duration::from_millis(200)).await;

    // Should now be able to connect again
    let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port))
        .await
        .unwrap();
    let resp = socks5_greeting(&mut client).await;
    assert_eq!(
        resp[1],
        protocol::AUTH_PASSWORD,
        "should accept after slots freed"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Wrong password via server accept loop
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_socks5_server_wrong_auth() {
    let port = free_port().await;
    let hash = password::hash_password("correct").unwrap();
    let server = start_socks5(make_socks_config(port, &hash, 100)).await;

    let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port))
        .await
        .unwrap();
    socks5_greeting(&mut client).await;
    let auth = socks5_auth(&mut client, "alice", "wrong").await;
    assert_eq!(auth, 0x01, "wrong password should fail");
}

// ---------------------------------------------------------------------------
// Test 5: Client offering only AUTH_NONE via server accept loop
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_socks5_server_no_password_method() {
    let port = free_port().await;
    let hash = password::hash_password("pass").unwrap();
    let server = start_socks5(make_socks_config(port, &hash, 100)).await;

    let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port))
        .await
        .unwrap();
    // Only advertise AUTH_NONE (0x00), not AUTH_PASSWORD
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[0], 0x05);
    assert_eq!(resp[1], protocol::AUTH_NO_ACCEPTABLE);
}

// ---------------------------------------------------------------------------
// Test 6: CONNECT to localhost blocked by anti-SSRF
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_socks5_server_connect_anti_ssrf() {
    let port = free_port().await;
    let hash = password::hash_password("pass").unwrap();
    let server = start_socks5(make_socks_config(port, &hash, 100)).await;

    let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port))
        .await
        .unwrap();
    socks5_greeting(&mut client).await;
    let auth = socks5_auth(&mut client, "alice", "pass").await;
    assert_eq!(auth, 0x00);

    // Try CONNECT to 127.0.0.1 - should be rejected by anti-SSRF
    let reply = socks5_connect_ipv4(&mut client, [127, 0, 0, 1], 80).await;
    assert_ne!(
        reply,
        protocol::REPLY_SUCCESS,
        "localhost should be blocked"
    );
}
