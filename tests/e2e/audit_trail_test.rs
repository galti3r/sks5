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
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};

async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

fn make_config(socks_port: u16, password_hash: &str) -> AppConfig {
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
socks5_listen = "127.0.0.1:{socks_port}"
host_key_path = "/tmp/sks5-e2e-audit-key"

[limits]
max_connections = 100
connection_timeout = 5

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

async fn start_socks5_with_audit(config: AppConfig, audit_path: std::path::PathBuf) -> TestServer {
    let socks_addr = config.server.socks5_listen.clone().unwrap();
    let port: u16 = socks_addr.split(':').next_back().unwrap().parse().unwrap();
    let config = Arc::new(config);
    let audit = Arc::new(AuditLogger::new(Some(audit_path), 0, 0, None));
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

// ---------------------------------------------------------------------------
// Test 1: Successful SOCKS5 auth generates audit.success event
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_socks5_auth_success_audit_event() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("audit.log");

    let port = free_port().await;
    let hash = password::hash_password("auditpass").unwrap();
    let server = start_socks5_with_audit(make_config(port, &hash), audit_path.clone()).await;

    // Successful auth
    let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port))
        .await
        .unwrap();

    client
        .write_all(&[0x05, 0x01, protocol::AUTH_PASSWORD])
        .await
        .unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();

    let mut buf = vec![0x01];
    buf.push(5); // username len
    buf.extend_from_slice(b"alice");
    buf.push(9); // password len
    buf.extend_from_slice(b"auditpass");
    client.write_all(&buf).await.unwrap();

    let mut auth_resp = [0u8; 2];
    client.read_exact(&mut auth_resp).await.unwrap();
    assert_eq!(auth_resp[1], 0x00, "auth should succeed");

    // Drop client and wait for audit to flush
    drop(client);
    sleep(Duration::from_millis(300)).await;

    // Verify audit log
    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert!(!lines.is_empty(), "audit log should have entries");

    // Find the auth.success event
    let success_line = lines
        .iter()
        .find(|l| l.contains("auth.success"))
        .expect("should have auth.success event");

    let parsed: serde_json::Value = serde_json::from_str(success_line).unwrap();
    assert_eq!(parsed["event_type"], "auth.success");
    assert_eq!(parsed["username"], "alice");
    assert_eq!(parsed["method"], "socks5");
    assert!(parsed["source_ip"].as_str().unwrap().contains("127.0.0.1"));
}

// ---------------------------------------------------------------------------
// Test 2: Failed SOCKS5 auth generates audit.failure event
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_socks5_auth_failure_audit_event() {
    let temp_dir = TempDir::new().unwrap();
    let audit_path = temp_dir.path().join("audit.log");

    let port = free_port().await;
    let hash = password::hash_password("correctpass").unwrap();
    let server = start_socks5_with_audit(make_config(port, &hash), audit_path.clone()).await;

    // Failed auth
    let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port))
        .await
        .unwrap();

    client
        .write_all(&[0x05, 0x01, protocol::AUTH_PASSWORD])
        .await
        .unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();

    let mut buf = vec![0x01];
    buf.push(5);
    buf.extend_from_slice(b"alice");
    buf.push(8);
    buf.extend_from_slice(b"wrongpwd");
    client.write_all(&buf).await.unwrap();

    let mut auth_resp = [0u8; 2];
    client.read_exact(&mut auth_resp).await.unwrap();
    assert_eq!(auth_resp[1], 0x01, "auth should fail");

    // Drop client and wait for audit to flush
    drop(client);
    sleep(Duration::from_millis(300)).await;

    // Verify audit log
    let content = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert!(!lines.is_empty(), "audit log should have entries");

    let failure_line = lines
        .iter()
        .find(|l| l.contains("auth.failure"))
        .expect("should have auth.failure event");

    let parsed: serde_json::Value = serde_json::from_str(failure_line).unwrap();
    assert_eq!(parsed["event_type"], "auth.failure");
    assert_eq!(parsed["username"], "alice");
    assert_eq!(parsed["method"], "socks5");
    assert!(parsed["source_ip"].as_str().unwrap().contains("127.0.0.1"));
}
