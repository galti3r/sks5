use sks5::audit::AuditLogger;
use sks5::auth::password;
use sks5::auth::AuthService;
use sks5::config::types::AppConfig;
use sks5::context::AppContext;
use sks5::metrics::MetricsRegistry;
use sks5::proxy::ProxyEngine;
use sks5::quota::QuotaTracker;
use sks5::security::SecurityManager;
use sks5::ssh::handler::SshHandler;

use russh::keys::PrivateKey;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};

async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

fn make_ssh_config(ssh_port: u16, password_hash: &str) -> AppConfig {
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:{ssh_port}"
host_key_path = "/tmp/sks5-e2e-ssh-key"

[shell]
hostname = "e2e-test"

[limits]
max_connections = 100
max_auth_attempts = 5
connection_timeout = 5
idle_timeout = 5

[security]
ban_enabled = false

[logging]
level = "debug"

[[users]]
username = "testuser"
password_hash = "{password_hash}"
allow_shell = true
"##
    );
    toml::from_str(&toml_str).unwrap()
}

/// Test SSH server using russh::server::Server trait
struct TestSshServer {
    ctx: Arc<AppContext>,
}

impl russh::server::Server for TestSshServer {
    type Handler = SshHandler;

    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> SshHandler {
        let peer = peer_addr.unwrap_or_else(|| "0.0.0.0:0".parse().expect("valid fallback"));
        SshHandler::new(self.ctx.clone(), peer)
    }
}

/// Minimal russh client handler for testing
struct TestClientHandler;

impl russh::client::Handler for TestClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true) // Accept any server key for testing
    }
}

async fn start_ssh_server(config: AppConfig) -> (u16, tokio::task::JoinHandle<()>) {
    let ssh_addr = config.server.ssh_listen.clone();
    let port: u16 = ssh_addr.split(':').next_back().unwrap().parse().unwrap();
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
        userdata_store: None,
    });

    let key_pair =
        PrivateKey::random(&mut rand::rngs::OsRng, russh::keys::Algorithm::Ed25519).unwrap();
    let mut ssh_config = russh::server::Config::default();
    ssh_config.keys.push(key_pair);
    ssh_config.server_id = russh::SshId::Standard("SSH-2.0-sks5_e2e_test".to_string());
    ssh_config.auth_rejection_time = Duration::from_millis(100);
    ssh_config.auth_rejection_time_initial = Some(Duration::from_millis(0));
    let ssh_config = Arc::new(ssh_config);

    let task = tokio::spawn(async move {
        use russh::server::Server as _;
        let mut server = TestSshServer { ctx };
        let _ = server.run_on_address(ssh_config, &ssh_addr as &str).await;
    });

    // Wait for SSH server to start listening
    sleep(Duration::from_millis(200)).await;

    (port, task)
}

// ---------------------------------------------------------------------------
// Test 1: SSH password auth success
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_ssh_password_auth_success() {
    let port = free_port().await;
    let hash = password::hash_password("sshpass123").unwrap();
    let (_port, _server_task) = start_ssh_server(make_ssh_config(port, &hash)).await;

    let client_config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(
        client_config,
        format!("127.0.0.1:{}", port),
        TestClientHandler,
    )
    .await
    .unwrap();

    let authenticated = handle
        .authenticate_password("testuser", "sshpass123")
        .await
        .unwrap();

    assert!(authenticated.success(), "password auth should succeed");
}

// ---------------------------------------------------------------------------
// Test 2: SSH password auth failure
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_ssh_password_auth_failure() {
    let port = free_port().await;
    let hash = password::hash_password("correctpass").unwrap();
    let (_port, _server_task) = start_ssh_server(make_ssh_config(port, &hash)).await;

    let client_config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(
        client_config,
        format!("127.0.0.1:{}", port),
        TestClientHandler,
    )
    .await
    .unwrap();

    let authenticated = handle
        .authenticate_password("testuser", "wrongpass")
        .await
        .unwrap();

    assert!(!authenticated.success(), "wrong password should fail");
}

// ---------------------------------------------------------------------------
// Test 3: SSH shell session - open channel, receive prompt
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_ssh_shell_session() {
    let port = free_port().await;
    let hash = password::hash_password("shellpass").unwrap();
    let (_port, _server_task) = start_ssh_server(make_ssh_config(port, &hash)).await;

    let client_config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(
        client_config,
        format!("127.0.0.1:{}", port),
        TestClientHandler,
    )
    .await
    .unwrap();

    let authenticated = handle
        .authenticate_password("testuser", "shellpass")
        .await
        .unwrap();
    assert!(authenticated.success());

    // Open a session channel
    let channel = handle.channel_open_session().await.unwrap();
    let _channel_id = channel.id();

    // Request a shell
    channel.request_shell(true).await.unwrap();

    // Read data from the channel - should get a prompt
    let mut stream = channel.into_stream();
    let mut buf = vec![0u8; 1024];
    let read_result = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
    )
    .await;

    let n = read_result
        .expect("timeout waiting for shell prompt")
        .expect("read error on channel");
    assert!(n > 0, "channel closed without sending prompt");
    let output = String::from_utf8_lossy(&buf[..n]);
    // Should contain a prompt (e.g., "testuser@e2e-test:~$ ")
    assert!(
        output.contains("$") || output.contains("#") || output.contains("testuser"),
        "shell output should contain prompt, got: {}",
        output
    );
}
