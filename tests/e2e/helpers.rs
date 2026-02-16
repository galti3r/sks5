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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};

/// Get an OS-assigned free port
pub async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// Hash a password using Argon2
pub fn hash_pass(pw: &str) -> String {
    password::hash_password(pw).unwrap()
}

/// Holds references to a running sks5 SSH server
pub struct TestSshServer {
    pub port: u16,
    pub _task: tokio::task::JoinHandle<()>,
}

/// Holds references to a running sks5 SOCKS5 server
pub struct TestSocksServer {
    pub port: u16,
    pub _task: tokio::task::JoinHandle<()>,
}

/// Holds references to a running API server
pub struct TestApiServer {
    pub port: u16,
    pub _task: tokio::task::JoinHandle<()>,
}

/// Minimal russh client handler for testing
pub struct TestClientHandler;

impl russh::client::Handler for TestClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Test SSH server using russh::server::Server trait
struct InternalSshServer {
    ctx: Arc<AppContext>,
}

impl russh::server::Server for InternalSshServer {
    type Handler = SshHandler;

    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> SshHandler {
        let peer = peer_addr.unwrap_or_else(|| "0.0.0.0:0".parse().expect("valid fallback"));
        SshHandler::new(self.ctx.clone(), peer)
    }
}

/// Start an SSH server from a TOML config string (with dynamic port substitution)
pub async fn start_ssh(config: AppConfig) -> TestSshServer {
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
        let mut server = InternalSshServer { ctx };
        let _ = server.run_on_address(ssh_config, &ssh_addr as &str).await;
    });

    // Wait until the server is actually accepting TCP connections
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .is_ok()
        {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    TestSshServer { port, _task: task }
}

/// Start a SOCKS5 server from an AppConfig
pub async fn start_socks5(config: AppConfig) -> TestSocksServer {
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
    TestSocksServer { port, _task: task }
}

/// Holds references to API server internals for data injection in tests
pub struct TestApiServerWithState {
    pub port: u16,
    pub _task: tokio::task::JoinHandle<()>,
    pub proxy_engine: Arc<ProxyEngine>,
    pub quota_tracker: Arc<QuotaTracker>,
    pub security: Arc<RwLock<SecurityManager>>,
    pub audit: Arc<AuditLogger>,
}

/// Start the API server from an AppConfig (without quota tracker for backward compat).
/// Pre-binds the listener to eliminate TOCTOU port races in parallel tests.
pub async fn start_api(config: AppConfig) -> TestApiServer {
    let api_addr = config.api.listen.clone();
    let listener = TcpListener::bind(&api_addr).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = Arc::new(config);

    let audit = Arc::new(AuditLogger::new(None, 0, 0, None));
    let state = sks5::api::AppState {
        auth_service: Arc::new(RwLock::new(AuthService::new(&config).unwrap())),
        proxy_engine: Arc::new(ProxyEngine::new(config.clone(), audit)),
        security: Arc::new(RwLock::new(SecurityManager::new(&config))),
        metrics: Arc::new(MetricsRegistry::new()),
        api_token: config.api.token.clone(),
        maintenance: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        start_time: std::time::Instant::now(),
        config_path: None,
        audit: None,
        broadcast_tx: None,
        ssh_listen_addr: None,
        quota_tracker: None,
        webhook_dispatcher: None,
    };

    let task = tokio::spawn(async move {
        let _ = sks5::api::start_api_server_on_listener(
            listener,
            state,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
    });

    // Wait until the server is actually accepting connections
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .is_ok()
        {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    TestApiServer { port, _task: task }
}

/// Start the API server and return handles to internals for data injection.
/// Pre-binds the listener to eliminate TOCTOU port races in parallel tests.
pub async fn start_api_with_state(config: AppConfig) -> TestApiServerWithState {
    let api_addr = config.api.listen.clone();
    let listener = TcpListener::bind(&api_addr).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = Arc::new(config);

    let audit = Arc::new(AuditLogger::new(None, 0, 0, None));
    let proxy_engine = Arc::new(ProxyEngine::new(config.clone(), audit.clone()));
    let security = Arc::new(RwLock::new(SecurityManager::new(&config)));
    let quota_tracker = Arc::new(QuotaTracker::new(&config.limits));

    let state = sks5::api::AppState {
        auth_service: Arc::new(RwLock::new(AuthService::new(&config).unwrap())),
        proxy_engine: proxy_engine.clone(),
        security: security.clone(),
        metrics: Arc::new(MetricsRegistry::new()),
        api_token: config.api.token.clone(),
        maintenance: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        start_time: std::time::Instant::now(),
        config_path: None,
        audit: Some(audit.clone()),
        broadcast_tx: None,
        ssh_listen_addr: None,
        quota_tracker: Some(quota_tracker.clone()),
        webhook_dispatcher: None,
    };

    let task = tokio::spawn(async move {
        let _ = sks5::api::start_api_server_on_listener(
            listener,
            state,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
    });

    // Wait until the server is actually accepting connections
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .is_ok()
        {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    TestApiServerWithState {
        port,
        _task: task,
        proxy_engine,
        quota_tracker,
        security,
        audit,
    }
}

/// Start the metrics/health server
pub async fn start_metrics(config: AppConfig) -> (u16, tokio::task::JoinHandle<()>) {
    let metrics_addr = config.metrics.listen.clone();
    let port: u16 = metrics_addr
        .split(':')
        .next_back()
        .unwrap()
        .parse()
        .unwrap();

    let metrics = Arc::new(MetricsRegistry::new());
    let maintenance = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let m = metrics.clone();
    let maint = maintenance.clone();
    let task = tokio::spawn(async move {
        let _ = sks5::api::start_metrics_server(
            &metrics_addr,
            m,
            maint,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
    });

    sleep(Duration::from_millis(100)).await;
    (port, task)
}

/// Build a config for SSH tests
pub fn ssh_config(ssh_port: u16, password_hash: &str) -> AppConfig {
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:{ssh_port}"
host_key_path = "/tmp/sks5-e2e-ssh-key"

[shell]
hostname = "e2e-test"

[limits]
max_connections = 100
max_connections_per_user = 50
max_auth_attempts = 5
connection_timeout = 10
idle_timeout = 10

[security]
ban_enabled = false
ip_guard_enabled = false

[logging]
level = "debug"

[[users]]
username = "testuser"
password_hash = "{password_hash}"
allow_forwarding = true
allow_shell = true
"##
    );
    toml::from_str(&toml_str).unwrap()
}

/// Build a config for SSH tests with multiple users
pub fn ssh_config_multi_user(ssh_port: u16, user1_hash: &str, user2_hash: &str) -> AppConfig {
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:{ssh_port}"
host_key_path = "/tmp/sks5-e2e-ssh-key"

[shell]
hostname = "e2e-test"

[limits]
max_connections = 100
max_connections_per_user = 50
max_auth_attempts = 5
connection_timeout = 10
idle_timeout = 10

[security]
ban_enabled = false
ip_guard_enabled = false

[logging]
level = "debug"

[[users]]
username = "testuser"
password_hash = "{user1_hash}"
allow_forwarding = true
allow_shell = true

[[users]]
username = "nofwd"
password_hash = "{user2_hash}"
allow_shell = true

[users.acl]
default_policy = "deny"
allow = []
deny = []
inherit = false
"##
    );
    toml::from_str(&toml_str).unwrap()
}

/// Build a SOCKS5 test config
pub fn socks_config(socks_port: u16, password_hash: &str) -> AppConfig {
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
socks5_listen = "127.0.0.1:{socks_port}"
host_key_path = "/tmp/sks5-e2e-socks-key"

[limits]
max_connections = 100
max_connections_per_user = 50
connection_timeout = 10
idle_timeout = 10

[security]
ban_enabled = false
ip_guard_enabled = false

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

/// Build an API test config
pub fn api_config(api_port: u16, token: &str, password_hash: &str) -> AppConfig {
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
host_key_path = "/tmp/sks5-e2e-api-key"

[api]
enabled = true
listen = "127.0.0.1:{api_port}"
token = "{token}"

[security]
ban_enabled = false

[logging]
level = "debug"

[[users]]
username = "testuser"
password_hash = "{password_hash}"
allow_forwarding = true
allow_shell = true
"##
    );
    toml::from_str(&toml_str).unwrap()
}

/// Build an ACL test config
pub fn acl_config(
    ssh_port: u16,
    password_hash: &str,
    allow_rules: &[&str],
    deny_rules: &[&str],
    default_policy: &str,
) -> AppConfig {
    let allow_str = allow_rules
        .iter()
        .map(|r| format!("\"{}\"", r))
        .collect::<Vec<_>>()
        .join(", ");
    let deny_str = deny_rules
        .iter()
        .map(|r| format!("\"{}\"", r))
        .collect::<Vec<_>>()
        .join(", ");
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:{ssh_port}"
host_key_path = "/tmp/sks5-e2e-acl-key"

[shell]
hostname = "e2e-test"

[limits]
max_connections = 100
max_connections_per_user = 50
max_auth_attempts = 5
connection_timeout = 10
idle_timeout = 10

[security]
ban_enabled = false
ip_guard_enabled = false

[logging]
level = "debug"

[[users]]
username = "testuser"
password_hash = "{password_hash}"
allow_forwarding = true
allow_shell = true

[users.acl]
default_policy = "{default_policy}"
allow = [{allow_str}]
deny = [{deny_str}]
"##
    );
    toml::from_str(&toml_str).unwrap()
}

/// Start a TCP echo server that echoes back anything sent to it
pub async fn tcp_echo_server() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let task = tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    loop {
                        match socket.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if socket.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        }
    });

    (port, task)
}

/// SOCKS5 helpers for raw TCP protocol testing
pub async fn socks5_greeting(stream: &mut tokio::net::TcpStream) -> [u8; 2] {
    stream
        .write_all(&[0x05, 0x01, sks5::socks::protocol::AUTH_PASSWORD])
        .await
        .unwrap();
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.unwrap();
    resp
}

pub async fn socks5_auth(stream: &mut tokio::net::TcpStream, user: &str, pass: &str) -> u8 {
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

pub async fn socks5_connect_domain(
    stream: &mut tokio::net::TcpStream,
    host: &str,
    port: u16,
) -> u8 {
    let mut buf = vec![0x05, 0x01, 0x00, 0x03]; // CONNECT, DOMAIN
    buf.push(host.len() as u8);
    buf.extend_from_slice(host.as_bytes());
    buf.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&buf).await.unwrap();
    let mut resp = [0u8; 10];
    let n = stream.read(&mut resp).await.unwrap();
    if n < 2 {
        return 0xFF;
    }
    resp[1]
}
