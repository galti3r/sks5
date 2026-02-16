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
use tokio::sync::RwLock;

fn make_config_with_hash(password_hash: &str) -> AppConfig {
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:2222"
host_key_path = "/tmp/sks5-test-host-key"

[limits]
connection_timeout = 2

[security]
ban_enabled = true
ban_threshold = 3
ban_window = 300
ban_duration = 600

[[users]]
username = "alice"
password_hash = "{password_hash}"
allow_forwarding = true
allow_shell = true
"##
    );
    toml::from_str(&toml_str).unwrap()
}

fn setup(app_config: AppConfig) -> Arc<AppContext> {
    let config = Arc::new(app_config);
    let audit = Arc::new(AuditLogger::new(None, 0, 0, None));
    Arc::new(AppContext {
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
    })
}

/// Helper: write a SOCKS5 greeting advertising password auth
async fn write_greeting_password(stream: &mut (impl AsyncWriteExt + Unpin)) {
    stream
        .write_all(&[0x05, 0x01, protocol::AUTH_PASSWORD])
        .await
        .unwrap();
}

/// Helper: write a SOCKS5 greeting with no acceptable methods
async fn write_greeting_no_auth(stream: &mut (impl AsyncWriteExt + Unpin)) {
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap(); // only AUTH_NONE
}

/// Helper: write RFC 1929 username/password subnegotiation
async fn write_credentials(
    stream: &mut (impl AsyncWriteExt + Unpin),
    username: &str,
    password: &str,
) {
    let mut buf = vec![0x01]; // subneg version
    buf.push(username.len() as u8);
    buf.extend_from_slice(username.as_bytes());
    buf.push(password.len() as u8);
    buf.extend_from_slice(password.as_bytes());
    stream.write_all(&buf).await.unwrap();
}

/// Helper: write a SOCKS5 CONNECT request to a domain
async fn write_connect_domain(stream: &mut (impl AsyncWriteExt + Unpin), domain: &str, port: u16) {
    let mut buf = vec![
        0x05, // VER
        0x01, // CMD = CONNECT
        0x00, // RSV
        0x03, // ATYP = DOMAIN
    ];
    buf.push(domain.len() as u8);
    buf.extend_from_slice(domain.as_bytes());
    buf.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&buf).await.unwrap();
}

// ---------------------------------------------------------------------------
// Test 1: Client offering only AUTH_NONE gets NO_ACCEPTABLE
// ---------------------------------------------------------------------------
#[tokio::test]
async fn no_password_method_rejected() {
    let hash = password::hash_password("testpass").unwrap();
    let ctx = setup(make_config_with_hash(&hash));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        sks5::socks::handler::handle_connection(stream, ctx).await
    });

    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();

    // Send greeting with only AUTH_NONE (no password)
    write_greeting_no_auth(&mut client).await;

    // Read server method selection
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[0], 0x05); // SOCKS version
    assert_eq!(resp[1], protocol::AUTH_NO_ACCEPTABLE);

    let result = server_handle.await.unwrap();
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Test 2: Wrong password gets auth failure
// ---------------------------------------------------------------------------
#[tokio::test]
async fn wrong_password_rejected() {
    let hash = password::hash_password("correctpass").unwrap();
    let ctx = setup(make_config_with_hash(&hash));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        sks5::socks::handler::handle_connection(stream, ctx).await
    });

    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();

    // Greeting with password auth
    write_greeting_password(&mut client).await;

    // Read method selection
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[1], protocol::AUTH_PASSWORD);

    // Send wrong credentials
    write_credentials(&mut client, "alice", "wrongpass").await;

    // Read auth result
    let mut auth_resp = [0u8; 2];
    client.read_exact(&mut auth_resp).await.unwrap();
    assert_eq!(auth_resp[0], 0x01); // subneg version
    assert_eq!(auth_resp[1], 0x01); // AUTH_FAILURE

    let result = server_handle.await.unwrap();
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Test 3: Correct password gets auth success
// ---------------------------------------------------------------------------
#[tokio::test]
async fn correct_password_accepted() {
    let hash = password::hash_password("mypassword").unwrap();
    let ctx = setup(make_config_with_hash(&hash));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        sks5::socks::handler::handle_connection(stream, ctx).await
    });

    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();

    // Greeting
    write_greeting_password(&mut client).await;

    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[1], protocol::AUTH_PASSWORD);

    // Send correct credentials
    write_credentials(&mut client, "alice", "mypassword").await;

    // Read auth result - should be success
    let mut auth_resp = [0u8; 2];
    client.read_exact(&mut auth_resp).await.unwrap();
    assert_eq!(auth_resp[0], 0x01); // subneg version
    assert_eq!(auth_resp[1], 0x00); // AUTH_SUCCESS

    // After auth success, send a CONNECT to an unreachable target
    // (will fail at connect phase, but auth succeeded)
    write_connect_domain(&mut client, "192.0.2.1", 12345).await;

    // Read reply - should be host unreachable (can't connect to TEST-NET)
    let mut reply_buf = [0u8; 10];
    let n = client.read(&mut reply_buf).await.unwrap();
    assert!(n >= 4);
    assert_eq!(reply_buf[0], 0x05); // SOCKS version
                                    // Reply code should indicate failure (host unreachable or general failure)
    assert_ne!(reply_buf[1], protocol::REPLY_SUCCESS);

    let _ = server_handle.await;
}

// ---------------------------------------------------------------------------
// Test 4: Nonexistent user gets auth failure
// ---------------------------------------------------------------------------
#[tokio::test]
async fn nonexistent_user_rejected() {
    let hash = password::hash_password("pass").unwrap();
    let ctx = setup(make_config_with_hash(&hash));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        sks5::socks::handler::handle_connection(stream, ctx).await
    });

    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();

    write_greeting_password(&mut client).await;

    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();

    // Send credentials for nonexistent user
    write_credentials(&mut client, "nobody", "pass").await;

    let mut auth_resp = [0u8; 2];
    client.read_exact(&mut auth_resp).await.unwrap();
    assert_eq!(auth_resp[1], 0x01); // AUTH_FAILURE

    let result = server_handle.await.unwrap();
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Test 6: Banned IP rejection after failed auth (ban_threshold = 1)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn banned_ip_rejected_after_threshold() {
    let hash = password::hash_password("correctpass").unwrap();

    // Config with ban_threshold = 1: a single auth failure triggers an immediate ban
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:2222"
host_key_path = "/tmp/sks5-test-host-key"

[limits]
connection_timeout = 2

[security]
ban_enabled = true
ban_threshold = 1
ban_window = 300
ban_duration = 600

[[users]]
username = "alice"
password_hash = "{hash}"
allow_forwarding = true
allow_shell = true
"##
    );
    let app_config: AppConfig = toml::from_str(&toml_str).unwrap();
    let ctx = setup(app_config);

    // --- Connection 1: wrong password to trigger the ban ---
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let ctx1 = ctx.clone();
    let server1 = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        sks5::socks::handler::handle_connection(stream, ctx1).await
    });

    let mut client1 = tokio::net::TcpStream::connect(addr).await.unwrap();
    write_greeting_password(&mut client1).await;

    let mut resp = [0u8; 2];
    client1.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[1], protocol::AUTH_PASSWORD);

    // Send wrong credentials to trigger ban
    write_credentials(&mut client1, "alice", "wrongpass").await;

    let mut auth_resp = [0u8; 2];
    client1.read_exact(&mut auth_resp).await.unwrap();
    assert_eq!(auth_resp[1], 0x01); // AUTH_FAILURE

    let result1 = server1.await.unwrap();
    assert!(result1.is_ok());

    // Drop client1 to close the connection cleanly
    drop(client1);

    // --- Connection 2: should be rejected early because IP is now banned ---
    let listener2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr2 = listener2.local_addr().unwrap();

    let ctx2 = ctx.clone();
    let server2 = tokio::spawn(async move {
        let (stream, _) = listener2.accept().await.unwrap();
        sks5::socks::handler::handle_connection(stream, ctx2).await
    });

    let mut client2 = tokio::net::TcpStream::connect(addr2).await.unwrap();

    // The banned-IP path in the handler reads the greeting, then sends AUTH_NO_ACCEPTABLE
    write_greeting_password(&mut client2).await;

    let mut resp2 = [0u8; 2];
    client2.read_exact(&mut resp2).await.unwrap();
    assert_eq!(resp2[0], 0x05); // SOCKS version
    assert_eq!(
        resp2[1],
        protocol::AUTH_NO_ACCEPTABLE,
        "banned IP should receive AUTH_NO_ACCEPTABLE"
    );

    let result2 = server2.await.unwrap();
    assert!(result2.is_ok());
}

// ---------------------------------------------------------------------------
// Test 7: Multiple auth methods in greeting - server selects AUTH_PASSWORD
// ---------------------------------------------------------------------------
#[tokio::test]
async fn multiple_auth_methods_selects_password() {
    let hash = password::hash_password("testpass").unwrap();
    let ctx = setup(make_config_with_hash(&hash));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        sks5::socks::handler::handle_connection(stream, ctx).await
    });

    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();

    // Send greeting with both AUTH_NONE (0x00) and AUTH_PASSWORD (0x02)
    client
        .write_all(&[0x05, 0x02, protocol::AUTH_NONE, protocol::AUTH_PASSWORD])
        .await
        .unwrap();

    // Server should select AUTH_PASSWORD because the handler requires it
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[0], 0x05, "SOCKS version");
    assert_eq!(
        resp[1],
        protocol::AUTH_PASSWORD,
        "server must select AUTH_PASSWORD when client offers [AUTH_NONE, AUTH_PASSWORD]"
    );

    // Complete the auth flow to confirm the selection works end-to-end
    write_credentials(&mut client, "alice", "testpass").await;

    let mut auth_resp = [0u8; 2];
    client.read_exact(&mut auth_resp).await.unwrap();
    assert_eq!(auth_resp[0], 0x01); // subneg version
    assert_eq!(auth_resp[1], 0x00); // AUTH_SUCCESS

    // After successful auth, send a CONNECT to an unreachable address
    // to let the server complete the handler cleanly
    write_connect_domain(&mut client, "192.0.2.1", 12345).await;

    let mut reply_buf = [0u8; 10];
    let n = client.read(&mut reply_buf).await.unwrap();
    assert!(n >= 4);
    assert_eq!(reply_buf[0], 0x05); // SOCKS version

    let _ = server_handle.await;
}

// ---------------------------------------------------------------------------
// Test 8: Large username/password (255 chars each) - protocol max
// ---------------------------------------------------------------------------
#[tokio::test]
async fn large_username_password_max_length() {
    // RFC 1929 uses a single byte for username/password length, so max is 255.
    let long_user = "a".repeat(255);
    let long_pass = "b".repeat(255);

    let hash = password::hash_password(&long_pass).unwrap();

    // Build config with the 255-char username
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:2222"
host_key_path = "/tmp/sks5-test-host-key"

[limits]
connection_timeout = 5

[security]
ban_enabled = false

[[users]]
username = "{long_user}"
password_hash = "{hash}"
allow_forwarding = true
allow_shell = true
"##
    );
    let app_config: AppConfig = toml::from_str(&toml_str).unwrap();
    let ctx = setup(app_config);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        sks5::socks::handler::handle_connection(stream, ctx).await
    });

    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();

    // Greeting
    write_greeting_password(&mut client).await;

    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[1], protocol::AUTH_PASSWORD);

    // Send max-length credentials (255 bytes each)
    write_credentials(&mut client, &long_user, &long_pass).await;

    // Should succeed with the matching credentials
    let mut auth_resp = [0u8; 2];
    client.read_exact(&mut auth_resp).await.unwrap();
    assert_eq!(auth_resp[0], 0x01, "subneg version");
    assert_eq!(
        auth_resp[1], 0x00,
        "AUTH_SUCCESS for max-length credentials"
    );

    // Send a CONNECT to let the handler exit cleanly
    write_connect_domain(&mut client, "192.0.2.1", 12345).await;

    let mut reply_buf = [0u8; 10];
    let n = client.read(&mut reply_buf).await.unwrap();
    assert!(n >= 4);
    assert_eq!(reply_buf[0], 0x05);

    let _ = server_handle.await;
}

// ---------------------------------------------------------------------------
// Test 9: Concurrent connections - two clients authenticate simultaneously
// ---------------------------------------------------------------------------
#[tokio::test]
async fn concurrent_connections_both_succeed() {
    let hash = password::hash_password("sharedpass").unwrap();
    let ctx = setup(make_config_with_hash(&hash));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Spawn two server handlers that accept two connections
    let ctx1 = ctx.clone();
    let ctx2 = ctx.clone();

    let server_handle = tokio::spawn(async move {
        let (stream1, _) = listener.accept().await.unwrap();
        let (stream2, _) = listener.accept().await.unwrap();

        let h1 = tokio::spawn(sks5::socks::handler::handle_connection(stream1, ctx1));
        let h2 = tokio::spawn(sks5::socks::handler::handle_connection(stream2, ctx2));

        let (r1, r2) = tokio::join!(h1, h2);
        (r1.unwrap(), r2.unwrap())
    });

    // Connect two clients concurrently
    let (client1, client2) = tokio::join!(
        tokio::net::TcpStream::connect(addr),
        tokio::net::TcpStream::connect(addr),
    );
    let client1 = client1.unwrap();
    let client2 = client2.unwrap();

    // Run both auth flows concurrently
    let auth_flow = |mut client: tokio::net::TcpStream| async move {
        // Greeting
        write_greeting_password(&mut client).await;

        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[1], protocol::AUTH_PASSWORD);

        // Auth
        write_credentials(&mut client, "alice", "sharedpass").await;

        let mut auth_resp = [0u8; 2];
        client.read_exact(&mut auth_resp).await.unwrap();
        assert_eq!(auth_resp[0], 0x01, "subneg version");
        assert_eq!(auth_resp[1], 0x00, "AUTH_SUCCESS");

        // Send CONNECT to unreachable host so the handler completes
        write_connect_domain(&mut client, "192.0.2.1", 12345).await;

        let mut reply_buf = [0u8; 10];
        let n = client.read(&mut reply_buf).await.unwrap();
        assert!(n >= 4);
        assert_eq!(reply_buf[0], 0x05);
        // Reply should be a failure (unreachable), not success
        assert_ne!(reply_buf[1], protocol::REPLY_SUCCESS);
    };

    let (r1, r2) = tokio::join!(auth_flow(client1), auth_flow(client2));

    // Both auth flows completed (unit type)
    let _ = (r1, r2);

    let (server_r1, server_r2) = server_handle.await.unwrap();
    // Both server handlers should complete without panic
    // (connect failures are ok, we only care about concurrent auth)
    let _ = (server_r1, server_r2);
}
