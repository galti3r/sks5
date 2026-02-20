#[allow(dead_code, unused_imports)]
mod helpers;

use helpers::*;
use sks5::socks::protocol;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Duration;

// ---------------------------------------------------------------------------
// Test 1: SOCKS5 standalone auth success
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_socks5_standalone_auth_success() {
    let port = free_port().await;
    let hash = hash_pass("secret");
    let server = start_socks5(socks_config(port, &hash)).await;

    let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port))
        .await
        .unwrap();

    let resp = socks5_greeting(&mut client).await;
    assert_eq!(resp[0], 0x05);
    assert_eq!(resp[1], protocol::AUTH_PASSWORD);

    let auth = socks5_auth(&mut client, "alice", "secret").await;
    assert_eq!(auth, 0x00, "auth should succeed");
}

// ---------------------------------------------------------------------------
// Test 2: SOCKS5 standalone auth failure
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_socks5_standalone_auth_failure() {
    let port = free_port().await;
    let hash = hash_pass("correct");
    let server = start_socks5(socks_config(port, &hash)).await;

    let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port))
        .await
        .unwrap();

    socks5_greeting(&mut client).await;
    let auth = socks5_auth(&mut client, "alice", "wrong").await;
    assert_eq!(auth, 0x01, "wrong password should fail");
}

// ---------------------------------------------------------------------------
// Test 3: SOCKS5 standalone forward through proxy
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_socks5_standalone_forward() {
    let socks_port = free_port().await;
    let hash = hash_pass("pass");
    let server = start_socks5(socks_config(socks_port, &hash)).await;

    // Start echo server
    let (echo_port, _echo_task) = tcp_echo_server().await;

    let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port))
        .await
        .unwrap();

    socks5_greeting(&mut client).await;
    let auth = socks5_auth(&mut client, "alice", "pass").await;
    assert_eq!(auth, 0x00);

    // CONNECT to echo server via SOCKS5
    let reply = socks5_connect_domain(&mut client, "127.0.0.1", echo_port).await;
    assert_eq!(
        reply,
        protocol::REPLY_SUCCESS,
        "CONNECT to echo server should succeed"
    );

    // Send data through SOCKS5 tunnel
    client.write_all(b"socks5-data").await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
        .await
        .expect("timeout")
        .expect("read error");

    assert_eq!(&buf[..n], b"socks5-data", "echo should work through SOCKS5");
}

// ---------------------------------------------------------------------------
// Test 4: SOCKS5 concurrent connections
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_socks5_concurrent_connections() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let server = start_socks5(socks_config(port, &hash)).await;

    let mut handles = vec![];
    for i in 0..10 {
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
// Test 5: SOCKS5 standalone SSRF blocked (ip_guard re-enabled)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_socks5_standalone_anti_ssrf() {
    let port = free_port().await;
    let hash = hash_pass("pass");

    // Create config with ip_guard ENABLED
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
socks5_listen = "127.0.0.1:{port}"
host_key_path = "/tmp/sks5-e2e-socks-ssrf-key"

[limits]
max_connections = 100
connection_timeout = 5

[security]
ban_enabled = false
ip_guard_enabled = true

[logging]
level = "debug"

[[users]]
username = "alice"
password_hash = "{hash}"
allow_shell = true
"##
    );
    let config: sks5::config::types::AppConfig = toml::from_str(&toml_str).unwrap();
    let server = start_socks5(config).await;

    let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port))
        .await
        .unwrap();

    socks5_greeting(&mut client).await;
    let auth = socks5_auth(&mut client, "alice", "pass").await;
    assert_eq!(auth, 0x00);

    // Try CONNECT to 169.254.169.254 (link-local/SSRF target)
    let mut buf = vec![0x05, 0x01, 0x00, 0x01]; // CONNECT IPv4
    buf.extend_from_slice(&[169, 254, 169, 254]); // IP
    buf.extend_from_slice(&80u16.to_be_bytes()); // port
    client.write_all(&buf).await.unwrap();

    let mut resp = [0u8; 10];
    let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut resp))
        .await
        .expect("timeout")
        .unwrap_or(0);

    if n >= 2 {
        assert_ne!(
            resp[1],
            protocol::REPLY_SUCCESS,
            "SSRF target should be blocked"
        );
    }
}
