#[allow(dead_code, unused_imports)]
mod helpers;
use helpers::{free_port, hash_pass};

use sks5::config::types::AppConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ---------------------------------------------------------------------------
// Test 1: SOCKS5 handshake timeout closes slow client
// ---------------------------------------------------------------------------
#[tokio::test]
async fn socks5_handshake_timeout_closes_slow_client() {
    let socks_port = free_port().await;
    let hash = hash_pass("test");

    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
socks5_listen = "127.0.0.1:{socks_port}"

[limits]
max_connections = 100
max_connections_per_user = 50
connection_timeout = 10
idle_timeout = 10
socks5_handshake_timeout = 5

[security]
ban_enabled = false
ip_guard_enabled = false

[[users]]
username = "alice"
password_hash = "{hash}"
"##
    );
    let config: AppConfig = toml::from_str(&toml_str).unwrap();
    let _server = helpers::start_socks5(config).await;

    // Connect a TCP client and send the SOCKS5 greeting
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", socks_port))
        .await
        .unwrap();

    // Send greeting: version=5, 1 auth method, method=0x02 (username/password)
    stream.write_all(&[0x05, 0x01, 0x02]).await.unwrap();

    // Read method selection response
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[0], 0x05, "SOCKS5 version expected");

    // Now stall - don't send auth credentials. Server should timeout and close.
    let start = std::time::Instant::now();
    let mut buf = [0u8; 1];
    let result =
        tokio::time::timeout(std::time::Duration::from_secs(10), stream.read(&mut buf)).await;
    let elapsed = start.elapsed();

    // Connection should be closed by server within ~5s timeout (allow some margin)
    assert!(
        elapsed.as_secs() <= 8,
        "timeout took too long: {:?}",
        elapsed
    );
    match result {
        Ok(Ok(0)) => {}  // EOF = connection closed by server (expected)
        Ok(Err(_)) => {} // Connection reset (also acceptable)
        other => panic!("expected connection close, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Test 2: SOCKS5 handshake timeout config parses correctly
// ---------------------------------------------------------------------------
#[test]
fn socks5_handshake_timeout_config_parses() {
    let hash = hash_pass("test");

    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"

[limits]
max_connections = 100
max_connections_per_user = 50
connection_timeout = 10
idle_timeout = 10
socks5_handshake_timeout = 10

[security]
ban_enabled = false
ip_guard_enabled = false

[[users]]
username = "alice"
password_hash = "{hash}"
"##
    );
    let config: AppConfig = toml::from_str(&toml_str).unwrap();
    assert_eq!(
        config.limits.socks5_handshake_timeout, 10,
        "socks5_handshake_timeout should parse to 10"
    );
}
