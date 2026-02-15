#[allow(dead_code, unused_imports)]
mod helpers;

use helpers::*;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Duration;

// ---------------------------------------------------------------------------
// Test 1: SSH local forwarding (direct-tcpip) works
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_ssh_local_forward_works() {
    let ssh_port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(ssh_port, &hash)).await;

    // Start a TCP echo server
    let (echo_port, _echo_task) = tcp_echo_server().await;

    let client_config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(
        client_config,
        format!("127.0.0.1:{}", ssh_port),
        TestClientHandler,
    )
    .await
    .unwrap();

    let ok = handle
        .authenticate_password("testuser", "pass")
        .await
        .unwrap();
    assert!(ok.success());

    // Open direct-tcpip channel (local forward)
    let channel = handle
        .channel_open_direct_tcpip("127.0.0.1", echo_port as u32, "127.0.0.1", 12345)
        .await
        .unwrap();

    let mut stream = channel.into_stream();

    // Send data through the tunnel
    let test_data = b"Hello through SSH tunnel!";
    stream.write_all(test_data).await.unwrap();

    // Read echo back
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("timeout reading echo")
        .expect("read error");

    assert_eq!(
        &buf[..n],
        test_data,
        "should receive echoed data through tunnel"
    );
}

// ---------------------------------------------------------------------------
// Test 2: SSH local forwarding transfers data correctly
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_ssh_local_forward_large_data() {
    let ssh_port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(ssh_port, &hash)).await;

    let (echo_port, _echo_task) = tcp_echo_server().await;

    let client_config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(
        client_config,
        format!("127.0.0.1:{}", ssh_port),
        TestClientHandler,
    )
    .await
    .unwrap();

    let ok = handle
        .authenticate_password("testuser", "pass")
        .await
        .unwrap();
    assert!(ok.success());

    let channel = handle
        .channel_open_direct_tcpip("127.0.0.1", echo_port as u32, "127.0.0.1", 12345)
        .await
        .unwrap();

    let mut stream = channel.into_stream();

    // Send larger data
    let test_data = vec![0x42u8; 8192];
    stream.write_all(&test_data).await.unwrap();

    // Read echo back
    let mut received = Vec::new();
    let mut buf = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while received.len() < test_data.len() {
        match tokio::time::timeout_at(deadline, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => received.extend_from_slice(&buf[..n]),
            Ok(Err(_)) => break,
            Err(_) => break,
        }
    }

    assert_eq!(received.len(), test_data.len(), "should echo all data back");
    assert_eq!(received, test_data);
}

// ---------------------------------------------------------------------------
// Test 3: Forwarding denied for user with allow_forwarding=false
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_forwarding_denied_user() {
    let ssh_port = free_port().await;
    let hash1 = hash_pass("pass1");
    let hash2 = hash_pass("pass2");
    let config = ssh_config_multi_user(ssh_port, &hash1, &hash2);
    let _server = start_ssh(config).await;

    let (echo_port, _echo_task) = tcp_echo_server().await;

    // Connect as "nofwd" user who has allow_forwarding=false
    let client_config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(
        client_config,
        format!("127.0.0.1:{}", ssh_port),
        TestClientHandler,
    )
    .await
    .unwrap();

    let ok = handle
        .authenticate_password("nofwd", "pass2")
        .await
        .unwrap();
    assert!(ok.success());

    // Try to open direct-tcpip - should fail
    let result = handle
        .channel_open_direct_tcpip("127.0.0.1", echo_port as u32, "127.0.0.1", 12345)
        .await;

    assert!(
        result.is_err(),
        "forwarding should be denied for nofwd user"
    );
}
