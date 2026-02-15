#[allow(dead_code, unused_imports)]
mod helpers;

use helpers::*;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Duration;

// ---------------------------------------------------------------------------
// Test 1: ACL subnet allow with CIDR notation
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_acl_subnet_allow() {
    let ssh_port = free_port().await;
    let hash = hash_pass("pass");
    let (echo_port, _echo_task) = tcp_echo_server().await;

    // Allow 127.0.0.0/8:* (covers 127.0.0.1)
    let config = acl_config(ssh_port, &hash, &["127.0.0.0/8:*"], &[], "deny");
    let _server = start_ssh(config).await;

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
    stream.write_all(b"subnet-ok").await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("timeout")
        .expect("read error");

    assert_eq!(&buf[..n], b"subnet-ok");
}

// ---------------------------------------------------------------------------
// Test 2: ACL subnet deny - channel opens but relay fails (no echo)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_acl_subnet_deny() {
    let ssh_port = free_port().await;
    let hash = hash_pass("pass");
    let (echo_port, _echo_task) = tcp_echo_server().await;

    // Deny 127.0.0.0/8:* (covers 127.0.0.1), default allow
    let config = acl_config(ssh_port, &hash, &[], &["127.0.0.0/8:*"], "allow");
    let _server = start_ssh(config).await;

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

    // Channel opens but relay fails inside the spawned task (CIDR deny)
    let channel = handle
        .channel_open_direct_tcpip("127.0.0.1", echo_port as u32, "127.0.0.1", 12345)
        .await
        .unwrap();

    let mut stream = channel.into_stream();
    let _ = stream.write_all(b"test").await;

    let mut buf = vec![0u8; 1024];
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
    match result {
        Ok(Ok(n)) if n > 0 => panic!("should not echo data when subnet denied, got {} bytes", n),
        _ => {} // EOF, error, or timeout — all expected
    }
}

// ---------------------------------------------------------------------------
// Test 3: ACL subnet with specific port
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_acl_subnet_specific_port() {
    let ssh_port = free_port().await;
    let hash = hash_pass("pass");
    let (echo_port, _echo_task) = tcp_echo_server().await;

    // Allow only specific port
    let config = acl_config(
        ssh_port,
        &hash,
        &[&format!("127.0.0.0/8:{}", echo_port)],
        &[],
        "deny",
    );
    let _server = start_ssh(config).await;

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

    // Allowed port
    let channel = handle
        .channel_open_direct_tcpip("127.0.0.1", echo_port as u32, "127.0.0.1", 12345)
        .await
        .unwrap();

    let mut stream = channel.into_stream();
    stream.write_all(b"port-ok").await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("timeout")
        .expect("read error");

    assert_eq!(&buf[..n], b"port-ok");
}
