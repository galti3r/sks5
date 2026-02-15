#[allow(dead_code, unused_imports)]
mod helpers;

use helpers::*;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Duration;

// ---------------------------------------------------------------------------
// Test 1: ACL allow works for local forward to allowed target
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_acl_fqdn_allow_local_forward() {
    let ssh_port = free_port().await;
    let hash = hash_pass("pass");
    let (echo_port, _echo_task) = tcp_echo_server().await;

    // Allow only localhost:echo_port
    let config = acl_config(
        ssh_port,
        &hash,
        &[&format!("127.0.0.1:{}", echo_port)],
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

    // Forward to allowed target
    let channel = handle
        .channel_open_direct_tcpip("127.0.0.1", echo_port as u32, "127.0.0.1", 12345)
        .await
        .unwrap();

    let mut stream = channel.into_stream();
    stream.write_all(b"acl-allowed").await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("timeout")
        .expect("read error");

    assert_eq!(
        &buf[..n],
        b"acl-allowed",
        "echo should work through allowed ACL"
    );
}

// ---------------------------------------------------------------------------
// Test 2: ACL deny blocks forward to denied target
// Channel opens but relay fails (ACL checked post-connect) - no data echoed
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_acl_fqdn_deny_local_forward() {
    let ssh_port = free_port().await;
    let hash = hash_pass("pass");
    let (echo_port, _echo_task) = tcp_echo_server().await;

    // Deny localhost:echo_port, default allow
    let config = acl_config(
        ssh_port,
        &hash,
        &[],
        &[&format!("127.0.0.1:{}", echo_port)],
        "allow",
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

    // Channel opens but relay fails inside the spawned task
    let channel = handle
        .channel_open_direct_tcpip("127.0.0.1", echo_port as u32, "127.0.0.1", 12345)
        .await
        .unwrap();

    let mut stream = channel.into_stream();
    let _ = stream.write_all(b"test").await;

    // Should get EOF or error (relay denied by ACL)
    let mut buf = vec![0u8; 1024];
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
    match result {
        Ok(Ok(n)) if n > 0 => panic!("should not echo data when ACL denies, got {} bytes", n),
        _ => {} // EOF, error, or timeout — all expected
    }
}

// ---------------------------------------------------------------------------
// Test 3: ACL default deny blocks unlisted targets
// Channel opens but relay fails (default deny) - no data echoed
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_acl_fqdn_default_deny() {
    let ssh_port = free_port().await;
    let hash = hash_pass("pass");
    let (echo_port, _echo_task) = tcp_echo_server().await;

    // Allow only port 9999 (not our echo_port), default deny
    let config = acl_config(ssh_port, &hash, &["127.0.0.1:9999"], &[], "deny");
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

    // Channel opens but relay fails (default deny)
    let channel = handle
        .channel_open_direct_tcpip("127.0.0.1", echo_port as u32, "127.0.0.1", 12345)
        .await
        .unwrap();

    let mut stream = channel.into_stream();
    let _ = stream.write_all(b"test").await;

    let mut buf = vec![0u8; 1024];
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
    match result {
        Ok(Ok(n)) if n > 0 => panic!("should not echo data when default deny, got {} bytes", n),
        _ => {} // EOF, error, or timeout — all expected
    }
}

// ---------------------------------------------------------------------------
// Test 4: ACL wildcard port works
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_acl_wildcard_port() {
    let ssh_port = free_port().await;
    let hash = hash_pass("pass");
    let (echo_port, _echo_task) = tcp_echo_server().await;

    // Allow 127.0.0.1:* (any port)
    let config = acl_config(ssh_port, &hash, &["127.0.0.1:*"], &[], "deny");
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

    // Forward to echo_port - should work with wildcard
    let channel = handle
        .channel_open_direct_tcpip("127.0.0.1", echo_port as u32, "127.0.0.1", 12345)
        .await
        .unwrap();

    let mut stream = channel.into_stream();
    stream.write_all(b"wildcard").await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("timeout")
        .expect("read error");

    assert_eq!(&buf[..n], b"wildcard");
}
