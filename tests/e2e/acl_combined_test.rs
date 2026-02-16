#[allow(dead_code, unused_imports)]
mod helpers;

use helpers::*;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Duration;

// ---------------------------------------------------------------------------
// Test 1: Combined allow FQDN + deny subnet: deny takes priority
// The ACL pre-check rejects the channel immediately because deny rules
// are evaluated before allow rules. The channel open fails.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_acl_deny_overrides_allow() {
    let ssh_port = free_port().await;
    let hash = hash_pass("pass");
    let (echo_port, _echo_task) = tcp_echo_server().await;

    // Allow 127.0.0.1:echo_port, but also deny 127.0.0.0/8:*
    // Deny should take priority (checked first in ACL pre-check)
    let config = acl_config(
        ssh_port,
        &hash,
        &[&format!("127.0.0.1:{}", echo_port)],
        &["127.0.0.0/8:*"],
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

    // Channel open should fail because ACL deny takes priority over allow
    let result = handle
        .channel_open_direct_tcpip("127.0.0.1", echo_port as u32, "127.0.0.1", 12345)
        .await;

    assert!(
        result.is_err(),
        "forwarding should be denied (deny overrides allow in ACL)"
    );
}

// ---------------------------------------------------------------------------
// Test 2: Combined allow FQDN + subnet - both work
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_acl_combined_allow_rules() {
    let ssh_port = free_port().await;
    let hash = hash_pass("pass");
    let (echo_port, _echo_task) = tcp_echo_server().await;

    // Allow both specific IP and subnet (both cover 127.0.0.1)
    let config = acl_config(
        ssh_port,
        &hash,
        &[&format!("127.0.0.1:{}", echo_port), "127.0.0.0/8:*"],
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

    let channel = handle
        .channel_open_direct_tcpip("127.0.0.1", echo_port as u32, "127.0.0.1", 12345)
        .await
        .unwrap();

    let mut stream = channel.into_stream();
    stream.write_all(b"combined").await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("timeout")
        .expect("read error");

    assert_eq!(&buf[..n], b"combined");
}

// ---------------------------------------------------------------------------
// Test 3: Default allow with no explicit rules
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_acl_default_allow_no_rules() {
    let ssh_port = free_port().await;
    let hash = hash_pass("pass");
    let (echo_port, _echo_task) = tcp_echo_server().await;

    // Default allow, no explicit rules
    let config = acl_config(ssh_port, &hash, &[], &[], "allow");
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
    stream.write_all(b"default-allow").await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("timeout")
        .expect("read error");

    assert_eq!(&buf[..n], b"default-allow");
}
