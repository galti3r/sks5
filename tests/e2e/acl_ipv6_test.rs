#[allow(dead_code, unused_imports)]
mod helpers;

use helpers::*;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Duration;

// ---------------------------------------------------------------------------
// Test 1: ACL IPv6 loopback works with ip_guard disabled
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_acl_ipv6_loopback_forward() {
    // Start echo server on IPv6 loopback
    let listener = tokio::net::TcpListener::bind("[::1]:0").await;
    let listener = match listener {
        Ok(l) => l,
        Err(_) => {
            eprintln!("IPv6 not available, skipping test");
            return;
        }
    };
    let echo_port = listener.local_addr().unwrap().port();

    // Start echo server
    let _echo_task = tokio::spawn(async move {
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

    let ssh_port = free_port().await;
    let hash = hash_pass("pass");

    // Allow ::1:* (IPv6 loopback)
    let config = acl_config(
        ssh_port,
        &hash,
        &[&format!("[::1]:{}", echo_port)],
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
        .channel_open_direct_tcpip("::1", echo_port as u32, "127.0.0.1", 12345)
        .await
        .unwrap();

    let mut stream = channel.into_stream();
    stream.write_all(b"ipv6-test").await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("timeout")
        .expect("read error");

    assert_eq!(&buf[..n], b"ipv6-test");
}

// ---------------------------------------------------------------------------
// Test 2: ACL IPv6 subnet deny — channel opens but data is not forwarded
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_acl_ipv6_subnet_deny() {
    // Start an echo server on IPv6 loopback to prove data doesn't get through
    let listener = tokio::net::TcpListener::bind("[::1]:0").await;
    let listener = match listener {
        Ok(l) => l,
        Err(_) => {
            eprintln!("IPv6 not available, skipping test");
            return;
        }
    };
    let echo_port = listener.local_addr().unwrap().port();

    let _echo_task = tokio::spawn(async move {
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

    let ssh_port = free_port().await;
    let hash = hash_pass("pass");

    // Deny all of ::1/128
    let config = acl_config(ssh_port, &hash, &[], &["[::1]:*"], "allow");
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
        .channel_open_direct_tcpip("::1", echo_port as u32, "127.0.0.1", 12345)
        .await
        .unwrap();

    let mut stream = channel.into_stream();
    let _ = stream.write_all(b"ipv6-deny-test").await;

    // Data should NOT echo back — ACL denies the connection
    let mut buf = vec![0u8; 1024];
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
    match result {
        Ok(Ok(n)) if n > 0 => panic!("should not echo data when IPv6 denied, got {} bytes", n),
        _ => {} // EOF, error, or timeout — all expected
    }
}
