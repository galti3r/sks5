#[allow(dead_code, unused_imports)]
mod helpers;

use helpers::*;
use std::sync::Arc;
use tokio::time::Duration;

// ---------------------------------------------------------------------------
// Test 1: SSH password auth success via russh client
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_ssh_password_auth_success() {
    let port = free_port().await;
    let hash = hash_pass("testpass");
    let server = start_ssh(ssh_config(port, &hash)).await;

    let client_config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(
        client_config,
        format!("127.0.0.1:{}", server.port),
        TestClientHandler,
    )
    .await
    .unwrap();

    let ok = handle
        .authenticate_password("testuser", "testpass")
        .await
        .unwrap();
    assert!(ok.success(), "password auth should succeed");
}

// ---------------------------------------------------------------------------
// Test 2: SSH password auth failure
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_ssh_password_auth_failure() {
    let port = free_port().await;
    let hash = hash_pass("correct");
    let server = start_ssh(ssh_config(port, &hash)).await;

    let client_config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(
        client_config,
        format!("127.0.0.1:{}", server.port),
        TestClientHandler,
    )
    .await
    .unwrap();

    let ok = handle
        .authenticate_password("testuser", "wrong")
        .await
        .unwrap();
    assert!(!ok.success(), "wrong password should fail");
}

// ---------------------------------------------------------------------------
// Test 3: SSH unknown user rejected
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_ssh_unknown_user_rejected() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let server = start_ssh(ssh_config(port, &hash)).await;

    let client_config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(
        client_config,
        format!("127.0.0.1:{}", server.port),
        TestClientHandler,
    )
    .await
    .unwrap();

    let ok = handle
        .authenticate_password("nonexistent", "pass")
        .await
        .unwrap();
    assert!(!ok.success(), "unknown user should be rejected");
}

// ---------------------------------------------------------------------------
// Test 4: Open shell session and receive prompt
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_ssh_shell_session_prompt() {
    let port = free_port().await;
    let hash = hash_pass("shellpass");
    let server = start_ssh(ssh_config(port, &hash)).await;

    let client_config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(
        client_config,
        format!("127.0.0.1:{}", server.port),
        TestClientHandler,
    )
    .await
    .unwrap();

    let ok = handle
        .authenticate_password("testuser", "shellpass")
        .await
        .unwrap();
    assert!(ok.success());

    let channel = handle.channel_open_session().await.unwrap();
    channel.request_shell(true).await.unwrap();

    let mut stream = channel.into_stream();
    let mut buf = vec![0u8; 1024];
    let read_result = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
    )
    .await;

    let n = read_result.expect("timeout").expect("read error");
    assert!(n > 0, "should receive data");
    let mut output = String::from_utf8_lossy(&buf[..n]).to_string();

    // The shell sends MOTD + prompt across multiple packets, so keep reading
    // until we see the "$" prompt or timeout.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !output.contains("$") {
        match tokio::time::timeout_at(
            deadline,
            tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
        )
        .await
        {
            Ok(Ok(n2)) if n2 > 0 => {
                output.push_str(&String::from_utf8_lossy(&buf[..n2]));
            }
            _ => break,
        }
    }

    assert!(
        output.contains("testuser") && output.contains("$"),
        "prompt should contain username and $, got: {}",
        output
    );
}

// ---------------------------------------------------------------------------
// Test 5: Multiple auth attempts with wrong then right password
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_ssh_auth_retry_then_success() {
    let port = free_port().await;
    let hash = hash_pass("correct");
    let server = start_ssh(ssh_config(port, &hash)).await;

    let client_config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(
        client_config,
        format!("127.0.0.1:{}", server.port),
        TestClientHandler,
    )
    .await
    .unwrap();

    // First attempt: wrong password
    let ok = handle
        .authenticate_password("testuser", "wrong")
        .await
        .unwrap();
    assert!(!ok.success());

    // Second attempt: correct password
    let ok = handle
        .authenticate_password("testuser", "correct")
        .await
        .unwrap();
    assert!(
        ok.success(),
        "correct password should succeed after a failure"
    );
}
