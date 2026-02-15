#[allow(dead_code, unused_imports)]
mod helpers;

use helpers::*;
use std::sync::Arc;
use tokio::time::Duration;

/// Helper: exec a command and get the output
async fn exec_command(port: u16, password: &str, command: &str) -> String {
    let client_config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(
        client_config,
        format!("127.0.0.1:{}", port),
        TestClientHandler,
    )
    .await
    .unwrap();

    let ok = handle
        .authenticate_password("testuser", password)
        .await
        .unwrap();
    assert!(ok.success(), "auth should succeed");

    let channel = handle.channel_open_session().await.unwrap();
    channel.exec(true, command).await.unwrap();

    let mut stream = channel.into_stream();
    let mut buf = vec![0u8; 4096];
    let mut output = String::new();

    loop {
        match tokio::time::timeout(
            Duration::from_secs(3),
            tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
        )
        .await
        {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => output.push_str(&String::from_utf8_lossy(&buf[..n])),
            Ok(Err(_)) => break,
            Err(_) => break,
        }
    }

    output
}

// ---------------------------------------------------------------------------
// Test 1: SFTP subsystem rejected (server sends channel_failure)
// After requesting subsystem, the channel gets closed / no data flows
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_sftp_subsystem_rejected() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let client_config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(
        client_config,
        format!("127.0.0.1:{}", port),
        TestClientHandler,
    )
    .await
    .unwrap();

    let ok = handle
        .authenticate_password("testuser", "pass")
        .await
        .unwrap();
    assert!(ok.success());

    let channel = handle.channel_open_session().await.unwrap();

    // Request sftp subsystem - server sends channel_failure
    let _ = channel.request_subsystem(true, "sftp").await;

    // The subsystem was rejected - if we try to use the channel, it won't work.
    // Verify by trying to write and read - should get EOF/error.
    let mut stream = channel.into_stream();

    // Try to send SFTP init packet
    let _ =
        tokio::io::AsyncWriteExt::write_all(&mut stream, b"\x00\x00\x00\x05\x01\x00\x00\x00\x03")
            .await;

    let mut buf = vec![0u8; 1024];
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
    )
    .await;

    // Should get EOF or error (no valid SFTP response)
    if let Ok(Ok(n)) = result {
        // If we got data, it should not be a valid SFTP response
        // (server shell would say "command not found" or similar)
        let output = String::from_utf8_lossy(&buf[..n]);
        assert!(
            !output.contains("\x02"), // SSH_FXP_VERSION = 0x02
            "should not get valid SFTP response"
        );
    }
    // EOF, error, or timeout - all expected for rejected subsystem
}

// ---------------------------------------------------------------------------
// Test 2: Reverse forwarding (tcpip_forward) rejected
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_ssh_reverse_forward_rejected() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let client_config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(
        client_config,
        format!("127.0.0.1:{}", port),
        TestClientHandler,
    )
    .await
    .unwrap();

    let ok = handle
        .authenticate_password("testuser", "pass")
        .await
        .unwrap();
    assert!(ok.success());

    // Request reverse forwarding - should return false/fail
    let result = handle.tcpip_forward("127.0.0.1", 0).await;
    // tcpip_forward returns false -> client gets RequestFailure
    assert!(result.is_err(), "Reverse forwarding should be rejected");
}

// ---------------------------------------------------------------------------
// Test 3: exec safe commands only (whoami works)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_exec_safe_commands_only() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "whoami").await;
    assert!(
        output.contains("testuser"),
        "whoami should work, got: {}",
        output
    );
}

// ---------------------------------------------------------------------------
// Test 4: exec dangerous command rejected (bash)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_exec_dangerous_bash_rejected() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "bash -i").await;
    assert!(
        output.contains("command not found"),
        "bash should be blocked, got: {}",
        output
    );
}

// ---------------------------------------------------------------------------
// Test 5: exec dangerous command rejected (sh)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_exec_dangerous_sh_rejected() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "sh -c 'cat /etc/passwd'").await;
    assert!(
        output.contains("command not found"),
        "sh should be blocked, got: {}",
        output
    );
}

// ---------------------------------------------------------------------------
// Test 6: exec dangerous command rejected (nc/netcat)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_exec_dangerous_nc_rejected() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "nc -l 4444").await;
    assert!(
        output.contains("command not found"),
        "nc should be blocked, got: {}",
        output
    );
}

// ---------------------------------------------------------------------------
// Test 7: exec rsync command rejected (via virtual shell)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_exec_rsync_rejected() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "rsync --server --sender .").await;
    assert!(
        output.contains("command not found"),
        "rsync should be blocked, got: {}",
        output
    );
}

// ---------------------------------------------------------------------------
// Test 8: Injection via long username
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_long_username_rejected() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let long_user = "a".repeat(10000);

    let client_config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(
        client_config,
        format!("127.0.0.1:{}", port),
        TestClientHandler,
    )
    .await
    .unwrap();

    let ok = handle
        .authenticate_password(&long_user, "pass")
        .await
        .unwrap();
    assert!(!ok.success(), "long username should be rejected");
}
