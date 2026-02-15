#![allow(deprecated)] // Command::cargo_bin is deprecated in assert_cmd 2.x but still functional

use assert_cmd::Command;
use std::io::Write;
use tempfile::NamedTempFile;

const FAKE_HASH: &str = "argon2id-fakehash-for-testing";

/// Helper: create a temporary config file with the given TOML content.
/// Returns the NamedTempFile (keeps it alive so the path remains valid).
fn write_temp_config(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("failed to create temp file");
    f.write_all(content.as_bytes())
        .expect("failed to write temp config");
    f.flush().expect("failed to flush temp config");
    f
}

/// Minimal valid config TOML for show-config / check-config tests.
fn minimal_config() -> String {
    format!(
        r##"[server]
ssh_listen = "127.0.0.1:2222"

[[users]]
username = "testuser"
password_hash = "{FAKE_HASH}"
"##
    )
}

// ---------------------------------------------------------------------------
// Test 1: show-config in TOML format
// ---------------------------------------------------------------------------
#[test]
fn test_show_config_toml_format() {
    let cfg = write_temp_config(&minimal_config());
    let path = cfg.path().to_str().unwrap();

    let output = Command::cargo_bin("sks5")
        .unwrap()
        .args(["-c", path, "show-config"])
        .output()
        .expect("failed to run sks5 show-config");

    assert!(
        output.status.success(),
        "show-config should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("[server]"),
        "TOML output should contain [server]"
    );
    assert!(
        stdout.contains("ssh_listen"),
        "TOML output should contain ssh_listen"
    );
    // Password hash must be redacted
    assert!(
        !stdout.contains(FAKE_HASH),
        "password_hash should be redacted, not contain the raw hash"
    );
    assert!(
        stdout.contains("***"),
        "redacted fields should appear as ***"
    );
}

// ---------------------------------------------------------------------------
// Test 2: show-config in JSON format
// ---------------------------------------------------------------------------
#[test]
fn test_show_config_json_format() {
    let cfg = write_temp_config(&minimal_config());
    let path = cfg.path().to_str().unwrap();

    let output = Command::cargo_bin("sks5")
        .unwrap()
        .args(["-c", path, "show-config", "--format", "json"])
        .output()
        .expect("failed to run sks5 show-config --format json");

    assert!(
        output.status.success(),
        "show-config --format json should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains('{'),
        "JSON output should contain opening brace"
    );
    // Password hash must be redacted
    assert!(
        !stdout.contains(FAKE_HASH),
        "password_hash should be redacted in JSON output"
    );
    assert!(
        stdout.contains("***"),
        "redacted fields should appear as *** in JSON"
    );
}

// ---------------------------------------------------------------------------
// Test 3: init creates a config file
// ---------------------------------------------------------------------------
#[test]
fn test_init_creates_config() {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let out_path = dir.path().join("sks5-test-init.toml");
    let out_str = out_path.to_str().unwrap();

    let output = Command::cargo_bin("sks5")
        .unwrap()
        .args(["init", "--password", "test", "--output", out_str])
        .output()
        .expect("failed to run sks5 init");

    assert!(
        output.status.success(),
        "init should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content = std::fs::read_to_string(&out_path).expect("init output file should exist");
    assert!(
        content.contains("[server]"),
        "config should contain [server]"
    );
    assert!(
        content.contains("[[users]]"),
        "config should contain [[users]]"
    );
    assert!(
        content.contains("password_hash"),
        "config should contain password_hash"
    );
}

// ---------------------------------------------------------------------------
// Test 4: init with bastion preset
// ---------------------------------------------------------------------------
#[test]
fn test_init_bastion_preset() {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let out_path = dir.path().join("sks5-test-bastion.toml");
    let out_str = out_path.to_str().unwrap();

    let output = Command::cargo_bin("sks5")
        .unwrap()
        .args([
            "init",
            "--preset",
            "bastion",
            "--password",
            "test",
            "--output",
            out_str,
        ])
        .output()
        .expect("failed to run sks5 init --preset bastion");

    assert!(
        output.status.success(),
        "init --preset bastion should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content = std::fs::read_to_string(&out_path).expect("bastion config should exist");
    assert!(
        content.contains("deny"),
        "bastion preset should contain deny ACL policy"
    );
    assert!(
        content.contains("ban_enabled = true"),
        "bastion preset should have ban_enabled = true"
    );
}

// ---------------------------------------------------------------------------
// Test 5: init with proxy preset
// ---------------------------------------------------------------------------
#[test]
fn test_init_proxy_preset() {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let out_path = dir.path().join("sks5-test-proxy.toml");
    let out_str = out_path.to_str().unwrap();

    let output = Command::cargo_bin("sks5")
        .unwrap()
        .args([
            "init",
            "--preset",
            "proxy",
            "--password",
            "test",
            "--output",
            out_str,
        ])
        .output()
        .expect("failed to run sks5 init --preset proxy");

    assert!(
        output.status.success(),
        "init --preset proxy should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content = std::fs::read_to_string(&out_path).expect("proxy config should exist");
    assert!(
        content.contains("socks5_listen"),
        "proxy preset should contain socks5_listen"
    );
}

// ---------------------------------------------------------------------------
// Test 6: init with dev preset
// ---------------------------------------------------------------------------
#[test]
fn test_init_dev_preset() {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let out_path = dir.path().join("sks5-test-dev.toml");
    let out_str = out_path.to_str().unwrap();

    let output = Command::cargo_bin("sks5")
        .unwrap()
        .args([
            "init",
            "--preset",
            "dev",
            "--password",
            "test",
            "--output",
            out_str,
        ])
        .output()
        .expect("failed to run sks5 init --preset dev");

    assert!(
        output.status.success(),
        "init --preset dev should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content = std::fs::read_to_string(&out_path).expect("dev config should exist");
    assert!(
        content.contains("ban_enabled = false"),
        "dev preset should have ban_enabled = false"
    );
}

// ---------------------------------------------------------------------------
// Test 7: completions for bash
// ---------------------------------------------------------------------------
#[test]
fn test_completions_bash() {
    let output = Command::cargo_bin("sks5")
        .unwrap()
        .args(["completions", "bash"])
        .output()
        .expect("failed to run sks5 completions bash");

    assert!(
        output.status.success(),
        "completions bash should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.is_empty(),
        "completions bash should produce non-empty output"
    );
}

// ---------------------------------------------------------------------------
// Test 8: manpage output
// ---------------------------------------------------------------------------
#[test]
fn test_manpage_output() {
    let output = Command::cargo_bin("sks5")
        .unwrap()
        .args(["manpage"])
        .output()
        .expect("failed to run sks5 manpage");

    assert!(
        output.status.success(),
        "manpage should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(".TH"),
        "manpage output should contain roff .TH macro"
    );
}

// ---------------------------------------------------------------------------
// Test 9: check-config with a valid config
// ---------------------------------------------------------------------------
#[test]
fn test_check_config_valid() {
    let cfg = write_temp_config(&minimal_config());
    let path = cfg.path().to_str().unwrap();

    let output = Command::cargo_bin("sks5")
        .unwrap()
        .args(["-c", path, "check-config"])
        .output()
        .expect("failed to run sks5 check-config");

    assert!(
        output.status.success(),
        "check-config on valid config should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ---------------------------------------------------------------------------
// Test 10: check-config with an invalid config
// ---------------------------------------------------------------------------
#[test]
fn test_check_config_invalid() {
    let cfg = write_temp_config("this is not valid toml [[[");
    let path = cfg.path().to_str().unwrap();

    let output = Command::cargo_bin("sks5")
        .unwrap()
        .args(["-c", path, "check-config"])
        .output()
        .expect("failed to run sks5 check-config with invalid config");

    assert!(
        !output.status.success(),
        "check-config on invalid config should exit non-zero"
    );
}
