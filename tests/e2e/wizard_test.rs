#![allow(deprecated)]

use assert_cmd::Command;

#[test]
fn test_wizard_non_interactive_creates_config() {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let out_path = dir.path().join("wizard-output.toml");
    let out_str = out_path.to_str().unwrap();

    let output = Command::cargo_bin("sks5")
        .unwrap()
        .args(["wizard", "--non-interactive", "--output", out_str])
        .output()
        .expect("failed to run sks5 wizard --non-interactive");

    assert!(
        output.status.success(),
        "wizard --non-interactive should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content = std::fs::read_to_string(&out_path).expect("wizard output file should exist");

    // Verify it's a valid TOML config
    assert!(
        content.contains("[server]"),
        "config should contain [server]"
    );
    assert!(
        content.contains("[[users]]"),
        "config should contain [[users]]"
    );
    assert!(
        content.contains("ssh_listen"),
        "config should contain ssh_listen"
    );
    assert!(
        content.contains("password_hash"),
        "config should contain password_hash"
    );
}

#[test]
fn test_wizard_non_interactive_config_validates() {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let out_path = dir.path().join("wizard-validate.toml");
    let out_str = out_path.to_str().unwrap();

    // Generate config with wizard
    let output = Command::cargo_bin("sks5")
        .unwrap()
        .args(["wizard", "--non-interactive", "--output", out_str])
        .output()
        .expect("failed to run sks5 wizard");

    assert!(
        output.status.success(),
        "wizard should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Validate it with check-config
    let output = Command::cargo_bin("sks5")
        .unwrap()
        .args(["-c", out_str, "check-config"])
        .output()
        .expect("failed to run sks5 check-config");

    assert!(
        output.status.success(),
        "check-config on wizard output should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_wizard_non_interactive_prints_credentials() {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let out_path = dir.path().join("wizard-creds.toml");
    let out_str = out_path.to_str().unwrap();

    let output = Command::cargo_bin("sks5")
        .unwrap()
        .args(["wizard", "--non-interactive", "--output", out_str])
        .output()
        .expect("failed to run sks5 wizard");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should print generated credentials
    assert!(
        stderr.contains("Username: user"),
        "stderr should contain generated username"
    );
    assert!(
        stderr.contains("Password:"),
        "stderr should contain generated password"
    );
    assert!(
        stderr.contains("Configuration written to"),
        "stderr should confirm file was written"
    );
}

#[test]
fn test_wizard_help_shows_wizard_subcommand() {
    let output = Command::cargo_bin("sks5")
        .unwrap()
        .args(["--help"])
        .output()
        .expect("failed to run sks5 --help");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("wizard"),
        "help output should list wizard subcommand"
    );
}
