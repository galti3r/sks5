use clap::Parser;
use sks5::cli::{Cli, Command};

// ---------------------------------------------------------------------------
// Test 1: Default config path is "config.toml"
// ---------------------------------------------------------------------------
#[test]
fn default_config_path() {
    let cli = Cli::try_parse_from(["sks5"]).unwrap();
    assert_eq!(cli.config.to_str().unwrap(), "config.toml");
    assert!(cli.command.is_none());
    assert!(cli.log_level.is_none());
}

// ---------------------------------------------------------------------------
// Test 2: Custom config with -c flag
// ---------------------------------------------------------------------------
#[test]
fn custom_config_short_flag() {
    let cli = Cli::try_parse_from(["sks5", "-c", "/etc/sks5/custom.toml"]).unwrap();
    assert_eq!(cli.config.to_str().unwrap(), "/etc/sks5/custom.toml");
}

// ---------------------------------------------------------------------------
// Test 3: Custom config with --config flag
// ---------------------------------------------------------------------------
#[test]
fn custom_config_long_flag() {
    let cli = Cli::try_parse_from(["sks5", "--config", "myconfig.toml"]).unwrap();
    assert_eq!(cli.config.to_str().unwrap(), "myconfig.toml");
}

// ---------------------------------------------------------------------------
// Test 4: Log level override
// ---------------------------------------------------------------------------
#[test]
fn log_level_override() {
    let cli = Cli::try_parse_from(["sks5", "--log-level", "debug"]).unwrap();
    assert_eq!(cli.log_level.as_deref(), Some("debug"));
}

// ---------------------------------------------------------------------------
// Test 5: hash-password subcommand with password
// ---------------------------------------------------------------------------
#[test]
fn hash_password_subcommand_with_password() {
    let cli = Cli::try_parse_from(["sks5", "hash-password", "-p", "mysecret"]).unwrap();
    match cli.command {
        Some(Command::HashPassword { password }) => {
            assert_eq!(password.as_deref(), Some("mysecret"));
        }
        _ => panic!("expected HashPassword command"),
    }
}

// ---------------------------------------------------------------------------
// Test 6: hash-password subcommand without password (reads from stdin)
// ---------------------------------------------------------------------------
#[test]
fn hash_password_subcommand_no_password() {
    let cli = Cli::try_parse_from(["sks5", "hash-password"]).unwrap();
    match cli.command {
        Some(Command::HashPassword { password }) => {
            assert!(password.is_none());
        }
        _ => panic!("expected HashPassword command"),
    }
}

// ---------------------------------------------------------------------------
// Test 7: check-config subcommand
// ---------------------------------------------------------------------------
#[test]
fn check_config_subcommand() {
    let cli = Cli::try_parse_from(["sks5", "check-config"]).unwrap();
    match cli.command {
        Some(Command::CheckConfig) => {}
        _ => panic!("expected CheckConfig command"),
    }
}

// ---------------------------------------------------------------------------
// Test 8: Combined flags and subcommand
// ---------------------------------------------------------------------------
#[test]
fn combined_flags_and_subcommand() {
    let cli = Cli::try_parse_from([
        "sks5",
        "-c",
        "/custom/config.toml",
        "--log-level",
        "trace",
        "check-config",
    ])
    .unwrap();
    assert_eq!(cli.config.to_str().unwrap(), "/custom/config.toml");
    assert_eq!(cli.log_level.as_deref(), Some("trace"));
    assert!(matches!(cli.command, Some(Command::CheckConfig)));
}

// ---------------------------------------------------------------------------
// Test 9: Unknown subcommand is rejected
// ---------------------------------------------------------------------------
#[test]
fn unknown_subcommand_rejected() {
    let result = Cli::try_parse_from(["sks5", "unknown-command"]);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Test 10: Version flag
// ---------------------------------------------------------------------------
#[test]
fn version_flag() {
    let result = Cli::try_parse_from(["sks5", "--version"]);
    // --version causes clap to exit with an error containing version info
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
}

// ---------------------------------------------------------------------------
// Test 11: quick-start subcommand with defaults
// ---------------------------------------------------------------------------
#[test]
fn quick_start_defaults() {
    let cli = Cli::try_parse_from(["sks5", "quick-start"]).unwrap();
    match cli.command {
        Some(Command::QuickStart {
            username,
            ssh_listen,
            socks5_listen,
            password,
            save_config,
        }) => {
            assert_eq!(username, "user");
            assert_eq!(ssh_listen, "0.0.0.0:2222");
            assert!(socks5_listen.is_none());
            assert!(password.is_none());
            assert!(save_config.is_none());
        }
        _ => panic!("expected QuickStart command"),
    }
}

// ---------------------------------------------------------------------------
// Test 12: quick-start with all flags
// ---------------------------------------------------------------------------
#[test]
fn quick_start_all_flags() {
    let cli = Cli::try_parse_from([
        "sks5",
        "quick-start",
        "--username",
        "alice",
        "--ssh-listen",
        "127.0.0.1:3333",
        "--socks5-listen",
        "0.0.0.0:1080",
        "--password",
        "secret",
        "--save-config",
        "/tmp/out.toml",
    ])
    .unwrap();
    match cli.command {
        Some(Command::QuickStart {
            username,
            ssh_listen,
            socks5_listen,
            password,
            save_config,
        }) => {
            assert_eq!(username, "alice");
            assert_eq!(ssh_listen, "127.0.0.1:3333");
            assert_eq!(socks5_listen.as_deref(), Some("0.0.0.0:1080"));
            assert_eq!(password.as_deref(), Some("secret"));
            assert_eq!(save_config.unwrap().to_str().unwrap(), "/tmp/out.toml");
        }
        _ => panic!("expected QuickStart command"),
    }
}

// ---------------------------------------------------------------------------
// Test 13: init subcommand with defaults
// ---------------------------------------------------------------------------
#[test]
fn init_defaults() {
    let cli = Cli::try_parse_from(["sks5", "init"]).unwrap();
    match cli.command {
        Some(Command::Init {
            output,
            username,
            password,
            preset,
        }) => {
            assert_eq!(output.to_str().unwrap(), "config.toml");
            assert_eq!(username, "user");
            assert!(password.is_none());
            assert!(preset.is_none());
        }
        _ => panic!("expected Init command"),
    }
}

// ---------------------------------------------------------------------------
// Test 14: init subcommand with all flags
// ---------------------------------------------------------------------------
#[test]
fn init_all_flags() {
    let cli = Cli::try_parse_from([
        "sks5",
        "init",
        "--output",
        "/tmp/my.toml",
        "--username",
        "bob",
        "--password",
        "pass123",
    ])
    .unwrap();
    match cli.command {
        Some(Command::Init {
            output,
            username,
            password,
            preset,
        }) => {
            assert_eq!(output.to_str().unwrap(), "/tmp/my.toml");
            assert_eq!(username, "bob");
            assert_eq!(password.as_deref(), Some("pass123"));
            assert!(preset.is_none());
        }
        _ => panic!("expected Init command"),
    }
}

// ---------------------------------------------------------------------------
// Test 16: init with preset flag
// ---------------------------------------------------------------------------
#[test]
fn init_with_preset() {
    let cli =
        Cli::try_parse_from(["sks5", "init", "--preset", "bastion", "--password", "test"]).unwrap();
    match cli.command {
        Some(Command::Init { preset, .. }) => {
            assert_eq!(preset.as_deref(), Some("bastion"));
        }
        _ => panic!("expected Init command"),
    }
}

// ---------------------------------------------------------------------------
// Test 17: completions subcommand
// ---------------------------------------------------------------------------
#[test]
fn completions_subcommand() {
    let cli = Cli::try_parse_from(["sks5", "completions", "bash"]).unwrap();
    assert!(matches!(cli.command, Some(Command::Completions { .. })));
}

// ---------------------------------------------------------------------------
// Test 18: manpage subcommand
// ---------------------------------------------------------------------------
#[test]
fn manpage_subcommand() {
    let cli = Cli::try_parse_from(["sks5", "manpage"]).unwrap();
    assert!(matches!(cli.command, Some(Command::Manpage)));
}

// ---------------------------------------------------------------------------
// Test 19: show-config subcommand
// ---------------------------------------------------------------------------
#[test]
fn show_config_subcommand() {
    let cli = Cli::try_parse_from(["sks5", "show-config"]).unwrap();
    match cli.command {
        Some(Command::ShowConfig { format }) => {
            assert_eq!(format, "toml"); // default
        }
        _ => panic!("expected ShowConfig command"),
    }
}

// ---------------------------------------------------------------------------
// Test 20: show-config with json format
// ---------------------------------------------------------------------------
#[test]
fn show_config_json_format() {
    let cli = Cli::try_parse_from(["sks5", "show-config", "--format", "json"]).unwrap();
    match cli.command {
        Some(Command::ShowConfig { format }) => {
            assert_eq!(format, "json");
        }
        _ => panic!("expected ShowConfig command"),
    }
}

// ---------------------------------------------------------------------------
// Test 21: backup subcommand
// ---------------------------------------------------------------------------
#[test]
fn backup_subcommand() {
    let cli = Cli::try_parse_from([
        "sks5",
        "backup",
        "--token",
        "my-token",
        "--output",
        "/tmp/backup.json",
    ])
    .unwrap();
    match cli.command {
        Some(Command::Backup {
            output,
            token,
            api_addr,
        }) => {
            assert_eq!(token, "my-token");
            assert_eq!(output.unwrap().to_str().unwrap(), "/tmp/backup.json");
            assert_eq!(api_addr, "http://127.0.0.1:9091"); // default
        }
        _ => panic!("expected Backup command"),
    }
}

// ---------------------------------------------------------------------------
// Test 22: restore subcommand
// ---------------------------------------------------------------------------
#[test]
fn restore_subcommand() {
    let cli = Cli::try_parse_from([
        "sks5",
        "restore",
        "--token",
        "my-token",
        "--input",
        "/tmp/backup.json",
    ])
    .unwrap();
    match cli.command {
        Some(Command::Restore {
            input,
            token,
            api_addr,
        }) => {
            assert_eq!(token, "my-token");
            assert_eq!(input.to_str().unwrap(), "/tmp/backup.json");
            assert_eq!(api_addr, "http://127.0.0.1:9091"); // default
        }
        _ => panic!("expected Restore command"),
    }
}

// ---------------------------------------------------------------------------
// Test 15: init with -o short flag
// ---------------------------------------------------------------------------
#[test]
fn init_short_output_flag() {
    let cli = Cli::try_parse_from(["sks5", "init", "-o", "short.toml"]).unwrap();
    match cli.command {
        Some(Command::Init { output, .. }) => {
            assert_eq!(output.to_str().unwrap(), "short.toml");
        }
        _ => panic!("expected Init command"),
    }
}

// ---------------------------------------------------------------------------
// Test 23: health-check subcommand defaults
// ---------------------------------------------------------------------------
#[test]
fn health_check_defaults() {
    let cli = Cli::try_parse_from(["sks5", "health-check"]).unwrap();
    match cli.command {
        Some(Command::HealthCheck { addr, timeout }) => {
            assert_eq!(addr, "127.0.0.1:2222");
            assert_eq!(timeout, 5);
        }
        _ => panic!("expected HealthCheck command"),
    }
}

// ---------------------------------------------------------------------------
// Test 24: health-check subcommand custom args
// ---------------------------------------------------------------------------
#[test]
fn health_check_custom_args() {
    let cli = Cli::try_parse_from([
        "sks5",
        "health-check",
        "--addr",
        "10.0.0.1:3333",
        "--timeout",
        "10",
    ])
    .unwrap();
    match cli.command {
        Some(Command::HealthCheck { addr, timeout }) => {
            assert_eq!(addr, "10.0.0.1:3333");
            assert_eq!(timeout, 10);
        }
        _ => panic!("expected HealthCheck command"),
    }
}

// ---------------------------------------------------------------------------
// Test 25: ssh-config subcommand with required args
// ---------------------------------------------------------------------------
#[test]
fn ssh_config_required_args() {
    let cli = Cli::try_parse_from([
        "sks5",
        "ssh-config",
        "--user",
        "alice",
        "--host",
        "proxy.example.com",
    ])
    .unwrap();
    match cli.command {
        Some(Command::SshConfig {
            user,
            host,
            port,
            name,
            dynamic_forward,
        }) => {
            assert_eq!(user, "alice");
            assert_eq!(host, "proxy.example.com");
            assert_eq!(port, 2222); // default
            assert!(name.is_none());
            assert!(dynamic_forward.is_none());
        }
        _ => panic!("expected SshConfig command"),
    }
}

// ---------------------------------------------------------------------------
// Test 26: ssh-config subcommand with all flags
// ---------------------------------------------------------------------------
#[test]
fn ssh_config_all_flags() {
    let cli = Cli::try_parse_from([
        "sks5",
        "ssh-config",
        "--user",
        "bob",
        "--host",
        "10.0.0.1",
        "--port",
        "3333",
        "--name",
        "myproxy",
        "--dynamic-forward",
        "1080",
    ])
    .unwrap();
    match cli.command {
        Some(Command::SshConfig {
            user,
            host,
            port,
            name,
            dynamic_forward,
        }) => {
            assert_eq!(user, "bob");
            assert_eq!(host, "10.0.0.1");
            assert_eq!(port, 3333);
            assert_eq!(name.as_deref(), Some("myproxy"));
            assert_eq!(dynamic_forward, Some(1080));
        }
        _ => panic!("expected SshConfig command"),
    }
}

// ---------------------------------------------------------------------------
// Test 27: ssh-config missing required --user fails
// ---------------------------------------------------------------------------
#[test]
fn ssh_config_missing_user_fails() {
    let result = Cli::try_parse_from(["sks5", "ssh-config", "--host", "localhost"]);
    assert!(result.is_err(), "ssh-config without --user should fail");
}

// ---------------------------------------------------------------------------
// Test 28: ssh-config missing required --host fails
// ---------------------------------------------------------------------------
#[test]
fn ssh_config_missing_host_fails() {
    let result = Cli::try_parse_from(["sks5", "ssh-config", "--user", "alice"]);
    assert!(result.is_err(), "ssh-config without --host should fail");
}

// ---------------------------------------------------------------------------
// Test 29: generate-totp subcommand with username
// ---------------------------------------------------------------------------
#[test]
fn generate_totp_parses_username() {
    let cli = Cli::try_parse_from(["sks5", "generate-totp", "--username", "alice"]).unwrap();
    match cli.command {
        Some(Command::GenerateTotp { username }) => {
            assert_eq!(username, "alice");
        }
        _ => panic!("expected GenerateTotp command"),
    }
}

// ---------------------------------------------------------------------------
// Test 30: generate-totp missing required --username fails
// ---------------------------------------------------------------------------
#[test]
fn generate_totp_missing_username_fails() {
    let result = Cli::try_parse_from(["sks5", "generate-totp"]);
    assert!(
        result.is_err(),
        "generate-totp without --username should fail"
    );
}
