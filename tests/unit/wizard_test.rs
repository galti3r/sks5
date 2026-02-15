use sks5::config;
use sks5::wizard;

#[test]
fn test_non_interactive_config_is_valid() {
    let config = wizard::run_wizard(true).expect("non-interactive wizard should succeed");
    config::parse_config_validate(&config).expect("generated config should validate");

    assert_eq!(config.server.ssh_listen, "0.0.0.0:2222");
    assert_eq!(config.server.socks5_listen.as_deref(), Some("0.0.0.0:1080"));
    assert_eq!(config.users.len(), 1);
    assert_eq!(config.users[0].username, "user");
    assert!(config.users[0].password_hash.is_some());
    assert!(config.users[0].allow_forwarding);
    assert!(config.users[0].allow_shell);
}

#[test]
fn test_non_interactive_config_toml_round_trip() {
    let config = wizard::run_wizard(true).expect("non-interactive wizard should succeed");
    let toml_str = wizard::config_to_toml(&config).expect("should serialize to TOML");

    // TOML must contain key sections
    assert!(toml_str.contains("[server]"), "missing [server] section");
    assert!(toml_str.contains("[[users]]"), "missing [[users]] section");
    assert!(toml_str.contains("ssh_listen"), "missing ssh_listen field");

    // Must round-trip: TOML → AppConfig → validate
    let reparsed = config::parse_config(&toml_str).expect("generated TOML should re-parse");
    assert_eq!(reparsed.server.ssh_listen, config.server.ssh_listen);
    assert_eq!(reparsed.users.len(), config.users.len());
    assert_eq!(reparsed.users[0].username, config.users[0].username);
}

#[test]
fn test_non_interactive_generates_unique_passwords() {
    let config1 = wizard::run_wizard(true).expect("first wizard run");
    let config2 = wizard::run_wizard(true).expect("second wizard run");

    // Each run should generate a unique password hash (different salts)
    assert_ne!(
        config1.users[0].password_hash, config2.users[0].password_hash,
        "two non-interactive runs should produce different password hashes"
    );
}

#[test]
fn test_config_to_toml_has_comment_header() {
    let config = wizard::run_wizard(true).expect("non-interactive wizard should succeed");
    let toml_str = wizard::config_to_toml(&config).expect("should serialize to TOML");

    assert!(
        toml_str.starts_with("# sks5 configuration"),
        "TOML output should start with a comment header"
    );
}

#[test]
fn test_non_interactive_config_has_sensible_defaults() {
    let config = wizard::run_wizard(true).expect("non-interactive wizard should succeed");

    // Security defaults
    assert!(config.security.ban_enabled);
    assert_eq!(config.security.ban_threshold, 5);
    assert!(config.security.ip_guard_enabled);

    // Logging defaults
    assert_eq!(config.logging.level, sks5::config::types::LogLevel::Info);
    assert_eq!(
        config.logging.format,
        sks5::config::types::LogFormat::Pretty
    );

    // API/metrics off by default
    assert!(!config.api.enabled);
    assert!(!config.metrics.enabled);
}
