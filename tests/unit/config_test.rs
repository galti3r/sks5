use sks5::config;

const FAKE_HASH: &str = "argon2id-fakehash-for-testing";

#[test]
fn test_parse_config_with_socks5() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"
socks5_listen = "0.0.0.0:1080"

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##,
    );
    let cfg = config::parse_config(&toml).unwrap();
    assert_eq!(cfg.server.socks5_listen.as_deref(), Some("0.0.0.0:1080"));
}

#[test]
fn test_parse_config_without_socks5() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##,
    );
    let cfg = config::parse_config(&toml).unwrap();
    assert!(cfg.server.socks5_listen.is_none());
}

#[test]
fn test_user_defaults() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##,
    );
    let cfg = config::parse_config(&toml).unwrap();
    let user = &cfg.users[0];
    assert!(user.allow_forwarding);
    assert_eq!(user.allow_shell, None);
    assert_eq!(user.max_new_connections_per_minute, 0);
    assert_eq!(user.max_bandwidth_kbps, 0);
    assert_eq!(user.acl.default_policy, None);
}

#[test]
fn test_api_requires_token() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[api]
enabled = true
token = ""

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##,
    );
    assert!(config::parse_config(&toml).is_err());
}
