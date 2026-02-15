use sks5::config::types::AppConfig;
use sks5::security::SecurityManager;
use std::net::IpAddr;

fn config_with_allowed_ips(ips: Vec<&str>) -> AppConfig {
    let mut config = default_config();
    config.security.allowed_source_ips = ips.into_iter().map(|s| s.parse().unwrap()).collect();
    config
}

fn default_config() -> AppConfig {
    toml::from_str(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "test"
password_hash = "argon2id-fake"
"##,
    )
    .unwrap()
}

#[test]
fn pre_auth_check_allows_when_no_restrictions() {
    let config = default_config();
    let sm = SecurityManager::new(&config);
    let ip: IpAddr = "1.2.3.4".parse().unwrap();
    assert!(sm.pre_auth_check(&ip).is_ok());
}

#[test]
fn pre_auth_check_rejects_disallowed_ip() {
    let config = config_with_allowed_ips(vec!["10.0.0.0/8"]);
    let sm = SecurityManager::new(&config);
    let ip: IpAddr = "1.2.3.4".parse().unwrap();
    assert_eq!(sm.pre_auth_check(&ip), Err("disallowed source IP"));
}

#[test]
fn pre_auth_check_allows_matching_ip() {
    let config = config_with_allowed_ips(vec!["10.0.0.0/8"]);
    let sm = SecurityManager::new(&config);
    let ip: IpAddr = "10.1.2.3".parse().unwrap();
    assert!(sm.pre_auth_check(&ip).is_ok());
}

#[test]
fn pre_auth_check_rejects_banned_ip() {
    let mut config = default_config();
    config.security.ban_enabled = true;
    config.security.ban_threshold = 1;
    let sm = SecurityManager::new(&config);
    let ip: IpAddr = "5.5.5.5".parse().unwrap();

    // Record a failure to trigger ban
    sm.record_auth_failure(&ip);

    assert_eq!(sm.pre_auth_check(&ip), Err("banned IP"));
}

#[test]
fn pre_auth_check_ip_allowlist_checked_before_ban() {
    // If IP is not in allowlist, we get "disallowed" even if also banned
    let config = config_with_allowed_ips(vec!["10.0.0.0/8"]);
    let sm = SecurityManager::new(&config);
    let ip: IpAddr = "5.5.5.5".parse().unwrap();
    sm.record_auth_failure(&ip);

    assert_eq!(sm.pre_auth_check(&ip), Err("disallowed source IP"));
}
