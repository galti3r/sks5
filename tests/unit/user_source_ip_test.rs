use crate::test_support::default_server_config;
use sks5::auth::user::User;
use sks5::config::types::{GlobalAclConfig, LimitsConfig, ShellConfig, UserConfig, UserRole};
use std::collections::HashMap;

fn user_with_source_ips(ips: &[&str]) -> User {
    let cfg = UserConfig {
        username: "test".to_string(),
        password_hash: Some("argon2id-fake".to_string()),
        authorized_keys: vec![],
        allow_forwarding: true,
        allow_shell: true,
        max_new_connections_per_minute: 60,
        max_bandwidth_kbps: 0,
        source_ips: ips.iter().map(|s| s.parse().unwrap()).collect(),
        expires_at: None,
        upstream_proxy: None,
        acl: Default::default(),
        totp_secret: None,
        totp_enabled: false,
        max_aggregate_bandwidth_kbps: 0,
        group: None,
        role: UserRole::User,
        shell_permissions: None,
        motd: None,
        quotas: None,
        time_access: None,
        auth_methods: None,
        idle_warning_secs: None,
        colors: None,
        connect_retry: None,
        connect_retry_delay_ms: None,
        aliases: HashMap::new(),
        max_connections: None,
        rate_limits: None,
    };
    User::from_config(
        &cfg,
        &[],
        &GlobalAclConfig::default(),
        &LimitsConfig::default(),
        &default_server_config(),
        &ShellConfig::default(),
    )
    .unwrap()
}

#[test]
fn empty_source_ips_allows_any() {
    let user = user_with_source_ips(&[]);
    assert!(user.is_source_ip_allowed(&"1.2.3.4".parse().unwrap()));
    assert!(user.is_source_ip_allowed(&"10.0.0.1".parse().unwrap()));
    assert!(user.is_source_ip_allowed(&"::1".parse().unwrap()));
}

#[test]
fn matching_cidr_allows() {
    let user = user_with_source_ips(&["192.168.1.0/24"]);
    assert!(user.is_source_ip_allowed(&"192.168.1.100".parse().unwrap()));
    assert!(user.is_source_ip_allowed(&"192.168.1.1".parse().unwrap()));
}

#[test]
fn non_matching_cidr_rejects() {
    let user = user_with_source_ips(&["192.168.1.0/24"]);
    assert!(!user.is_source_ip_allowed(&"192.168.2.1".parse().unwrap()));
    assert!(!user.is_source_ip_allowed(&"10.0.0.1".parse().unwrap()));
}

#[test]
fn multiple_cidrs_any_match_allows() {
    let user = user_with_source_ips(&["10.0.0.0/8", "172.16.0.0/12"]);
    assert!(user.is_source_ip_allowed(&"10.1.2.3".parse().unwrap()));
    assert!(user.is_source_ip_allowed(&"172.20.0.1".parse().unwrap()));
    assert!(!user.is_source_ip_allowed(&"192.168.1.1".parse().unwrap()));
}

#[test]
fn single_host_cidr() {
    let user = user_with_source_ips(&["1.2.3.4/32"]);
    assert!(user.is_source_ip_allowed(&"1.2.3.4".parse().unwrap()));
    assert!(!user.is_source_ip_allowed(&"1.2.3.5".parse().unwrap()));
}
