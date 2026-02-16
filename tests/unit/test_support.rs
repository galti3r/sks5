//! Shared test utilities for unit tests.
//!
//! Provides default config builders to eliminate duplication across test files.
//! Usage: add `mod test_support;` at the top of your unit test file.

#![allow(dead_code)]

use sks5::config::types::*;
use std::collections::HashMap;

/// Default `ServerConfig` for struct-literal tests.
pub fn default_server_config() -> ServerConfig {
    ServerConfig {
        ssh_listen: "127.0.0.1:2222".to_string(),
        socks5_listen: None,
        host_key_path: "host_key".into(),
        server_id: "SSH-2.0-sks5_test".to_string(),
        banner: "test".to_string(),
        motd_path: None,
        proxy_protocol: false,
        allowed_ciphers: Vec::new(),
        allowed_kex: Vec::new(),
        shutdown_timeout: 30,
        socks5_tls_cert: None,
        socks5_tls_key: None,
        dns_cache_ttl: -1,
        dns_cache_max_entries: 1000,
        connect_retry: 0,
        connect_retry_delay_ms: 1000,
        bookmarks_path: None,
        ssh_keepalive_interval_secs: 15,
        ssh_keepalive_max: 3,
        ssh_auth_timeout: 120,
    }
}

/// Default `UserConfig` for struct-literal tests.
pub fn default_user_config(username: &str) -> UserConfig {
    UserConfig {
        username: username.to_string(),
        password_hash: Some("hash".to_string()),
        authorized_keys: Vec::new(),
        allow_forwarding: true,
        allow_shell: Some(true),
        max_new_connections_per_minute: 0,
        max_bandwidth_kbps: 0,
        source_ips: Vec::new(),
        expires_at: None,
        upstream_proxy: None,
        acl: Default::default(),
        totp_secret: None,
        totp_enabled: false,
        max_aggregate_bandwidth_kbps: 0,
        group: None,
        role: UserRole::default(),
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
    }
}

/// Fake argon2id hash for TOML-based config tests.
pub const FAKE_HASH: &str = "argon2id-fakehash-for-testing";

/// Build a minimal `AppConfig` from TOML, suitable for most unit tests.
///
/// `extra_toml` is inserted between the standard sections and `[[users]]`.
/// Do NOT re-declare `[server]`, `[limits]`, or `[security]` in `extra_toml`.
pub fn minimal_app_config(extra_toml: &str) -> AppConfig {
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:2222"
host_key_path = "/tmp/sks5-test-host-key"

[limits]
max_auth_attempts = 3

[security]
ban_enabled = false

{extra_toml}

[[users]]
username = "alice"
password_hash = "{FAKE_HASH}"
allow_forwarding = true
allow_shell = true
"##
    );
    toml::from_str(&toml_str).unwrap()
}

/// Build a minimal `AppConfig` with a custom password hash (for auth tests).
pub fn config_with_hash(password_hash: &str) -> AppConfig {
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:2222"
host_key_path = "/tmp/sks5-test-host-key"

[limits]
max_auth_attempts = 3

[security]
ban_enabled = false

[[users]]
username = "alice"
password_hash = "{password_hash}"
allow_forwarding = true
allow_shell = true
"##
    );
    toml::from_str(&toml_str).unwrap()
}

/// Build a minimal `AppConfig` with SOCKS5 enabled.
pub fn config_with_socks5(socks5_port: u16, password_hash: &str) -> AppConfig {
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
socks5_listen = "127.0.0.1:{socks5_port}"
host_key_path = "/tmp/sks5-test-host-key"

[limits]
max_connections = 100
max_connections_per_user = 50
connection_timeout = 10
idle_timeout = 10

[security]
ban_enabled = false
ip_guard_enabled = false

[[users]]
username = "alice"
password_hash = "{password_hash}"
allow_forwarding = true
allow_shell = true
"##
    );
    toml::from_str(&toml_str).unwrap()
}

/// Build a `AppConfig` with API enabled.
pub fn config_with_api(api_port: u16, token: &str, password_hash: &str) -> AppConfig {
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
host_key_path = "/tmp/sks5-test-host-key"

[api]
enabled = true
listen = "127.0.0.1:{api_port}"
token = "{token}"

[security]
ban_enabled = false

[[users]]
username = "alice"
password_hash = "{password_hash}"
allow_forwarding = true
allow_shell = true
"##
    );
    toml::from_str(&toml_str).unwrap()
}

/// Build a full `AppConfig` via struct literals (for certificate_auth style tests).
pub fn full_app_config(users: Vec<UserConfig>, security: SecurityConfig) -> AppConfig {
    AppConfig {
        server: default_server_config(),
        shell: ShellConfig::default(),
        limits: LimitsConfig::default(),
        security,
        logging: LoggingConfig::default(),
        metrics: MetricsConfig::default(),
        api: ApiConfig::default(),
        geoip: GeoIpConfig::default(),
        upstream_proxy: None,
        webhooks: Vec::new(),
        acl: GlobalAclConfig::default(),
        users,
        groups: Vec::new(),
        motd: MotdConfig::default(),
        alerting: AlertingConfig::default(),
        maintenance_windows: Vec::new(),
        connection_pool: ConnectionPoolConfig::default(),
    }
}
