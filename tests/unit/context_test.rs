use sks5::config::types::*;

// ---------------------------------------------------------------------------
// Test 1: LogLevel Display
// ---------------------------------------------------------------------------
#[test]
fn log_level_display() {
    assert_eq!(LogLevel::Trace.to_string(), "trace");
    assert_eq!(LogLevel::Debug.to_string(), "debug");
    assert_eq!(LogLevel::Info.to_string(), "info");
    assert_eq!(LogLevel::Warn.to_string(), "warn");
    assert_eq!(LogLevel::Error.to_string(), "error");
}

// ---------------------------------------------------------------------------
// Test 2: LogFormat Display
// ---------------------------------------------------------------------------
#[test]
fn log_format_display() {
    assert_eq!(LogFormat::Pretty.to_string(), "pretty");
    assert_eq!(LogFormat::Json.to_string(), "json");
}

// ---------------------------------------------------------------------------
// Test 3: AclPolicyConfig Display
// ---------------------------------------------------------------------------
#[test]
fn acl_policy_display() {
    assert_eq!(AclPolicyConfig::Allow.to_string(), "allow");
    assert_eq!(AclPolicyConfig::Deny.to_string(), "deny");
}

// ---------------------------------------------------------------------------
// Test 4: LimitsConfig defaults
// ---------------------------------------------------------------------------
#[test]
fn limits_config_defaults() {
    let limits = LimitsConfig::default();
    assert_eq!(limits.max_connections, 1000);
    assert_eq!(limits.max_connections_per_user, 0);
    assert_eq!(limits.connection_timeout, 300);
    assert_eq!(limits.idle_timeout, 0);
    assert_eq!(limits.max_auth_attempts, 3);
}

// ---------------------------------------------------------------------------
// Test 5: SecurityConfig defaults
// ---------------------------------------------------------------------------
#[test]
fn security_config_defaults() {
    let sec = SecurityConfig::default();
    assert!(sec.ban_enabled);
    assert_eq!(sec.ban_threshold, 5);
    assert_eq!(sec.ban_window, 300);
    assert_eq!(sec.ban_duration, 900);
    assert!(sec.allowed_source_ips.is_empty());
    assert!(sec.ban_whitelist.is_empty());
}

// ---------------------------------------------------------------------------
// Test 6: ShellConfig defaults
// ---------------------------------------------------------------------------
#[test]
fn shell_config_defaults() {
    let shell = ShellConfig::default();
    assert_eq!(shell.hostname, "sks5-proxy");
    assert_eq!(shell.prompt, "$ ");
}

// ---------------------------------------------------------------------------
// Test 7: MetricsConfig defaults
// ---------------------------------------------------------------------------
#[test]
fn metrics_config_defaults() {
    let metrics = MetricsConfig::default();
    assert!(!metrics.enabled);
    assert_eq!(metrics.listen, "127.0.0.1:9090");
}

// ---------------------------------------------------------------------------
// Test 8: ApiConfig defaults
// ---------------------------------------------------------------------------
#[test]
fn api_config_defaults() {
    let api = ApiConfig::default();
    assert!(!api.enabled);
    assert_eq!(api.listen, "127.0.0.1:9091");
    assert!(api.token.is_empty());
}

// ---------------------------------------------------------------------------
// Test 9: ApiConfig Debug redacts token
// ---------------------------------------------------------------------------
#[test]
fn api_config_debug_redacts_token() {
    let api = ApiConfig {
        enabled: true,
        listen: "0.0.0.0:9091".to_string(),
        token: "super-secret-api-token".to_string(),
    };

    let debug = format!("{:?}", api);
    assert!(debug.contains("***"), "token should be redacted in Debug");
    assert!(
        !debug.contains("super-secret-api-token"),
        "token value must not appear"
    );
}

// ---------------------------------------------------------------------------
// Test 10: ApiConfig Debug shows empty when no token
// ---------------------------------------------------------------------------
#[test]
fn api_config_debug_empty_token() {
    let api = ApiConfig::default();
    let debug = format!("{:?}", api);
    assert!(debug.contains("(empty)"));
}

// ---------------------------------------------------------------------------
// Test 11: GlobalAclConfig defaults
// ---------------------------------------------------------------------------
#[test]
fn global_acl_config_defaults() {
    let acl = GlobalAclConfig::default();
    assert_eq!(acl.default_policy, AclPolicyConfig::Allow);
    assert!(acl.allow.is_empty());
    assert!(acl.deny.is_empty());
}

// ---------------------------------------------------------------------------
// Test 11b: UserAclConfig defaults
// ---------------------------------------------------------------------------
#[test]
fn user_acl_config_defaults() {
    let acl = UserAclConfig::default();
    assert!(acl.default_policy.is_none());
    assert!(acl.allow.is_empty());
    assert!(acl.deny.is_empty());
    assert!(acl.inherit);
}

// ---------------------------------------------------------------------------
// Test 12: GeoIpConfig defaults
// ---------------------------------------------------------------------------
#[test]
fn geoip_config_defaults() {
    let geoip = GeoIpConfig::default();
    assert!(!geoip.enabled);
    assert!(geoip.database_path.is_none());
    assert!(geoip.allowed_countries.is_empty());
    assert!(geoip.denied_countries.is_empty());
}

// ---------------------------------------------------------------------------
// Test 13: LogLevel equality
// ---------------------------------------------------------------------------
#[test]
fn log_level_equality() {
    assert_eq!(LogLevel::Info, LogLevel::Info);
    assert_ne!(LogLevel::Info, LogLevel::Debug);
}

// ---------------------------------------------------------------------------
// Test 14: LogFormat equality
// ---------------------------------------------------------------------------
#[test]
fn log_format_equality() {
    assert_eq!(LogFormat::Json, LogFormat::Json);
    assert_ne!(LogFormat::Json, LogFormat::Pretty);
}

// ---------------------------------------------------------------------------
// Test 15: AclPolicyConfig equality
// ---------------------------------------------------------------------------
#[test]
fn acl_policy_equality() {
    assert_eq!(AclPolicyConfig::Allow, AclPolicyConfig::Allow);
    assert_ne!(AclPolicyConfig::Allow, AclPolicyConfig::Deny);
}

// ---------------------------------------------------------------------------
// Test 16: UserConfig Debug redacts password_hash
// ---------------------------------------------------------------------------
#[test]
fn user_config_debug_redacts_hash() {
    let toml_str = r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "test"
password_hash = "argon2-secret-hash-value"
"##
    .to_string();

    let config: AppConfig = toml::from_str(&toml_str).unwrap();
    let debug = format!("{:?}", config.users[0]);
    assert!(debug.contains("***"), "password_hash should be redacted");
    assert!(
        !debug.contains("argon2-secret-hash-value"),
        "hash must not appear in Debug"
    );
}

// ---------------------------------------------------------------------------
// Test 17: Full AppConfig from TOML with all sections
// ---------------------------------------------------------------------------
#[test]
fn full_config_with_all_sections() {
    let toml_str = r##"
[server]
ssh_listen = "0.0.0.0:2222"
socks5_listen = "0.0.0.0:1080"
proxy_protocol = true

[shell]
hostname = "myhost"
prompt = "> "

[limits]
max_connections = 500
max_connections_per_user = 5
connection_timeout = 60
idle_timeout = 120
max_auth_attempts = 2

[security]
allowed_source_ips = ["10.0.0.0/8", "192.168.0.0/16"]
ban_enabled = false

[logging]
level = "trace"
format = "json"

[metrics]
enabled = true
listen = "0.0.0.0:9090"

[geoip]
enabled = true
allowed_countries = ["US", "FR"]
denied_countries = ["CN"]

[[webhooks]]
url = "https://example.com/hook"
events = ["auth_success"]

[[users]]
username = "admin"
password_hash = "fakehash"
allow_forwarding = true
allow_shell = true
max_new_connections_per_minute = 60
source_ips = ["10.0.0.0/24"]
"##;

    let config: AppConfig = toml::from_str(toml_str).unwrap();

    assert_eq!(config.server.socks5_listen.as_deref(), Some("0.0.0.0:1080"));
    assert!(config.server.proxy_protocol);
    assert_eq!(config.shell.hostname, "myhost");
    assert_eq!(config.shell.prompt, "> ");
    assert_eq!(config.limits.max_connections, 500);
    assert_eq!(config.limits.max_connections_per_user, 5);
    assert_eq!(config.limits.connection_timeout, 60);
    assert_eq!(config.limits.idle_timeout, 120);
    assert_eq!(config.limits.max_auth_attempts, 2);
    assert_eq!(config.security.allowed_source_ips.len(), 2);
    assert!(!config.security.ban_enabled);
    assert_eq!(config.logging.level, LogLevel::Trace);
    assert_eq!(config.logging.format, LogFormat::Json);
    assert!(config.metrics.enabled);
    assert!(config.geoip.enabled);
    assert_eq!(config.geoip.allowed_countries, vec!["US", "FR"]);
    assert_eq!(config.geoip.denied_countries, vec!["CN"]);
    assert_eq!(config.webhooks.len(), 1);
    assert_eq!(config.webhooks[0].url, "https://example.com/hook");
    assert_eq!(config.users[0].max_new_connections_per_minute, 60);
    assert_eq!(config.users[0].source_ips.len(), 1);
}
