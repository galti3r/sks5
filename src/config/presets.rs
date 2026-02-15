/// Generate a bastion-mode configuration template.
/// Deny-default ACL, ban enabled, strict security, TOTP required.
pub fn bastion_preset(username: &str, password_hash: &str) -> String {
    format!(
        r##"# sks5 bastion preset — high security, deny-default
[server]
ssh_listen = "0.0.0.0:2222"
host_key_path = "host_key"
server_id = "SSH-2.0-sks5_{version}"
banner = "Authorized access only"
shutdown_timeout = 30

[shell]
hostname = "bastion"
prompt = "bastion$ "

[limits]
max_connections = 100
max_connections_per_user = 5
connection_timeout = 300
idle_timeout = 600
max_auth_attempts = 3
socks5_handshake_timeout = 15

[security]
ban_enabled = true
ban_threshold = 3
ban_window = 300
ban_duration = 3600
ip_guard_enabled = true
totp_required_for = ["ssh", "socks5"]

[logging]
level = "info"
format = "json"
audit_log_path = "audit.log"
audit_max_size_mb = 100
audit_max_files = 10

[metrics]
enabled = true
listen = "127.0.0.1:9090"

[api]
enabled = true
listen = "127.0.0.1:9091"
token = "CHANGE-ME-TO-A-RANDOM-TOKEN"

[acl]
default_policy = "deny"
allow = []
deny = ["169.254.169.254:*", "10.0.0.0/8:*", "172.16.0.0/12:*", "192.168.0.0/16:*"]

[[users]]
username = "{username}"
password_hash = "{password_hash}"
allow_forwarding = true
allow_shell = true
totp_enabled = true
role = "admin"

[users.acl]
default_policy = "deny"
allow = ["*:443", "*:80", "*:8080", "*:8443"]
deny = []
"##,
        version = env!("CARGO_PKG_VERSION"),
        username = username,
        password_hash = password_hash,
    )
}

/// Generate a proxy-mode configuration template.
/// Allow-default, standalone SOCKS5, moderate rate limits.
pub fn proxy_preset(username: &str, password_hash: &str) -> String {
    format!(
        r##"# sks5 proxy preset — permissive forwarding proxy
[server]
ssh_listen = "0.0.0.0:2222"
socks5_listen = "0.0.0.0:1080"
host_key_path = "host_key"
server_id = "SSH-2.0-sks5_{version}"
banner = "Welcome to sks5 proxy"
dns_cache_ttl = 300
connect_retry = 2

[shell]
hostname = "sks5-proxy"
prompt = "$ "

[limits]
max_connections = 1000
max_connections_per_user = 50
connection_timeout = 300
idle_timeout = 0
max_auth_attempts = 5
socks5_handshake_timeout = 30

[security]
ban_enabled = true
ban_threshold = 10
ban_window = 300
ban_duration = 600
ip_guard_enabled = true

[logging]
level = "info"
format = "pretty"

[metrics]
enabled = true
listen = "127.0.0.1:9090"

[api]
enabled = true
listen = "127.0.0.1:9091"
token = "CHANGE-ME-TO-A-RANDOM-TOKEN"

[acl]
default_policy = "allow"
allow = []
deny = ["169.254.169.254:*"]

[[users]]
username = "{username}"
password_hash = "{password_hash}"
allow_forwarding = true
allow_shell = true

[users.acl]
default_policy = "allow"
deny = ["169.254.169.254:*"]
"##,
        version = env!("CARGO_PKG_VERSION"),
        username = username,
        password_hash = password_hash,
    )
}

/// Generate a development configuration template.
/// Everything allowed, debug logging, no bans, minimal security.
pub fn dev_preset(username: &str, password_hash: &str) -> String {
    format!(
        r##"# sks5 dev preset — development and testing
[server]
ssh_listen = "127.0.0.1:2222"
socks5_listen = "127.0.0.1:1080"
host_key_path = "host_key"
server_id = "SSH-2.0-sks5_{version}"
banner = "sks5 dev mode"

[shell]
hostname = "sks5-dev"
prompt = "dev$ "
colors = true

[limits]
max_connections = 100
connection_timeout = 600
idle_timeout = 0
max_auth_attempts = 10
socks5_handshake_timeout = 60

[security]
ban_enabled = false
ban_threshold = 100
ip_guard_enabled = false

[logging]
level = "debug"
format = "pretty"
connection_flow_logs = true

[metrics]
enabled = true
listen = "127.0.0.1:9090"

[api]
enabled = true
listen = "127.0.0.1:9091"
token = "dev-token-change-me"

[acl]
default_policy = "allow"

[[users]]
username = "{username}"
password_hash = "{password_hash}"
allow_forwarding = true
allow_shell = true
role = "admin"

[users.acl]
default_policy = "allow"
"##,
        version = env!("CARGO_PKG_VERSION"),
        username = username,
        password_hash = password_hash,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_config;

    const FAKE_HASH: &str = "argon2id-fakehash-for-testing";

    #[test]
    fn test_bastion_preset_parses() {
        let toml = bastion_preset("admin", FAKE_HASH);
        let config = parse_config(&toml).expect("bastion preset should parse");
        assert_eq!(config.users[0].username, "admin");
        assert_eq!(
            config.acl.default_policy,
            crate::config::types::AclPolicyConfig::Deny
        );
        assert!(config.security.ban_enabled);
    }

    #[test]
    fn test_proxy_preset_parses() {
        let toml = proxy_preset("proxy_user", FAKE_HASH);
        let config = parse_config(&toml).expect("proxy preset should parse");
        assert_eq!(config.users[0].username, "proxy_user");
        assert_eq!(
            config.acl.default_policy,
            crate::config::types::AclPolicyConfig::Allow
        );
        assert!(config.server.socks5_listen.is_some());
    }

    #[test]
    fn test_dev_preset_parses() {
        let toml = dev_preset("dev", FAKE_HASH);
        let config = parse_config(&toml).expect("dev preset should parse");
        assert_eq!(config.users[0].username, "dev");
        assert!(!config.security.ban_enabled);
        assert_eq!(config.logging.level, crate::config::types::LogLevel::Debug);
    }
}
