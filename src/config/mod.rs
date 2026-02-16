pub mod acl;
pub mod env;
pub mod presets;
pub mod redact;
pub mod types;

use anyhow::{Context, Result};
use std::path::Path;
use types::AppConfig;

/// Maximum config file size (1 MB)
const MAX_CONFIG_SIZE: u64 = 1_048_576;

/// Load and validate configuration from a TOML file
pub fn load_config(path: &Path) -> Result<AppConfig> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("reading config metadata: {}", path.display()))?;
    if metadata.len() > MAX_CONFIG_SIZE {
        anyhow::bail!(
            "config file too large: {} bytes (max {} bytes)",
            metadata.len(),
            MAX_CONFIG_SIZE
        );
    }

    // Check file permissions on Unix (warn if group/other readable)
    check_config_file_permissions(path);

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading config: {}", path.display()))?;
    parse_config(&content)
}

/// On Unix, warn if the config file is readable by group or others,
/// since it may contain sensitive data (password hashes, API tokens, TOTP secrets).
#[cfg(unix)]
fn check_config_file_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    match std::fs::metadata(path) {
        Ok(meta) => {
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                tracing::warn!(
                    path = %path.display(),
                    mode = format!("{:04o}", mode & 0o7777),
                    "Config file is readable by group/others. \
                     Consider restricting permissions to 0600 (owner read/write only) \
                     since it may contain secrets."
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "Could not check config file permissions"
            );
        }
    }
}

#[cfg(not(unix))]
fn check_config_file_permissions(_path: &Path) {
    // Permission checks are only available on Unix systems
}

/// Parse configuration from a TOML string
pub fn parse_config(content: &str) -> Result<AppConfig> {
    let config: AppConfig = toml::from_str(content).context("parsing TOML configuration")?;
    validate_config(&config)?;
    Ok(config)
}

/// Validate an already-constructed AppConfig (e.g. built from env vars).
pub fn parse_config_validate(config: &AppConfig) -> Result<()> {
    validate_config(config)
}

/// Validate configuration values
fn validate_config(config: &AppConfig) -> Result<()> {
    validate_server(config)?;
    validate_limits(config)?;
    validate_socks5_handshake_timeout(config)?;
    validate_socks5_tls(config)?;
    validate_global_acl(config)?;
    validate_users(config)?;
    validate_api(config)?;
    validate_webhooks(config)?;
    Ok(())
}

fn validate_global_acl(config: &AppConfig) -> Result<()> {
    for rule in &config.acl.allow {
        acl::AclRule::parse(rule).with_context(|| format!("global ACL allow rule: {rule}"))?;
    }
    for rule in &config.acl.deny {
        acl::AclRule::parse(rule).with_context(|| format!("global ACL deny rule: {rule}"))?;
    }

    // Warn operators about permissive default ACL policy
    if config.acl.default_policy == types::AclPolicyConfig::Allow && config.acl.deny.is_empty() {
        tracing::warn!(
            "Global ACL default_policy is 'allow' with no deny rules. \
             All proxy destinations are reachable. Consider setting \
             [acl] default_policy = \"deny\" with explicit allow rules \
             for production deployments."
        );
    }

    // Warn when deny rules are 100% hostname-based (no CIDR) with allow policy.
    // Users can bypass hostname deny rules by sending raw IP addresses.
    if config.acl.default_policy == types::AclPolicyConfig::Allow && !config.acl.deny.is_empty() {
        let all_hostname = config.acl.deny.iter().all(|rule| {
            matches!(
                acl::AclRule::parse(rule),
                Ok(acl::AclRule::HostPattern { .. })
            )
        });
        if all_hostname {
            tracing::warn!(
                "Global ACL deny rules are all hostname-based with default_policy='allow'. \
                 Users can bypass these rules by connecting with raw IP addresses. \
                 Consider using default_policy=\"deny\" with an allow list, \
                 or adding CIDR deny rules for the target IP ranges."
            );
        }
    }

    Ok(())
}

fn validate_server(config: &AppConfig) -> Result<()> {
    if config.server.ssh_listen.is_empty() {
        anyhow::bail!("server.ssh_listen must not be empty");
    }
    if !config.server.server_id.starts_with("SSH-2.0-") {
        anyhow::bail!(
            "server.server_id must start with 'SSH-2.0-' (got '{}')",
            config.server.server_id
        );
    }
    Ok(())
}

fn validate_limits(config: &AppConfig) -> Result<()> {
    if config.limits.connection_timeout == 0 {
        anyhow::bail!("limits.connection_timeout must be > 0");
    }
    if config.security.ban_enabled && config.security.ban_threshold < 1 {
        anyhow::bail!("security.ban_threshold must be >= 1");
    }
    Ok(())
}

fn validate_users(config: &AppConfig) -> Result<()> {
    if config.users.is_empty() {
        anyhow::bail!("at least one user is required");
    }

    let mut seen = std::collections::HashSet::new();
    for user in &config.users {
        if user.username.is_empty() {
            anyhow::bail!("user entry has empty username");
        }
        if user.password_hash.is_none() && user.authorized_keys.is_empty() {
            anyhow::bail!(
                "user '{}' must have at least a password_hash or authorized_keys",
                user.username
            );
        }
        if !seen.insert(&user.username) {
            anyhow::bail!("duplicate username: {}", user.username);
        }

        for rule in &user.acl.allow {
            acl::AclRule::parse(rule)
                .with_context(|| format!("user '{}' ACL allow rule: {}", user.username, rule))?;
        }
        for rule in &user.acl.deny {
            acl::AclRule::parse(rule)
                .with_context(|| format!("user '{}' ACL deny rule: {}", user.username, rule))?;
        }

        // Warn per-user hostname-only deny rules with allow policy
        let effective_policy = user
            .acl
            .default_policy
            .as_ref()
            .unwrap_or(&config.acl.default_policy);
        if *effective_policy == types::AclPolicyConfig::Allow && !user.acl.deny.is_empty() {
            let all_hostname = user.acl.deny.iter().all(|rule| {
                matches!(
                    acl::AclRule::parse(rule),
                    Ok(acl::AclRule::HostPattern { .. })
                )
            });
            if all_hostname {
                tracing::warn!(
                    "User '{}' ACL deny rules are all hostname-based with default_policy='allow'. \
                     Connections using raw IP addresses will bypass these rules.",
                    user.username
                );
            }
        }
    }
    Ok(())
}

fn validate_api(config: &AppConfig) -> Result<()> {
    if config.api.enabled && config.api.token.is_empty() {
        anyhow::bail!("api.token must be set when api is enabled");
    }
    if config.api.enabled && !config.api.token.is_empty() && config.api.token.len() < 16 {
        anyhow::bail!(
            "API token is too short ({} chars, minimum 16)",
            config.api.token.len()
        );
    }
    Ok(())
}

fn validate_webhooks(config: &AppConfig) -> Result<()> {
    for (i, webhook) in config.webhooks.iter().enumerate() {
        let parsed = url::Url::parse(&webhook.url)
            .with_context(|| format!("webhook[{}] invalid URL: {}", i, webhook.url))?;

        let scheme = parsed.scheme();
        if scheme != "http" && scheme != "https" {
            anyhow::bail!(
                "webhook[{}] URL must use http or https scheme: {}",
                i,
                webhook.url
            );
        }

        // P0-1: Check for private/internal IPs unless allow_private_ips is set
        if !webhook.allow_private_ips {
            if let Some(host) = parsed.host_str() {
                // Check obvious localhost names
                if host == "localhost" || host == "0.0.0.0" {
                    anyhow::bail!(
                        "webhook[{}] URL must not point to localhost (set allow_private_ips=true to override): {}",
                        i, webhook.url
                    );
                }
                // Check if host is a direct IP address
                if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    if crate::proxy::ip_guard::is_dangerous_ip(&ip) {
                        let range =
                            crate::proxy::ip_guard::classify_dangerous_ip(&ip).unwrap_or("private");
                        anyhow::bail!(
                            "webhook[{}] URL points to {} IP {} (set allow_private_ips=true to override): {}",
                            i, range, ip, webhook.url
                        );
                    }
                }
                // Check bracketed IPv6
                let trimmed = host.trim_start_matches('[').trim_end_matches(']');
                if trimmed != host {
                    if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
                        if crate::proxy::ip_guard::is_dangerous_ip(&ip) {
                            let range = crate::proxy::ip_guard::classify_dangerous_ip(&ip)
                                .unwrap_or("private");
                            anyhow::bail!(
                                "webhook[{}] URL points to {} IP {} (set allow_private_ips=true to override): {}",
                                i, range, ip, webhook.url
                            );
                        }
                    }
                }
            }
        }

        // Validate webhook format + template
        if webhook.format == types::WebhookFormat::Custom && webhook.template.is_none() {
            anyhow::bail!(
                "webhook[{}] format is 'custom' but no template is provided",
                i
            );
        }
        if webhook.format != types::WebhookFormat::Custom && webhook.template.is_some() {
            tracing::warn!(
                webhook_index = i,
                url = %webhook.url,
                "webhook has template but format is not 'custom' — template will be ignored"
            );
        }
    }
    Ok(())
}

fn validate_socks5_handshake_timeout(config: &AppConfig) -> Result<()> {
    let timeout = config.limits.socks5_handshake_timeout;
    if timeout < 5 {
        anyhow::bail!(
            "limits.socks5_handshake_timeout must be >= 5 (got {})",
            timeout
        );
    }
    if timeout > 120 {
        anyhow::bail!(
            "limits.socks5_handshake_timeout must be <= 120 (got {})",
            timeout
        );
    }
    Ok(())
}

fn validate_socks5_tls(config: &AppConfig) -> Result<()> {
    let has_cert = config.server.socks5_tls_cert.is_some();
    let has_key = config.server.socks5_tls_key.is_some();
    if has_cert != has_key {
        anyhow::bail!("socks5_tls_cert and socks5_tls_key must both be set or both be absent");
    }
    if has_cert {
        let cert_path = config.server.socks5_tls_cert.as_ref().unwrap();
        let key_path = config.server.socks5_tls_key.as_ref().unwrap();
        if !cert_path.exists() {
            anyhow::bail!("socks5_tls_cert not found: {}", cert_path.display());
        }
        if !key_path.exists() {
            anyhow::bail!("socks5_tls_key not found: {}", key_path.display());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAKE_HASH: &str = "argon2id-fakehash-for-testing";

    fn minimal_config(extra: &str) -> String {
        format!(
            r##"
[server]
ssh_listen = "0.0.0.0:2222"
{extra}
"##
        )
    }

    fn user_block(username: &str, extra: &str) -> String {
        format!(
            r#"
[[users]]
username = "{username}"
password_hash = "{FAKE_HASH}"
{extra}
"#,
            FAKE_HASH = FAKE_HASH,
        )
    }

    #[test]
    fn test_parse_minimal_config() {
        let toml = format!("{}{}", minimal_config(""), user_block("test", ""));
        let config = parse_config(&toml).unwrap();
        assert_eq!(config.server.ssh_listen, "0.0.0.0:2222");
        assert!(config.server.socks5_listen.is_none());
        assert_eq!(config.users.len(), 1);
        assert_eq!(config.users[0].username, "test");
    }

    #[test]
    fn test_parse_full_config() {
        let toml = format!(
            r##"
[server]
ssh_listen = "0.0.0.0:2222"
socks5_listen = "0.0.0.0:1080"
server_id = "SSH-2.0-sks5_test"
banner = "Test banner"

[shell]
hostname = "test-host"
prompt = "# "

[limits]
max_connections = 500
max_auth_attempts = 5

[security]
ban_enabled = true
ban_threshold = 3

[logging]
level = "debug"
format = "json"

[metrics]
enabled = true
listen = "127.0.0.1:9090"

[api]
enabled = true
listen = "127.0.0.1:9091"
token = "test-token-long-enough"

[[users]]
username = "alice"
password_hash = "{hash}"
allow_forwarding = true
allow_shell = true

[users.acl]
default_policy = "deny"
allow = ["*.example.com:443", "10.0.0.0/8:*"]
deny = ["169.254.169.254:*"]

[[users]]
username = "bob"
password_hash = "{hash}"
allow_forwarding = true
allow_shell = false

[users.acl]
default_policy = "allow"
deny = ["169.254.169.254:*"]
"##,
            hash = FAKE_HASH,
        );
        let config = parse_config(&toml).unwrap();
        assert_eq!(config.server.socks5_listen.as_deref(), Some("0.0.0.0:1080"));
        assert_eq!(config.shell.hostname, "test-host");
        assert_eq!(config.limits.max_connections, 500);
        assert!(config.security.ban_enabled);
        assert_eq!(config.users.len(), 2);
        assert_eq!(config.users[0].acl.allow.len(), 2);
    }

    #[test]
    fn test_empty_username_rejected() {
        let toml = format!(
            r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = ""
password_hash = "{hash}"
"##,
            hash = FAKE_HASH,
        );
        assert!(parse_config(&toml).is_err());
    }

    #[test]
    fn test_no_auth_method_rejected() {
        let toml = r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "noauth"
"##;
        assert!(parse_config(toml).is_err());
    }

    #[test]
    fn test_duplicate_username_rejected() {
        let toml = format!(
            r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "alice"
password_hash = "{hash}"

[[users]]
username = "alice"
password_hash = "{hash}"
"##,
            hash = FAKE_HASH,
        );
        assert!(parse_config(&toml).is_err());
    }

    #[test]
    fn test_invalid_log_level_rejected() {
        let toml = format!(
            r##"
[server]
ssh_listen = "0.0.0.0:2222"

[logging]
level = "verbose"

[[users]]
username = "test"
password_hash = "{hash}"
"##,
            hash = FAKE_HASH,
        );
        assert!(parse_config(&toml).is_err());
    }

    #[test]
    fn test_invalid_acl_rule_rejected() {
        let toml = format!(
            r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "test"
password_hash = "{hash}"

[users.acl]
default_policy = "deny"
allow = ["host:notaport"]
"##,
            hash = FAKE_HASH,
        );
        assert!(parse_config(&toml).is_err());
    }

    #[test]
    fn test_defaults_applied() {
        let toml = format!("{}{}", minimal_config(""), user_block("test", ""));
        let config = parse_config(&toml).unwrap();
        assert_eq!(config.limits.max_connections, 1000);
        assert_eq!(config.limits.max_auth_attempts, 3);
        assert_eq!(config.limits.connection_timeout, 300);
        assert_eq!(config.limits.idle_timeout, 0);
        assert!(config.security.ban_enabled);
        assert_eq!(config.logging.level, types::LogLevel::Info);
        assert_eq!(config.logging.format, types::LogFormat::Pretty);
    }

    #[test]
    fn test_zero_users_rejected() {
        let toml = r##"
[server]
ssh_listen = "0.0.0.0:2222"
"##;
        assert!(parse_config(toml).is_err());
    }

    #[test]
    fn test_zero_connection_timeout_rejected() {
        let toml = format!(
            r##"
[server]
ssh_listen = "0.0.0.0:2222"

[limits]
connection_timeout = 0

[[users]]
username = "test"
password_hash = "{hash}"
"##,
            hash = FAKE_HASH,
        );
        assert!(parse_config(&toml).is_err());
    }

    #[test]
    fn test_invalid_acl_policy_rejected() {
        let toml = format!(
            r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "test"
password_hash = "{hash}"

[users.acl]
default_policy = "maybe"
"##,
            hash = FAKE_HASH,
        );
        // Serde should reject "maybe" as an invalid AclPolicyConfig variant
        assert!(parse_config(&toml).is_err());
    }

    #[test]
    fn test_port_range_inverted_rejected() {
        let toml = format!(
            r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "test"
password_hash = "{hash}"

[users.acl]
default_policy = "deny"
allow = ["example.com:443-80"]
"##,
            hash = FAKE_HASH,
        );
        assert!(parse_config(&toml).is_err());
    }

    #[test]
    fn test_invalid_server_id_rejected() {
        let toml = format!(
            r##"
[server]
ssh_listen = "0.0.0.0:2222"
server_id = "OpenSSH_9.2p1"

[[users]]
username = "test"
password_hash = "{hash}"
"##,
            hash = FAKE_HASH,
        );
        let err = parse_config(&toml).unwrap_err();
        assert!(
            err.to_string().contains("SSH-2.0-"),
            "error should mention SSH-2.0- prefix: {}",
            err
        );
    }

    #[test]
    fn test_valid_server_id_accepted() {
        let toml = format!(
            r##"
[server]
ssh_listen = "0.0.0.0:2222"
server_id = "SSH-2.0-OpenSSH_9.2p1"

[[users]]
username = "test"
password_hash = "{hash}"
"##,
            hash = FAKE_HASH,
        );
        assert!(parse_config(&toml).is_ok());
    }

    #[test]
    fn test_invalid_log_format_rejected() {
        let toml = format!(
            r##"
[server]
ssh_listen = "0.0.0.0:2222"

[logging]
format = "xml"

[[users]]
username = "test"
password_hash = "{hash}"
"##,
            hash = FAKE_HASH,
        );
        assert!(parse_config(&toml).is_err());
    }
}
