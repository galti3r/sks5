mod advanced;
pub mod helpers;
mod monitoring;
mod security;
mod server;
mod users;

use anyhow::{bail, Result};
use dialoguer::Select;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::config::types::*;

/// Section names and their display labels for the menu.
const SECTION_LABELS: &[&str] = &[
    "Server",
    "Users",
    "Security",
    "ACL",
    "API",
    "Metrics",
    "Logging",
    "Groups",
    "GeoIP",
    "Webhooks",
    "Alerting",
    "Maintenance",
    "Pool",
    "Upstream",
];

/// Number of configurable sections.
const NUM_SECTIONS: usize = 14;

/// Run the interactive wizard and return a fully built AppConfig.
///
/// If `non_interactive` is true, all defaults are used (no TTY required).
pub fn run_wizard(non_interactive: bool) -> Result<AppConfig> {
    if non_interactive {
        return build_non_interactive_config();
    }

    if !helpers::is_tty() {
        bail!(
            "stdin is not a terminal. Use --non-interactive for non-TTY environments, \
             or pipe input from a terminal."
        );
    }

    let mut config = AppConfig {
        server: ServerConfig {
            ssh_listen: "0.0.0.0:2222".to_string(),
            socks5_listen: Some("0.0.0.0:1080".to_string()),
            host_key_path: PathBuf::from("host_key"),
            server_id: "SSH-2.0-sks5".to_string(),
            banner: "Welcome to sks5".to_string(),
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
        },
        shell: ShellConfig::default(),
        limits: LimitsConfig::default(),
        security: SecurityConfig::default(),
        logging: LoggingConfig::default(),
        metrics: MetricsConfig::default(),
        api: ApiConfig::default(),
        geoip: GeoIpConfig::default(),
        upstream_proxy: None,
        webhooks: Vec::new(),
        acl: GlobalAclConfig::default(),
        users: Vec::new(),
        groups: Vec::new(),
        motd: MotdConfig::default(),
        alerting: AlertingConfig::default(),
        maintenance_windows: Vec::new(),
        connection_pool: ConnectionPoolConfig::default(),
    };

    // Track which sections have been configured by the user.
    let mut configured = [false; NUM_SECTIONS];

    loop {
        // Print the menu header.
        eprintln!();
        eprintln!("  sks5 configuration wizard");
        eprintln!("  =========================");
        eprintln!();

        // Build menu items with status indicators.
        let mut items: Vec<String> = Vec::with_capacity(NUM_SECTIONS + 1);
        for (i, label) in SECTION_LABELS.iter().enumerate() {
            let check = if configured[i] { "x" } else { " " };
            let status = section_status(&config, i);
            items.push(format!(
                "[{check}] {:2}. {:<12} \u{2014} {status}",
                i + 1,
                label
            ));
        }
        items.push("\u{2500}\u{2500}\u{2500} Save & Exit \u{2500}\u{2500}\u{2500}".to_string());

        let selection = Select::new()
            .with_prompt("Select a section to configure")
            .items(&items)
            .default(0)
            .interact()?;

        // "Save & Exit" is the last item.
        if selection == NUM_SECTIONS {
            break;
        }

        // Route to the appropriate section prompt.
        match selection {
            0 => server::prompt_server_section(&mut config)?,
            1 => users::prompt_users_section(&mut config)?,
            2 => security::prompt_security_section(&mut config)?,
            3 => security::prompt_acl_section(&mut config)?,
            4 => monitoring::prompt_api_section(&mut config)?,
            5 => monitoring::prompt_metrics_section(&mut config)?,
            6 => monitoring::prompt_logging_section(&mut config)?,
            7 => advanced::prompt_groups_section(&mut config)?,
            8 => advanced::prompt_geoip_section(&mut config)?,
            9 => advanced::prompt_webhooks_section(&mut config)?,
            10 => advanced::prompt_alerting_section(&mut config)?,
            11 => advanced::prompt_maintenance_section(&mut config)?,
            12 => advanced::prompt_connection_pool_section(&mut config)?,
            13 => advanced::prompt_upstream_proxy_section(&mut config)?,
            _ => unreachable!(),
        }

        configured[selection] = true;
    }

    Ok(config)
}

/// Serialize the config to TOML with a comment header.
pub fn config_to_toml(config: &AppConfig) -> Result<String> {
    let toml = toml::to_string_pretty(config)?;
    Ok(format!(
        "# sks5 configuration \u{2014} generated by `sks5 wizard`\n\
         # Documentation: https://github.com/galti3r/sks5\n\
         \n\
         {toml}"
    ))
}

/// Build a non-interactive config with sensible defaults.
fn build_non_interactive_config() -> Result<AppConfig> {
    let password = crate::auth::password::generate_password(20);
    let password_hash = crate::auth::password::hash_password(&password)?;

    eprintln!("Generated credentials (non-interactive mode):");
    eprintln!("  Username: user");
    eprintln!("  Password: {password}");
    eprintln!();

    Ok(AppConfig {
        server: ServerConfig {
            ssh_listen: "0.0.0.0:2222".to_string(),
            socks5_listen: Some("0.0.0.0:1080".to_string()),
            host_key_path: PathBuf::from("host_key"),
            server_id: "SSH-2.0-sks5".to_string(),
            banner: "Welcome to sks5".to_string(),
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
        },
        shell: ShellConfig::default(),
        limits: LimitsConfig::default(),
        security: SecurityConfig::default(),
        logging: LoggingConfig::default(),
        metrics: MetricsConfig::default(),
        api: ApiConfig::default(),
        geoip: GeoIpConfig::default(),
        upstream_proxy: None,
        webhooks: Vec::new(),
        acl: GlobalAclConfig::default(),
        users: vec![default_user("user", password_hash)],
        groups: Vec::new(),
        motd: MotdConfig::default(),
        alerting: AlertingConfig::default(),
        maintenance_windows: Vec::new(),
        connection_pool: ConnectionPoolConfig::default(),
    })
}

/// Create a UserConfig with sensible defaults.
pub(crate) fn default_user(username: &str, password_hash: String) -> UserConfig {
    UserConfig {
        username: username.to_string(),
        password_hash: Some(password_hash),
        authorized_keys: Vec::new(),
        allow_forwarding: true,
        allow_shell: Some(true),
        max_new_connections_per_minute: 0,
        max_bandwidth_kbps: 0,
        source_ips: Vec::new(),
        expires_at: None,
        upstream_proxy: None,
        acl: UserAclConfig::default(),
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
    }
}

// ---------------------------------------------------------------------------
// Status line for each section (shown in the menu)
// ---------------------------------------------------------------------------

/// Return a short status string describing the current state of a section.
fn section_status(config: &AppConfig, idx: usize) -> String {
    match idx {
        // 1. Server
        0 => {
            let socks = config.server.socks5_listen.as_deref().unwrap_or("disabled");
            format!("SSH: {}, SOCKS5: {}", config.server.ssh_listen, socks)
        }
        // 2. Users
        1 => {
            let n = config.users.len();
            if n == 0 {
                "0 users configured".to_string()
            } else {
                let names: Vec<&str> = config.users.iter().map(|u| u.username.as_str()).collect();
                format!("{} user(s): {}", n, names.join(", "))
            }
        }
        // 3. Security
        2 => {
            let ban = if config.security.ban_enabled {
                "on"
            } else {
                "off"
            };
            let ip_guard = if config.security.ip_guard_enabled {
                "on"
            } else {
                "off"
            };
            format!("ban: {}, ip_guard: {}", ban, ip_guard)
        }
        // 4. ACL
        3 => {
            format!(
                "policy: {}, {} deny, {} allow",
                config.acl.default_policy,
                config.acl.deny.len(),
                config.acl.allow.len()
            )
        }
        // 5. API
        4 => {
            if config.api.enabled {
                config.api.listen.to_string()
            } else {
                "disabled".to_string()
            }
        }
        // 6. Metrics
        5 => {
            if config.metrics.enabled {
                config.metrics.listen.to_string()
            } else {
                "disabled".to_string()
            }
        }
        // 7. Logging
        6 => {
            format!("{}, {}", config.logging.level, config.logging.format)
        }
        // 8. Groups
        7 => {
            let n = config.groups.len();
            format!("{} group(s)", n)
        }
        // 9. GeoIP
        8 => {
            if config.geoip.enabled {
                let db = config
                    .geoip
                    .database_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "no db".to_string());
                format!("enabled ({})", db)
            } else {
                "disabled".to_string()
            }
        }
        // 10. Webhooks
        9 => {
            format!("{} webhook(s)", config.webhooks.len())
        }
        // 11. Alerting
        10 => {
            if config.alerting.enabled {
                format!("{} rule(s)", config.alerting.rules.len())
            } else {
                "disabled".to_string()
            }
        }
        // 12. Maintenance
        11 => {
            format!("{} window(s)", config.maintenance_windows.len())
        }
        // 13. Pool
        12 => {
            if config.connection_pool.enabled {
                format!(
                    "max_idle: {}, ttl: {}s",
                    config.connection_pool.max_idle_per_host,
                    config.connection_pool.idle_timeout_secs
                )
            } else {
                "disabled".to_string()
            }
        }
        // 14. Upstream
        13 => {
            if let Some(ref up) = config.upstream_proxy {
                up.url.clone()
            } else {
                "disabled".to_string()
            }
        }
        _ => "?".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    #[test]
    fn test_non_interactive_produces_valid_config() {
        let config = build_non_interactive_config().expect("non-interactive config should build");
        assert_eq!(config.server.ssh_listen, "0.0.0.0:2222");
        assert_eq!(config.users.len(), 1);
        assert_eq!(config.users[0].username, "user");
        assert!(config.users[0].password_hash.is_some());
        config::parse_config_validate(&config).expect("config should validate");
    }

    #[test]
    fn test_non_interactive_config_serializes_to_valid_toml() {
        let config = build_non_interactive_config().expect("non-interactive config should build");
        let toml_str = config_to_toml(&config).expect("should serialize to TOML");
        assert!(toml_str.contains("[server]"));
        assert!(toml_str.contains("[[users]]"));
        assert!(toml_str.contains("ssh_listen"));
        let reparsed: AppConfig = toml::from_str(&toml_str).expect("generated TOML should reparse");
        assert_eq!(reparsed.server.ssh_listen, "0.0.0.0:2222");
        assert_eq!(reparsed.users.len(), 1);
    }

    #[test]
    fn test_default_user_has_correct_defaults() {
        let user = default_user("alice", "hash123".to_string());
        assert_eq!(user.username, "alice");
        assert_eq!(user.password_hash, Some("hash123".to_string()));
        assert!(user.allow_forwarding);
        assert_eq!(user.allow_shell, Some(true));
        assert_eq!(user.role, UserRole::User);
        assert!(user.group.is_none());
    }
}
