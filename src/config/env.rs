//! Environment variable configuration support.
//!
//! Provides three modes:
//! 1. `SKS5_CONFIG` env var to specify config file path
//! 2. Full config from env vars (single-user Docker mode)
//! 3. Hybrid: file + env var overrides

use crate::config::types::*;
use std::collections::HashMap;
use std::path::PathBuf;

/// Check if enough env vars are set to build a full config without a file.
/// Requires at minimum: SKS5_SSH_LISTEN + auth credentials (single or multi-user).
pub fn can_build_from_env() -> bool {
    let has_ssh = std::env::var("SKS5_SSH_LISTEN").is_ok();
    if !has_ssh {
        return false;
    }
    // Multi-user indexed mode
    if std::env::var("SKS5_USER_0_USERNAME").is_ok() {
        return true;
    }
    // Single-user mode
    std::env::var("SKS5_PASSWORD_HASH").is_ok()
        || std::env::var("SKS5_PASSWORD_HASH_FILE").is_ok()
        || std::env::var("SKS5_AUTHORIZED_KEYS").is_ok()
}

/// Build a complete AppConfig from environment variables.
/// Supports both single-user (flat vars) and multi-user (indexed SKS5_USER_<N>_*) modes.
pub fn build_config_from_env() -> anyhow::Result<AppConfig> {
    let ssh_listen = require_env("SKS5_SSH_LISTEN")?;

    // Determine user list: multi-user indexed mode vs single-user flat mode
    let users = if std::env::var("SKS5_USER_0_USERNAME").is_ok() {
        collect_indexed_users()?
    } else {
        vec![build_single_user_from_env()?]
    };

    let mut config = AppConfig {
        server: ServerConfig {
            ssh_listen,
            socks5_listen: opt_env("SKS5_SOCKS5_LISTEN"),
            host_key_path: opt_env("SKS5_HOST_KEY_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("host_key")),
            server_id: opt_env("SKS5_SERVER_ID").unwrap_or_else(|| "SSH-2.0-sks5".to_string()),
            banner: opt_env("SKS5_BANNER").unwrap_or_else(|| "Welcome to sks5".to_string()),
            motd_path: opt_env("SKS5_MOTD_PATH").map(PathBuf::from),
            proxy_protocol: parse_bool_env("SKS5_PROXY_PROTOCOL", false),
            allowed_ciphers: parse_csv_env("SKS5_ALLOWED_CIPHERS"),
            allowed_kex: parse_csv_env("SKS5_ALLOWED_KEX"),
            shutdown_timeout: parse_env("SKS5_SHUTDOWN_TIMEOUT", 30),
            socks5_tls_cert: opt_env("SKS5_SOCKS5_TLS_CERT").map(PathBuf::from),
            socks5_tls_key: opt_env("SKS5_SOCKS5_TLS_KEY").map(PathBuf::from),
            dns_cache_ttl: parse_env("SKS5_DNS_CACHE_TTL", -1),
            dns_cache_max_entries: parse_env("SKS5_DNS_CACHE_MAX_ENTRIES", 1000),
            connect_retry: parse_env("SKS5_CONNECT_RETRY", 0),
            connect_retry_delay_ms: parse_env("SKS5_CONNECT_RETRY_DELAY_MS", 1000),
            bookmarks_path: opt_env("SKS5_BOOKMARKS_PATH").map(PathBuf::from),
            ssh_keepalive_interval_secs: parse_env("SKS5_SSH_KEEPALIVE_INTERVAL", 15),
            ssh_keepalive_max: parse_env("SKS5_SSH_KEEPALIVE_MAX", 3),
            ssh_auth_timeout: parse_env("SKS5_SSH_AUTH_TIMEOUT", 120),
        },
        shell: ShellConfig {
            hostname: opt_env("SKS5_SHELL_HOSTNAME").unwrap_or_else(|| "sks5-proxy".to_string()),
            prompt: opt_env("SKS5_SHELL_PROMPT").unwrap_or_else(|| "$ ".to_string()),
            colors: parse_bool_env("SKS5_SHELL_COLORS", true),
            autocomplete: parse_bool_env("SKS5_SHELL_AUTOCOMPLETE", true),
        },
        limits: LimitsConfig {
            max_connections: parse_env("SKS5_MAX_CONNECTIONS", 1000),
            max_connections_per_user: parse_env("SKS5_MAX_CONNECTIONS_PER_USER", 0),
            connection_timeout: parse_env("SKS5_CONNECTION_TIMEOUT", 300),
            idle_timeout: parse_env("SKS5_IDLE_TIMEOUT", 0),
            max_auth_attempts: parse_env("SKS5_MAX_AUTH_ATTEMPTS", 3),
            socks5_handshake_timeout: parse_env("SKS5_SOCKS5_HANDSHAKE_TIMEOUT", 30),
            idle_warning_secs: parse_env("SKS5_IDLE_WARNING_SECS", 0),
            max_bandwidth_mbps: parse_env("SKS5_MAX_BANDWIDTH_MBPS", 0),
            max_new_connections_per_second: parse_env("SKS5_MAX_NEW_CONNECTIONS_PER_SECOND", 0),
            max_new_connections_per_minute: parse_env(
                "SKS5_MAX_NEW_CONNECTIONS_PER_MINUTE_SERVER",
                0,
            ),
            udp_relay_timeout: parse_env("SKS5_UDP_RELAY_TIMEOUT", 300),
            max_udp_sessions_per_user: parse_env("SKS5_MAX_UDP_SESSIONS_PER_USER", 0),
        },
        security: SecurityConfig {
            allowed_source_ips: opt_env("SKS5_ALLOWED_SOURCE_IPS")
                .map(|s| {
                    s.split(',')
                        .filter(|v| !v.trim().is_empty())
                        .map(|v| v.trim().parse())
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()
                .map_err(|e| anyhow::anyhow!("invalid SKS5_ALLOWED_SOURCE_IPS: {e}"))?
                .unwrap_or_default(),
            ban_enabled: parse_bool_env("SKS5_BAN_ENABLED", true),
            ban_threshold: parse_env("SKS5_BAN_THRESHOLD", 5),
            ban_window: parse_env("SKS5_BAN_WINDOW", 300),
            ban_duration: parse_env("SKS5_BAN_DURATION", 900),
            ban_whitelist: parse_csv_env("SKS5_BAN_WHITELIST"),
            ip_guard_enabled: parse_bool_env("SKS5_IP_GUARD_ENABLED", true),
            totp_required_for: parse_csv_env("SKS5_TOTP_REQUIRED_FOR"),
            max_new_connections_per_ip_per_minute: parse_env(
                "SKS5_MAX_NEW_CONNECTIONS_PER_IP_PER_MINUTE",
                0,
            ),
            ip_reputation_enabled: parse_bool_env("SKS5_IP_REPUTATION_ENABLED", false),
            ip_reputation_ban_threshold: parse_env("SKS5_IP_REPUTATION_BAN_THRESHOLD", 100),
            trusted_user_ca_keys: parse_csv_env("SKS5_TRUSTED_USER_CA_KEYS"),
            argon2_memory_cost: parse_env("SKS5_ARGON2_MEMORY_COST", 19456),
            argon2_time_cost: parse_env("SKS5_ARGON2_TIME_COST", 2),
            argon2_parallelism: parse_env("SKS5_ARGON2_PARALLELISM", 1),
            rate_limit_cleanup_interval: parse_env("SKS5_RATE_LIMIT_CLEANUP_INTERVAL", 60),
            rate_limit_max_ips: parse_env("SKS5_RATE_LIMIT_MAX_IPS", 100_000),
            rate_limit_max_users: parse_env("SKS5_RATE_LIMIT_MAX_USERS", 10_000),
        },
        logging: LoggingConfig {
            level: opt_env("SKS5_LOG_LEVEL")
                .map(|s| parse_log_level(&s))
                .transpose()?
                .unwrap_or(LogLevel::Info),
            format: opt_env("SKS5_LOG_FORMAT")
                .map(|s| parse_log_format(&s))
                .transpose()?
                .unwrap_or(LogFormat::Pretty),
            audit_log_path: opt_env("SKS5_AUDIT_LOG_PATH").map(PathBuf::from),
            audit_max_size_mb: parse_env("SKS5_AUDIT_MAX_SIZE_MB", 100),
            audit_max_files: parse_env("SKS5_AUDIT_MAX_FILES", 5),
            connection_flow_logs: parse_bool_env("SKS5_CONNECTION_FLOW_LOGS", false),
            log_denied_connections: parse_bool_env("SKS5_LOG_DENIED_CONNECTIONS", true),
        },
        metrics: MetricsConfig {
            enabled: parse_bool_env("SKS5_METRICS_ENABLED", false),
            listen: opt_env("SKS5_METRICS_LISTEN").unwrap_or_else(|| "127.0.0.1:9090".to_string()),
            max_metric_labels: parse_env("SKS5_MAX_METRIC_LABELS", 100),
        },
        api: ApiConfig {
            enabled: parse_bool_env("SKS5_API_ENABLED", false),
            listen: opt_env("SKS5_API_LISTEN").unwrap_or_else(|| "127.0.0.1:9091".to_string()),
            token: resolve_env_or_file("SKS5_API_TOKEN")?.unwrap_or_default(),
        },
        geoip: GeoIpConfig {
            enabled: parse_bool_env("SKS5_GEOIP_ENABLED", false),
            database_path: opt_env("SKS5_GEOIP_DATABASE_PATH").map(PathBuf::from),
            allowed_countries: parse_csv_env("SKS5_GEOIP_ALLOWED_COUNTRIES"),
            denied_countries: parse_csv_env("SKS5_GEOIP_DENIED_COUNTRIES"),
            fail_closed: parse_bool_env("SKS5_GEOIP_FAIL_CLOSED", false),
        },
        upstream_proxy: opt_env("SKS5_UPSTREAM_PROXY_URL").map(|url| UpstreamProxyConfig { url }),
        webhooks: Vec::new(),
        acl: GlobalAclConfig {
            default_policy: opt_env("SKS5_GLOBAL_ACL_DEFAULT_POLICY")
                .map(|s| parse_acl_policy(&s))
                .transpose()?
                .unwrap_or(AclPolicyConfig::Allow),
            allow: parse_csv_env("SKS5_GLOBAL_ACL_ALLOW"),
            deny: parse_csv_env("SKS5_GLOBAL_ACL_DENY"),
        },
        users,
        groups: Vec::new(),
        motd: MotdConfig::default(),
        alerting: AlertingConfig::default(),
        maintenance_windows: Vec::new(),
        connection_pool: ConnectionPoolConfig::default(),
        persistence: Default::default(),
    };

    // Apply persistence config from env
    apply_persistence_env(&mut config);

    // Clear sensitive env vars from the process environment after reading them.
    // This reduces the window in which secrets are visible via /proc/pid/environ.
    clear_sensitive_env_vars();

    Ok(config)
}

/// Build a UserConfig from env vars with the given prefix.
/// For single-user mode, prefix is "SKS5_", for indexed mode it's "SKS5_USER_N_".
fn build_user_config(
    prefix: &str,
    username: String,
    password_hash: Option<String>,
    authorized_keys: Vec<String>,
) -> anyhow::Result<UserConfig> {
    Ok(UserConfig {
        username,
        password_hash,
        authorized_keys,
        allow_forwarding: parse_bool_env(&format!("{prefix}ALLOW_FORWARDING"), true),
        allow_shell: opt_env(&format!("{prefix}ALLOW_SHELL"))
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "true" | "1" | "yes")),
        max_new_connections_per_minute: parse_env(
            &format!("{prefix}MAX_NEW_CONNECTIONS_PER_MINUTE"),
            0,
        ),
        max_bandwidth_kbps: parse_env(&format!("{prefix}MAX_BANDWIDTH_KBPS"), 0),
        max_aggregate_bandwidth_kbps: parse_env(
            &format!("{prefix}MAX_AGGREGATE_BANDWIDTH_KBPS"),
            0,
        ),
        source_ips: parse_cidr_csv_env(&format!("{prefix}SOURCE_IPS"))?,
        expires_at: opt_env(&format!("{prefix}EXPIRES_AT")),
        upstream_proxy: opt_env(&format!("{prefix}UPSTREAM_PROXY")),
        acl: UserAclConfig {
            default_policy: opt_env(&format!("{prefix}ACL_DEFAULT_POLICY"))
                .map(|s| parse_acl_policy(&s))
                .transpose()?,
            allow: parse_csv_env(&format!("{prefix}ACL_ALLOW")),
            deny: parse_csv_env(&format!("{prefix}ACL_DENY")),
            inherit: parse_bool_env(&format!("{prefix}ACL_INHERIT"), true),
        },
        totp_secret: resolve_env_or_file(&format!("{prefix}TOTP_SECRET"))?,
        totp_enabled: parse_bool_env(&format!("{prefix}TOTP_ENABLED"), false),
        group: opt_env(&format!("{prefix}GROUP")),
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
        max_connections: opt_env(&format!("{prefix}MAX_CONNECTIONS"))
            .map(|v| v.parse().unwrap_or(0)),
        rate_limits: build_rate_limits_from_env(&format!("{prefix}RATE_LIMIT")),
    })
}

/// Build a single user from flat env vars (backward-compatible mode).
fn build_single_user_from_env() -> anyhow::Result<UserConfig> {
    let password_hash = resolve_env_or_file("SKS5_PASSWORD_HASH")?;
    let authorized_keys_str = opt_env("SKS5_AUTHORIZED_KEYS");

    if password_hash.is_none() && authorized_keys_str.is_none() {
        anyhow::bail!(
            "env var config requires SKS5_PASSWORD_HASH or SKS5_AUTHORIZED_KEYS (or both)"
        );
    }

    let authorized_keys = authorized_keys_str
        .map(|s| s.split(',').map(|k| k.trim().to_string()).collect())
        .unwrap_or_default();

    let username = opt_env("SKS5_USERNAME").unwrap_or_else(|| "user".to_string());

    // Single-user mode uses "SKS5_" prefix (with some legacy names)
    let mut user = build_user_config("SKS5_", username, password_hash, authorized_keys)?;
    // Legacy: single-user upstream proxy uses a different env name
    if user.upstream_proxy.is_none() {
        user.upstream_proxy = opt_env("SKS5_USER_UPSTREAM_PROXY");
    }
    // Legacy: single-user max_connections uses different key
    if user.max_connections.is_none() {
        user.max_connections = opt_env("SKS5_MAX_CONNECTIONS_USER").map(|v| v.parse().unwrap_or(0));
    }
    Ok(user)
}

/// Collect indexed users from SKS5_USER_0_*, SKS5_USER_1_*, etc.
/// Stops at the first missing index.
fn collect_indexed_users() -> anyhow::Result<Vec<UserConfig>> {
    let mut users = Vec::new();
    for idx in 0u32.. {
        let prefix = format!("SKS5_USER_{idx}_");
        let username_key = format!("{prefix}USERNAME");

        let Some(username) = opt_env(&username_key) else {
            break;
        };

        let password_hash = resolve_env_or_file(&format!("{prefix}PASSWORD_HASH"))?;
        let authorized_keys_str = opt_env(&format!("{prefix}AUTHORIZED_KEYS"));

        if password_hash.is_none() && authorized_keys_str.is_none() {
            anyhow::bail!("user #{idx} ({username}) requires PASSWORD_HASH or AUTHORIZED_KEYS");
        }

        let authorized_keys = authorized_keys_str
            .map(|s| s.split(',').map(|k| k.trim().to_string()).collect())
            .unwrap_or_default();

        users.push(build_user_config(
            &prefix,
            username,
            password_hash,
            authorized_keys,
        )?);
    }

    if users.is_empty() {
        anyhow::bail!("SKS5_USER_0_USERNAME is set but no valid indexed users found");
    }

    Ok(users)
}

/// Build optional RateLimitsConfig from env vars with a given prefix.
/// e.g. prefix="SKS5_RATE_LIMIT" -> SKS5_RATE_LIMIT_PER_SECOND, SKS5_RATE_LIMIT_PER_MINUTE, SKS5_RATE_LIMIT_PER_HOUR
fn build_rate_limits_from_env(prefix: &str) -> Option<RateLimitsConfig> {
    let per_sec_key = format!("{prefix}_PER_SECOND");
    let per_min_key = format!("{prefix}_PER_MINUTE");
    let per_hour_key = format!("{prefix}_PER_HOUR");

    let per_sec = opt_env(&per_sec_key);
    let per_min = opt_env(&per_min_key);
    let per_hour = opt_env(&per_hour_key);

    if per_sec.is_none() && per_min.is_none() && per_hour.is_none() {
        return None;
    }

    Some(RateLimitsConfig {
        connections_per_second: per_sec.and_then(|v| v.parse().ok()).unwrap_or(0),
        connections_per_minute: per_min.and_then(|v| v.parse().ok()).unwrap_or(0),
        connections_per_hour: per_hour.and_then(|v| v.parse().ok()).unwrap_or(0),
    })
}

/// Apply environment variable overrides to an existing config (hybrid mode).
/// Only overrides values for which an env var is set. Supports _FILE convention.
pub fn apply_env_overrides(config: &mut AppConfig) {
    // Server overrides
    if let Some(v) = opt_env("SKS5_SSH_LISTEN") {
        config.server.ssh_listen = v;
    }
    if let Some(v) = opt_env("SKS5_SOCKS5_LISTEN") {
        config.server.socks5_listen = Some(v);
    }
    if let Some(v) = opt_env("SKS5_HOST_KEY_PATH") {
        config.server.host_key_path = PathBuf::from(v);
    }
    if let Some(v) = opt_env("SKS5_BANNER") {
        config.server.banner = v;
    }
    if std::env::var("SKS5_PROXY_PROTOCOL").is_ok() {
        config.server.proxy_protocol = parse_bool_env("SKS5_PROXY_PROTOCOL", false);
    }

    // SOCKS5 handshake timeout override
    if std::env::var("SKS5_SOCKS5_HANDSHAKE_TIMEOUT").is_ok() {
        config.limits.socks5_handshake_timeout = parse_env(
            "SKS5_SOCKS5_HANDSHAKE_TIMEOUT",
            config.limits.socks5_handshake_timeout,
        );
    }

    // Logging overrides
    if let Some(v) = opt_env("SKS5_LOG_LEVEL") {
        if let Ok(level) = parse_log_level(&v) {
            config.logging.level = level;
        }
    }
    if let Some(v) = opt_env("SKS5_LOG_FORMAT") {
        if let Ok(format) = parse_log_format(&v) {
            config.logging.format = format;
        }
    }

    // Limits overrides
    if std::env::var("SKS5_MAX_CONNECTIONS").is_ok() {
        config.limits.max_connections =
            parse_env("SKS5_MAX_CONNECTIONS", config.limits.max_connections);
    }
    if std::env::var("SKS5_MAX_CONNECTIONS_PER_USER").is_ok() {
        config.limits.max_connections_per_user = parse_env(
            "SKS5_MAX_CONNECTIONS_PER_USER",
            config.limits.max_connections_per_user,
        );
    }
    if std::env::var("SKS5_CONNECTION_TIMEOUT").is_ok() {
        config.limits.connection_timeout =
            parse_env("SKS5_CONNECTION_TIMEOUT", config.limits.connection_timeout);
    }
    if std::env::var("SKS5_IDLE_TIMEOUT").is_ok() {
        config.limits.idle_timeout = parse_env("SKS5_IDLE_TIMEOUT", config.limits.idle_timeout);
    }
    if std::env::var("SKS5_MAX_BANDWIDTH_MBPS").is_ok() {
        config.limits.max_bandwidth_mbps =
            parse_env("SKS5_MAX_BANDWIDTH_MBPS", config.limits.max_bandwidth_mbps);
    }
    if std::env::var("SKS5_MAX_NEW_CONNECTIONS_PER_SECOND").is_ok() {
        config.limits.max_new_connections_per_second = parse_env(
            "SKS5_MAX_NEW_CONNECTIONS_PER_SECOND",
            config.limits.max_new_connections_per_second,
        );
    }
    if std::env::var("SKS5_MAX_NEW_CONNECTIONS_PER_MINUTE_SERVER").is_ok() {
        config.limits.max_new_connections_per_minute = parse_env(
            "SKS5_MAX_NEW_CONNECTIONS_PER_MINUTE_SERVER",
            config.limits.max_new_connections_per_minute,
        );
    }

    // Security overrides
    if std::env::var("SKS5_BAN_ENABLED").is_ok() {
        config.security.ban_enabled =
            parse_bool_env("SKS5_BAN_ENABLED", config.security.ban_enabled);
    }
    if std::env::var("SKS5_BAN_THRESHOLD").is_ok() {
        config.security.ban_threshold =
            parse_env("SKS5_BAN_THRESHOLD", config.security.ban_threshold);
    }

    // Rate limiter overrides
    if std::env::var("SKS5_RATE_LIMIT_CLEANUP_INTERVAL").is_ok() {
        config.security.rate_limit_cleanup_interval = parse_env(
            "SKS5_RATE_LIMIT_CLEANUP_INTERVAL",
            config.security.rate_limit_cleanup_interval,
        );
    }
    if std::env::var("SKS5_RATE_LIMIT_MAX_IPS").is_ok() {
        config.security.rate_limit_max_ips = parse_env(
            "SKS5_RATE_LIMIT_MAX_IPS",
            config.security.rate_limit_max_ips,
        );
    }
    if std::env::var("SKS5_RATE_LIMIT_MAX_USERS").is_ok() {
        config.security.rate_limit_max_users = parse_env(
            "SKS5_RATE_LIMIT_MAX_USERS",
            config.security.rate_limit_max_users,
        );
    }

    // Argon2 parameter overrides
    if std::env::var("SKS5_ARGON2_MEMORY_COST").is_ok() {
        config.security.argon2_memory_cost = parse_env(
            "SKS5_ARGON2_MEMORY_COST",
            config.security.argon2_memory_cost,
        );
    }
    if std::env::var("SKS5_ARGON2_TIME_COST").is_ok() {
        config.security.argon2_time_cost =
            parse_env("SKS5_ARGON2_TIME_COST", config.security.argon2_time_cost);
    }
    if std::env::var("SKS5_ARGON2_PARALLELISM").is_ok() {
        config.security.argon2_parallelism = parse_env(
            "SKS5_ARGON2_PARALLELISM",
            config.security.argon2_parallelism,
        );
    }

    // API overrides (useful for injecting tokens without putting them in config files)
    // Supports _FILE convention for Docker/K8s secrets
    if let Ok(Some(v)) = resolve_env_or_file("SKS5_API_TOKEN") {
        config.api.token = v;
    }
    if std::env::var("SKS5_API_ENABLED").is_ok() {
        config.api.enabled = parse_bool_env("SKS5_API_ENABLED", config.api.enabled);
    }
    if let Some(v) = opt_env("SKS5_API_LISTEN") {
        config.api.listen = v;
    }

    // Metrics overrides
    if std::env::var("SKS5_METRICS_ENABLED").is_ok() {
        config.metrics.enabled = parse_bool_env("SKS5_METRICS_ENABLED", config.metrics.enabled);
    }
    if let Some(v) = opt_env("SKS5_METRICS_LISTEN") {
        config.metrics.listen = v;
    }

    // Persistence overrides
    apply_persistence_env(config);

    // Global ACL overrides
    if let Some(v) = opt_env("SKS5_GLOBAL_ACL_DEFAULT_POLICY") {
        if let Ok(policy) = parse_acl_policy(&v) {
            config.acl.default_policy = policy;
        }
    }
    if std::env::var("SKS5_GLOBAL_ACL_ALLOW").is_ok() {
        config.acl.allow = parse_csv_env("SKS5_GLOBAL_ACL_ALLOW");
    }
    if std::env::var("SKS5_GLOBAL_ACL_DENY").is_ok() {
        config.acl.deny = parse_csv_env("SKS5_GLOBAL_ACL_DENY");
    }
}

/// Clear sensitive environment variables from the process after they have been read.
/// This limits exposure via /proc/pid/environ or similar process inspection.
/// Covers: PASSWORD_HASH, API_TOKEN, TOTP_SECRET and their _FILE and indexed variants.
fn clear_sensitive_env_vars() {
    let sensitive_suffixes = [
        "PASSWORD_HASH",
        "PASSWORD_HASH_FILE",
        "API_TOKEN",
        "API_TOKEN_FILE",
        "TOTP_SECRET",
        "TOTP_SECRET_FILE",
    ];

    // Clear single-user flat vars
    for suffix in &sensitive_suffixes {
        let key = format!("SKS5_{suffix}");
        if std::env::var_os(&key).is_some() {
            // SAFETY: We only remove env vars that we own (SKS5_* namespace).
            // There is an inherent race if other threads read these concurrently,
            // but this is best-effort defense-in-depth and happens at startup.
            unsafe {
                std::env::remove_var(&key);
            }
        }
    }

    // Clear indexed multi-user vars
    for idx in 0u32.. {
        let prefix = format!("SKS5_USER_{idx}_");
        // Stop when we reach an index with no USERNAME
        if std::env::var_os(format!("{prefix}USERNAME")).is_none() {
            break;
        }
        for suffix in &sensitive_suffixes {
            let key = format!("{prefix}{suffix}");
            if std::env::var_os(&key).is_some() {
                unsafe {
                    std::env::remove_var(&key);
                }
            }
        }
    }
}

/// Apply persistence-related environment variable overrides.
fn apply_persistence_env(config: &mut AppConfig) {
    if let Some(v) = opt_env("SKS5_DATA_DIR") {
        config.persistence.data_dir = Some(PathBuf::from(v));
    }

    // State persistence
    if std::env::var("SKS5_STATE_PERSIST_ENABLED").is_ok() {
        config.persistence.state.enabled = parse_bool_env(
            "SKS5_STATE_PERSIST_ENABLED",
            config.persistence.state.enabled,
        );
    }
    if std::env::var("SKS5_STATE_FLUSH_INTERVAL").is_ok() {
        config.persistence.state.flush_interval_secs = parse_env(
            "SKS5_STATE_FLUSH_INTERVAL",
            config.persistence.state.flush_interval_secs,
        );
    }
    if std::env::var("SKS5_STATE_IP_REP_MIN_SCORE").is_ok() {
        config.persistence.state.ip_reputation_min_score = parse_env(
            "SKS5_STATE_IP_REP_MIN_SCORE",
            config.persistence.state.ip_reputation_min_score,
        );
    }
    if std::env::var("SKS5_STATE_IP_REP_FLUSH_INTERVAL").is_ok() {
        config.persistence.state.ip_reputation_flush_interval_secs = parse_env(
            "SKS5_STATE_IP_REP_FLUSH_INTERVAL",
            config.persistence.state.ip_reputation_flush_interval_secs,
        );
    }
    if std::env::var("SKS5_STATE_INACTIVE_USER_DAYS").is_ok() {
        config.persistence.state.inactive_user_retention_days = parse_env(
            "SKS5_STATE_INACTIVE_USER_DAYS",
            config.persistence.state.inactive_user_retention_days,
        );
    }

    // User data persistence
    if std::env::var("SKS5_USERDATA_ENABLED").is_ok() {
        config.persistence.userdata.enabled =
            parse_bool_env("SKS5_USERDATA_ENABLED", config.persistence.userdata.enabled);
    }
    if std::env::var("SKS5_SHELL_HISTORY_MAX").is_ok() {
        config.persistence.userdata.shell_history_max = parse_env(
            "SKS5_SHELL_HISTORY_MAX",
            config.persistence.userdata.shell_history_max,
        );
    }
    if std::env::var("SKS5_SHELL_HISTORY_FLUSH_SECS").is_ok() {
        config.persistence.userdata.shell_history_flush_secs = parse_env(
            "SKS5_SHELL_HISTORY_FLUSH_SECS",
            config.persistence.userdata.shell_history_flush_secs,
        );
    }
    if std::env::var("SKS5_BOOKMARKS_MAX").is_ok() {
        config.persistence.userdata.bookmarks_max = parse_env(
            "SKS5_BOOKMARKS_MAX",
            config.persistence.userdata.bookmarks_max,
        );
    }
    if std::env::var("SKS5_USERDATA_INACTIVE_DAYS").is_ok() {
        config.persistence.userdata.inactive_retention_days = parse_env(
            "SKS5_USERDATA_INACTIVE_DAYS",
            config.persistence.userdata.inactive_retention_days,
        );
    }

    // Config history
    if std::env::var("SKS5_CONFIG_HISTORY_ENABLED").is_ok() {
        config.persistence.config_history.enabled = parse_bool_env(
            "SKS5_CONFIG_HISTORY_ENABLED",
            config.persistence.config_history.enabled,
        );
    }
    if std::env::var("SKS5_CONFIG_HISTORY_MAX").is_ok() {
        config.persistence.config_history.max_entries = parse_env(
            "SKS5_CONFIG_HISTORY_MAX",
            config.persistence.config_history.max_entries,
        );
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn opt_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// Resolve a value from an env var, with _FILE fallback for Docker/K8s secrets.
/// Priority: direct env var > _FILE (read file content, trimmed) > None.
fn resolve_env_or_file(key: &str) -> anyhow::Result<Option<String>> {
    if let Some(val) = opt_env(key) {
        return Ok(Some(val));
    }
    let file_key = format!("{key}_FILE");
    if let Some(path) = opt_env(&file_key) {
        let content = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("reading {file_key}={path}: {e}"))?;
        let trimmed = content.trim().to_string();
        if trimmed.is_empty() {
            anyhow::bail!("{file_key}={path} is empty");
        }
        return Ok(Some(trimmed));
    }
    Ok(None)
}

fn require_env(key: &str) -> anyhow::Result<String> {
    opt_env(key).ok_or_else(|| anyhow::anyhow!("required env var {key} is not set"))
}

fn parse_env<T: std::str::FromStr + Copy>(key: &str, default: T) -> T {
    opt_env(key).and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn parse_bool_env(key: &str, default: bool) -> bool {
    opt_env(key)
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "true" | "1" | "yes"))
        .unwrap_or(default)
}

fn parse_csv_env(key: &str) -> Vec<String> {
    opt_env(key)
        .map(|s| {
            s.split(',')
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn parse_cidr_csv_env(key: &str) -> anyhow::Result<Vec<ipnet::IpNet>> {
    opt_env(key)
        .map(|s| {
            s.split(',')
                .filter(|v| !v.trim().is_empty())
                .map(|v| v.trim().parse())
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()
        .map_err(|e| anyhow::anyhow!("invalid {key}: {e}"))
        .map(|v| v.unwrap_or_default())
}

fn parse_acl_policy(s: &str) -> anyhow::Result<AclPolicyConfig> {
    match s.to_ascii_lowercase().as_str() {
        "allow" => Ok(AclPolicyConfig::Allow),
        "deny" => Ok(AclPolicyConfig::Deny),
        _ => anyhow::bail!("invalid ACL policy: '{s}' (expected 'allow' or 'deny')"),
    }
}

fn parse_log_level(s: &str) -> anyhow::Result<LogLevel> {
    match s.to_ascii_lowercase().as_str() {
        "trace" => Ok(LogLevel::Trace),
        "debug" => Ok(LogLevel::Debug),
        "info" => Ok(LogLevel::Info),
        "warn" => Ok(LogLevel::Warn),
        "error" => Ok(LogLevel::Error),
        _ => anyhow::bail!("invalid log level: '{s}'"),
    }
}

fn parse_log_format(s: &str) -> anyhow::Result<LogFormat> {
    match s.to_ascii_lowercase().as_str() {
        "pretty" => Ok(LogFormat::Pretty),
        "json" => Ok(LogFormat::Json),
        _ => anyhow::bail!("invalid log format: '{s}'"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Env var tests must run serially since they mutate process state
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_env_vars<F: FnOnce()>(vars: &[(&str, &str)], f: F) {
        let _lock = ENV_LOCK.lock().unwrap();
        // Set vars
        for (k, v) in vars {
            std::env::set_var(k, v);
        }
        f();
        // Clean up
        for (k, _) in vars {
            std::env::remove_var(k);
        }
        // Also clean up common vars that might leak
        for key in [
            "SKS5_SSH_LISTEN",
            "SKS5_PASSWORD_HASH",
            "SKS5_PASSWORD_HASH_FILE",
            "SKS5_AUTHORIZED_KEYS",
            "SKS5_USERNAME",
            "SKS5_SOCKS5_LISTEN",
            "SKS5_LOG_LEVEL",
            "SKS5_LOG_FORMAT",
            "SKS5_ACL_DEFAULT_POLICY",
            "SKS5_ACL_ALLOW",
            "SKS5_ACL_DENY",
            "SKS5_API_TOKEN",
            "SKS5_API_TOKEN_FILE",
            "SKS5_API_ENABLED",
            "SKS5_METRICS_ENABLED",
            "SKS5_BAN_ENABLED",
            "SKS5_GLOBAL_ACL_DEFAULT_POLICY",
            "SKS5_GLOBAL_ACL_ALLOW",
            "SKS5_GLOBAL_ACL_DENY",
            "SKS5_TOTP_SECRET",
            "SKS5_TOTP_SECRET_FILE",
            "SKS5_USER_0_USERNAME",
            "SKS5_USER_0_PASSWORD_HASH",
            "SKS5_USER_0_PASSWORD_HASH_FILE",
            "SKS5_USER_0_AUTHORIZED_KEYS",
            "SKS5_USER_0_ALLOW_SHELL",
            "SKS5_USER_0_ACL_DEFAULT_POLICY",
            "SKS5_USER_0_ACL_ALLOW",
            "SKS5_USER_1_USERNAME",
            "SKS5_USER_1_PASSWORD_HASH",
            "SKS5_USER_1_ALLOW_FORWARDING",
            "SKS5_USER_1_ALLOW_SHELL",
            "SKS5_ARGON2_MEMORY_COST",
            "SKS5_ARGON2_TIME_COST",
            "SKS5_ARGON2_PARALLELISM",
        ] {
            std::env::remove_var(key);
        }
    }

    #[test]
    fn test_can_build_from_env_false_when_empty() {
        with_env_vars(&[], || {
            assert!(!can_build_from_env());
        });
    }

    #[test]
    fn test_can_build_from_env_true_with_password() {
        with_env_vars(
            &[
                ("SKS5_SSH_LISTEN", "0.0.0.0:2222"),
                ("SKS5_PASSWORD_HASH", "argon2id-fake"),
            ],
            || {
                assert!(can_build_from_env());
            },
        );
    }

    #[test]
    fn test_can_build_from_env_true_with_keys() {
        with_env_vars(
            &[
                ("SKS5_SSH_LISTEN", "0.0.0.0:2222"),
                ("SKS5_AUTHORIZED_KEYS", "ssh-ed25519 AAAA..."),
            ],
            || {
                assert!(can_build_from_env());
            },
        );
    }

    #[test]
    fn test_build_config_minimal() {
        with_env_vars(
            &[
                ("SKS5_SSH_LISTEN", "0.0.0.0:2222"),
                ("SKS5_PASSWORD_HASH", "argon2id-fake"),
            ],
            || {
                let config = build_config_from_env().unwrap();
                assert_eq!(config.server.ssh_listen, "0.0.0.0:2222");
                assert!(config.server.socks5_listen.is_none());
                assert_eq!(config.users.len(), 1);
                assert_eq!(config.users[0].username, "user"); // default
                assert_eq!(
                    config.users[0].password_hash.as_deref(),
                    Some("argon2id-fake")
                );
            },
        );
    }

    #[test]
    fn test_build_config_full() {
        with_env_vars(
            &[
                ("SKS5_SSH_LISTEN", "0.0.0.0:2222"),
                ("SKS5_SOCKS5_LISTEN", "0.0.0.0:1080"),
                ("SKS5_USERNAME", "alice"),
                ("SKS5_PASSWORD_HASH", "argon2id-fake"),
                ("SKS5_LOG_LEVEL", "debug"),
                ("SKS5_LOG_FORMAT", "json"),
                ("SKS5_ACL_DEFAULT_POLICY", "deny"),
                ("SKS5_ACL_ALLOW", "*.example.com:443,api.github.com:443"),
                ("SKS5_ACL_DENY", "evil.com:*"),
                ("SKS5_GLOBAL_ACL_DENY", "169.254.169.254:*"),
            ],
            || {
                let config = build_config_from_env().unwrap();
                assert_eq!(config.server.ssh_listen, "0.0.0.0:2222");
                assert_eq!(config.server.socks5_listen.as_deref(), Some("0.0.0.0:1080"));
                assert_eq!(config.users[0].username, "alice");
                assert_eq!(config.logging.level, LogLevel::Debug);
                assert_eq!(config.logging.format, LogFormat::Json);
                assert_eq!(
                    config.users[0].acl.default_policy,
                    Some(AclPolicyConfig::Deny)
                );
                assert_eq!(config.users[0].acl.allow.len(), 2);
                assert_eq!(config.users[0].acl.deny.len(), 1);
                assert_eq!(config.acl.deny.len(), 1);
            },
        );
    }

    #[test]
    fn test_build_config_missing_auth_fails() {
        with_env_vars(&[("SKS5_SSH_LISTEN", "0.0.0.0:2222")], || {
            let result = build_config_from_env();
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_apply_env_overrides() {
        with_env_vars(
            &[
                ("SKS5_LOG_LEVEL", "debug"),
                ("SKS5_API_TOKEN", "secret-from-env"),
                ("SKS5_GLOBAL_ACL_DENY", "10.0.0.0/8:*"),
            ],
            || {
                let toml_str = r##"
[server]
ssh_listen = "0.0.0.0:2222"

[api]
enabled = true
listen = "127.0.0.1:9091"
token = "old-token"

[[users]]
username = "test"
password_hash = "argon2id-fake"
"##;
                let mut config: AppConfig = toml::from_str(toml_str).unwrap();
                apply_env_overrides(&mut config);

                assert_eq!(config.logging.level, LogLevel::Debug);
                assert_eq!(config.api.token, "secret-from-env");
                assert_eq!(config.acl.deny, vec!["10.0.0.0/8:*".to_string()]);
            },
        );
    }

    #[test]
    fn test_parse_csv_env_empty() {
        with_env_vars(&[], || {
            assert!(parse_csv_env("SKS5_NONEXISTENT").is_empty());
        });
    }

    #[test]
    fn test_parse_bool_env_variants() {
        with_env_vars(&[("SKS5_TEST_BOOL", "true")], || {
            assert!(parse_bool_env("SKS5_TEST_BOOL", false));
        });
        with_env_vars(&[("SKS5_TEST_BOOL", "1")], || {
            assert!(parse_bool_env("SKS5_TEST_BOOL", false));
        });
        with_env_vars(&[("SKS5_TEST_BOOL", "yes")], || {
            assert!(parse_bool_env("SKS5_TEST_BOOL", false));
        });
        with_env_vars(&[("SKS5_TEST_BOOL", "false")], || {
            assert!(!parse_bool_env("SKS5_TEST_BOOL", true));
        });
        with_env_vars(&[("SKS5_TEST_BOOL", "0")], || {
            assert!(!parse_bool_env("SKS5_TEST_BOOL", true));
        });
    }

    // --- Multi-user indexed tests ---

    #[test]
    fn test_can_build_from_env_multiuser() {
        with_env_vars(
            &[
                ("SKS5_SSH_LISTEN", "0.0.0.0:2222"),
                ("SKS5_USER_0_USERNAME", "alice"),
                ("SKS5_USER_0_PASSWORD_HASH", "argon2id-fake"),
            ],
            || {
                assert!(can_build_from_env());
            },
        );
    }

    #[test]
    fn test_build_config_multiuser_two_users() {
        with_env_vars(
            &[
                ("SKS5_SSH_LISTEN", "0.0.0.0:2222"),
                ("SKS5_USER_0_USERNAME", "alice"),
                ("SKS5_USER_0_PASSWORD_HASH", "argon2id-fake-alice"),
                ("SKS5_USER_0_ALLOW_SHELL", "true"),
                ("SKS5_USER_0_ACL_DEFAULT_POLICY", "deny"),
                ("SKS5_USER_0_ACL_ALLOW", "*.example.com:443"),
                ("SKS5_USER_1_USERNAME", "bob"),
                ("SKS5_USER_1_PASSWORD_HASH", "argon2id-fake-bob"),
                ("SKS5_USER_1_ALLOW_FORWARDING", "false"),
                ("SKS5_USER_1_ALLOW_SHELL", "false"),
            ],
            || {
                let config = build_config_from_env().unwrap();
                assert_eq!(config.users.len(), 2);
                assert_eq!(config.users[0].username, "alice");
                assert_eq!(
                    config.users[0].password_hash.as_deref(),
                    Some("argon2id-fake-alice")
                );
                assert_eq!(
                    config.users[0].acl.default_policy,
                    Some(AclPolicyConfig::Deny)
                );
                assert_eq!(config.users[0].acl.allow, vec!["*.example.com:443"]);
                assert_eq!(config.users[0].allow_shell, Some(true));

                assert_eq!(config.users[1].username, "bob");
                assert!(!config.users[1].allow_forwarding);
                assert_eq!(config.users[1].allow_shell, Some(false));
            },
        );
    }

    #[test]
    fn test_build_config_multiuser_stops_at_gap() {
        with_env_vars(
            &[
                ("SKS5_SSH_LISTEN", "0.0.0.0:2222"),
                ("SKS5_USER_0_USERNAME", "alice"),
                ("SKS5_USER_0_PASSWORD_HASH", "argon2id-fake"),
                // SKS5_USER_1_USERNAME is missing → only 1 user
            ],
            || {
                let config = build_config_from_env().unwrap();
                assert_eq!(config.users.len(), 1);
                assert_eq!(config.users[0].username, "alice");
            },
        );
    }

    #[test]
    fn test_build_config_multiuser_no_auth_fails() {
        with_env_vars(
            &[
                ("SKS5_SSH_LISTEN", "0.0.0.0:2222"),
                ("SKS5_USER_0_USERNAME", "alice"),
                // No PASSWORD_HASH or AUTHORIZED_KEYS
            ],
            || {
                let result = build_config_from_env();
                assert!(result.is_err());
                let err = result.unwrap_err().to_string();
                assert!(
                    err.contains("alice"),
                    "error should mention username: {err}"
                );
            },
        );
    }

    #[test]
    fn test_build_config_multiuser_with_keys() {
        with_env_vars(
            &[
                ("SKS5_SSH_LISTEN", "0.0.0.0:2222"),
                ("SKS5_USER_0_USERNAME", "charlie"),
                (
                    "SKS5_USER_0_AUTHORIZED_KEYS",
                    "ssh-ed25519 AAAA1,ssh-ed25519 AAAA2",
                ),
            ],
            || {
                let config = build_config_from_env().unwrap();
                assert_eq!(config.users[0].username, "charlie");
                assert!(config.users[0].password_hash.is_none());
                assert_eq!(config.users[0].authorized_keys.len(), 2);
            },
        );
    }

    #[test]
    fn test_multiuser_ignores_flat_vars() {
        // When SKS5_USER_0_USERNAME exists, flat vars (SKS5_USERNAME etc.) are ignored
        with_env_vars(
            &[
                ("SKS5_SSH_LISTEN", "0.0.0.0:2222"),
                ("SKS5_USERNAME", "flat-user"),
                ("SKS5_PASSWORD_HASH", "flat-hash"),
                ("SKS5_USER_0_USERNAME", "indexed-alice"),
                ("SKS5_USER_0_PASSWORD_HASH", "indexed-hash"),
            ],
            || {
                let config = build_config_from_env().unwrap();
                assert_eq!(config.users.len(), 1);
                assert_eq!(config.users[0].username, "indexed-alice");
            },
        );
    }

    // --- _FILE convention tests ---

    #[test]
    fn test_resolve_env_or_file_direct() {
        with_env_vars(&[("SKS5_API_TOKEN", "direct-value")], || {
            let result = resolve_env_or_file("SKS5_API_TOKEN").unwrap();
            assert_eq!(result.as_deref(), Some("direct-value"));
        });
    }

    #[test]
    fn test_resolve_env_or_file_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let secret_path = dir.path().join("secret.txt");
        std::fs::write(&secret_path, "  file-secret-value  \n").unwrap();

        with_env_vars(
            &[("SKS5_API_TOKEN_FILE", secret_path.to_str().unwrap())],
            || {
                let result = resolve_env_or_file("SKS5_API_TOKEN").unwrap();
                assert_eq!(result.as_deref(), Some("file-secret-value"));
            },
        );
    }

    #[test]
    fn test_resolve_env_or_file_direct_takes_priority() {
        let dir = tempfile::tempdir().unwrap();
        let secret_path = dir.path().join("secret.txt");
        std::fs::write(&secret_path, "file-value").unwrap();

        with_env_vars(
            &[
                ("SKS5_API_TOKEN", "direct-value"),
                ("SKS5_API_TOKEN_FILE", secret_path.to_str().unwrap()),
            ],
            || {
                let result = resolve_env_or_file("SKS5_API_TOKEN").unwrap();
                assert_eq!(result.as_deref(), Some("direct-value"));
            },
        );
    }

    #[test]
    fn test_resolve_env_or_file_missing_file_fails() {
        with_env_vars(
            &[("SKS5_API_TOKEN_FILE", "/nonexistent/path/secret.txt")],
            || {
                let result = resolve_env_or_file("SKS5_API_TOKEN");
                assert!(result.is_err());
            },
        );
    }

    #[test]
    fn test_build_config_password_hash_file() {
        let dir = tempfile::tempdir().unwrap();
        let hash_path = dir.path().join("hash.txt");
        std::fs::write(&hash_path, "argon2id-from-file\n").unwrap();

        with_env_vars(
            &[
                ("SKS5_SSH_LISTEN", "0.0.0.0:2222"),
                ("SKS5_PASSWORD_HASH_FILE", hash_path.to_str().unwrap()),
            ],
            || {
                let config = build_config_from_env().unwrap();
                assert_eq!(
                    config.users[0].password_hash.as_deref(),
                    Some("argon2id-from-file")
                );
            },
        );
    }

    #[test]
    fn test_can_build_from_env_with_password_hash_file() {
        let dir = tempfile::tempdir().unwrap();
        let hash_path = dir.path().join("hash.txt");
        std::fs::write(&hash_path, "argon2id-from-file").unwrap();

        with_env_vars(
            &[
                ("SKS5_SSH_LISTEN", "0.0.0.0:2222"),
                ("SKS5_PASSWORD_HASH_FILE", hash_path.to_str().unwrap()),
            ],
            || {
                assert!(can_build_from_env());
            },
        );
    }

    #[test]
    fn test_multiuser_password_hash_file() {
        let dir = tempfile::tempdir().unwrap();
        let hash_path = dir.path().join("alice_hash.txt");
        std::fs::write(&hash_path, "argon2id-alice-from-file\n").unwrap();

        with_env_vars(
            &[
                ("SKS5_SSH_LISTEN", "0.0.0.0:2222"),
                ("SKS5_USER_0_USERNAME", "alice"),
                (
                    "SKS5_USER_0_PASSWORD_HASH_FILE",
                    hash_path.to_str().unwrap(),
                ),
            ],
            || {
                let config = build_config_from_env().unwrap();
                assert_eq!(config.users[0].username, "alice");
                assert_eq!(
                    config.users[0].password_hash.as_deref(),
                    Some("argon2id-alice-from-file")
                );
            },
        );
    }
}
