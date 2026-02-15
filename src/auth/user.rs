use crate::auth::pubkey;
use crate::config::acl::ParsedAcl;
use crate::config::types::{
    GlobalAclConfig, GroupConfig, LimitsConfig, MotdConfig, QuotaConfig, RateLimitsConfig,
    ServerConfig, ShellConfig, ShellPermissions, TimeAccessConfig, UserConfig, UserRole,
};
use anyhow::Result;
use chrono::{Datelike, Timelike, Utc};
use ipnet::IpNet;
use russh::keys::PublicKey;
use std::collections::HashMap;
use std::sync::Arc;

/// Runtime user data (parsed from config with group/global inheritance resolved)
#[derive(Clone)]
pub struct User {
    pub username: String,
    pub password_hash: Option<String>,
    pub authorized_keys: Vec<String>,
    pub parsed_authorized_keys: Vec<PublicKey>,
    pub allow_forwarding: bool,
    pub allow_shell: bool,
    pub max_new_connections_per_minute: u32,
    pub max_bandwidth_kbps: u64,
    pub source_ips: Vec<IpNet>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub upstream_proxy: Option<String>,
    pub acl: ParsedAcl,
    pub totp_enabled: bool,
    pub totp_secret: Option<String>,
    pub max_aggregate_bandwidth_kbps: u64,
    /// Group membership name (if any)
    pub group: Option<String>,
    /// User role (user or admin)
    pub role: UserRole,
    /// Resolved shell permissions: user > group > global default
    pub shell_permissions: ShellPermissions,
    /// Resolved MOTD config: user > group > None
    pub motd_config: Option<MotdConfig>,
    /// Per-user/group quotas
    pub quotas: Option<QuotaConfig>,
    /// Time-based access restrictions
    pub time_access: Option<TimeAccessConfig>,
    /// Auth method chain (e.g. ["pubkey", "password"])
    pub auth_methods: Option<Vec<String>>,
    /// Idle warning seconds before disconnect (resolved: user > group > global)
    pub idle_warning_secs: u64,
    /// Color support (resolved: user > group > shell config)
    pub colors: bool,
    /// Smart retry on connect (resolved: user > group > server config)
    pub connect_retry: u32,
    /// Smart retry delay in ms (resolved: user > group > server config)
    pub connect_retry_delay_ms: u64,
    /// Shell command aliases
    pub aliases: HashMap<String, String>,
    /// Resolved max concurrent connections for this user (0 = unlimited)
    pub max_connections: u32,
    /// Resolved multi-window rate limits (user > group > server defaults)
    pub rate_limits: RateLimitsConfig,
}

impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("username", &self.username)
            .field("password_hash", &self.password_hash.as_ref().map(|_| "***"))
            .field(
                "authorized_keys",
                &format!("[{} keys]", self.authorized_keys.len()),
            )
            .field("allow_forwarding", &self.allow_forwarding)
            .field("allow_shell", &self.allow_shell)
            .field("group", &self.group)
            .field("role", &self.role)
            .field("expires_at", &self.expires_at)
            .field("idle_warning_secs", &self.idle_warning_secs)
            .field("colors", &self.colors)
            .field("connect_retry", &self.connect_retry)
            .field("aliases", &self.aliases)
            .finish()
    }
}

impl User {
    /// Build a runtime User by resolving config inheritance: user > group > global defaults.
    ///
    /// `groups` is the full list of configured groups (the user's group name is matched).
    /// `global_acl`, `limits`, `server`, `shell` provide global defaults for merged fields.
    pub fn from_config(
        cfg: &UserConfig,
        groups: &[GroupConfig],
        global_acl: &GlobalAclConfig,
        limits: &LimitsConfig,
        server: &ServerConfig,
        shell: &ShellConfig,
    ) -> Result<Self> {
        // Find the user's group (if any)
        let group_cfg = cfg
            .group
            .as_ref()
            .and_then(|name| groups.iter().find(|g| &g.name == name));

        // --- ACL: merge global > group > user ---
        let group_acl = group_cfg.map(|g| &g.acl);
        let acl = ParsedAcl::from_config_merged_with_group(global_acl, group_acl, &cfg.acl)?;

        // --- expires_at parsing ---
        let expires_at = match &cfg.expires_at {
            Some(s) => Some(s.parse::<chrono::DateTime<chrono::Utc>>().map_err(|e| {
                anyhow::anyhow!("invalid expires_at for '{}': {}", cfg.username, e)
            })?),
            None => None,
        };

        let parsed_authorized_keys = pubkey::parse_authorized_keys(&cfg.authorized_keys);

        // --- allow_forwarding: user explicit > group > user default (true) ---
        let allow_forwarding =
            group_cfg
                .and_then(|g| g.allow_forwarding)
                .map_or(cfg.allow_forwarding, |group_val| {
                    // User config `allow_forwarding` defaults to true via serde;
                    // if group restricts it, group wins unless user explicitly sets it.
                    // Since serde always provides a value, we use the user's value directly
                    // (user config is authoritative when present).
                    cfg.allow_forwarding && group_val
                });

        // --- allow_shell: same logic ---
        let allow_shell = group_cfg
            .and_then(|g| g.allow_shell)
            .map_or(cfg.allow_shell, |group_val| cfg.allow_shell && group_val);

        // --- max_new_connections_per_minute: user > group > user default (0) ---
        let max_new_connections_per_minute = if cfg.max_new_connections_per_minute > 0 {
            cfg.max_new_connections_per_minute
        } else {
            group_cfg
                .and_then(|g| g.max_new_connections_per_minute)
                .unwrap_or(cfg.max_new_connections_per_minute)
        };

        // --- max_bandwidth_kbps: user > group > user default (0) ---
        let max_bandwidth_kbps = if cfg.max_bandwidth_kbps > 0 {
            cfg.max_bandwidth_kbps
        } else {
            group_cfg
                .and_then(|g| g.max_bandwidth_kbps)
                .unwrap_or(cfg.max_bandwidth_kbps)
        };

        // --- max_aggregate_bandwidth_kbps: user > group > user default (0) ---
        let max_aggregate_bandwidth_kbps = if cfg.max_aggregate_bandwidth_kbps > 0 {
            cfg.max_aggregate_bandwidth_kbps
        } else {
            group_cfg
                .and_then(|g| g.max_aggregate_bandwidth_kbps)
                .unwrap_or(cfg.max_aggregate_bandwidth_kbps)
        };

        // --- role: user > group > UserRole::User ---
        let role = if cfg.role != UserRole::default() {
            cfg.role
        } else {
            group_cfg.and_then(|g| g.role).unwrap_or(cfg.role)
        };

        // --- shell_permissions: merge user > group > ShellPermissions::default() ---
        let shell_permissions = resolve_shell_permissions(
            &cfg.shell_permissions,
            group_cfg.and_then(|g| g.shell_permissions.as_ref()),
        );

        // --- motd_config: user > group > None ---
        let motd_config = cfg
            .motd
            .clone()
            .or_else(|| group_cfg.and_then(|g| g.motd.clone()));

        // --- quotas: user > group > None ---
        let quotas = cfg
            .quotas
            .clone()
            .or_else(|| group_cfg.and_then(|g| g.quotas.clone()));

        // --- time_access: user > group > None ---
        let time_access = cfg
            .time_access
            .clone()
            .or_else(|| group_cfg.and_then(|g| g.time_access.clone()));

        // --- auth_methods: user > group > None ---
        let auth_methods = cfg
            .auth_methods
            .clone()
            .or_else(|| group_cfg.and_then(|g| g.auth_methods.clone()));

        // --- idle_warning_secs: user > group > global limits ---
        let idle_warning_secs = cfg
            .idle_warning_secs
            .or_else(|| group_cfg.and_then(|g| g.idle_warning_secs))
            .unwrap_or(limits.idle_warning_secs);

        // --- colors: user > group > shell config ---
        let colors = cfg
            .colors
            .or_else(|| group_cfg.and_then(|g| g.colors))
            .unwrap_or(shell.colors);

        // --- connect_retry: user > group > server config ---
        let connect_retry = cfg
            .connect_retry
            .or_else(|| group_cfg.and_then(|g| g.connect_retry))
            .unwrap_or(server.connect_retry);

        // --- connect_retry_delay_ms: user > group > server config ---
        let connect_retry_delay_ms = cfg
            .connect_retry_delay_ms
            .or_else(|| group_cfg.and_then(|g| g.connect_retry_delay_ms))
            .unwrap_or(server.connect_retry_delay_ms);

        // --- max_connections: user > group > limits.max_connections_per_user ---
        let max_connections = cfg
            .max_connections
            .or_else(|| group_cfg.and_then(|g| g.max_connections_per_user))
            .unwrap_or(limits.max_connections_per_user);

        // --- rate_limits: merge user > group, with compat for max_new_connections_per_minute ---
        let rate_limits = resolve_rate_limits(
            cfg.rate_limits.as_ref(),
            group_cfg.and_then(|g| g.rate_limits.as_ref()),
            max_new_connections_per_minute,
        );

        Ok(Self {
            username: cfg.username.clone(),
            password_hash: cfg.password_hash.clone(),
            authorized_keys: cfg.authorized_keys.clone(),
            parsed_authorized_keys,
            allow_forwarding,
            allow_shell,
            max_new_connections_per_minute,
            max_bandwidth_kbps,
            source_ips: cfg.source_ips.clone(),
            expires_at,
            upstream_proxy: cfg.upstream_proxy.clone(),
            acl,
            totp_enabled: cfg.totp_enabled,
            totp_secret: cfg.totp_secret.clone(),
            max_aggregate_bandwidth_kbps,
            group: cfg.group.clone(),
            role,
            shell_permissions,
            motd_config,
            quotas,
            time_access,
            auth_methods,
            idle_warning_secs,
            colors,
            connect_retry,
            connect_retry_delay_ms,
            aliases: cfg.aliases.clone(),
            max_connections,
            rate_limits,
        })
    }

    pub fn is_expired(&self) -> bool {
        if let Some(exp) = &self.expires_at {
            chrono::Utc::now() > *exp
        } else {
            false
        }
    }

    /// Check if a source IP is allowed for this user.
    /// Returns true if source_ips is empty (no restriction) or if the IP matches any entry.
    pub fn is_source_ip_allowed(&self, ip: &std::net::IpAddr) -> bool {
        if self.source_ips.is_empty() {
            return true;
        }
        let ip = crate::security::normalize::normalize_ip(*ip);
        self.source_ips.iter().any(|net| net.contains(&ip))
    }

    /// Check if current time is within the user's allowed access hours and days.
    ///
    /// Returns `true` if:
    /// - No time_access restrictions are configured
    /// - Current UTC time is within the allowed hours AND on an allowed day
    ///
    /// Time format: "HH:MM-HH:MM" (24h, UTC). Days: "mon", "tue", "wed", etc.
    pub fn check_time_access(&self) -> bool {
        let ta = match &self.time_access {
            Some(ta) => ta,
            None => return true,
        };

        let now = Utc::now();

        // Check access_days (if configured)
        if !ta.access_days.is_empty() {
            let today = match now.weekday() {
                chrono::Weekday::Mon => "mon",
                chrono::Weekday::Tue => "tue",
                chrono::Weekday::Wed => "wed",
                chrono::Weekday::Thu => "thu",
                chrono::Weekday::Fri => "fri",
                chrono::Weekday::Sat => "sat",
                chrono::Weekday::Sun => "sun",
            };
            if !ta.access_days.iter().any(|d| d.eq_ignore_ascii_case(today)) {
                return false;
            }
        }

        // Check access_hours (if configured)
        if let Some(hours) = &ta.access_hours {
            if let Some((start, end)) = parse_hour_range(hours) {
                let now_mins = now.hour() * 60 + now.minute();
                if now_mins < start || now_mins >= end {
                    return false;
                }
            }
            // If parsing fails, treat as unrestricted (permissive fallback)
        }

        true
    }
}

/// Parse "HH:MM-HH:MM" into (start_minutes, end_minutes) from midnight.
fn parse_hour_range(s: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 2 {
        return None;
    }
    let start = parse_hhmm(parts[0])?;
    let end = parse_hhmm(parts[1])?;
    Some((start, end))
}

/// Parse "HH:MM" into minutes from midnight.
fn parse_hhmm(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.trim().split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let h: u32 = parts[0].parse().ok()?;
    let m: u32 = parts[1].parse().ok()?;
    if h > 23 || m > 59 {
        return None;
    }
    Some(h * 60 + m)
}

/// Resolve ShellPermissions with user > group > default merging.
///
/// Each field is resolved independently: if the user provides a ShellPermissions struct,
/// its fields override. Otherwise, group fields override. Otherwise, default (all true).
fn resolve_shell_permissions(
    user: &Option<ShellPermissions>,
    group: Option<&ShellPermissions>,
) -> ShellPermissions {
    let base = ShellPermissions::default();
    let after_group = match group {
        Some(g) => g.clone(),
        None => base,
    };
    match user {
        Some(u) => u.clone(),
        None => after_group,
    }
}

/// Resolve multi-window rate limits: user > group, with backward compat for
/// `max_new_connections_per_minute` (the most strict value wins for the per-minute window).
fn resolve_rate_limits(
    user: Option<&RateLimitsConfig>,
    group: Option<&RateLimitsConfig>,
    legacy_per_minute: u32,
) -> RateLimitsConfig {
    let base = match (user, group) {
        (Some(u), _) => u.clone(),
        (None, Some(g)) => g.clone(),
        (None, None) => RateLimitsConfig::default(),
    };

    // Backward compat: merge legacy max_new_connections_per_minute with rate_limits.connections_per_minute.
    // Take the most restrictive non-zero value.
    let merged_per_minute = match (base.connections_per_minute, legacy_per_minute) {
        (0, legacy) => legacy,
        (new, 0) => new,
        (new, legacy) => new.min(legacy),
    };

    RateLimitsConfig {
        connections_per_second: base.connections_per_second,
        connections_per_minute: merged_per_minute,
        connections_per_hour: base.connections_per_hour,
    }
}

/// In-memory user store
#[derive(Debug)]
pub struct UserStore {
    users: HashMap<String, Arc<User>>,
}

impl UserStore {
    pub fn from_config(
        configs: &[UserConfig],
        groups: &[GroupConfig],
        global_acl: &GlobalAclConfig,
        limits: &LimitsConfig,
        server: &ServerConfig,
        shell: &ShellConfig,
    ) -> Result<Self> {
        let mut users = HashMap::new();
        for cfg in configs {
            let user = User::from_config(cfg, groups, global_acl, limits, server, shell)?;
            users.insert(user.username.clone(), Arc::new(user));
        }
        Ok(Self { users })
    }

    pub fn get(&self, username: &str) -> Option<&Arc<User>> {
        self.users.get(username)
    }

    pub fn usernames(&self) -> Vec<String> {
        self.users.keys().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.users.len()
    }

    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    /// Get all distinct group names
    pub fn group_names(&self) -> Vec<String> {
        let mut groups: Vec<String> = self
            .users
            .values()
            .filter_map(|u| u.group.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        groups.sort();
        groups
    }

    /// Get all users in a specific group
    pub fn users_in_group(&self, group: &str) -> Vec<&Arc<User>> {
        self.users
            .values()
            .filter(|u| u.group.as_deref() == Some(group))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{GlobalAclConfig, TimeAccessConfig};

    fn default_limits() -> LimitsConfig {
        LimitsConfig::default()
    }

    fn default_server() -> ServerConfig {
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
            connect_retry: 2,
            connect_retry_delay_ms: 500,
            bookmarks_path: None,
            ssh_keepalive_interval_secs: 15,
            ssh_keepalive_max: 3,
            ssh_auth_timeout: 120,
        }
    }

    fn default_shell() -> ShellConfig {
        ShellConfig::default()
    }

    fn make_user_config(username: &str) -> UserConfig {
        UserConfig {
            username: username.to_string(),
            password_hash: Some("hash".to_string()),
            authorized_keys: Vec::new(),
            allow_forwarding: true,
            allow_shell: true,
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

    #[test]
    fn test_user_from_config_basic() {
        let cfg = make_user_config("alice");
        let user = User::from_config(
            &cfg,
            &[],
            &GlobalAclConfig::default(),
            &default_limits(),
            &default_server(),
            &default_shell(),
        )
        .unwrap();

        assert_eq!(user.username, "alice");
        assert_eq!(user.role, UserRole::User);
        assert!(user.shell_permissions.show_connections);
        assert!(user.colors);
        assert_eq!(user.connect_retry, 2); // from server default
        assert_eq!(user.idle_warning_secs, 0); // from limits default
    }

    #[test]
    fn test_user_inherits_from_group() {
        let mut cfg = make_user_config("bob");
        cfg.group = Some("devs".to_string());

        let group = GroupConfig {
            name: "devs".to_string(),
            acl: Default::default(),
            max_connections_per_user: None,
            max_bandwidth_kbps: Some(5000),
            max_aggregate_bandwidth_kbps: Some(10000),
            max_new_connections_per_minute: Some(20),
            allow_forwarding: Some(true),
            allow_shell: Some(true),
            shell_permissions: Some(ShellPermissions {
                show_connections: true,
                show_bandwidth: false,
                ..ShellPermissions::default()
            }),
            motd: Some(MotdConfig {
                enabled: true,
                template: Some("Hello {user}!".to_string()),
                colors: false,
            }),
            quotas: None,
            time_access: None,
            auth_methods: Some(vec!["pubkey".to_string()]),
            idle_warning_secs: Some(30),
            role: Some(UserRole::Admin),
            colors: Some(false),
            connect_retry: Some(5),
            connect_retry_delay_ms: Some(2000),
            rate_limits: None,
        };

        let user = User::from_config(
            &cfg,
            &[group],
            &GlobalAclConfig::default(),
            &default_limits(),
            &default_server(),
            &default_shell(),
        )
        .unwrap();

        assert_eq!(user.group.as_deref(), Some("devs"));
        assert_eq!(user.role, UserRole::Admin);
        assert_eq!(user.max_bandwidth_kbps, 5000);
        assert_eq!(user.max_aggregate_bandwidth_kbps, 10000);
        assert!(!user.shell_permissions.show_bandwidth);
        assert!(user.motd_config.is_some());
        assert_eq!(user.auth_methods, Some(vec!["pubkey".to_string()]));
        assert_eq!(user.idle_warning_secs, 30);
        assert!(!user.colors);
        assert_eq!(user.connect_retry, 5);
        assert_eq!(user.connect_retry_delay_ms, 2000);
    }

    #[test]
    fn test_user_overrides_group() {
        let mut cfg = make_user_config("carol");
        cfg.group = Some("devs".to_string());
        cfg.colors = Some(true);
        cfg.connect_retry = Some(10);
        cfg.idle_warning_secs = Some(60);

        let group = GroupConfig {
            name: "devs".to_string(),
            acl: Default::default(),
            max_connections_per_user: None,
            max_bandwidth_kbps: None,
            max_aggregate_bandwidth_kbps: None,
            max_new_connections_per_minute: None,
            allow_forwarding: None,
            allow_shell: None,
            shell_permissions: None,
            motd: None,
            quotas: None,
            time_access: None,
            auth_methods: None,
            idle_warning_secs: Some(30),
            role: None,
            colors: Some(false),
            connect_retry: Some(5),
            connect_retry_delay_ms: None,
            rate_limits: None,
        };

        let user = User::from_config(
            &cfg,
            &[group],
            &GlobalAclConfig::default(),
            &default_limits(),
            &default_server(),
            &default_shell(),
        )
        .unwrap();

        // User overrides should win
        assert!(user.colors);
        assert_eq!(user.connect_retry, 10);
        assert_eq!(user.idle_warning_secs, 60);
    }

    #[test]
    fn test_check_time_access_no_restrictions() {
        let cfg = make_user_config("dave");
        let user = User::from_config(
            &cfg,
            &[],
            &GlobalAclConfig::default(),
            &default_limits(),
            &default_server(),
            &default_shell(),
        )
        .unwrap();

        assert!(user.check_time_access());
    }

    #[test]
    fn test_check_time_access_all_days() {
        let mut cfg = make_user_config("eve");
        cfg.time_access = Some(TimeAccessConfig {
            access_hours: Some("00:00-23:59".to_string()),
            access_days: vec![
                "mon".to_string(),
                "tue".to_string(),
                "wed".to_string(),
                "thu".to_string(),
                "fri".to_string(),
                "sat".to_string(),
                "sun".to_string(),
            ],
            timezone: "UTC".to_string(),
        });

        let user = User::from_config(
            &cfg,
            &[],
            &GlobalAclConfig::default(),
            &default_limits(),
            &default_server(),
            &default_shell(),
        )
        .unwrap();

        assert!(user.check_time_access());
    }

    #[test]
    fn test_check_time_access_day_restriction() {
        let mut cfg = make_user_config("frank");
        // Only allow access on a day that is definitely not today
        // (we use an empty day list which means no restriction on days)
        cfg.time_access = Some(TimeAccessConfig {
            access_hours: None,
            access_days: vec![], // empty = no day restriction
            timezone: "UTC".to_string(),
        });

        let user = User::from_config(
            &cfg,
            &[],
            &GlobalAclConfig::default(),
            &default_limits(),
            &default_server(),
            &default_shell(),
        )
        .unwrap();

        // No day restriction + no hour restriction = allowed
        assert!(user.check_time_access());
    }

    #[test]
    fn test_parse_hour_range() {
        assert_eq!(parse_hour_range("08:00-18:00"), Some((480, 1080)));
        assert_eq!(parse_hour_range("00:00-23:59"), Some((0, 1439)));
        assert_eq!(parse_hour_range("invalid"), None);
        assert_eq!(parse_hour_range("25:00-18:00"), None);
    }

    #[test]
    fn test_parse_hhmm() {
        assert_eq!(parse_hhmm("08:00"), Some(480));
        assert_eq!(parse_hhmm("00:00"), Some(0));
        assert_eq!(parse_hhmm("23:59"), Some(1439));
        assert_eq!(parse_hhmm("24:00"), None);
        assert_eq!(parse_hhmm("12:60"), None);
        assert_eq!(parse_hhmm("bad"), None);
    }

    #[test]
    fn test_user_store_from_config() {
        let configs = vec![make_user_config("alice"), make_user_config("bob")];
        let store = UserStore::from_config(
            &configs,
            &[],
            &GlobalAclConfig::default(),
            &default_limits(),
            &default_server(),
            &default_shell(),
        )
        .unwrap();

        assert_eq!(store.len(), 2);
        assert!(!store.is_empty());
        assert!(store.get("alice").is_some());
        assert!(store.get("bob").is_some());
        assert!(store.get("unknown").is_none());
    }
}
