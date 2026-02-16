use chrono::{Datelike, Timelike};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

/// Log level enum (replaces stringly-typed field)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogLevel::Trace => write!(f, "trace"),
            LogLevel::Debug => write!(f, "debug"),
            LogLevel::Info => write!(f, "info"),
            LogLevel::Warn => write!(f, "warn"),
            LogLevel::Error => write!(f, "error"),
        }
    }
}

/// Log format enum (replaces stringly-typed field)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Pretty,
    Json,
}

impl fmt::Display for LogFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogFormat::Pretty => write!(f, "pretty"),
            LogFormat::Json => write!(f, "json"),
        }
    }
}

/// ACL default policy enum (replaces stringly-typed field)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AclPolicyConfig {
    Allow,
    Deny,
}

impl fmt::Display for AclPolicyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AclPolicyConfig::Allow => write!(f, "allow"),
            AclPolicyConfig::Deny => write!(f, "deny"),
        }
    }
}

/// User role for delegated admin
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    #[default]
    User,
    Admin,
}

impl fmt::Display for UserRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserRole::User => write!(f, "user"),
            UserRole::Admin => write!(f, "admin"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    #[serde(default)]
    pub shell: ShellConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub geoip: GeoIpConfig,
    #[serde(default)]
    pub upstream_proxy: Option<UpstreamProxyConfig>,
    #[serde(default)]
    pub webhooks: Vec<WebhookConfig>,
    #[serde(default)]
    pub acl: GlobalAclConfig,
    #[serde(default, rename = "users")]
    pub users: Vec<UserConfig>,
    #[serde(default)]
    pub groups: Vec<GroupConfig>,
    #[serde(default)]
    pub motd: MotdConfig,
    #[serde(default)]
    pub alerting: AlertingConfig,
    #[serde(default)]
    pub maintenance_windows: Vec<MaintenanceWindowConfig>,
    #[serde(default)]
    pub connection_pool: ConnectionPoolConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub ssh_listen: String,
    pub socks5_listen: Option<String>,
    #[serde(default = "default_host_key_path")]
    pub host_key_path: PathBuf,
    #[serde(default = "default_server_id")]
    pub server_id: String,
    #[serde(default = "default_banner")]
    pub banner: String,
    pub motd_path: Option<PathBuf>,
    /// Enable HAProxy PROXY protocol v1/v2 header parsing on the SSH listener.
    /// NOTE: Currently accepted in config for forward-compatibility but not yet enforced.
    #[serde(default)]
    pub proxy_protocol: bool,
    #[serde(default)]
    pub allowed_ciphers: Vec<String>,
    #[serde(default)]
    pub allowed_kex: Vec<String>,
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout: u64,
    /// TLS certificate path for SOCKS5 standalone listener (optional).
    pub socks5_tls_cert: Option<PathBuf>,
    /// TLS private key path for SOCKS5 standalone listener (optional).
    pub socks5_tls_key: Option<PathBuf>,
    /// DNS cache TTL: -1 = follow native DNS TTL (default), 0 = disabled, N = N seconds.
    #[serde(default = "default_dns_cache_ttl")]
    pub dns_cache_ttl: i64,
    /// Maximum DNS cache entries (default 1000).
    #[serde(default = "default_dns_cache_max_entries")]
    pub dns_cache_max_entries: u32,
    /// Smart retry on connect: number of retries (0 = disabled).
    #[serde(default)]
    pub connect_retry: u32,
    /// Smart retry delay in milliseconds.
    #[serde(default = "default_connect_retry_delay_ms")]
    pub connect_retry_delay_ms: u64,
    /// Bookmarks storage path (optional, in-memory if not set).
    pub bookmarks_path: Option<PathBuf>,
    /// SSH keepalive interval in seconds (0 = disabled). Server sends keepalive
    /// requests to detect dead clients and prevent ghost sessions.
    #[serde(default = "default_ssh_keepalive_interval_secs")]
    pub ssh_keepalive_interval_secs: u64,
    /// Maximum number of unanswered SSH keepalives before disconnecting the client.
    #[serde(default = "default_ssh_keepalive_max")]
    pub ssh_keepalive_max: u32,
    /// Maximum time in seconds allowed for SSH authentication (key exchange + auth).
    /// Connections that don't authenticate within this window are rejected.
    /// Default: 120 seconds. Range: 10-600.
    #[serde(default = "default_ssh_auth_timeout")]
    pub ssh_auth_timeout: u64,
}

fn default_dns_cache_ttl() -> i64 {
    -1
}

fn default_dns_cache_max_entries() -> u32 {
    1000
}

fn default_host_key_path() -> PathBuf {
    PathBuf::from("host_key")
}

fn default_server_id() -> String {
    "SSH-2.0-sks5".to_string()
}

fn default_banner() -> String {
    "Welcome to sks5".to_string()
}

fn default_shutdown_timeout() -> u64 {
    30
}

fn default_connect_retry_delay_ms() -> u64 {
    1000
}

fn default_ssh_keepalive_interval_secs() -> u64 {
    15
}

fn default_ssh_keepalive_max() -> u32 {
    3
}

fn default_ssh_auth_timeout() -> u64 {
    120
}

/// MOTD template configuration (global, overridable by group/user)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MotdConfig {
    /// Enable MOTD display
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Template string with variables: {user}, {auth_method}, {source_ip}, {connections},
    /// {acl_policy}, {expires_at}, {bandwidth_used}, {bandwidth_limit}, {last_login},
    /// {uptime}, {version}, {group}, {role}
    #[serde(default)]
    pub template: Option<String>,
    /// Enable ANSI color codes in MOTD output
    #[serde(default = "default_true")]
    pub colors: bool,
}

impl Default for MotdConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            template: None,
            colors: true,
        }
    }
}

/// Shell configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ShellConfig {
    #[serde(default = "default_hostname")]
    pub hostname: String,
    #[serde(default = "default_prompt")]
    pub prompt: String,
    /// Enable ANSI color in shell output
    #[serde(default = "default_true")]
    pub colors: bool,
    /// Enable tab-completion
    #[serde(default = "default_true")]
    pub autocomplete: bool,
}

impl Default for ShellConfig {
    fn default() -> Self {
        Self {
            hostname: default_hostname(),
            prompt: default_prompt(),
            colors: true,
            autocomplete: true,
        }
    }
}

fn default_hostname() -> String {
    "sks5-proxy".to_string()
}

fn default_prompt() -> String {
    "$ ".to_string()
}

/// Shell command permissions — configurable at global/group/user level
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ShellPermissions {
    #[serde(default = "default_true")]
    pub show_connections: bool,
    #[serde(default = "default_true")]
    pub show_bandwidth: bool,
    #[serde(default = "default_true")]
    pub show_acl: bool,
    #[serde(default = "default_true")]
    pub show_status: bool,
    #[serde(default = "default_true")]
    pub show_history: bool,
    #[serde(default = "default_true")]
    pub show_fingerprint: bool,
    #[serde(default = "default_true")]
    pub test_command: bool,
    #[serde(default = "default_true")]
    pub ping_command: bool,
    #[serde(default = "default_true")]
    pub resolve_command: bool,
    #[serde(default = "default_true")]
    pub bookmark_command: bool,
    #[serde(default = "default_true")]
    pub alias_command: bool,
    #[serde(default = "default_true")]
    pub show_quota: bool,
}

impl Default for ShellPermissions {
    fn default() -> Self {
        Self {
            show_connections: true,
            show_bandwidth: true,
            show_acl: true,
            show_status: true,
            show_history: true,
            show_fingerprint: true,
            test_command: true,
            ping_command: true,
            resolve_command: true,
            bookmark_command: true,
            alias_command: true,
            show_quota: true,
        }
    }
}

/// Group configuration (global → group → user inheritance)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GroupConfig {
    pub name: String,
    #[serde(default)]
    pub acl: UserAclConfig,
    #[serde(default)]
    pub max_connections_per_user: Option<u32>,
    #[serde(default)]
    pub max_bandwidth_kbps: Option<u64>,
    #[serde(default)]
    pub max_aggregate_bandwidth_kbps: Option<u64>,
    #[serde(default)]
    pub max_new_connections_per_minute: Option<u32>,
    /// Deprecated: ignored at runtime, use ACL instead.
    #[serde(default)]
    pub allow_forwarding: Option<bool>,
    #[serde(default)]
    pub allow_shell: Option<bool>,
    #[serde(default)]
    pub shell_permissions: Option<ShellPermissions>,
    #[serde(default)]
    pub motd: Option<MotdConfig>,
    #[serde(default)]
    pub quotas: Option<QuotaConfig>,
    #[serde(default)]
    pub time_access: Option<TimeAccessConfig>,
    #[serde(default)]
    pub auth_methods: Option<Vec<String>>,
    #[serde(default)]
    pub idle_warning_secs: Option<u64>,
    #[serde(default)]
    pub role: Option<UserRole>,
    #[serde(default)]
    pub colors: Option<bool>,
    #[serde(default)]
    pub connect_retry: Option<u32>,
    #[serde(default)]
    pub connect_retry_delay_ms: Option<u64>,
    /// Multi-window rate limits for new connections (overrides server defaults)
    #[serde(default)]
    pub rate_limits: Option<RateLimitsConfig>,
}

/// Time-based access restrictions
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TimeAccessConfig {
    /// Allowed hours in "HH:MM-HH:MM" format (e.g. "08:00-18:00")
    #[serde(default)]
    pub access_hours: Option<String>,
    /// Allowed days: "mon", "tue", "wed", "thu", "fri", "sat", "sun"
    #[serde(default)]
    pub access_days: Vec<String>,
    /// Timezone (default: UTC). IANA format e.g. "Europe/Paris"
    #[serde(default = "default_timezone")]
    pub timezone: String,
}

fn default_timezone() -> String {
    "UTC".to_string()
}

impl Default for TimeAccessConfig {
    fn default() -> Self {
        Self {
            access_hours: None,
            access_days: Vec::new(),
            timezone: default_timezone(),
        }
    }
}

/// Multi-window rate limits for new connections (per-second, per-minute, per-hour).
/// Applied at user, group, or server level. 0 = unlimited for each window.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RateLimitsConfig {
    /// Max new connections per second (0 = unlimited)
    #[serde(default)]
    pub connections_per_second: u32,
    /// Max new connections per minute (0 = unlimited)
    #[serde(default)]
    pub connections_per_minute: u32,
    /// Max new connections per hour (0 = unlimited)
    #[serde(default)]
    pub connections_per_hour: u32,
}

/// Quota configuration (daily/monthly limits)
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct QuotaConfig {
    /// Max bytes per day (0 = unlimited)
    #[serde(default)]
    pub daily_bandwidth_bytes: u64,
    /// Max connections per day (0 = unlimited)
    #[serde(default)]
    pub daily_connection_limit: u32,
    /// Max bytes per month (0 = unlimited)
    #[serde(default)]
    pub monthly_bandwidth_bytes: u64,
    /// Max connections per month (0 = unlimited)
    #[serde(default)]
    pub monthly_connection_limit: u32,
    /// Max bytes per hour (0 = unlimited), rolling window
    #[serde(default)]
    pub bandwidth_per_hour_bytes: u64,
    /// Max total bytes ever (0 = unlimited). Never auto-resets.
    #[serde(default)]
    pub total_bandwidth_bytes: u64,
}

/// Alerting rules configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AlertingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub rules: Vec<AlertRule>,
}

/// Typed alert condition for type-safe matching.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlertCondition {
    BandwidthExceeded,
    ConnectionsExceeded,
    MonthlyBandwidthExceeded,
    HourlyBandwidthExceeded,
    AuthFailures,
}

impl std::fmt::Display for AlertCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BandwidthExceeded => write!(f, "bandwidth_exceeded"),
            Self::ConnectionsExceeded => write!(f, "connections_exceeded"),
            Self::MonthlyBandwidthExceeded => write!(f, "monthly_bandwidth_exceeded"),
            Self::HourlyBandwidthExceeded => write!(f, "hourly_bandwidth_exceeded"),
            Self::AuthFailures => write!(f, "auth_failures"),
        }
    }
}

/// A single alerting rule
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AlertRule {
    pub name: String,
    /// Condition type
    pub condition: AlertCondition,
    /// Threshold value
    pub threshold: u64,
    /// Window in seconds
    #[serde(default = "default_alert_window")]
    pub window_secs: u64,
    /// Users to apply to (empty = all)
    #[serde(default)]
    pub users: Vec<String>,
    /// Webhook URL to notify (uses existing webhook infrastructure)
    pub webhook_url: Option<String>,
}

fn default_alert_window() -> u64 {
    3600
}

/// Scheduled maintenance window
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MaintenanceWindowConfig {
    /// Cron-like schedule: "Sun 02:00-04:00" or "daily 03:00-04:00"
    pub schedule: String,
    /// Timezone (default: UTC)
    #[serde(default = "default_timezone")]
    pub timezone: String,
    /// Message to show to connecting users during maintenance
    #[serde(default = "default_maintenance_message")]
    pub message: String,
    /// Gracefully disconnect existing connections
    #[serde(default)]
    pub disconnect_existing: bool,
}

fn default_maintenance_message() -> String {
    "Server is under scheduled maintenance. Please try again later.".to_string()
}

impl MaintenanceWindowConfig {
    /// Check if the maintenance window is currently active.
    ///
    /// Schedule format:
    /// - `"daily 03:00-04:00"` — every day between 03:00 and 04:00 UTC
    /// - `"Sun 02:00-04:00"` — every Sunday between 02:00 and 04:00 UTC
    /// - `"Mon 22:00-23:00"` — every Monday between 22:00 and 23:00 UTC
    ///
    /// Day names (case-insensitive): mon, tue, wed, thu, fri, sat, sun
    /// Time is always interpreted as UTC regardless of the timezone field
    /// (timezone support for chrono-tz would require an additional dependency).
    pub fn is_active(&self, now: &chrono::DateTime<chrono::Utc>) -> bool {
        let parts: Vec<&str> = self.schedule.splitn(2, ' ').collect();
        if parts.len() != 2 {
            return false;
        }

        let day_spec = parts[0].to_lowercase();
        let time_range = parts[1];

        // Check day
        if day_spec != "daily" {
            let today = match now.weekday() {
                chrono::Weekday::Mon => "mon",
                chrono::Weekday::Tue => "tue",
                chrono::Weekday::Wed => "wed",
                chrono::Weekday::Thu => "thu",
                chrono::Weekday::Fri => "fri",
                chrono::Weekday::Sat => "sat",
                chrono::Weekday::Sun => "sun",
            };
            if day_spec != today {
                return false;
            }
        }

        // Parse time range "HH:MM-HH:MM"
        let time_parts: Vec<&str> = time_range.split('-').collect();
        if time_parts.len() != 2 {
            return false;
        }

        let start = Self::parse_hhmm(time_parts[0]);
        let end = Self::parse_hhmm(time_parts[1]);

        match (start, end) {
            (Some(start_mins), Some(end_mins)) => {
                let now_mins = now.hour() * 60 + now.minute();
                now_mins >= start_mins && now_mins < end_mins
            }
            _ => false,
        }
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
}

#[cfg(test)]
mod maintenance_window_tests {
    use super::*;
    use chrono::TimeZone;

    fn make_window(schedule: &str) -> MaintenanceWindowConfig {
        MaintenanceWindowConfig {
            schedule: schedule.to_string(),
            timezone: "UTC".to_string(),
            message: "maintenance".to_string(),
            disconnect_existing: false,
        }
    }

    #[test]
    fn test_daily_window_active() {
        let window = make_window("daily 02:00-04:00");
        // Wednesday 03:00 UTC
        let now = chrono::Utc.with_ymd_and_hms(2026, 2, 11, 3, 0, 0).unwrap();
        assert!(window.is_active(&now));
    }

    #[test]
    fn test_daily_window_before() {
        let window = make_window("daily 02:00-04:00");
        // Wednesday 01:59 UTC
        let now = chrono::Utc.with_ymd_and_hms(2026, 2, 11, 1, 59, 0).unwrap();
        assert!(!window.is_active(&now));
    }

    #[test]
    fn test_daily_window_after() {
        let window = make_window("daily 02:00-04:00");
        // Wednesday 04:00 UTC (end is exclusive)
        let now = chrono::Utc.with_ymd_and_hms(2026, 2, 11, 4, 0, 0).unwrap();
        assert!(!window.is_active(&now));
    }

    #[test]
    fn test_specific_day_active() {
        let window = make_window("Sun 02:00-04:00");
        // Sunday 03:30 UTC
        let now = chrono::Utc.with_ymd_and_hms(2026, 2, 15, 3, 30, 0).unwrap();
        assert!(window.is_active(&now));
    }

    #[test]
    fn test_specific_day_wrong_day() {
        let window = make_window("Sun 02:00-04:00");
        // Monday 03:00 UTC
        let now = chrono::Utc.with_ymd_and_hms(2026, 2, 16, 3, 0, 0).unwrap();
        assert!(!window.is_active(&now));
    }

    #[test]
    fn test_specific_day_right_day_wrong_time() {
        let window = make_window("Sun 02:00-04:00");
        // Sunday 05:00 UTC
        let now = chrono::Utc.with_ymd_and_hms(2026, 2, 15, 5, 0, 0).unwrap();
        assert!(!window.is_active(&now));
    }

    #[test]
    fn test_case_insensitive_day() {
        let window = make_window("MON 10:00-12:00");
        // Monday 11:00 UTC
        let now = chrono::Utc.with_ymd_and_hms(2026, 2, 16, 11, 0, 0).unwrap();
        assert!(window.is_active(&now));
    }

    #[test]
    fn test_invalid_schedule_format() {
        let window = make_window("invalid");
        let now = chrono::Utc::now();
        assert!(!window.is_active(&now));
    }

    #[test]
    fn test_invalid_time_range() {
        let window = make_window("daily bad-time");
        let now = chrono::Utc::now();
        assert!(!window.is_active(&now));
    }

    #[test]
    fn test_boundary_start_inclusive() {
        let window = make_window("daily 10:00-11:00");
        // Exactly 10:00
        let now = chrono::Utc.with_ymd_and_hms(2026, 2, 11, 10, 0, 0).unwrap();
        assert!(window.is_active(&now));
    }

    #[test]
    fn test_boundary_end_exclusive() {
        let window = make_window("daily 10:00-11:00");
        // Exactly 11:00 (end is exclusive)
        let now = chrono::Utc.with_ymd_and_hms(2026, 2, 11, 11, 0, 0).unwrap();
        assert!(!window.is_active(&now));
    }
}

/// Connection pooling configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConnectionPoolConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_pool_size")]
    pub max_idle_per_host: u32,
    #[serde(default = "default_pool_ttl")]
    pub idle_timeout_secs: u64,
}

fn default_pool_size() -> u32 {
    10
}

fn default_pool_ttl() -> u64 {
    60
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_idle_per_host: default_pool_size(),
            idle_timeout_secs: default_pool_ttl(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /// Max concurrent connections per user (0 = unlimited). Default: 0.
    #[serde(default)]
    pub max_connections_per_user: u32,
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout: u64,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout: u64,
    #[serde(default = "default_max_auth_attempts")]
    pub max_auth_attempts: u32,
    /// SOCKS5 handshake timeout in seconds (default 30, min 5, max 120).
    #[serde(default = "default_socks5_handshake_timeout")]
    pub socks5_handshake_timeout: u64,
    /// Idle warning: seconds before disconnect to warn user (0 = no warning).
    #[serde(default)]
    pub idle_warning_secs: u64,
    /// Server-wide bandwidth cap in Mbps (0 = unlimited).
    #[serde(default)]
    pub max_bandwidth_mbps: u64,
    /// Server-level max new connections per second (0 = unlimited).
    #[serde(default)]
    pub max_new_connections_per_second: u32,
    /// Server-level max new connections per minute (0 = unlimited).
    #[serde(default)]
    pub max_new_connections_per_minute: u32,
    /// UDP relay idle timeout in seconds (default 300, range 30-3600)
    #[serde(default = "default_udp_relay_timeout")]
    pub udp_relay_timeout: u64,
    /// Maximum concurrent UDP relay sessions per user (0 = unlimited)
    #[serde(default)]
    pub max_udp_sessions_per_user: u32,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            max_connections_per_user: 0,
            connection_timeout: default_connection_timeout(),
            idle_timeout: default_idle_timeout(),
            max_auth_attempts: default_max_auth_attempts(),
            socks5_handshake_timeout: default_socks5_handshake_timeout(),
            idle_warning_secs: 0,
            max_bandwidth_mbps: 0,
            max_new_connections_per_second: 0,
            max_new_connections_per_minute: 0,
            udp_relay_timeout: default_udp_relay_timeout(),
            max_udp_sessions_per_user: 0,
        }
    }
}

fn default_socks5_handshake_timeout() -> u64 {
    30
}

fn default_udp_relay_timeout() -> u64 {
    300
}

fn default_max_connections() -> u32 {
    1000
}
fn default_connection_timeout() -> u64 {
    300
}
fn default_idle_timeout() -> u64 {
    0
}
fn default_max_auth_attempts() -> u32 {
    3
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    #[serde(default)]
    pub allowed_source_ips: Vec<IpNet>,
    #[serde(default = "default_true")]
    pub ban_enabled: bool,
    #[serde(default = "default_ban_threshold")]
    pub ban_threshold: u32,
    #[serde(default = "default_ban_window")]
    pub ban_window: u64,
    #[serde(default = "default_ban_duration")]
    pub ban_duration: u64,
    #[serde(default)]
    pub ban_whitelist: Vec<String>,
    #[serde(default = "default_true")]
    pub ip_guard_enabled: bool,
    #[serde(default)]
    pub totp_required_for: Vec<String>,
    /// Maximum new connections per IP per minute (pre-auth). 0 = unlimited.
    #[serde(default)]
    pub max_new_connections_per_ip_per_minute: u32,
    /// IP reputation scoring: enable dynamic scoring
    #[serde(default)]
    pub ip_reputation_enabled: bool,
    /// IP reputation: auto-ban threshold score (0 = disabled)
    #[serde(default = "default_ip_reputation_threshold")]
    pub ip_reputation_ban_threshold: u32,
    /// Trusted CA keys for SSH certificate authentication
    #[serde(default)]
    pub trusted_user_ca_keys: Vec<String>,
    /// Argon2id memory cost in KiB (default 19456 = 19 MiB, OWASP recommendation)
    #[serde(default = "default_argon2_memory_cost")]
    pub argon2_memory_cost: u32,
    /// Argon2id time cost / iterations (default 2)
    #[serde(default = "default_argon2_time_cost")]
    pub argon2_time_cost: u32,
    /// Argon2id parallelism / lanes (default 1)
    #[serde(default = "default_argon2_parallelism")]
    pub argon2_parallelism: u32,
    /// Rate limiter cleanup interval in seconds (default 60).
    /// A background task prunes stale entries at this interval.
    #[serde(default = "default_rate_limit_cleanup_interval")]
    pub rate_limit_cleanup_interval: u64,
    /// Maximum number of tracked IPs in the rate limiter (default 100_000).
    /// When exceeded, oldest entries are evicted.
    #[serde(default = "default_rate_limit_max_ips")]
    pub rate_limit_max_ips: usize,
    /// Maximum number of tracked usernames in the rate limiter (default 10_000).
    /// When exceeded, oldest entries are evicted.
    #[serde(default = "default_rate_limit_max_users")]
    pub rate_limit_max_users: usize,
}

fn default_ip_reputation_threshold() -> u32 {
    100
}

fn default_argon2_memory_cost() -> u32 {
    19456
}

fn default_argon2_time_cost() -> u32 {
    2
}

fn default_argon2_parallelism() -> u32 {
    1
}

fn default_rate_limit_cleanup_interval() -> u64 {
    60
}

fn default_rate_limit_max_ips() -> usize {
    100_000
}

fn default_rate_limit_max_users() -> usize {
    10_000
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            allowed_source_ips: Vec::new(),
            ban_enabled: true,
            ban_threshold: default_ban_threshold(),
            ban_window: default_ban_window(),
            ban_duration: default_ban_duration(),
            ban_whitelist: Vec::new(),
            ip_guard_enabled: true,
            totp_required_for: Vec::new(),
            max_new_connections_per_ip_per_minute: 0,
            ip_reputation_enabled: false,
            ip_reputation_ban_threshold: default_ip_reputation_threshold(),
            trusted_user_ca_keys: Vec::new(),
            argon2_memory_cost: default_argon2_memory_cost(),
            argon2_time_cost: default_argon2_time_cost(),
            argon2_parallelism: default_argon2_parallelism(),
            rate_limit_cleanup_interval: default_rate_limit_cleanup_interval(),
            rate_limit_max_ips: default_rate_limit_max_ips(),
            rate_limit_max_users: default_rate_limit_max_users(),
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_ban_threshold() -> u32 {
    5
}
fn default_ban_window() -> u64 {
    300
}
fn default_ban_duration() -> u64 {
    900
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: LogLevel,
    #[serde(default = "default_log_format")]
    pub format: LogFormat,
    pub audit_log_path: Option<PathBuf>,
    #[serde(default = "default_audit_max_size_mb")]
    pub audit_max_size_mb: u64,
    #[serde(default = "default_audit_max_files")]
    pub audit_max_files: u32,
    /// Enable connection flow logs (detailed per-step timing)
    #[serde(default)]
    pub connection_flow_logs: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
            audit_log_path: None,
            audit_max_size_mb: default_audit_max_size_mb(),
            audit_max_files: default_audit_max_files(),
            connection_flow_logs: false,
        }
    }
}

fn default_log_level() -> LogLevel {
    LogLevel::Info
}

fn default_log_format() -> LogFormat {
    LogFormat::Pretty
}

fn default_audit_max_size_mb() -> u64 {
    100
}

fn default_audit_max_files() -> u32 {
    5
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_metrics_listen")]
    pub listen: String,
    /// Maximum distinct label values before aggregating under "_other" (default 100).
    #[serde(default = "default_max_metric_labels")]
    pub max_metric_labels: u32,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_metrics_listen(),
            max_metric_labels: default_max_metric_labels(),
        }
    }
}

fn default_max_metric_labels() -> u32 {
    100
}

fn default_metrics_listen() -> String {
    "127.0.0.1:9090".to_string()
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ApiConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_api_listen")]
    pub listen: String,
    #[serde(default)]
    pub token: String,
}

impl fmt::Debug for ApiConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiConfig")
            .field("enabled", &self.enabled)
            .field("listen", &self.listen)
            .field(
                "token",
                &if self.token.is_empty() {
                    "(empty)"
                } else {
                    "***"
                },
            )
            .finish()
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_api_listen(),
            token: String::new(),
        }
    }
}

fn default_api_listen() -> String {
    "127.0.0.1:9091".to_string()
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct GeoIpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub database_path: Option<PathBuf>,
    #[serde(default)]
    pub allowed_countries: Vec<String>,
    #[serde(default)]
    pub denied_countries: Vec<String>,
    #[serde(default)]
    pub fail_closed: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpstreamProxyConfig {
    pub url: String,
}

/// Parsed upstream SOCKS5 proxy configuration, ready for use at connection time.
#[derive(Debug, Clone)]
pub struct ParsedUpstreamProxy {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl ParsedUpstreamProxy {
    /// Parse a `socks5://[user:pass@]host:port` URL into a `ParsedUpstreamProxy`.
    pub fn from_url(raw: &str) -> anyhow::Result<Self> {
        let parsed = url::Url::parse(raw)
            .map_err(|e| anyhow::anyhow!("invalid upstream proxy URL: {}", e))?;

        if parsed.scheme() != "socks5" {
            anyhow::bail!(
                "unsupported upstream proxy scheme '{}' (only socks5:// is supported)",
                parsed.scheme()
            );
        }

        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("upstream proxy URL missing host"))?
            .to_string();

        let port = parsed
            .port()
            .ok_or_else(|| anyhow::anyhow!("upstream proxy URL missing port"))?;

        let username = if !parsed.username().is_empty() {
            Some(
                percent_encoding::percent_decode_str(parsed.username())
                    .decode_utf8()
                    .map_err(|e| {
                        anyhow::anyhow!("invalid upstream proxy username encoding: {}", e)
                    })?
                    .into_owned(),
            )
        } else {
            None
        };

        let password = parsed.password().map(|p| {
            percent_encoding::percent_decode_str(p)
                .decode_utf8()
                .map(|s| s.into_owned())
                .unwrap_or_else(|_| p.to_string())
        });

        Ok(Self {
            host,
            port,
            username,
            password,
        })
    }

    /// Format as display string (without credentials) for logging.
    pub fn display_addr(&self) -> String {
        format!("socks5://{}:{}", self.host, self.port)
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct WebhookConfig {
    pub url: String,
    #[serde(default)]
    pub events: Vec<String>,
    pub secret: Option<String>,
    /// Allow webhook delivery to private/internal IPs (for local monitoring).
    #[serde(default)]
    pub allow_private_ips: bool,
    /// Maximum retry attempts on delivery failure (default 3).
    #[serde(default = "default_webhook_max_retries")]
    pub max_retries: u32,
    /// Initial retry delay in milliseconds (default 1000).
    #[serde(default = "default_webhook_retry_delay_ms")]
    pub retry_delay_ms: u64,
    /// Maximum retry delay in milliseconds (default 30000).
    #[serde(default = "default_webhook_max_retry_delay_ms")]
    pub max_retry_delay_ms: u64,
}

fn default_webhook_max_retries() -> u32 {
    3
}
fn default_webhook_retry_delay_ms() -> u64 {
    1000
}
fn default_webhook_max_retry_delay_ms() -> u64 {
    30000
}

impl fmt::Debug for WebhookConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookConfig")
            .field("url", &self.url)
            .field("events", &self.events)
            .field("secret", &self.secret.as_ref().map(|_| "***"))
            .finish()
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct UserConfig {
    pub username: String,
    pub password_hash: Option<String>,
    #[serde(default)]
    pub authorized_keys: Vec<String>,
    /// Deprecated: ignored at runtime, use ACL instead.
    #[serde(default = "default_true")]
    pub allow_forwarding: bool,
    #[serde(default)]
    pub allow_shell: Option<bool>,
    #[serde(default)]
    pub max_new_connections_per_minute: u32,
    #[serde(default)]
    pub max_bandwidth_kbps: u64,
    #[serde(default)]
    pub source_ips: Vec<IpNet>,
    pub expires_at: Option<String>,
    pub upstream_proxy: Option<String>,
    #[serde(default)]
    pub acl: UserAclConfig,
    #[serde(default)]
    pub totp_secret: Option<String>,
    #[serde(default)]
    pub totp_enabled: bool,
    #[serde(default)]
    pub max_aggregate_bandwidth_kbps: u64,
    /// Group membership (references GroupConfig.name)
    pub group: Option<String>,
    /// User role (admin / user)
    #[serde(default)]
    pub role: UserRole,
    /// Shell command permissions (overrides group/global)
    #[serde(default)]
    pub shell_permissions: Option<ShellPermissions>,
    /// Per-user MOTD override
    #[serde(default)]
    pub motd: Option<MotdConfig>,
    /// Per-user quotas
    #[serde(default)]
    pub quotas: Option<QuotaConfig>,
    /// Time-based access restrictions
    #[serde(default)]
    pub time_access: Option<TimeAccessConfig>,
    /// Auth method chain: e.g. ["pubkey", "password"] means both required
    #[serde(default)]
    pub auth_methods: Option<Vec<String>>,
    /// Idle warning seconds (overrides group/global)
    #[serde(default)]
    pub idle_warning_secs: Option<u64>,
    /// Color support override
    #[serde(default)]
    pub colors: Option<bool>,
    /// Smart retry override
    #[serde(default)]
    pub connect_retry: Option<u32>,
    /// Smart retry delay override
    #[serde(default)]
    pub connect_retry_delay_ms: Option<u64>,
    /// Shell aliases: {"db": "test prod-db:5432", "status": "show status"}
    #[serde(default)]
    pub aliases: HashMap<String, String>,
    /// Per-user max concurrent connections (None = inherit from group/global, 0 = unlimited)
    #[serde(default)]
    pub max_connections: Option<u32>,
    /// Multi-window rate limits for new connections (overrides group/server defaults)
    #[serde(default)]
    pub rate_limits: Option<RateLimitsConfig>,
}

impl fmt::Debug for UserConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserConfig")
            .field("username", &self.username)
            .field("password_hash", &self.password_hash.as_ref().map(|_| "***"))
            .field(
                "authorized_keys",
                &format!("[{} keys]", self.authorized_keys.len()),
            )
            .field("allow_shell", &self.allow_shell)
            .field(
                "max_new_connections_per_minute",
                &self.max_new_connections_per_minute,
            )
            .field("max_bandwidth_kbps", &self.max_bandwidth_kbps)
            .field("source_ips", &self.source_ips)
            .field("expires_at", &self.expires_at)
            .field("upstream_proxy", &self.upstream_proxy)
            .field("acl", &self.acl)
            .field("group", &self.group)
            .field("role", &self.role)
            .finish()
    }
}

/// Global ACL configuration applied to all users.
/// Users inherit these rules unless they set `inherit = false`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GlobalAclConfig {
    #[serde(default = "default_acl_policy")]
    pub default_policy: AclPolicyConfig,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

impl Default for GlobalAclConfig {
    fn default() -> Self {
        Self {
            default_policy: default_acl_policy(),
            allow: Vec::new(),
            deny: Vec::new(),
        }
    }
}

/// Per-user ACL configuration. Merged with global ACL by default.
/// - `default_policy`: if None, inherits from global; if Some, overrides global.
/// - `allow`/`deny`: appended to global rules (when `inherit = true`).
/// - `inherit`: if false, ignores global ACL entirely.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserAclConfig {
    #[serde(default)]
    pub default_policy: Option<AclPolicyConfig>,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default = "default_true")]
    pub inherit: bool,
}

impl Default for UserAclConfig {
    fn default() -> Self {
        Self {
            default_policy: None,
            allow: Vec::new(),
            deny: Vec::new(),
            inherit: true,
        }
    }
}

fn default_acl_policy() -> AclPolicyConfig {
    AclPolicyConfig::Allow
}
