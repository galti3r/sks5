pub mod ban;
pub mod ip_filter;
pub mod ip_reputation;
pub mod normalize;
pub mod rate_limit;

use crate::audit::AuditLogger;
use crate::config::types::AppConfig;
use ban::BanManager;
use ip_reputation::IpReputationManager;
use ipnet::IpNet;
use normalize::normalize_ip;
use rate_limit::{IpRateLimiter, UserRateLimiter};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// Parse ban whitelist entries as IpNet (supports both single IPs and CIDR ranges).
fn parse_ban_whitelist(entries: &[String]) -> Vec<IpNet> {
    entries
        .iter()
        .filter_map(|s| {
            if let Ok(net) = s.parse::<IpNet>() {
                Some(net)
            } else if let Ok(ip) = s.parse::<IpAddr>() {
                Some(IpNet::from(ip))
            } else {
                None
            }
        })
        .collect()
}

/// Centralized security manager
pub struct SecurityManager {
    ban_manager: BanManager,
    rate_limiter: UserRateLimiter,
    ip_rate_limiter: IpRateLimiter,
    ip_reputation: IpReputationManager,
    global_allowed_ips: Vec<IpNet>,
    /// L-4: Ban whitelist supports CIDR ranges
    ban_whitelist: Vec<IpNet>,
}

impl SecurityManager {
    pub fn new(config: &AppConfig) -> Self {
        let ban_manager = BanManager::new(
            config.security.ban_enabled,
            config.security.ban_threshold,
            config.security.ban_window,
            config.security.ban_duration,
            config.security.ban_whitelist.clone(),
        );

        let ip_reputation = IpReputationManager::new(
            config.security.ip_reputation_enabled,
            config.security.ip_reputation_ban_threshold,
        );

        Self {
            ban_manager,
            rate_limiter: UserRateLimiter::new(config.security.rate_limit_max_users),
            ip_rate_limiter: IpRateLimiter::new(
                config.security.max_new_connections_per_ip_per_minute,
                config.security.rate_limit_max_ips,
            ),
            ip_reputation,
            global_allowed_ips: config.security.allowed_source_ips.clone(),
            ban_whitelist: parse_ban_whitelist(&config.security.ban_whitelist),
        }
    }

    /// Reload security configuration (called on SIGHUP)
    /// Preserves existing bans (M-2 fix)
    pub fn reload(&mut self, config: &AppConfig) {
        self.ban_manager.update_config(
            config.security.ban_enabled,
            config.security.ban_threshold,
            config.security.ban_window,
            config.security.ban_duration,
            config.security.ban_whitelist.clone(),
        );
        self.rate_limiter = UserRateLimiter::new(config.security.rate_limit_max_users);
        self.ip_rate_limiter = IpRateLimiter::new(
            config.security.max_new_connections_per_ip_per_minute,
            config.security.rate_limit_max_ips,
        );
        self.ip_reputation = IpReputationManager::new(
            config.security.ip_reputation_enabled,
            config.security.ip_reputation_ban_threshold,
        );
        self.global_allowed_ips = config.security.allowed_source_ips.clone();
        self.ban_whitelist = parse_ban_whitelist(&config.security.ban_whitelist);
    }

    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        let ip = normalize_ip(*ip);
        self.ban_manager.is_banned(&ip)
    }

    pub fn record_auth_failure(&self, ip: &IpAddr) {
        let ip = normalize_ip(*ip);
        self.ban_manager.record_failure(&ip);
    }

    pub fn check_source_ip(&self, ip: &IpAddr) -> bool {
        let ip = normalize_ip(*ip);
        ip_filter::is_allowed(&ip, &self.global_allowed_ips)
    }

    /// Combined pre-authentication check: IP rate limit + IP allowlist + ban status.
    /// Returns Ok(()) if the IP is allowed, or Err with a reason string.
    pub fn pre_auth_check(&self, ip: &IpAddr) -> Result<(), &'static str> {
        // P2-1: Per-IP rate limiting (before other checks)
        let normalized = normalize_ip(*ip);
        if !self
            .ban_whitelist
            .iter()
            .any(|net| net.contains(&normalized))
            && !self.ip_rate_limiter.check(&normalized)
        {
            return Err("IP rate limit exceeded");
        }
        if !self.check_source_ip(ip) {
            return Err("disallowed source IP");
        }
        if self.is_banned(ip) {
            return Err("banned IP");
        }
        if self.ip_reputation.should_ban(&normalized) {
            return Err("IP reputation too low");
        }
        Ok(())
    }

    pub fn check_rate_limit(&self, username: &str, max_per_minute: u32) -> bool {
        self.rate_limiter.check(username, max_per_minute)
    }

    /// Wire the audit logger for ban event emission.
    pub fn set_audit(&mut self, audit: Arc<AuditLogger>) {
        self.ban_manager.set_audit(audit);
    }

    pub fn ban_manager(&self) -> &BanManager {
        &self.ban_manager
    }

    pub fn ip_reputation(&self) -> &IpReputationManager {
        &self.ip_reputation
    }

    /// Clean up stale rate limiter entries
    pub fn cleanup_rate_limiters(&self, max_age: Duration) {
        self.rate_limiter.cleanup_stale(max_age);
        self.ip_rate_limiter.cleanup_stale(max_age);
    }

    /// Return (ip_count, user_count) of tracked rate limiter entries
    pub fn rate_limiter_sizes(&self) -> (usize, usize) {
        (self.ip_rate_limiter.len(), self.rate_limiter.len())
    }
}
