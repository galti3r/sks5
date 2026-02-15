use crate::audit::AuditLogger;
use dashmap::DashMap;
use ipnet::IpNet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Parse a whitelist entry as either an IpNet (CIDR) or a single IpAddr.
fn parse_whitelist(entries: &[String]) -> Vec<IpNet> {
    entries
        .iter()
        .filter_map(|s| {
            // Try CIDR first, then single IP
            if let Ok(net) = s.parse::<IpNet>() {
                Some(net)
            } else if let Ok(ip) = s.parse::<IpAddr>() {
                Some(IpNet::from(ip))
            } else {
                warn!(entry = %s, "Invalid IP/CIDR in ban whitelist, skipping");
                None
            }
        })
        .collect()
}

/// Auto-ban manager (fail2ban-like)
pub struct BanManager {
    /// Track auth failures per IP: IP -> list of failure timestamps
    failures: DashMap<IpAddr, Vec<Instant>>,
    /// Currently banned IPs: IP -> ban expiry
    bans: DashMap<IpAddr, Instant>,
    /// Number of failures before ban
    threshold: u32,
    /// Window in which failures are counted
    window: Duration,
    /// Ban duration
    duration: Duration,
    /// IPs/CIDRs that are never banned (L-4: supports CIDR ranges)
    whitelist: Vec<IpNet>,
    /// Whether banning is enabled
    enabled: bool,
    /// Optional audit logger for ban events
    audit: Option<Arc<AuditLogger>>,
}

impl BanManager {
    pub fn new(
        enabled: bool,
        threshold: u32,
        window_secs: u64,
        duration_secs: u64,
        whitelist: Vec<String>,
    ) -> Self {
        Self {
            failures: DashMap::new(),
            bans: DashMap::new(),
            threshold,
            window: Duration::from_secs(window_secs),
            duration: Duration::from_secs(duration_secs),
            whitelist: parse_whitelist(&whitelist),
            enabled,
            audit: None,
        }
    }

    /// Update configuration without losing existing bans/failures (M-2 fix)
    pub fn update_config(
        &mut self,
        enabled: bool,
        threshold: u32,
        window_secs: u64,
        duration_secs: u64,
        whitelist: Vec<String>,
    ) {
        self.enabled = enabled;
        self.threshold = threshold;
        self.window = Duration::from_secs(window_secs);
        self.duration = Duration::from_secs(duration_secs);
        self.whitelist = parse_whitelist(&whitelist);
        // bans and failures are preserved
    }

    /// Set the audit logger for ban event emission.
    pub fn set_audit(&mut self, audit: Arc<AuditLogger>) {
        self.audit = Some(audit);
    }

    /// Record an auth failure. May trigger a ban.
    pub fn record_failure(&self, ip: &IpAddr) {
        if !self.enabled || self.is_whitelisted(ip) {
            return;
        }

        // M-4: Capacity check to prevent memory exhaustion
        if !self.failures.contains_key(ip) && self.failures.len() >= 100_000 {
            warn!("Ban manager failure map capacity exceeded, rejecting new IP tracking");
            return;
        }

        let now = Instant::now();
        let mut failures = self.failures.entry(*ip).or_default();

        // Remove old failures outside the window
        failures.retain(|t| now.duration_since(*t) < self.window);
        // Cap vector size to prevent memory growth under sustained attack
        let max_entries = (self.threshold as usize).saturating_mul(2).max(10);
        if failures.len() >= max_entries {
            let drain_count = failures.len() - max_entries + 1;
            failures.drain(..drain_count);
        }
        failures.push(now);

        if failures.len() >= self.threshold as usize {
            // Ban the IP
            let expiry = now + self.duration;
            self.bans.insert(*ip, expiry);
            failures.clear();
            warn!(ip = %ip, duration_secs = self.duration.as_secs(), "IP banned");
            if let Some(ref audit) = self.audit {
                audit.log_ban_created(ip, self.duration.as_secs());
            }
        }
    }

    /// Check if an IP is currently banned
    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        if !self.enabled || self.is_whitelisted(ip) {
            return false;
        }

        // Atomically remove expired bans (no TOCTOU between get and remove)
        if self
            .bans
            .remove_if(ip, |_, expiry| Instant::now() >= *expiry)
            .is_some()
        {
            info!(ip = %ip, "IP ban expired");
            if let Some(ref audit) = self.audit {
                audit.log_ban_expired(ip);
            }
            return false;
        }

        self.bans.contains_key(ip)
    }

    /// Manually ban an IP
    pub fn ban(&self, ip: IpAddr, duration: Duration) {
        self.bans.insert(ip, Instant::now() + duration);
        info!(ip = %ip, duration_secs = duration.as_secs(), "IP manually banned");
    }

    /// Manually unban an IP
    pub fn unban(&self, ip: &IpAddr) -> bool {
        let removed = self.bans.remove(ip).is_some();
        if removed {
            info!(ip = %ip, "IP manually unbanned");
        }
        removed
    }

    /// Get all currently banned IPs
    pub fn banned_ips(&self) -> Vec<(IpAddr, Instant)> {
        let now = Instant::now();
        self.bans
            .iter()
            .filter(|entry| now < *entry.value())
            .map(|entry| (*entry.key(), *entry.value()))
            .collect()
    }

    fn is_whitelisted(&self, ip: &IpAddr) -> bool {
        self.whitelist.iter().any(|net| net.contains(ip))
    }

    /// Remove stale entries from the failures map (IPs with no recent failures).
    /// Called periodically by the cleanup task.
    pub fn cleanup_stale_failures(&self) {
        let now = Instant::now();
        self.failures.retain(|_ip, failures| {
            failures.retain(|t| now.duration_since(*t) < self.window);
            !failures.is_empty()
        });
        // L-5: Also clean up expired bans
        self.bans.retain(|_ip, expiry| now < *expiry);
    }
}

/// Spawn a background task that periodically cleans up stale failure entries,
/// expired bans, and stale rate limiter entries.
pub fn spawn_cleanup_task(security: Arc<tokio::sync::RwLock<super::SecurityManager>>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
            let sec = security.read().await;
            sec.ban_manager().cleanup_stale_failures();
            sec.cleanup_rate_limiters(Duration::from_secs(600));
            debug!("Security cleanup completed (bans + rate limiters)");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ban_after_threshold() {
        let mgr = BanManager::new(true, 3, 300, 60, vec![]);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        assert!(!mgr.is_banned(&ip));
        mgr.record_failure(&ip);
        mgr.record_failure(&ip);
        assert!(!mgr.is_banned(&ip));
        mgr.record_failure(&ip);
        assert!(mgr.is_banned(&ip));
    }

    #[test]
    fn test_whitelist_bypass() {
        let mgr = BanManager::new(true, 1, 300, 60, vec!["127.0.0.1".to_string()]);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        mgr.record_failure(&ip);
        mgr.record_failure(&ip);
        assert!(!mgr.is_banned(&ip));
    }

    #[test]
    fn test_disabled() {
        let mgr = BanManager::new(false, 1, 300, 60, vec![]);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        mgr.record_failure(&ip);
        mgr.record_failure(&ip);
        assert!(!mgr.is_banned(&ip));
    }

    #[test]
    fn test_manual_ban_unban() {
        let mgr = BanManager::new(true, 100, 300, 60, vec![]);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        assert!(!mgr.is_banned(&ip));
        mgr.ban(ip, Duration::from_secs(60));
        assert!(mgr.is_banned(&ip));
        mgr.unban(&ip);
        assert!(!mgr.is_banned(&ip));
    }
}
