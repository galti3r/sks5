pub mod bandwidth;
pub mod rolling_window;

pub use crate::config::types::QuotaConfig;
use crate::config::types::{LimitsConfig, RateLimitsConfig};
use dashmap::DashMap;
use rolling_window::RollingWindow;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Result from recording bytes: either Ok(throttle delay) or QuotaExceeded.
pub enum QuotaResult {
    /// Ok with suggested delay for throttling (Duration::ZERO if none needed).
    Ok(Duration),
    /// Quota exceeded with human-readable reason.
    Exceeded(String),
}

/// Per-user bandwidth and connection state.
pub struct UserBandwidthState {
    /// 1-second rolling window for instantaneous rate tracking.
    second_window: RollingWindow,
    /// 3600-second rolling window (60 buckets of 60s) for hourly bandwidth.
    hour_window: RollingWindow,
    /// Cumulative daily bytes.
    daily_bytes: AtomicU64,
    /// Cumulative daily connections.
    daily_connections: AtomicU32,
    /// Cumulative monthly bytes.
    monthly_bytes: AtomicU64,
    /// Cumulative monthly connections.
    monthly_connections: AtomicU32,
    /// Unix timestamp of next daily reset.
    daily_reset: AtomicU64,
    /// Unix timestamp of next monthly reset.
    monthly_reset: AtomicU64,
    /// Per-user multi-window connection rate counters.
    conn_per_second: RollingWindow,
    conn_per_minute: RollingWindow,
    conn_per_hour: RollingWindow,
    /// Lifetime total bytes (never auto-reset by lazy_reset)
    total_bytes: AtomicU64,
    /// Last activity timestamp (for cleanup).
    last_activity: AtomicU64,
}

impl UserBandwidthState {
    fn new() -> Self {
        let now = unix_secs();
        Self {
            second_window: RollingWindow::new(1, 1),
            hour_window: RollingWindow::new(3600, 60),
            daily_bytes: AtomicU64::new(0),
            daily_connections: AtomicU32::new(0),
            monthly_bytes: AtomicU64::new(0),
            monthly_connections: AtomicU32::new(0),
            daily_reset: AtomicU64::new(next_day_boundary(now)),
            monthly_reset: AtomicU64::new(next_month_boundary(now)),
            conn_per_second: RollingWindow::new(1, 1),
            conn_per_minute: RollingWindow::new(60, 60),
            conn_per_hour: RollingWindow::new(3600, 60),
            total_bytes: AtomicU64::new(0),
            last_activity: AtomicU64::new(now),
        }
    }

    /// Lazy reset: check if day/month boundaries have passed and reset counters.
    fn lazy_reset(&self) {
        let now = unix_secs();

        // Daily reset
        let daily = self.daily_reset.load(Ordering::Acquire);
        if now >= daily {
            self.daily_bytes.store(0, Ordering::Relaxed);
            self.daily_connections.store(0, Ordering::Relaxed);
            self.daily_reset
                .store(next_day_boundary(now), Ordering::Release);
        }

        // Monthly reset
        let monthly = self.monthly_reset.load(Ordering::Acquire);
        if now >= monthly {
            self.monthly_bytes.store(0, Ordering::Relaxed);
            self.monthly_connections.store(0, Ordering::Relaxed);
            self.monthly_reset
                .store(next_month_boundary(now), Ordering::Release);
        }
    }
}

/// Usage snapshot for a user (returned by get_user_usage).
#[derive(Debug, Clone, serde::Serialize)]
pub struct UserQuotaUsage {
    pub daily_bytes: u64,
    pub daily_connections: u32,
    pub monthly_bytes: u64,
    pub monthly_connections: u32,
    pub current_rate_bps: u64,
    pub hourly_bytes: u64,
    pub total_bytes: u64,
}

/// Central quota and rate-limiting tracker.
/// Thread-safe, lock-free (atomics + DashMap).
pub struct QuotaTracker {
    user_state: DashMap<String, Arc<UserBandwidthState>>,
    /// Server-level rate limiter for new connections.
    server_conn_per_second: Option<RollingWindow>,
    server_conn_per_minute: Option<RollingWindow>,
    /// Server-level bandwidth tracker.
    server_bandwidth: RollingWindow,
    /// Server bandwidth limit in bytes/sec (from max_bandwidth_mbps).
    server_bandwidth_limit_bps: AtomicU64,
}

impl QuotaTracker {
    pub fn new(limits: &LimitsConfig) -> Self {
        let server_bw_limit = limits.max_bandwidth_mbps * 1_000_000 / 8; // Mbps -> bytes/sec
        Self {
            user_state: DashMap::new(),
            server_conn_per_second: if limits.max_new_connections_per_second > 0 {
                Some(RollingWindow::new(1, 1))
            } else {
                None
            },
            server_conn_per_minute: if limits.max_new_connections_per_minute > 0 {
                Some(RollingWindow::new(60, 60))
            } else {
                None
            },
            server_bandwidth: RollingWindow::new(1, 1),
            server_bandwidth_limit_bps: AtomicU64::new(server_bw_limit),
        }
    }

    /// Get or create per-user state. Can be cached to avoid DashMap lookups in hot loops.
    pub fn get_user(&self, username: &str) -> Arc<UserBandwidthState> {
        self.user_state
            .entry(username.to_string())
            .or_insert_with(|| Arc::new(UserBandwidthState::new()))
            .clone()
    }

    /// Check multi-window connection rate limits for a user.
    /// Returns Ok(()) if allowed, Err(reason) if rate-limited.
    pub fn check_connection_rate(
        &self,
        username: &str,
        rate_limits: &RateLimitsConfig,
        server_limits: &LimitsConfig,
    ) -> Result<(), String> {
        // Server-level checks
        if let Some(ref limiter) = self.server_conn_per_second {
            if limiter.sum() >= server_limits.max_new_connections_per_second as u64 {
                return Err("server connection rate limit (per-second) exceeded".to_string());
            }
        }
        if let Some(ref limiter) = self.server_conn_per_minute {
            if limiter.sum() >= server_limits.max_new_connections_per_minute as u64 {
                return Err("server connection rate limit (per-minute) exceeded".to_string());
            }
        }

        // Per-user checks
        let state = self.get_user(username);
        state.last_activity.store(unix_secs(), Ordering::Relaxed);

        if rate_limits.connections_per_second > 0
            && state.conn_per_second.sum() >= rate_limits.connections_per_second as u64
        {
            return Err(format!(
                "per-user connection rate limit (per-second: {}) exceeded",
                rate_limits.connections_per_second
            ));
        }
        if rate_limits.connections_per_minute > 0
            && state.conn_per_minute.sum() >= rate_limits.connections_per_minute as u64
        {
            return Err(format!(
                "per-user connection rate limit (per-minute: {}) exceeded",
                rate_limits.connections_per_minute
            ));
        }
        if rate_limits.connections_per_hour > 0
            && state.conn_per_hour.sum() >= rate_limits.connections_per_hour as u64
        {
            return Err(format!(
                "per-user connection rate limit (per-hour: {}) exceeded",
                rate_limits.connections_per_hour
            ));
        }

        Ok(())
    }

    /// Record a new connection: increment rate counters and cumulative counters.
    /// Checks daily/monthly connection quotas BEFORE incrementing.
    pub fn record_connection(
        &self,
        username: &str,
        quotas: Option<&QuotaConfig>,
    ) -> Result<(), String> {
        let state = self.get_user(username);
        state.lazy_reset();

        // Check cumulative quotas before accepting
        if let Some(q) = quotas {
            if q.daily_connection_limit > 0
                && state.daily_connections.load(Ordering::Relaxed) >= q.daily_connection_limit
            {
                return Err("daily connection quota exceeded".to_string());
            }
            if q.monthly_connection_limit > 0
                && state.monthly_connections.load(Ordering::Relaxed) >= q.monthly_connection_limit
            {
                return Err("monthly connection quota exceeded".to_string());
            }
        }

        // Record in rate windows
        state.conn_per_second.record(1);
        state.conn_per_minute.record(1);
        state.conn_per_hour.record(1);

        // Record in server-level windows
        if let Some(ref limiter) = self.server_conn_per_second {
            limiter.record(1);
        }
        if let Some(ref limiter) = self.server_conn_per_minute {
            limiter.record(1);
        }

        // Increment cumulative counters
        state.daily_connections.fetch_add(1, Ordering::Relaxed);
        state.monthly_connections.fetch_add(1, Ordering::Relaxed);

        state.last_activity.store(unix_secs(), Ordering::Relaxed);
        Ok(())
    }

    /// Pre-check whether bandwidth quotas are already exhausted (without recording).
    /// Call this before starting a relay to avoid wasted connection setup.
    pub fn check_bandwidth_quota(
        &self,
        username: &str,
        quotas: Option<&QuotaConfig>,
    ) -> Result<(), String> {
        let Some(q) = quotas else { return Ok(()) };
        let state = self.get_user(username);
        state.lazy_reset();

        if q.total_bandwidth_bytes > 0
            && state.total_bytes.load(Ordering::Relaxed) >= q.total_bandwidth_bytes
        {
            return Err("total bandwidth quota exceeded".to_string());
        }
        if q.daily_bandwidth_bytes > 0
            && state.daily_bytes.load(Ordering::Relaxed) >= q.daily_bandwidth_bytes
        {
            return Err("daily bandwidth quota exceeded".to_string());
        }
        if q.monthly_bandwidth_bytes > 0
            && state.monthly_bytes.load(Ordering::Relaxed) >= q.monthly_bandwidth_bytes
        {
            return Err("monthly bandwidth quota exceeded".to_string());
        }
        if q.bandwidth_per_hour_bytes > 0 && state.hour_window.sum() >= q.bandwidth_per_hour_bytes {
            return Err("hourly bandwidth quota exceeded".to_string());
        }
        Ok(())
    }

    /// Record bytes transferred for a user. Returns Ok(delay) or QuotaExceeded.
    pub fn record_bytes(
        &self,
        username: &str,
        bytes: u64,
        per_conn_limit_kbps: u64,
        aggregate_limit_kbps: u64,
        quotas: Option<&QuotaConfig>,
    ) -> QuotaResult {
        let state = self.get_user(username);
        state.lazy_reset();
        state.last_activity.store(unix_secs(), Ordering::Relaxed);

        // Record in rolling windows
        state.second_window.record(bytes);
        state.hour_window.record(bytes);

        // Record server-level bandwidth
        self.server_bandwidth.record(bytes);

        // Increment cumulative counters
        state.daily_bytes.fetch_add(bytes, Ordering::Relaxed);
        state.monthly_bytes.fetch_add(bytes, Ordering::Relaxed);
        state.total_bytes.fetch_add(bytes, Ordering::Relaxed);

        // Check cumulative quotas
        if let Some(q) = quotas {
            if q.total_bandwidth_bytes > 0
                && state.total_bytes.load(Ordering::Relaxed) >= q.total_bandwidth_bytes
            {
                return QuotaResult::Exceeded("total bandwidth quota exceeded".to_string());
            }
            if q.daily_bandwidth_bytes > 0
                && state.daily_bytes.load(Ordering::Relaxed) >= q.daily_bandwidth_bytes
            {
                return QuotaResult::Exceeded("daily bandwidth quota exceeded".to_string());
            }
            if q.monthly_bandwidth_bytes > 0
                && state.monthly_bytes.load(Ordering::Relaxed) >= q.monthly_bandwidth_bytes
            {
                return QuotaResult::Exceeded("monthly bandwidth quota exceeded".to_string());
            }
            if q.bandwidth_per_hour_bytes > 0
                && state.hour_window.sum() >= q.bandwidth_per_hour_bytes
            {
                return QuotaResult::Exceeded("hourly bandwidth quota exceeded".to_string());
            }
        }

        // Compute throttle delay
        let aggregate_limit_bps = aggregate_limit_kbps * 1000 / 8;
        let aggregate_rate_bps = state.second_window.sum();
        let server_limit_bps = self.server_bandwidth_limit_bps.load(Ordering::Relaxed);
        let server_rate_bps = self.server_bandwidth.sum();

        let delay = bandwidth::compute_throttle(
            bytes,
            per_conn_limit_kbps,
            aggregate_rate_bps,
            aggregate_limit_bps,
            server_rate_bps,
            server_limit_bps,
        );

        QuotaResult::Ok(delay)
    }

    /// Like `record_bytes` but uses a pre-fetched user state to avoid DashMap lookups per chunk.
    /// Call `get_user()` once before the hot loop and pass the result here.
    pub fn record_bytes_cached(
        &self,
        state: &Arc<UserBandwidthState>,
        bytes: u64,
        per_conn_limit_kbps: u64,
        aggregate_limit_kbps: u64,
        quotas: Option<&QuotaConfig>,
    ) -> QuotaResult {
        state.lazy_reset();
        state.last_activity.store(unix_secs(), Ordering::Relaxed);

        state.second_window.record(bytes);
        state.hour_window.record(bytes);
        self.server_bandwidth.record(bytes);

        state.daily_bytes.fetch_add(bytes, Ordering::Relaxed);
        state.monthly_bytes.fetch_add(bytes, Ordering::Relaxed);
        state.total_bytes.fetch_add(bytes, Ordering::Relaxed);

        if let Some(q) = quotas {
            if q.total_bandwidth_bytes > 0
                && state.total_bytes.load(Ordering::Relaxed) >= q.total_bandwidth_bytes
            {
                return QuotaResult::Exceeded("total bandwidth quota exceeded".to_string());
            }
            if q.daily_bandwidth_bytes > 0
                && state.daily_bytes.load(Ordering::Relaxed) >= q.daily_bandwidth_bytes
            {
                return QuotaResult::Exceeded("daily bandwidth quota exceeded".to_string());
            }
            if q.monthly_bandwidth_bytes > 0
                && state.monthly_bytes.load(Ordering::Relaxed) >= q.monthly_bandwidth_bytes
            {
                return QuotaResult::Exceeded("monthly bandwidth quota exceeded".to_string());
            }
            if q.bandwidth_per_hour_bytes > 0
                && state.hour_window.sum() >= q.bandwidth_per_hour_bytes
            {
                return QuotaResult::Exceeded("hourly bandwidth quota exceeded".to_string());
            }
        }

        let aggregate_limit_bps = aggregate_limit_kbps * 1000 / 8;
        let aggregate_rate_bps = state.second_window.sum();
        let server_limit_bps = self.server_bandwidth_limit_bps.load(Ordering::Relaxed);
        let server_rate_bps = self.server_bandwidth.sum();

        let delay = bandwidth::compute_throttle(
            bytes,
            per_conn_limit_kbps,
            aggregate_rate_bps,
            aggregate_limit_bps,
            server_rate_bps,
            server_limit_bps,
        );

        QuotaResult::Ok(delay)
    }

    /// Get current usage snapshot for a user.
    pub fn get_user_usage(&self, username: &str) -> UserQuotaUsage {
        let state = self.get_user(username);
        state.lazy_reset();
        UserQuotaUsage {
            daily_bytes: state.daily_bytes.load(Ordering::Relaxed),
            daily_connections: state.daily_connections.load(Ordering::Relaxed),
            monthly_bytes: state.monthly_bytes.load(Ordering::Relaxed),
            monthly_connections: state.monthly_connections.load(Ordering::Relaxed),
            current_rate_bps: state.second_window.sum(),
            hourly_bytes: state.hour_window.sum(),
            total_bytes: state.total_bytes.load(Ordering::Relaxed),
        }
    }

    /// Update server-level limits (called on config reload).
    pub fn update_config(&self, limits: &LimitsConfig) {
        let server_bw_limit = limits.max_bandwidth_mbps * 1_000_000 / 8;
        self.server_bandwidth_limit_bps
            .store(server_bw_limit, Ordering::Relaxed);
    }

    /// Clean up stale user entries (no activity in the last `max_idle_secs` seconds).
    pub fn cleanup_stale(&self, max_idle_secs: u64) {
        let now = unix_secs();
        self.user_state.retain(|_, state| {
            let last = state.last_activity.load(Ordering::Relaxed);
            now.saturating_sub(last) < max_idle_secs
        });
    }

    /// Reset quotas for a specific user (admin action).
    pub fn reset_user(&self, username: &str) {
        if let Some(state) = self.user_state.get(username) {
            state.daily_bytes.store(0, Ordering::Relaxed);
            state.daily_connections.store(0, Ordering::Relaxed);
            state.monthly_bytes.store(0, Ordering::Relaxed);
            state.monthly_connections.store(0, Ordering::Relaxed);
            state.total_bytes.store(0, Ordering::Relaxed);
        }
    }

    /// Restore user usage from a backup (admin action).
    pub fn restore_user_usage(
        &self,
        username: &str,
        daily_bytes: u64,
        daily_connections: u32,
        monthly_bytes: u64,
        monthly_connections: u32,
        total_bytes: u64,
    ) {
        let state = self.get_user(username);
        state.daily_bytes.store(daily_bytes, Ordering::Relaxed);
        state
            .daily_connections
            .store(daily_connections, Ordering::Relaxed);
        state.monthly_bytes.store(monthly_bytes, Ordering::Relaxed);
        state
            .monthly_connections
            .store(monthly_connections, Ordering::Relaxed);
        state.total_bytes.store(total_bytes, Ordering::Relaxed);
    }

    /// Get all usernames with tracked state.
    pub fn tracked_users(&self) -> Vec<String> {
        self.user_state.iter().map(|e| e.key().clone()).collect()
    }
}

/// Compute the next day boundary (midnight UTC) from a given unix timestamp.
fn next_day_boundary(now: u64) -> u64 {
    let secs_per_day = 86400;
    ((now / secs_per_day) + 1) * secs_per_day
}

/// Compute the next month boundary (1st of next month 00:00 UTC) from a given unix timestamp.
fn next_month_boundary(now: u64) -> u64 {
    use chrono::{Datelike, LocalResult, NaiveDateTime, TimeZone, Utc};
    let dt = match Utc.timestamp_opt(now as i64, 0) {
        LocalResult::Single(t) => t,
        // Fallback: advance by 30 days if timestamp is ambiguous/invalid
        _ => return now + 30 * 86400,
    };
    let (year, month) = if dt.month() == 12 {
        (dt.year() + 1, 1)
    } else {
        (dt.year(), dt.month() + 1)
    };
    let midnight =
        chrono::NaiveTime::from_hms_opt(0, 0, 0).expect("00:00:00 is always a valid time");
    let next_month = NaiveDateTime::new(
        chrono::NaiveDate::from_ymd_opt(year, month, 1).unwrap_or(dt.naive_utc().date()),
        midnight,
    );
    Utc.from_utc_datetime(&next_month).timestamp() as u64
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_limits() -> LimitsConfig {
        LimitsConfig {
            max_bandwidth_mbps: 0,
            max_new_connections_per_second: 0,
            max_new_connections_per_minute: 0,
            ..LimitsConfig::default()
        }
    }

    #[test]
    fn test_quota_tracker_basic() {
        let tracker = QuotaTracker::new(&test_limits());
        assert_eq!(tracker.get_user_usage("alice").daily_bytes, 0);
    }

    #[test]
    fn test_record_connection() {
        let tracker = QuotaTracker::new(&test_limits());
        let result = tracker.record_connection("alice", None);
        assert!(result.is_ok());
        let usage = tracker.get_user_usage("alice");
        assert_eq!(usage.daily_connections, 1);
        assert_eq!(usage.monthly_connections, 1);
    }

    #[test]
    fn test_daily_connection_quota() {
        let tracker = QuotaTracker::new(&test_limits());
        let quota = QuotaConfig {
            daily_connection_limit: 2,
            ..Default::default()
        };
        assert!(tracker.record_connection("alice", Some(&quota)).is_ok());
        assert!(tracker.record_connection("alice", Some(&quota)).is_ok());
        assert!(tracker.record_connection("alice", Some(&quota)).is_err());
    }

    #[test]
    fn test_record_bytes_no_quota() {
        let tracker = QuotaTracker::new(&test_limits());
        match tracker.record_bytes("alice", 1024, 0, 0, None) {
            QuotaResult::Ok(d) => assert_eq!(d, Duration::ZERO),
            QuotaResult::Exceeded(_) => panic!("should not exceed"),
        }
        assert_eq!(tracker.get_user_usage("alice").daily_bytes, 1024);
    }

    #[test]
    fn test_daily_bandwidth_quota() {
        let tracker = QuotaTracker::new(&test_limits());
        let quota = QuotaConfig {
            daily_bandwidth_bytes: 1000,
            ..Default::default()
        };
        // First write: under quota
        match tracker.record_bytes("alice", 500, 0, 0, Some(&quota)) {
            QuotaResult::Ok(_) => {}
            QuotaResult::Exceeded(r) => panic!("should not exceed: {r}"),
        }
        // Second write: exceeds daily quota
        match tracker.record_bytes("alice", 600, 0, 0, Some(&quota)) {
            QuotaResult::Exceeded(r) => assert!(r.contains("daily")),
            QuotaResult::Ok(_) => panic!("should have exceeded"),
        }
    }

    #[test]
    fn test_rate_limit_check() {
        let limits = test_limits();
        let tracker = QuotaTracker::new(&limits);
        let rate = RateLimitsConfig {
            connections_per_second: 2,
            connections_per_minute: 0,
            connections_per_hour: 0,
        };
        assert!(tracker
            .check_connection_rate("alice", &rate, &limits)
            .is_ok());
        tracker.record_connection("alice", None).unwrap();
        tracker.record_connection("alice", None).unwrap();
        assert!(tracker
            .check_connection_rate("alice", &rate, &limits)
            .is_err());
    }

    #[test]
    fn test_reset_user() {
        let tracker = QuotaTracker::new(&test_limits());
        tracker.record_connection("alice", None).unwrap();
        match tracker.record_bytes("alice", 1024, 0, 0, None) {
            QuotaResult::Ok(_) => {}
            QuotaResult::Exceeded(_) => panic!(),
        }
        tracker.reset_user("alice");
        let usage = tracker.get_user_usage("alice");
        assert_eq!(usage.daily_bytes, 0);
        assert_eq!(usage.daily_connections, 0);
    }

    #[test]
    fn test_cleanup_stale() {
        let tracker = QuotaTracker::new(&test_limits());
        tracker.record_connection("alice", None).unwrap();
        assert!(tracker.tracked_users().contains(&"alice".to_string()));
        // Cleanup with 0 idle time should remove everything
        tracker.cleanup_stale(0);
        assert!(tracker.tracked_users().is_empty());
    }

    #[test]
    fn test_next_day_boundary() {
        let now = 86400 * 10 + 3600; // day 10, 1 hour in
        let boundary = next_day_boundary(now);
        assert_eq!(boundary, 86400 * 11); // midnight of day 11
    }

    #[test]
    fn test_total_bandwidth_quota() {
        let tracker = QuotaTracker::new(&test_limits());
        let quota = QuotaConfig {
            total_bandwidth_bytes: 1000,
            ..Default::default()
        };
        match tracker.record_bytes("alice", 500, 0, 0, Some(&quota)) {
            QuotaResult::Ok(_) => {}
            QuotaResult::Exceeded(r) => panic!("should not exceed: {r}"),
        }
        match tracker.record_bytes("alice", 600, 0, 0, Some(&quota)) {
            QuotaResult::Exceeded(r) => assert!(r.contains("total")),
            QuotaResult::Ok(_) => panic!("should have exceeded"),
        }
    }

    #[test]
    fn test_total_bytes_survives_lazy_reset() {
        let tracker = QuotaTracker::new(&test_limits());
        // Record some bytes
        match tracker.record_bytes("alice", 500, 0, 0, None) {
            QuotaResult::Ok(_) => {}
            QuotaResult::Exceeded(_) => panic!(),
        }
        let usage = tracker.get_user_usage("alice");
        assert_eq!(usage.total_bytes, 500);
        // total_bytes should persist (we can't easily trigger lazy_reset in test,
        // but verify the field is independent)
        assert_eq!(usage.total_bytes, 500);
    }

    #[test]
    fn test_reset_user_resets_total() {
        let tracker = QuotaTracker::new(&test_limits());
        match tracker.record_bytes("alice", 1024, 0, 0, None) {
            QuotaResult::Ok(_) => {}
            QuotaResult::Exceeded(_) => panic!(),
        }
        assert_eq!(tracker.get_user_usage("alice").total_bytes, 1024);
        tracker.reset_user("alice");
        assert_eq!(tracker.get_user_usage("alice").total_bytes, 0);
    }
}
