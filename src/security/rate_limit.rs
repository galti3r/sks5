use dashmap::DashMap;
use governor::{Quota, RateLimiter};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

type Limiter = RateLimiter<
    governor::state::NotKeyed,
    governor::state::InMemoryState,
    governor::clock::DefaultClock,
>;

/// Wraps a limiter with a last-used timestamp for staleness tracking
struct TrackedLimiter {
    limiter: Arc<Limiter>,
    last_used: Instant,
}

/// Per-user rate limiter
pub struct UserRateLimiter {
    limiters: DashMap<String, TrackedLimiter>,
    max_entries: usize,
}

/// Per-IP rate limiter (pre-auth, for connection attempts)
pub struct IpRateLimiter {
    limiters: DashMap<IpAddr, TrackedLimiter>,
    max_per_minute: u32,
    max_entries: usize,
}

impl IpRateLimiter {
    pub fn new(max_per_minute: u32, max_entries: usize) -> Self {
        Self {
            limiters: DashMap::new(),
            max_per_minute,
            max_entries,
        }
    }

    /// Check if an IP can make a new connection (returns true if allowed).
    /// 0 = unlimited.
    pub fn check(&self, ip: &IpAddr) -> bool {
        if self.max_per_minute == 0 {
            return true;
        }

        if !self.limiters.contains_key(ip) && self.limiters.len() >= self.max_entries {
            // Attempt emergency cleanup of stale entries (>10 min old) before rejecting
            self.cleanup_stale(Duration::from_secs(600));

            // If still at capacity, evict oldest entries to make room
            if self.limiters.len() >= self.max_entries {
                let evicted = self.evict_oldest(self.max_entries / 10);
                warn!(
                    tracked_ips = self.limiters.len(),
                    evicted, "IP rate limiter at capacity, evicted oldest entries"
                );
            }
        }

        let entry = self.limiters.entry(*ip).or_insert_with(|| {
            let quota =
                Quota::per_minute(NonZeroU32::new(self.max_per_minute).unwrap_or(NonZeroU32::MIN));
            TrackedLimiter {
                limiter: Arc::new(RateLimiter::direct(quota)),
                last_used: Instant::now(),
            }
        });

        let mut tracked = entry;
        tracked.last_used = Instant::now();
        tracked.limiter.check().is_ok()
    }

    /// Remove entries that haven't been used for `max_age`.
    pub fn cleanup_stale(&self, max_age: Duration) {
        let now = Instant::now();
        let before = self.limiters.len();
        self.limiters
            .retain(|_, tracked| now.duration_since(tracked.last_used) < max_age);
        let removed = before.saturating_sub(self.limiters.len());
        if removed > 0 {
            debug!(
                removed,
                remaining = self.limiters.len(),
                "IP rate limiter stale cleanup"
            );
        }
    }

    /// Evict the oldest `count` entries (LRU-like). Returns how many were evicted.
    fn evict_oldest(&self, count: usize) -> usize {
        if count == 0 || self.limiters.is_empty() {
            return 0;
        }

        // Collect (key, last_used) without holding shard locks for long
        let mut entries: Vec<(IpAddr, Instant)> = self
            .limiters
            .iter()
            .map(|entry| (*entry.key(), entry.value().last_used))
            .collect();

        // Sort by last_used ascending (oldest first)
        entries.sort_by_key(|&(_, t)| t);

        let to_evict = entries.len().min(count);
        for (ip, _) in entries.into_iter().take(to_evict) {
            self.limiters.remove(&ip);
        }

        to_evict
    }

    /// Current number of tracked entries.
    pub fn len(&self) -> usize {
        self.limiters.len()
    }

    /// Whether the rate limiter has no tracked entries.
    pub fn is_empty(&self) -> bool {
        self.limiters.is_empty()
    }
}

impl Default for IpRateLimiter {
    fn default() -> Self {
        Self::new(0, 100_000)
    }
}

impl UserRateLimiter {
    pub fn new(max_entries: usize) -> Self {
        Self {
            limiters: DashMap::new(),
            max_entries,
        }
    }

    /// Check if a user can make a new connection (returns true if allowed)
    pub fn check(&self, username: &str, max_per_minute: u32) -> bool {
        if max_per_minute == 0 {
            return true; // 0 = unlimited
        }

        // Safety cap: refuse if too many tracked usernames (DoS protection)
        if !self.limiters.contains_key(username) && self.limiters.len() >= self.max_entries {
            // Attempt emergency cleanup of stale entries (>10 min old) before rejecting
            self.cleanup_stale(Duration::from_secs(600));

            // If still at capacity, evict oldest entries to make room
            if self.limiters.len() >= self.max_entries {
                let evicted = self.evict_oldest(self.max_entries / 10);
                warn!(
                    tracked_users = self.limiters.len(),
                    evicted, "User rate limiter at capacity, evicted oldest entries"
                );
            }
        }

        let entry = self
            .limiters
            .entry(username.to_string())
            .or_insert_with(|| {
                let quota =
                    Quota::per_minute(NonZeroU32::new(max_per_minute).unwrap_or(NonZeroU32::MIN));
                TrackedLimiter {
                    limiter: Arc::new(RateLimiter::direct(quota)),
                    last_used: Instant::now(),
                }
            });

        let mut tracked = entry;
        tracked.last_used = Instant::now();
        tracked.limiter.check().is_ok()
    }

    /// Remove entries that haven't been used for `max_age`.
    pub fn cleanup_stale(&self, max_age: Duration) {
        let now = Instant::now();
        let before = self.limiters.len();
        self.limiters
            .retain(|_, tracked| now.duration_since(tracked.last_used) < max_age);
        let removed = before.saturating_sub(self.limiters.len());
        if removed > 0 {
            debug!(
                removed,
                remaining = self.limiters.len(),
                "User rate limiter stale cleanup"
            );
        }
    }

    /// Evict the oldest `count` entries (LRU-like). Returns how many were evicted.
    fn evict_oldest(&self, count: usize) -> usize {
        if count == 0 || self.limiters.is_empty() {
            return 0;
        }

        // Collect (key, last_used) without holding shard locks for long
        let mut entries: Vec<(String, Instant)> = self
            .limiters
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().last_used))
            .collect();

        // Sort by last_used ascending (oldest first)
        entries.sort_by_key(|&(_, t)| t);

        let to_evict = entries.len().min(count);
        for (username, _) in entries.into_iter().take(to_evict) {
            self.limiters.remove(&username);
        }

        to_evict
    }

    /// Current number of tracked entries.
    pub fn len(&self) -> usize {
        self.limiters.len()
    }

    /// Whether the rate limiter has no tracked entries.
    pub fn is_empty(&self) -> bool {
        self.limiters.is_empty()
    }
}

impl Default for UserRateLimiter {
    fn default() -> Self {
        Self::new(10_000)
    }
}

/// Configuration for the background rate limiter cleanup task.
pub struct RateLimitCleanupConfig {
    /// How often to run cleanup (in seconds).
    pub cleanup_interval_secs: u64,
    /// Max age for stale entries (entries unused for this long are removed).
    pub max_stale_age: Duration,
}

impl Default for RateLimitCleanupConfig {
    fn default() -> Self {
        Self {
            cleanup_interval_secs: 60,
            max_stale_age: Duration::from_secs(600),
        }
    }
}

/// Spawn a background task that periodically cleans up stale rate limiter entries
/// and enforces capacity limits. Runs independently of the ban cleanup task to
/// avoid blocking the hot path during distributed brute-force attacks (S-8, P-7).
pub fn spawn_cleanup_task(
    security: Arc<tokio::sync::RwLock<super::SecurityManager>>,
    config: RateLimitCleanupConfig,
) {
    let interval_secs = config.cleanup_interval_secs.max(5); // minimum 5s to avoid spinning
    let max_stale_age = config.max_stale_age;

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        // Don't let missed ticks pile up (if cleanup takes longer than the interval)
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            interval.tick().await;

            // Use a read lock -- cleanup_stale and evict_oldest only need &self
            // because DashMap handles internal locking per shard.
            let sec = security.read().await;
            sec.cleanup_rate_limiters(max_stale_age);
            let (ip_count, user_count) = sec.rate_limiter_sizes();
            drop(sec); // release lock immediately

            debug!(
                ip_entries = ip_count,
                user_entries = user_count,
                "Rate limiter background cleanup completed"
            );
        }
    });

    info!(
        interval_secs = config.cleanup_interval_secs,
        max_stale_age_secs = config.max_stale_age.as_secs(),
        "Rate limiter background cleanup task started"
    );
}
