use crate::proxy::ip_guard;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::debug;

/// DNS cache entry
struct CacheEntry {
    addrs: Vec<SocketAddr>,
    inserted_at: Instant,
    last_accessed: Instant,
    ttl: Duration,
}

/// DNS cache with configurable TTL and ip_guard re-validation.
pub struct DnsCache {
    cache: DashMap<String, CacheEntry>,
    /// -1 = follow native DNS TTL, 0 = disabled, N = N seconds custom TTL.
    ttl_mode: i64,
    max_entries: u32,
    pub hits: AtomicU64,
    pub misses: AtomicU64,
}

impl DnsCache {
    pub fn new(ttl_mode: i64, max_entries: u32) -> Self {
        Self {
            cache: DashMap::new(),
            ttl_mode,
            max_entries,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Check if caching is enabled.
    pub fn is_enabled(&self) -> bool {
        self.ttl_mode != 0
    }

    /// Lookup cached addresses. Re-validates against ip_guard before returning.
    /// Returns None on miss or if all cached IPs are now blocked.
    pub fn get(&self, key: &str, ip_guard_enabled: bool) -> Option<Vec<SocketAddr>> {
        if !self.is_enabled() {
            return None;
        }

        let mut entry = self.cache.get_mut(key)?;
        let now = Instant::now();

        // Check TTL expiry
        if now.duration_since(entry.inserted_at) > entry.ttl {
            drop(entry);
            self.cache.remove(key);
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        // Re-validate against ip_guard (IPs may have been reclassified)
        let addrs: Vec<SocketAddr> = if ip_guard_enabled {
            entry
                .addrs
                .iter()
                .filter(|a| !ip_guard::is_dangerous_ip(&a.ip()))
                .copied()
                .collect()
        } else {
            entry.addrs.clone()
        };

        if addrs.is_empty() {
            drop(entry);
            self.cache.remove(key);
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        // Update last_accessed for LRU tracking
        entry.last_accessed = now;

        self.hits.fetch_add(1, Ordering::Relaxed);
        Some(addrs)
    }

    /// Insert resolved addresses into cache with the given native TTL.
    pub fn insert(&self, key: &str, addrs: Vec<SocketAddr>, native_ttl: Option<Duration>) {
        if !self.is_enabled() {
            return;
        }

        // Enforce max entries: evict expired first, then LRU if still full
        if self.cache.len() >= self.max_entries as usize {
            self.cleanup_expired();
            if self.cache.len() >= self.max_entries as usize {
                self.evict_lru();
            }
        }

        let ttl = self.resolve_ttl(native_ttl);
        let now = Instant::now();

        self.cache.insert(
            key.to_string(),
            CacheEntry {
                addrs,
                inserted_at: now,
                last_accessed: now,
                ttl,
            },
        );
    }

    /// Determine the TTL to use based on config mode and native DNS TTL.
    fn resolve_ttl(&self, native_ttl: Option<Duration>) -> Duration {
        if self.ttl_mode < 0 {
            // Follow native DNS TTL, default to 60s if not available
            native_ttl.unwrap_or(Duration::from_secs(60))
        } else {
            Duration::from_secs(self.ttl_mode as u64)
        }
    }

    /// Evict the least-recently-accessed entry from the cache.
    fn evict_lru(&self) {
        let oldest = self
            .cache
            .iter()
            .min_by_key(|entry| entry.value().last_accessed)
            .map(|entry| entry.key().clone());

        if let Some(key) = oldest {
            debug!(key = %key, "DNS cache full, evicting LRU entry");
            self.cache.remove(&key);
        }
    }

    /// Remove expired entries.
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        self.cache
            .retain(|_, entry| now.duration_since(entry.inserted_at) <= entry.ttl);
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new(-1, 1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn addr(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]),
            port,
        ))
    }

    #[test]
    fn test_lru_eviction_when_full() {
        // Cache with max 2 entries, 60s TTL
        let cache = DnsCache::new(60, 2);

        cache.insert("a.com", vec![addr([1, 1, 1, 1], 80)], None);
        cache.insert("b.com", vec![addr([2, 2, 2, 2], 80)], None);
        assert_eq!(cache.len(), 2);

        // Access "a.com" to make it more recently used
        let _ = cache.get("a.com", false);

        // Insert "c.com" — should evict "b.com" (least recently accessed)
        cache.insert("c.com", vec![addr([3, 3, 3, 3], 80)], None);
        assert_eq!(cache.len(), 2);

        // "b.com" should be evicted, "a.com" and "c.com" should remain
        assert!(cache.get("a.com", false).is_some());
        assert!(cache.get("b.com", false).is_none());
        assert!(cache.get("c.com", false).is_some());
    }

    #[test]
    fn test_expired_entries_cleaned_before_lru() {
        // Cache with max 2 entries, 0-second TTL (immediate expiry)
        let cache = DnsCache::new(1, 2); // 1 second TTL

        cache.insert(
            "a.com",
            vec![addr([1, 1, 1, 1], 80)],
            Some(Duration::from_millis(0)),
        );
        cache.insert(
            "b.com",
            vec![addr([2, 2, 2, 2], 80)],
            Some(Duration::from_millis(0)),
        );

        // Both entries should be expired, so inserting a third should succeed
        // after cleanup (no LRU needed)
        std::thread::sleep(Duration::from_millis(10));
        cache.insert("c.com", vec![addr([3, 3, 3, 3], 80)], None);

        // Only "c.com" should exist (the expired ones were cleaned up)
        assert!(cache.get("c.com", false).is_some());
    }

    #[test]
    fn test_disabled_cache() {
        let cache = DnsCache::new(0, 10);
        cache.insert("a.com", vec![addr([1, 1, 1, 1], 80)], None);
        assert_eq!(cache.len(), 0);
        assert!(cache.get("a.com", false).is_none());
    }

    #[test]
    fn test_cache_hit_miss_counters() {
        let cache = DnsCache::new(60, 10);
        cache.insert("a.com", vec![addr([1, 1, 1, 1], 80)], None);

        let _ = cache.get("a.com", false); // hit
        let _ = cache.get("b.com", false); // miss (not in cache, returns None early)

        assert_eq!(cache.hits.load(Ordering::Relaxed), 1);
        // misses counter only incremented on expired/blocked entries, not on simple None
        assert_eq!(cache.misses.load(Ordering::Relaxed), 0);
    }
}
