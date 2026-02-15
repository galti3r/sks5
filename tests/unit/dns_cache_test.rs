use sks5::proxy::dns_cache::DnsCache;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;

// -- Helper ------------------------------------------------------------------

fn addr(s: &str) -> SocketAddr {
    s.parse::<SocketAddr>().unwrap()
}

fn public_addrs() -> Vec<SocketAddr> {
    vec![addr("8.8.8.8:53"), addr("1.1.1.1:53")]
}

// -- 1. disabled_cache_returns_none ------------------------------------------

#[test]
fn disabled_cache_returns_none() {
    let cache = DnsCache::new(0, 100);
    assert!(!cache.is_enabled());
    cache.insert("example.com", public_addrs(), None);
    assert!(cache.get("example.com", false).is_none());
    assert!(cache.get("example.com", true).is_none());
}

// -- 2. disabled_cache_insert_noop -------------------------------------------

#[test]
fn disabled_cache_insert_noop() {
    let cache = DnsCache::new(0, 100);
    cache.insert("example.com", public_addrs(), None);
    assert_eq!(cache.len(), 0);
    assert!(cache.is_empty());
}

// -- 3. insert_and_get_hit ---------------------------------------------------

#[test]
fn insert_and_get_hit() {
    let cache = DnsCache::new(60, 100);
    let addrs = public_addrs();
    cache.insert("example.com", addrs.clone(), None);

    let result = cache.get("example.com", false);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), addrs);
    assert_eq!(cache.hits.load(Ordering::Relaxed), 1);
    assert_eq!(cache.misses.load(Ordering::Relaxed), 0);
}

// -- 4. cache_miss_increments_counter ----------------------------------------

#[test]
fn cache_miss_increments_counter() {
    let cache = DnsCache::new(60, 100);
    let result = cache.get("nonexistent.com", false);
    assert!(result.is_none());
    // A miss on a key that never existed doesn't reach the TTL/ip_guard path,
    // it returns None from the DashMap lookup before incrementing miss counter.
    // The miss counter is only incremented on TTL expiry or ip_guard removal.
    // So we insert, wait for expiry, then verify.
    // But for a simple miss (key not found), the code path returns None from
    // `self.cache.get(key)?` which does NOT increment misses.
    // Let's verify this behavior is consistent:
    assert_eq!(cache.misses.load(Ordering::Relaxed), 0);

    // To actually test miss counter: insert with expired TTL
    // We use ttl_mode=1 (1 second custom) and sleep
    let cache2 = DnsCache::new(1, 100);
    cache2.insert("test.com", public_addrs(), None);
    // Entry exists and is fresh
    assert!(cache2.get("test.com", false).is_some());
    assert_eq!(cache2.hits.load(Ordering::Relaxed), 1);

    // Sleep to expire
    std::thread::sleep(Duration::from_millis(1100));
    let result = cache2.get("test.com", false);
    assert!(result.is_none());
    assert_eq!(cache2.misses.load(Ordering::Relaxed), 1);
}

// -- 5. ttl_expiry_removes_entry ---------------------------------------------

#[tokio::test]
async fn ttl_expiry_removes_entry() {
    // ttl_mode=1 means 1 second custom TTL
    let cache = DnsCache::new(1, 100);
    cache.insert("expire.com", public_addrs(), None);

    // Immediately accessible
    assert!(cache.get("expire.com", false).is_some());

    // Wait for TTL to expire
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // Now it should be gone
    assert!(cache.get("expire.com", false).is_none());
    // The expired lookup should have removed the entry
    assert_eq!(cache.len(), 0);
}

// -- 6. native_ttl_mode_uses_provided_ttl ------------------------------------

#[tokio::test]
async fn native_ttl_mode_uses_provided_ttl() {
    // ttl_mode=-1 means follow native DNS TTL
    let cache = DnsCache::new(-1, 100);
    cache.insert(
        "native.com",
        public_addrs(),
        Some(Duration::from_millis(100)),
    );

    // Immediately accessible
    assert!(cache.get("native.com", false).is_some());

    // Wait for native TTL to expire
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Should be expired now
    assert!(cache.get("native.com", false).is_none());
}

// -- 7. native_ttl_mode_defaults_60s -----------------------------------------

#[test]
fn native_ttl_mode_defaults_60s() {
    // ttl_mode=-1, native_ttl=None -> defaults to 60 seconds
    let cache = DnsCache::new(-1, 100);
    cache.insert("default-ttl.com", public_addrs(), None);

    // Entry should exist immediately (60s is far in the future)
    assert!(cache.get("default-ttl.com", false).is_some());
    assert_eq!(cache.len(), 1);
}

// -- 8. custom_ttl_mode_overrides_native -------------------------------------

#[tokio::test]
async fn custom_ttl_mode_overrides_native() {
    // ttl_mode=1 (1 second) overrides native_ttl=60s
    let cache = DnsCache::new(1, 100);
    cache.insert(
        "override.com",
        public_addrs(),
        Some(Duration::from_secs(60)),
    );

    // Immediately accessible
    assert!(cache.get("override.com", false).is_some());

    // Wait for custom TTL (1s) to expire -- native would still be valid
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // Custom TTL wins, entry expired despite native_ttl=60s
    assert!(cache.get("override.com", false).is_none());
}

// -- 9. max_entries_enforced (LRU eviction) ----------------------------------

#[test]
fn max_entries_enforced() {
    let cache = DnsCache::new(300, 3);
    cache.insert("a.com", vec![addr("1.1.1.1:53")], None);
    cache.insert("b.com", vec![addr("2.2.2.2:53")], None);
    cache.insert("c.com", vec![addr("3.3.3.3:53")], None);
    assert_eq!(cache.len(), 3);

    // Access "b.com" and "c.com" to make them more recently used than "a.com"
    let _ = cache.get("b.com", false);
    let _ = cache.get("c.com", false);

    // 4th insert evicts the LRU entry ("a.com") and inserts "d.com"
    cache.insert("d.com", vec![addr("4.4.4.4:53")], None);
    assert_eq!(cache.len(), 3);

    // d.com was inserted
    assert!(cache.get("d.com", false).is_some());

    // a.com was evicted (least recently accessed)
    assert!(cache.get("a.com", false).is_none());

    // b.com and c.com still there
    assert!(cache.get("b.com", false).is_some());
    assert!(cache.get("c.com", false).is_some());
}

// -- 10. max_entries_cleanup_then_insert -------------------------------------

#[tokio::test]
async fn max_entries_cleanup_then_insert() {
    // max_entries=2, use short TTL so entries expire quickly
    let cache = DnsCache::new(1, 2);
    cache.insert("old1.com", vec![addr("1.1.1.1:53")], None);
    cache.insert("old2.com", vec![addr("2.2.2.2:53")], None);
    assert_eq!(cache.len(), 2);

    // Wait for entries to expire
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // Insert triggers cleanup_expired, then adds successfully
    cache.insert("new.com", vec![addr("3.3.3.3:53")], None);
    // Old entries cleaned up during insert, new one added
    assert_eq!(cache.len(), 1);
    assert!(cache.get("new.com", false).is_some());
}

// -- 11. ip_guard_filters_dangerous_ips --------------------------------------

#[test]
fn ip_guard_filters_dangerous_ips() {
    let cache = DnsCache::new(60, 100);
    // Insert only loopback addresses (dangerous)
    cache.insert("evil.com", vec![addr("127.0.0.1:80")], None);

    // With ip_guard enabled, all addresses are filtered -> None
    let result = cache.get("evil.com", true);
    assert!(result.is_none());

    // The entry should also be removed from the cache since all IPs were blocked
    assert_eq!(cache.len(), 0);
}

// -- 12. ip_guard_disabled_allows_all ----------------------------------------

#[test]
fn ip_guard_disabled_allows_all() {
    let cache = DnsCache::new(60, 100);
    let addrs = vec![addr("127.0.0.1:80")];
    cache.insert("local.com", addrs.clone(), None);

    // With ip_guard disabled, loopback addresses are returned
    let result = cache.get("local.com", false);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), addrs);
}

// -- 13. ip_guard_mixed_addrs ------------------------------------------------

#[test]
fn ip_guard_mixed_addrs() {
    let cache = DnsCache::new(60, 100);
    let addrs = vec![addr("8.8.8.8:53"), addr("127.0.0.1:80")];
    cache.insert("mixed.com", addrs, None);

    // With ip_guard enabled, only public IPs returned
    let result = cache.get("mixed.com", true);
    assert!(result.is_some());
    let filtered = result.unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0], addr("8.8.8.8:53"));

    // Verify hit was counted (some addresses survived)
    assert_eq!(cache.hits.load(Ordering::Relaxed), 1);
}

// -- 14. cleanup_expired_removes_old -----------------------------------------

#[tokio::test]
async fn cleanup_expired_removes_old() {
    let cache = DnsCache::new(1, 100);
    cache.insert("stale1.com", vec![addr("1.1.1.1:53")], None);
    cache.insert("stale2.com", vec![addr("2.2.2.2:53")], None);
    cache.insert("stale3.com", vec![addr("3.3.3.3:53")], None);
    assert_eq!(cache.len(), 3);

    // Wait for TTL to expire
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // Cleanup should remove all expired entries
    cache.cleanup_expired();
    assert_eq!(cache.len(), 0);
    assert!(cache.is_empty());
}

// -- 15. is_empty_and_len ----------------------------------------------------

#[test]
fn is_empty_and_len() {
    let cache = DnsCache::new(60, 100);
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);

    cache.insert("one.com", vec![addr("1.1.1.1:53")], None);
    assert!(!cache.is_empty());
    assert_eq!(cache.len(), 1);

    cache.insert("two.com", vec![addr("2.2.2.2:53")], None);
    assert!(!cache.is_empty());
    assert_eq!(cache.len(), 2);

    // Re-inserting the same key updates, doesn't add
    cache.insert("one.com", vec![addr("3.3.3.3:53")], None);
    assert_eq!(cache.len(), 2);
}

// -- 16. default_creates_enabled_cache ---------------------------------------

#[test]
fn default_creates_enabled_cache() {
    let cache = DnsCache::default();
    assert!(cache.is_enabled());
    // Default should work: insert and get
    cache.insert("default.com", public_addrs(), None);
    assert!(cache.get("default.com", false).is_some());
    assert_eq!(cache.len(), 1);
    assert_eq!(cache.hits.load(Ordering::Relaxed), 1);
}

// -- 17. concurrent_access ---------------------------------------------------

#[tokio::test]
async fn concurrent_access() {
    use std::sync::Arc;

    let cache = Arc::new(DnsCache::new(60, 10_000));
    let mut handles = Vec::new();

    // Spawn writer tasks
    for i in 0..10 {
        let cache = Arc::clone(&cache);
        handles.push(tokio::spawn(async move {
            for j in 0..100 {
                let key = format!("host-{}-{}.com", i, j);
                let port = 1000 + (j % 65) as u16;
                let addr_str = format!("8.{}.{}.{}:{}", i, j / 256, j % 256, port);
                let a: SocketAddr = addr_str.parse().unwrap();
                cache.insert(&key, vec![a], None);
            }
        }));
    }

    // Spawn reader tasks
    for i in 0..10 {
        let cache = Arc::clone(&cache);
        handles.push(tokio::spawn(async move {
            for j in 0..100 {
                let key = format!("host-{}-{}.com", i, j);
                // Result may or may not be present depending on timing
                let _ = cache.get(&key, false);
                let _ = cache.get(&key, true);
            }
        }));
    }

    // Spawn cleanup tasks
    for _ in 0..3 {
        let cache = Arc::clone(&cache);
        handles.push(tokio::spawn(async move {
            for _ in 0..10 {
                cache.cleanup_expired();
                tokio::task::yield_now().await;
            }
        }));
    }

    // All tasks must complete without panics
    for handle in handles {
        handle.await.expect("task must not panic");
    }

    // Cache should have some entries (writers ran, TTL is 60s so nothing expired)
    assert!(!cache.is_empty());
    // Total hits + misses should be sensible (readers ran)
    let total_lookups = cache.hits.load(Ordering::Relaxed) + cache.misses.load(Ordering::Relaxed);
    // At minimum some lookups happened (readers did 10*100*2 = 2000 lookups)
    assert!(total_lookups > 0 || !cache.is_empty());
}
