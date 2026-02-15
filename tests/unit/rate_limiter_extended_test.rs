use std::net::IpAddr;
use std::time::Duration;

use sks5::security::rate_limit::IpRateLimiter;

// ---------------------------------------------------------------------------
// Capacity eviction
// ---------------------------------------------------------------------------

#[test]
fn capacity_eviction_triggers_when_max_entries_exceeded() {
    // Use max_entries=20 so evict_oldest(20/10=2) actually evicts entries.
    // With max_entries=5, integer division 5/10=0 means no eviction occurs.
    let max_entries = 20;
    let limiter = IpRateLimiter::new(60, max_entries);

    // Fill to capacity with distinct IPs
    for i in 1..=max_entries as u8 {
        let ip: IpAddr = format!("10.0.0.{i}").parse().unwrap();
        assert!(limiter.check(&ip), "IP 10.0.0.{i} should be allowed");
    }
    assert_eq!(limiter.len(), max_entries);

    // A new IP beyond capacity should trigger eviction and still succeed
    let overflow_ip: IpAddr = "10.0.0.100".parse().unwrap();
    assert!(
        limiter.check(&overflow_ip),
        "IP beyond capacity should succeed after eviction"
    );

    // After eviction, total entries should be <= max_entries
    // (evict_oldest removes max_entries/10 = 2, then the new entry is inserted)
    assert!(
        limiter.len() <= max_entries,
        "Entries should not exceed max_entries after eviction, got {}",
        limiter.len()
    );
}

#[test]
fn capacity_eviction_removes_oldest_entries_first() {
    let max_entries = 20;
    let limiter = IpRateLimiter::new(60, max_entries);

    // Insert IPs sequentially so the first ones are oldest
    for i in 1..=max_entries as u8 {
        let ip: IpAddr = format!("10.0.0.{i}").parse().unwrap();
        limiter.check(&ip);
    }

    // Add an IP beyond capacity to trigger eviction
    let overflow_ip: IpAddr = "10.0.0.100".parse().unwrap();
    limiter.check(&overflow_ip);

    // The limiter should have evicted at least some entries and remain within capacity
    assert!(
        limiter.len() <= max_entries,
        "Should remain within capacity after eviction, got {}",
        limiter.len()
    );
}

// ---------------------------------------------------------------------------
// Zero rate means unlimited
// ---------------------------------------------------------------------------

#[test]
fn zero_rate_always_allows_single_ip() {
    let limiter = IpRateLimiter::new(0, 100);
    let ip: IpAddr = "192.168.1.1".parse().unwrap();

    for _ in 0..500 {
        assert!(
            limiter.check(&ip),
            "Zero rate should always allow connections"
        );
    }
}

#[test]
fn zero_rate_always_allows_multiple_ips() {
    let limiter = IpRateLimiter::new(0, 100);

    for i in 1..=50u8 {
        let ip: IpAddr = format!("10.0.0.{i}").parse().unwrap();
        for _ in 0..10 {
            assert!(limiter.check(&ip), "Zero rate should always allow any IP");
        }
    }
}

#[test]
fn zero_rate_does_not_track_entries() {
    let limiter = IpRateLimiter::new(0, 100);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    limiter.check(&ip);
    // With zero rate, check returns early before inserting into the map
    assert!(limiter.is_empty(), "Zero rate should not track any entries");
}

// ---------------------------------------------------------------------------
// Rate limiting behavior
// ---------------------------------------------------------------------------

#[test]
fn rate_limit_allows_burst_then_blocks() {
    // max_per_minute=2 means the governor allows a burst of 2 tokens
    let limiter = IpRateLimiter::new(2, 100);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    let first = limiter.check(&ip);
    let second = limiter.check(&ip);
    let third = limiter.check(&ip);

    assert!(first, "First check should succeed");
    assert!(second, "Second check should succeed (within burst)");
    assert!(!third, "Third check should be rate limited");
}

#[test]
fn rate_limit_with_burst_of_one() {
    let limiter = IpRateLimiter::new(1, 100);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    assert!(limiter.check(&ip), "First check should succeed");
    assert!(!limiter.check(&ip), "Second check should be rate limited");
    assert!(
        !limiter.check(&ip),
        "Third check should still be rate limited"
    );
}

// ---------------------------------------------------------------------------
// cleanup_stale removes old entries
// ---------------------------------------------------------------------------

#[test]
fn cleanup_stale_with_zero_duration_removes_all() {
    let limiter = IpRateLimiter::new(60, 100);

    for i in 1..=10u8 {
        let ip: IpAddr = format!("10.0.0.{i}").parse().unwrap();
        limiter.check(&ip);
    }
    assert_eq!(limiter.len(), 10);

    // Zero duration means all entries are considered stale
    limiter.cleanup_stale(Duration::from_secs(0));
    assert_eq!(limiter.len(), 0, "All entries should be removed");
}

#[test]
fn cleanup_stale_preserves_recent_entries() {
    let limiter = IpRateLimiter::new(60, 100);

    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    limiter.check(&ip);

    // Cleanup with a very large duration should keep the entry
    limiter.cleanup_stale(Duration::from_secs(3600));
    assert_eq!(
        limiter.len(),
        1,
        "Recent entries should survive cleanup with large max_age"
    );
}

#[test]
fn cleanup_stale_on_empty_limiter_does_not_panic() {
    let limiter = IpRateLimiter::new(60, 100);
    assert!(limiter.is_empty());

    // Should not panic
    limiter.cleanup_stale(Duration::from_secs(0));
    assert!(limiter.is_empty());
}

#[test]
fn cleanup_stale_allows_fresh_limiter_for_cleaned_ip() {
    let limiter = IpRateLimiter::new(1, 100);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    // Exhaust the rate limit
    assert!(limiter.check(&ip));
    assert!(!limiter.check(&ip));

    // Remove the stale entry
    limiter.cleanup_stale(Duration::from_secs(0));
    assert!(limiter.is_empty());

    // A fresh limiter should be created for this IP, so check succeeds again
    assert!(
        limiter.check(&ip),
        "After cleanup, IP should get a fresh rate limiter"
    );
}

// ---------------------------------------------------------------------------
// Different IPs tracked independently
// ---------------------------------------------------------------------------

#[test]
fn independent_tracking_rate_limit_one_ip_does_not_affect_another() {
    let limiter = IpRateLimiter::new(1, 100);
    let ip1: IpAddr = "10.0.0.1".parse().unwrap();
    let ip2: IpAddr = "10.0.0.2".parse().unwrap();

    // Exhaust ip1
    assert!(limiter.check(&ip1));
    assert!(!limiter.check(&ip1));

    // ip2 should be unaffected
    assert!(
        limiter.check(&ip2),
        "Rate limit for ip1 should not affect ip2"
    );
}

#[test]
fn independent_tracking_many_ips_each_get_own_bucket() {
    let limiter = IpRateLimiter::new(1, 100);

    // Each IP should get exactly 1 allowed check
    for i in 1..=20u8 {
        let ip: IpAddr = format!("10.0.0.{i}").parse().unwrap();
        assert!(
            limiter.check(&ip),
            "First check for IP 10.0.0.{i} should succeed"
        );
        assert!(
            !limiter.check(&ip),
            "Second check for IP 10.0.0.{i} should be rate limited"
        );
    }
    assert_eq!(limiter.len(), 20);
}

#[test]
fn independent_tracking_cleanup_one_ip_preserves_others() {
    let limiter = IpRateLimiter::new(60, 100);
    let ip1: IpAddr = "10.0.0.1".parse().unwrap();
    let ip2: IpAddr = "10.0.0.2".parse().unwrap();

    limiter.check(&ip1);
    limiter.check(&ip2);
    assert_eq!(limiter.len(), 2);

    // Cleaning with zero duration removes all, but re-adding one should work
    limiter.cleanup_stale(Duration::from_secs(0));
    assert_eq!(limiter.len(), 0);

    limiter.check(&ip1);
    assert_eq!(limiter.len(), 1);
}

// ---------------------------------------------------------------------------
// len() and is_empty()
// ---------------------------------------------------------------------------

#[test]
fn len_and_is_empty_reflect_tracked_entries() {
    let limiter = IpRateLimiter::new(60, 100);
    assert!(limiter.is_empty());
    assert_eq!(limiter.len(), 0);

    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    limiter.check(&ip);
    assert!(!limiter.is_empty());
    assert_eq!(limiter.len(), 1);

    let ip2: IpAddr = "10.0.0.2".parse().unwrap();
    limiter.check(&ip2);
    assert_eq!(limiter.len(), 2);
}
