use sks5::security::rate_limit::{IpRateLimiter, UserRateLimiter};
use std::net::IpAddr;
use std::time::Duration;

// ===========================================================================
// IpRateLimiter tests
// ===========================================================================

// ---------------------------------------------------------------------------
// Construction and basic behavior
// ---------------------------------------------------------------------------

#[test]
fn ip_limiter_new_creates_with_given_rate() {
    let limiter = IpRateLimiter::new(10, 100_000);
    let ip: IpAddr = "192.168.1.1".parse().unwrap();
    // First check should always succeed
    assert!(limiter.check(&ip));
}

#[test]
fn ip_limiter_default_is_unlimited() {
    let limiter = IpRateLimiter::default();
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    for _ in 0..1000 {
        assert!(limiter.check(&ip), "unlimited limiter should never block");
    }
}

#[test]
fn ip_limiter_zero_rate_means_unlimited() {
    let limiter = IpRateLimiter::new(0, 100_000);
    let ip: IpAddr = "172.16.0.1".parse().unwrap();
    for _ in 0..500 {
        assert!(limiter.check(&ip), "rate 0 should mean unlimited");
    }
}

// ---------------------------------------------------------------------------
// Rate enforcement
// ---------------------------------------------------------------------------

#[test]
fn ip_limiter_first_check_succeeds() {
    let limiter = IpRateLimiter::new(1, 100_000);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    assert!(limiter.check(&ip), "first check should succeed");
}

#[test]
fn ip_limiter_blocks_after_exhausting_burst() {
    // With max_per_minute=1, governor allows a burst of 1 then blocks
    let limiter = IpRateLimiter::new(1, 100_000);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    let first = limiter.check(&ip);
    let second = limiter.check(&ip);
    assert!(first, "first check should pass");
    assert!(!second, "second check should be rate limited");
}

#[test]
fn ip_limiter_rapid_checks_exhaust_quota() {
    // With max_per_minute=5, the burst is typically 5 then it blocks
    let limiter = IpRateLimiter::new(5, 100_000);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    let mut allowed = 0;
    for _ in 0..100 {
        if limiter.check(&ip) {
            allowed += 1;
        }
    }
    // Governor burst should allow roughly 5 initial requests
    assert!(
        (1..=10).contains(&allowed),
        "expected burst of ~5, got {}",
        allowed
    );
}

// ---------------------------------------------------------------------------
// Per-IP isolation
// ---------------------------------------------------------------------------

#[test]
fn ip_limiter_different_ips_are_independent() {
    let limiter = IpRateLimiter::new(1, 100_000);
    let ip1: IpAddr = "10.0.0.1".parse().unwrap();
    let ip2: IpAddr = "10.0.0.2".parse().unwrap();
    let ip3: IpAddr = "10.0.0.3".parse().unwrap();

    // Each IP should get its own bucket
    assert!(limiter.check(&ip1));
    assert!(limiter.check(&ip2));
    assert!(limiter.check(&ip3));

    // Now all three should be exhausted
    assert!(!limiter.check(&ip1));
    assert!(!limiter.check(&ip2));
    assert!(!limiter.check(&ip3));
}

#[test]
fn ip_limiter_ipv4_and_ipv6_are_independent() {
    let limiter = IpRateLimiter::new(1, 100_000);
    let ipv4: IpAddr = "127.0.0.1".parse().unwrap();
    let ipv6: IpAddr = "::1".parse().unwrap();

    assert!(limiter.check(&ipv4));
    assert!(limiter.check(&ipv6));

    // Both should now be exhausted independently
    assert!(!limiter.check(&ipv4));
    assert!(!limiter.check(&ipv6));
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

#[test]
fn ip_limiter_cleanup_stale_with_zero_duration_removes_all() {
    let limiter = IpRateLimiter::new(60, 100_000);
    let ip1: IpAddr = "10.0.0.1".parse().unwrap();
    let ip2: IpAddr = "10.0.0.2".parse().unwrap();
    let ip3: IpAddr = "10.0.0.3".parse().unwrap();

    limiter.check(&ip1);
    limiter.check(&ip2);
    limiter.check(&ip3);

    // Cleanup with 0 duration removes everything (all entries are older than "now")
    limiter.cleanup_stale(Duration::from_secs(0));

    // After cleanup, a new check should succeed because a fresh bucket is created
    assert!(
        limiter.check(&ip1),
        "fresh bucket should allow after cleanup"
    );
    assert!(
        limiter.check(&ip2),
        "fresh bucket should allow after cleanup"
    );
    assert!(
        limiter.check(&ip3),
        "fresh bucket should allow after cleanup"
    );
}

#[test]
fn ip_limiter_cleanup_stale_preserves_recent_entries() {
    let limiter = IpRateLimiter::new(1, 100_000);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    // Use the bucket (exhaust its token)
    assert!(limiter.check(&ip));
    assert!(!limiter.check(&ip));

    // Cleanup with a very long duration should NOT remove the entry
    limiter.cleanup_stale(Duration::from_secs(3600));

    // The entry should still exist and still be rate-limited
    assert!(
        !limiter.check(&ip),
        "recently used entry should persist after cleanup"
    );
}

#[test]
fn ip_limiter_cleanup_is_idempotent() {
    let limiter = IpRateLimiter::new(60, 100_000);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    limiter.check(&ip);

    // Multiple cleanups should not panic or cause issues
    limiter.cleanup_stale(Duration::from_secs(0));
    limiter.cleanup_stale(Duration::from_secs(0));
    limiter.cleanup_stale(Duration::from_secs(0));

    // Should still work
    assert!(limiter.check(&ip));
}

#[test]
fn ip_limiter_cleanup_on_empty_limiter() {
    let limiter = IpRateLimiter::new(60, 100_000);
    // Cleaning up an empty limiter should not panic
    limiter.cleanup_stale(Duration::from_secs(0));
    limiter.cleanup_stale(Duration::from_secs(3600));
}

// ---------------------------------------------------------------------------
// High rate values
// ---------------------------------------------------------------------------

#[test]
fn ip_limiter_high_rate_allows_many_checks() {
    let limiter = IpRateLimiter::new(1000, 100_000);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    let mut allowed = 0;
    for _ in 0..100 {
        if limiter.check(&ip) {
            allowed += 1;
        }
    }
    // With 1000/min, all 100 rapid checks should pass
    assert_eq!(allowed, 100, "high rate should allow 100 rapid checks");
}

// ===========================================================================
// UserRateLimiter tests
// ===========================================================================

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

#[test]
fn user_limiter_new_creates_empty() {
    let limiter = UserRateLimiter::new(10_000);
    // Check should succeed for a new user
    assert!(limiter.check("alice", 60));
}

#[test]
fn user_limiter_default_creates_empty() {
    let limiter = UserRateLimiter::default();
    assert!(limiter.check("alice", 60));
}

// ---------------------------------------------------------------------------
// Rate enforcement
// ---------------------------------------------------------------------------

#[test]
fn user_limiter_zero_rate_means_unlimited() {
    let limiter = UserRateLimiter::new(10_000);
    for _ in 0..500 {
        assert!(limiter.check("alice", 0), "rate 0 should mean unlimited");
    }
}

#[test]
fn user_limiter_blocks_after_exhausting_burst() {
    let limiter = UserRateLimiter::new(10_000);
    let first = limiter.check("alice", 1);
    let second = limiter.check("alice", 1);
    assert!(first, "first check should pass");
    assert!(!second, "second check should be rate limited");
}

#[test]
fn user_limiter_rapid_checks_exhaust_quota() {
    let limiter = UserRateLimiter::new(10_000);
    let mut allowed = 0;
    for _ in 0..100 {
        if limiter.check("alice", 5) {
            allowed += 1;
        }
    }
    assert!(
        (1..=10).contains(&allowed),
        "expected burst of ~5, got {}",
        allowed
    );
}

// ---------------------------------------------------------------------------
// Per-user isolation
// ---------------------------------------------------------------------------

#[test]
fn user_limiter_different_users_are_independent() {
    let limiter = UserRateLimiter::new(10_000);

    // Each user gets their own bucket
    assert!(limiter.check("alice", 1));
    assert!(limiter.check("bob", 1));
    assert!(limiter.check("charlie", 1));

    // Now all three should be exhausted
    assert!(!limiter.check("alice", 1));
    assert!(!limiter.check("bob", 1));
    assert!(!limiter.check("charlie", 1));
}

#[test]
fn user_limiter_same_user_different_rates_uses_first_rate() {
    let limiter = UserRateLimiter::new(10_000);

    // First call creates the bucket with rate 1
    assert!(limiter.check("alice", 1));

    // Second call with higher rate still uses the original bucket
    // (the limiter is created on first call and reused)
    assert!(!limiter.check("alice", 1000));
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

#[test]
fn user_limiter_cleanup_stale_with_zero_removes_all() {
    let limiter = UserRateLimiter::new(10_000);

    limiter.check("alice", 60);
    limiter.check("bob", 60);
    limiter.check("charlie", 60);

    // Cleanup with 0 duration should remove everything
    limiter.cleanup_stale(Duration::from_secs(0));

    // After cleanup, a new check should succeed (fresh bucket)
    assert!(limiter.check("alice", 1), "fresh bucket after cleanup");
}

#[test]
fn user_limiter_cleanup_stale_preserves_recent() {
    let limiter = UserRateLimiter::new(10_000);

    // Exhaust alice's bucket
    assert!(limiter.check("alice", 1));
    assert!(!limiter.check("alice", 1));

    // Cleanup with a long duration should preserve
    limiter.cleanup_stale(Duration::from_secs(3600));

    // Alice should still be rate-limited
    assert!(
        !limiter.check("alice", 1),
        "recently used entry should persist"
    );
}

#[test]
fn user_limiter_cleanup_on_empty() {
    let limiter = UserRateLimiter::new(10_000);
    // Should not panic
    limiter.cleanup_stale(Duration::from_secs(0));
    limiter.cleanup_stale(Duration::from_secs(3600));
}

#[test]
fn user_limiter_cleanup_is_idempotent() {
    let limiter = UserRateLimiter::new(10_000);
    limiter.check("alice", 60);

    limiter.cleanup_stale(Duration::from_secs(0));
    limiter.cleanup_stale(Duration::from_secs(0));
    limiter.cleanup_stale(Duration::from_secs(0));

    // Should still work
    assert!(limiter.check("alice", 60));
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn user_limiter_empty_username() {
    let limiter = UserRateLimiter::new(10_000);
    // Empty username is technically valid
    assert!(limiter.check("", 1));
    assert!(!limiter.check("", 1));
}

#[test]
fn user_limiter_unicode_username() {
    let limiter = UserRateLimiter::new(10_000);
    assert!(limiter.check("utilisateur", 1));
    assert!(!limiter.check("utilisateur", 1));
    // Different unicode username should have its own bucket
    assert!(limiter.check("benutzer", 1));
}

#[test]
fn ip_limiter_many_different_ips_tracked() {
    let limiter = IpRateLimiter::new(1, 100_000);

    // Track many different IPs without hitting the MAX_TRACKED_IPS limit
    for i in 0..100u8 {
        let ip: IpAddr = format!("10.0.0.{}", i).parse().unwrap();
        assert!(
            limiter.check(&ip),
            "first check for 10.0.0.{} should pass",
            i
        );
    }

    // Each should now be exhausted
    for i in 0..100u8 {
        let ip: IpAddr = format!("10.0.0.{}", i).parse().unwrap();
        assert!(
            !limiter.check(&ip),
            "second check for 10.0.0.{} should fail",
            i
        );
    }
}

#[test]
fn user_limiter_high_rate_allows_many() {
    let limiter = UserRateLimiter::new(10_000);
    let mut allowed = 0;
    for _ in 0..100 {
        if limiter.check("alice", 1000) {
            allowed += 1;
        }
    }
    assert_eq!(allowed, 100, "high rate should allow all 100 checks");
}
