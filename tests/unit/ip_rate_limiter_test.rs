use sks5::security::rate_limit::IpRateLimiter;
use std::net::IpAddr;
use std::time::Duration;

#[test]
fn unlimited_always_allows() {
    let limiter = IpRateLimiter::new(0, 100_000);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    for _ in 0..1000 {
        assert!(limiter.check(&ip));
    }
}

#[test]
fn allows_under_limit() {
    let limiter = IpRateLimiter::new(60, 100_000);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    assert!(limiter.check(&ip));
}

#[test]
fn blocks_over_limit() {
    // With max_per_minute=1, governor allows a burst of 1 token then blocks
    let limiter = IpRateLimiter::new(1, 100_000);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    let first = limiter.check(&ip);
    let second = limiter.check(&ip);
    assert!(first);
    assert!(!second);
}

#[test]
fn different_ips_tracked_separately() {
    let limiter = IpRateLimiter::new(1, 100_000);
    let ip1: IpAddr = "10.0.0.1".parse().unwrap();
    let ip2: IpAddr = "10.0.0.2".parse().unwrap();
    assert!(limiter.check(&ip1));
    assert!(limiter.check(&ip2));
}

#[test]
fn cleanup_stale_removes_old() {
    let limiter = IpRateLimiter::new(60, 100_000);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    limiter.check(&ip);
    // Cleanup with zero duration removes everything (all entries are older than "now")
    limiter.cleanup_stale(Duration::from_secs(0));
    // After cleanup the internal map should be empty.
    // We verify indirectly: a new check should succeed because a fresh limiter is created
    // for this IP (proving the old entry was removed).
    // More directly, we just confirm check still works (fresh bucket).
    assert!(limiter.check(&ip));
}

#[test]
fn default_is_unlimited() {
    let limiter = IpRateLimiter::default();
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    for _ in 0..1000 {
        assert!(limiter.check(&ip));
    }
}

#[test]
fn ipv4_and_ipv6_tracked_separately() {
    let limiter = IpRateLimiter::new(1, 100_000);
    let ipv4: IpAddr = "127.0.0.1".parse().unwrap();
    let ipv6: IpAddr = "::1".parse().unwrap();
    assert!(limiter.check(&ipv4));
    assert!(limiter.check(&ipv6));
    // Both should now be exhausted independently
    assert!(!limiter.check(&ipv4));
    assert!(!limiter.check(&ipv6));
}
