use sks5::proxy::connector;

// ===========================================================================
// Port 0 rejection (M-9)
// ===========================================================================

#[tokio::test]
async fn connect_port_zero_rejected() {
    let result = connector::connect("example.com", 0, 5, false).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("port 0"),
        "expected port 0 error, got: {}",
        err
    );
}

#[tokio::test]
async fn connect_port_zero_rejected_with_ip_guard() {
    let result = connector::connect("example.com", 0, 5, true).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("port 0"),
        "expected port 0 error, got: {}",
        err
    );
}

#[tokio::test]
async fn connect_with_cache_port_zero_rejected() {
    let dns_cache = sks5::proxy::dns_cache::DnsCache::new(-1, 1000);
    let result = connector::connect_with_cache("example.com", 0, 5, false, &dns_cache, None).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("port 0"),
        "expected port 0 error, got: {}",
        err
    );
}

// ===========================================================================
// IP guard: private/loopback IP blocking (anti-SSRF)
// ===========================================================================

#[tokio::test]
async fn connect_loopback_blocked_by_ip_guard() {
    let result = connector::connect("127.0.0.1", 80, 5, true).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("blocked") || err.contains("ip_guard"),
        "expected anti-SSRF error, got: {}",
        err
    );
}

#[tokio::test]
async fn connect_private_10_blocked_by_ip_guard() {
    let result = connector::connect("10.0.0.1", 80, 5, true).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("blocked") || err.contains("ip_guard"),
        "expected anti-SSRF error, got: {}",
        err
    );
}

#[tokio::test]
async fn connect_private_172_blocked_by_ip_guard() {
    let result = connector::connect("172.16.0.1", 80, 5, true).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("blocked") || err.contains("ip_guard"),
        "expected anti-SSRF error, got: {}",
        err
    );
}

#[tokio::test]
async fn connect_private_192_blocked_by_ip_guard() {
    let result = connector::connect("192.168.1.1", 80, 5, true).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("blocked") || err.contains("ip_guard"),
        "expected anti-SSRF error, got: {}",
        err
    );
}

#[tokio::test]
async fn connect_ipv6_loopback_blocked_by_ip_guard() {
    let result = connector::connect("::1", 80, 5, true).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("blocked") || err.contains("ip_guard"),
        "expected anti-SSRF error for ::1, got: {}",
        err
    );
}

#[tokio::test]
async fn connect_link_local_blocked_by_ip_guard() {
    let result = connector::connect("169.254.169.254", 80, 5, true).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("blocked") || err.contains("ip_guard"),
        "expected anti-SSRF error for link-local, got: {}",
        err
    );
}

// ===========================================================================
// IP guard disabled: private IPs allowed (may still fail to connect)
// ===========================================================================

#[tokio::test]
async fn connect_loopback_not_blocked_when_guard_disabled() {
    let result = connector::connect("127.0.0.1", 1, 2, false).await;
    // It should either connect or fail with connection error, NOT with anti-SSRF
    if let Err(e) = &result {
        let err = e.to_string();
        assert!(
            !err.contains("blocked") && !err.contains("ip_guard"),
            "ip_guard disabled should not block loopback, got: {}",
            err
        );
    }
}

#[tokio::test]
async fn connect_private_not_blocked_when_guard_disabled() {
    let result = connector::connect("10.0.0.1", 1, 2, false).await;
    if let Err(e) = &result {
        let err = e.to_string();
        assert!(
            !err.contains("blocked") && !err.contains("ip_guard"),
            "ip_guard disabled should not block private IP, got: {}",
            err
        );
    }
}

// ===========================================================================
// DNS resolution failures
// ===========================================================================

#[tokio::test]
async fn connect_invalid_hostname_fails() {
    let result = connector::connect("this-host-does-not-exist.invalid", 80, 2, false).await;
    assert!(result.is_err(), "invalid hostname should fail");
}

#[tokio::test]
async fn connect_empty_hostname_fails() {
    let result = connector::connect("", 80, 2, false).await;
    assert!(result.is_err(), "empty hostname should fail");
}

// ===========================================================================
// Timeout behavior
// ===========================================================================

#[tokio::test]
async fn connect_to_nonroutable_times_out() {
    // RFC 5737: 198.51.100.0/24 is "TEST-NET-2" - should not route
    let result = connector::connect("198.51.100.1", 80, 1, false).await;
    assert!(result.is_err(), "non-routable IP should timeout or fail");
}

#[tokio::test]
async fn connect_very_short_timeout() {
    // Even a valid host with a very short timeout should likely fail
    let result = connector::connect("198.51.100.1", 80, 1, false).await;
    assert!(result.is_err());
}

// ===========================================================================
// resolve_and_check
// ===========================================================================

#[tokio::test]
async fn resolve_and_check_loopback_blocked_by_ip_guard() {
    let result = connector::resolve_and_check("127.0.0.1", 80, 5, true).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("blocked") || err.contains("ip_guard"),
        "expected anti-SSRF error, got: {}",
        err
    );
}

#[tokio::test]
async fn resolve_and_check_loopback_allowed_without_ip_guard() {
    let result = connector::resolve_and_check("127.0.0.1", 80, 5, false).await;
    assert!(
        result.is_ok(),
        "127.0.0.1 should resolve when ip_guard is disabled"
    );
    let addrs = result.unwrap();
    assert!(!addrs.is_empty());
    assert!(addrs[0].ip().is_loopback());
}

#[tokio::test]
async fn resolve_and_check_invalid_host_fails() {
    let result =
        connector::resolve_and_check("this-host-does-not-exist.invalid", 80, 2, false).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn resolve_and_check_ipv6_loopback_blocked_by_ip_guard() {
    let result = connector::resolve_and_check("::1", 80, 5, true).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn resolve_and_check_ipv6_format_with_brackets() {
    // The code handles IPv6 by wrapping in brackets: [::1]:port
    let result = connector::resolve_and_check("::1", 80, 5, false).await;
    assert!(
        result.is_ok(),
        "IPv6 resolution should work without ip_guard"
    );
}

// ===========================================================================
// connect_with_cache
// ===========================================================================

#[tokio::test]
async fn connect_with_cache_loopback_blocked_by_ip_guard() {
    let dns_cache = sks5::proxy::dns_cache::DnsCache::new(-1, 1000);
    let result = connector::connect_with_cache("127.0.0.1", 80, 5, true, &dns_cache, None).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("blocked") || err.contains("ip_guard"),
        "expected anti-SSRF error, got: {}",
        err
    );
}

#[tokio::test]
async fn connect_with_cache_invalid_hostname_fails() {
    let dns_cache = sks5::proxy::dns_cache::DnsCache::new(-1, 1000);
    let result = connector::connect_with_cache(
        "this-host-does-not-exist.invalid",
        80,
        2,
        false,
        &dns_cache,
        None,
    )
    .await;
    assert!(result.is_err());
}

// ===========================================================================
// Edge cases with valid ports
// ===========================================================================

#[tokio::test]
async fn connect_port_1_unreachable() {
    // Port 1 on a test-net address should be unreachable
    let result = connector::connect("198.51.100.1", 1, 2, false).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn connect_port_65535() {
    // Max valid port number - should not cause issues (though it likely fails to connect)
    let result = connector::connect("198.51.100.1", 65535, 1, false).await;
    assert!(result.is_err());
}
