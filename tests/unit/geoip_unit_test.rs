use sks5::geoip::GeoIpService;
use std::net::IpAddr;

// ===========================================================================
// GeoIP disabled (no filtering)
// ===========================================================================

#[test]
fn disabled_geoip_allows_all_ipv4() {
    let svc = GeoIpService::new(false, None, vec![], vec![], false);
    let ip: IpAddr = "8.8.8.8".parse().unwrap();
    assert!(svc.is_allowed(&ip));
}

#[test]
fn disabled_geoip_allows_all_ipv6() {
    let svc = GeoIpService::new(false, None, vec![], vec![], false);
    let ip: IpAddr = "2001:db8::1".parse().unwrap();
    assert!(svc.is_allowed(&ip));
}

#[test]
fn disabled_geoip_allows_even_with_deny_list() {
    let svc = GeoIpService::new(
        false,
        None,
        vec![],
        vec!["CN".to_string(), "RU".to_string()],
        false,
    );
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    assert!(
        svc.is_allowed(&ip),
        "disabled GeoIP should ignore deny lists"
    );
}

#[test]
fn disabled_geoip_allows_even_with_allow_list() {
    let svc = GeoIpService::new(false, None, vec!["US".to_string()], vec![], false);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    assert!(
        svc.is_allowed(&ip),
        "disabled GeoIP should ignore allow lists"
    );
}

#[test]
fn disabled_geoip_allows_even_with_both_lists() {
    let svc = GeoIpService::new(
        false,
        None,
        vec!["US".to_string()],
        vec!["CN".to_string()],
        false,
    );
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    assert!(svc.is_allowed(&ip));
}

// ===========================================================================
// GeoIP enabled but no reader (no DB / bad path)
// ===========================================================================

#[test]
fn enabled_no_db_path_allows_all_when_fail_open() {
    let svc = GeoIpService::new(true, None, vec!["US".to_string()], vec![], false);
    let ip: IpAddr = "1.2.3.4".parse().unwrap();
    assert!(
        svc.is_allowed(&ip),
        "no reader + fail_closed=false should allow"
    );
}

#[test]
fn enabled_no_db_path_denies_all_when_fail_closed() {
    let svc = GeoIpService::new(true, None, vec!["US".to_string()], vec![], true);
    let ip: IpAddr = "1.2.3.4".parse().unwrap();
    assert!(
        !svc.is_allowed(&ip),
        "no reader + fail_closed=true should deny"
    );
}

#[test]
fn enabled_bad_db_path_allows_all_when_fail_open() {
    let svc = GeoIpService::new(
        true,
        Some(std::path::Path::new("/nonexistent/GeoLite2-Country.mmdb")),
        vec!["US".to_string()],
        vec!["CN".to_string()],
        false,
    );
    let ip: IpAddr = "203.0.113.1".parse().unwrap();
    assert!(
        svc.is_allowed(&ip),
        "bad path + fail_closed=false should allow"
    );
}

#[test]
fn enabled_bad_db_path_denies_all_when_fail_closed() {
    let svc = GeoIpService::new(
        true,
        Some(std::path::Path::new("/nonexistent/GeoLite2-Country.mmdb")),
        vec!["US".to_string()],
        vec![],
        true,
    );
    let ip: IpAddr = "203.0.113.1".parse().unwrap();
    assert!(
        !svc.is_allowed(&ip),
        "bad path + fail_closed=true should deny"
    );
}

// ===========================================================================
// Empty country lists
// ===========================================================================

#[test]
fn enabled_bad_path_empty_lists_allows_all_fail_open() {
    let svc = GeoIpService::new(
        true,
        Some(std::path::Path::new("/tmp/does-not-exist.mmdb")),
        vec![],
        vec![],
        false,
    );
    let ip: IpAddr = "192.0.2.1".parse().unwrap();
    assert!(svc.is_allowed(&ip));
}

#[test]
fn enabled_bad_path_empty_lists_denies_when_fail_closed() {
    let svc = GeoIpService::new(
        true,
        Some(std::path::Path::new("/tmp/does-not-exist.mmdb")),
        vec![],
        vec![],
        true,
    );
    let ip: IpAddr = "192.0.2.1".parse().unwrap();
    // No reader => fail_closed=true => deny
    assert!(!svc.is_allowed(&ip));
}

// ===========================================================================
// fail_closed behavior with disabled GeoIP
// ===========================================================================

#[test]
fn disabled_geoip_ignores_fail_closed() {
    // When GeoIP is disabled, reader is None. fail_closed still applies
    // because the code checks `if self.reader.is_none() { return !self.fail_closed }`
    let svc_open = GeoIpService::new(false, None, vec![], vec![], false);
    let svc_closed = GeoIpService::new(false, None, vec![], vec![], true);

    let ip: IpAddr = "8.8.8.8".parse().unwrap();

    assert!(
        svc_open.is_allowed(&ip),
        "disabled + fail_open should allow"
    );
    // When disabled, reader is None, so fail_closed applies
    assert!(
        !svc_closed.is_allowed(&ip),
        "disabled + fail_closed denies (no reader)"
    );
}

// ===========================================================================
// IPv4 and IPv6 pass-through without reader
// ===========================================================================

#[test]
fn no_reader_ipv4_loopback_allowed() {
    let svc = GeoIpService::new(false, None, vec![], vec![], false);
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    assert!(svc.is_allowed(&ip));
}

#[test]
fn no_reader_ipv6_loopback_allowed() {
    let svc = GeoIpService::new(false, None, vec![], vec![], false);
    let ip: IpAddr = "::1".parse().unwrap();
    assert!(svc.is_allowed(&ip));
}

#[test]
fn no_reader_private_ipv4_allowed() {
    let svc = GeoIpService::new(false, None, vec![], vec![], false);
    let ip: IpAddr = "192.168.1.1".parse().unwrap();
    assert!(svc.is_allowed(&ip));
}

#[test]
fn no_reader_link_local_ipv6_allowed() {
    let svc = GeoIpService::new(false, None, vec![], vec![], false);
    let ip: IpAddr = "fe80::1".parse().unwrap();
    assert!(svc.is_allowed(&ip));
}

// ===========================================================================
// Multiple countries in lists (no DB, just structural tests)
// ===========================================================================

#[test]
fn enabled_no_path_with_multiple_allowed_countries() {
    let svc = GeoIpService::new(
        true,
        None,
        vec!["US".to_string(), "FR".to_string(), "DE".to_string()],
        vec![],
        false,
    );
    let ip: IpAddr = "198.51.100.1".parse().unwrap();
    // No reader => fail_open => allow
    assert!(svc.is_allowed(&ip));
}

#[test]
fn enabled_no_path_with_multiple_denied_countries() {
    let svc = GeoIpService::new(
        true,
        None,
        vec![],
        vec!["CN".to_string(), "RU".to_string(), "KP".to_string()],
        false,
    );
    let ip: IpAddr = "198.51.100.1".parse().unwrap();
    // No reader => fail_open => allow
    assert!(svc.is_allowed(&ip));
}

#[test]
fn enabled_no_path_with_both_lists() {
    let svc = GeoIpService::new(
        true,
        None,
        vec!["US".to_string(), "GB".to_string()],
        vec!["CN".to_string(), "RU".to_string()],
        false,
    );
    let ip: IpAddr = "198.51.100.1".parse().unwrap();
    // No reader => fail_open => allow
    assert!(svc.is_allowed(&ip));
}

// ===========================================================================
// Constructing GeoIpService with various parameter combinations
// ===========================================================================

#[test]
fn construct_with_empty_allowed_and_denied() {
    let svc = GeoIpService::new(true, None, vec![], vec![], false);
    let ip: IpAddr = "1.1.1.1".parse().unwrap();
    assert!(svc.is_allowed(&ip));
}

#[test]
fn construct_disabled_with_fail_closed_and_lists() {
    let svc = GeoIpService::new(
        false,
        Some(std::path::Path::new("/nonexistent.mmdb")),
        vec!["US".to_string()],
        vec!["CN".to_string()],
        true,
    );
    // Disabled => reader is None => fail_closed applies
    let ip: IpAddr = "1.1.1.1".parse().unwrap();
    assert!(!svc.is_allowed(&ip));
}

// ===========================================================================
// Various IP address formats
// ===========================================================================

#[test]
fn handles_unspecified_ipv4() {
    let svc = GeoIpService::new(false, None, vec![], vec![], false);
    let ip: IpAddr = "0.0.0.0".parse().unwrap();
    assert!(svc.is_allowed(&ip));
}

#[test]
fn handles_unspecified_ipv6() {
    let svc = GeoIpService::new(false, None, vec![], vec![], false);
    let ip: IpAddr = "::".parse().unwrap();
    assert!(svc.is_allowed(&ip));
}

#[test]
fn handles_broadcast_ipv4() {
    let svc = GeoIpService::new(false, None, vec![], vec![], false);
    let ip: IpAddr = "255.255.255.255".parse().unwrap();
    assert!(svc.is_allowed(&ip));
}
