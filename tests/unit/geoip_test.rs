use sks5::geoip::GeoIpService;
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// Test 1: Disabled GeoIP → is_allowed always returns true
// ---------------------------------------------------------------------------
#[test]
fn disabled_geoip_allows_all() {
    let svc = GeoIpService::new(false, None, vec![], vec![], false);
    let ip: IpAddr = "8.8.8.8".parse().unwrap();
    assert!(svc.is_allowed(&ip));
}

// ---------------------------------------------------------------------------
// Test 2: Enabled but no DB path → reader is None, allows all
// ---------------------------------------------------------------------------
#[test]
fn enabled_no_db_path_allows_all() {
    let svc = GeoIpService::new(true, None, vec!["US".to_string()], vec![], false);
    let ip: IpAddr = "1.2.3.4".parse().unwrap();
    assert!(svc.is_allowed(&ip));
}

// ---------------------------------------------------------------------------
// Test 3: Enabled with nonexistent DB → reader is None, allows all
// ---------------------------------------------------------------------------
#[test]
fn enabled_bad_db_path_allows_all() {
    let svc = GeoIpService::new(
        true,
        Some(std::path::Path::new("/nonexistent/GeoLite2-Country.mmdb")),
        vec!["US".to_string()],
        vec!["CN".to_string()],
        false,
    );
    let ip: IpAddr = "203.0.113.1".parse().unwrap();
    assert!(svc.is_allowed(&ip), "should allow when DB cannot be loaded");
}

// ---------------------------------------------------------------------------
// Test 4: Disabled with deny list → still allows (disabled overrides)
// ---------------------------------------------------------------------------
#[test]
fn disabled_with_deny_list_still_allows() {
    let svc = GeoIpService::new(
        false,
        None,
        vec![],
        vec!["CN".to_string(), "RU".to_string()],
        false,
    );
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    assert!(svc.is_allowed(&ip));
}

// ---------------------------------------------------------------------------
// Test 5: No reader, IPv6 allowed
// ---------------------------------------------------------------------------
#[test]
fn no_reader_ipv6_allowed() {
    let svc = GeoIpService::new(false, None, vec![], vec![], false);
    let ip: IpAddr = "2001:db8::1".parse().unwrap();
    assert!(svc.is_allowed(&ip));
}

// ---------------------------------------------------------------------------
// Test 6: Enabled, bad path, empty lists → allows all
// ---------------------------------------------------------------------------
#[test]
fn enabled_bad_path_empty_lists_allows_all() {
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

// ---------------------------------------------------------------------------
// Test 7: Enabled, no path, with only allowed countries → still allows (no reader)
// ---------------------------------------------------------------------------
#[test]
fn enabled_no_path_with_allowed_countries() {
    let svc = GeoIpService::new(true, None, vec!["FR".to_string()], vec![], false);
    let ip: IpAddr = "198.51.100.1".parse().unwrap();
    assert!(svc.is_allowed(&ip), "no reader means allow by default");
}
