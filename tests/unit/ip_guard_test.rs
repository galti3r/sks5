use sks5::proxy::ip_guard::{classify_dangerous_ip, is_dangerous_ip};

// =========================================================================
// IPv4 private ranges
// =========================================================================

#[test]
fn private_10_blocked() {
    assert!(is_dangerous_ip(&"10.0.0.1".parse().unwrap()));
    assert!(is_dangerous_ip(&"10.255.255.255".parse().unwrap()));
    assert!(is_dangerous_ip(&"10.100.50.25".parse().unwrap()));
}

#[test]
fn private_172_16_blocked() {
    assert!(is_dangerous_ip(&"172.16.0.1".parse().unwrap()));
    assert!(is_dangerous_ip(&"172.31.255.255".parse().unwrap()));
    assert!(is_dangerous_ip(&"172.20.10.5".parse().unwrap()));
}

#[test]
fn private_192_168_blocked() {
    assert!(is_dangerous_ip(&"192.168.0.1".parse().unwrap()));
    assert!(is_dangerous_ip(&"192.168.255.255".parse().unwrap()));
    assert!(is_dangerous_ip(&"192.168.1.100".parse().unwrap()));
}

// =========================================================================
// IPv4 loopback
// =========================================================================

#[test]
fn loopback_blocked() {
    assert!(is_dangerous_ip(&"127.0.0.1".parse().unwrap()));
    assert!(is_dangerous_ip(&"127.255.255.255".parse().unwrap()));
    assert!(is_dangerous_ip(&"127.0.0.0".parse().unwrap()));
}

// =========================================================================
// IPv4 link-local
// =========================================================================

#[test]
fn link_local_blocked() {
    assert!(is_dangerous_ip(&"169.254.0.1".parse().unwrap()));
    assert!(is_dangerous_ip(&"169.254.169.254".parse().unwrap())); // AWS metadata
    assert!(is_dangerous_ip(&"169.254.255.255".parse().unwrap()));
}

// =========================================================================
// IPv4 multicast
// =========================================================================

#[test]
fn multicast_blocked() {
    assert!(is_dangerous_ip(&"224.0.0.1".parse().unwrap()));
    assert!(is_dangerous_ip(&"239.255.255.255".parse().unwrap()));
    assert!(is_dangerous_ip(&"232.100.50.25".parse().unwrap()));
}

// =========================================================================
// IPv4 CGNAT (100.64.0.0/10)
// =========================================================================

#[test]
fn cgnat_blocked() {
    assert!(is_dangerous_ip(&"100.64.0.1".parse().unwrap()));
    assert!(is_dangerous_ip(&"100.127.255.255".parse().unwrap()));
    // Outside CGNAT range
    assert!(!is_dangerous_ip(&"100.128.0.1".parse().unwrap()));
    assert!(!is_dangerous_ip(&"100.63.255.255".parse().unwrap()));
}

// =========================================================================
// IPv4 reserved and test networks
// =========================================================================

#[test]
fn reserved_range_blocked() {
    assert!(is_dangerous_ip(&"240.0.0.1".parse().unwrap()));
    assert!(is_dangerous_ip(&"255.255.255.254".parse().unwrap()));
}

#[test]
fn this_network_blocked() {
    assert!(is_dangerous_ip(&"0.0.0.0".parse().unwrap()));
    assert!(is_dangerous_ip(&"0.1.2.3".parse().unwrap()));
}

#[test]
fn test_nets_blocked() {
    assert!(is_dangerous_ip(&"192.0.2.1".parse().unwrap())); // TEST-NET-1
    assert!(is_dangerous_ip(&"198.51.100.1".parse().unwrap())); // TEST-NET-2
    assert!(is_dangerous_ip(&"203.0.113.1".parse().unwrap())); // TEST-NET-3
}

// =========================================================================
// IPv4 public addresses allowed
// =========================================================================

#[test]
fn public_ipv4_allowed() {
    assert!(!is_dangerous_ip(&"8.8.8.8".parse().unwrap()));
    assert!(!is_dangerous_ip(&"93.184.216.34".parse().unwrap()));
    assert!(!is_dangerous_ip(&"1.1.1.1".parse().unwrap()));
    assert!(!is_dangerous_ip(&"142.250.217.110".parse().unwrap()));
}

#[test]
fn non_private_172_allowed() {
    assert!(!is_dangerous_ip(&"172.32.0.1".parse().unwrap()));
    assert!(!is_dangerous_ip(&"172.15.255.255".parse().unwrap()));
}

// =========================================================================
// IPv6 variants
// =========================================================================

#[test]
fn ipv6_loopback_blocked() {
    assert!(is_dangerous_ip(&"::1".parse().unwrap()));
}

#[test]
fn ipv6_unspecified_blocked() {
    assert!(is_dangerous_ip(&"::".parse().unwrap()));
}

#[test]
fn ipv6_link_local_blocked() {
    assert!(is_dangerous_ip(&"fe80::1".parse().unwrap()));
    assert!(is_dangerous_ip(&"fe80::abcd:1234".parse().unwrap()));
}

#[test]
fn ipv6_unique_local_blocked() {
    assert!(is_dangerous_ip(&"fc00::1".parse().unwrap()));
    assert!(is_dangerous_ip(&"fd12:3456:789a::1".parse().unwrap()));
}

#[test]
fn ipv6_multicast_blocked() {
    assert!(is_dangerous_ip(&"ff02::1".parse().unwrap()));
    assert!(is_dangerous_ip(&"ff0e::1".parse().unwrap()));
}

#[test]
fn ipv6_public_allowed() {
    assert!(!is_dangerous_ip(
        &"2607:f8b0:4004:800::200e".parse().unwrap()
    ));
    assert!(!is_dangerous_ip(&"2001:4860:4860::8888".parse().unwrap()));
}

// =========================================================================
// IPv4-mapped IPv6 addresses
// =========================================================================

#[test]
fn ipv4_mapped_ipv6_loopback_blocked() {
    assert!(is_dangerous_ip(&"::ffff:127.0.0.1".parse().unwrap()));
}

#[test]
fn ipv4_mapped_ipv6_private_blocked() {
    assert!(is_dangerous_ip(&"::ffff:10.0.0.1".parse().unwrap()));
    assert!(is_dangerous_ip(&"::ffff:192.168.1.1".parse().unwrap()));
    assert!(is_dangerous_ip(&"::ffff:172.16.0.1".parse().unwrap()));
}

#[test]
fn ipv4_mapped_ipv6_link_local_blocked() {
    assert!(is_dangerous_ip(&"::ffff:169.254.169.254".parse().unwrap()));
}

#[test]
fn ipv4_mapped_ipv6_public_allowed() {
    assert!(!is_dangerous_ip(&"::ffff:8.8.8.8".parse().unwrap()));
    assert!(!is_dangerous_ip(&"::ffff:1.1.1.1".parse().unwrap()));
}

// =========================================================================
// 6to4 addresses (2002::/16)
// =========================================================================

#[test]
fn sixto4_embedded_private_blocked() {
    // 2002:0a00:0001:: embeds 10.0.0.1 (private)
    assert!(is_dangerous_ip(&"2002:0a00:0001::1".parse().unwrap()));
    // 2002:7f00:0001:: embeds 127.0.0.1 (loopback)
    assert!(is_dangerous_ip(&"2002:7f00:0001::1".parse().unwrap()));
}

#[test]
fn sixto4_embedded_public_allowed() {
    // 2002:0808:0808:: embeds 8.8.8.8 (public)
    assert!(!is_dangerous_ip(&"2002:0808:0808::1".parse().unwrap()));
}

// =========================================================================
// classify_dangerous_ip returns correct range names
// =========================================================================

#[test]
fn classify_returns_correct_names() {
    assert_eq!(
        classify_dangerous_ip(&"127.0.0.1".parse().unwrap()),
        Some("loopback")
    );
    assert_eq!(
        classify_dangerous_ip(&"10.1.2.3".parse().unwrap()),
        Some("private-10")
    );
    assert_eq!(
        classify_dangerous_ip(&"172.16.0.1".parse().unwrap()),
        Some("private-172")
    );
    assert_eq!(
        classify_dangerous_ip(&"192.168.1.1".parse().unwrap()),
        Some("private-192")
    );
    assert_eq!(
        classify_dangerous_ip(&"169.254.1.1".parse().unwrap()),
        Some("link-local")
    );
    assert_eq!(
        classify_dangerous_ip(&"224.0.0.1".parse().unwrap()),
        Some("multicast")
    );
    assert_eq!(
        classify_dangerous_ip(&"240.0.0.1".parse().unwrap()),
        Some("reserved")
    );
    assert_eq!(
        classify_dangerous_ip(&"0.0.0.0".parse().unwrap()),
        Some("this-network")
    );
    assert_eq!(
        classify_dangerous_ip(&"100.64.0.1".parse().unwrap()),
        Some("cgnat")
    );
    assert_eq!(
        classify_dangerous_ip(&"192.0.2.1".parse().unwrap()),
        Some("test-net-1")
    );
    assert_eq!(
        classify_dangerous_ip(&"198.51.100.1".parse().unwrap()),
        Some("test-net-2")
    );
    assert_eq!(
        classify_dangerous_ip(&"203.0.113.1".parse().unwrap()),
        Some("test-net-3")
    );
}

#[test]
fn classify_ipv6_range_names() {
    assert_eq!(
        classify_dangerous_ip(&"::1".parse().unwrap()),
        Some("ipv6-loopback")
    );
    assert_eq!(
        classify_dangerous_ip(&"fc00::1".parse().unwrap()),
        Some("ipv6-ula")
    );
    assert_eq!(
        classify_dangerous_ip(&"fe80::1".parse().unwrap()),
        Some("ipv6-link-local")
    );
    assert_eq!(
        classify_dangerous_ip(&"ff02::1".parse().unwrap()),
        Some("ipv6-multicast")
    );
    assert_eq!(
        classify_dangerous_ip(&"::".parse().unwrap()),
        Some("this-network")
    );
}

#[test]
fn classify_public_returns_none() {
    assert_eq!(classify_dangerous_ip(&"8.8.8.8".parse().unwrap()), None);
    assert_eq!(
        classify_dangerous_ip(&"2607:f8b0:4004:800::200e".parse().unwrap()),
        None
    );
}

#[test]
fn classify_ipv4_mapped_range_names() {
    assert_eq!(
        classify_dangerous_ip(&"::ffff:127.0.0.1".parse().unwrap()),
        Some("loopback")
    );
    assert_eq!(
        classify_dangerous_ip(&"::ffff:10.0.0.1".parse().unwrap()),
        Some("private-10")
    );
    assert_eq!(
        classify_dangerous_ip(&"::ffff:8.8.8.8".parse().unwrap()),
        None
    );
}
