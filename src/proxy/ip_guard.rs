use std::net::IpAddr;

/// Classify a dangerous IP address by its range name.
/// Returns `Some("range-name")` if the IP is private/reserved/dangerous, `None` if public.
pub fn classify_dangerous_ip(ip: &IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            if octets[0] == 0 {
                Some("this-network")
            } else if octets[0] == 127 {
                Some("loopback")
            } else if octets[0] == 10 {
                Some("private-10")
            } else if octets[0] == 172 && (octets[1] & 0xf0) == 16 {
                Some("private-172")
            } else if octets[0] == 192 && octets[1] == 168 {
                Some("private-192")
            } else if octets[0] == 169 && octets[1] == 254 {
                Some("link-local")
            } else if (octets[0] & 0xf0) == 224 {
                Some("multicast")
            } else if (octets[0] & 0xf0) == 240 {
                Some("reserved")
            } else if octets[0] == 100 && (octets[1] & 0xc0) == 64 {
                Some("cgnat")
            } else if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
                Some("test-net-1")
            } else if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
                Some("test-net-2")
            } else if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
                Some("test-net-3")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            // IPv4-mapped IPv6 (::ffff:x.x.x.x) — check the inner IPv4
            if let Some(v4) = v6.to_ipv4_mapped() {
                return classify_dangerous_ip(&IpAddr::V4(v4));
            }
            // 6to4 addresses (2002::/16) - extract embedded IPv4 and re-check
            if v6.segments()[0] == 0x2002 {
                let embedded_ipv4 = std::net::Ipv4Addr::new(
                    (v6.segments()[1] >> 8) as u8,
                    (v6.segments()[1] & 0xff) as u8,
                    (v6.segments()[2] >> 8) as u8,
                    (v6.segments()[2] & 0xff) as u8,
                );
                if let Some(range) = classify_dangerous_ip(&IpAddr::V4(embedded_ipv4)) {
                    return Some(range);
                }
            }
            if v6.is_loopback() {
                Some("ipv6-loopback")
            } else if (v6.segments()[0] & 0xfe00) == 0xfc00 {
                Some("ipv6-ula")
            } else if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                Some("ipv6-link-local")
            } else if v6.is_unspecified() {
                Some("this-network")
            } else if (v6.segments()[0] & 0xff00) == 0xff00 {
                Some("ipv6-multicast")
            } else {
                None
            }
        }
    }
}

/// Check if an IP address is a private/reserved/dangerous destination (anti-SSRF).
/// This should be called AFTER DNS resolution, BEFORE connecting.
pub fn is_dangerous_ip(ip: &IpAddr) -> bool {
    classify_dangerous_ip(ip).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loopback_blocked() {
        assert!(is_dangerous_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_dangerous_ip(&"127.255.255.255".parse().unwrap()));
        assert!(is_dangerous_ip(&"::1".parse().unwrap()));
    }

    #[test]
    fn test_private_ranges_blocked() {
        assert!(is_dangerous_ip(&"10.0.0.1".parse().unwrap()));
        assert!(is_dangerous_ip(&"10.255.255.255".parse().unwrap()));
        assert!(is_dangerous_ip(&"172.16.0.1".parse().unwrap()));
        assert!(is_dangerous_ip(&"172.31.255.255".parse().unwrap()));
        assert!(is_dangerous_ip(&"192.168.0.1".parse().unwrap()));
        assert!(is_dangerous_ip(&"192.168.255.255".parse().unwrap()));
    }

    #[test]
    fn test_link_local_blocked() {
        assert!(is_dangerous_ip(&"169.254.0.1".parse().unwrap()));
        assert!(is_dangerous_ip(&"169.254.169.254".parse().unwrap()));
        assert!(is_dangerous_ip(&"fe80::1".parse().unwrap()));
    }

    #[test]
    fn test_multicast_blocked() {
        assert!(is_dangerous_ip(&"224.0.0.1".parse().unwrap()));
        assert!(is_dangerous_ip(&"239.255.255.255".parse().unwrap()));
    }

    #[test]
    fn test_this_network_blocked() {
        assert!(is_dangerous_ip(&"0.0.0.0".parse().unwrap()));
        assert!(is_dangerous_ip(&"0.1.2.3".parse().unwrap()));
    }

    #[test]
    fn test_ipv6_unique_local_blocked() {
        assert!(is_dangerous_ip(&"fc00::1".parse().unwrap()));
        assert!(is_dangerous_ip(&"fd12:3456:789a::1".parse().unwrap()));
    }

    #[test]
    fn test_ipv6_unspecified_blocked() {
        assert!(is_dangerous_ip(&"::".parse().unwrap()));
    }

    #[test]
    fn test_ipv6_multicast_blocked() {
        assert!(is_dangerous_ip(&"ff02::1".parse().unwrap()));
    }

    #[test]
    fn test_ipv4_mapped_ipv6_blocked() {
        // ::ffff:127.0.0.1 should be caught as loopback
        assert!(is_dangerous_ip(&"::ffff:127.0.0.1".parse().unwrap()));
        // ::ffff:10.0.0.1 should be caught as private
        assert!(is_dangerous_ip(&"::ffff:10.0.0.1".parse().unwrap()));
        // ::ffff:169.254.169.254 should be caught as link-local
        assert!(is_dangerous_ip(&"::ffff:169.254.169.254".parse().unwrap()));
        // ::ffff:192.168.1.1 should be caught as private
        assert!(is_dangerous_ip(&"::ffff:192.168.1.1".parse().unwrap()));
        // ::ffff:8.8.8.8 should be allowed (public)
        assert!(!is_dangerous_ip(&"::ffff:8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_public_ips_allowed() {
        assert!(!is_dangerous_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_dangerous_ip(&"93.184.216.34".parse().unwrap()));
        assert!(!is_dangerous_ip(&"1.1.1.1".parse().unwrap()));
        assert!(!is_dangerous_ip(
            &"2607:f8b0:4004:800::200e".parse().unwrap()
        ));
    }

    #[test]
    fn test_172_non_private_allowed() {
        assert!(!is_dangerous_ip(&"172.32.0.1".parse().unwrap()));
        assert!(!is_dangerous_ip(&"172.15.255.255".parse().unwrap()));
    }

    #[test]
    fn test_classify_range_names() {
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
        assert_eq!(classify_dangerous_ip(&"8.8.8.8".parse().unwrap()), None);
        assert_eq!(
            classify_dangerous_ip(&"2607:f8b0:4004:800::200e".parse().unwrap()),
            None
        );
    }

    #[test]
    fn test_classify_ipv4_mapped() {
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

    #[test]
    fn test_cgnat_blocked() {
        assert!(is_dangerous_ip(&"100.64.0.1".parse().unwrap()));
        assert!(is_dangerous_ip(&"100.127.255.255".parse().unwrap()));
        assert!(!is_dangerous_ip(&"100.128.0.1".parse().unwrap()));
    }

    #[test]
    fn test_test_nets_blocked() {
        assert!(is_dangerous_ip(&"192.0.2.1".parse().unwrap()));
        assert!(is_dangerous_ip(&"198.51.100.1".parse().unwrap()));
        assert!(is_dangerous_ip(&"203.0.113.1".parse().unwrap()));
    }

    #[test]
    fn test_6to4_embedded_private() {
        // 2002:0a00:0001:: embeds 10.0.0.1 (private)
        assert!(is_dangerous_ip(&"2002:0a00:0001::1".parse().unwrap()));
        // 2002:7f00:0001:: embeds 127.0.0.1 (loopback)
        assert!(is_dangerous_ip(&"2002:7f00:0001::1".parse().unwrap()));
        // 2002:0808:0808:: embeds 8.8.8.8 (public - allowed)
        assert!(!is_dangerous_ip(&"2002:0808:0808::1".parse().unwrap()));
    }
}
