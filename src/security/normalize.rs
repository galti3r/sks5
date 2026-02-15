use std::net::IpAddr;

/// Normalize an IP address by converting IPv4-mapped IPv6 addresses to their IPv4 form.
/// This prevents bypasses where `::ffff:127.0.0.1` is treated differently from `127.0.0.1`.
pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_unchanged() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(normalize_ip(ip), ip);
    }

    #[test]
    fn test_ipv6_unchanged() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(normalize_ip(ip), ip);
    }

    #[test]
    fn test_ipv4_mapped_normalized() {
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        let expected: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(normalize_ip(mapped), expected);
    }

    #[test]
    fn test_ipv4_mapped_private() {
        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        let expected: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(normalize_ip(mapped), expected);
    }
}
