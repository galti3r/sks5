use super::normalize::normalize_ip;
use ipnet::IpNet;
use std::net::IpAddr;

/// Check if an IP is in a list of allowed networks
pub fn is_allowed(ip: &IpAddr, allowed_networks: &[IpNet]) -> bool {
    if allowed_networks.is_empty() {
        return true; // Empty list = all allowed
    }
    let ip = normalize_ip(*ip);
    allowed_networks.iter().any(|net| net.contains(&ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_allows_all() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(is_allowed(&ip, &[]));
    }

    #[test]
    fn test_allowed_in_cidr() {
        let nets: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        assert!(is_allowed(&"10.1.2.3".parse().unwrap(), &nets));
        assert!(!is_allowed(&"192.168.1.1".parse().unwrap(), &nets));
    }

    #[test]
    fn test_multiple_cidrs() {
        let nets: Vec<IpNet> = vec![
            "10.0.0.0/8".parse().unwrap(),
            "192.168.0.0/16".parse().unwrap(),
        ];
        assert!(is_allowed(&"10.1.2.3".parse().unwrap(), &nets));
        assert!(is_allowed(&"192.168.1.1".parse().unwrap(), &nets));
        assert!(!is_allowed(&"172.16.0.1".parse().unwrap(), &nets));
    }
}
