use proptest::prelude::*;
use sks5::config::acl::{AclPolicy, AclRule, ParsedAcl};
use sks5::config::types::AclPolicyConfig;

proptest! {
    #[test]
    fn acl_rule_parse_never_panics(s in "\\PC{0,100}") {
        // AclRule::parse should return Ok or Err, never panic
        let _ = AclRule::parse(&s);
    }

    #[test]
    fn acl_valid_host_port_rules_parse(
        host in "[a-z]{1,10}(\\.[a-z]{1,10}){0,3}",
        port in 1u16..=65535u16,
    ) {
        let rule_str = format!("{}:{}", host, port);
        let result = AclRule::parse(&rule_str);
        prop_assert!(result.is_ok(), "valid host:port rule should parse: {}", rule_str);
    }

    #[test]
    fn acl_wildcard_port_rules_parse(
        host in "[a-z]{1,10}(\\.[a-z]{1,10}){0,3}",
    ) {
        let rule_str = format!("{}:*", host);
        let result = AclRule::parse(&rule_str);
        prop_assert!(result.is_ok(), "wildcard port rule should parse: {}", rule_str);
    }

    #[test]
    fn acl_wildcard_host_rules_parse(
        port in 1u16..=65535u16,
    ) {
        let rule_str = format!("*.example.com:{}", port);
        let result = AclRule::parse(&rule_str);
        prop_assert!(result.is_ok(), "wildcard host rule should parse: {}", rule_str);
    }

    #[test]
    fn acl_port_range_rules_parse(
        host in "[a-z]{1,10}(\\.[a-z]{1,10}){0,3}",
        lo in 1u16..=32000u16,
        hi in 32001u16..=65535u16,
    ) {
        let rule_str = format!("{}:{}-{}", host, lo, hi);
        let result = AclRule::parse(&rule_str);
        prop_assert!(result.is_ok(), "port range rule should parse: {}", rule_str);
    }

    #[test]
    fn acl_cidr_v4_rules_parse(
        a in 1u8..=254u8,
        b in 0u8..=255u8,
        prefix in 8u8..=32u8,
        port in 1u16..=65535u16,
    ) {
        let rule_str = format!("{}.{}.0.0/{}:{}", a, b, prefix, port);
        // CIDR rules may or may not parse depending on prefix validity for the IP
        let _ = AclRule::parse(&rule_str);
    }

    #[test]
    fn acl_ipv4_single_ip_rules_parse(
        a in 1u8..=254u8,
        b in 0u8..=255u8,
        c in 0u8..=255u8,
        d in 1u8..=254u8,
        port in 1u16..=65535u16,
    ) {
        let rule_str = format!("{}.{}.{}.{}:{}", a, b, c, d, port);
        let result = AclRule::parse(&rule_str);
        prop_assert!(result.is_ok(), "single IPv4 rule should parse: {}", rule_str);
    }

    #[test]
    fn acl_check_returns_default_for_no_rules(
        host in "[a-z]{1,10}\\.[a-z]{1,10}",
        port in 1u16..=65535u16,
        use_allow in prop::bool::ANY,
    ) {
        let policy = if use_allow { AclPolicyConfig::Allow } else { AclPolicyConfig::Deny };
        let acl = ParsedAcl::from_config(policy, &[], &[]).unwrap();
        let result = acl.check(&host, port, None);
        let expected = if use_allow { AclPolicy::Allow } else { AclPolicy::Deny };
        prop_assert_eq!(result, expected, "empty ACL should return default policy");
    }

    #[test]
    fn acl_deny_rule_overrides_default_allow(
        host in "[a-z]{3,10}",
        port in 1u16..=65535u16,
    ) {
        let deny_rule = format!("{}:*", host);
        let acl = ParsedAcl::from_config(
            AclPolicyConfig::Allow,
            &[],
            &[deny_rule],
        ).unwrap();
        let result = acl.check(&host, port, None);
        prop_assert_eq!(result, AclPolicy::Deny, "deny rule should override allow default");
    }

    #[test]
    fn acl_allow_rule_overrides_default_deny(
        host in "[a-z]{3,10}",
        port in 1u16..=65535u16,
    ) {
        let allow_rule = format!("{}:*", host);
        let acl = ParsedAcl::from_config(
            AclPolicyConfig::Deny,
            &[allow_rule],
            &[],
        ).unwrap();
        let result = acl.check(&host, port, None);
        prop_assert_eq!(result, AclPolicy::Allow, "allow rule should override deny default");
    }

    #[test]
    fn acl_deny_takes_precedence_over_allow(
        host in "[a-z]{3,10}",
        port in 1u16..=65535u16,
    ) {
        // When both deny and allow match, deny takes precedence (checked first)
        let rule = format!("{}:*", host);
        let acl = ParsedAcl::from_config(
            AclPolicyConfig::Allow,
            std::slice::from_ref(&rule),
            std::slice::from_ref(&rule),
        ).unwrap();
        let result = acl.check(&host, port, None);
        prop_assert_eq!(result, AclPolicy::Deny, "deny should take precedence over allow");
    }

    #[test]
    fn acl_cidr_matches_contained_ips(
        third_octet in 0u8..=255u8,
        fourth_octet in 1u8..=254u8,
        port in 1u16..=65535u16,
    ) {
        let acl = ParsedAcl::from_config(
            AclPolicyConfig::Deny,
            &["10.0.0.0/8:*".to_string()],
            &[],
        ).unwrap();
        let ip_str = format!("10.0.{}.{}", third_octet, fourth_octet);
        let ip: std::net::IpAddr = ip_str.parse().unwrap();
        let result = acl.check(&ip_str, port, Some(ip));
        prop_assert_eq!(result, AclPolicy::Allow, "10.x.x.x should match 10.0.0.0/8");
    }

    #[test]
    fn acl_check_verbose_agrees_with_check(
        host in "[a-z]{3,10}\\.[a-z]{3,10}",
        port in 1u16..=65535u16,
    ) {
        let acl = ParsedAcl::from_config(
            AclPolicyConfig::Deny,
            &["*.example.com:443".to_string()],
            &["evil.com:*".to_string()],
        ).unwrap();
        let simple = acl.check(&host, port, None);
        let (verbose, _matched) = acl.check_verbose(&host, port, None);
        prop_assert_eq!(simple, verbose, "check and check_verbose should agree");
    }
}
