//! Edge case tests for ACL config merging (global + group + user).
//!
//! These tests exercise unusual inheritance combinations that could trip up
//! the three-level merge logic in `ParsedAcl::from_config_merged_with_group`.

use sks5::config::acl::{AclPolicy, ParsedAcl, PreCheckResult};
use sks5::config::types::{AclPolicyConfig, GlobalAclConfig, UserAclConfig};

// ---------------------------------------------------------------------------
// 1. User `inherit=false` ignores both global and group rules entirely
// ---------------------------------------------------------------------------

#[test]
fn user_no_inherit_ignores_global_deny_rules() {
    let global = GlobalAclConfig {
        default_policy: AclPolicyConfig::Allow,
        allow: vec![],
        deny: vec!["evil.com:*".to_string()],
    };
    let user = UserAclConfig {
        default_policy: None, // falls back to Allow when inherit=false
        allow: vec![],
        deny: vec![],
        inherit: false,
    };

    let acl = ParsedAcl::from_config_merged(&global, &user).unwrap();
    // Global deny of evil.com should be ignored because user disables inheritance
    assert_eq!(acl.check("evil.com", 80, None), AclPolicy::Allow);
}

#[test]
fn user_no_inherit_ignores_group_deny_rules() {
    let global = GlobalAclConfig {
        default_policy: AclPolicyConfig::Allow,
        allow: vec![],
        deny: vec![],
    };
    let group = UserAclConfig {
        default_policy: Some(AclPolicyConfig::Deny),
        allow: vec!["safe.com:*".to_string()],
        deny: vec!["evil.com:*".to_string()],
        inherit: true,
    };
    let user = UserAclConfig {
        default_policy: Some(AclPolicyConfig::Allow),
        allow: vec![],
        deny: vec![],
        inherit: false,
    };

    let acl = ParsedAcl::from_config_merged_with_group(&global, Some(&group), &user).unwrap();
    // Group rules should be fully ignored
    assert_eq!(acl.check("evil.com", 80, None), AclPolicy::Allow);
    // Default policy should be user's explicit Allow, not group's Deny
    assert_eq!(acl.check("anything.com", 443, None), AclPolicy::Allow);
}

#[test]
fn user_no_inherit_without_policy_defaults_to_allow() {
    let global = GlobalAclConfig {
        default_policy: AclPolicyConfig::Deny,
        allow: vec![],
        deny: vec![],
    };
    let user = UserAclConfig {
        default_policy: None, // no explicit policy
        allow: vec![],
        deny: vec![],
        inherit: false,
    };

    let acl = ParsedAcl::from_config_merged(&global, &user).unwrap();
    // Should default to Allow (not inherit global Deny)
    assert_eq!(acl.check("anything.com", 80, None), AclPolicy::Allow);
}

// ---------------------------------------------------------------------------
// 2. Policy resolution precedence: user > group > global
// ---------------------------------------------------------------------------

#[test]
fn user_policy_overrides_group_policy() {
    let global = GlobalAclConfig {
        default_policy: AclPolicyConfig::Allow,
        allow: vec![],
        deny: vec![],
    };
    let group = UserAclConfig {
        default_policy: Some(AclPolicyConfig::Deny),
        allow: vec![],
        deny: vec![],
        inherit: true,
    };
    let user = UserAclConfig {
        default_policy: Some(AclPolicyConfig::Allow),
        allow: vec![],
        deny: vec![],
        inherit: true,
    };

    let acl = ParsedAcl::from_config_merged_with_group(&global, Some(&group), &user).unwrap();
    assert_eq!(acl.default_policy, AclPolicy::Allow);
}

#[test]
fn group_policy_overrides_global_when_user_has_none() {
    let global = GlobalAclConfig {
        default_policy: AclPolicyConfig::Allow,
        allow: vec![],
        deny: vec![],
    };
    let group = UserAclConfig {
        default_policy: Some(AclPolicyConfig::Deny),
        allow: vec![],
        deny: vec![],
        inherit: true,
    };
    let user = UserAclConfig {
        default_policy: None, // no override
        allow: vec![],
        deny: vec![],
        inherit: true,
    };

    let acl = ParsedAcl::from_config_merged_with_group(&global, Some(&group), &user).unwrap();
    assert_eq!(acl.default_policy, AclPolicy::Deny);
}

#[test]
fn global_policy_used_when_both_group_and_user_are_none() {
    let global = GlobalAclConfig {
        default_policy: AclPolicyConfig::Deny,
        allow: vec![],
        deny: vec![],
    };
    let group = UserAclConfig {
        default_policy: None,
        allow: vec![],
        deny: vec![],
        inherit: true,
    };
    let user = UserAclConfig {
        default_policy: None,
        allow: vec![],
        deny: vec![],
        inherit: true,
    };

    let acl = ParsedAcl::from_config_merged_with_group(&global, Some(&group), &user).unwrap();
    assert_eq!(acl.default_policy, AclPolicy::Deny);
}

// ---------------------------------------------------------------------------
// 3. Rule concatenation: global + group + user rules are merged
// ---------------------------------------------------------------------------

#[test]
fn deny_rules_from_all_three_levels_are_merged() {
    let global = GlobalAclConfig {
        default_policy: AclPolicyConfig::Allow,
        allow: vec![],
        deny: vec!["10.0.0.0/8:*".to_string()],
    };
    let group = UserAclConfig {
        default_policy: None,
        allow: vec![],
        deny: vec!["172.16.0.0/12:*".to_string()],
        inherit: true,
    };
    let user = UserAclConfig {
        default_policy: None,
        allow: vec![],
        deny: vec!["192.168.0.0/16:*".to_string()],
        inherit: true,
    };

    let acl = ParsedAcl::from_config_merged_with_group(&global, Some(&group), &user).unwrap();

    // All three deny rules should be active
    assert_eq!(
        acl.check("10.0.0.1", 80, Some("10.0.0.1".parse().unwrap())),
        AclPolicy::Deny
    );
    assert_eq!(
        acl.check("172.16.0.1", 80, Some("172.16.0.1".parse().unwrap())),
        AclPolicy::Deny
    );
    assert_eq!(
        acl.check("192.168.1.1", 80, Some("192.168.1.1".parse().unwrap())),
        AclPolicy::Deny
    );
    // Public IP should still be allowed (default policy)
    assert_eq!(
        acl.check("8.8.8.8", 80, Some("8.8.8.8".parse().unwrap())),
        AclPolicy::Allow
    );
}

#[test]
fn allow_rules_from_all_three_levels_are_merged() {
    let global = GlobalAclConfig {
        default_policy: AclPolicyConfig::Deny,
        allow: vec!["*.google.com:443".to_string()],
        deny: vec![],
    };
    let group = UserAclConfig {
        default_policy: None,
        allow: vec!["*.github.com:443".to_string()],
        deny: vec![],
        inherit: true,
    };
    let user = UserAclConfig {
        default_policy: None,
        allow: vec!["*.example.com:443".to_string()],
        deny: vec![],
        inherit: true,
    };

    let acl = ParsedAcl::from_config_merged_with_group(&global, Some(&group), &user).unwrap();

    // All three allow rules should be active
    assert_eq!(acl.check("api.google.com", 443, None), AclPolicy::Allow);
    assert_eq!(acl.check("api.github.com", 443, None), AclPolicy::Allow);
    assert_eq!(acl.check("api.example.com", 443, None), AclPolicy::Allow);
    // Non-matching host should be denied (default policy)
    assert_eq!(acl.check("evil.com", 443, None), AclPolicy::Deny);
}

// ---------------------------------------------------------------------------
// 4. Deny always takes priority over allow (regardless of level)
// ---------------------------------------------------------------------------

#[test]
fn global_deny_overrides_user_allow_for_same_host() {
    let global = GlobalAclConfig {
        default_policy: AclPolicyConfig::Deny,
        allow: vec![],
        deny: vec!["evil.com:*".to_string()],
    };
    let user = UserAclConfig {
        default_policy: None,
        allow: vec!["evil.com:*".to_string()],
        deny: vec![],
        inherit: true,
    };

    let acl = ParsedAcl::from_config_merged(&global, &user).unwrap();
    // Deny rules are checked first, so global deny wins
    assert_eq!(acl.check("evil.com", 443, None), AclPolicy::Deny);
}

#[test]
fn user_deny_overrides_global_allow_for_same_host() {
    let global = GlobalAclConfig {
        default_policy: AclPolicyConfig::Deny,
        allow: vec!["good.com:*".to_string()],
        deny: vec![],
    };
    let user = UserAclConfig {
        default_policy: None,
        allow: vec![],
        deny: vec!["good.com:*".to_string()],
        inherit: true,
    };

    let acl = ParsedAcl::from_config_merged(&global, &user).unwrap();
    // Deny rules are checked first, so user deny wins even though global allows
    assert_eq!(acl.check("good.com", 443, None), AclPolicy::Deny);
}

// ---------------------------------------------------------------------------
// 5. No group provided (None) -- should behave like global + user only
// ---------------------------------------------------------------------------

#[test]
fn no_group_merges_only_global_and_user() {
    let global = GlobalAclConfig {
        default_policy: AclPolicyConfig::Allow,
        allow: vec![],
        deny: vec!["169.254.169.254:*".to_string()],
    };
    let user = UserAclConfig {
        default_policy: Some(AclPolicyConfig::Deny),
        allow: vec!["*.example.com:443".to_string()],
        deny: vec![],
        inherit: true,
    };

    let acl = ParsedAcl::from_config_merged_with_group(&global, None, &user).unwrap();
    assert_eq!(acl.default_policy, AclPolicy::Deny);
    // Global deny should still apply
    assert_eq!(
        acl.check(
            "169.254.169.254",
            80,
            Some("169.254.169.254".parse().unwrap())
        ),
        AclPolicy::Deny
    );
    // User allow should work
    assert_eq!(acl.check("api.example.com", 443, None), AclPolicy::Allow);
    // Unmatched should use user's deny policy
    assert_eq!(acl.check("random.com", 80, None), AclPolicy::Deny);
}

// ---------------------------------------------------------------------------
// 6. Empty rules at all levels -- falls back to default policy
// ---------------------------------------------------------------------------

#[test]
fn all_empty_rules_fall_back_to_global_allow() {
    let global = GlobalAclConfig {
        default_policy: AclPolicyConfig::Allow,
        allow: vec![],
        deny: vec![],
    };
    let group = UserAclConfig {
        default_policy: None,
        allow: vec![],
        deny: vec![],
        inherit: true,
    };
    let user = UserAclConfig {
        default_policy: None,
        allow: vec![],
        deny: vec![],
        inherit: true,
    };

    let acl = ParsedAcl::from_config_merged_with_group(&global, Some(&group), &user).unwrap();
    assert_eq!(acl.check("any-host.com", 80, None), AclPolicy::Allow);
}

#[test]
fn all_empty_rules_fall_back_to_global_deny() {
    let global = GlobalAclConfig {
        default_policy: AclPolicyConfig::Deny,
        allow: vec![],
        deny: vec![],
    };
    let group = UserAclConfig {
        default_policy: None,
        allow: vec![],
        deny: vec![],
        inherit: true,
    };
    let user = UserAclConfig {
        default_policy: None,
        allow: vec![],
        deny: vec![],
        inherit: true,
    };

    let acl = ParsedAcl::from_config_merged_with_group(&global, Some(&group), &user).unwrap();
    assert_eq!(acl.check("any-host.com", 80, None), AclPolicy::Deny);
}

// ---------------------------------------------------------------------------
// 7. Invalid ACL rules at any level produce errors
// ---------------------------------------------------------------------------

#[test]
fn invalid_global_deny_rule_returns_error() {
    let global = GlobalAclConfig {
        default_policy: AclPolicyConfig::Allow,
        allow: vec![],
        deny: vec!["host:not-a-port".to_string()],
    };
    let user = UserAclConfig::default();
    let result = ParsedAcl::from_config_merged(&global, &user);
    assert!(result.is_err());
}

#[test]
fn invalid_user_allow_rule_returns_error() {
    let global = GlobalAclConfig::default();
    let user = UserAclConfig {
        default_policy: None,
        allow: vec!["host:99999".to_string()], // port overflow
        deny: vec![],
        inherit: true,
    };
    let result = ParsedAcl::from_config_merged(&global, &user);
    assert!(result.is_err());
}

#[test]
fn invalid_group_deny_rule_returns_error() {
    let global = GlobalAclConfig::default();
    let group = UserAclConfig {
        default_policy: None,
        allow: vec![],
        deny: vec!["host:abc".to_string()],
        inherit: true,
    };
    let user = UserAclConfig::default();
    let result = ParsedAcl::from_config_merged_with_group(&global, Some(&group), &user);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// 8. Pre-check hostname: CIDR rules with literal IPs vs hostnames
// ---------------------------------------------------------------------------

#[test]
fn precheck_literal_ip_matches_cidr_deny_immediately() {
    let acl =
        ParsedAcl::from_config(AclPolicyConfig::Allow, &[], &["10.0.0.0/8:*".to_string()]).unwrap();

    // Literal IP that matches CIDR should be denied at pre-check
    let result = acl.check_hostname_only("10.1.2.3", 80);
    assert_eq!(result, PreCheckResult::Deny);
}

#[test]
fn precheck_hostname_defers_for_cidr_only_rules() {
    let acl =
        ParsedAcl::from_config(AclPolicyConfig::Allow, &[], &["10.0.0.0/8:*".to_string()]).unwrap();

    // Hostname (not a literal IP) should defer to post-check
    let result = acl.check_hostname_only("example.com", 80);
    assert_eq!(result, PreCheckResult::Defer);
}

#[test]
fn precheck_hostname_deny_matches_before_cidr_allow() {
    let acl = ParsedAcl::from_config(
        AclPolicyConfig::Allow,
        &["10.0.0.0/8:*".to_string()],
        &["evil.com:*".to_string()],
    )
    .unwrap();

    // Hostname deny should be checked before allow
    let result = acl.check_hostname_only("evil.com", 80);
    assert_eq!(result, PreCheckResult::Deny);
}

// ---------------------------------------------------------------------------
// 9. Port range edge cases in merged ACLs
// ---------------------------------------------------------------------------

#[test]
fn merged_acl_respects_port_range_in_allow_rule() {
    let global = GlobalAclConfig {
        default_policy: AclPolicyConfig::Deny,
        allow: vec!["*.example.com:80-443".to_string()],
        deny: vec![],
    };
    let user = UserAclConfig::default();

    let acl = ParsedAcl::from_config_merged(&global, &user).unwrap();
    assert_eq!(acl.check("api.example.com", 80, None), AclPolicy::Allow);
    assert_eq!(acl.check("api.example.com", 443, None), AclPolicy::Allow);
    assert_eq!(acl.check("api.example.com", 200, None), AclPolicy::Allow);
    assert_eq!(acl.check("api.example.com", 8080, None), AclPolicy::Deny);
    assert_eq!(acl.check("api.example.com", 22, None), AclPolicy::Deny);
}

// ---------------------------------------------------------------------------
// 10. Wildcard hostname matching edge cases
// ---------------------------------------------------------------------------

#[test]
fn wildcard_deny_blocks_exact_domain_match() {
    let acl = ParsedAcl::from_config(
        AclPolicyConfig::Allow,
        &[],
        &["*.example.com:*".to_string()],
    )
    .unwrap();

    // *.example.com should match example.com itself
    assert_eq!(acl.check("example.com", 80, None), AclPolicy::Deny);
    // And subdomains
    assert_eq!(acl.check("sub.example.com", 80, None), AclPolicy::Deny);
    // But not a different domain ending with same suffix
    assert_eq!(acl.check("notexample.com", 80, None), AclPolicy::Allow);
}
