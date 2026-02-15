//! Edge case tests for proxy ACL decision functions.
//!
//! Tests the `pre_check_hostname_and_log` and `check_and_log` functions
//! in `sks5::proxy::acl` which wrap the raw ACL checks with logging.

use sks5::config::acl::ParsedAcl;
use sks5::config::types::AclPolicyConfig;
use sks5::proxy::acl::{check_and_log, pre_check_hostname_and_log};

// ---------------------------------------------------------------------------
// pre_check_hostname_and_log
// ---------------------------------------------------------------------------

#[test]
fn precheck_denies_hostname_deny_rule() {
    let acl =
        ParsedAcl::from_config(AclPolicyConfig::Allow, &[], &["evil.com:*".to_string()]).unwrap();

    let decision = pre_check_hostname_and_log(&acl, "alice", "evil.com", 80);
    assert!(!decision.allowed);
    assert!(decision.matched_rule.is_some());
    assert!(decision.matched_rule.unwrap().contains("deny"));
}

#[test]
fn precheck_allows_when_no_deny_matches() {
    let acl = ParsedAcl::from_config(
        AclPolicyConfig::Allow,
        &["*.example.com:443".to_string()],
        &["evil.com:*".to_string()],
    )
    .unwrap();

    let decision = pre_check_hostname_and_log(&acl, "alice", "safe.example.com", 443);
    assert!(decision.allowed);
}

#[test]
fn precheck_allows_on_defer_for_cidr_only_rules() {
    // When only CIDR deny rules exist and host is a domain name,
    // the pre-check should return allowed=true (defer means proceed to DNS)
    let acl =
        ParsedAcl::from_config(AclPolicyConfig::Allow, &[], &["10.0.0.0/8:*".to_string()]).unwrap();

    let decision = pre_check_hostname_and_log(&acl, "alice", "example.com", 80);
    assert!(decision.allowed);
}

#[test]
fn precheck_denies_literal_ip_matching_cidr() {
    let acl =
        ParsedAcl::from_config(AclPolicyConfig::Allow, &[], &["10.0.0.0/8:*".to_string()]).unwrap();

    // Literal IP string that matches CIDR should be denied at pre-check
    let decision = pre_check_hostname_and_log(&acl, "alice", "10.1.2.3", 80);
    assert!(!decision.allowed);
}

#[test]
fn precheck_returns_matched_rule_for_allow() {
    let acl =
        ParsedAcl::from_config(AclPolicyConfig::Deny, &["safe.com:443".to_string()], &[]).unwrap();

    let decision = pre_check_hostname_and_log(&acl, "alice", "safe.com", 443);
    assert!(decision.allowed);
    assert!(decision.matched_rule.is_some());
    assert!(decision.matched_rule.unwrap().contains("allow"));
}

#[test]
fn precheck_with_empty_acl_allows_everything() {
    let acl = ParsedAcl::from_config(AclPolicyConfig::Allow, &[], &[]).unwrap();

    let decision = pre_check_hostname_and_log(&acl, "alice", "anything.com", 12345);
    // No rules to match, so defer, which is treated as allowed
    assert!(decision.allowed);
    assert!(decision.matched_rule.is_none());
}

// ---------------------------------------------------------------------------
// check_and_log (post-check with resolved IP)
// ---------------------------------------------------------------------------

#[test]
fn postcheck_allows_public_ip_with_allow_default() {
    let acl = ParsedAcl::from_config(AclPolicyConfig::Allow, &[], &[]).unwrap();

    let decision = check_and_log(
        &acl,
        "alice",
        "example.com",
        80,
        Some("93.184.216.34".parse().unwrap()),
    );
    assert!(decision.allowed);
    assert!(decision.matched_rule.is_none()); // default policy, no rule matched
}

#[test]
fn postcheck_denies_matching_cidr_deny_rule() {
    let acl =
        ParsedAcl::from_config(AclPolicyConfig::Allow, &[], &["10.0.0.0/8:*".to_string()]).unwrap();

    let decision = check_and_log(
        &acl,
        "alice",
        "internal.corp",
        80,
        Some("10.1.2.3".parse().unwrap()),
    );
    assert!(!decision.allowed);
    assert!(decision.matched_rule.is_some());
}

#[test]
fn postcheck_allows_matching_allow_rule_with_deny_default() {
    let acl = ParsedAcl::from_config(
        AclPolicyConfig::Deny,
        &["*.example.com:443".to_string()],
        &[],
    )
    .unwrap();

    let decision = check_and_log(&acl, "alice", "api.example.com", 443, None);
    assert!(decision.allowed);
    assert!(decision.matched_rule.is_some());
}

#[test]
fn postcheck_deny_wins_over_allow_for_same_target() {
    let acl = ParsedAcl::from_config(
        AclPolicyConfig::Allow,
        &["evil.com:*".to_string()],
        &["evil.com:*".to_string()],
    )
    .unwrap();

    // Deny is checked first, so it should deny even though allow also matches
    let decision = check_and_log(&acl, "alice", "evil.com", 80, None);
    assert!(!decision.allowed);
}

#[test]
fn postcheck_with_none_resolved_ip_uses_hostname_matching() {
    let acl =
        ParsedAcl::from_config(AclPolicyConfig::Deny, &["good.com:443".to_string()], &[]).unwrap();

    // No resolved IP provided -- hostname matching only
    let decision = check_and_log(&acl, "alice", "good.com", 443, None);
    assert!(decision.allowed);
}

#[test]
fn postcheck_cidr_rule_does_not_match_unresolved_hostname() {
    let acl = ParsedAcl::from_config(
        AclPolicyConfig::Deny,
        &["93.184.216.0/24:*".to_string()],
        &[],
    )
    .unwrap();

    // No resolved IP -- CIDR rule cannot match hostname "example.com"
    let decision = check_and_log(&acl, "alice", "example.com", 80, None);
    assert!(!decision.allowed); // falls to default Deny
}

#[test]
fn postcheck_port_specific_deny_only_blocks_that_port() {
    let acl =
        ParsedAcl::from_config(AclPolicyConfig::Allow, &[], &["evil.com:22".to_string()]).unwrap();

    let decision_22 = check_and_log(&acl, "alice", "evil.com", 22, None);
    assert!(!decision_22.allowed);

    let decision_443 = check_and_log(&acl, "alice", "evil.com", 443, None);
    assert!(decision_443.allowed);
}

#[test]
fn postcheck_ipv6_resolved_address_matches_cidr() {
    let acl =
        ParsedAcl::from_config(AclPolicyConfig::Allow, &[], &["fc00::/7:*".to_string()]).unwrap();

    // IPv6 ULA address should match fc00::/7
    let decision = check_and_log(
        &acl,
        "alice",
        "internal.srv",
        80,
        Some("fd12:3456::1".parse().unwrap()),
    );
    assert!(!decision.allowed);
}
