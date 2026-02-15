use sks5::config::acl::{AclPolicy, AclRule, ParsedAcl};
use sks5::config::types::{AclPolicyConfig, GlobalAclConfig, UserAclConfig};

#[test]
fn test_acl_deny_metadata_endpoint() {
    let acl = ParsedAcl::from_config(
        AclPolicyConfig::Allow,
        &[],
        &["169.254.169.254:*".to_string()],
    )
    .unwrap();
    let ip = "169.254.169.254".parse().unwrap();
    assert_eq!(acl.check("169.254.169.254", 80, Some(ip)), AclPolicy::Deny);
    assert_eq!(acl.check("169.254.169.254", 443, Some(ip)), AclPolicy::Deny);
}

#[test]
fn test_acl_allow_specific_domain() {
    let acl = ParsedAcl::from_config(
        AclPolicyConfig::Deny,
        &["*.example.com:443".to_string()],
        &[],
    )
    .unwrap();

    assert_eq!(acl.check("api.example.com", 443, None), AclPolicy::Allow);
    assert_eq!(acl.check("api.example.com", 80, None), AclPolicy::Deny);
    assert_eq!(acl.check("other.com", 443, None), AclPolicy::Deny);
}

#[test]
fn test_acl_cidr_with_port() {
    let acl =
        ParsedAcl::from_config(AclPolicyConfig::Deny, &["10.0.0.0/8:*".to_string()], &[]).unwrap();

    assert_eq!(
        acl.check("10.1.2.3", 80, Some("10.1.2.3".parse().unwrap())),
        AclPolicy::Allow,
    );
    assert_eq!(
        acl.check("192.168.1.1", 80, Some("192.168.1.1".parse().unwrap())),
        AclPolicy::Deny,
    );
}

#[test]
fn test_acl_deny_overrides_allow() {
    let acl = ParsedAcl::from_config(
        AclPolicyConfig::Deny,
        &["*:*".to_string()],
        &["evil.com:*".to_string()],
    )
    .unwrap();

    assert_eq!(acl.check("evil.com", 80, None), AclPolicy::Deny);
    assert_eq!(acl.check("good.com", 80, None), AclPolicy::Allow);
}

#[test]
fn test_acl_port_range() {
    let rule = AclRule::parse("example.com:80-443").unwrap();
    assert!(rule.matches("example.com", 80, None));
    assert!(rule.matches("example.com", 443, None));
    assert!(rule.matches("example.com", 200, None));
    assert!(!rule.matches("example.com", 444, None));
    assert!(!rule.matches("example.com", 79, None));
}

// ---------------------------------------------------------------------------
// Global ACL merge tests
// ---------------------------------------------------------------------------

#[test]
fn test_global_acl_deny_inherited_by_user() {
    let global = GlobalAclConfig {
        default_policy: AclPolicyConfig::Allow,
        allow: vec![],
        deny: vec!["169.254.169.254:*".to_string()],
    };
    let user = UserAclConfig::default(); // inherit = true, no overrides

    let acl = ParsedAcl::from_config_merged(&global, &user).unwrap();
    let ip = "169.254.169.254".parse().unwrap();
    assert_eq!(acl.check("169.254.169.254", 80, Some(ip)), AclPolicy::Deny);
    assert_eq!(
        acl.check("example.com", 80, Some("93.184.216.34".parse().unwrap())),
        AclPolicy::Allow
    );
}

#[test]
fn test_global_acl_user_adds_rules() {
    let global = GlobalAclConfig {
        default_policy: AclPolicyConfig::Allow,
        allow: vec![],
        deny: vec!["169.254.169.254:*".to_string()],
    };
    let user = UserAclConfig {
        default_policy: None, // inherit global Allow
        allow: vec![],
        deny: vec!["evil.com:*".to_string()],
        inherit: true,
    };

    let acl = ParsedAcl::from_config_merged(&global, &user).unwrap();
    // Global deny applies
    let ip = "169.254.169.254".parse().unwrap();
    assert_eq!(acl.check("169.254.169.254", 80, Some(ip)), AclPolicy::Deny);
    // User deny applies
    assert_eq!(acl.check("evil.com", 443, None), AclPolicy::Deny);
    // Default is allow
    assert_eq!(acl.check("good.com", 80, None), AclPolicy::Allow);
}

#[test]
fn test_global_acl_user_overrides_default_policy() {
    let global = GlobalAclConfig {
        default_policy: AclPolicyConfig::Allow,
        allow: vec![],
        deny: vec![],
    };
    let user = UserAclConfig {
        default_policy: Some(AclPolicyConfig::Deny),
        allow: vec!["*.example.com:443".to_string()],
        deny: vec![],
        inherit: true,
    };

    let acl = ParsedAcl::from_config_merged(&global, &user).unwrap();
    // User overrode default to Deny
    assert_eq!(acl.check("other.com", 80, None), AclPolicy::Deny);
    // User allow rule works
    assert_eq!(acl.check("api.example.com", 443, None), AclPolicy::Allow);
}

#[test]
fn test_global_acl_inherit_false_ignores_global() {
    let global = GlobalAclConfig {
        default_policy: AclPolicyConfig::Deny,
        allow: vec!["*.example.com:443".to_string()],
        deny: vec!["169.254.169.254:*".to_string()],
    };
    let user = UserAclConfig {
        default_policy: Some(AclPolicyConfig::Allow),
        allow: vec![],
        deny: vec![],
        inherit: false,
    };

    let acl = ParsedAcl::from_config_merged(&global, &user).unwrap();
    // Global deny on metadata is NOT applied
    let ip = "169.254.169.254".parse().unwrap();
    assert_eq!(acl.check("169.254.169.254", 80, Some(ip)), AclPolicy::Allow);
    // User default is Allow (independently set)
    assert_eq!(acl.check("anything.com", 80, None), AclPolicy::Allow);
}

#[test]
fn test_global_acl_inherit_false_defaults_to_allow() {
    let global = GlobalAclConfig {
        default_policy: AclPolicyConfig::Deny,
        allow: vec![],
        deny: vec![],
    };
    let user = UserAclConfig {
        default_policy: None, // no override, should fallback to Allow
        allow: vec![],
        deny: vec![],
        inherit: false,
    };

    let acl = ParsedAcl::from_config_merged(&global, &user).unwrap();
    // Fallback default is Allow when inherit=false and no user policy
    assert_eq!(acl.check("anything.com", 80, None), AclPolicy::Allow);
}

#[test]
fn test_global_acl_allow_rules_merge() {
    let global = GlobalAclConfig {
        default_policy: AclPolicyConfig::Deny,
        allow: vec!["*.global.com:443".to_string()],
        deny: vec![],
    };
    let user = UserAclConfig {
        default_policy: None, // inherit Deny
        allow: vec!["*.user.com:443".to_string()],
        deny: vec![],
        inherit: true,
    };

    let acl = ParsedAcl::from_config_merged(&global, &user).unwrap();
    // Global allow
    assert_eq!(acl.check("api.global.com", 443, None), AclPolicy::Allow);
    // User allow
    assert_eq!(acl.check("api.user.com", 443, None), AclPolicy::Allow);
    // Neither matches, default is Deny
    assert_eq!(acl.check("other.com", 443, None), AclPolicy::Deny);
}

#[test]
fn test_global_acl_toml_parsing() {
    let toml_str = r##"
[server]
ssh_listen = "0.0.0.0:2222"

[acl]
default_policy = "allow"
deny = ["169.254.169.254:*", "10.0.0.0/8:*"]

[[users]]
username = "alice"
password_hash = "argon2id-fake"

[[users]]
username = "bob"
password_hash = "argon2id-fake"
[users.acl]
default_policy = "deny"
allow = ["*.example.com:443"]
deny = ["evil.com:*"]
"##
    .to_string();
    let config: sks5::config::types::AppConfig = toml::from_str(&toml_str).unwrap();

    // Global ACL parsed
    assert_eq!(config.acl.default_policy, AclPolicyConfig::Allow);
    assert_eq!(config.acl.deny.len(), 2);

    // Alice: no per-user ACL → inherits global
    assert!(config.users[0].acl.default_policy.is_none());
    assert!(config.users[0].acl.allow.is_empty());
    assert!(config.users[0].acl.deny.is_empty());
    assert!(config.users[0].acl.inherit);

    // Bob: per-user ACL with overrides
    assert_eq!(
        config.users[1].acl.default_policy,
        Some(AclPolicyConfig::Deny)
    );
    assert_eq!(config.users[1].acl.allow.len(), 1);
    assert_eq!(config.users[1].acl.deny.len(), 1);
}
