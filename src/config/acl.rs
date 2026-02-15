use crate::config::types::{AclPolicyConfig, GlobalAclConfig, UserAclConfig};
use ipnet::IpNet;
use std::fmt;
use std::net::IpAddr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AclError {
    #[error("invalid ACL rule: {0}")]
    InvalidRule(String),
}

/// Represents a parsed ACL rule that can match against host:port targets
#[derive(Debug, Clone)]
pub enum AclRule {
    /// Match a CIDR network with optional port
    Cidr { network: IpNet, port: PortMatch },
    /// Match a hostname pattern with optional port
    HostPattern { pattern: String, port: PortMatch },
}

#[derive(Debug, Clone)]
pub enum PortMatch {
    Any,
    Exact(u16),
    Range(u16, u16),
}

/// Parsed ACL policy for a user
#[derive(Debug, Clone)]
pub struct ParsedAcl {
    pub default_policy: AclPolicy,
    pub allow_rules: Vec<AclRule>,
    pub deny_rules: Vec<AclRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclPolicy {
    Allow,
    Deny,
}

/// Result of a hostname-only pre-check (before DNS resolution)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreCheckResult {
    /// A hostname-based rule explicitly allows
    Allow,
    /// A hostname-based rule explicitly denies
    Deny,
    /// No hostname rule matched — need resolved IP for CIDR rules
    Defer,
}

impl fmt::Display for PortMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortMatch::Any => write!(f, "*"),
            PortMatch::Exact(p) => write!(f, "{}", p),
            PortMatch::Range(lo, hi) => write!(f, "{}-{}", lo, hi),
        }
    }
}

impl fmt::Display for AclRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AclRule::Cidr { network, port } => write!(f, "{}:{}", network, port),
            AclRule::HostPattern { pattern, port } => write!(f, "{}:{}", pattern, port),
        }
    }
}

/// Helper: convert AclPolicyConfig to AclPolicy.
fn to_policy(p: AclPolicyConfig) -> AclPolicy {
    match p {
        AclPolicyConfig::Allow => AclPolicy::Allow,
        AclPolicyConfig::Deny => AclPolicy::Deny,
    }
}

/// Helper: parse a slice of rule strings into AclRule vec.
fn parse_rules(rules: &[String]) -> Result<Vec<AclRule>, AclError> {
    rules.iter().map(|r| AclRule::parse(r)).collect()
}

impl ParsedAcl {
    pub fn from_config(
        default_policy: AclPolicyConfig,
        allow: &[String],
        deny: &[String],
    ) -> Result<Self, AclError> {
        Ok(Self {
            default_policy: to_policy(default_policy),
            allow_rules: parse_rules(allow)?,
            deny_rules: parse_rules(deny)?,
        })
    }

    /// Build a ParsedAcl by merging global, optional group, and per-user ACL configs.
    ///
    /// Merge order: global → group → user (most specific wins for policy).
    /// Rules are concatenated: global deny + group deny + user deny, etc.
    ///
    /// When `user.inherit == false`:
    ///   - Only user rules are used; global and group are ignored
    ///   - `default_policy` falls back to `Allow` if not set by user
    pub fn from_config_merged_with_group(
        global: &GlobalAclConfig,
        group: Option<&UserAclConfig>,
        user: &UserAclConfig,
    ) -> Result<Self, AclError> {
        if !user.inherit {
            let policy = user.default_policy.unwrap_or(AclPolicyConfig::Allow);
            return Ok(Self {
                default_policy: to_policy(policy),
                allow_rules: parse_rules(&user.allow)?,
                deny_rules: parse_rules(&user.deny)?,
            });
        }

        // Resolve default_policy: user > group > global
        let group_policy = group.and_then(|g| g.default_policy);
        let policy = user
            .default_policy
            .or(group_policy)
            .unwrap_or(global.default_policy);

        // Merge rules: global + group + user
        let mut deny_rules = parse_rules(&global.deny)?;
        if let Some(g) = group {
            deny_rules.extend(parse_rules(&g.deny)?);
        }
        deny_rules.extend(parse_rules(&user.deny)?);

        let mut allow_rules = parse_rules(&global.allow)?;
        if let Some(g) = group {
            allow_rules.extend(parse_rules(&g.allow)?);
        }
        allow_rules.extend(parse_rules(&user.allow)?);

        Ok(Self {
            default_policy: to_policy(policy),
            allow_rules,
            deny_rules,
        })
    }

    /// Build a ParsedAcl by merging global and per-user ACL configs (no group).
    pub fn from_config_merged(
        global: &GlobalAclConfig,
        user: &UserAclConfig,
    ) -> Result<Self, AclError> {
        Self::from_config_merged_with_group(global, None, user)
    }

    /// Pre-check ACL using only hostname (before DNS resolution).
    /// Returns `Deny` if a hostname deny rule matches, `Allow` if hostname allow matches,
    /// `Defer` if only CIDR rules could match (needs resolved IP).
    ///
    /// If the host is already a literal IP address, CIDR rules are also checked
    /// immediately (no DNS needed).
    pub fn check_hostname_only(&self, host: &str, port: u16) -> PreCheckResult {
        // If the host is a literal IP, we can also check CIDR rules immediately
        let literal_ip: Option<IpAddr> = host.parse().ok();

        for rule in &self.deny_rules {
            match rule {
                AclRule::HostPattern { .. } => {
                    if rule.matches(host, port, None) {
                        return PreCheckResult::Deny;
                    }
                }
                AclRule::Cidr { .. } if literal_ip.is_some() => {
                    if rule.matches(host, port, literal_ip) {
                        return PreCheckResult::Deny;
                    }
                }
                _ => {}
            }
        }

        for rule in &self.allow_rules {
            match rule {
                AclRule::HostPattern { .. } => {
                    if rule.matches(host, port, None) {
                        return PreCheckResult::Allow;
                    }
                }
                AclRule::Cidr { .. } if literal_ip.is_some() => {
                    if rule.matches(host, port, literal_ip) {
                        return PreCheckResult::Allow;
                    }
                }
                _ => {}
            }
        }

        // If there are only CIDR rules and host is not a literal IP, we need DNS
        PreCheckResult::Defer
    }

    /// Check if a connection to host:port is allowed.
    /// `resolved_ip` is the IP the hostname resolved to (for CIDR matching).
    pub fn check(&self, host: &str, port: u16, resolved_ip: Option<IpAddr>) -> AclPolicy {
        // Check deny rules first
        for rule in &self.deny_rules {
            if rule.matches(host, port, resolved_ip) {
                return AclPolicy::Deny;
            }
        }

        // Check allow rules
        for rule in &self.allow_rules {
            if rule.matches(host, port, resolved_ip) {
                return AclPolicy::Allow;
            }
        }

        self.default_policy
    }

    /// Like `check()` but also returns the matched rule as a Display string.
    pub fn check_verbose(
        &self,
        host: &str,
        port: u16,
        resolved_ip: Option<IpAddr>,
    ) -> (AclPolicy, Option<String>) {
        for rule in &self.deny_rules {
            if rule.matches(host, port, resolved_ip) {
                return (AclPolicy::Deny, Some(format!("deny:{}", rule)));
            }
        }

        for rule in &self.allow_rules {
            if rule.matches(host, port, resolved_ip) {
                return (AclPolicy::Allow, Some(format!("allow:{}", rule)));
            }
        }

        (self.default_policy, None)
    }

    /// Like `check_hostname_only()` but also returns the matched rule.
    pub fn check_hostname_verbose(
        &self,
        host: &str,
        port: u16,
    ) -> (PreCheckResult, Option<String>) {
        // If the host is a literal IP, we can also check CIDR rules immediately
        let literal_ip: Option<IpAddr> = host.parse().ok();

        for rule in &self.deny_rules {
            match rule {
                AclRule::HostPattern { .. } => {
                    if rule.matches(host, port, None) {
                        return (PreCheckResult::Deny, Some(format!("deny:{}", rule)));
                    }
                }
                AclRule::Cidr { .. } if literal_ip.is_some() => {
                    if rule.matches(host, port, literal_ip) {
                        return (PreCheckResult::Deny, Some(format!("deny:{}", rule)));
                    }
                }
                _ => {}
            }
        }

        for rule in &self.allow_rules {
            match rule {
                AclRule::HostPattern { .. } => {
                    if rule.matches(host, port, None) {
                        return (PreCheckResult::Allow, Some(format!("allow:{}", rule)));
                    }
                }
                AclRule::Cidr { .. } if literal_ip.is_some() => {
                    if rule.matches(host, port, literal_ip) {
                        return (PreCheckResult::Allow, Some(format!("allow:{}", rule)));
                    }
                }
                _ => {}
            }
        }

        (PreCheckResult::Defer, None)
    }
}

impl AclRule {
    /// Parse a rule string like "*.example.com:443", "10.0.0.0/8:*", "host:80-443"
    pub fn parse(rule: &str) -> Result<Self, AclError> {
        // Split host:port
        let (host_part, port_part) = split_host_port(rule)?;
        let port = parse_port_match(port_part)?;

        // Try to parse as CIDR
        if let Ok(network) = host_part.parse::<IpNet>() {
            return Ok(AclRule::Cidr { network, port });
        }

        // Try as single IP
        if let Ok(ip) = host_part.parse::<IpAddr>() {
            let network = IpNet::from(ip);
            return Ok(AclRule::Cidr { network, port });
        }

        // Treat as hostname pattern (pre-lowercase for case-insensitive matching)
        Ok(AclRule::HostPattern {
            pattern: host_part.to_ascii_lowercase(),
            port,
        })
    }

    /// Check if this rule matches the given target
    pub fn matches(&self, host: &str, port: u16, resolved_ip: Option<IpAddr>) -> bool {
        match self {
            AclRule::Cidr { network, port: pm } => {
                if !pm.matches(port) {
                    return false;
                }
                // Match against resolved IP
                if let Some(ip) = resolved_ip {
                    network.contains(&ip)
                } else if let Ok(ip) = host.parse::<IpAddr>() {
                    network.contains(&ip)
                } else {
                    false
                }
            }
            AclRule::HostPattern { pattern, port: pm } => {
                if !pm.matches(port) {
                    return false;
                }
                hostname_matches(host, pattern)
            }
        }
    }
}

impl PortMatch {
    pub fn matches(&self, port: u16) -> bool {
        match self {
            PortMatch::Any => true,
            PortMatch::Exact(p) => *p == port,
            PortMatch::Range(lo, hi) => port >= *lo && port <= *hi,
        }
    }
}

/// Split "host:port" or "cidr:port"
/// Handles IPv6 addresses in brackets: [::1]:port
fn split_host_port(rule: &str) -> Result<(&str, &str), AclError> {
    // Handle IPv6 bracket notation [addr]:port
    if rule.starts_with('[') {
        if let Some(bracket_end) = rule.find(']') {
            let host = &rule[1..bracket_end];
            if bracket_end + 1 < rule.len() && rule.as_bytes()[bracket_end + 1] == b':' {
                let port = &rule[bracket_end + 2..];
                return Ok((host, port));
            }
            return Ok((host, "*"));
        }
        return Err(AclError::InvalidRule(format!(
            "unclosed bracket in: {rule}"
        )));
    }

    // For non-bracketed, find the last ':'
    if let Some(pos) = rule.rfind(':') {
        let host = &rule[..pos];
        let port = &rule[pos + 1..];
        // Check if host part looks like a CIDR or hostname (not a bare IPv6)
        // If there are multiple colons in host, it might be IPv6 without port
        if host.contains(':') && !host.contains('/') {
            // Likely an IPv6 address without port, treat whole thing as host
            return Ok((rule, "*"));
        }
        Ok((host, port))
    } else {
        // No port specified, match all ports
        Ok((rule, "*"))
    }
}

fn parse_port_match(port_str: &str) -> Result<PortMatch, AclError> {
    if port_str == "*" {
        return Ok(PortMatch::Any);
    }

    if let Some(dash_pos) = port_str.find('-') {
        let lo: u16 = port_str[..dash_pos]
            .parse()
            .map_err(|_| AclError::InvalidRule(format!("invalid port range: {port_str}")))?;
        let hi: u16 = port_str[dash_pos + 1..]
            .parse()
            .map_err(|_| AclError::InvalidRule(format!("invalid port range: {port_str}")))?;
        if lo > hi {
            return Err(AclError::InvalidRule(format!(
                "port range low > high: {port_str}"
            )));
        }
        return Ok(PortMatch::Range(lo, hi));
    }

    let port: u16 = port_str
        .parse()
        .map_err(|_| AclError::InvalidRule(format!("invalid port: {port_str}")))?;
    Ok(PortMatch::Exact(port))
}

/// Wildcard hostname matching: "*.example.com" matches "foo.example.com"
/// `pattern` is already lowercased at parse time.
fn hostname_matches(host: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Match the domain itself and any subdomain
        host.eq_ignore_ascii_case(suffix)
            || (host.len() > suffix.len() + 1
                && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
                && host[host.len() - suffix.len()..].eq_ignore_ascii_case(suffix))
    } else {
        host.eq_ignore_ascii_case(pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_port_basic() {
        let (host, port) = split_host_port("example.com:443").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, "443");
    }

    #[test]
    fn test_parse_host_port_wildcard() {
        let (host, port) = split_host_port("*.example.com:*").unwrap();
        assert_eq!(host, "*.example.com");
        assert_eq!(port, "*");
    }

    #[test]
    fn test_parse_cidr_port() {
        let (host, port) = split_host_port("10.0.0.0/8:*").unwrap();
        assert_eq!(host, "10.0.0.0/8");
        assert_eq!(port, "*");
    }

    #[test]
    fn test_hostname_matches_exact() {
        assert!(hostname_matches("example.com", "example.com"));
        assert!(!hostname_matches("other.com", "example.com"));
    }

    #[test]
    fn test_hostname_matches_wildcard() {
        assert!(hostname_matches("foo.example.com", "*.example.com"));
        assert!(hostname_matches("bar.baz.example.com", "*.example.com"));
        assert!(hostname_matches("example.com", "*.example.com"));
        assert!(!hostname_matches("notexample.com", "*.example.com"));
    }

    #[test]
    fn test_hostname_matches_star() {
        assert!(hostname_matches("anything.com", "*"));
    }

    #[test]
    fn test_port_match() {
        assert!(PortMatch::Any.matches(443));
        assert!(PortMatch::Exact(443).matches(443));
        assert!(!PortMatch::Exact(443).matches(80));
        assert!(PortMatch::Range(80, 443).matches(80));
        assert!(PortMatch::Range(80, 443).matches(443));
        assert!(PortMatch::Range(80, 443).matches(200));
        assert!(!PortMatch::Range(80, 443).matches(444));
    }

    #[test]
    fn test_acl_rule_cidr() {
        let rule = AclRule::parse("10.0.0.0/8:*").unwrap();
        assert!(rule.matches("10.1.2.3", 80, Some("10.1.2.3".parse().unwrap())));
        assert!(!rule.matches("192.168.1.1", 80, Some("192.168.1.1".parse().unwrap())));
    }

    #[test]
    fn test_acl_rule_hostname() {
        let rule = AclRule::parse("*.example.com:443").unwrap();
        assert!(rule.matches("foo.example.com", 443, None));
        assert!(!rule.matches("foo.example.com", 80, None));
        assert!(!rule.matches("other.com", 443, None));
    }

    #[test]
    fn test_parsed_acl_deny_first() {
        let acl = ParsedAcl::from_config(
            AclPolicyConfig::Allow,
            &[],
            &["169.254.169.254:*".to_string()],
        )
        .unwrap();

        assert_eq!(
            acl.check(
                "169.254.169.254",
                80,
                Some("169.254.169.254".parse().unwrap())
            ),
            AclPolicy::Deny
        );
        assert_eq!(
            acl.check("example.com", 80, Some("93.184.216.34".parse().unwrap())),
            AclPolicy::Allow
        );
    }

    #[test]
    fn test_parsed_acl_deny_default() {
        let acl = ParsedAcl::from_config(
            AclPolicyConfig::Deny,
            &["*.example.com:443".to_string()],
            &[],
        )
        .unwrap();

        assert_eq!(acl.check("foo.example.com", 443, None), AclPolicy::Allow);
        assert_eq!(acl.check("foo.example.com", 80, None), AclPolicy::Deny);
        assert_eq!(acl.check("other.com", 443, None), AclPolicy::Deny);
    }

    #[test]
    fn test_display_port_match() {
        assert_eq!(PortMatch::Any.to_string(), "*");
        assert_eq!(PortMatch::Exact(443).to_string(), "443");
        assert_eq!(PortMatch::Range(80, 443).to_string(), "80-443");
    }

    #[test]
    fn test_display_acl_rule() {
        let rule = AclRule::parse("*.example.com:443").unwrap();
        assert_eq!(rule.to_string(), "*.example.com:443");

        let rule = AclRule::parse("10.0.0.0/8:*").unwrap();
        assert_eq!(rule.to_string(), "10.0.0.0/8:*");

        let rule = AclRule::parse("host.com:80-443").unwrap();
        assert_eq!(rule.to_string(), "host.com:80-443");
    }

    #[test]
    fn test_check_verbose_deny() {
        let acl = ParsedAcl::from_config(
            AclPolicyConfig::Allow,
            &[],
            &["169.254.169.254:*".to_string()],
        )
        .unwrap();

        let (policy, matched) = acl.check_verbose(
            "169.254.169.254",
            80,
            Some("169.254.169.254".parse().unwrap()),
        );
        assert_eq!(policy, AclPolicy::Deny);
        assert_eq!(matched.unwrap(), "deny:169.254.169.254/32:*");
    }

    #[test]
    fn test_check_verbose_allow() {
        let acl = ParsedAcl::from_config(
            AclPolicyConfig::Deny,
            &["*.example.com:443".to_string()],
            &[],
        )
        .unwrap();

        let (policy, matched) = acl.check_verbose("foo.example.com", 443, None);
        assert_eq!(policy, AclPolicy::Allow);
        assert_eq!(matched.unwrap(), "allow:*.example.com:443");
    }

    #[test]
    fn test_check_verbose_default() {
        let acl = ParsedAcl::from_config(AclPolicyConfig::Allow, &[], &[]).unwrap();

        let (policy, matched) =
            acl.check_verbose("anything.com", 80, Some("93.184.216.34".parse().unwrap()));
        assert_eq!(policy, AclPolicy::Allow);
        assert!(matched.is_none());
    }

    #[test]
    fn test_check_hostname_verbose_deny() {
        let acl = ParsedAcl::from_config(AclPolicyConfig::Allow, &[], &["evil.com:*".to_string()])
            .unwrap();

        let (result, matched) = acl.check_hostname_verbose("evil.com", 80);
        assert_eq!(result, PreCheckResult::Deny);
        assert_eq!(matched.unwrap(), "deny:evil.com:*");
    }

    #[test]
    fn test_check_hostname_verbose_defer() {
        let acl =
            ParsedAcl::from_config(AclPolicyConfig::Allow, &[], &["10.0.0.0/8:*".to_string()])
                .unwrap();

        let (result, matched) = acl.check_hostname_verbose("example.com", 80);
        assert_eq!(result, PreCheckResult::Defer);
        assert!(matched.is_none());
    }
}
