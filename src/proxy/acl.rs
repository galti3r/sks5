use crate::config::acl::{ParsedAcl, PreCheckResult};
use std::net::IpAddr;
use tracing::{info, warn};

/// Result of an ACL check with the matched rule information
pub struct AclDecision {
    pub allowed: bool,
    pub matched_rule: Option<String>,
}

/// Pre-check ACL using hostname only (before DNS/connect).
/// Returns AclDecision with matched_rule info.
pub fn pre_check_hostname_and_log(
    acl: &ParsedAcl,
    username: &str,
    host: &str,
    port: u16,
) -> AclDecision {
    let (result, matched_rule) = acl.check_hostname_verbose(host, port);
    match result {
        PreCheckResult::Deny => {
            warn!(
                user = %username,
                target = %format!("{}:{}", host, port),
                matched_rule = ?matched_rule,
                reason = "hostname pre-check",
                "ACL: denied (hostname pre-check)"
            );
            AclDecision {
                allowed: false,
                matched_rule,
            }
        }
        PreCheckResult::Allow | PreCheckResult::Defer => AclDecision {
            allowed: true,
            matched_rule,
        },
    }
}

/// Check ACL and log the decision, with resolved IP and matched rule info.
pub fn check_and_log(
    acl: &ParsedAcl,
    username: &str,
    host: &str,
    port: u16,
    resolved_ip: Option<IpAddr>,
) -> AclDecision {
    let (policy, matched_rule) = acl.check_verbose(host, port, resolved_ip);
    let resolved_str = resolved_ip.map(|ip| ip.to_string());

    match policy {
        crate::config::acl::AclPolicy::Allow => {
            info!(
                user = %username,
                target = %format!("{}:{}", host, port),
                resolved_ip = ?resolved_str,
                matched_rule = ?matched_rule,
                reason = "post-check",
                "ACL: allowed"
            );
            AclDecision {
                allowed: true,
                matched_rule,
            }
        }
        crate::config::acl::AclPolicy::Deny => {
            warn!(
                user = %username,
                target = %format!("{}:{}", host, port),
                resolved_ip = ?resolved_str,
                matched_rule = ?matched_rule,
                reason = "post-check",
                "ACL: denied"
            );
            AclDecision {
                allowed: false,
                matched_rule,
            }
        }
    }
}
