use crate::config::acl::AclPolicy;
use crate::shell::commands::CommandResult;
use crate::shell::context::ShellContext;

use super::colors::{color, GREEN, RED};

/// Test if a destination is allowed by ACL without actually connecting.
///
/// Usage: test <host:port>
pub fn run(args: &[String], ctx: &ShellContext) -> CommandResult {
    if !ctx.permissions.test_command {
        return CommandResult::output("Permission denied: test\r\n".to_string());
    }

    if args.is_empty() {
        return CommandResult::output("Usage: test <host:port>\r\n".to_string());
    }

    let target = &args[0];
    let (host, port) = match parse_host_port(target) {
        Some(hp) => hp,
        None => {
            return CommandResult::output(format!(
                "Invalid target '{}'. Expected format: host:port\r\n",
                target
            ));
        }
    };

    let (policy, matched_rule) = ctx.acl.check_verbose(host, port, None);
    let colors = ctx.colors;

    let result_str = match policy {
        AclPolicy::Allow => {
            let status = color(GREEN, "ALLOWED", colors);
            match matched_rule {
                Some(rule) => format!("{}:{} -> {} (rule: {})\r\n", host, port, status, rule),
                None => format!("{}:{} -> {} (default policy)\r\n", host, port, status),
            }
        }
        AclPolicy::Deny => {
            let status = color(RED, "DENIED", colors);
            match matched_rule {
                Some(rule) => format!("{}:{} -> {} (rule: {})\r\n", host, port, status, rule),
                None => format!("{}:{} -> {} (default policy)\r\n", host, port, status),
            }
        }
    };

    CommandResult::output(result_str)
}

/// Parse "host:port" into (&str, u16). Handles IPv6 bracket notation.
fn parse_host_port(input: &str) -> Option<(&str, u16)> {
    // Handle [ipv6]:port
    if input.starts_with('[') {
        let bracket_end = input.find(']')?;
        let host = &input[1..bracket_end];
        if bracket_end + 1 < input.len() && input.as_bytes()[bracket_end + 1] == b':' {
            let port: u16 = input[bracket_end + 2..].parse().ok()?;
            return Some((host, port));
        }
        return None;
    }

    // For normal host:port, find the last colon
    let colon_pos = input.rfind(':')?;
    let host = &input[..colon_pos];
    let port: u16 = input[colon_pos + 1..].parse().ok()?;
    if host.is_empty() {
        return None;
    }
    Some((host, port))
}

#[cfg(test)]
mod tests {
    use super::super::test_helpers::make_test_ctx;
    use super::*;
    use crate::config::acl::ParsedAcl;
    use crate::config::types::AclPolicyConfig;

    fn make_ctx() -> ShellContext {
        let mut ctx = make_test_ctx();
        ctx.acl = ParsedAcl::from_config(
            AclPolicyConfig::Deny,
            &["*.example.com:443".to_string()],
            &["evil.com:*".to_string()],
        )
        .unwrap();
        ctx
    }

    #[test]
    fn test_allowed_destination() {
        let ctx = make_ctx();
        let result = run(&["foo.example.com:443".to_string()], &ctx);
        assert!(result.output.contains("ALLOWED"));
        assert!(result.output.contains("allow:"));
    }

    #[test]
    fn test_denied_destination() {
        let ctx = make_ctx();
        let result = run(&["evil.com:80".to_string()], &ctx);
        assert!(result.output.contains("DENIED"));
        assert!(result.output.contains("deny:"));
    }

    #[test]
    fn test_default_policy_deny() {
        let ctx = make_ctx();
        let result = run(&["unknown.com:80".to_string()], &ctx);
        assert!(result.output.contains("DENIED"));
        assert!(result.output.contains("default policy"));
    }

    #[test]
    fn test_missing_arg() {
        let ctx = make_ctx();
        let result = run(&[], &ctx);
        assert!(result.output.contains("Usage:"));
    }

    #[test]
    fn test_invalid_format() {
        let ctx = make_ctx();
        let result = run(&["noporthere".to_string()], &ctx);
        assert!(result.output.contains("Invalid target"));
    }

    #[test]
    fn test_permission_denied() {
        let mut ctx = make_ctx();
        ctx.permissions.test_command = false;
        let result = run(&["foo:80".to_string()], &ctx);
        assert!(result.output.contains("Permission denied"));
    }

    #[test]
    fn test_parse_host_port_basic() {
        let (h, p) = parse_host_port("example.com:443").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 443);
    }

    #[test]
    fn test_parse_host_port_ipv6() {
        let (h, p) = parse_host_port("[::1]:8080").unwrap();
        assert_eq!(h, "::1");
        assert_eq!(p, 8080);
    }

    #[test]
    fn test_parse_host_port_invalid() {
        assert!(parse_host_port("no-port").is_none());
        assert!(parse_host_port(":80").is_none());
        assert!(parse_host_port("host:notaport").is_none());
    }
}
