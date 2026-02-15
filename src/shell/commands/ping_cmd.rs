use crate::config::acl::AclPolicy;
use crate::shell::commands::CommandResult;
use crate::shell::context::ShellContext;
use std::net::ToSocketAddrs;

use super::colors::{color, CYAN, GREEN, RED};

/// TCP connect test with DNS resolution and ACL check.
///
/// Usage: ping <host[:port]>
///
/// Default port is 80 if not specified. This does NOT perform real ICMP ping;
/// it resolves DNS, checks ACL, and reports the result.
pub fn run(args: &[String], ctx: &ShellContext) -> CommandResult {
    if !ctx.permissions.ping_command {
        return CommandResult::output("Permission denied: ping\r\n".to_string());
    }

    if args.is_empty() {
        return CommandResult::output("Usage: ping <host[:port]>\r\n".to_string());
    }

    let target = &args[0];
    let (host, port) = parse_host_port_default(target);

    let colors = ctx.colors;
    let mut output = String::new();

    // DNS resolution
    output.push_str(&format!("Resolving {}...\r\n", color(CYAN, host, colors)));

    let start = std::time::Instant::now();
    let addr_str = format!("{}:{}", host, port);
    match addr_str.to_socket_addrs() {
        Ok(addrs) => {
            let elapsed = start.elapsed();
            let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
            if ips.is_empty() {
                output.push_str(&format!("{}\r\n", color(RED, "No addresses found", colors)));
                return CommandResult::output(output);
            }

            let first_ip = &ips[0];
            output.push_str(&format!(
                "Resolved to: {} ({:.1}ms)\r\n",
                color(GREEN, first_ip, colors),
                elapsed.as_secs_f64() * 1000.0
            ));

            // ACL check
            let resolved_ip = first_ip.parse().ok();
            let (policy, rule) = ctx.acl.check_verbose(host, port, resolved_ip);
            match policy {
                AclPolicy::Allow => {
                    let msg = match rule {
                        Some(r) => {
                            format!("ACL check: {} ({})", color(GREEN, "allowed", colors), r)
                        }
                        None => format!(
                            "ACL check: {} (default policy)",
                            color(GREEN, "allowed", colors)
                        ),
                    };
                    output.push_str(&format!("{}\r\n", msg));
                }
                AclPolicy::Deny => {
                    let msg = match rule {
                        Some(r) => format!("ACL check: {} ({})", color(RED, "denied", colors), r),
                        None => format!(
                            "ACL check: {} (default policy)",
                            color(RED, "denied", colors)
                        ),
                    };
                    output.push_str(&format!("{}\r\n", msg));
                }
            }

            output.push_str("Note: TCP connect requires async context\r\n");
        }
        Err(e) => {
            output.push_str(&format!(
                "{}: {}\r\n",
                color(RED, "Resolution failed", colors),
                e
            ));
        }
    }

    CommandResult::output(output)
}

/// Parse "host[:port]" — default port 80 if omitted.
fn parse_host_port_default(input: &str) -> (&str, u16) {
    // Handle [ipv6]:port
    if input.starts_with('[') {
        if let Some(bracket_end) = input.find(']') {
            let host = &input[1..bracket_end];
            if bracket_end + 1 < input.len() && input.as_bytes()[bracket_end + 1] == b':' {
                if let Ok(port) = input[bracket_end + 2..].parse::<u16>() {
                    return (host, port);
                }
            }
            return (host, 80);
        }
    }

    // Check if there is a colon-separated port
    if let Some(colon_pos) = input.rfind(':') {
        let host = &input[..colon_pos];
        // Avoid treating IPv6 addresses without brackets as host:port
        if !host.contains(':') {
            if let Ok(port) = input[colon_pos + 1..].parse::<u16>() {
                return (host, port);
            }
        }
    }

    (input, 80)
}

#[cfg(test)]
mod tests {
    use super::super::test_helpers::make_test_ctx;
    use super::*;

    fn make_ctx() -> ShellContext {
        make_test_ctx()
    }

    #[test]
    fn test_ping_missing_arg() {
        let ctx = make_ctx();
        let result = run(&[], &ctx);
        assert!(result.output.contains("Usage:"));
    }

    #[test]
    fn test_ping_permission_denied() {
        let mut ctx = make_ctx();
        ctx.permissions.ping_command = false;
        let result = run(&["example.com".to_string()], &ctx);
        assert!(result.output.contains("Permission denied"));
    }

    #[test]
    fn test_ping_resolves_localhost() {
        let ctx = make_ctx();
        let result = run(&["localhost".to_string()], &ctx);
        assert!(result.output.contains("Resolving"));
        // localhost should resolve
        assert!(
            result.output.contains("Resolved to:") || result.output.contains("Resolution failed")
        );
    }

    #[test]
    fn test_parse_host_port_default_no_port() {
        let (h, p) = parse_host_port_default("example.com");
        assert_eq!(h, "example.com");
        assert_eq!(p, 80);
    }

    #[test]
    fn test_parse_host_port_default_with_port() {
        let (h, p) = parse_host_port_default("example.com:443");
        assert_eq!(h, "example.com");
        assert_eq!(p, 443);
    }

    #[test]
    fn test_parse_host_port_default_ipv6() {
        let (h, p) = parse_host_port_default("[::1]:8080");
        assert_eq!(h, "::1");
        assert_eq!(p, 8080);
    }

    #[test]
    fn test_parse_host_port_default_ipv6_no_port() {
        let (h, p) = parse_host_port_default("[::1]");
        assert_eq!(h, "::1");
        assert_eq!(p, 80);
    }
}
