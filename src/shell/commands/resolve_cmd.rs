use crate::shell::commands::CommandResult;
use crate::shell::context::ShellContext;
use std::net::ToSocketAddrs;

use super::colors::{color, CYAN, GREEN, RED};

/// DNS lookup showing all resolved IP addresses.
///
/// Usage: resolve <domain>
pub fn run(args: &[String], ctx: &ShellContext) -> CommandResult {
    if !ctx.permissions.resolve_command {
        return CommandResult::output("Permission denied: resolve\r\n".to_string());
    }

    if args.is_empty() {
        return CommandResult::output("Usage: resolve <domain>\r\n".to_string());
    }

    let domain = &args[0];
    let colors = ctx.colors;
    let mut output = String::new();

    output.push_str(&format!("Resolving {}...\r\n", color(CYAN, domain, colors)));

    // Use port 0 for pure DNS lookup
    let addr_str = format!("{}:0", domain);
    let start = std::time::Instant::now();
    match addr_str.to_socket_addrs() {
        Ok(addrs) => {
            let elapsed = start.elapsed();
            // Collect unique IPs (ToSocketAddrs may return duplicates)
            let mut ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
            ips.dedup();

            if ips.is_empty() {
                output.push_str(&format!("{}\r\n", color(RED, "No addresses found", colors)));
            } else {
                output.push_str(&format!(
                    "Resolved {} address(es) in {:.1}ms:\r\n",
                    ips.len(),
                    elapsed.as_secs_f64() * 1000.0
                ));
                for ip in &ips {
                    output.push_str(&format!("  {}\r\n", color(GREEN, ip, colors)));
                }
            }
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

#[cfg(test)]
mod tests {
    use super::super::test_helpers::make_test_ctx;
    use super::*;

    fn make_ctx() -> ShellContext {
        make_test_ctx()
    }

    #[test]
    fn test_resolve_missing_arg() {
        let ctx = make_ctx();
        let result = run(&[], &ctx);
        assert!(result.output.contains("Usage:"));
    }

    #[test]
    fn test_resolve_permission_denied() {
        let mut ctx = make_ctx();
        ctx.permissions.resolve_command = false;
        let result = run(&["example.com".to_string()], &ctx);
        assert!(result.output.contains("Permission denied"));
    }

    #[test]
    fn test_resolve_localhost() {
        let ctx = make_ctx();
        let result = run(&["localhost".to_string()], &ctx);
        assert!(result.output.contains("Resolving"));
        assert!(result.output.contains("Resolved") || result.output.contains("Resolution failed"));
    }

    #[test]
    fn test_resolve_invalid_domain() {
        let ctx = make_ctx();
        let result = run(
            &["this-domain-definitely-does-not-exist-xyzzy.invalid".to_string()],
            &ctx,
        );
        assert!(result.output.contains("Resolving"));
        // Should either fail or have no results
        assert!(result.output.contains("failed") || result.output.contains("No addresses"));
    }
}
