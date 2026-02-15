use crate::config::acl::AclPolicy;
use crate::shell::commands::CommandResult;
use crate::shell::context::ShellContext;
use crate::utils::format_bytes_used;

use super::colors::{color, BOLD, CYAN, GREEN, RED, YELLOW};

/// Check a permission flag and return early with "Permission denied" if false.
macro_rules! require_permission {
    ($ctx:expr, $field:ident, $name:expr) => {
        if !$ctx.permissions.$field {
            return CommandResult::output(
                concat!("Permission denied: show ", $name, "\r\n").to_string(),
            );
        }
    };
}

/// Format bits-per-second as a human-readable rate string.
fn format_rate(bps: u64) -> String {
    if bps >= 1_000_000 {
        format!("{:.1} Mbps", bps as f64 / 1_000_000.0)
    } else if bps >= 1_000 {
        format!("{:.1} Kbps", bps as f64 / 1_000.0)
    } else {
        format!("{} bps", bps)
    }
}

/// Route `show <subcommand>` to the correct handler.
pub fn run(args: &[String], ctx: &ShellContext) -> CommandResult {
    if args.is_empty() {
        return CommandResult::output(
            "Usage: show <connections|bandwidth|quota|acl|status|history|fingerprint>\r\n"
                .to_string(),
        );
    }

    match args[0].as_str() {
        "connections" | "conn" => show_connections(ctx),
        "bandwidth" | "bw" => show_bandwidth(ctx),
        "quota" | "quotas" => show_quota(ctx),
        "acl" => show_acl(ctx),
        "status" => show_status(ctx),
        "history" | "hist" => show_history(ctx),
        "fingerprint" | "fp" => show_fingerprint(ctx),
        other => CommandResult::output(format!(
            "show: unknown subcommand '{}'\r\nAvailable: connections, bandwidth, quota, acl, status, history, fingerprint\r\n",
            other
        )),
    }
}

fn show_connections(ctx: &ShellContext) -> CommandResult {
    require_permission!(ctx, show_connections, "connections");
    if let Some(ref pe) = ctx.proxy_engine {
        let count = pe.user_connections(&ctx.username);
        if count > 0 {
            CommandResult::output(format!("Active connections: {}\r\n", count))
        } else {
            CommandResult::output("No active proxy connections\r\n".to_string())
        }
    } else {
        CommandResult::output("No active proxy connections\r\n".to_string())
    }
}

fn show_bandwidth(ctx: &ShellContext) -> CommandResult {
    require_permission!(ctx, show_bandwidth, "bandwidth");
    let limit = if ctx.max_bandwidth_kbps == 0 {
        "unlimited".to_string()
    } else {
        format!("{} kbps", ctx.max_bandwidth_kbps)
    };

    if let Some(ref qt) = ctx.quota_tracker {
        let usage = qt.get_user_usage(&ctx.username);
        let mut output = String::from("Bandwidth usage:\r\n");
        output.push_str(&format!(
            "  Daily:    {} used\r\n",
            format_bytes_used(usage.daily_bytes)
        ));
        output.push_str(&format!(
            "  Monthly:  {} used\r\n",
            format_bytes_used(usage.monthly_bytes)
        ));
        output.push_str(&format!(
            "  Hourly:   {} used\r\n",
            format_bytes_used(usage.hourly_bytes)
        ));
        output.push_str(&format!(
            "  Rate:     {}\r\n",
            format_rate(usage.current_rate_bps * 8)
        ));
        output.push_str(&format!("  Limit:    {}\r\n", limit));
        CommandResult::output(output)
    } else {
        CommandResult::output(format!(
            "Upload: 0 B | Download: 0 B | Limit: {}\r\n",
            limit
        ))
    }
}

fn show_acl(ctx: &ShellContext) -> CommandResult {
    require_permission!(ctx, show_acl, "acl");

    let mut output = String::new();
    let colors = ctx.colors;

    // Default policy
    let policy_str = match ctx.acl.default_policy {
        AclPolicy::Allow => color(GREEN, "allow", colors),
        AclPolicy::Deny => color(RED, "deny", colors),
    };
    output.push_str(&format!(
        "{}  Default policy: {}\r\n",
        color(BOLD, "ACL Rules", colors),
        policy_str
    ));
    output.push_str("\r\n");

    // Deny rules
    if !ctx.acl.deny_rules.is_empty() {
        output.push_str(&format!("  {} rules:\r\n", color(RED, "Deny", colors)));
        for rule in &ctx.acl.deny_rules {
            output.push_str(&format!(
                "    {} {}\r\n",
                color(RED, "\u{2717}", colors),
                rule
            ));
        }
        output.push_str("\r\n");
    }

    // Allow rules
    if !ctx.acl.allow_rules.is_empty() {
        output.push_str(&format!("  {} rules:\r\n", color(GREEN, "Allow", colors)));
        for rule in &ctx.acl.allow_rules {
            output.push_str(&format!(
                "    {} {}\r\n",
                color(GREEN, "\u{2713}", colors),
                rule
            ));
        }
        output.push_str("\r\n");
    }

    if ctx.acl.deny_rules.is_empty() && ctx.acl.allow_rules.is_empty() {
        output.push_str("  No explicit rules configured.\r\n");
    }

    CommandResult::output(output)
}

fn show_status(ctx: &ShellContext) -> CommandResult {
    require_permission!(ctx, show_status, "status");

    let colors = ctx.colors;
    let mut output = String::new();

    output.push_str(&format!("{}\r\n", color(BOLD, "Session Status", colors)));
    output.push_str(&format!(
        "  User:        {}\r\n",
        color(CYAN, &ctx.username, colors)
    ));
    output.push_str(&format!("  Role:        {}\r\n", ctx.role));
    if let Some(ref group) = ctx.group {
        output.push_str(&format!("  Group:       {}\r\n", group));
    }
    output.push_str(&format!("  Auth:        {}\r\n", ctx.auth_method));
    output.push_str(&format!("  Source IP:   {}\r\n", ctx.source_ip));
    output.push_str(&format!("  Uptime:      {}\r\n", ctx.uptime()));

    // Live connections from proxy engine
    let conn_count = ctx
        .proxy_engine
        .as_ref()
        .map(|pe| pe.user_connections(&ctx.username))
        .unwrap_or(0);
    output.push_str(&format!("  Connections: {} active\r\n", conn_count));

    // Expiry
    match &ctx.expires_at {
        Some(exp) => {
            output.push_str(&format!(
                "  Expires:     {}\r\n",
                color(YELLOW, exp, colors)
            ));
        }
        None => {
            output.push_str("  Expires:     never\r\n");
        }
    }

    // Rate limit / bandwidth
    if ctx.max_bandwidth_kbps > 0 {
        output.push_str(&format!(
            "  Rate limit:  {} kbps\r\n",
            ctx.max_bandwidth_kbps
        ));
    } else {
        output.push_str("  Rate limit:  unlimited\r\n");
    }

    CommandResult::output(output)
}

fn show_history(ctx: &ShellContext) -> CommandResult {
    require_permission!(ctx, show_history, "history");
    if let Some(ref qt) = ctx.quota_tracker {
        let usage = qt.get_user_usage(&ctx.username);
        let mut output = String::from("Connection summary:\r\n");
        output.push_str(&format!(
            "  Today:      {} connections, {} transferred\r\n",
            usage.daily_connections,
            format_bytes_used(usage.daily_bytes)
        ));
        output.push_str(&format!(
            "  This month: {} connections, {} transferred\r\n",
            usage.monthly_connections,
            format_bytes_used(usage.monthly_bytes)
        ));
        CommandResult::output(output)
    } else {
        CommandResult::output("No connection history available\r\n".to_string())
    }
}

fn show_quota(ctx: &ShellContext) -> CommandResult {
    require_permission!(ctx, show_quota, "quota");

    let usage = ctx
        .quota_tracker
        .as_ref()
        .map(|qt| qt.get_user_usage(&ctx.username));
    let config = ctx.quota_config.as_ref();

    let mut output = String::from("Quota usage:\r\n");

    // Bandwidth section
    output.push_str("  Bandwidth:\r\n");

    // Hourly
    let hourly_used = usage.as_ref().map_or(0, |u| u.hourly_bytes);
    let hourly_limit = config.map_or(0, |c| c.bandwidth_per_hour_bytes);
    output.push_str(&format!(
        "    Hourly:    {} / {}\r\n",
        format_bytes_used(hourly_used),
        format_limit(hourly_limit)
    ));

    // Daily
    let daily_used = usage.as_ref().map_or(0, |u| u.daily_bytes);
    let daily_limit = config.map_or(0, |c| c.daily_bandwidth_bytes);
    output.push_str(&format!(
        "    Daily:     {} / {}\r\n",
        format_bytes_used(daily_used),
        format_limit(daily_limit)
    ));

    // Monthly
    let monthly_used = usage.as_ref().map_or(0, |u| u.monthly_bytes);
    let monthly_limit = config.map_or(0, |c| c.monthly_bandwidth_bytes);
    output.push_str(&format!(
        "    Monthly:   {} / {}\r\n",
        format_bytes_used(monthly_used),
        format_limit(monthly_limit)
    ));

    // Total
    let total_used = usage.as_ref().map_or(0, |u| u.total_bytes);
    let total_limit = config.map_or(0, |c| c.total_bandwidth_bytes);
    output.push_str(&format!(
        "    Total:     {} / {}\r\n",
        format_bytes_used(total_used),
        format_limit(total_limit)
    ));

    // Connections section
    output.push_str("  Connections:\r\n");

    let daily_conn = usage.as_ref().map_or(0, |u| u.daily_connections);
    let daily_conn_limit = config.map_or(0, |c| c.daily_connection_limit);
    output.push_str(&format!(
        "    Daily:     {} / {}\r\n",
        daily_conn,
        format_conn_limit(daily_conn_limit)
    ));

    let monthly_conn = usage.as_ref().map_or(0, |u| u.monthly_connections);
    let monthly_conn_limit = config.map_or(0, |c| c.monthly_connection_limit);
    output.push_str(&format!(
        "    Monthly:   {} / {}\r\n",
        monthly_conn,
        format_conn_limit(monthly_conn_limit)
    ));

    // Rate limit
    if ctx.max_bandwidth_kbps > 0 {
        output.push_str(&format!(
            "  Rate limit:  {} kbps\r\n",
            ctx.max_bandwidth_kbps
        ));
    } else {
        output.push_str("  Rate limit:  unlimited\r\n");
    }

    CommandResult::output(output)
}

/// Format a byte limit: 0 means unlimited.
fn format_limit(limit: u64) -> String {
    if limit == 0 {
        "unlimited".to_string()
    } else {
        format_bytes_used(limit)
    }
}

/// Format a connection limit: 0 means unlimited.
fn format_conn_limit(limit: u32) -> String {
    if limit == 0 {
        "unlimited".to_string()
    } else {
        limit.to_string()
    }
}

fn show_fingerprint(ctx: &ShellContext) -> CommandResult {
    require_permission!(ctx, show_fingerprint, "fingerprint");
    match &ctx.ssh_key_fingerprint {
        Some(fp) => CommandResult::output(format!("SSH key fingerprint: {}\r\n", fp)),
        None => CommandResult::output("No key fingerprint available\r\n".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_helpers::make_test_ctx;
    use super::*;
    use crate::config::acl::ParsedAcl;
    use crate::config::types::{AclPolicyConfig, LimitsConfig};
    use crate::proxy::ProxyEngine;
    use crate::quota::QuotaTracker;
    use crate::utils::format_bytes_used;
    use std::sync::Arc;

    fn make_ctx() -> ShellContext {
        let mut ctx = make_test_ctx();
        ctx.acl = ParsedAcl::from_config(
            AclPolicyConfig::Allow,
            &["*.example.com:443".to_string()],
            &["10.0.0.0/8:*".to_string()],
        )
        .unwrap();
        ctx.source_ip = "192.168.1.100".to_string();
        ctx.group = Some("developers".to_string());
        ctx.expires_at = Some("2026-12-31".to_string());
        ctx.max_bandwidth_kbps = 1024;
        ctx.ssh_key_fingerprint = Some("SHA256:abc123".to_string());
        ctx
    }

    #[test]
    fn test_show_connections() {
        let ctx = make_ctx();
        let result = run(&["connections".to_string()], &ctx);
        assert!(result.output.contains("No active proxy connections"));
    }

    #[test]
    fn test_show_bandwidth() {
        let ctx = make_ctx();
        let result = run(&["bandwidth".to_string()], &ctx);
        assert!(result.output.contains("1024 kbps"));
    }

    #[test]
    fn test_show_bandwidth_unlimited() {
        let mut ctx = make_ctx();
        ctx.max_bandwidth_kbps = 0;
        let result = run(&["bandwidth".to_string()], &ctx);
        assert!(result.output.contains("unlimited"));
    }

    #[test]
    fn test_show_acl() {
        let ctx = make_ctx();
        let result = run(&["acl".to_string()], &ctx);
        assert!(result.output.contains("Default policy:"));
        assert!(result.output.contains("Deny"));
        assert!(result.output.contains("Allow"));
    }

    #[test]
    fn test_show_status() {
        let ctx = make_ctx();
        let result = run(&["status".to_string()], &ctx);
        assert!(result.output.contains("testuser"));
        assert!(result.output.contains("password"));
        assert!(result.output.contains("192.168.1.100"));
        assert!(result.output.contains("2026-12-31"));
    }

    #[test]
    fn test_show_history() {
        let ctx = make_ctx();
        let result = run(&["history".to_string()], &ctx);
        assert!(result.output.contains("No connection history"));
    }

    #[test]
    fn test_show_fingerprint() {
        let ctx = make_ctx();
        let result = run(&["fingerprint".to_string()], &ctx);
        assert!(result.output.contains("SHA256:abc123"));
    }

    #[test]
    fn test_show_fingerprint_none() {
        let mut ctx = make_ctx();
        ctx.ssh_key_fingerprint = None;
        let result = run(&["fingerprint".to_string()], &ctx);
        assert!(result.output.contains("No key fingerprint"));
    }

    #[test]
    fn test_show_no_subcommand() {
        let ctx = make_ctx();
        let result = run(&[], &ctx);
        assert!(result.output.contains("Usage:"));
    }

    #[test]
    fn test_show_unknown_subcommand() {
        let ctx = make_ctx();
        let result = run(&["unknown".to_string()], &ctx);
        assert!(result.output.contains("unknown subcommand"));
    }

    #[test]
    fn test_show_permission_denied() {
        let mut ctx = make_ctx();
        ctx.permissions.show_connections = false;
        let result = run(&["connections".to_string()], &ctx);
        assert!(result.output.contains("Permission denied"));
    }

    #[test]
    fn test_show_bandwidth_with_quota_data() {
        let limits = LimitsConfig::default();
        let qt = Arc::new(QuotaTracker::new(&limits));
        qt.record_bytes("testuser", 1_048_576, 0, 0, None); // 1 MB
        qt.record_connection("testuser", None).unwrap();

        let mut ctx = make_ctx();
        ctx.quota_tracker = Some(qt);

        let result = run(&["bandwidth".to_string()], &ctx);
        assert!(result.output.contains("Daily:"));
        assert!(result.output.contains("Monthly:"));
        assert!(result.output.contains("Hourly:"));
        assert!(result.output.contains("Rate:"));
        assert!(result.output.contains("1.0 MB used"));
    }

    #[test]
    fn test_show_bandwidth_without_tracker() {
        let ctx = make_ctx();
        let result = run(&["bandwidth".to_string()], &ctx);
        assert!(result.output.contains("Upload: 0 B"));
        assert!(result.output.contains("Download: 0 B"));
    }

    fn test_config() -> crate::config::types::AppConfig {
        toml::from_str(
            r##"
[server]
ssh_listen = "127.0.0.1:0"
"##,
        )
        .unwrap()
    }

    #[test]
    fn test_show_connections_with_proxy() {
        let config = Arc::new(test_config());
        let audit = Arc::new(crate::audit::AuditLogger::new_noop());
        let pe = Arc::new(ProxyEngine::new(config, audit));
        let _guard = pe.acquire_connection("testuser", 0).unwrap();

        let mut ctx = make_ctx();
        ctx.proxy_engine = Some(pe);

        let result = run(&["connections".to_string()], &ctx);
        assert!(result.output.contains("Active connections: 1"));
    }

    #[test]
    fn test_show_connections_zero() {
        let config = Arc::new(test_config());
        let audit = Arc::new(crate::audit::AuditLogger::new_noop());
        let pe = Arc::new(ProxyEngine::new(config, audit));

        let mut ctx = make_ctx();
        ctx.proxy_engine = Some(pe);

        let result = run(&["connections".to_string()], &ctx);
        assert!(result.output.contains("No active proxy connections"));
    }

    #[test]
    fn test_show_status_with_live_data() {
        let config = Arc::new(test_config());
        let audit = Arc::new(crate::audit::AuditLogger::new_noop());
        let pe = Arc::new(ProxyEngine::new(config, audit));
        let _guard = pe.acquire_connection("testuser", 0).unwrap();

        let mut ctx = make_ctx();
        ctx.proxy_engine = Some(pe);
        ctx.auth_method = "publickey".to_string();

        let result = run(&["status".to_string()], &ctx);
        assert!(result.output.contains("Auth:        publickey"));
        assert!(result.output.contains("Connections: 1 active"));
    }

    #[test]
    fn test_show_history_with_quota_data() {
        let limits = LimitsConfig::default();
        let qt = Arc::new(QuotaTracker::new(&limits));
        qt.record_connection("testuser", None).unwrap();
        qt.record_connection("testuser", None).unwrap();
        qt.record_bytes("testuser", 2_097_152, 0, 0, None); // 2 MB

        let mut ctx = make_ctx();
        ctx.quota_tracker = Some(qt);

        let result = run(&["history".to_string()], &ctx);
        assert!(result.output.contains("Today:"));
        assert!(result.output.contains("2 connections"));
        assert!(result.output.contains("2.0 MB transferred"));
        assert!(result.output.contains("This month:"));
    }

    #[test]
    fn test_show_history_without_tracker() {
        let ctx = make_ctx();
        let result = run(&["history".to_string()], &ctx);
        assert!(result.output.contains("No connection history available"));
    }

    #[test]
    fn test_format_bytes_values() {
        assert_eq!(format_bytes_used(0), "0 B");
        assert_eq!(format_bytes_used(512), "512 B");
        assert_eq!(format_bytes_used(1024), "1.0 KB");
        assert_eq!(format_bytes_used(1_048_576), "1.0 MB");
        assert_eq!(format_bytes_used(1_073_741_824), "1.0 GB");
    }

    #[test]
    fn test_format_rate_values() {
        assert_eq!(format_rate(0), "0 bps");
        assert_eq!(format_rate(500), "500 bps");
        assert_eq!(format_rate(1_500), "1.5 Kbps");
        assert_eq!(format_rate(10_000_000), "10.0 Mbps");
    }

    #[test]
    fn test_show_quota_no_tracker_no_config() {
        let ctx = make_ctx();
        let result = run(&["quota".to_string()], &ctx);
        assert!(result.output.contains("Quota usage:"));
        assert!(result.output.contains("Bandwidth:"));
        assert!(result.output.contains("Connections:"));
        assert!(result.output.contains("unlimited"));
    }

    #[test]
    fn test_show_quota_with_config_and_tracker() {
        use crate::config::types::QuotaConfig;

        let limits = LimitsConfig::default();
        let qt = Arc::new(QuotaTracker::new(&limits));
        qt.record_bytes("testuser", 1_073_741_824, 0, 0, None); // 1 GB
        qt.record_connection("testuser", None).unwrap();
        qt.record_connection("testuser", None).unwrap();

        let mut ctx = make_ctx();
        ctx.quota_tracker = Some(qt);
        ctx.quota_config = Some(QuotaConfig {
            daily_bandwidth_bytes: 5_368_709_120,    // 5 GB
            monthly_bandwidth_bytes: 53_687_091_200, // 50 GB
            bandwidth_per_hour_bytes: 1_073_741_824, // 1 GB
            total_bandwidth_bytes: 0,                // unlimited
            daily_connection_limit: 100,
            monthly_connection_limit: 1000,
        });

        let result = run(&["quota".to_string()], &ctx);
        assert!(
            result.output.contains("1.0 GB / 1.0 GB"),
            "hourly: {}",
            result.output
        );
        assert!(
            result.output.contains("1.0 GB / 5.0 GB"),
            "daily: {}",
            result.output
        );
        assert!(
            result.output.contains("1.0 GB / 50.0 GB"),
            "monthly: {}",
            result.output
        );
        assert!(
            result.output.contains("1.0 GB / unlimited"),
            "total: {}",
            result.output
        );
        assert!(
            result.output.contains("2 / 100"),
            "daily conn: {}",
            result.output
        );
        assert!(
            result.output.contains("2 / 1000"),
            "monthly conn: {}",
            result.output
        );
    }

    #[test]
    fn test_show_quota_aliases() {
        let ctx = make_ctx();
        let result = run(&["quotas".to_string()], &ctx);
        assert!(result.output.contains("Quota usage:"));
    }

    #[test]
    fn test_show_quota_permission_denied() {
        let mut ctx = make_ctx();
        ctx.permissions.show_quota = false;
        let result = run(&["quota".to_string()], &ctx);
        assert!(result.output.contains("Permission denied"));
    }

    #[test]
    fn test_show_quota_rate_limit_display() {
        let mut ctx = make_ctx();
        ctx.max_bandwidth_kbps = 2048;
        let result = run(&["quota".to_string()], &ctx);
        assert!(result.output.contains("Rate limit:  2048 kbps"));
    }
}
