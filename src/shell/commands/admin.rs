use std::net::IpAddr;
use std::sync::atomic::Ordering;

use crate::shell::commands::CommandResult;
use crate::shell::context::ShellContext;
use crate::utils::{format_bytes_used, format_duration};

use super::colors::{color, BOLD, GREEN, RED, YELLOW};
use super::show::format_rate;

macro_rules! require_admin {
    ($ctx:expr) => {
        if !$ctx.role.is_admin() {
            return CommandResult::output(
                "Permission denied: admin commands require role = \"admin\"\r\n",
            );
        }
    };
}

pub fn run(args: &[String], ctx: &ShellContext) -> CommandResult {
    require_admin!(ctx);

    if args.is_empty() {
        return CommandResult::output(
            "Usage: admin <server|users|sessions|bans|user <name>|unban <ip>|kick <user>|quota reset <user>>\r\n",
        );
    }

    match args[0].as_str() {
        "server" => admin_server(ctx),
        "users" => admin_users(ctx),
        "sessions" => admin_sessions(ctx),
        "bans" => admin_bans(ctx),
        "user" => admin_user_detail(&args[1..], ctx),
        "unban" => admin_unban(&args[1..], ctx),
        "kick" => admin_kick(&args[1..], ctx),
        "quota" => admin_quota(&args[1..], ctx),
        other => CommandResult::output(format!(
            "admin: unknown subcommand '{}'\r\nAvailable: server, users, sessions, bans, user, unban, kick, quota\r\n",
            other
        )),
    }
}

fn admin_server(ctx: &ShellContext) -> CommandResult {
    let colors = ctx.colors;
    let mut out = String::new();
    out.push_str(&format!("{}\r\n", color(BOLD, "Server Overview", colors)));

    // Uptime
    out.push_str(&format!("  Uptime:          {}\r\n", ctx.uptime()));

    // Version
    out.push_str(&format!(
        "  Version:         {}\r\n",
        env!("CARGO_PKG_VERSION")
    ));

    // Active connections
    if let Some(ref pe) = ctx.proxy_engine {
        out.push_str(&format!(
            "  Connections:     {} active\r\n",
            pe.active_connections()
        ));
    }

    // Users online / configured
    if let Some(ref pe) = ctx.proxy_engine {
        let online = pe.active_connection_details().len();
        if let Some(ref auth) = ctx.auth_service {
            if let Ok(auth) = auth.try_read() {
                let total = auth.user_store().len();
                out.push_str(&format!(
                    "  Users:           {} online / {} configured\r\n",
                    online, total
                ));
            }
        }
    }

    // Banned IPs
    if let Some(ref sec) = ctx.security {
        if let Ok(sec) = sec.try_read() {
            let banned = sec.ban_manager().banned_ips().len();
            out.push_str(&format!("  Banned IPs:      {}\r\n", banned));
        }
    }

    // Maintenance status
    if let Some(ref maint) = ctx.maintenance {
        let status = if maint.load(Ordering::Relaxed) {
            color(YELLOW, "ON", colors)
        } else {
            color(GREEN, "off", colors)
        };
        out.push_str(&format!("  Maintenance:     {}\r\n", status));
    }

    // Config info
    if let Some(ref cfg) = ctx.server_config {
        out.push_str(&format!(
            "  Max connections: {}\r\n",
            cfg.limits.max_connections
        ));
        if cfg.limits.max_bandwidth_mbps > 0 {
            out.push_str(&format!(
                "  Bandwidth cap:   {} Mbps\r\n",
                cfg.limits.max_bandwidth_mbps
            ));
        } else {
            out.push_str("  Bandwidth cap:   unlimited\r\n");
        }
    }

    CommandResult::output(out)
}

fn admin_users(ctx: &ShellContext) -> CommandResult {
    let auth = match ctx.auth_service.as_ref().and_then(|a| a.try_read().ok()) {
        Some(a) => a,
        None => return CommandResult::output("Server busy, try again\r\n"),
    };

    let colors = ctx.colors;
    let mut out = String::new();
    out.push_str(&format!(
        "{}\r\n\r\n",
        color(BOLD, "Configured Users", colors)
    ));

    // Header
    out.push_str(&format!(
        "  {:<16} {:<8} {:<12} {:<6} {:<12} {}\r\n",
        "USER", "ROLE", "GROUP", "CONNS", "DAILY BW", "STATUS"
    ));
    out.push_str(&format!("  {}\r\n", "-".repeat(70)));

    let store = auth.user_store();
    let mut usernames = store.usernames();
    usernames.sort();

    for uname in &usernames {
        if let Some(user) = store.get(uname) {
            let conns = ctx
                .proxy_engine
                .as_ref()
                .map(|pe| pe.user_connections(uname))
                .unwrap_or(0);

            let daily_bw = ctx
                .quota_tracker
                .as_ref()
                .map(|qt| format_bytes_used(qt.get_user_usage(uname).daily_bytes))
                .unwrap_or_else(|| "-".to_string());

            let group = user.group.as_deref().unwrap_or("-");

            let status = if user.is_expired() {
                color(RED, "expired", colors)
            } else if conns > 0 {
                color(GREEN, "active", colors)
            } else {
                "idle".to_string()
            };

            out.push_str(&format!(
                "  {:<16} {:<8} {:<12} {:<6} {:<12} {}\r\n",
                uname, user.role, group, conns, daily_bw, status
            ));
        }
    }

    out.push_str(&format!("\r\n  Total: {} users\r\n", usernames.len()));

    CommandResult::output(out)
}

fn admin_sessions(ctx: &ShellContext) -> CommandResult {
    let sessions = match ctx.proxy_engine.as_ref() {
        Some(pe) => pe.get_sessions(),
        None => return CommandResult::output("No active sessions\r\n"),
    };

    if sessions.is_empty() {
        return CommandResult::output("No active sessions\r\n");
    }

    let colors = ctx.colors;
    let mut out = String::new();
    out.push_str(&format!(
        "{}\r\n\r\n",
        color(BOLD, "Active Sessions", colors)
    ));

    out.push_str(&format!(
        "  {:<14} {:<24} {:<16} {:<10} {}\r\n",
        "USER", "TARGET", "SOURCE IP", "DURATION", "TRANSFER"
    ));
    out.push_str(&format!("  {}\r\n", "-".repeat(76)));

    let now = chrono::Utc::now();
    for s in &sessions {
        let duration = now.signed_duration_since(s.started_at).num_seconds().max(0) as u64;
        let dur_str = format_duration(duration);
        let target = format!("{}:{}", s.target_host, s.target_port);
        let transfer = format!(
            "{} / {}",
            format_bytes_used(s.bytes_up),
            format_bytes_used(s.bytes_down)
        );

        out.push_str(&format!(
            "  {:<14} {:<24} {:<16} {:<10} {}\r\n",
            s.username, target, s.source_ip, dur_str, transfer
        ));
    }

    out.push_str(&format!("\r\n  Total: {} sessions\r\n", sessions.len()));

    CommandResult::output(out)
}

fn admin_bans(ctx: &ShellContext) -> CommandResult {
    let sec = match ctx.security.as_ref().and_then(|s| s.try_read().ok()) {
        Some(s) => s,
        None => return CommandResult::output("Server busy, try again\r\n"),
    };

    let bans = sec.ban_manager().banned_ips();
    if bans.is_empty() {
        return CommandResult::output("No banned IPs\r\n");
    }

    let colors = ctx.colors;
    let mut out = String::new();
    out.push_str(&format!("{}\r\n\r\n", color(BOLD, "Banned IPs", colors)));
    out.push_str(&format!("  {:<40} {}\r\n", "IP", "REMAINING"));
    out.push_str(&format!("  {}\r\n", "-".repeat(52)));

    let now = std::time::Instant::now();
    for (ip, expiry) in &bans {
        let remaining = if *expiry > now {
            format_duration((*expiry - now).as_secs())
        } else {
            "expiring".to_string()
        };
        out.push_str(&format!(
            "  {:<40} {}\r\n",
            color(RED, &ip.to_string(), colors),
            remaining
        ));
    }

    out.push_str(&format!("\r\n  Total: {} banned\r\n", bans.len()));

    CommandResult::output(out)
}

fn admin_user_detail(args: &[String], ctx: &ShellContext) -> CommandResult {
    if args.is_empty() {
        return CommandResult::output("Usage: admin user <username>\r\n");
    }

    let target = &args[0];
    let auth = match ctx.auth_service.as_ref().and_then(|a| a.try_read().ok()) {
        Some(a) => a,
        None => return CommandResult::output("Server busy, try again\r\n"),
    };

    let user = match auth.user_store().get(target) {
        Some(u) => u.clone(),
        None => return CommandResult::output(format!("User not found: {}\r\n", target)),
    };

    let colors = ctx.colors;
    let mut out = String::new();
    out.push_str(&format!(
        "{}\r\n",
        color(BOLD, &format!("User: {}", target), colors)
    ));
    out.push_str(&format!("  Role:           {}\r\n", user.role));
    out.push_str(&format!(
        "  Group:          {}\r\n",
        user.group.as_deref().unwrap_or("none")
    ));
    out.push_str(&format!("  Shell:          {}\r\n", user.allow_shell));

    // Auth methods
    let has_password = user.password_hash.is_some();
    let key_count = user.authorized_keys.len();
    let mut auth_methods = Vec::new();
    if has_password {
        auth_methods.push("password".to_string());
    }
    if key_count > 0 {
        auth_methods.push(format!("pubkey ({} keys)", key_count));
    }
    if user.totp_enabled {
        auth_methods.push("totp".to_string());
    }
    out.push_str(&format!(
        "  Auth:           {}\r\n",
        if auth_methods.is_empty() {
            "none".to_string()
        } else {
            auth_methods.join(", ")
        }
    ));

    // Expiry
    match user.expires_at {
        Some(dt) => {
            let status = if user.is_expired() {
                color(RED, "EXPIRED", colors)
            } else {
                color(GREEN, "active", colors)
            };
            out.push_str(&format!(
                "  Expires:        {} ({})\r\n",
                dt.to_rfc3339(),
                status
            ));
        }
        None => out.push_str("  Expires:        never\r\n"),
    }

    // Bandwidth limit
    if user.max_bandwidth_kbps > 0 {
        out.push_str(&format!(
            "  BW limit:       {} kbps\r\n",
            user.max_bandwidth_kbps
        ));
    } else {
        out.push_str("  BW limit:       unlimited\r\n");
    }

    // Connection limit
    if user.max_connections > 0 {
        out.push_str(&format!("  Max conns:      {}\r\n", user.max_connections));
    } else {
        out.push_str("  Max conns:      unlimited\r\n");
    }

    // Live data
    let conns = ctx
        .proxy_engine
        .as_ref()
        .map(|pe| pe.user_connections(target))
        .unwrap_or(0);
    out.push_str(&format!("  Active conns:   {}\r\n", conns));

    if let Some(ref qt) = ctx.quota_tracker {
        let usage = qt.get_user_usage(target);
        out.push_str(&format!(
            "  Daily BW:       {}\r\n",
            format_bytes_used(usage.daily_bytes)
        ));
        out.push_str(&format!(
            "  Monthly BW:     {}\r\n",
            format_bytes_used(usage.monthly_bytes)
        ));
        out.push_str(&format!(
            "  Current rate:   {}\r\n",
            format_rate(usage.current_rate_bps * 8)
        ));
    }

    CommandResult::output(out)
}

fn admin_unban(args: &[String], ctx: &ShellContext) -> CommandResult {
    if args.is_empty() {
        return CommandResult::output("Usage: admin unban <ip>\r\n");
    }

    let ip: IpAddr = match args[0].parse() {
        Ok(ip) => ip,
        Err(_) => return CommandResult::output(format!("Invalid IP address: {}\r\n", args[0])),
    };

    let sec = match ctx.security.as_ref().and_then(|s| s.try_read().ok()) {
        Some(s) => s,
        None => return CommandResult::output("Server busy, try again\r\n"),
    };

    if sec.ban_manager().unban(&ip) {
        CommandResult::output(format!("Unbanned {}\r\n", ip))
    } else {
        CommandResult::output(format!("{} is not currently banned\r\n", ip))
    }
}

fn admin_kick(args: &[String], ctx: &ShellContext) -> CommandResult {
    if args.is_empty() {
        return CommandResult::output("Usage: admin kick <username>\r\n");
    }

    let target = &args[0];
    let tokens = match ctx.kick_tokens.as_ref() {
        Some(kt) => kt,
        None => return CommandResult::output("Kick registry not available\r\n"),
    };

    match tokens.get(target) {
        Some(user_tokens) if !user_tokens.is_empty() => {
            let count = user_tokens.len();
            for token in user_tokens.iter() {
                token.cancel();
            }
            CommandResult::output(format!(
                "Kicked {} ({} sessions cancelled)\r\n",
                target, count
            ))
        }
        _ => CommandResult::output(format!("No active sessions for user '{}'\r\n", target)),
    }
}

fn admin_quota(args: &[String], ctx: &ShellContext) -> CommandResult {
    if args.len() < 2 || args[0] != "reset" {
        return CommandResult::output("Usage: admin quota reset <username>\r\n");
    }

    let target = &args[1];
    let qt = match ctx.quota_tracker.as_ref() {
        Some(qt) => qt,
        None => return CommandResult::output("Quota tracker not available\r\n"),
    };

    qt.reset_user(target);
    CommandResult::output(format!("Quota counters reset for '{}'\r\n", target))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{AppConfig, UserRole};
    use crate::shell::commands::test_helpers::make_test_ctx;
    use std::sync::Arc;

    fn make_admin_ctx() -> ShellContext {
        let mut ctx = make_test_ctx();
        ctx.role = UserRole::Admin;
        ctx.username = "adminuser".to_string();

        // Wire up minimal admin fields
        let config: AppConfig = toml::from_str(
            r##"
[server]
ssh_listen = "127.0.0.1:0"

[[users]]
username = "adminuser"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$test"
role = "admin"

[[users]]
username = "normaluser"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$test"
"##,
        )
        .unwrap();

        let config = Arc::new(config);
        let auth_service = Arc::new(tokio::sync::RwLock::new(
            crate::auth::AuthService::new(&config).unwrap(),
        ));
        let security = {
            let sm = crate::security::SecurityManager::new(&config);
            Arc::new(tokio::sync::RwLock::new(sm))
        };
        let quota_tracker = Arc::new(crate::quota::QuotaTracker::new(&config.limits));
        let kick_tokens = Arc::new(dashmap::DashMap::new());
        let maintenance = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let audit = Arc::new(crate::audit::AuditLogger::new_noop());
        let proxy_engine = Arc::new(crate::proxy::ProxyEngine::new(config.clone(), audit));

        ctx.security = Some(security);
        ctx.auth_service = Some(auth_service);
        ctx.kick_tokens = Some(kick_tokens);
        ctx.maintenance = Some(maintenance);
        ctx.server_config = Some(config);
        ctx.proxy_engine = Some(proxy_engine);
        ctx.quota_tracker = Some(quota_tracker);

        ctx
    }

    #[test]
    fn test_admin_permission_denied() {
        let ctx = make_test_ctx(); // regular user
        let result = run(&["server".to_string()], &ctx);
        assert!(result.output.contains("Permission denied"));
    }

    #[test]
    fn test_admin_no_subcommand() {
        let ctx = make_admin_ctx();
        let result = run(&[], &ctx);
        assert!(result.output.contains("Usage:"));
    }

    #[test]
    fn test_admin_unknown_subcommand() {
        let ctx = make_admin_ctx();
        let result = run(&["foobar".to_string()], &ctx);
        assert!(result.output.contains("unknown subcommand"));
    }

    #[test]
    fn test_admin_server_basic() {
        let ctx = make_admin_ctx();
        let result = run(&["server".to_string()], &ctx);
        assert!(
            result.output.contains("Server Overview"),
            "got: {}",
            result.output
        );
        assert!(result.output.contains("Uptime:"));
        assert!(result.output.contains("Connections:"));
        assert!(result.output.contains("Maintenance:"));
    }

    #[test]
    fn test_admin_users_list() {
        let ctx = make_admin_ctx();
        let result = run(&["users".to_string()], &ctx);
        assert!(
            result.output.contains("Configured Users"),
            "got: {}",
            result.output
        );
        assert!(result.output.contains("adminuser"));
        assert!(result.output.contains("normaluser"));
        assert!(result.output.contains("Total: 2 users"));
    }

    #[test]
    fn test_admin_sessions_empty() {
        let ctx = make_admin_ctx();
        let result = run(&["sessions".to_string()], &ctx);
        assert!(result.output.contains("No active sessions"));
    }

    #[test]
    fn test_admin_bans_empty() {
        let ctx = make_admin_ctx();
        let result = run(&["bans".to_string()], &ctx);
        assert!(result.output.contains("No banned IPs"));
    }

    #[test]
    fn test_admin_user_not_found() {
        let ctx = make_admin_ctx();
        let result = run(&["user".to_string(), "nonexistent".to_string()], &ctx);
        assert!(result.output.contains("User not found"));
    }

    #[test]
    fn test_admin_user_detail() {
        let ctx = make_admin_ctx();
        let result = run(&["user".to_string(), "normaluser".to_string()], &ctx);
        assert!(
            result.output.contains("User: normaluser"),
            "got: {}",
            result.output
        );
        assert!(result.output.contains("Role:"));
        assert!(result.output.contains("Shell:"));
    }

    #[test]
    fn test_admin_user_no_args() {
        let ctx = make_admin_ctx();
        let result = run(&["user".to_string()], &ctx);
        assert!(result.output.contains("Usage:"));
    }

    #[test]
    fn test_admin_kick_no_sessions() {
        let ctx = make_admin_ctx();
        let result = run(&["kick".to_string(), "nobody".to_string()], &ctx);
        assert!(result.output.contains("No active sessions"));
    }

    #[test]
    fn test_admin_kick_no_args() {
        let ctx = make_admin_ctx();
        let result = run(&["kick".to_string()], &ctx);
        assert!(result.output.contains("Usage:"));
    }

    #[test]
    fn test_admin_quota_reset() {
        let ctx = make_admin_ctx();
        // Record some usage first
        ctx.quota_tracker
            .as_ref()
            .unwrap()
            .record_bytes("normaluser", 1024, 0, 0, None);
        let result = run(
            &[
                "quota".to_string(),
                "reset".to_string(),
                "normaluser".to_string(),
            ],
            &ctx,
        );
        assert!(
            result.output.contains("Quota counters reset"),
            "got: {}",
            result.output
        );
    }

    #[test]
    fn test_admin_quota_no_args() {
        let ctx = make_admin_ctx();
        let result = run(&["quota".to_string()], &ctx);
        assert!(result.output.contains("Usage:"));
    }

    #[test]
    fn test_admin_unban_parse_error() {
        let ctx = make_admin_ctx();
        let result = run(&["unban".to_string(), "not-an-ip".to_string()], &ctx);
        assert!(result.output.contains("Invalid IP address"));
    }

    #[test]
    fn test_admin_unban_not_banned() {
        let ctx = make_admin_ctx();
        let result = run(&["unban".to_string(), "10.0.0.1".to_string()], &ctx);
        assert!(result.output.contains("not currently banned"));
    }

    #[test]
    fn test_admin_unban_no_args() {
        let ctx = make_admin_ctx();
        let result = run(&["unban".to_string()], &ctx);
        assert!(result.output.contains("Usage:"));
    }

    #[test]
    fn test_admin_kick_with_tokens() {
        let ctx = make_admin_ctx();
        // Register a token for a user
        let token = tokio_util::sync::CancellationToken::new();
        ctx.kick_tokens
            .as_ref()
            .unwrap()
            .entry("targetuser".to_string())
            .or_default()
            .push(token.clone());

        let result = run(&["kick".to_string(), "targetuser".to_string()], &ctx);
        assert!(
            result.output.contains("Kicked targetuser"),
            "got: {}",
            result.output
        );
        assert!(result.output.contains("1 sessions cancelled"));
        assert!(token.is_cancelled());
    }

    #[test]
    fn test_admin_bans_with_data() {
        let ctx = make_admin_ctx();
        // Ban an IP
        {
            let sec = ctx.security.as_ref().unwrap().try_read().unwrap();
            sec.ban_manager().ban(
                "192.168.1.99".parse().unwrap(),
                std::time::Duration::from_secs(300),
            );
        }

        let result = run(&["bans".to_string()], &ctx);
        assert!(
            result.output.contains("192.168.1.99"),
            "got: {}",
            result.output
        );
        assert!(result.output.contains("Total: 1 banned"));
    }

    #[test]
    fn test_admin_unban_success() {
        let ctx = make_admin_ctx();
        // Ban then unban
        {
            let sec = ctx.security.as_ref().unwrap().try_read().unwrap();
            sec.ban_manager().ban(
                "10.20.30.40".parse().unwrap(),
                std::time::Duration::from_secs(300),
            );
        }

        let result = run(&["unban".to_string(), "10.20.30.40".to_string()], &ctx);
        assert!(
            result.output.contains("Unbanned 10.20.30.40"),
            "got: {}",
            result.output
        );
    }

    #[test]
    fn test_format_duration_values() {
        assert_eq!(format_duration(30), "30s");
        assert_eq!(format_duration(90), "1m 30s");
        assert_eq!(format_duration(3661), "1h 1m");
        assert_eq!(format_duration(90000), "1d 1h");
    }
}
