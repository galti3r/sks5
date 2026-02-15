use crate::config::types::MotdConfig;
use crate::utils::{format_bytes, format_bytes_used};

/// All template variables available for MOTD rendering.
pub struct MotdContext {
    /// Username of the connected user.
    pub user: String,
    /// Authentication method used: "password", "pubkey", "pubkey+totp".
    pub auth_method: String,
    /// Source IP address of the connection.
    pub source_ip: String,
    /// Number of active connections for this user.
    pub connections: u32,
    /// Summary of ACL policy: "allow" or "deny".
    pub acl_policy: String,
    /// Account expiration in ISO 8601 format, or None for "never".
    pub expires_at: Option<String>,
    /// Bandwidth consumed in bytes.
    pub bandwidth_used: u64,
    /// Bandwidth limit in bytes (0 = unlimited).
    pub bandwidth_limit: u64,
    /// Last login timestamp in ISO 8601 format, or None if first login.
    pub last_login: Option<String>,
    /// Server uptime in seconds.
    pub uptime: u64,
    /// Server version string.
    pub version: String,
    /// Group membership, or None if ungrouped.
    pub group: Option<String>,
    /// User role: "user" or "admin".
    pub role: String,
    /// List of ACL deny rules as display strings.
    pub denied: Vec<String>,
}

/// Format seconds as "Xd Xh Xm".
fn format_uptime(total_secs: u64) -> String {
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let minutes = (total_secs % 3600) / 60;

    if days > 0 {
        format!("{}d {}h {}m", days, hours, minutes)
    } else if hours > 0 {
        format!("{}h {}m", hours, minutes)
    } else {
        format!("{}m", minutes)
    }
}

/// Check whether an ISO 8601 datetime string is within 7 days from now.
///
/// Performs a simple prefix parse of "YYYY-MM-DDTHH:MM:SS" (ignoring timezone).
/// Returns false on any parse failure.
fn is_within_7_days(iso: &str) -> bool {
    // Minimal parse: extract "YYYY-MM-DD" and compare against a rough threshold.
    // We avoid pulling in chrono as a dependency by doing a basic calculation.
    // Parse "YYYY-MM-DDTHH:MM:SS..." or "YYYY-MM-DD HH:MM:SS..."
    if iso.len() < 10 {
        return false;
    }
    let date_part = &iso[..10];
    let parts: Vec<&str> = date_part.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    let year: i64 = match parts[0].parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let month: i64 = match parts[1].parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let day: i64 = match parts[2].parse() {
        Ok(v) => v,
        Err(_) => return false,
    };

    // Convert to a rough day-count since epoch for comparison.
    // This is approximate but sufficient for a "within 7 days" check.
    let expire_days = year * 365 + (year / 4) - (year / 100) + (year / 400) + month * 30 + day;

    // Get current date from SystemTime.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let now_secs = now.as_secs() as i64;
    // Approximate current date in the same rough day-count.
    let now_year = 1970 + now_secs / 31_557_600; // average seconds per year
    let remaining_secs = now_secs % 31_557_600;
    let now_month = 1 + remaining_secs / 2_629_800; // average seconds per month
    let now_day = 1 + (remaining_secs % 2_629_800) / 86400;
    let now_days = now_year * 365 + (now_year / 4) - (now_year / 100)
        + (now_year / 400)
        + now_month * 30
        + now_day;

    let diff = expire_days - now_days;
    (0..=7).contains(&diff)
}

/// Render a MOTD template string by replacing placeholders with context values.
///
/// When `colors` is true, certain values are wrapped in ANSI escape codes:
/// - Username in bold cyan
/// - `acl_policy` "allow" in green, "deny" in red
/// - `expires_at` in yellow when within 7 days
/// - `role` "admin" in bold magenta
///
/// Line endings in the output use `\r\n` for SSH terminal compatibility.
pub fn render_motd(template: &str, ctx: &MotdContext, colors: bool) -> String {
    let user_val = if colors {
        format!("\x1b[1;36m{}\x1b[0m", ctx.user)
    } else {
        ctx.user.clone()
    };

    let acl_val = if colors {
        match ctx.acl_policy.as_str() {
            "allow" => "\x1b[32mallow\x1b[0m".to_string(),
            "deny" => "\x1b[31mdeny\x1b[0m".to_string(),
            other => other.to_string(),
        }
    } else {
        ctx.acl_policy.clone()
    };

    let expires_val = match &ctx.expires_at {
        Some(ts) => {
            if colors && is_within_7_days(ts) {
                format!("\x1b[33m{}\x1b[0m", ts)
            } else {
                ts.clone()
            }
        }
        None => "never".to_string(),
    };

    let role_val = if colors && ctx.role == "admin" {
        "\x1b[1;35madmin\x1b[0m".to_string()
    } else {
        ctx.role.clone()
    };

    let group_val = match &ctx.group {
        Some(g) => g.clone(),
        None => "none".to_string(),
    };

    let last_login_val = match &ctx.last_login {
        Some(ts) => ts.clone(),
        None => "first login".to_string(),
    };

    let bandwidth_used_val = format_bytes_used(ctx.bandwidth_used);
    let bandwidth_limit_val = format_bytes(ctx.bandwidth_limit);
    let uptime_val = format_uptime(ctx.uptime);

    let denied_val = if ctx.denied.is_empty() {
        "none".to_string()
    } else {
        ctx.denied.join(", ")
    };

    // Single-pass template rendering to avoid 14 intermediate String allocations.
    let replacements: &[(&str, &str)] = &[
        ("{user}", &user_val),
        ("{auth_method}", &ctx.auth_method),
        ("{source_ip}", &ctx.source_ip),
        ("{connections}", &ctx.connections.to_string()),
        ("{acl_policy}", &acl_val),
        ("{expires_at}", &expires_val),
        ("{bandwidth_used}", &bandwidth_used_val),
        ("{bandwidth_limit}", &bandwidth_limit_val),
        ("{last_login}", &last_login_val),
        ("{uptime}", &uptime_val),
        ("{version}", &ctx.version),
        ("{group}", &group_val),
        ("{role}", &role_val),
        ("{denied}", &denied_val),
    ];

    let mut result = String::with_capacity(template.len() * 2);
    let mut i = 0;
    let bytes = template.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'{' {
            let mut found = false;
            for &(key, value) in replacements {
                if template[i..].starts_with(key) {
                    result.push_str(value);
                    i += key.len();
                    found = true;
                    break;
                }
            }
            if !found {
                result.push(bytes[i] as char);
                i += 1;
            }
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }

    // Normalize line endings to \r\n for SSH terminals.
    // First collapse any existing \r\n to \n, then replace all \n with \r\n.
    let normalized = result.replace("\r\n", "\n");
    normalized.replace('\n', "\r\n")
}

/// Returns the default MOTD template string.
///
/// This template uses `\r\n` line endings for SSH terminal compatibility
/// and includes all available placeholders.
pub fn default_motd_template() -> String {
    [
        "Welcome {user}!",
        "Role: {role} | Group: {group} | Auth: {auth_method}",
        "Source: {source_ip} | Connections: {connections}",
        "ACL Policy: {acl_policy} | Denied: {denied}",
        "Bandwidth: {bandwidth_used} / {bandwidth_limit}",
        "Expires: {expires_at}",
        "Server uptime: {uptime} | sks5 v{version}",
    ]
    .join("\r\n")
}

/// Resolve the effective MOTD configuration using user > group > global precedence.
///
/// Returns `(enabled, template, colors)`:
/// - `enabled`: whether MOTD should be displayed
/// - `template`: the template string if explicitly set, or None for default
/// - `colors`: whether ANSI colors should be used
pub fn resolve_motd_config(
    global: &MotdConfig,
    group: Option<&MotdConfig>,
    user: Option<&MotdConfig>,
) -> (bool, Option<String>, bool) {
    // Start with global values.
    let mut enabled = global.enabled;
    let mut template = global.template.clone();
    let mut colors = global.colors;

    // Group overrides global.
    if let Some(g) = group {
        enabled = g.enabled;
        if g.template.is_some() {
            template = g.template.clone();
        }
        colors = g.colors;
    }

    // User overrides group and global.
    if let Some(u) = user {
        enabled = u.enabled;
        if u.template.is_some() {
            template = u.template.clone();
        }
        colors = u.colors;
    }

    (enabled, template, colors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{format_bytes, format_bytes_used};

    fn sample_context() -> MotdContext {
        MotdContext {
            user: "alice".to_string(),
            auth_method: "pubkey".to_string(),
            source_ip: "192.168.1.100".to_string(),
            connections: 3,
            acl_policy: "allow".to_string(),
            expires_at: Some("2099-12-31T23:59:59Z".to_string()),
            bandwidth_used: 1_073_741_824,   // 1 GB
            bandwidth_limit: 10_737_418_240, // 10 GB
            last_login: Some("2026-01-15T08:30:00Z".to_string()),
            uptime: 90061, // 1d 1h 1m 1s
            version: "0.1.0".to_string(),
            group: Some("developers".to_string()),
            role: "user".to_string(),
            denied: vec!["169.254.169.254:*".to_string(), "evil.com:*".to_string()],
        }
    }

    #[test]
    fn test_format_bytes_zero_is_unlimited() {
        assert_eq!(format_bytes(0), "unlimited");
    }

    #[test]
    fn test_format_bytes_small() {
        assert_eq!(format_bytes(500), "500 B");
    }

    #[test]
    fn test_format_bytes_kb() {
        assert_eq!(format_bytes(2048), "2.0 KB");
    }

    #[test]
    fn test_format_bytes_mb() {
        assert_eq!(format_bytes(5_242_880), "5.0 MB");
    }

    #[test]
    fn test_format_bytes_gb() {
        assert_eq!(format_bytes(1_073_741_824), "1.0 GB");
    }

    #[test]
    fn test_format_bytes_tb() {
        assert_eq!(format_bytes(1_099_511_627_776), "1.0 TB");
    }

    #[test]
    fn test_format_bytes_used_zero() {
        assert_eq!(format_bytes_used(0), "0 B");
    }

    #[test]
    fn test_format_bytes_used_nonzero() {
        assert_eq!(format_bytes_used(1024), "1.0 KB");
    }

    #[test]
    fn test_format_uptime_minutes_only() {
        assert_eq!(format_uptime(300), "5m");
    }

    #[test]
    fn test_format_uptime_hours_minutes() {
        assert_eq!(format_uptime(3660), "1h 1m");
    }

    #[test]
    fn test_format_uptime_days_hours_minutes() {
        assert_eq!(format_uptime(90061), "1d 1h 1m");
    }

    #[test]
    fn test_format_uptime_zero() {
        assert_eq!(format_uptime(0), "0m");
    }

    #[test]
    fn test_render_motd_no_colors() {
        let ctx = sample_context();
        let template = default_motd_template();
        let result = render_motd(&template, &ctx, false);

        assert!(result.contains("Welcome alice!"));
        assert!(result.contains("Role: user"));
        assert!(result.contains("Group: developers"));
        assert!(result.contains("Auth: pubkey"));
        assert!(result.contains("Source: 192.168.1.100"));
        assert!(result.contains("Connections: 3"));
        assert!(result.contains("ACL Policy: allow"));
        assert!(result.contains("1.0 GB / 10.0 GB"));
        assert!(result.contains("Expires: 2099-12-31T23:59:59Z"));
        assert!(result.contains("1d 1h 1m"));
        assert!(result.contains("sks5 v0.1.0"));
        // No ANSI codes.
        assert!(!result.contains("\x1b["));
    }

    #[test]
    fn test_render_motd_with_colors() {
        let ctx = sample_context();
        let template = default_motd_template();
        let result = render_motd(&template, &ctx, true);

        // Username in bold cyan.
        assert!(result.contains("\x1b[1;36malice\x1b[0m"));
        // ACL "allow" in green.
        assert!(result.contains("\x1b[32mallow\x1b[0m"));
    }

    #[test]
    fn test_render_motd_admin_role_colored() {
        let mut ctx = sample_context();
        ctx.role = "admin".to_string();
        let template = "Role: {role}";
        let result = render_motd(template, &ctx, true);

        assert!(result.contains("\x1b[1;35madmin\x1b[0m"));
    }

    #[test]
    fn test_render_motd_deny_policy_colored() {
        let mut ctx = sample_context();
        ctx.acl_policy = "deny".to_string();
        let template = "ACL: {acl_policy}";
        let result = render_motd(template, &ctx, true);

        assert!(result.contains("\x1b[31mdeny\x1b[0m"));
    }

    #[test]
    fn test_render_motd_none_fields() {
        let mut ctx = sample_context();
        ctx.expires_at = None;
        ctx.group = None;
        ctx.last_login = None;
        let template = "Expires: {expires_at} Group: {group} Last: {last_login}";
        let result = render_motd(template, &ctx, false);

        assert!(result.contains("Expires: never"));
        assert!(result.contains("Group: none"));
        assert!(result.contains("Last: first login"));
    }

    #[test]
    fn test_render_motd_unlimited_bandwidth() {
        let mut ctx = sample_context();
        ctx.bandwidth_limit = 0;
        let template = "BW: {bandwidth_used} / {bandwidth_limit}";
        let result = render_motd(template, &ctx, false);

        assert!(result.contains("/ unlimited"));
    }

    #[test]
    fn test_render_motd_crlf_line_endings() {
        let ctx = sample_context();
        let template = "Line1\nLine2\nLine3";
        let result = render_motd(template, &ctx, false);

        assert!(result.contains("Line1\r\nLine2\r\nLine3"));
        // Should not have bare \n.
        assert!(!result.contains("Line1\nLine2"));
    }

    #[test]
    fn test_render_motd_existing_crlf_not_doubled() {
        let ctx = sample_context();
        let template = "Line1\r\nLine2";
        let result = render_motd(template, &ctx, false);

        assert_eq!(result, "Line1\r\nLine2");
        // Should NOT have \r\r\n.
        assert!(!result.contains("\r\r\n"));
    }

    #[test]
    fn test_default_motd_template_has_crlf() {
        let template = default_motd_template();
        assert!(template.contains("\r\n"));
        assert!(!template.contains("\r\r\n"));
    }

    #[test]
    fn test_default_motd_template_has_all_placeholders() {
        let template = default_motd_template();
        let placeholders = [
            "{user}",
            "{role}",
            "{group}",
            "{auth_method}",
            "{source_ip}",
            "{connections}",
            "{acl_policy}",
            "{bandwidth_used}",
            "{bandwidth_limit}",
            "{expires_at}",
            "{uptime}",
            "{version}",
            "{denied}",
        ];
        for ph in &placeholders {
            assert!(template.contains(ph), "Missing placeholder: {}", ph);
        }
    }

    #[test]
    fn test_render_motd_denied_rules() {
        let ctx = sample_context();
        let template = "Denied: {denied}";
        let result = render_motd(template, &ctx, false);
        assert_eq!(result, "Denied: 169.254.169.254:*, evil.com:*");
    }

    #[test]
    fn test_render_motd_denied_empty() {
        let mut ctx = sample_context();
        ctx.denied = vec![];
        let template = "Denied: {denied}";
        let result = render_motd(template, &ctx, false);
        assert_eq!(result, "Denied: none");
    }

    #[test]
    fn test_resolve_motd_config_global_only() {
        let global = MotdConfig {
            enabled: true,
            template: Some("Global template".to_string()),
            colors: true,
        };
        let (enabled, template, colors) = resolve_motd_config(&global, None, None);
        assert!(enabled);
        assert_eq!(template, Some("Global template".to_string()));
        assert!(colors);
    }

    #[test]
    fn test_resolve_motd_config_group_overrides_global() {
        let global = MotdConfig {
            enabled: true,
            template: Some("Global template".to_string()),
            colors: true,
        };
        let group = MotdConfig {
            enabled: false,
            template: Some("Group template".to_string()),
            colors: false,
        };
        let (enabled, template, colors) = resolve_motd_config(&global, Some(&group), None);
        assert!(!enabled);
        assert_eq!(template, Some("Group template".to_string()));
        assert!(!colors);
    }

    #[test]
    fn test_resolve_motd_config_user_overrides_all() {
        let global = MotdConfig {
            enabled: true,
            template: Some("Global".to_string()),
            colors: true,
        };
        let group = MotdConfig {
            enabled: false,
            template: Some("Group".to_string()),
            colors: false,
        };
        let user = MotdConfig {
            enabled: true,
            template: Some("User".to_string()),
            colors: true,
        };
        let (enabled, template, colors) = resolve_motd_config(&global, Some(&group), Some(&user));
        assert!(enabled);
        assert_eq!(template, Some("User".to_string()));
        assert!(colors);
    }

    #[test]
    fn test_resolve_motd_config_user_without_template_inherits() {
        let global = MotdConfig {
            enabled: true,
            template: Some("Global".to_string()),
            colors: true,
        };
        let user = MotdConfig {
            enabled: true,
            template: None,
            colors: false,
        };
        let (enabled, template, colors) = resolve_motd_config(&global, None, Some(&user));
        assert!(enabled);
        // User has no template, so global template is inherited.
        assert_eq!(template, Some("Global".to_string()));
        assert!(!colors);
    }

    #[test]
    fn test_resolve_motd_config_group_without_template_inherits() {
        let global = MotdConfig {
            enabled: true,
            template: Some("Global".to_string()),
            colors: true,
        };
        let group = MotdConfig {
            enabled: true,
            template: None,
            colors: false,
        };
        let (enabled, template, colors) = resolve_motd_config(&global, Some(&group), None);
        assert!(enabled);
        assert_eq!(template, Some("Global".to_string()));
        assert!(!colors);
    }

    #[test]
    fn test_resolve_motd_config_defaults() {
        let global = MotdConfig::default();
        let (enabled, template, colors) = resolve_motd_config(&global, None, None);
        assert!(enabled);
        assert!(template.is_none());
        assert!(colors);
    }

    #[test]
    fn test_render_custom_template() {
        let ctx = sample_context();
        let template = "Hello {user}, you have {connections} active sessions.";
        let result = render_motd(template, &ctx, false);
        assert_eq!(result, "Hello alice, you have 3 active sessions.");
    }

    #[test]
    fn test_render_empty_template() {
        let ctx = sample_context();
        let result = render_motd("", &ctx, false);
        assert_eq!(result, "");
    }
}
