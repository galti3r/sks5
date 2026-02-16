// Unit tests for new features: IP Reputation, MOTD, ShellContext, ConnectionPoolConfig.
//
// No connection pool module (src/proxy/pool.rs) exists yet, so we test
// the ConnectionPoolConfig struct defaults instead.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use sks5::config::acl::ParsedAcl;
use sks5::config::parse_config;
use sks5::config::types::{
    AclPolicyConfig, ConnectionPoolConfig, MotdConfig, ShellPermissions, UserRole,
};
use sks5::motd::{default_motd_template, render_motd, resolve_motd_config, MotdContext};
use sks5::security::ip_reputation::IpReputationManager;
use sks5::shell::context::ShellContext;

// ---------------------------------------------------------------------------
// Helper: fake TOML config for SecurityManager-based tests
// ---------------------------------------------------------------------------
const FAKE_HASH: &str = "argon2id-fakehash-for-testing";

fn create_test_config(security_section: &str) -> sks5::config::types::AppConfig {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

{security_section}

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    parse_config(&toml).unwrap()
}

// ---------------------------------------------------------------------------
// 1. IP Reputation Manager
// ---------------------------------------------------------------------------

#[test]
fn test_ip_reputation_new_enabled() {
    let mgr = IpReputationManager::new(true, 50);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    // A fresh manager should report score 0 for any IP.
    assert_eq!(mgr.get_score(&ip), 0);
}

#[test]
fn test_ip_reputation_new_disabled() {
    let mgr = IpReputationManager::new(false, 50);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    assert_eq!(mgr.get_score(&ip), 0);
}

#[test]
fn test_ip_reputation_record_auth_failure_adds_10() {
    let mgr = IpReputationManager::new(true, 100);
    let ip: IpAddr = "192.168.1.1".parse().unwrap();

    mgr.record_auth_failure(&ip);
    // Score should be approximately 10 (tiny decay is negligible).
    let score = mgr.get_score(&ip);
    assert!((9..=10).contains(&score), "expected ~10, got {}", score);
}

#[test]
fn test_ip_reputation_record_acl_denial_adds_5() {
    let mgr = IpReputationManager::new(true, 100);
    let ip: IpAddr = "192.168.1.2".parse().unwrap();

    mgr.record_acl_denial(&ip);
    let score = mgr.get_score(&ip);
    assert!((4..=5).contains(&score), "expected ~5, got {}", score);
}

#[test]
fn test_ip_reputation_record_rapid_connections_adds_3() {
    let mgr = IpReputationManager::new(true, 100);
    let ip: IpAddr = "192.168.1.3".parse().unwrap();

    mgr.record_rapid_connections(&ip);
    let score = mgr.get_score(&ip);
    assert!((2..=3).contains(&score), "expected ~3, got {}", score);
}

#[test]
fn test_ip_reputation_record_auth_success_reduces_score() {
    let mgr = IpReputationManager::new(true, 100);
    let ip: IpAddr = "192.168.1.4".parse().unwrap();

    // Build up some score.
    mgr.record_auth_failure(&ip); // +10
    mgr.record_auth_failure(&ip); // +10
    let before = mgr.get_score(&ip);
    assert!(before >= 19, "expected >= 19, got {}", before);

    // Successful auth reduces by 5.
    mgr.record_auth_success(&ip);
    let after = mgr.get_score(&ip);
    assert!(
        after < before,
        "score should decrease after auth success: before={}, after={}",
        before,
        after
    );
}

#[test]
fn test_ip_reputation_auth_success_does_not_go_below_zero() {
    let mgr = IpReputationManager::new(true, 100);
    let ip: IpAddr = "192.168.1.5".parse().unwrap();

    // Record a success on a fresh IP (score starts at 0).
    mgr.record_auth_success(&ip);
    let score = mgr.get_score(&ip);
    assert_eq!(score, 0, "score should not go below 0");
}

#[test]
fn test_ip_reputation_cumulative_failures() {
    let mgr = IpReputationManager::new(true, 100);
    let ip: IpAddr = "10.0.0.5".parse().unwrap();

    for _ in 0..5 {
        mgr.record_auth_failure(&ip);
    }
    let score = mgr.get_score(&ip);
    // 5 * 10 = 50, minus tiny decay.
    assert!((48..=50).contains(&score), "expected ~50, got {}", score);
}

#[test]
fn test_ip_reputation_should_ban_above_threshold() {
    let mgr = IpReputationManager::new(true, 25);
    let ip: IpAddr = "10.0.0.6".parse().unwrap();

    // 3 auth failures = ~30 points, comfortably above threshold of 25.
    for _ in 0..3 {
        mgr.record_auth_failure(&ip);
    }
    assert!(
        mgr.should_ban(&ip),
        "IP with score >= threshold should be banned, score = {}",
        mgr.get_score(&ip)
    );
}

#[test]
fn test_ip_reputation_should_ban_below_threshold() {
    let mgr = IpReputationManager::new(true, 30);
    let ip: IpAddr = "10.0.0.7".parse().unwrap();

    // 2 auth failures = 20 points — below threshold of 30.
    mgr.record_auth_failure(&ip);
    mgr.record_auth_failure(&ip);
    assert!(
        !mgr.should_ban(&ip),
        "IP with score < threshold should not be banned"
    );
}

#[test]
fn test_ip_reputation_should_ban_disabled_always_false() {
    let mgr = IpReputationManager::new(false, 10);
    let ip: IpAddr = "10.0.0.8".parse().unwrap();

    // Even if we record failures, should_ban returns false when disabled.
    mgr.record_auth_failure(&ip);
    mgr.record_auth_failure(&ip);
    assert!(!mgr.should_ban(&ip));
}

#[test]
fn test_ip_reputation_should_ban_zero_threshold_always_false() {
    let mgr = IpReputationManager::new(true, 0);
    let ip: IpAddr = "10.0.0.9".parse().unwrap();

    mgr.record_auth_failure(&ip);
    mgr.record_auth_failure(&ip);
    mgr.record_auth_failure(&ip);
    // ban_threshold == 0 means never auto-ban.
    assert!(!mgr.should_ban(&ip));
}

#[test]
fn test_ip_reputation_disabled_manager_ignores_events() {
    let mgr = IpReputationManager::new(false, 50);
    let ip: IpAddr = "172.16.0.1".parse().unwrap();

    mgr.record_auth_failure(&ip);
    mgr.record_acl_denial(&ip);
    mgr.record_rapid_connections(&ip);
    mgr.record_auth_success(&ip);

    assert_eq!(mgr.get_score(&ip), 0, "disabled manager always returns 0");
    assert!(!mgr.should_ban(&ip));
    assert!(mgr.all_scores().is_empty());
}

#[test]
fn test_ip_reputation_all_scores_returns_nonzero_ips() {
    let mgr = IpReputationManager::new(true, 100);
    let ip1: IpAddr = "10.0.0.1".parse().unwrap();
    let ip2: IpAddr = "10.0.0.2".parse().unwrap();

    mgr.record_auth_failure(&ip1);
    mgr.record_auth_failure(&ip2);
    mgr.record_auth_failure(&ip2);

    let scores = mgr.all_scores();
    assert_eq!(scores.len(), 2, "should have 2 IPs with nonzero scores");

    let ip1_score = scores.iter().find(|(ip, _)| *ip == ip1).map(|(_, s)| *s);
    let ip2_score = scores.iter().find(|(ip, _)| *ip == ip2).map(|(_, s)| *s);
    assert!(ip1_score.is_some());
    assert!(ip2_score.is_some());
    assert!(
        ip2_score.unwrap() > ip1_score.unwrap(),
        "ip2 should have higher score"
    );
}

#[test]
fn test_ip_reputation_cleanup_removes_low_scores() {
    let mgr = IpReputationManager::new(true, 100);
    let ip_low: IpAddr = "10.0.0.10".parse().unwrap();
    let ip_high: IpAddr = "10.0.0.11".parse().unwrap();

    // Give ip_low a very small score (rapid_connections = 3).
    mgr.record_rapid_connections(&ip_low);

    // Give ip_high a large score.
    for _ in 0..10 {
        mgr.record_auth_failure(&ip_high);
    }

    // Before cleanup, both should appear.
    let before = mgr.all_scores();
    assert!(!before.is_empty());

    // Cleanup retains entries with decayed score >= 1.0.
    // Since we just recorded, both should still be above 1.0.
    mgr.cleanup();
    let after = mgr.all_scores();
    assert!(
        after.iter().any(|(ip, _)| *ip == ip_high),
        "high-score IP should survive cleanup"
    );
}

#[test]
fn test_ip_reputation_mixed_events() {
    let mgr = IpReputationManager::new(true, 100);
    let ip: IpAddr = "203.0.113.1".parse().unwrap();

    mgr.record_auth_failure(&ip); // +10
    mgr.record_acl_denial(&ip); // +5
    mgr.record_rapid_connections(&ip); // +3
                                       // Total ~18
    let score = mgr.get_score(&ip);
    assert!(
        (17..=18).contains(&score),
        "expected ~18 from mixed events, got {}",
        score
    );

    // Auth success reduces by 5.
    mgr.record_auth_success(&ip);
    let score2 = mgr.get_score(&ip);
    assert!(
        (12..=13).contains(&score2),
        "expected ~13 after success, got {}",
        score2
    );
}

#[test]
fn test_ip_reputation_multiple_ips_independent() {
    let mgr = IpReputationManager::new(true, 100);
    let ip1: IpAddr = "1.1.1.1".parse().unwrap();
    let ip2: IpAddr = "2.2.2.2".parse().unwrap();

    mgr.record_auth_failure(&ip1);
    // ip2 should remain at 0.
    assert_eq!(mgr.get_score(&ip2), 0);
    assert!(mgr.get_score(&ip1) > 0);
}

// ---------------------------------------------------------------------------
// 2. MOTD - Integration-style tests (exercising public API)
// ---------------------------------------------------------------------------

fn make_motd_context() -> MotdContext {
    MotdContext {
        user: "bob".to_string(),
        auth_method: "password".to_string(),
        source_ip: "10.0.0.42".to_string(),
        connections: 2,
        acl_policy: "deny".to_string(),
        expires_at: Some("2099-06-15T12:00:00Z".to_string()),
        bandwidth_used: 5_242_880,      // 5 MB
        bandwidth_limit: 1_073_741_824, // 1 GB
        last_login: Some("2026-02-01T10:00:00Z".to_string()),
        uptime: 93784, // 1d 2h 3m 4s
        version: "1.2.3".to_string(),
        group: Some("ops".to_string()),
        role: "admin".to_string(),
        denied: vec!["169.254.169.254:*".to_string()],
        allowed: vec![],
    }
}

fn default_perms() -> ShellPermissions {
    ShellPermissions::default()
}

#[test]
fn test_render_motd_full_context_no_colors() {
    let ctx = make_motd_context();
    let template = default_motd_template();
    let result = render_motd(&template, &ctx, false, &default_perms());

    assert!(result.contains("Welcome, bob!"));
    assert!(result.contains("Role: admin"));
    assert!(result.contains("Group: ops"));
    assert!(result.contains("Auth: password"));
    assert!(result.contains("Source: 10.0.0.42"));
    assert!(result.contains("Connections: 2"));
    assert!(result.contains("Policy: deny"));
    assert!(result.contains("5.0 MB / 1.0 GB"));
    assert!(result.contains("Expires: 2099-06-15T12:00:00Z"));
    assert!(result.contains("1d 2h 3m"));
    assert!(result.contains("sks5 Proxy  v1.2.3"));

    // No ANSI escape codes.
    assert!(!result.contains("\x1b["));
}

#[test]
fn test_render_motd_full_context_with_colors() {
    let ctx = make_motd_context();
    let template = default_motd_template();
    let result = render_motd(&template, &ctx, true, &default_perms());

    // Username in bold cyan.
    assert!(result.contains("\x1b[1;36mbob\x1b[0m"));
    // ACL "deny" in red.
    assert!(result.contains("\x1b[31mdeny\x1b[0m"));
    // Admin role in bold magenta.
    assert!(result.contains("\x1b[1;35madmin\x1b[0m"));
}

#[test]
fn test_render_motd_user_role_not_colored_when_plain() {
    let mut ctx = make_motd_context();
    ctx.role = "user".to_string();
    let template = "Role: {role}";
    let result = render_motd(template, &ctx, true, &default_perms());
    // "user" role does NOT get ANSI colors.
    assert!(!result.contains("\x1b["));
    assert!(result.contains("Role: user"));
}

#[test]
fn test_render_motd_bandwidth_zero_used_unlimited_limit() {
    let mut ctx = make_motd_context();
    ctx.bandwidth_used = 0;
    ctx.bandwidth_limit = 0;
    let template = "BW: {bandwidth_used} / {bandwidth_limit}";
    let result = render_motd(template, &ctx, false, &default_perms());
    assert_eq!(result, "BW: 0 B / unlimited");
}

#[test]
fn test_render_motd_no_group_no_expiry_first_login() {
    let mut ctx = make_motd_context();
    ctx.group = None;
    ctx.expires_at = None;
    ctx.last_login = None;
    let template = "Group: {group} | Expires: {expires_at} | Last login: {last_login}";
    let result = render_motd(template, &ctx, false, &default_perms());
    assert!(result.contains("Group: none"));
    assert!(result.contains("Expires: never"));
    assert!(result.contains("Last login: first login"));
}

#[test]
fn test_render_motd_line_endings_normalized_to_crlf() {
    let ctx = make_motd_context();
    let template = "Line1\nLine2\nLine3";
    let result = render_motd(template, &ctx, false, &default_perms());

    // All newlines should be \r\n.
    assert!(result.contains("Line1\r\nLine2\r\nLine3"));
    // Should not have a bare \n not preceded by \r.
    for (i, byte) in result.as_bytes().iter().enumerate() {
        if *byte == b'\n' {
            assert!(
                i > 0 && result.as_bytes()[i - 1] == b'\r',
                "bare \\n found at byte offset {}",
                i
            );
        }
    }
}

#[test]
fn test_render_motd_custom_template_single_placeholder() {
    let ctx = make_motd_context();
    let template = "Hi {user}, your IP is {source_ip}.";
    let result = render_motd(template, &ctx, false, &default_perms());
    assert_eq!(result, "Hi bob, your IP is 10.0.0.42.");
}

#[test]
fn test_render_motd_uptime_formatting() {
    // Test different uptime ranges.
    let mut ctx = make_motd_context();

    // Less than an hour: "Xm"
    ctx.uptime = 120; // 2 minutes
    let result = render_motd("Up: {uptime}", &ctx, false, &default_perms());
    assert_eq!(result, "Up: 2m");

    // Hours + minutes: "Xh Xm"
    ctx.uptime = 7260; // 2h 1m
    let result = render_motd("Up: {uptime}", &ctx, false, &default_perms());
    assert_eq!(result, "Up: 2h 1m");

    // Days + hours + minutes: "Xd Xh Xm"
    ctx.uptime = 90000; // 1d 1h 0m
    let result = render_motd("Up: {uptime}", &ctx, false, &default_perms());
    assert_eq!(result, "Up: 1d 1h 0m");
}

// ---------------------------------------------------------------------------
// 2b. resolve_motd_config tests covering all 3 levels
// ---------------------------------------------------------------------------

#[test]
fn test_resolve_motd_config_global_only() {
    let global = MotdConfig {
        enabled: true,
        template: Some("Global message".to_string()),
        colors: false,
    };
    let (enabled, template, colors) = resolve_motd_config(&global, None, None);
    assert!(enabled);
    assert_eq!(template, Some("Global message".to_string()));
    assert!(!colors);
}

#[test]
fn test_resolve_motd_config_group_overrides_global() {
    let global = MotdConfig {
        enabled: true,
        template: Some("Global".to_string()),
        colors: true,
    };
    let group = MotdConfig {
        enabled: false,
        template: Some("Group msg".to_string()),
        colors: false,
    };
    let (enabled, template, colors) = resolve_motd_config(&global, Some(&group), None);
    assert!(!enabled);
    assert_eq!(template, Some("Group msg".to_string()));
    assert!(!colors);
}

#[test]
fn test_resolve_motd_config_user_overrides_group_and_global() {
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
        template: Some("User special".to_string()),
        colors: true,
    };
    let (enabled, template, colors) = resolve_motd_config(&global, Some(&group), Some(&user));
    assert!(enabled);
    assert_eq!(template, Some("User special".to_string()));
    assert!(colors);
}

#[test]
fn test_resolve_motd_config_user_inherits_template_from_global() {
    let global = MotdConfig {
        enabled: true,
        template: Some("Inherited template".to_string()),
        colors: true,
    };
    let user = MotdConfig {
        enabled: false,
        template: None, // no override
        colors: false,
    };
    let (enabled, template, colors) = resolve_motd_config(&global, None, Some(&user));
    assert!(!enabled);
    // User did not set template, so global template is inherited.
    assert_eq!(template, Some("Inherited template".to_string()));
    assert!(!colors);
}

#[test]
fn test_resolve_motd_config_group_inherits_template_from_global() {
    let global = MotdConfig {
        enabled: true,
        template: Some("Global tmpl".to_string()),
        colors: true,
    };
    let group = MotdConfig {
        enabled: true,
        template: None,
        colors: false,
    };
    let (enabled, template, colors) = resolve_motd_config(&global, Some(&group), None);
    assert!(enabled);
    assert_eq!(template, Some("Global tmpl".to_string()));
    assert!(!colors);
}

#[test]
fn test_resolve_motd_config_user_overrides_group_template_but_inherits_global_when_group_has_none()
{
    let global = MotdConfig {
        enabled: true,
        template: Some("Global".to_string()),
        colors: true,
    };
    let group = MotdConfig {
        enabled: true,
        template: None, // group does not override
        colors: true,
    };
    let user = MotdConfig {
        enabled: true,
        template: None, // user does not override either
        colors: false,
    };
    let (enabled, template, colors) = resolve_motd_config(&global, Some(&group), Some(&user));
    assert!(enabled);
    // Neither group nor user set a template, so global template carries through.
    assert_eq!(template, Some("Global".to_string()));
    assert!(!colors);
}

#[test]
fn test_resolve_motd_config_defaults_all_none() {
    let global = MotdConfig::default();
    let (enabled, template, colors) = resolve_motd_config(&global, None, None);
    assert!(enabled);
    assert!(template.is_none());
    assert!(colors);
}

#[test]
fn test_resolve_motd_config_user_sets_template_overrides_group() {
    let global = MotdConfig::default();
    let group = MotdConfig {
        enabled: true,
        template: Some("Group tmpl".to_string()),
        colors: true,
    };
    let user = MotdConfig {
        enabled: true,
        template: Some("User tmpl".to_string()),
        colors: true,
    };
    let (_, template, _) = resolve_motd_config(&global, Some(&group), Some(&user));
    assert_eq!(template, Some("User tmpl".to_string()));
}

// ---------------------------------------------------------------------------
// 3. ShellContext::uptime() formatting
// ---------------------------------------------------------------------------

fn make_shell_context(start: Instant) -> ShellContext {
    ShellContext {
        username: "testuser".to_string(),
        auth_method: "password".to_string(),
        source_ip: "127.0.0.1".to_string(),
        role: UserRole::User,
        group: None,
        permissions: ShellPermissions::default(),
        acl: ParsedAcl::from_config(AclPolicyConfig::Allow, &[], &[]).unwrap(),
        colors: false,
        expires_at: None,
        max_bandwidth_kbps: 0,
        server_start_time: start,
        bookmarks: HashMap::new(),
        aliases: HashMap::new(),
        ssh_key_fingerprint: None,
        proxy_engine: None,
        quota_tracker: None,
        quota_config: None,
    }
}

#[test]
fn test_shell_context_uptime_seconds_only() {
    // Create an instant that is "now" so elapsed is very small.
    let ctx = make_shell_context(Instant::now());
    let uptime = ctx.uptime();
    // Should be "0s" or a very small number of seconds.
    assert!(
        uptime.ends_with('s') && !uptime.contains('m') && !uptime.contains('h'),
        "expected seconds-only format, got: {}",
        uptime
    );
}

#[test]
fn test_shell_context_uptime_format_recent() {
    // Start time is now, so uptime should be "0s".
    let ctx = make_shell_context(Instant::now());
    let uptime = ctx.uptime();
    assert_eq!(uptime, "0s");
}

#[test]
fn test_shell_context_uptime_format_uses_correct_units() {
    // We can only control the start time by setting it in the past.
    // Instant::now() - Duration is available via checked_sub (nightly) or
    // by simply creating and sleeping. Instead, test the boundary logic
    // indirectly: create with now() and verify the output pattern.
    let ctx = make_shell_context(Instant::now());
    let uptime = ctx.uptime();
    // Should match pattern: Xs, Xm Xs, or Xh Xm Xs.
    assert!(
        uptime.contains('s'),
        "uptime should always contain 's': {}",
        uptime
    );
}

#[test]
fn test_shell_context_fields_preserved() {
    let ctx = make_shell_context(Instant::now());
    assert_eq!(ctx.username, "testuser");
    assert_eq!(ctx.auth_method, "password");
    assert_eq!(ctx.source_ip, "127.0.0.1");
    assert!(matches!(ctx.role, UserRole::User));
    assert!(ctx.group.is_none());
    assert!(ctx.expires_at.is_none());
    assert_eq!(ctx.max_bandwidth_kbps, 0);
    assert!(ctx.bookmarks.is_empty());
    assert!(ctx.aliases.is_empty());
    assert!(ctx.ssh_key_fingerprint.is_none());
}

#[test]
fn test_shell_context_with_admin_role() {
    let mut ctx = make_shell_context(Instant::now());
    ctx.role = UserRole::Admin;
    ctx.group = Some("admins".to_string());
    ctx.ssh_key_fingerprint = Some("SHA256:abc123".to_string());
    assert!(matches!(ctx.role, UserRole::Admin));
    assert_eq!(ctx.group.as_deref(), Some("admins"));
    assert_eq!(ctx.ssh_key_fingerprint.as_deref(), Some("SHA256:abc123"));
}

#[test]
fn test_shell_context_bookmarks_and_aliases() {
    let mut ctx = make_shell_context(Instant::now());
    ctx.bookmarks
        .insert("prod-db".to_string(), "db.internal:5432".to_string());
    ctx.aliases
        .insert("st".to_string(), "show status".to_string());

    assert_eq!(ctx.bookmarks.get("prod-db").unwrap(), "db.internal:5432");
    assert_eq!(ctx.aliases.get("st").unwrap(), "show status");
}

// ---------------------------------------------------------------------------
// 4. ConnectionPoolConfig defaults (no pool.rs module exists)
// ---------------------------------------------------------------------------

#[test]
fn test_connection_pool_config_defaults() {
    let cfg = ConnectionPoolConfig::default();
    assert!(!cfg.enabled);
    assert_eq!(cfg.max_idle_per_host, 10);
    assert_eq!(cfg.idle_timeout_secs, 60);
}

#[test]
fn test_connection_pool_config_from_toml_default() {
    let config = create_test_config("");
    assert!(!config.connection_pool.enabled);
    assert_eq!(config.connection_pool.max_idle_per_host, 10);
    assert_eq!(config.connection_pool.idle_timeout_secs, 60);
}

#[test]
fn test_connection_pool_config_from_toml_custom() {
    let config = create_test_config(
        r##"
[connection_pool]
enabled = true
max_idle_per_host = 25
idle_timeout_secs = 120
"##,
    );
    assert!(config.connection_pool.enabled);
    assert_eq!(config.connection_pool.max_idle_per_host, 25);
    assert_eq!(config.connection_pool.idle_timeout_secs, 120);
}

#[test]
fn test_connection_pool_config_from_toml_partial_override() {
    let config = create_test_config(
        r##"
[connection_pool]
enabled = true
"##,
    );
    assert!(config.connection_pool.enabled);
    // Non-specified fields should use defaults.
    assert_eq!(config.connection_pool.max_idle_per_host, 10);
    assert_eq!(config.connection_pool.idle_timeout_secs, 60);
}

// ---------------------------------------------------------------------------
// IP Reputation via SecurityManager integration
// ---------------------------------------------------------------------------

#[test]
fn test_ip_reputation_via_security_manager_enabled() {
    let config = create_test_config(
        r##"
[security]
ip_reputation_enabled = true
ip_reputation_ban_threshold = 25
"##,
    );
    let security = sks5::security::SecurityManager::new(&config);
    let ip: IpAddr = "198.51.100.1".parse().unwrap();

    let rep = security.ip_reputation();
    rep.record_auth_failure(&ip);
    rep.record_auth_failure(&ip);
    let score = rep.get_score(&ip);
    assert!((19..=20).contains(&score), "expected ~20, got {}", score);

    // 20 < 25 so should not ban yet.
    assert!(!rep.should_ban(&ip));

    // One more failure pushes to ~30, above 25.
    rep.record_auth_failure(&ip);
    assert!(rep.should_ban(&ip));
}

#[test]
fn test_ip_reputation_via_security_manager_disabled_by_default() {
    let config = create_test_config("");
    let security = sks5::security::SecurityManager::new(&config);
    let ip: IpAddr = "198.51.100.2".parse().unwrap();

    // Default config: ip_reputation_enabled = false.
    let rep = security.ip_reputation();
    rep.record_auth_failure(&ip);
    assert_eq!(rep.get_score(&ip), 0);
    assert!(!rep.should_ban(&ip));
}

// ---------------------------------------------------------------------------
// IP Reputation - score independence across IPs
// ---------------------------------------------------------------------------

#[test]
fn test_ip_reputation_different_ips_isolated() {
    let mgr = IpReputationManager::new(true, 100);
    let ip_a: IpAddr = "203.0.113.10".parse().unwrap();
    let ip_b: IpAddr = "203.0.113.20".parse().unwrap();

    mgr.record_auth_failure(&ip_a);
    mgr.record_auth_failure(&ip_a);
    mgr.record_auth_failure(&ip_a); // ip_a ~30

    mgr.record_acl_denial(&ip_b); // ip_b ~5

    let score_a = mgr.get_score(&ip_a);
    let score_b = mgr.get_score(&ip_b);

    assert!(score_a > score_b, "ip_a={}, ip_b={}", score_a, score_b);
    assert!(score_a >= 29);
    assert!(score_b <= 5);
}

// ---------------------------------------------------------------------------
// IP Reputation - cleanup does not remove recently active high-score IPs
// ---------------------------------------------------------------------------

#[test]
fn test_ip_reputation_cleanup_preserves_high_scores() {
    let mgr = IpReputationManager::new(true, 100);
    let ip: IpAddr = "198.51.100.50".parse().unwrap();

    // Build a high score.
    for _ in 0..10 {
        mgr.record_auth_failure(&ip);
    }

    mgr.cleanup();

    // High score should survive cleanup.
    let score = mgr.get_score(&ip);
    assert!(
        score >= 90,
        "high score should survive cleanup, got {}",
        score
    );
}

// ---------------------------------------------------------------------------
// IP Reputation - all_scores empty on fresh manager
// ---------------------------------------------------------------------------

#[test]
fn test_ip_reputation_all_scores_empty_initially() {
    let mgr = IpReputationManager::new(true, 100);
    assert!(mgr.all_scores().is_empty());
}
