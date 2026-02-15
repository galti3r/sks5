//! Validate that all commands used in the VHS demo tape and browser screenshots
//! actually work as expected. If a command is renamed, removed, or its output
//! format changes, this test breaks **before** the VHS/screenshots silently break.

use sks5::audit::AuditLogger;
use sks5::config::acl::ParsedAcl;
use sks5::config::types::{AclPolicyConfig, ShellPermissions, UserRole};
use sks5::demo::build_demo_config;
use sks5::proxy::ProxyEngine;
use sks5::quota::QuotaTracker;
use sks5::shell::commands::{execute, CommandResult};
use sks5::shell::context::ShellContext;
use sks5::shell::filesystem::VirtualFs;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// Build a `ShellContext` that mirrors what `alice` would see in demo mode.
fn demo_shell_context() -> (ShellContext, Arc<ProxyEngine>, Arc<QuotaTracker>) {
    let config = build_demo_config(0, 0, 0, "fakehash");
    let config = Arc::new(config);
    let audit = Arc::new(AuditLogger::new_noop());
    let pe = Arc::new(ProxyEngine::new(config.clone(), audit));
    let qt = Arc::new(QuotaTracker::new(&config.limits));

    // Restore alice's demo usage
    qt.restore_user_usage(
        "alice",
        1_288_490_189, // ~1.2 GB daily
        42,
        13_314_398_618, // ~12.4 GB monthly
        350,
        48_535_150_182, // ~45.2 GB total
    );

    // Register demo sessions
    let s1 = pe.register_session("alice", "github.com", 443, "10.0.1.42", "ssh");
    s1.bytes_up.store(15_728_640, Ordering::Relaxed);
    s1.bytes_down.store(148_897_792, Ordering::Relaxed);

    let s2 = pe.register_session("alice", "api.example.com", 8080, "10.0.1.42", "ssh");
    s2.bytes_up.store(2_097_152, Ordering::Relaxed);
    s2.bytes_down.store(8_388_608, Ordering::Relaxed);

    // Build ACL matching the demo config
    let acl = ParsedAcl::from_config(
        AclPolicyConfig::Deny,
        &[
            "*.example.com:443".to_string(),
            "*.github.com:443".to_string(),
            "httpbin.org:*".to_string(),
            "example.com:*".to_string(),
        ],
        &["*.internal:*".to_string(), "10.0.0.0/8:*".to_string()],
    )
    .unwrap();

    let alice_quota = config
        .users
        .iter()
        .find(|u| u.username == "alice")
        .and_then(|u| u.quotas.clone());

    let ctx = ShellContext {
        username: "alice".to_string(),
        auth_method: "password".to_string(),
        source_ip: "127.0.0.1".to_string(),
        role: UserRole::Admin,
        group: Some("developers".to_string()),
        permissions: ShellPermissions::default(),
        acl,
        colors: false,
        expires_at: None,
        max_bandwidth_kbps: 0,
        server_start_time: std::time::Instant::now(),
        bookmarks: HashMap::new(),
        aliases: HashMap::new(),
        ssh_key_fingerprint: None,
        proxy_engine: Some(pe.clone()),
        quota_tracker: Some(qt.clone()),
        quota_config: alice_quota,
    };

    (ctx, pe, qt)
}

/// Execute a single command string and return the CommandResult.
fn run_cmd(ctx: &mut ShellContext, fs: &mut VirtualFs, line: &str) -> CommandResult {
    let tokens: Vec<String> = line.split_whitespace().map(String::from).collect();
    if tokens.is_empty() {
        return CommandResult::empty();
    }
    let cmd = &tokens[0];
    let args: Vec<String> = tokens[1..].to_vec();
    let username = ctx.username.clone();
    execute(cmd, &args, fs, &username, "sks5-demo", Some(ctx))
}

// ---- Scenario contract tests ----

#[test]
fn demo_show_status() {
    let (mut ctx, _pe, _qt) = demo_shell_context();
    let mut fs = VirtualFs::new("alice", "sks5-demo");
    let r = run_cmd(&mut ctx, &mut fs, "show status");
    assert!(r.output.contains("User:"), "output: {}", r.output);
    assert!(r.output.contains("alice"), "output: {}", r.output);
    assert!(r.output.contains("Role:"), "output: {}", r.output);
    assert!(r.output.contains("admin"), "output: {}", r.output);
}

#[test]
fn demo_show_acl() {
    let (mut ctx, _pe, _qt) = demo_shell_context();
    let mut fs = VirtualFs::new("alice", "sks5-demo");
    let r = run_cmd(&mut ctx, &mut fs, "show acl");
    assert!(
        r.output.contains("deny"),
        "should show default deny: {}",
        r.output
    );
    assert!(
        r.output.contains("*.example.com:443"),
        "should show allow rule: {}",
        r.output
    );
}

#[test]
fn demo_show_quota() {
    let (mut ctx, _pe, _qt) = demo_shell_context();
    let mut fs = VirtualFs::new("alice", "sks5-demo");
    let r = run_cmd(&mut ctx, &mut fs, "show quota");
    assert!(
        r.output.contains("1.2 GB"),
        "daily usage ~1.2 GB: {}",
        r.output
    );
    assert!(
        r.output.contains("5.0 GB"),
        "daily limit 5 GB: {}",
        r.output
    );
}

#[test]
fn demo_show_connections() {
    let (mut ctx, _pe, _qt) = demo_shell_context();
    let mut fs = VirtualFs::new("alice", "sks5-demo");
    let r = run_cmd(&mut ctx, &mut fs, "show connections");
    // show connections returns either "Active connections: N" or "No active proxy connections"
    assert!(
        r.output.contains("connections"),
        "should mention connections: {}",
        r.output
    );
}

#[test]
fn demo_test_allowed() {
    let (mut ctx, _pe, _qt) = demo_shell_context();
    let mut fs = VirtualFs::new("alice", "sks5-demo");
    let r = run_cmd(&mut ctx, &mut fs, "test example.com:443");
    assert!(r.output.contains("ALLOWED"), "output: {}", r.output);
}

#[test]
fn demo_test_denied() {
    let (mut ctx, _pe, _qt) = demo_shell_context();
    let mut fs = VirtualFs::new("alice", "sks5-demo");
    let r = run_cmd(&mut ctx, &mut fs, "test blocked.internal:22");
    assert!(r.output.contains("DENIED"), "output: {}", r.output);
}

#[test]
fn demo_comment_is_noop() {
    let (mut ctx, _pe, _qt) = demo_shell_context();
    let mut fs = VirtualFs::new("alice", "sks5-demo");
    // The VHS tape uses `Type "# Test ACL rules"` — the shell receives "#" as the command
    let r = run_cmd(&mut ctx, &mut fs, "# this is a comment");
    assert!(
        r.output.is_empty(),
        "comment should produce no output: {:?}",
        r.output
    );
    assert!(!r.exit_requested);
}

#[test]
fn demo_bookmark_add_and_list() {
    let (mut ctx, _pe, _qt) = demo_shell_context();
    let mut fs = VirtualFs::new("alice", "sks5-demo");
    let r = run_cmd(&mut ctx, &mut fs, "bookmark add web example.com:443");
    assert!(
        r.output.contains("Added") || r.output.contains("Updated"),
        "bookmark add: {}",
        r.output
    );

    let r = run_cmd(&mut ctx, &mut fs, "bookmark list");
    assert!(
        r.output.contains("web"),
        "bookmark list should contain 'web': {}",
        r.output
    );
}

#[test]
fn demo_help() {
    let (mut ctx, _pe, _qt) = demo_shell_context();
    let mut fs = VirtualFs::new("alice", "sks5-demo");
    let r = run_cmd(&mut ctx, &mut fs, "help");
    assert!(
        r.output.contains("Available commands"),
        "help output: {}",
        r.output
    );
}

#[test]
fn demo_whoami() {
    let (mut ctx, _pe, _qt) = demo_shell_context();
    let mut fs = VirtualFs::new("alice", "sks5-demo");
    let r = run_cmd(&mut ctx, &mut fs, "whoami");
    assert!(r.output.contains("alice"), "whoami output: {}", r.output);
}

#[test]
fn demo_exit() {
    let (mut ctx, _pe, _qt) = demo_shell_context();
    let mut fs = VirtualFs::new("alice", "sks5-demo");
    let r = run_cmd(&mut ctx, &mut fs, "exit");
    assert!(r.exit_requested, "exit should request exit");
}
