use anyhow::{bail, Result};
use dialoguer::{Confirm, Input, MultiSelect, Password, Select};
use std::collections::HashMap;

use crate::config::types::*;

/// Users section: create, edit, remove users.
pub(crate) fn prompt_users_section(config: &mut AppConfig) -> Result<()> {
    loop {
        let mut items: Vec<String> = config
            .users
            .iter()
            .map(|u| {
                let auth = if u.password_hash.is_some() && !u.authorized_keys.is_empty() {
                    "pass+key"
                } else if u.password_hash.is_some() {
                    "pass"
                } else {
                    "key"
                };
                let shell = if u.allow_shell == Some(true) {
                    "shell"
                } else {
                    "no-shell"
                };
                let group = u.group.as_deref().unwrap_or("-");
                format!("  {} ({}, {}, group: {})", u.username, auth, shell, group)
            })
            .collect();

        items.push("  + Add new user".to_string());
        items.push("  Back to main menu".to_string());

        let sel = Select::new()
            .with_prompt("Users — select to edit or add")
            .items(&items)
            .default(items.len().saturating_sub(2))
            .interact()?;

        if sel == items.len() - 1 {
            break; // Back
        } else if sel == items.len() - 2 {
            prompt_new_user(config)?;
        } else {
            prompt_edit_user(config, sel)?;
        }
    }

    Ok(())
}

fn prompt_new_user(config: &mut AppConfig) -> Result<()> {
    eprintln!();
    let username: String = Input::new().with_prompt("Username").interact_text()?;

    if username.is_empty() {
        bail!("username must not be empty");
    }
    if config.users.iter().any(|u| u.username == username) {
        bail!("username '{}' already exists", username);
    }

    let (password_hash, authorized_keys) = prompt_auth()?;

    let allow_shell = Confirm::new()
        .with_prompt("Allow shell access?")
        .default(true)
        .interact()?;

    let mut user = UserConfig {
        username,
        password_hash,
        authorized_keys,
        allow_forwarding: true,
        allow_shell: Some(allow_shell),
        max_new_connections_per_minute: 0,
        max_bandwidth_kbps: 0,
        source_ips: Vec::new(),
        expires_at: None,
        upstream_proxy: None,
        acl: UserAclConfig::default(),
        totp_secret: None,
        totp_enabled: false,
        max_aggregate_bandwidth_kbps: 0,
        group: None,
        role: UserRole::User,
        shell_permissions: None,
        motd: None,
        quotas: None,
        time_access: None,
        auth_methods: None,
        idle_warning_secs: None,
        colors: None,
        connect_retry: None,
        connect_retry_delay_ms: None,
        aliases: HashMap::new(),
        max_connections: None,
        rate_limits: None,
    };

    if Confirm::new()
        .with_prompt("Configure advanced options for this user?")
        .default(false)
        .interact()?
    {
        prompt_user_advanced(&mut user, &[])?;
    }

    config.users.push(user);
    Ok(())
}

fn prompt_auth() -> Result<(Option<String>, Vec<String>)> {
    let auth_items = &["Password", "Public key", "Both"];
    let auth_method = Select::new()
        .with_prompt("Authentication method")
        .items(auth_items)
        .default(0)
        .interact()?;

    let password_hash = if auth_method == 0 || auth_method == 2 {
        let password = Password::new()
            .with_prompt("Password")
            .with_confirmation("Confirm password", "Passwords don't match")
            .interact()?;
        if password.len() < 8 {
            bail!("password must be at least 8 characters");
        }
        eprintln!("  Hashing password with Argon2id...");
        Some(crate::auth::password::hash_password(&password)?)
    } else {
        None
    };

    let authorized_keys = if auth_method == 1 || auth_method == 2 {
        let keys: String = Input::new()
            .with_prompt("Public key(s) (one per line, empty to skip)")
            .default(String::new())
            .allow_empty(true)
            .interact_text()?;
        let parsed: Vec<String> = keys
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        // Validate key format
        for key in &parsed {
            if !key.starts_with("ssh-") && !key.starts_with("ecdsa-") {
                eprintln!(
                    "  Warning: key doesn't look like a valid SSH public key: {}",
                    &key[..key.len().min(40)]
                );
            }
        }
        parsed
    } else {
        Vec::new()
    };

    Ok((password_hash, authorized_keys))
}

fn prompt_edit_user(config: &mut AppConfig, idx: usize) -> Result<()> {
    let group_names: Vec<String> = config.groups.iter().map(|g| g.name.clone()).collect();
    let user = &mut config.users[idx];

    let items = &[
        "Authentication (password, keys)",
        "Role & group",
        "Shell & forwarding",
        "Source IPs & expiration",
        "Bandwidth & connection limits",
        "Per-user ACL",
        "TOTP setup",
        "Quotas",
        "Time access restrictions",
        "Shell permissions (18 flags)",
        "Rate limits",
        "Aliases",
        "MOTD override",
        "Retry & miscellaneous",
        "Delete this user",
        "Back to user list",
    ];

    loop {
        let sel = Select::new()
            .with_prompt(format!("Editing user '{}' — select", user.username))
            .items(items)
            .default(items.len() - 1)
            .interact()?;

        match sel {
            0 => {
                let (pw, keys) = prompt_auth()?;
                user.password_hash = pw;
                user.authorized_keys = keys;
            }
            1 => prompt_role_group(user, &group_names)?,
            2 => prompt_shell_forwarding(user)?,
            3 => prompt_source_ips_expires(user)?,
            4 => prompt_bandwidth_limits(user)?,
            5 => prompt_user_acl(user)?,
            6 => prompt_totp(user)?,
            7 => prompt_quotas(user)?,
            8 => prompt_time_access(user)?,
            9 => prompt_shell_permissions(user)?,
            10 => prompt_rate_limits(user)?,
            11 => prompt_aliases(user)?,
            12 => prompt_user_motd(user)?,
            13 => prompt_misc(user)?,
            14 => {
                if Confirm::new()
                    .with_prompt(format!("Delete user '{}'?", user.username))
                    .default(false)
                    .interact()?
                {
                    config.users.remove(idx);
                    return Ok(());
                }
            }
            _ => break,
        }
    }

    Ok(())
}

fn prompt_user_advanced(user: &mut UserConfig, group_names: &[String]) -> Result<()> {
    prompt_role_group(user, group_names)?;
    prompt_source_ips_expires(user)?;
    prompt_bandwidth_limits(user)?;

    if Confirm::new()
        .with_prompt("Configure TOTP 2FA?")
        .default(false)
        .interact()?
    {
        prompt_totp(user)?;
    }
    if Confirm::new()
        .with_prompt("Configure quotas?")
        .default(false)
        .interact()?
    {
        prompt_quotas(user)?;
    }
    if Confirm::new()
        .with_prompt("Configure time access?")
        .default(false)
        .interact()?
    {
        prompt_time_access(user)?;
    }
    if Confirm::new()
        .with_prompt("Configure shell permissions?")
        .default(false)
        .interact()?
    {
        prompt_shell_permissions(user)?;
    }
    if Confirm::new()
        .with_prompt("Configure rate limits?")
        .default(false)
        .interact()?
    {
        prompt_rate_limits(user)?;
    }

    Ok(())
}

fn prompt_role_group(user: &mut UserConfig, group_names: &[String]) -> Result<()> {
    let roles = &["user", "admin"];
    let current = if user.role == UserRole::Admin { 1 } else { 0 };
    let role_sel = Select::new()
        .with_prompt("Role")
        .items(roles)
        .default(current)
        .interact()?;
    user.role = if role_sel == 0 {
        UserRole::User
    } else {
        UserRole::Admin
    };

    if !group_names.is_empty() {
        let mut items: Vec<String> = vec!["(none)".to_string()];
        items.extend(group_names.iter().cloned());
        let current_group = user
            .group
            .as_ref()
            .and_then(|g| group_names.iter().position(|n| n == g))
            .map(|i| i + 1)
            .unwrap_or(0);
        let sel = Select::new()
            .with_prompt("Group")
            .items(&items)
            .default(current_group)
            .interact()?;
        user.group = if sel == 0 {
            None
        } else {
            Some(group_names[sel - 1].clone())
        };
    }

    Ok(())
}

fn prompt_shell_forwarding(user: &mut UserConfig) -> Result<()> {
    user.allow_shell = Some(
        Confirm::new()
            .with_prompt("Allow shell access?")
            .default(user.allow_shell.unwrap_or(true))
            .interact()?,
    );

    user.allow_forwarding = Confirm::new()
        .with_prompt("Allow port forwarding (ssh -D, ssh -L)?")
        .default(user.allow_forwarding)
        .interact()?;

    user.colors = Some(
        Confirm::new()
            .with_prompt("Enable ANSI colors in shell?")
            .default(user.colors.unwrap_or(true))
            .interact()?,
    );

    Ok(())
}

fn prompt_source_ips_expires(user: &mut UserConfig) -> Result<()> {
    let ips: String = Input::new()
        .with_prompt("Allowed source IPs (comma-separated CIDRs, empty=any)")
        .default(
            user.source_ips
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        )
        .allow_empty(true)
        .interact_text()?;

    if ips.is_empty() {
        user.source_ips = Vec::new();
    } else {
        user.source_ips = ips
            .split(',')
            .map(|s| {
                s.trim()
                    .parse()
                    .map_err(|e| anyhow::anyhow!("invalid CIDR '{}': {}", s.trim(), e))
            })
            .collect::<Result<Vec<_>>>()?;
    }

    let expires: String = Input::new()
        .with_prompt("Expires at (ISO 8601, empty=never)")
        .default(user.expires_at.clone().unwrap_or_default())
        .allow_empty(true)
        .interact_text()?;

    user.expires_at = if expires.is_empty() {
        None
    } else {
        Some(expires)
    };

    Ok(())
}

fn prompt_bandwidth_limits(user: &mut UserConfig) -> Result<()> {
    user.max_bandwidth_kbps = Input::new()
        .with_prompt("Max bandwidth per connection (Kbps, 0=unlimited)")
        .default(user.max_bandwidth_kbps)
        .interact_text()?;

    user.max_aggregate_bandwidth_kbps = Input::new()
        .with_prompt("Max aggregate bandwidth (Kbps, 0=unlimited)")
        .default(user.max_aggregate_bandwidth_kbps)
        .interact_text()?;

    let max_conn: u32 = Input::new()
        .with_prompt("Max concurrent connections (0=unlimited)")
        .default(user.max_connections.unwrap_or(0))
        .interact_text()?;
    user.max_connections = if max_conn == 0 { None } else { Some(max_conn) };

    user.max_new_connections_per_minute = Input::new()
        .with_prompt("Max new connections per minute (0=unlimited)")
        .default(user.max_new_connections_per_minute)
        .interact_text()?;

    Ok(())
}

fn prompt_user_acl(user: &mut UserConfig) -> Result<()> {
    let inherit = Confirm::new()
        .with_prompt("Inherit global ACL rules?")
        .default(user.acl.inherit)
        .interact()?;
    user.acl.inherit = inherit;

    let policies = &["(inherit global)", "allow", "deny"];
    let current = match &user.acl.default_policy {
        None => 0,
        Some(p) if *p == AclPolicyConfig::Allow => 1,
        _ => 2,
    };
    let pol = Select::new()
        .with_prompt("Per-user default policy")
        .items(policies)
        .default(current)
        .interact()?;
    user.acl.default_policy = match pol {
        1 => Some(AclPolicyConfig::Allow),
        2 => Some(AclPolicyConfig::Deny),
        _ => None,
    };

    let deny: String = Input::new()
        .with_prompt("Deny rules (comma-separated)")
        .default(user.acl.deny.join(", "))
        .allow_empty(true)
        .interact_text()?;
    user.acl.deny = deny
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let allow: String = Input::new()
        .with_prompt("Allow rules (comma-separated)")
        .default(user.acl.allow.join(", "))
        .allow_empty(true)
        .interact_text()?;
    user.acl.allow = allow
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    Ok(())
}

fn prompt_totp(user: &mut UserConfig) -> Result<()> {
    user.totp_enabled = Confirm::new()
        .with_prompt("Enable TOTP 2FA?")
        .default(user.totp_enabled)
        .interact()?;

    if !user.totp_enabled {
        user.totp_secret = None;
        return Ok(());
    }

    let generate_new = user.totp_secret.is_none()
        || Confirm::new()
            .with_prompt("Generate new TOTP secret? (current will be replaced)")
            .default(false)
            .interact()?;

    if generate_new {
        // Generate a 20-byte random secret and encode as base32 via totp_rs
        let secret = totp_rs::Secret::generate_secret();
        let secret_b32 = secret.to_encoded().to_string();
        let secret_bytes = match secret.to_bytes() {
            Ok(b) => b,
            Err(e) => bail!("failed to decode generated TOTP secret: {e}"),
        };

        let totp = totp_rs::TOTP::new(
            totp_rs::Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
            Some("sks5".to_string()),
            user.username.clone(),
        )
        .map_err(|e| anyhow::anyhow!("failed to create TOTP: {e}"))?;

        let otpauth = totp.get_url();
        eprintln!("  TOTP Secret: {secret_b32}");
        eprintln!("  OTPAuth URL: {otpauth}");
        eprintln!("  Scan the URL as a QR code in your authenticator app.");

        // Verify a TOTP code
        let verify = Confirm::new()
            .with_prompt("Verify a TOTP code now?")
            .default(true)
            .interact()?;

        if verify {
            let code: String = Input::new()
                .with_prompt("Enter current 6-digit TOTP code")
                .interact_text()?;
            if code.len() == 6 && code.chars().all(|c| c.is_ascii_digit()) {
                match totp.check_current(&code) {
                    Ok(true) => eprintln!("  TOTP code verified successfully!"),
                    Ok(false) => {
                        eprintln!("  Warning: TOTP code did not match. Check your clock sync.");
                    }
                    Err(e) => eprintln!("  Warning: TOTP verification error: {e}"),
                }
            } else {
                eprintln!("  Warning: invalid code format (expected 6 digits).");
            }
        }

        user.totp_secret = Some(secret_b32);
    }

    Ok(())
}

fn prompt_quotas(user: &mut UserConfig) -> Result<()> {
    let q = user.quotas.get_or_insert_with(QuotaConfig::default);

    q.daily_bandwidth_bytes = Input::new()
        .with_prompt("Daily bandwidth limit (bytes, 0=unlimited)")
        .default(q.daily_bandwidth_bytes)
        .interact_text()?;

    q.monthly_bandwidth_bytes = Input::new()
        .with_prompt("Monthly bandwidth limit (bytes, 0=unlimited)")
        .default(q.monthly_bandwidth_bytes)
        .interact_text()?;

    q.total_bandwidth_bytes = Input::new()
        .with_prompt("Total bandwidth limit (bytes, 0=unlimited)")
        .default(q.total_bandwidth_bytes)
        .interact_text()?;

    q.bandwidth_per_hour_bytes = Input::new()
        .with_prompt("Bandwidth per hour (bytes, 0=unlimited)")
        .default(q.bandwidth_per_hour_bytes)
        .interact_text()?;

    q.daily_connection_limit = Input::new()
        .with_prompt("Daily connection limit (0=unlimited)")
        .default(q.daily_connection_limit)
        .interact_text()?;

    q.monthly_connection_limit = Input::new()
        .with_prompt("Monthly connection limit (0=unlimited)")
        .default(q.monthly_connection_limit)
        .interact_text()?;

    // If all zeros, remove the quota config
    if q.daily_bandwidth_bytes == 0
        && q.monthly_bandwidth_bytes == 0
        && q.total_bandwidth_bytes == 0
        && q.bandwidth_per_hour_bytes == 0
        && q.daily_connection_limit == 0
        && q.monthly_connection_limit == 0
    {
        user.quotas = None;
    }

    Ok(())
}

fn prompt_time_access(user: &mut UserConfig) -> Result<()> {
    let ta = user
        .time_access
        .get_or_insert_with(TimeAccessConfig::default);

    let hours: String = Input::new()
        .with_prompt("Access hours (HH:MM-HH:MM, empty=24h)")
        .default(ta.access_hours.clone().unwrap_or_default())
        .allow_empty(true)
        .interact_text()?;
    ta.access_hours = if hours.is_empty() { None } else { Some(hours) };

    let all_days = &["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
    let defaults: Vec<bool> = all_days
        .iter()
        .map(|d| ta.access_days.is_empty() || ta.access_days.contains(&d.to_string()))
        .collect();

    let selected = MultiSelect::new()
        .with_prompt("Access days (space to toggle, enter to confirm)")
        .items(all_days)
        .defaults(&defaults)
        .interact()?;

    ta.access_days = if selected.len() == 7 {
        Vec::new() // All days = no restriction
    } else {
        selected.iter().map(|&i| all_days[i].to_string()).collect()
    };

    ta.timezone = Input::new()
        .with_prompt("Timezone (IANA)")
        .default(ta.timezone.clone())
        .interact_text()?;

    // If no restrictions, remove
    if ta.access_hours.is_none() && ta.access_days.is_empty() && ta.timezone == "UTC" {
        user.time_access = None;
    }

    Ok(())
}

fn prompt_shell_permissions(user: &mut UserConfig) -> Result<()> {
    let sp = user
        .shell_permissions
        .get_or_insert_with(ShellPermissions::default);

    let names: Vec<&str> = vec![
        "show_connections",
        "show_bandwidth",
        "show_acl",
        "show_status",
        "show_history",
        "show_fingerprint",
        "test_command",
        "ping_command",
        "resolve_command",
        "bookmark_command",
        "alias_command",
        "show_quota",
        "show_role",
        "show_group",
        "show_expires",
        "show_source_ip",
        "show_auth_method",
        "show_uptime",
    ];
    let current_values = vec![
        sp.show_connections,
        sp.show_bandwidth,
        sp.show_acl,
        sp.show_status,
        sp.show_history,
        sp.show_fingerprint,
        sp.test_command,
        sp.ping_command,
        sp.resolve_command,
        sp.bookmark_command,
        sp.alias_command,
        sp.show_quota,
        sp.show_role,
        sp.show_group,
        sp.show_expires,
        sp.show_source_ip,
        sp.show_auth_method,
        sp.show_uptime,
    ];

    let selected = MultiSelect::new()
        .with_prompt("Shell permissions (space to toggle, selected = enabled)")
        .items(&names)
        .defaults(&current_values)
        .interact()?;

    let enabled: Vec<bool> = (0..names.len()).map(|i| selected.contains(&i)).collect();

    sp.show_connections = enabled[0];
    sp.show_bandwidth = enabled[1];
    sp.show_acl = enabled[2];
    sp.show_status = enabled[3];
    sp.show_history = enabled[4];
    sp.show_fingerprint = enabled[5];
    sp.test_command = enabled[6];
    sp.ping_command = enabled[7];
    sp.resolve_command = enabled[8];
    sp.bookmark_command = enabled[9];
    sp.alias_command = enabled[10];
    sp.show_quota = enabled[11];
    sp.show_role = enabled[12];
    sp.show_group = enabled[13];
    sp.show_expires = enabled[14];
    sp.show_source_ip = enabled[15];
    sp.show_auth_method = enabled[16];
    sp.show_uptime = enabled[17];

    // If all true, remove the override (inherit defaults)
    if enabled.iter().all(|&v| v) {
        user.shell_permissions = None;
    }

    Ok(())
}

fn prompt_rate_limits(user: &mut UserConfig) -> Result<()> {
    let rl = user
        .rate_limits
        .get_or_insert_with(RateLimitsConfig::default);

    rl.connections_per_second = Input::new()
        .with_prompt("Max new connections per second (0=unlimited)")
        .default(rl.connections_per_second)
        .interact_text()?;

    rl.connections_per_minute = Input::new()
        .with_prompt("Max new connections per minute (0=unlimited)")
        .default(rl.connections_per_minute)
        .interact_text()?;

    rl.connections_per_hour = Input::new()
        .with_prompt("Max new connections per hour (0=unlimited)")
        .default(rl.connections_per_hour)
        .interact_text()?;

    if rl.connections_per_second == 0
        && rl.connections_per_minute == 0
        && rl.connections_per_hour == 0
    {
        user.rate_limits = None;
    }

    Ok(())
}

fn prompt_aliases(user: &mut UserConfig) -> Result<()> {
    loop {
        let mut items: Vec<String> = user
            .aliases
            .iter()
            .map(|(k, v)| format!("  {} = {}", k, v))
            .collect();
        items.push("  + Add alias".to_string());
        items.push("  Clear all aliases".to_string());
        items.push("  Back".to_string());

        let sel = Select::new()
            .with_prompt("Aliases")
            .items(&items)
            .default(items.len() - 1)
            .interact()?;

        if sel == items.len() - 1 {
            break;
        } else if sel == items.len() - 2 {
            user.aliases.clear();
            eprintln!("  All aliases cleared.");
        } else if sel == items.len() - 3 {
            let name: String = Input::new().with_prompt("Alias name").interact_text()?;
            let cmd: String = Input::new().with_prompt("Command").interact_text()?;
            user.aliases.insert(name, cmd);
        } else {
            // Delete selected alias
            let key = user.aliases.keys().nth(sel).cloned();
            if let Some(key) = key {
                if Confirm::new()
                    .with_prompt(format!("Delete alias '{}'?", key))
                    .default(false)
                    .interact()?
                {
                    user.aliases.remove(&key);
                }
            }
        }
    }

    Ok(())
}

fn prompt_user_motd(user: &mut UserConfig) -> Result<()> {
    let override_motd = Confirm::new()
        .with_prompt("Override global MOTD for this user?")
        .default(user.motd.is_some())
        .interact()?;

    if !override_motd {
        user.motd = None;
        return Ok(());
    }

    let motd = user.motd.get_or_insert_with(MotdConfig::default);

    motd.enabled = Confirm::new()
        .with_prompt("Enable MOTD?")
        .default(motd.enabled)
        .interact()?;

    motd.colors = Confirm::new()
        .with_prompt("Enable MOTD colors?")
        .default(motd.colors)
        .interact()?;

    let template: String = Input::new()
        .with_prompt("MOTD template (empty=built-in default)")
        .default(motd.template.clone().unwrap_or_default())
        .allow_empty(true)
        .interact_text()?;
    motd.template = if template.is_empty() {
        None
    } else {
        Some(template)
    };

    Ok(())
}

fn prompt_misc(user: &mut UserConfig) -> Result<()> {
    let idle: u64 = Input::new()
        .with_prompt("Idle warning (seconds before disconnect, 0=inherit)")
        .default(user.idle_warning_secs.unwrap_or(0))
        .interact_text()?;
    user.idle_warning_secs = if idle == 0 { None } else { Some(idle) };

    let retry: u32 = Input::new()
        .with_prompt("Connect retry attempts (0=inherit)")
        .default(user.connect_retry.unwrap_or(0))
        .interact_text()?;
    user.connect_retry = if retry == 0 { None } else { Some(retry) };

    if user.connect_retry.is_some() {
        let delay: u64 = Input::new()
            .with_prompt("Connect retry delay (ms)")
            .default(user.connect_retry_delay_ms.unwrap_or(1000))
            .interact_text()?;
        user.connect_retry_delay_ms = Some(delay);
    }

    let upstream: String = Input::new()
        .with_prompt("Per-user upstream proxy URL (empty=inherit)")
        .default(user.upstream_proxy.clone().unwrap_or_default())
        .allow_empty(true)
        .interact_text()?;
    user.upstream_proxy = if upstream.is_empty() {
        None
    } else {
        Some(upstream)
    };

    // Auth methods
    let configure_auth_methods = Confirm::new()
        .with_prompt("Configure auth method chain?")
        .default(user.auth_methods.is_some())
        .interact()?;

    if configure_auth_methods {
        let methods = &["password", "pubkey"];
        let defaults: Vec<bool> = methods
            .iter()
            .map(|m| {
                user.auth_methods
                    .as_ref()
                    .map(|v| v.contains(&m.to_string()))
                    .unwrap_or(true)
            })
            .collect();
        let selected = MultiSelect::new()
            .with_prompt("Required auth methods (order: pubkey first, then password)")
            .items(methods)
            .defaults(&defaults)
            .interact()?;
        let chain: Vec<String> = selected.iter().map(|&i| methods[i].to_string()).collect();
        user.auth_methods = if chain.is_empty() { None } else { Some(chain) };
    } else {
        user.auth_methods = None;
    }

    Ok(())
}
