use anyhow::Result;
use dialoguer::{Confirm, Input, Select};

use crate::config::types::*;

/// Security section: ban, IP guard, TOTP, IP reputation, Argon2.
pub(crate) fn prompt_security_section(config: &mut AppConfig) -> Result<()> {
    let items = &[
        "Autoban settings",
        "IP guard & source IP restrictions",
        "TOTP enforcement",
        "IP reputation",
        "Argon2 password hashing parameters",
        "Rate limiter housekeeping",
        "Back to main menu",
    ];

    loop {
        let sel = Select::new()
            .with_prompt("Security — configure")
            .items(items)
            .default(0)
            .interact()?;

        match sel {
            0 => prompt_autoban(config)?,
            1 => prompt_ip_guard(config)?,
            2 => prompt_totp_enforcement(config)?,
            3 => prompt_ip_reputation(config)?,
            4 => prompt_argon2(config)?,
            5 => prompt_rate_limiter(config)?,
            _ => break,
        }
    }

    Ok(())
}

fn prompt_autoban(config: &mut AppConfig) -> Result<()> {
    config.security.ban_enabled = Confirm::new()
        .with_prompt("Enable autoban (block IPs after failed auth)?")
        .default(config.security.ban_enabled)
        .interact()?;

    if config.security.ban_enabled {
        config.security.ban_threshold = Input::new()
            .with_prompt("Ban threshold (failed attempts)")
            .default(config.security.ban_threshold)
            .interact_text()?;

        config.security.ban_window = Input::new()
            .with_prompt("Ban window (seconds)")
            .default(config.security.ban_window)
            .interact_text()?;

        config.security.ban_duration = Input::new()
            .with_prompt("Ban duration (seconds)")
            .default(config.security.ban_duration)
            .interact_text()?;

        let whitelist: String = Input::new()
            .with_prompt("Ban whitelist (comma-separated IPs/CIDRs, empty=none)")
            .default(config.security.ban_whitelist.join(", "))
            .allow_empty(true)
            .interact_text()?;
        config.security.ban_whitelist = whitelist
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }

    Ok(())
}

fn prompt_ip_guard(config: &mut AppConfig) -> Result<()> {
    config.security.ip_guard_enabled = Confirm::new()
        .with_prompt("Enable IP guard (block private/internal IPs)?")
        .default(config.security.ip_guard_enabled)
        .interact()?;

    let source_ips: String = Input::new()
        .with_prompt("Allowed source IPs (comma-separated CIDRs, empty=all)")
        .default(
            config
                .security
                .allowed_source_ips
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        )
        .allow_empty(true)
        .interact_text()?;

    if source_ips.is_empty() {
        config.security.allowed_source_ips = Vec::new();
    } else {
        config.security.allowed_source_ips = source_ips
            .split(',')
            .map(|s| {
                s.trim()
                    .parse()
                    .map_err(|e| anyhow::anyhow!("invalid CIDR '{}': {}", s.trim(), e))
            })
            .collect::<Result<Vec<_>>>()?;
    }

    config.security.max_new_connections_per_ip_per_minute = Input::new()
        .with_prompt("Max new connections per IP per minute (0=unlimited)")
        .default(config.security.max_new_connections_per_ip_per_minute)
        .interact_text()?;

    Ok(())
}

fn prompt_totp_enforcement(config: &mut AppConfig) -> Result<()> {
    let protocols = &["ssh", "socks5"];
    let defaults: Vec<bool> = protocols
        .iter()
        .map(|p| config.security.totp_required_for.contains(&p.to_string()))
        .collect();

    eprintln!("  TOTP can be enforced globally for specific protocols.");
    eprintln!("  Per-user totp_enabled still applies regardless.");

    let selected = dialoguer::MultiSelect::new()
        .with_prompt("Require TOTP for protocols (space to toggle)")
        .items(protocols)
        .defaults(&defaults)
        .interact()?;

    config.security.totp_required_for =
        selected.iter().map(|&i| protocols[i].to_string()).collect();

    Ok(())
}

fn prompt_ip_reputation(config: &mut AppConfig) -> Result<()> {
    config.security.ip_reputation_enabled = Confirm::new()
        .with_prompt("Enable IP reputation scoring?")
        .default(config.security.ip_reputation_enabled)
        .interact()?;

    if config.security.ip_reputation_enabled {
        config.security.ip_reputation_ban_threshold = Input::new()
            .with_prompt("Reputation auto-ban threshold (0=scoring only)")
            .default(config.security.ip_reputation_ban_threshold)
            .interact_text()?;
    }

    Ok(())
}

fn prompt_argon2(config: &mut AppConfig) -> Result<()> {
    eprintln!("  Argon2id parameters for password hashing.");
    eprintln!("  OWASP recommends: m=19456 (19 MiB), t=2, p=1");

    config.security.argon2_memory_cost = Input::new()
        .with_prompt("Argon2 memory cost (KiB)")
        .default(config.security.argon2_memory_cost)
        .interact_text()?;

    config.security.argon2_time_cost = Input::new()
        .with_prompt("Argon2 time cost (iterations)")
        .default(config.security.argon2_time_cost)
        .interact_text()?;

    config.security.argon2_parallelism = Input::new()
        .with_prompt("Argon2 parallelism (lanes)")
        .default(config.security.argon2_parallelism)
        .interact_text()?;

    Ok(())
}

fn prompt_rate_limiter(config: &mut AppConfig) -> Result<()> {
    config.security.rate_limit_cleanup_interval = Input::new()
        .with_prompt("Rate limiter cleanup interval (seconds)")
        .default(config.security.rate_limit_cleanup_interval)
        .interact_text()?;

    config.security.rate_limit_max_ips = Input::new()
        .with_prompt("Max IPs tracked by rate limiter")
        .default(config.security.rate_limit_max_ips)
        .interact_text()?;

    config.security.rate_limit_max_users = Input::new()
        .with_prompt("Max users tracked by rate limiter")
        .default(config.security.rate_limit_max_users)
        .interact_text()?;

    Ok(())
}

/// ACL section: global default policy, allow/deny rules.
pub(crate) fn prompt_acl_section(config: &mut AppConfig) -> Result<()> {
    let policies = &[
        "allow — permit all, block specific (default)",
        "deny — block all, permit specific (whitelist)",
    ];
    let current = if config.acl.default_policy == AclPolicyConfig::Deny {
        1
    } else {
        0
    };

    let policy = Select::new()
        .with_prompt("Default ACL policy")
        .items(policies)
        .default(current)
        .interact()?;

    config.acl.default_policy = if policy == 0 {
        AclPolicyConfig::Allow
    } else {
        AclPolicyConfig::Deny
    };

    let deny: String = Input::new()
        .with_prompt("Deny rules (comma-separated, e.g. '169.254.169.254:*,10.0.0.0/8:*')")
        .default(config.acl.deny.join(", "))
        .allow_empty(true)
        .interact_text()?;

    config.acl.deny = deny
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let allow: String = Input::new()
        .with_prompt("Allow rules (comma-separated, e.g. '*:443,*:80')")
        .default(config.acl.allow.join(", "))
        .allow_empty(true)
        .interact_text()?;

    config.acl.allow = allow
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    Ok(())
}
