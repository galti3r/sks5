use anyhow::Result;
use dialoguer::{Confirm, Input, MultiSelect, Select};
use std::path::PathBuf;

use crate::config::types::*;

/// Groups section.
pub(crate) fn prompt_groups_section(config: &mut AppConfig) -> Result<()> {
    loop {
        let mut items: Vec<String> = config
            .groups
            .iter()
            .map(|g| {
                let members = config
                    .users
                    .iter()
                    .filter(|u| u.group.as_deref() == Some(&g.name))
                    .count();
                format!("  {} ({} members)", g.name, members)
            })
            .collect();
        items.push("  + Add new group".to_string());
        items.push("  Assign users to groups".to_string());
        items.push("  Back to main menu".to_string());

        let sel = Select::new()
            .with_prompt("Groups — select to edit or add")
            .items(&items)
            .default(items.len() - 1)
            .interact()?;

        if sel == items.len() - 1 {
            break;
        } else if sel == items.len() - 2 {
            assign_users_to_groups(config)?;
        } else if sel == items.len() - 3 {
            prompt_new_group(config)?;
        } else {
            prompt_edit_group(config, sel)?;
        }
    }

    Ok(())
}

fn prompt_new_group(config: &mut AppConfig) -> Result<()> {
    let name: String = Input::new().with_prompt("Group name").interact_text()?;

    if config.groups.iter().any(|g| g.name == name) {
        eprintln!("  Group '{}' already exists.", name);
        return Ok(());
    }

    let max_bw: u64 = Input::new()
        .with_prompt("Max bandwidth per user (Kbps, 0=unlimited)")
        .default(0u64)
        .interact_text()?;

    let max_conn: u32 = Input::new()
        .with_prompt("Max connections per user (0=unlimited)")
        .default(0u32)
        .interact_text()?;

    config.groups.push(GroupConfig {
        name,
        acl: UserAclConfig::default(),
        max_connections_per_user: if max_conn > 0 { Some(max_conn) } else { None },
        max_bandwidth_kbps: if max_bw > 0 { Some(max_bw) } else { None },
        max_aggregate_bandwidth_kbps: None,
        max_new_connections_per_minute: None,
        allow_shell: None,
        shell_permissions: None,
        motd: None,
        quotas: None,
        time_access: None,
        auth_methods: None,
        idle_warning_secs: None,
        role: None,
        colors: None,
        connect_retry: None,
        connect_retry_delay_ms: None,
        rate_limits: None,
    });

    Ok(())
}

fn prompt_edit_group(config: &mut AppConfig, idx: usize) -> Result<()> {
    let group = &mut config.groups[idx];

    let items = &[
        "Bandwidth & connection limits",
        "Shell permissions",
        "Rate limits",
        "ACL",
        "Quotas",
        "Time access",
        "MOTD override",
        "Role & shell defaults",
        "Delete group",
        "Back",
    ];

    loop {
        let sel = Select::new()
            .with_prompt(format!("Group '{}' — configure", group.name))
            .items(items)
            .default(items.len() - 1)
            .interact()?;

        match sel {
            0 => {
                let bw: u64 = Input::new()
                    .with_prompt("Max bandwidth per user (Kbps, 0=unlimited)")
                    .default(group.max_bandwidth_kbps.unwrap_or(0))
                    .interact_text()?;
                group.max_bandwidth_kbps = if bw > 0 { Some(bw) } else { None };

                let agg: u64 = Input::new()
                    .with_prompt("Max aggregate bandwidth (Kbps, 0=unlimited)")
                    .default(group.max_aggregate_bandwidth_kbps.unwrap_or(0))
                    .interact_text()?;
                group.max_aggregate_bandwidth_kbps = if agg > 0 { Some(agg) } else { None };

                let conn: u32 = Input::new()
                    .with_prompt("Max connections per user (0=unlimited)")
                    .default(group.max_connections_per_user.unwrap_or(0))
                    .interact_text()?;
                group.max_connections_per_user = if conn > 0 { Some(conn) } else { None };

                let rate: u32 = Input::new()
                    .with_prompt("Max new conn/min (0=unlimited)")
                    .default(group.max_new_connections_per_minute.unwrap_or(0))
                    .interact_text()?;
                group.max_new_connections_per_minute = if rate > 0 { Some(rate) } else { None };
            }
            1 => {
                let sp = group
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
                let vals = vec![
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
                    .with_prompt("Shell permissions (selected = enabled)")
                    .items(&names)
                    .defaults(&vals)
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
                if enabled.iter().all(|&v| v) {
                    group.shell_permissions = None;
                }
            }
            2 => {
                let rl = group
                    .rate_limits
                    .get_or_insert_with(RateLimitsConfig::default);
                rl.connections_per_second = Input::new()
                    .with_prompt("Conn/second (0=unlimited)")
                    .default(rl.connections_per_second)
                    .interact_text()?;
                rl.connections_per_minute = Input::new()
                    .with_prompt("Conn/minute (0=unlimited)")
                    .default(rl.connections_per_minute)
                    .interact_text()?;
                rl.connections_per_hour = Input::new()
                    .with_prompt("Conn/hour (0=unlimited)")
                    .default(rl.connections_per_hour)
                    .interact_text()?;
                if rl.connections_per_second == 0
                    && rl.connections_per_minute == 0
                    && rl.connections_per_hour == 0
                {
                    group.rate_limits = None;
                }
            }
            3 => {
                let acl = &mut group.acl;
                let policies = &["(inherit global)", "allow", "deny"];
                let cur = match &acl.default_policy {
                    None => 0,
                    Some(p) if *p == AclPolicyConfig::Allow => 1,
                    _ => 2,
                };
                let p = Select::new()
                    .with_prompt("Default policy")
                    .items(policies)
                    .default(cur)
                    .interact()?;
                acl.default_policy = match p {
                    1 => Some(AclPolicyConfig::Allow),
                    2 => Some(AclPolicyConfig::Deny),
                    _ => None,
                };
                let deny: String = Input::new()
                    .with_prompt("Deny rules")
                    .default(acl.deny.join(", "))
                    .allow_empty(true)
                    .interact_text()?;
                acl.deny = deny
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                let allow: String = Input::new()
                    .with_prompt("Allow rules")
                    .default(acl.allow.join(", "))
                    .allow_empty(true)
                    .interact_text()?;
                acl.allow = allow
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            4 => {
                let q = group.quotas.get_or_insert_with(QuotaConfig::default);
                q.daily_bandwidth_bytes = Input::new()
                    .with_prompt("Daily BW (bytes, 0=unlimited)")
                    .default(q.daily_bandwidth_bytes)
                    .interact_text()?;
                q.monthly_bandwidth_bytes = Input::new()
                    .with_prompt("Monthly BW (bytes, 0=unlimited)")
                    .default(q.monthly_bandwidth_bytes)
                    .interact_text()?;
                q.total_bandwidth_bytes = Input::new()
                    .with_prompt("Total BW (bytes, 0=unlimited)")
                    .default(q.total_bandwidth_bytes)
                    .interact_text()?;
                q.daily_connection_limit = Input::new()
                    .with_prompt("Daily conns (0=unlimited)")
                    .default(q.daily_connection_limit)
                    .interact_text()?;
                q.monthly_connection_limit = Input::new()
                    .with_prompt("Monthly conns (0=unlimited)")
                    .default(q.monthly_connection_limit)
                    .interact_text()?;
                if q.daily_bandwidth_bytes == 0
                    && q.monthly_bandwidth_bytes == 0
                    && q.total_bandwidth_bytes == 0
                    && q.daily_connection_limit == 0
                    && q.monthly_connection_limit == 0
                    && q.bandwidth_per_hour_bytes == 0
                {
                    group.quotas = None;
                }
            }
            5 => {
                let ta = group
                    .time_access
                    .get_or_insert_with(TimeAccessConfig::default);
                let hours: String = Input::new()
                    .with_prompt("Access hours (HH:MM-HH:MM, empty=24h)")
                    .default(ta.access_hours.clone().unwrap_or_default())
                    .allow_empty(true)
                    .interact_text()?;
                ta.access_hours = if hours.is_empty() { None } else { Some(hours) };
                if ta.access_hours.is_none() && ta.access_days.is_empty() {
                    group.time_access = None;
                }
            }
            6 => {
                let m = group.motd.get_or_insert_with(MotdConfig::default);
                m.enabled = Confirm::new()
                    .with_prompt("Enable MOTD?")
                    .default(m.enabled)
                    .interact()?;
                m.colors = Confirm::new()
                    .with_prompt("Colors?")
                    .default(m.colors)
                    .interact()?;
                let t: String = Input::new()
                    .with_prompt("Template (empty=default)")
                    .default(m.template.clone().unwrap_or_default())
                    .allow_empty(true)
                    .interact_text()?;
                m.template = if t.is_empty() { None } else { Some(t) };
            }
            7 => {
                let roles = &["(inherit)", "user", "admin"];
                let cur = match &group.role {
                    None => 0,
                    Some(UserRole::User) => 1,
                    Some(UserRole::Admin) => 2,
                };
                let r = Select::new()
                    .with_prompt("Default role")
                    .items(roles)
                    .default(cur)
                    .interact()?;
                group.role = match r {
                    1 => Some(UserRole::User),
                    2 => Some(UserRole::Admin),
                    _ => None,
                };

                let shell = Select::new()
                    .with_prompt("Allow shell?")
                    .items(["(inherit)", "yes", "no"])
                    .default(match group.allow_shell {
                        None => 0,
                        Some(true) => 1,
                        Some(false) => 2,
                    })
                    .interact()?;
                group.allow_shell = match shell {
                    1 => Some(true),
                    2 => Some(false),
                    _ => None,
                };
            }
            8 => {
                let name = group.name.clone();
                if Confirm::new()
                    .with_prompt(format!("Delete group '{name}'?"))
                    .default(false)
                    .interact()?
                {
                    // Unassign users
                    for u in config.users.iter_mut() {
                        if u.group.as_deref() == Some(&name) {
                            u.group = None;
                        }
                    }
                    config.groups.remove(idx);
                    return Ok(());
                }
            }
            _ => break,
        }
    }

    Ok(())
}

fn assign_users_to_groups(config: &mut AppConfig) -> Result<()> {
    if config.groups.is_empty() {
        eprintln!("  No groups defined. Add a group first.");
        return Ok(());
    }

    let group_names: Vec<&str> = config.groups.iter().map(|g| g.name.as_str()).collect();

    for user in config.users.iter_mut() {
        let mut items: Vec<String> = vec!["(none)".to_string()];
        items.extend(group_names.iter().map(|g| g.to_string()));
        let current = user
            .group
            .as_ref()
            .and_then(|g| group_names.iter().position(|n| *n == g.as_str()))
            .map(|i| i + 1)
            .unwrap_or(0);

        let sel = Select::new()
            .with_prompt(format!("Group for '{}'", user.username))
            .items(&items)
            .default(current)
            .interact()?;

        user.group = if sel == 0 {
            None
        } else {
            Some(group_names[sel - 1].to_string())
        };
    }

    Ok(())
}

/// GeoIP section.
pub(crate) fn prompt_geoip_section(config: &mut AppConfig) -> Result<()> {
    config.geoip.enabled = Confirm::new()
        .with_prompt("Enable GeoIP filtering?")
        .default(config.geoip.enabled)
        .interact()?;

    if !config.geoip.enabled {
        return Ok(());
    }

    let db_path: String = Input::new()
        .with_prompt("GeoIP database path (.mmdb)")
        .default(
            config
                .geoip
                .database_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "GeoLite2-Country.mmdb".to_string()),
        )
        .interact_text()?;
    config.geoip.database_path = Some(PathBuf::from(db_path));

    let allowed: String = Input::new()
        .with_prompt("Allowed countries (ISO codes, comma-separated, empty=all)")
        .default(config.geoip.allowed_countries.join(", "))
        .allow_empty(true)
        .interact_text()?;
    config.geoip.allowed_countries = allowed
        .split(',')
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty())
        .collect();

    let denied: String = Input::new()
        .with_prompt("Denied countries (ISO codes, comma-separated)")
        .default(config.geoip.denied_countries.join(", "))
        .allow_empty(true)
        .interact_text()?;
    config.geoip.denied_countries = denied
        .split(',')
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty())
        .collect();

    config.geoip.fail_closed = Confirm::new()
        .with_prompt("Fail closed (deny on lookup failure)?")
        .default(config.geoip.fail_closed)
        .interact()?;

    Ok(())
}

/// Webhooks section.
pub(crate) fn prompt_webhooks_section(config: &mut AppConfig) -> Result<()> {
    loop {
        let mut items: Vec<String> = config
            .webhooks
            .iter()
            .map(|w| format!("  {} ({} events)", w.url, w.events.len()))
            .collect();
        items.push("  + Add webhook".to_string());
        items.push("  Back to main menu".to_string());

        let sel = Select::new()
            .with_prompt("Webhooks")
            .items(&items)
            .default(items.len() - 1)
            .interact()?;

        if sel == items.len() - 1 {
            break;
        } else if sel == items.len() - 2 {
            let url: String = Input::new().with_prompt("Webhook URL").interact_text()?;
            let available_events = &[
                "auth_success",
                "auth_failure",
                "connection_open",
                "connection_close",
                "ban",
            ];
            let selected = MultiSelect::new()
                .with_prompt("Events (space to select)")
                .items(available_events)
                .interact()?;
            let events: Vec<String> = selected
                .iter()
                .map(|&i| available_events[i].to_string())
                .collect();
            let secret: String = Input::new()
                .with_prompt("HMAC secret (empty=none)")
                .default(String::new())
                .allow_empty(true)
                .interact_text()?;
            let format_options = &["generic", "slack", "discord", "custom"];
            let format_sel = Select::new()
                .with_prompt("Payload format")
                .items(format_options)
                .default(0)
                .interact()?;
            let format = match format_sel {
                1 => crate::config::types::WebhookFormat::Slack,
                2 => crate::config::types::WebhookFormat::Discord,
                3 => crate::config::types::WebhookFormat::Custom,
                _ => crate::config::types::WebhookFormat::Generic,
            };
            let template = if format == crate::config::types::WebhookFormat::Custom {
                let t: String = Input::new()
                    .with_prompt("Custom template (use {event_type}, {username}, {summary}, etc.)")
                    .interact_text()?;
                Some(t)
            } else {
                None
            };
            config.webhooks.push(WebhookConfig {
                url,
                events,
                secret: if secret.is_empty() {
                    None
                } else {
                    Some(secret)
                },
                format,
                template,
                allow_private_ips: false,
                max_retries: 3,
                retry_delay_ms: 1000,
                max_retry_delay_ms: 30000,
            });
        } else {
            // Edit/delete existing webhook
            if Confirm::new()
                .with_prompt(format!("Delete webhook '{}'?", config.webhooks[sel].url))
                .default(false)
                .interact()?
            {
                config.webhooks.remove(sel);
            }
        }
    }

    Ok(())
}

/// Alerting section.
pub(crate) fn prompt_alerting_section(config: &mut AppConfig) -> Result<()> {
    config.alerting.enabled = Confirm::new()
        .with_prompt("Enable alerting?")
        .default(config.alerting.enabled)
        .interact()?;

    if !config.alerting.enabled {
        return Ok(());
    }

    loop {
        let mut items: Vec<String> = config
            .alerting
            .rules
            .iter()
            .map(|r| {
                format!(
                    "  {} ({})",
                    r.name,
                    format!("{:?}", r.condition).to_lowercase()
                )
            })
            .collect();
        items.push("  + Add alert rule".to_string());
        items.push("  Back".to_string());

        let sel = Select::new()
            .with_prompt("Alert rules")
            .items(&items)
            .default(items.len() - 1)
            .interact()?;

        if sel == items.len() - 1 {
            break;
        } else if sel == items.len() - 2 {
            let name: String = Input::new().with_prompt("Rule name").interact_text()?;
            let conditions = &[
                "bandwidth_exceeded",
                "connections_exceeded",
                "auth_failures",
                "monthly_bandwidth_exceeded",
                "hourly_bandwidth_exceeded",
            ];
            let cond_idx = Select::new()
                .with_prompt("Condition")
                .items(conditions)
                .default(0)
                .interact()?;
            let condition = match cond_idx {
                0 => AlertCondition::BandwidthExceeded,
                1 => AlertCondition::ConnectionsExceeded,
                2 => AlertCondition::AuthFailures,
                3 => AlertCondition::MonthlyBandwidthExceeded,
                _ => AlertCondition::HourlyBandwidthExceeded,
            };
            let threshold: u64 = Input::new()
                .with_prompt("Threshold")
                .default(100u64)
                .interact_text()?;
            let window: u64 = Input::new()
                .with_prompt("Window (seconds)")
                .default(3600u64)
                .interact_text()?;
            let webhook: String = Input::new()
                .with_prompt("Webhook URL (empty=none)")
                .default(String::new())
                .allow_empty(true)
                .interact_text()?;
            config.alerting.rules.push(AlertRule {
                name,
                condition,
                threshold,
                window_secs: window,
                users: Vec::new(),
                webhook_url: if webhook.is_empty() {
                    None
                } else {
                    Some(webhook)
                },
            });
        } else if Confirm::new()
            .with_prompt(format!(
                "Delete rule '{}'?",
                config.alerting.rules[sel].name
            ))
            .default(false)
            .interact()?
        {
            config.alerting.rules.remove(sel);
        }
    }

    Ok(())
}

/// Maintenance windows section.
pub(crate) fn prompt_maintenance_section(config: &mut AppConfig) -> Result<()> {
    loop {
        let mut items: Vec<String> = config
            .maintenance_windows
            .iter()
            .map(|w| format!("  {}", w.schedule))
            .collect();
        items.push("  + Add window".to_string());
        items.push("  Back".to_string());

        let sel = Select::new()
            .with_prompt("Maintenance windows")
            .items(&items)
            .default(items.len() - 1)
            .interact()?;

        if sel == items.len() - 1 {
            break;
        } else if sel == items.len() - 2 {
            let schedule: String = Input::new()
                .with_prompt("Schedule (e.g. 'daily 03:00-04:00' or 'Sun 02:00-04:00')")
                .interact_text()?;
            let msg: String = Input::new()
                .with_prompt("Message")
                .default(
                    "Server is under scheduled maintenance. Please try again later.".to_string(),
                )
                .interact_text()?;
            let disconnect = Confirm::new()
                .with_prompt("Disconnect existing sessions?")
                .default(false)
                .interact()?;
            config.maintenance_windows.push(MaintenanceWindowConfig {
                schedule,
                message: msg,
                disconnect_existing: disconnect,
            });
        } else if Confirm::new()
            .with_prompt("Delete this window?")
            .default(false)
            .interact()?
        {
            config.maintenance_windows.remove(sel);
        }
    }

    Ok(())
}

/// Connection pool section.
pub(crate) fn prompt_connection_pool_section(config: &mut AppConfig) -> Result<()> {
    config.connection_pool.enabled = Confirm::new()
        .with_prompt("Enable connection pooling?")
        .default(config.connection_pool.enabled)
        .interact()?;

    if !config.connection_pool.enabled {
        return Ok(());
    }

    config.connection_pool.max_idle_per_host = Input::new()
        .with_prompt("Max idle connections per host")
        .default(config.connection_pool.max_idle_per_host)
        .interact_text()?;

    config.connection_pool.idle_timeout_secs = Input::new()
        .with_prompt("Idle timeout (seconds)")
        .default(config.connection_pool.idle_timeout_secs)
        .interact_text()?;

    Ok(())
}

/// Upstream proxy section.
pub(crate) fn prompt_upstream_proxy_section(config: &mut AppConfig) -> Result<()> {
    let enable = Confirm::new()
        .with_prompt("Route traffic through upstream SOCKS5 proxy?")
        .default(config.upstream_proxy.is_some())
        .interact()?;

    if !enable {
        config.upstream_proxy = None;
        return Ok(());
    }

    let url: String = Input::new()
        .with_prompt("Upstream proxy URL (e.g. socks5://host:port)")
        .default(
            config
                .upstream_proxy
                .as_ref()
                .map(|p| p.url.clone())
                .unwrap_or_default(),
        )
        .interact_text()?;

    config.upstream_proxy = Some(UpstreamProxyConfig { url });

    Ok(())
}
