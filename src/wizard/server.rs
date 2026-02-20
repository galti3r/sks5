use anyhow::Result;
use dialoguer::{Confirm, Input, Select};
use std::path::PathBuf;

use crate::config::types::*;

/// Server section: SSH/SOCKS5 listen, shell, limits, MOTD.
pub(crate) fn prompt_server_section(config: &mut AppConfig) -> Result<()> {
    let items = &[
        "Listen addresses (SSH, SOCKS5)",
        "Shell settings (hostname, prompt, colors)",
        "Connection limits (timeouts, bandwidth, rates)",
        "MOTD settings",
        "Advanced server (DNS cache, keepalive, TLS, retry)",
        "Back to main menu",
    ];

    loop {
        let sel = Select::new()
            .with_prompt("Server — configure")
            .items(items)
            .default(0)
            .interact()?;

        match sel {
            0 => prompt_listen(config)?,
            1 => prompt_shell(config)?,
            2 => prompt_limits(config)?,
            3 => prompt_motd(config)?,
            4 => prompt_advanced_server(config)?,
            _ => break,
        }
    }

    Ok(())
}

fn prompt_listen(config: &mut AppConfig) -> Result<()> {
    config.server.ssh_listen = Input::new()
        .with_prompt("SSH listen address")
        .default(config.server.ssh_listen.clone())
        .interact_text()?;

    let enable_socks5 = Confirm::new()
        .with_prompt("Enable standalone SOCKS5 listener?")
        .default(config.server.socks5_listen.is_some())
        .interact()?;

    config.server.socks5_listen = if enable_socks5 {
        let addr: String = Input::new()
            .with_prompt("SOCKS5 listen address")
            .default(
                config
                    .server
                    .socks5_listen
                    .clone()
                    .unwrap_or("0.0.0.0:1080".to_string()),
            )
            .interact_text()?;
        Some(addr)
    } else {
        None
    };

    config.server.banner = Input::new()
        .with_prompt("SSH banner message")
        .default(config.server.banner.clone())
        .interact_text()?;

    Ok(())
}

fn prompt_shell(config: &mut AppConfig) -> Result<()> {
    config.shell.hostname = Input::new()
        .with_prompt("Shell hostname (user@hostname:~$)")
        .default(config.shell.hostname.clone())
        .interact_text()?;

    config.shell.prompt = Input::new()
        .with_prompt("Shell prompt suffix")
        .default(config.shell.prompt.clone())
        .interact_text()?;

    config.shell.colors = Confirm::new()
        .with_prompt("Enable shell colors?")
        .default(config.shell.colors)
        .interact()?;

    config.shell.autocomplete = Confirm::new()
        .with_prompt("Enable tab completion?")
        .default(config.shell.autocomplete)
        .interact()?;

    Ok(())
}

fn prompt_limits(config: &mut AppConfig) -> Result<()> {
    config.limits.max_connections = Input::new()
        .with_prompt("Max total connections")
        .default(config.limits.max_connections)
        .interact_text()?;

    config.limits.max_connections_per_user = Input::new()
        .with_prompt("Max connections per user (0=unlimited)")
        .default(config.limits.max_connections_per_user)
        .interact_text()?;

    config.limits.connection_timeout = Input::new()
        .with_prompt("Connection timeout (seconds)")
        .default(config.limits.connection_timeout)
        .interact_text()?;

    config.limits.idle_timeout = Input::new()
        .with_prompt("Idle timeout (seconds, 0=disabled)")
        .default(config.limits.idle_timeout)
        .interact_text()?;

    if config.limits.idle_timeout > 0 {
        config.limits.idle_warning_secs = Input::new()
            .with_prompt("Idle warning (seconds before disconnect, 0=none)")
            .default(config.limits.idle_warning_secs)
            .interact_text()?;
    }

    config.limits.max_bandwidth_mbps = Input::new()
        .with_prompt("Server-wide bandwidth cap (Mbps, 0=unlimited)")
        .default(config.limits.max_bandwidth_mbps)
        .interact_text()?;

    config.limits.max_new_connections_per_second = Input::new()
        .with_prompt("Max new connections/second (0=unlimited)")
        .default(config.limits.max_new_connections_per_second)
        .interact_text()?;

    config.limits.max_new_connections_per_minute = Input::new()
        .with_prompt("Max new connections/minute (0=unlimited)")
        .default(config.limits.max_new_connections_per_minute)
        .interact_text()?;

    Ok(())
}

fn prompt_motd(config: &mut AppConfig) -> Result<()> {
    config.motd.enabled = Confirm::new()
        .with_prompt("Enable MOTD (Message of the Day)?")
        .default(config.motd.enabled)
        .interact()?;

    if !config.motd.enabled {
        return Ok(());
    }

    config.motd.colors = Confirm::new()
        .with_prompt("Enable MOTD colors?")
        .default(config.motd.colors)
        .interact()?;

    let use_custom = Confirm::new()
        .with_prompt("Use custom MOTD template? (No = built-in default)")
        .default(config.motd.template.is_some())
        .interact()?;

    if use_custom {
        eprintln!(
            "  Available variables: {{user}}, {{role}}, {{group}}, {{auth_method}}, {{source_ip}},"
        );
        eprintln!("  {{connections}}, {{acl_policy}}, {{allowed}}, {{denied}}, {{expires_at}},");
        eprintln!(
            "  {{bandwidth_used}}, {{bandwidth_limit}}, {{uptime}}, {{version}}, {{last_login}}"
        );
        let template: String = Input::new()
            .with_prompt("MOTD template")
            .default(config.motd.template.clone().unwrap_or_default())
            .interact_text()?;
        config.motd.template = Some(template);
    } else {
        config.motd.template = None;
    }

    Ok(())
}

fn prompt_advanced_server(config: &mut AppConfig) -> Result<()> {
    config.server.dns_cache_ttl = Input::new()
        .with_prompt("DNS cache TTL (-1=native, 0=disabled, N=seconds)")
        .default(config.server.dns_cache_ttl)
        .interact_text()?;

    config.server.ssh_keepalive_interval_secs = Input::new()
        .with_prompt("SSH keepalive interval (seconds, 0=disabled)")
        .default(config.server.ssh_keepalive_interval_secs)
        .interact_text()?;

    config.server.ssh_auth_timeout = Input::new()
        .with_prompt("SSH auth timeout (seconds, 10-600)")
        .default(config.server.ssh_auth_timeout)
        .interact_text()?;

    config.server.shutdown_timeout = Input::new()
        .with_prompt("Graceful shutdown timeout (seconds)")
        .default(config.server.shutdown_timeout)
        .interact_text()?;

    config.server.connect_retry = Input::new()
        .with_prompt("Connect retry attempts (0=disabled)")
        .default(config.server.connect_retry)
        .interact_text()?;

    if config.server.connect_retry > 0 {
        config.server.connect_retry_delay_ms = Input::new()
            .with_prompt("Connect retry initial delay (ms)")
            .default(config.server.connect_retry_delay_ms)
            .interact_text()?;
    }

    let enable_tls = Confirm::new()
        .with_prompt("Enable TLS for SOCKS5 listener?")
        .default(config.server.socks5_tls_cert.is_some())
        .interact()?;

    if enable_tls {
        let cert: String = Input::new()
            .with_prompt("TLS certificate path")
            .default(
                config
                    .server
                    .socks5_tls_cert
                    .clone()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default(),
            )
            .interact_text()?;
        let key: String = Input::new()
            .with_prompt("TLS key path")
            .default(
                config
                    .server
                    .socks5_tls_key
                    .clone()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default(),
            )
            .interact_text()?;
        config.server.socks5_tls_cert = Some(PathBuf::from(cert));
        config.server.socks5_tls_key = Some(PathBuf::from(key));
    } else {
        config.server.socks5_tls_cert = None;
        config.server.socks5_tls_key = None;
    }

    Ok(())
}
