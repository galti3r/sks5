use anyhow::Result;
use dialoguer::{Confirm, Input, Select};
use std::path::PathBuf;

use crate::config::types::*;

/// API section.
pub(crate) fn prompt_api_section(config: &mut AppConfig) -> Result<()> {
    config.api.enabled = Confirm::new()
        .with_prompt("Enable REST API / dashboard?")
        .default(config.api.enabled)
        .interact()?;

    if !config.api.enabled {
        return Ok(());
    }

    config.api.listen = Input::new()
        .with_prompt("API listen address")
        .default(config.api.listen.clone())
        .interact_text()?;

    let token: String = Input::new()
        .with_prompt("API token (empty to auto-generate)")
        .default(if config.api.token.is_empty() {
            String::new()
        } else {
            config.api.token.clone()
        })
        .allow_empty(true)
        .interact_text()?;

    config.api.token = if token.is_empty() {
        let generated = crate::auth::password::generate_password(32);
        eprintln!("  Generated API token: {generated}");
        generated
    } else {
        token
    };

    Ok(())
}

/// Metrics section.
pub(crate) fn prompt_metrics_section(config: &mut AppConfig) -> Result<()> {
    config.metrics.enabled = Confirm::new()
        .with_prompt("Enable Prometheus metrics?")
        .default(config.metrics.enabled)
        .interact()?;

    if !config.metrics.enabled {
        return Ok(());
    }

    config.metrics.listen = Input::new()
        .with_prompt("Metrics listen address")
        .default(config.metrics.listen.clone())
        .interact_text()?;

    config.metrics.max_metric_labels = Input::new()
        .with_prompt("Max metric labels per metric")
        .default(config.metrics.max_metric_labels)
        .interact_text()?;

    Ok(())
}

/// Logging section.
pub(crate) fn prompt_logging_section(config: &mut AppConfig) -> Result<()> {
    let levels = &["trace", "debug", "info", "warn", "error"];
    let current = match config.logging.level {
        LogLevel::Trace => 0,
        LogLevel::Debug => 1,
        LogLevel::Info => 2,
        LogLevel::Warn => 3,
        LogLevel::Error => 4,
    };

    let level = Select::new()
        .with_prompt("Log level")
        .items(levels)
        .default(current)
        .interact()?;

    config.logging.level = match level {
        0 => LogLevel::Trace,
        1 => LogLevel::Debug,
        2 => LogLevel::Info,
        3 => LogLevel::Warn,
        _ => LogLevel::Error,
    };

    let formats = &["pretty", "json"];
    let current_fmt = if config.logging.format == LogFormat::Json {
        1
    } else {
        0
    };
    let format = Select::new()
        .with_prompt("Log format")
        .items(formats)
        .default(current_fmt)
        .interact()?;

    config.logging.format = if format == 0 {
        LogFormat::Pretty
    } else {
        LogFormat::Json
    };

    config.logging.log_denied_connections = Confirm::new()
        .with_prompt("Log denied connections (ACL deny, rate limit, etc.)?")
        .default(config.logging.log_denied_connections)
        .interact()?;

    config.logging.connection_flow_logs = Confirm::new()
        .with_prompt("Enable connection flow logs (verbose)?")
        .default(config.logging.connection_flow_logs)
        .interact()?;

    let audit = Confirm::new()
        .with_prompt("Enable audit log?")
        .default(config.logging.audit_log_path.is_some())
        .interact()?;

    if audit {
        let path: String = Input::new()
            .with_prompt("Audit log path")
            .default(
                config
                    .logging
                    .audit_log_path
                    .as_ref()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| "audit.log".to_string()),
            )
            .interact_text()?;
        config.logging.audit_log_path = Some(PathBuf::from(path));

        config.logging.audit_max_size_mb = Input::new()
            .with_prompt("Audit log max size (MB)")
            .default(config.logging.audit_max_size_mb)
            .interact_text()?;

        config.logging.audit_max_files = Input::new()
            .with_prompt("Audit log max files")
            .default(config.logging.audit_max_files)
            .interact_text()?;
    } else {
        config.logging.audit_log_path = None;
    }

    Ok(())
}
