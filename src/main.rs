use anyhow::{Context, Result};
use clap::Parser;
use tracing::{error, info};

use sks5::cli::{Cli, Command};
use sks5::config;
use std::collections::HashMap;
use std::path::PathBuf;

use sks5::config::types::{
    AlertingConfig, AppConfig, ConnectionPoolConfig, GlobalAclConfig, LogFormat, LoggingConfig,
    MotdConfig, SecurityConfig, ServerConfig, ShellConfig, UserAclConfig, UserConfig, UserRole,
};

fn setup_logging(level: &str, format: LogFormat) {
    sks5::logging::setup_logging(level, format);
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Command::HashPassword { password }) => {
            return sks5::auth::password::hash_password_cli(password.as_deref());
        }
        Some(Command::CheckConfig) => {
            let cfg = config::load_config(&cli.config)?;
            println!("Configuration is valid.");
            println!("  SSH listen: {}", cfg.server.ssh_listen);
            if let Some(ref socks) = cfg.server.socks5_listen {
                println!("  SOCKS5 listen: {}", socks);
            }
            println!("  Users: {}", cfg.users.len());
            return Ok(());
        }
        Some(Command::QuickStart {
            username,
            ssh_listen,
            socks5_listen,
            password,
            save_config,
        }) => {
            let password = match password {
                Some(p) => p.clone(),
                None => {
                    let generated = sks5::auth::password::generate_password(20);
                    eprintln!("Generated password: {}", generated);
                    generated
                }
            };

            let password_hash = sks5::auth::password::hash_password(&password)?;

            let app_config = build_quick_config(
                username.clone(),
                password_hash,
                ssh_listen.clone(),
                socks5_listen.clone(),
            );

            // Print summary
            eprintln!();
            eprintln!("=== sks5 quick-start ===");
            eprintln!("  SSH listen:  {}", ssh_listen);
            if let Some(ref socks) = socks5_listen {
                eprintln!("  SOCKS5:      {}", socks);
            }
            eprintln!("  Username:    {}", username);
            eprintln!("  Password:    {}", password);
            eprintln!();
            eprintln!("Connect with:");
            eprintln!(
                "  ssh -o StrictHostKeyChecking=no {}@localhost -p {}",
                username,
                ssh_listen.split(':').next_back().unwrap_or("2222")
            );
            if socks5_listen.is_some() {
                eprintln!(
                    "  curl --socks5 {}:{}@{} http://example.com",
                    username,
                    password,
                    socks5_listen.as_deref().unwrap_or("localhost:1080")
                );
            }
            eprintln!();

            if let Some(ref path) = save_config {
                let toml_str = generate_config_toml(
                    username,
                    app_config.users[0].password_hash.as_deref().unwrap_or(""),
                    ssh_listen,
                    socks5_listen.as_deref(),
                );
                std::fs::write(path, toml_str)?;
                eprintln!("Config saved to: {}", path.display());
                eprintln!();
            }

            setup_logging("info", app_config.logging.format);
            info!(
                version = env!("CARGO_PKG_VERSION"),
                ssh_listen = %app_config.server.ssh_listen,
                "Starting sks5 proxy server (quick-start)"
            );

            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                if let Err(e) = sks5::server::run(app_config).await {
                    error!(error = %e, "Server error");
                    std::process::exit(1);
                }
            });

            return Ok(());
        }
        Some(Command::Init {
            output,
            username,
            password,
            preset,
        }) => {
            let password = match password {
                Some(p) => p.clone(),
                None => {
                    eprint!("Enter password: ");
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;
                    input.trim().to_string()
                }
            };

            if password.is_empty() {
                anyhow::bail!("password must not be empty");
            }

            let password_hash = sks5::auth::password::hash_password(&password)?;

            let toml_str = if let Some(preset_name) = preset {
                match preset_name.as_str() {
                    "bastion" => config::presets::bastion_preset(username, &password_hash),
                    "proxy" => config::presets::proxy_preset(username, &password_hash),
                    "dev" => config::presets::dev_preset(username, &password_hash),
                    _ => anyhow::bail!(
                        "unknown preset '{}' (available: bastion, proxy, dev)",
                        preset_name
                    ),
                }
            } else {
                generate_config_toml(
                    username,
                    &password_hash,
                    "0.0.0.0:2222",
                    Some("0.0.0.0:1080"),
                )
            };

            std::fs::write(output, &toml_str)?;
            eprintln!("Configuration written to: {}", output.display());
            eprintln!("  Username: {}", username);
            if let Some(ref p) = preset {
                eprintln!("  Preset: {}", p);
            }
            eprintln!("  Password hash generated with Argon2id");
            eprintln!();
            eprintln!("Start the server with:");
            eprintln!("  sks5 -c {}", output.display());

            return Ok(());
        }
        Some(Command::HealthCheck { addr, timeout }) => {
            use std::net::TcpStream;
            use std::time::Duration;

            let timeout = Duration::from_secs(*timeout);
            match TcpStream::connect_timeout(
                &addr.parse().unwrap_or_else(|_| {
                    eprintln!("Invalid address: {}", addr);
                    std::process::exit(1);
                }),
                timeout,
            ) {
                Ok(_) => {
                    println!("OK: {} is reachable", addr);
                    return Ok(());
                }
                Err(e) => {
                    eprintln!("FAIL: {} is not reachable: {}", addr, e);
                    std::process::exit(1);
                }
            }
        }
        Some(Command::SshConfig {
            user,
            host,
            port,
            name,
            dynamic_forward,
        }) => {
            let alias = name.as_deref().unwrap_or("sks5-proxy");
            println!("# sks5 SSH config snippet");
            println!("# Add to ~/.ssh/config");
            println!();
            println!("Host {}", alias);
            println!("    HostName {}", host);
            println!("    Port {}", port);
            println!("    User {}", user);
            println!("    StrictHostKeyChecking no");
            println!("    UserKnownHostsFile /dev/null");
            if let Some(dyn_port) = dynamic_forward {
                println!("    DynamicForward {}", dyn_port);
            }
            println!("    ServerAliveInterval 30");
            println!("    ServerAliveCountMax 3");
            return Ok(());
        }
        Some(Command::GenerateTotp { username }) => {
            let secret = totp_rs::Secret::generate_secret();
            let secret_bytes = secret
                .to_bytes()
                .map_err(|e| anyhow::anyhow!("failed to convert TOTP secret to bytes: {}", e))?;
            let totp = totp_rs::TOTP::new(
                totp_rs::Algorithm::SHA1,
                6,
                1,
                30,
                secret_bytes,
                Some("sks5".to_string()),
                username.clone(),
            )
            .map_err(|e| anyhow::anyhow!("failed to create TOTP: {}", e))?;
            let encoded = secret.to_encoded().to_string();
            println!("TOTP secret for '{}': {}", username, encoded);
            println!("OTPAuth URL: {}", totp.get_url());
            println!();
            println!("Add to config.toml:");
            println!("  totp_secret = \"{}\"", encoded);
            println!("  totp_enabled = true");
            return Ok(());
        }
        Some(Command::Completions { shell }) => {
            use clap::CommandFactory;
            let mut cmd = Cli::command();
            clap_complete::generate(*shell, &mut cmd, "sks5", &mut std::io::stdout());
            return Ok(());
        }
        Some(Command::Manpage) => {
            use clap::CommandFactory;
            let cmd = Cli::command();
            let man = clap_mangen::Man::new(cmd);
            man.render(&mut std::io::stdout())?;
            return Ok(());
        }
        Some(Command::ShowConfig { format }) => {
            // Load config the same way as the server does
            let (app_config, _) = load_effective_config(&cli)?;

            let redacted = config::redact::redact_config(&app_config);

            match format.as_str() {
                "json" => {
                    let json = serde_json::to_string_pretty(&redacted)?;
                    println!("{}", json);
                }
                "toml" => {
                    let toml_str = toml::to_string_pretty(&redacted)?;
                    println!("{}", toml_str);
                }
                _ => {
                    anyhow::bail!("unsupported format '{}' (available: toml, json)", format);
                }
            }
            return Ok(());
        }
        Some(Command::Backup {
            output,
            api_addr,
            token,
        }) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let client = reqwest::Client::new();
                let resp = client
                    .get(format!("{}/api/backup", api_addr))
                    .header("Authorization", format!("Bearer {}", token))
                    .send()
                    .await?;

                if !resp.status().is_success() {
                    anyhow::bail!("backup failed: HTTP {}", resp.status());
                }

                let body = resp.text().await?;

                match output {
                    Some(path) => {
                        std::fs::write(path, &body)?;
                        eprintln!("Backup saved to: {}", path.display());
                    }
                    None => {
                        println!("{}", body);
                    }
                }
                Ok::<_, anyhow::Error>(())
            })?;
            return Ok(());
        }
        Some(Command::Restore {
            input,
            api_addr,
            token,
        }) => {
            let body = std::fs::read_to_string(input)?;
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let client = reqwest::Client::new();
                let resp = client
                    .post(format!("{}/api/restore", api_addr))
                    .header("Authorization", format!("Bearer {}", token))
                    .header("Content-Type", "application/json")
                    .body(body)
                    .send()
                    .await?;

                if !resp.status().is_success() {
                    anyhow::bail!("restore failed: HTTP {}", resp.status());
                }

                let result = resp.text().await?;
                println!("{}", result);
                Ok::<_, anyhow::Error>(())
            })?;
            return Ok(());
        }
        Some(Command::Wizard {
            output,
            non_interactive,
        }) => {
            let app_config = sks5::wizard::run_wizard(*non_interactive)?;

            // Validate the generated config
            config::parse_config_validate(&app_config)?;

            // Serialize to TOML
            let toml_str = sks5::wizard::config_to_toml(&app_config)?;

            // Write to file
            std::fs::write(output, &toml_str)?;
            eprintln!("Configuration written to: {}", output.display());
            eprintln!("  Users: {}", app_config.users.len());
            eprintln!();
            eprintln!("Start the server with:");
            eprintln!("  sks5 -c {}", output.display());

            return Ok(());
        }
        Some(Command::Demo {
            ssh_port,
            socks5_port,
            api_port,
            password,
        }) => {
            let password_hash = sks5::auth::password::hash_password(password)?;
            let demo_config =
                sks5::demo::build_demo_config(*ssh_port, *socks5_port, *api_port, &password_hash);

            eprintln!();
            eprintln!("=== sks5 demo ===");
            eprintln!("  SSH:       127.0.0.1:{}", ssh_port);
            eprintln!("  SOCKS5:    127.0.0.1:{}", socks5_port);
            eprintln!(
                "  Dashboard: http://127.0.0.1:{}/dashboard?token=demo",
                api_port
            );
            eprintln!(
                "  Users:     alice / bob / charlie (password: {})",
                password
            );
            eprintln!();

            setup_logging("info", demo_config.logging.format);
            info!(
                version = env!("CARGO_PKG_VERSION"),
                ssh_port = ssh_port,
                socks5_port = socks5_port,
                api_port = api_port,
                "Starting sks5 demo server"
            );

            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                if let Err(e) =
                    sks5::server::run_with_post_init(demo_config, None, |ctx| async move {
                        // Inject demo data; keep sessions alive for server lifetime
                        let _sessions = sks5::demo::inject_demo_data(&ctx).await;
                        // Sessions are held in this async block which lives as long
                        // as the hook future. Since run_with_post_init awaits the hook
                        // before proceeding, we need to leak them so they survive.
                        // Instead, we box-leak so the Arc<LiveSession>s stay alive.
                        std::mem::forget(_sessions);
                    })
                    .await
                {
                    error!(error = %e, "Demo server error");
                    std::process::exit(1);
                }
            });

            return Ok(());
        }
        None => {}
    }

    // Load config with priority chain: CLI > env (if force_env) > TOML > defaults
    let (app_config, config_path) = load_effective_config(&cli)?;

    // Setup logging (CLI override > config)
    let log_level = cli
        .log_level
        .as_deref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| app_config.logging.level.to_string());
    setup_logging(&log_level, app_config.logging.format);

    info!(
        version = env!("CARGO_PKG_VERSION"),
        ssh_listen = %app_config.server.ssh_listen,
        "Starting sks5 proxy server"
    );

    // Run the async server
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        if let Err(e) = sks5::server::run_with_config_path(app_config, config_path).await {
            error!(error = %e, "Server error");
            std::process::exit(1);
        }
    });

    Ok(())
}

fn build_quick_config(
    username: String,
    password_hash: String,
    ssh_listen: String,
    socks5_listen: Option<String>,
) -> AppConfig {
    AppConfig {
        server: ServerConfig {
            ssh_listen,
            socks5_listen,
            host_key_path: std::path::PathBuf::from("host_key"),
            server_id: "SSH-2.0-sks5".to_string(),
            banner: "Welcome to sks5".to_string(),
            motd_path: None,
            proxy_protocol: false,
            allowed_ciphers: Vec::new(),
            allowed_kex: Vec::new(),
            shutdown_timeout: 30,
            socks5_tls_cert: None,
            socks5_tls_key: None,
            dns_cache_ttl: -1,
            dns_cache_max_entries: 1000,
            connect_retry: 0,
            connect_retry_delay_ms: 1000,
            bookmarks_path: None,
            ssh_keepalive_interval_secs: 15,
            ssh_keepalive_max: 3,
            ssh_auth_timeout: 120,
        },
        shell: ShellConfig::default(),
        limits: Default::default(),
        security: SecurityConfig::default(),
        logging: LoggingConfig::default(),
        metrics: Default::default(),
        api: Default::default(),
        geoip: Default::default(),
        upstream_proxy: None,
        webhooks: Vec::new(),
        acl: GlobalAclConfig::default(),
        users: vec![UserConfig {
            username,
            password_hash: Some(password_hash),
            authorized_keys: Vec::new(),
            allow_forwarding: true,
            allow_shell: Some(true),
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
        }],
        groups: Vec::new(),
        motd: MotdConfig::default(),
        alerting: AlertingConfig::default(),
        maintenance_windows: Vec::new(),
        connection_pool: ConnectionPoolConfig::default(),
        persistence: Default::default(),
    }
}

fn generate_config_toml(
    username: &str,
    password_hash: &str,
    ssh_listen: &str,
    socks5_listen: Option<&str>,
) -> String {
    let socks_line = match socks5_listen {
        Some(addr) => format!("socks5_listen = \"{}\"", addr),
        None => "# socks5_listen = \"0.0.0.0:1080\"".to_string(),
    };

    format!(
        r#"[server]
ssh_listen = "{ssh_listen}"
{socks_line}
host_key_path = "host_key"           # auto-generated if absent
server_id = "SSH-2.0-sks5"
banner = "Welcome to sks5"
proxy_protocol = false

[shell]
hostname = "sks5-proxy"
prompt = "$ "

[limits]
max_connections = 1000
max_connections_per_user = 10
connection_timeout = 300
idle_timeout = 0
max_auth_attempts = 3

[security]
allowed_source_ips = []
ban_enabled = true
ban_threshold = 5
ban_window = 300
ban_duration = 900
ban_whitelist = ["127.0.0.1"]

[logging]
level = "info"
format = "pretty"

[metrics]
enabled = false
listen = "127.0.0.1:9090"

[api]
enabled = false
listen = "127.0.0.1:9091"
token = ""

[geoip]
enabled = false
allowed_countries = []
denied_countries = []

[[users]]
username = "{username}"
password_hash = "{password_hash}"
authorized_keys = []
allow_forwarding = true
allow_shell = true
max_new_connections_per_minute = 60
max_bandwidth_kbps = 0
source_ips = []

[users.acl]
default_policy = "allow"
allow = []
deny = ["169.254.169.254:*"]
"#,
        ssh_listen = ssh_listen,
        socks_line = socks_line,
        username = username,
        password_hash = password_hash,
    )
}

/// Load the effective configuration following the priority chain:
///   CLI args (highest) > env vars (if force_env or no config file) > config.toml > defaults
///
/// Returns (AppConfig, Option<config_path>).
fn load_effective_config(cli: &Cli) -> Result<(AppConfig, Option<PathBuf>)> {
    let config_explicitly_set = std::env::args().any(|a| a == "-c" || a == "--config")
        || std::env::var("SKS5_CONFIG").is_ok();

    let (mut cfg, config_path) = if cli.config.exists() {
        let mut loaded = config::load_config(&cli.config)?;
        // Only apply env overrides when force_env is set
        if cli.force_env {
            config::env::apply_env_overrides(&mut loaded);
        }
        (loaded, Some(cli.config.clone()))
    } else if config_explicitly_set {
        // User explicitly asked for a config file that doesn't exist — hard error
        anyhow::bail!(
            "config file not found: {} (specified via --config or SKS5_CONFIG)",
            cli.config.display()
        );
    } else if config::env::can_build_from_env() {
        let loaded = config::env::build_config_from_env()?;
        config::parse_config_validate(&loaded)?;
        eprintln!("No config file found — using environment variables");
        (loaded, None)
    } else {
        // Nothing available — generate minimal config and write it
        eprintln!("No config file or environment variables found.");
        eprintln!("Generating minimal config at: {}", cli.config.display());

        let password = sks5::auth::password::generate_password(20);
        let password_hash = sks5::auth::password::hash_password(&password)?;
        let toml_str =
            generate_config_toml("user", &password_hash, "0.0.0.0:2222", Some("0.0.0.0:1080"));
        std::fs::write(&cli.config, &toml_str)
            .with_context(|| format!("writing minimal config to {}", cli.config.display()))?;

        eprintln!("  Username: user");
        eprintln!("  Password: {}", password);
        eprintln!();

        let loaded = config::load_config(&cli.config)?;
        (loaded, Some(cli.config.clone()))
    };

    // Apply CLI overrides (always highest priority)
    apply_cli_overrides(cli, &mut cfg)?;

    Ok((cfg, config_path))
}

/// Apply CLI argument overrides to the config.
/// Priority: --ssh-listen, --data-dir, then generic --set key=value.
fn apply_cli_overrides(cli: &Cli, cfg: &mut AppConfig) -> Result<()> {
    // Dedicated CLI flags
    if let Some(ref listen) = cli.ssh_listen {
        cfg.server.ssh_listen = listen.clone();
    }
    if let Some(ref data_dir) = cli.data_dir {
        cfg.persistence.data_dir = Some(data_dir.clone());
    }

    // Generic --set overrides via serde_json Value manipulation
    if !cli.overrides.is_empty() {
        let mut value =
            serde_json::to_value(&*cfg).context("serializing config for --set override")?;

        for kv in &cli.overrides {
            let (key, val_str) = kv.split_once('=').ok_or_else(|| {
                anyhow::anyhow!("invalid --set format '{}' (expected KEY=VALUE)", kv)
            })?;

            let parts: Vec<&str> = key.split('.').collect();
            if parts.is_empty() {
                anyhow::bail!("invalid --set key: empty path");
            }

            // Navigate to the parent, then set the leaf
            let mut current = &mut value;
            for (i, part) in parts.iter().enumerate() {
                if i == parts.len() - 1 {
                    // Leaf — set the value
                    let obj = current.as_object_mut().ok_or_else(|| {
                        anyhow::anyhow!(
                            "--set: '{}' is not an object at '{}'",
                            key,
                            parts[..i].join(".")
                        )
                    })?;

                    // Try to parse as the same type as the existing value, or infer type
                    let new_val = if let Some(existing) = obj.get(*part) {
                        parse_value_like(val_str, existing)?
                    } else {
                        parse_value_infer(val_str)
                    };
                    obj.insert(part.to_string(), new_val);
                } else {
                    current = current.get_mut(*part).ok_or_else(|| {
                        anyhow::anyhow!(
                            "--set: unknown config path '{}' (failed at '{}')",
                            key,
                            part
                        )
                    })?;
                }
            }
        }

        *cfg =
            serde_json::from_value(value).context("deserializing config after --set overrides")?;
    }

    Ok(())
}

/// Parse a string value to match the type of an existing JSON value.
fn parse_value_like(s: &str, existing: &serde_json::Value) -> Result<serde_json::Value> {
    match existing {
        serde_json::Value::Bool(_) => {
            let b = matches!(s.to_ascii_lowercase().as_str(), "true" | "1" | "yes");
            Ok(serde_json::Value::Bool(b))
        }
        serde_json::Value::Number(_) => {
            if let Ok(n) = s.parse::<u64>() {
                Ok(serde_json::json!(n))
            } else if let Ok(n) = s.parse::<i64>() {
                Ok(serde_json::json!(n))
            } else if let Ok(n) = s.parse::<f64>() {
                Ok(serde_json::json!(n))
            } else {
                anyhow::bail!("expected a number for this field, got '{}'", s)
            }
        }
        serde_json::Value::String(_) => Ok(serde_json::Value::String(s.to_string())),
        _ => Ok(parse_value_infer(s)),
    }
}

/// Infer the type of a string value (for new/unknown fields).
fn parse_value_infer(s: &str) -> serde_json::Value {
    if s.eq_ignore_ascii_case("true") {
        serde_json::Value::Bool(true)
    } else if s.eq_ignore_ascii_case("false") {
        serde_json::Value::Bool(false)
    } else if let Ok(n) = s.parse::<u64>() {
        serde_json::json!(n)
    } else if let Ok(n) = s.parse::<i64>() {
        serde_json::json!(n)
    } else if let Ok(n) = s.parse::<f64>() {
        serde_json::json!(n)
    } else {
        serde_json::Value::String(s.to_string())
    }
}
