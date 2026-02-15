use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "sks5",
    version,
    about = "Lightweight SSH + SOCKS5 proxy server"
)]
pub struct Cli {
    /// Path to configuration file (also settable via SKS5_CONFIG env var)
    #[arg(short, long, default_value = "config.toml", env = "SKS5_CONFIG")]
    pub config: PathBuf,

    /// Log level override (trace, debug, info, warn, error)
    #[arg(long)]
    pub log_level: Option<String>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Hash a password using Argon2id for use in config
    HashPassword {
        /// Password to hash (if not provided, reads from stdin)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Validate configuration file
    CheckConfig,
    /// Start server instantly with sensible defaults (zero config)
    QuickStart {
        /// Username for the auto-created user
        #[arg(long, default_value = "user")]
        username: String,
        /// SSH listen address
        #[arg(long, default_value = "0.0.0.0:2222")]
        ssh_listen: String,
        /// Optional SOCKS5 standalone listener address
        #[arg(long)]
        socks5_listen: Option<String>,
        /// Password (auto-generated if omitted)
        #[arg(long)]
        password: Option<String>,
        /// Save the generated config to a TOML file
        #[arg(long)]
        save_config: Option<PathBuf>,
    },
    /// Generate a config file with hashed password
    Init {
        /// Output file path
        #[arg(short, long, default_value = "config.toml")]
        output: PathBuf,
        /// Username
        #[arg(long, default_value = "user")]
        username: String,
        /// Password (prompted if omitted)
        #[arg(long)]
        password: Option<String>,
        /// Use a preset template: bastion, proxy, dev
        #[arg(long)]
        preset: Option<String>,
    },
    /// Generate a TOTP secret for a user
    GenerateTotp {
        /// Username to generate TOTP for
        #[arg(long)]
        username: String,
    },
    /// Health check: verify the server is reachable via TCP connect
    HealthCheck {
        /// Address to check (host:port)
        #[arg(long, default_value = "127.0.0.1:2222")]
        addr: String,
        /// Timeout in seconds
        #[arg(long, default_value = "5")]
        timeout: u64,
    },
    /// Generate SSH config snippet for connecting to this server
    SshConfig {
        /// Username
        #[arg(long)]
        user: String,
        /// Server hostname or IP
        #[arg(long)]
        host: String,
        /// SSH port
        #[arg(long, default_value = "2222")]
        port: u16,
        /// Config entry name (Host alias)
        #[arg(long)]
        name: Option<String>,
        /// Enable SOCKS5 dynamic forwarding
        #[arg(long)]
        dynamic_forward: Option<u16>,
    },
    /// Generate shell completions for bash, zsh, or fish
    Completions {
        /// Shell type
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Generate a man page (roff format)
    Manpage,
    /// Show the effective configuration (with sensitive fields redacted)
    ShowConfig {
        /// Output format: toml or json
        #[arg(long, default_value = "toml")]
        format: String,
    },
    /// Backup server state (bans, quotas) via API
    Backup {
        /// Output file path (stdout if omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// API server address
        #[arg(long, default_value = "http://127.0.0.1:9091")]
        api_addr: String,
        /// API bearer token
        #[arg(long)]
        token: String,
    },
    /// Restore server state from a backup file via API
    Restore {
        /// Input backup file
        #[arg(short, long)]
        input: PathBuf,
        /// API server address
        #[arg(long, default_value = "http://127.0.0.1:9091")]
        api_addr: String,
        /// API bearer token
        #[arg(long)]
        token: String,
    },
    /// Interactive configuration wizard — generates a config file step by step
    Wizard {
        /// Output file path
        #[arg(short, long, default_value = "config.toml")]
        output: PathBuf,
        /// Non-interactive mode: use defaults for everything (for testing/CI)
        #[arg(long)]
        non_interactive: bool,
    },
    /// Start a demo server with pre-populated realistic data
    Demo {
        /// SSH listen port
        #[arg(long, default_value = "2222")]
        ssh_port: u16,
        /// SOCKS5 listen port
        #[arg(long, default_value = "1080")]
        socks5_port: u16,
        /// API/dashboard listen port
        #[arg(long, default_value = "9091")]
        api_port: u16,
        /// Password for all demo users
        #[arg(long, default_value = "demo")]
        password: String,
    },
}
