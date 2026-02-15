pub mod alias_cmd;
pub mod bookmark;
pub mod cat;
pub mod cd;
pub mod colors;
pub mod exit;
pub mod help;
pub mod ls;
pub mod ping_cmd;
pub mod pwd;
pub mod resolve_cmd;
pub mod show;
pub mod test_cmd;
pub mod uname;
pub mod whoami;

use crate::shell::context::ShellContext;
use crate::shell::filesystem::VirtualFs;
use crate::shell::parser;

/// Result of executing a command
pub struct CommandResult {
    pub output: String,
    pub exit_requested: bool,
}

impl CommandResult {
    pub fn output(text: impl Into<String>) -> Self {
        Self {
            output: text.into(),
            exit_requested: false,
        }
    }

    pub fn exit() -> Self {
        Self {
            output: "logout\r\n".to_string(),
            exit_requested: true,
        }
    }

    pub fn empty() -> Self {
        Self {
            output: String::new(),
            exit_requested: false,
        }
    }
}

/// Execute a command with arguments.
///
/// If a `ShellContext` is provided, the new extended commands (`show`, `test`,
/// `ping`, `resolve`, `bookmark`, `alias`) are available. When the context is
/// `None`, only the basic built-in commands work.
pub fn execute(
    cmd: &str,
    args: &[String],
    fs: &mut VirtualFs,
    username: &str,
    hostname: &str,
    ctx: Option<&mut ShellContext>,
) -> CommandResult {
    // First, check if this is an alias (only when context is available)
    if let Some(ref ctx_ref) = ctx {
        if let Some(expanded) = ctx_ref.aliases.get(cmd) {
            // Expand the alias: tokenize the expanded command, append remaining args
            let mut alias_tokens = parser::tokenize(expanded);
            if !alias_tokens.is_empty() {
                let alias_cmd = alias_tokens.remove(0);
                // Append any extra args the user passed after the alias
                for arg in args {
                    alias_tokens.push(arg.clone());
                }
                // Recursively execute the expanded command (no further alias expansion
                // to prevent infinite loops)
                return execute_inner(&alias_cmd, &alias_tokens, fs, username, hostname, ctx);
            }
        }
    }

    execute_inner(cmd, args, fs, username, hostname, ctx)
}

/// Inner execute that handles all command dispatch without alias expansion.
fn execute_inner(
    cmd: &str,
    args: &[String],
    fs: &mut VirtualFs,
    username: &str,
    hostname: &str,
    ctx: Option<&mut ShellContext>,
) -> CommandResult {
    match cmd {
        // Basic built-in commands (always available)
        "ls" => ls::run(args, fs),
        "pwd" => pwd::run(fs),
        "cd" => cd::run(args, fs),
        "cat" => cat::run(args, fs),
        "whoami" => whoami::run(username),
        "uname" => uname::run(args, hostname),
        "help" => help::run(ctx.as_deref()),
        "exit" | "logout" => exit::run(),
        "echo" => {
            let text = args.join(" ");
            CommandResult::output(format!("{}\r\n", text))
        }
        "id" => CommandResult::output(format!(
            "uid=1000({}) gid=1000({}) groups=1000({})\r\n",
            username, username, username
        )),
        "hostname" => CommandResult::output(format!("{}\r\n", hostname)),
        "clear" => CommandResult::output("\x1b[2J\x1b[H".to_string()),
        "env" | "printenv" => CommandResult::output(format!(
            "HOME=/home/{}\r\nUSER={}\r\nSHELL=/bin/sh\r\nHOSTNAME={}\r\nTERM=xterm-256color\r\nPATH=/usr/local/bin:/usr/bin:/bin\r\n",
            username, username, hostname
        )),
        "" => CommandResult::empty(),

        // Extended commands (require ShellContext)
        "show" => match ctx {
            Some(c) => show::run(args, c),
            None => CommandResult::output("show: context not available\r\n".to_string()),
        },
        "test" => match ctx {
            Some(c) => test_cmd::run(args, c),
            None => CommandResult::output("test: context not available\r\n".to_string()),
        },
        "ping" => match ctx {
            Some(c) => ping_cmd::run(args, c),
            None => CommandResult::output("ping: context not available\r\n".to_string()),
        },
        "resolve" => match ctx {
            Some(c) => resolve_cmd::run(args, c),
            None => CommandResult::output("resolve: context not available\r\n".to_string()),
        },
        "bookmark" => match ctx {
            Some(c) => bookmark::run(args, c),
            None => CommandResult::output("bookmark: context not available\r\n".to_string()),
        },
        "alias" => match ctx {
            Some(c) => alias_cmd::run(args, c),
            None => CommandResult::output("alias: context not available\r\n".to_string()),
        },

        _ if cmd.starts_with('#') => CommandResult::empty(),
        _ => CommandResult::output(format!("{}: command not found\r\n", cmd)),
    }
}

/// Shared test helpers for shell command tests.
#[cfg(test)]
pub mod test_helpers {
    use crate::config::acl::ParsedAcl;
    use crate::config::types::{AclPolicyConfig, ShellPermissions, UserRole};
    use crate::shell::context::ShellContext;
    use std::collections::HashMap;
    use std::time::Instant;

    /// Create a default `ShellContext` for testing with an allow-all ACL.
    ///
    /// Tests that need a specific ACL configuration or custom field values
    /// can modify the returned context as needed.
    pub fn make_test_ctx() -> ShellContext {
        let acl = ParsedAcl::from_config(AclPolicyConfig::Allow, &[], &[]).unwrap();
        ShellContext {
            username: "testuser".to_string(),
            auth_method: "password".to_string(),
            source_ip: "127.0.0.1".to_string(),
            role: UserRole::User,
            group: None,
            permissions: ShellPermissions::default(),
            acl,
            colors: false,
            expires_at: None,
            max_bandwidth_kbps: 0,
            server_start_time: Instant::now(),
            bookmarks: HashMap::new(),
            aliases: HashMap::new(),
            ssh_key_fingerprint: None,
            proxy_engine: None,
            quota_tracker: None,
            quota_config: None,
        }
    }
}
