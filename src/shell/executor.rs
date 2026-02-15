use crate::shell::commands::{self, CommandResult};
use crate::shell::context::ShellContext;
use crate::shell::filesystem::VirtualFs;
use crate::shell::parser;

pub struct CommandExecutor {
    pub fs: VirtualFs,
    pub username: String,
    pub hostname: String,
    pub context: Option<ShellContext>,
}

impl CommandExecutor {
    pub fn new(username: String, hostname: String) -> Self {
        let fs = VirtualFs::new(&username, &hostname);
        Self {
            fs,
            username,
            hostname,
            context: None,
        }
    }

    /// Set the shell context for extended command support.
    pub fn set_context(&mut self, ctx: ShellContext) {
        self.context = Some(ctx);
    }

    pub fn execute(&mut self, line: &str) -> CommandResult {
        let line = line.trim();
        if line.is_empty() {
            return CommandResult::empty();
        }

        let tokens = parser::tokenize(line);
        if tokens.is_empty() {
            return CommandResult::empty();
        }

        let cmd = &tokens[0];
        let args = &tokens[1..];

        commands::execute(
            cmd,
            args,
            &mut self.fs,
            &self.username,
            &self.hostname,
            self.context.as_mut(),
        )
    }

    pub fn prompt(&self) -> String {
        format!(
            "{}@{}:{}{} ",
            self.username,
            self.hostname,
            self.format_cwd(),
            "$"
        )
    }

    fn format_cwd(&self) -> String {
        let cwd = self.fs.cwd();
        let home = self.fs.home();
        if cwd == home {
            "~".to_string()
        } else if let Some(rest) = cwd.strip_prefix(home) {
            format!("~{}", rest)
        } else {
            cwd.to_string()
        }
    }
}
