pub mod commands;
pub mod context;
pub mod executor;
pub mod filesystem;
pub mod parser;
pub mod terminal;

use crate::persistence::userdata::UserDataStore;
use anyhow::Result;
use context::ShellContext;
use executor::CommandExecutor;
use russh::CryptoVec;
use std::sync::Arc;
use terminal::TerminalState;

/// A shell session attached to an SSH channel.
///
/// The `Channel<server::Msg>` received in `channel_open_session` is
/// intentionally NOT stored here. russh delivers every incoming message to
/// the Channel's internal bounded mpsc (`channel_buffer_size`, default 100)
/// **before** calling the Handler callback, and that send is awaited.  If
/// the receiver is never drained the buffer fills up and the entire SSH
/// session event loop deadlocks.  Dropping the Channel drops its `Receiver`,
/// making `chan.send()` return `Err` immediately (caught by `.unwrap_or(())`).
/// The SSH channel stays open — `Channel` has no `Drop` impl; only
/// `ChannelCloseOnDrop` (used by `into_stream()`) sends `SSH_MSG_CHANNEL_CLOSE`.
pub struct ShellSession {
    terminal: TerminalState,
    executor: CommandExecutor,
    closed: bool,
    /// Pre-rendered MOTD to send on shell_request
    motd: Option<String>,
    /// Username for this session (used for userdata recording)
    username: String,
    /// Optional userdata store for persisting history/bookmarks
    userdata_store: Option<Arc<UserDataStore>>,
}

impl ShellSession {
    pub fn new(username: String, hostname: String) -> Self {
        Self {
            terminal: TerminalState::new(),
            executor: CommandExecutor::new(username.clone(), hostname),
            closed: false,
            motd: None,
            username,
            userdata_store: None,
        }
    }

    /// Create a new shell session with pre-loaded command history.
    pub fn new_with_history(username: String, hostname: String, history: Vec<String>) -> Self {
        Self {
            terminal: TerminalState::with_history(history),
            executor: CommandExecutor::new(username.clone(), hostname),
            closed: false,
            motd: None,
            username,
            userdata_store: None,
        }
    }

    /// Set the userdata store for recording history and bookmarks.
    pub fn set_userdata_store(&mut self, store: Arc<UserDataStore>) {
        self.userdata_store = Some(store);
    }

    /// Get a reference to the terminal's command history.
    pub fn history(&self) -> &[String] {
        self.terminal.history()
    }

    /// Set the shell context for extended commands (show, test, ping, etc.).
    pub fn set_context(&mut self, ctx: ShellContext) {
        self.terminal.autocomplete = ctx.colors; // colors implies full UX
        self.executor.set_context(ctx);
    }

    /// Set the MOTD to display when the shell starts.
    pub fn set_motd(&mut self, motd: String) {
        self.motd = Some(motd);
    }

    /// Take the MOTD (returns it once, then None on subsequent calls).
    pub fn take_motd(&mut self) -> Option<String> {
        self.motd.take()
    }

    pub fn set_terminal_size(&mut self, cols: u32, rows: u32) {
        self.terminal.set_size(cols, rows);
    }

    /// Send the shell prompt
    pub async fn send_prompt(
        &mut self,
        session: &mut russh::server::Session,
        channel_id: russh::ChannelId,
    ) -> Result<()> {
        let prompt = self.executor.prompt();
        let _ = session.data(channel_id, CryptoVec::from_slice(prompt.as_bytes()));
        Ok(())
    }

    /// Handle input data from the SSH client
    pub async fn handle_input(
        &mut self,
        data: &[u8],
        session: &mut russh::server::Session,
        channel_id: russh::ChannelId,
    ) -> Result<()> {
        if self.closed {
            return Ok(());
        }

        for &byte in data {
            let (echo, completed_line) = self.terminal.process_byte(byte);

            // Echo back to the client
            if !echo.is_empty() {
                let _ = session.data(channel_id, CryptoVec::from_slice(&echo));
            }

            // If we got a completed line, execute it
            if let Some(line) = completed_line {
                if line.is_empty() {
                    // Just a newline, show prompt again
                    let prompt = self.executor.prompt();
                    let _ = session.data(channel_id, CryptoVec::from_slice(prompt.as_bytes()));
                    continue;
                }

                // Record command to userdata store for persistence
                if let Some(ref store) = self.userdata_store {
                    store.record_command(&self.username, line.clone());
                }

                let result = self.executor.execute(&line);

                if !result.output.is_empty() {
                    let _ =
                        session.data(channel_id, CryptoVec::from_slice(result.output.as_bytes()));
                }

                if result.exit_requested {
                    // Flush user data on clean exit
                    if let Some(ref store) = self.userdata_store {
                        store.flush_user(&self.username);
                    }
                    self.closed = true;
                    let _ = session.close(channel_id);
                    return Ok(());
                }

                // Show prompt for next command
                let prompt = self.executor.prompt();
                let _ = session.data(channel_id, CryptoVec::from_slice(prompt.as_bytes()));
            }
        }

        Ok(())
    }
}

impl Drop for ShellSession {
    fn drop(&mut self) {
        // Flush user data on session drop (covers disconnect without clean exit)
        if let Some(ref store) = self.userdata_store {
            store.flush_user(&self.username);
        }
    }
}
