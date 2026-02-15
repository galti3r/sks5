const MAX_LINE_LENGTH: usize = 4096;

/// Known commands for tab completion
const COMPLETABLE_COMMANDS: &[&str] = &[
    "alias", "bookmark", "cat", "cd", "clear", "echo", "env", "exit", "help", "hostname", "id",
    "logout", "ls", "ping", "printenv", "pwd", "resolve", "show", "test", "uname", "whoami",
];

/// Known show subcommands for tab completion
const SHOW_SUBCOMMANDS: &[&str] = &[
    "acl",
    "bandwidth",
    "connections",
    "fingerprint",
    "history",
    "quota",
    "status",
];

/// Known bookmark subcommands
const BOOKMARK_SUBCOMMANDS: &[&str] = &["add", "list", "remove"];

/// Known alias subcommands
const ALIAS_SUBCOMMANDS: &[&str] = &["remove"];

/// ANSI escape sequence parsing state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EscapeState {
    /// Normal input mode
    Normal,
    /// Received ESC byte, waiting for '[' or other
    GotEsc,
    /// Received ESC+[, waiting for final byte (CSI sequence)
    GotCsi,
}

/// Terminal handling: line editing, echo, special characters, tab-completion, history
pub struct TerminalState {
    /// Current input line buffer
    line_buffer: Vec<u8>,
    /// Cursor position within the line buffer
    cursor_pos: usize,
    /// Terminal width
    pub cols: u32,
    /// Terminal height
    pub rows: u32,
    /// Whether autocomplete is enabled
    pub autocomplete: bool,
    /// Command history (oldest first)
    history: Vec<String>,
    /// Current position in history during navigation (None = not navigating)
    history_index: Option<usize>,
    /// Saved line buffer before history navigation started
    saved_line: Vec<u8>,
    /// ANSI escape sequence parsing state
    esc_state: EscapeState,
}

const MAX_HISTORY: usize = 100;

impl Default for TerminalState {
    fn default() -> Self {
        Self {
            line_buffer: Vec::new(),
            cursor_pos: 0,
            cols: 80,
            rows: 24,
            autocomplete: true,
            history: Vec::new(),
            history_index: None,
            saved_line: Vec::new(),
            esc_state: EscapeState::Normal,
        }
    }
}

impl TerminalState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Process a byte of input, returns (echo_bytes, completed_line)
    pub fn process_byte(&mut self, byte: u8) -> (Vec<u8>, Option<String>) {
        // Handle ESC sequence state machine
        if self.esc_state == EscapeState::GotEsc {
            self.esc_state = EscapeState::Normal;
            if byte == b'[' {
                self.esc_state = EscapeState::GotCsi;
                return (Vec::new(), None);
            }
            // Not a CSI sequence, ignore the ESC + this byte
            return (Vec::new(), None);
        }
        if self.esc_state == EscapeState::GotCsi {
            self.esc_state = EscapeState::Normal;
            return match byte {
                b'A' => self.history_prev(), // Up arrow
                b'B' => self.history_next(), // Down arrow
                b'C' => {
                    // Right arrow: move cursor forward
                    if self.cursor_pos < self.line_buffer.len() {
                        self.cursor_pos += 1;
                        (b"\x1b[C".to_vec(), None)
                    } else {
                        (Vec::new(), None)
                    }
                }
                b'D' => {
                    // Left arrow: move cursor backward
                    if self.cursor_pos > 0 {
                        self.cursor_pos -= 1;
                        (b"\x1b[D".to_vec(), None)
                    } else {
                        (Vec::new(), None)
                    }
                }
                _ => (Vec::new(), None), // Unknown CSI sequence
            };
        }

        match byte {
            // Enter (CR or LF)
            b'\r' | b'\n' => {
                let line = String::from_utf8_lossy(&self.line_buffer).to_string();
                // Add non-empty, non-duplicate lines to history
                if !line.trim().is_empty() && self.history.last() != Some(&line) {
                    self.history.push(line.clone());
                    if self.history.len() > MAX_HISTORY {
                        self.history.remove(0);
                    }
                }
                self.history_index = None;
                self.saved_line.clear();
                self.line_buffer.clear();
                self.cursor_pos = 0;
                (b"\r\n".to_vec(), Some(line))
            }
            // Backspace or DEL
            0x7f | 0x08 => {
                if self.cursor_pos > 0 {
                    self.line_buffer.remove(self.cursor_pos - 1);
                    self.cursor_pos -= 1;
                    // Move cursor back, overwrite with space, move back again
                    (b"\x08 \x08".to_vec(), None)
                } else {
                    (Vec::new(), None)
                }
            }
            // Ctrl+C
            0x03 => {
                self.history_index = None;
                self.saved_line.clear();
                self.line_buffer.clear();
                self.cursor_pos = 0;
                (b"^C\r\n".to_vec(), Some(String::new()))
            }
            // Ctrl+D (EOF)
            0x04 => {
                if self.line_buffer.is_empty() {
                    (Vec::new(), Some("exit".to_string()))
                } else {
                    (Vec::new(), None)
                }
            }
            // Ctrl+U (kill line)
            0x15 => {
                let backspaces = self.cursor_pos;
                self.line_buffer.clear();
                self.cursor_pos = 0;
                let mut echo = Vec::new();
                for _ in 0..backspaces {
                    echo.extend_from_slice(b"\x08 \x08");
                }
                (echo, None)
            }
            // Ctrl+L (clear screen)
            0x0c => {
                // Clear screen, move to top-left
                let mut echo = b"\x1b[2J\x1b[H".to_vec();
                // Re-display the current line
                echo.extend_from_slice(&self.line_buffer);
                (echo, None)
            }
            // Tab - autocomplete
            b'\t' => {
                if !self.autocomplete {
                    return (Vec::new(), None);
                }
                self.handle_tab_completion()
            }
            // ESC sequence start
            0x1b => {
                self.esc_state = EscapeState::GotEsc;
                (Vec::new(), None)
            }
            // Regular printable character
            _ if byte >= 0x20 => {
                if self.line_buffer.len() >= MAX_LINE_LENGTH {
                    return (vec![0x07], None); // BEL
                }
                self.line_buffer.insert(self.cursor_pos, byte);
                self.cursor_pos += 1;
                (vec![byte], None)
            }
            // Ignore other control chars
            _ => (Vec::new(), None),
        }
    }

    /// Replace the current line buffer with new content, returning echo bytes
    /// that clear the old line and display the new one.
    fn replace_line(&mut self, new_content: &[u8]) -> Vec<u8> {
        let mut echo = Vec::new();
        // Move cursor to start of line
        for _ in 0..self.cursor_pos {
            echo.extend_from_slice(b"\x08");
        }
        // Overwrite with spaces to clear
        let old_len = self.line_buffer.len();
        echo.resize(echo.len() + old_len, b' ');
        // Move back to start
        for _ in 0..old_len {
            echo.extend_from_slice(b"\x08");
        }
        // Write new content
        echo.extend_from_slice(new_content);
        self.line_buffer = new_content.to_vec();
        self.cursor_pos = new_content.len();
        echo
    }

    /// Navigate to previous command in history (up arrow)
    fn history_prev(&mut self) -> (Vec<u8>, Option<String>) {
        if self.history.is_empty() {
            return (Vec::new(), None);
        }
        let new_index = match self.history_index {
            None => {
                // Save current line before starting history navigation
                self.saved_line = self.line_buffer.clone();
                self.history.len() - 1
            }
            Some(0) => return (Vec::new(), None), // Already at oldest
            Some(i) => i - 1,
        };
        self.history_index = Some(new_index);
        let echo = self.replace_line(self.history[new_index].as_bytes().to_vec().as_slice());
        (echo, None)
    }

    /// Navigate to next command in history (down arrow)
    fn history_next(&mut self) -> (Vec<u8>, Option<String>) {
        match self.history_index {
            None => (Vec::new(), None), // Not in history mode
            Some(i) if i + 1 >= self.history.len() => {
                // Past end of history - restore saved line
                self.history_index = None;
                let saved = self.saved_line.clone();
                self.saved_line.clear();
                let echo = self.replace_line(&saved);
                (echo, None)
            }
            Some(i) => {
                let new_index = i + 1;
                self.history_index = Some(new_index);
                let echo =
                    self.replace_line(self.history[new_index].as_bytes().to_vec().as_slice());
                (echo, None)
            }
        }
    }

    /// Handle tab completion
    fn handle_tab_completion(&mut self) -> (Vec<u8>, Option<String>) {
        let current = String::from_utf8_lossy(&self.line_buffer).to_string();
        let trimmed = current.trim_start();

        let completions = if trimmed.starts_with("show ") {
            // Complete show subcommands
            let prefix = trimmed.strip_prefix("show ").unwrap_or("");
            SHOW_SUBCOMMANDS
                .iter()
                .filter(|c| c.starts_with(prefix))
                .map(|c| format!("show {}", c))
                .collect::<Vec<_>>()
        } else if trimmed.starts_with("bookmark ") {
            let prefix = trimmed.strip_prefix("bookmark ").unwrap_or("");
            BOOKMARK_SUBCOMMANDS
                .iter()
                .filter(|c| c.starts_with(prefix))
                .map(|c| format!("bookmark {}", c))
                .collect::<Vec<_>>()
        } else if trimmed.starts_with("alias ") {
            let prefix = trimmed.strip_prefix("alias ").unwrap_or("");
            ALIAS_SUBCOMMANDS
                .iter()
                .filter(|c| c.starts_with(prefix))
                .map(|c| format!("alias {}", c))
                .collect::<Vec<_>>()
        } else if !trimmed.contains(' ') {
            // Complete top-level commands
            COMPLETABLE_COMMANDS
                .iter()
                .filter(|c| c.starts_with(trimmed))
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };

        if completions.is_empty() {
            return (vec![0x07], None); // BEL - no completions
        }

        if completions.len() == 1 {
            // Single match - complete it
            let completion = &completions[0];
            let suffix = &completion[trimmed.len()..];
            let suffix_with_space = format!("{} ", suffix);

            let bytes = suffix_with_space.as_bytes().to_vec();
            self.line_buffer.extend_from_slice(bytes.as_slice());
            self.cursor_pos = self.line_buffer.len();
            return (bytes, None);
        }

        // Multiple matches - find common prefix and show options
        let common = common_prefix(&completions);
        if common.len() > trimmed.len() {
            // Complete the common prefix
            let suffix = &common[trimmed.len()..];
            let bytes = suffix.as_bytes().to_vec();
            self.line_buffer.extend_from_slice(&bytes);
            self.cursor_pos = self.line_buffer.len();
            return (bytes, None);
        }

        // Show all options
        let mut echo = b"\r\n".to_vec();
        for c in &completions {
            echo.extend_from_slice(c.as_bytes());
            echo.extend_from_slice(b"  ");
        }
        echo.extend_from_slice(b"\r\n");
        // Re-display the current line (caller will re-send prompt)
        echo.extend_from_slice(&self.line_buffer);
        (echo, None)
    }

    pub fn set_size(&mut self, cols: u32, rows: u32) {
        self.cols = cols;
        self.rows = rows;
    }

    /// Get current line buffer content
    pub fn current_line(&self) -> String {
        String::from_utf8_lossy(&self.line_buffer).to_string()
    }
}

/// Find the longest common prefix among a set of strings
fn common_prefix(strings: &[String]) -> String {
    if strings.is_empty() {
        return String::new();
    }
    let first = &strings[0];
    let mut len = first.len();
    for s in &strings[1..] {
        len = len.min(s.len());
        for (i, (a, b)) in first.bytes().zip(s.bytes()).enumerate() {
            if a != b {
                len = len.min(i);
                break;
            }
        }
    }
    first[..len].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_input() {
        let mut term = TerminalState::new();
        let (echo, line) = term.process_byte(b'h');
        assert_eq!(echo, vec![b'h']);
        assert!(line.is_none());

        let (_, line) = term.process_byte(b'i');
        assert!(line.is_none());

        let (echo, line) = term.process_byte(b'\r');
        assert_eq!(echo, b"\r\n");
        assert_eq!(line, Some("hi".to_string()));
    }

    #[test]
    fn test_backspace() {
        let mut term = TerminalState::new();
        term.process_byte(b'a');
        term.process_byte(b'b');
        let (echo, _) = term.process_byte(0x7f);
        assert_eq!(echo, b"\x08 \x08");

        let (_, line) = term.process_byte(b'\r');
        assert_eq!(line, Some("a".to_string()));
    }

    #[test]
    fn test_ctrl_c() {
        let mut term = TerminalState::new();
        term.process_byte(b'h');
        let (echo, line) = term.process_byte(0x03);
        assert!(echo.starts_with(b"^C"));
        assert_eq!(line, Some(String::new()));
    }

    #[test]
    fn test_ctrl_d_empty() {
        let mut term = TerminalState::new();
        let (_, line) = term.process_byte(0x04);
        assert_eq!(line, Some("exit".to_string()));
    }

    #[test]
    fn test_ctrl_d_nonempty() {
        let mut term = TerminalState::new();
        term.process_byte(b'x');
        let (_, line) = term.process_byte(0x04);
        assert!(line.is_none());
    }

    #[test]
    fn test_max_line_length() {
        let mut term = TerminalState::new();
        // Fill buffer to max
        for _ in 0..MAX_LINE_LENGTH {
            let (echo, _) = term.process_byte(b'a');
            assert_eq!(echo, vec![b'a']);
        }
        // Next character should return BEL
        let (echo, _) = term.process_byte(b'b');
        assert_eq!(echo, vec![0x07]);
        // Buffer should still be at max length
        let (_, line) = term.process_byte(b'\r');
        assert_eq!(line.as_ref().unwrap().len(), MAX_LINE_LENGTH);
    }

    #[test]
    fn test_max_line_length_bel_returned() {
        let mut term = TerminalState::new();
        for _ in 0..MAX_LINE_LENGTH {
            term.process_byte(b'x');
        }
        let (echo, line) = term.process_byte(b'y');
        assert_eq!(echo, vec![0x07]); // BEL
        assert!(line.is_none());
    }

    #[test]
    fn test_ctrl_u() {
        let mut term = TerminalState::new();
        term.process_byte(b'a');
        term.process_byte(b'b');
        term.process_byte(b'c');
        let (echo, _) = term.process_byte(0x15);
        // Should send 3 backspace-space-backspace sequences
        assert_eq!(echo.len(), 9);
        let (_, line) = term.process_byte(b'\r');
        assert_eq!(line, Some(String::new()));
    }

    #[test]
    fn test_tab_completion_single_match() {
        let mut term = TerminalState::new();
        // Type "who" then tab
        for b in b"who" {
            term.process_byte(*b);
        }
        let (echo, line) = term.process_byte(b'\t');
        // Should complete to "whoami "
        assert!(line.is_none());
        let echo_str = String::from_utf8_lossy(&echo);
        assert!(
            echo_str.contains("ami "),
            "Expected 'ami ' completion, got: {:?}",
            echo_str
        );
    }

    #[test]
    fn test_tab_completion_show_subcommand() {
        let mut term = TerminalState::new();
        // Type "show st" then tab
        for b in b"show st" {
            term.process_byte(*b);
        }
        let (echo, line) = term.process_byte(b'\t');
        assert!(line.is_none());
        let echo_str = String::from_utf8_lossy(&echo);
        assert!(
            echo_str.contains("atus "),
            "Expected 'atus ' completion, got: {:?}",
            echo_str
        );
    }

    #[test]
    fn test_tab_completion_no_match() {
        let mut term = TerminalState::new();
        for b in b"zzz" {
            term.process_byte(*b);
        }
        let (echo, _) = term.process_byte(b'\t');
        assert_eq!(echo, vec![0x07]); // BEL
    }

    #[test]
    fn test_tab_disabled() {
        let mut term = TerminalState::new();
        term.autocomplete = false;
        for b in b"who" {
            term.process_byte(*b);
        }
        let (echo, _) = term.process_byte(b'\t');
        assert!(echo.is_empty());
    }

    #[test]
    fn test_common_prefix() {
        assert_eq!(
            common_prefix(&["show".to_string(), "shell".to_string()]),
            "sh"
        );
        assert_eq!(common_prefix(&["test".to_string()]), "test");
        assert_eq!(common_prefix(&[]), "");
    }

    // Helper: type a string and press Enter
    fn type_line(term: &mut TerminalState, s: &str) {
        for b in s.as_bytes() {
            term.process_byte(*b);
        }
        term.process_byte(b'\r');
    }

    // Helper: send up arrow (ESC [ A)
    fn press_up(term: &mut TerminalState) -> Vec<u8> {
        term.process_byte(0x1b);
        term.process_byte(b'[');
        let (echo, _) = term.process_byte(b'A');
        echo
    }

    // Helper: send down arrow (ESC [ B)
    fn press_down(term: &mut TerminalState) -> Vec<u8> {
        term.process_byte(0x1b);
        term.process_byte(b'[');
        let (echo, _) = term.process_byte(b'B');
        echo
    }

    #[test]
    fn test_history_up_recalls_last_command() {
        let mut term = TerminalState::new();
        type_line(&mut term, "hello");
        type_line(&mut term, "world");

        let echo = press_up(&mut term);
        // Should show "world"
        assert_eq!(term.current_line(), "world");
        assert!(!echo.is_empty());
    }

    #[test]
    fn test_history_up_twice_recalls_older() {
        let mut term = TerminalState::new();
        type_line(&mut term, "first");
        type_line(&mut term, "second");

        press_up(&mut term);
        assert_eq!(term.current_line(), "second");

        press_up(&mut term);
        assert_eq!(term.current_line(), "first");
    }

    #[test]
    fn test_history_up_at_oldest_stays() {
        let mut term = TerminalState::new();
        type_line(&mut term, "only");

        press_up(&mut term);
        assert_eq!(term.current_line(), "only");

        // Pressing up again should stay at "only"
        let echo = press_up(&mut term);
        assert_eq!(term.current_line(), "only");
        assert!(echo.is_empty());
    }

    #[test]
    fn test_history_down_restores_current_line() {
        let mut term = TerminalState::new();
        type_line(&mut term, "old");

        // Type partial line, then navigate history
        for b in b"partial" {
            term.process_byte(*b);
        }
        press_up(&mut term);
        assert_eq!(term.current_line(), "old");

        // Down restores the saved partial line
        press_down(&mut term);
        assert_eq!(term.current_line(), "partial");
    }

    #[test]
    fn test_history_empty_no_crash() {
        let mut term = TerminalState::new();
        let echo = press_up(&mut term);
        assert!(echo.is_empty());
        let echo = press_down(&mut term);
        assert!(echo.is_empty());
    }

    #[test]
    fn test_history_empty_lines_not_stored() {
        let mut term = TerminalState::new();
        type_line(&mut term, "real");
        type_line(&mut term, "");
        type_line(&mut term, "   ");

        press_up(&mut term);
        assert_eq!(term.current_line(), "real");
    }

    #[test]
    fn test_history_duplicate_not_stored() {
        let mut term = TerminalState::new();
        type_line(&mut term, "same");
        type_line(&mut term, "same");

        press_up(&mut term);
        assert_eq!(term.current_line(), "same");
        // Should only have one entry
        let echo = press_up(&mut term);
        assert!(echo.is_empty());
    }

    #[test]
    fn test_left_right_arrow() {
        let mut term = TerminalState::new();
        for b in b"abc" {
            term.process_byte(*b);
        }
        assert_eq!(term.cursor_pos, 3);

        // Left arrow
        term.process_byte(0x1b);
        term.process_byte(b'[');
        let (echo, _) = term.process_byte(b'D');
        assert_eq!(echo, b"\x1b[D");
        assert_eq!(term.cursor_pos, 2);

        // Right arrow
        term.process_byte(0x1b);
        term.process_byte(b'[');
        let (echo, _) = term.process_byte(b'C');
        assert_eq!(echo, b"\x1b[C");
        assert_eq!(term.cursor_pos, 3);

        // Right at end = no move
        term.process_byte(0x1b);
        term.process_byte(b'[');
        let (echo, _) = term.process_byte(b'C');
        assert!(echo.is_empty());
        assert_eq!(term.cursor_pos, 3);
    }

    #[test]
    fn test_history_submit_recalled_command() {
        let mut term = TerminalState::new();
        type_line(&mut term, "first");
        type_line(&mut term, "second");

        press_up(&mut term);
        // Submit the recalled command
        let (_, line) = term.process_byte(b'\r');
        assert_eq!(line, Some("second".to_string()));
    }
}
