//! Shared ANSI color constants and helper for shell commands.

pub const GREEN: &str = "\x1b[32m";
pub const RED: &str = "\x1b[31m";
pub const YELLOW: &str = "\x1b[33m";
pub const CYAN: &str = "\x1b[36m";
pub const BOLD: &str = "\x1b[1m";
pub const RESET: &str = "\x1b[0m";

/// Wrap `text` in ANSI color codes when `enabled` is true.
pub fn color(code: &str, text: &str, enabled: bool) -> String {
    if enabled {
        format!("{}{}{}", code, text, RESET)
    } else {
        text.to_string()
    }
}
