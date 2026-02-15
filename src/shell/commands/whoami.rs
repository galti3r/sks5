use crate::shell::commands::CommandResult;

pub fn run(username: &str) -> CommandResult {
    CommandResult::output(format!("{}\r\n", username))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whoami_returns_username() {
        let result = run("alice");
        assert_eq!(result.output, "alice\r\n");
        assert!(!result.exit_requested);
    }

    #[test]
    fn whoami_different_users() {
        assert_eq!(run("alice").output, "alice\r\n");
        assert_eq!(run("bob").output, "bob\r\n");
        assert_eq!(run("root").output, "root\r\n");
    }

    #[test]
    fn whoami_output_ends_with_crlf() {
        let result = run("testuser");
        assert!(result.output.ends_with("\r\n"));
    }

    #[test]
    fn whoami_does_not_request_exit() {
        let result = run("user");
        assert!(!result.exit_requested);
    }

    #[test]
    fn whoami_empty_username() {
        let result = run("");
        assert_eq!(result.output, "\r\n");
    }

    #[test]
    fn whoami_special_characters_in_username() {
        let result = run("user-name_123");
        assert_eq!(result.output, "user-name_123\r\n");
    }
}
