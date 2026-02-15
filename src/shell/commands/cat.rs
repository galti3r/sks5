use crate::shell::commands::CommandResult;
use crate::shell::filesystem::VirtualFs;

pub fn run(args: &[String], fs: &VirtualFs) -> CommandResult {
    if args.is_empty() {
        return CommandResult::output("cat: missing operand\r\n".to_string());
    }

    let mut output = String::new();
    for path in args {
        match fs.read_file(path) {
            Ok(content) => {
                // Convert LF to CR+LF for terminal display
                for line in content.split('\n') {
                    if !line.is_empty() {
                        output.push_str(line);
                        output.push_str("\r\n");
                    }
                }
            }
            Err(msg) => {
                output.push_str(&format!("{}\r\n", msg));
            }
        }
    }
    CommandResult::output(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fs() -> VirtualFs {
        VirtualFs::new("testuser", "testhost")
    }

    #[test]
    fn cat_no_args_shows_missing_operand() {
        let fs = make_fs();
        let result = run(&[], &fs);
        assert!(result.output.contains("cat: missing operand"));
        assert!(!result.exit_requested);
    }

    #[test]
    fn cat_existing_file_returns_content() {
        let fs = make_fs();
        let result = run(&["/etc/hostname".to_string()], &fs);
        assert!(result.output.contains("testhost"));
        assert!(!result.exit_requested);
    }

    #[test]
    fn cat_nonexistent_file_shows_error() {
        let fs = make_fs();
        let result = run(&["/etc/shadow".to_string()], &fs);
        assert!(result.output.contains("No such file"));
    }

    #[test]
    fn cat_etc_passwd_contains_username() {
        let fs = make_fs();
        let result = run(&["/etc/passwd".to_string()], &fs);
        assert!(result.output.contains("testuser"));
    }

    #[test]
    fn cat_etc_os_release_contains_sks5() {
        let fs = make_fs();
        let result = run(&["/etc/os-release".to_string()], &fs);
        assert!(result.output.contains("sks5"));
    }

    #[test]
    fn cat_multiple_files_concatenates_output() {
        let fs = make_fs();
        let result = run(
            &["/etc/hostname".to_string(), "/etc/passwd".to_string()],
            &fs,
        );
        assert!(result.output.contains("testhost"));
        assert!(result.output.contains("testuser"));
    }

    #[test]
    fn cat_mixed_existing_and_nonexistent() {
        let fs = make_fs();
        let result = run(
            &["/etc/hostname".to_string(), "/no/such/file".to_string()],
            &fs,
        );
        assert!(result.output.contains("testhost"));
        assert!(result.output.contains("No such file"));
    }

    #[test]
    fn cat_output_uses_crlf() {
        let fs = make_fs();
        let result = run(&["/etc/hostname".to_string()], &fs);
        assert!(result.output.contains("\r\n"));
    }

    #[test]
    fn cat_profile_file() {
        let fs = make_fs();
        let result = run(&["/home/testuser/.profile".to_string()], &fs);
        assert!(result.output.contains("sks5 shell profile"));
    }
}
