use crate::shell::commands::CommandResult;
use crate::shell::filesystem::VirtualFs;

pub fn run(fs: &VirtualFs) -> CommandResult {
    CommandResult::output(format!("{}\r\n", fs.cwd()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pwd_returns_home_directory_initially() {
        let fs = VirtualFs::new("testuser", "testhost");
        let result = run(&fs);
        assert_eq!(result.output, "/home/testuser\r\n");
        assert!(!result.exit_requested);
    }

    #[test]
    fn pwd_reflects_cd_change() {
        let mut fs = VirtualFs::new("testuser", "testhost");
        fs.cd("/tmp").unwrap();
        let result = run(&fs);
        assert_eq!(result.output, "/tmp\r\n");
    }

    #[test]
    fn pwd_after_cd_to_root() {
        let mut fs = VirtualFs::new("testuser", "testhost");
        fs.cd("/").unwrap();
        let result = run(&fs);
        assert_eq!(result.output, "/\r\n");
    }

    #[test]
    fn pwd_after_cd_parent() {
        let mut fs = VirtualFs::new("testuser", "testhost");
        fs.cd("..").unwrap();
        let result = run(&fs);
        assert_eq!(result.output, "/home\r\n");
    }

    #[test]
    fn pwd_output_ends_with_crlf() {
        let fs = VirtualFs::new("alice", "host");
        let result = run(&fs);
        assert!(result.output.ends_with("\r\n"));
    }

    #[test]
    fn pwd_different_usernames() {
        let fs = VirtualFs::new("alice", "host");
        let result = run(&fs);
        assert_eq!(result.output, "/home/alice\r\n");

        let fs2 = VirtualFs::new("bob", "host");
        let result2 = run(&fs2);
        assert_eq!(result2.output, "/home/bob\r\n");
    }
}
