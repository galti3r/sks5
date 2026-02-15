use crate::shell::commands::CommandResult;
use crate::shell::filesystem::VirtualFs;

pub fn run(args: &[String], fs: &mut VirtualFs) -> CommandResult {
    let path = args.first().map(|s| s.as_str()).unwrap_or("~");
    match fs.cd(path) {
        Ok(()) => CommandResult::empty(),
        Err(msg) => CommandResult::output(format!("{}\r\n", msg)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fs() -> VirtualFs {
        VirtualFs::new("testuser", "testhost")
    }

    #[test]
    fn cd_no_args_goes_home() {
        let mut fs = make_fs();
        // First move somewhere else
        fs.cd("/tmp").unwrap();
        assert_eq!(fs.cwd(), "/tmp");

        let result = run(&[], &mut fs);
        assert!(result.output.is_empty());
        assert!(!result.exit_requested);
        assert_eq!(fs.cwd(), "/home/testuser");
    }

    #[test]
    fn cd_absolute_path() {
        let mut fs = make_fs();
        let result = run(&["/tmp".to_string()], &mut fs);
        assert!(result.output.is_empty());
        assert_eq!(fs.cwd(), "/tmp");
    }

    #[test]
    fn cd_home_tilde() {
        let mut fs = make_fs();
        fs.cd("/tmp").unwrap();
        let result = run(&["~".to_string()], &mut fs);
        assert!(result.output.is_empty());
        assert_eq!(fs.cwd(), "/home/testuser");
    }

    #[test]
    fn cd_parent_directory() {
        let mut fs = make_fs();
        let result = run(&["..".to_string()], &mut fs);
        assert!(result.output.is_empty());
        assert_eq!(fs.cwd(), "/home");
    }

    #[test]
    fn cd_root() {
        let mut fs = make_fs();
        let result = run(&["/".to_string()], &mut fs);
        assert!(result.output.is_empty());
        assert_eq!(fs.cwd(), "/");
    }

    #[test]
    fn cd_nonexistent_directory_shows_error() {
        let mut fs = make_fs();
        let result = run(&["/nonexistent".to_string()], &mut fs);
        assert!(result.output.contains("no such file or directory"));
        // cwd should not change
        assert_eq!(fs.cwd(), "/home/testuser");
    }

    #[test]
    fn cd_to_file_shows_not_a_directory() {
        let mut fs = make_fs();
        let result = run(&["/etc/hostname".to_string()], &mut fs);
        assert!(result.output.contains("not a directory"));
        assert_eq!(fs.cwd(), "/home/testuser");
    }

    #[test]
    fn cd_etc() {
        let mut fs = make_fs();
        let result = run(&["/etc".to_string()], &mut fs);
        assert!(result.output.is_empty());
        assert_eq!(fs.cwd(), "/etc");
    }

    #[test]
    fn cd_var_log() {
        let mut fs = make_fs();
        let result = run(&["/var/log".to_string()], &mut fs);
        assert!(result.output.is_empty());
        assert_eq!(fs.cwd(), "/var/log");
    }

    #[test]
    fn cd_dot_stays_in_same_directory() {
        let mut fs = make_fs();
        let original = fs.cwd().to_string();
        let result = run(&[".".to_string()], &mut fs);
        assert!(result.output.is_empty());
        assert_eq!(fs.cwd(), original);
    }
}
