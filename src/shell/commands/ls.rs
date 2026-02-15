use crate::shell::commands::CommandResult;
use crate::shell::filesystem::VirtualFs;

pub fn run(args: &[String], fs: &VirtualFs) -> CommandResult {
    let show_hidden = args.iter().any(|a| a.contains('a'));
    let long_format = args.iter().any(|a| a.contains('l'));

    let path = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(|s| s.as_str())
        .unwrap_or(".");

    match fs.list_dir(path) {
        Ok(entries) => {
            let entries: Vec<_> = entries
                .into_iter()
                .filter(|e| show_hidden || !e.name.starts_with('.'))
                .collect();

            if entries.is_empty() {
                return CommandResult::empty();
            }

            if long_format {
                let mut output = String::new();
                for entry in &entries {
                    if entry.is_dir {
                        output.push_str(&format!(
                            "drwxr-xr-x  2 root root 4096 Jan  1 00:00 {}\r\n",
                            entry.name
                        ));
                    } else {
                        output.push_str(&format!(
                            "-rw-r--r--  1 root root   64 Jan  1 00:00 {}\r\n",
                            entry.name
                        ));
                    }
                }
                CommandResult::output(output)
            } else {
                let names: Vec<String> = entries
                    .iter()
                    .map(|e| {
                        if e.is_dir {
                            format!("{}/", e.name)
                        } else {
                            e.name.clone()
                        }
                    })
                    .collect();
                CommandResult::output(format!("{}\r\n", names.join("  ")))
            }
        }
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
    fn ls_no_args_lists_current_directory() {
        let fs = make_fs();
        // cwd is /home/testuser which has .profile and .ssh
        let result = run(&[], &fs);
        // Without -a, hidden files are filtered out
        // .profile and .ssh start with '.' so they are hidden
        // The directory may appear empty
        assert!(!result.exit_requested);
    }

    #[test]
    fn ls_root_shows_directories() {
        let mut fs = make_fs();
        fs.cd("/").unwrap();
        let result = run(&[], &fs);
        assert!(result.output.contains("etc"));
        assert!(result.output.contains("home"));
        assert!(result.output.contains("tmp"));
        assert!(result.output.contains("var"));
    }

    #[test]
    fn ls_etc_shows_files() {
        let fs = make_fs();
        let result = run(&["/etc".to_string()], &fs);
        assert!(result.output.contains("hostname"));
        assert!(result.output.contains("os-release"));
        assert!(result.output.contains("passwd"));
    }

    #[test]
    fn ls_with_hidden_flag_shows_dot_files() {
        let fs = make_fs();
        // Home directory has .profile and .ssh
        let result = run(&["-a".to_string()], &fs);
        assert!(result.output.contains(".profile"));
        assert!(result.output.contains(".ssh"));
    }

    #[test]
    fn ls_without_hidden_flag_hides_dot_files() {
        let fs = make_fs();
        let result = run(&[], &fs);
        assert!(!result.output.contains(".profile"));
        assert!(!result.output.contains(".ssh"));
    }

    #[test]
    fn ls_long_format_shows_permissions() {
        let fs = make_fs();
        let result = run(&["-l".to_string(), "/etc".to_string()], &fs);
        // Files should show file permissions
        assert!(result.output.contains("-rw-r--r--"));
    }

    #[test]
    fn ls_long_format_directories_show_d_prefix() {
        let mut fs = make_fs();
        fs.cd("/").unwrap();
        let result = run(&["-l".to_string()], &fs);
        // Root contains directories like etc, home, tmp
        assert!(result.output.contains("drwxr-xr-x"));
    }

    #[test]
    fn ls_nonexistent_path_shows_error() {
        let fs = make_fs();
        let result = run(&["/nonexistent".to_string()], &fs);
        assert!(result.output.contains("No such file or directory"));
    }

    #[test]
    fn ls_directories_have_trailing_slash_in_normal_mode() {
        let mut fs = make_fs();
        fs.cd("/").unwrap();
        let result = run(&[], &fs);
        // Directories should have trailing slash
        assert!(result.output.contains("etc/"));
        assert!(result.output.contains("home/"));
    }

    #[test]
    fn ls_combined_flags() {
        let fs = make_fs();
        // -la should show long format with hidden files
        let result = run(&["-la".to_string()], &fs);
        assert!(result.output.contains(".profile"));
        assert!(result.output.contains("-rw-r--r--") || result.output.contains("drwxr-xr-x"));
    }

    #[test]
    fn ls_file_path_shows_single_file() {
        let fs = make_fs();
        let result = run(&["/etc/hostname".to_string()], &fs);
        assert!(result.output.contains("hostname"));
    }

    #[test]
    fn ls_output_uses_crlf() {
        let fs = make_fs();
        let result = run(&["/etc".to_string()], &fs);
        assert!(result.output.contains("\r\n"));
    }
}
