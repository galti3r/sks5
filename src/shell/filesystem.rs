use std::collections::{BTreeMap, HashSet};

/// A virtual in-memory filesystem that exposes no real files
#[derive(Debug, Clone)]
pub struct VirtualFs {
    /// Map of path -> file content (for readable files)
    files: BTreeMap<String, String>,
    /// Set of directories
    dirs: HashSet<String>,
    /// Current working directory
    cwd: String,
    /// Home directory
    home: String,
}

impl VirtualFs {
    pub fn new(username: &str, hostname: &str) -> Self {
        let home = format!("/home/{}", username);
        let mut files = BTreeMap::new();
        let mut dirs = HashSet::from([
            "/".to_string(),
            "/home".to_string(),
            home.clone(),
            "/etc".to_string(),
            "/tmp".to_string(),
            "/var".to_string(),
            "/var/log".to_string(),
        ]);

        // Virtual files
        files.insert("/etc/hostname".to_string(), format!("{}\n", hostname));
        files.insert(
            "/etc/os-release".to_string(),
            format!(
                "NAME=\"sks5\"\nVERSION=\"{}\"\nID=sks5\nPRETTY_NAME=\"sks5 SSH Proxy\"\n",
                env!("CARGO_PKG_VERSION")
            ),
        );
        files.insert(
            "/etc/passwd".to_string(),
            format!("{}:x:1000:1000::/home/{}:/bin/sh\n", username, username),
        );
        files.insert(
            format!("{}/.profile", home),
            "# sks5 shell profile\n".to_string(),
        );

        // Ensure home subdirectory structure
        dirs.insert(format!("{}/.ssh", home));

        Self {
            files,
            dirs,
            cwd: home.clone(),
            home,
        }
    }

    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    pub fn home(&self) -> &str {
        &self.home
    }

    /// Change directory, returns Ok(()) or Err with message
    pub fn cd(&mut self, path: &str) -> Result<(), String> {
        let resolved = self.resolve_path(path);

        if self.is_dir(&resolved) {
            self.cwd = resolved;
            Ok(())
        } else if self.is_file(&resolved) {
            Err(format!("cd: not a directory: {}", path))
        } else {
            Err(format!("cd: no such file or directory: {}", path))
        }
    }

    /// Read a virtual file
    pub fn read_file(&self, path: &str) -> Result<&str, String> {
        let resolved = self.resolve_path(path);
        self.files
            .get(&resolved)
            .map(|s| s.as_str())
            .ok_or_else(|| format!("cat: {}: No such file or directory", path))
    }

    /// List directory contents
    pub fn list_dir(&self, path: &str) -> Result<Vec<DirEntry>, String> {
        let resolved = self.resolve_path(path);
        if !self.is_dir(&resolved) {
            if self.is_file(&resolved) {
                let name = resolved.rsplit('/').next().unwrap_or(&resolved);
                return Ok(vec![DirEntry {
                    name: name.to_string(),
                    is_dir: false,
                }]);
            }
            return Err(format!(
                "ls: cannot access '{}': No such file or directory",
                path
            ));
        }

        let prefix = if resolved == "/" {
            "/".to_string()
        } else {
            format!("{}/", resolved)
        };

        let mut entries = Vec::new();

        // Find subdirectories
        for dir in &self.dirs {
            if dir == &resolved {
                continue;
            }
            if let Some(rest) = dir.strip_prefix(&prefix) {
                if !rest.contains('/') && !rest.is_empty() {
                    entries.push(DirEntry {
                        name: rest.to_string(),
                        is_dir: true,
                    });
                }
            }
        }

        // Find files
        for file_path in self.files.keys() {
            if let Some(rest) = file_path.strip_prefix(&prefix) {
                if !rest.contains('/') && !rest.is_empty() {
                    entries.push(DirEntry {
                        name: rest.to_string(),
                        is_dir: false,
                    });
                }
            }
        }

        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    /// Resolve a path (handle ~, .., ., relative)
    pub fn resolve_path(&self, path: &str) -> String {
        let path = if path.starts_with('~') {
            path.replacen('~', &self.home, 1)
        } else {
            path.to_string()
        };

        let base = if path.starts_with('/') {
            String::new()
        } else {
            self.cwd.clone()
        };

        let mut components: Vec<&str> = Vec::new();
        if !base.is_empty() {
            for c in base.split('/') {
                if !c.is_empty() {
                    components.push(c);
                }
            }
        }

        for component in path.split('/') {
            match component {
                "" | "." => {}
                ".." => {
                    components.pop();
                }
                c => components.push(c),
            }
        }

        if components.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", components.join("/"))
        }
    }

    fn is_dir(&self, path: &str) -> bool {
        self.dirs.contains(path)
    }

    fn is_file(&self, path: &str) -> bool {
        self.files.contains_key(path)
    }
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let fs = VirtualFs::new("alice", "bastion");
        assert_eq!(fs.cwd(), "/home/alice");
        assert_eq!(fs.home(), "/home/alice");
    }

    #[test]
    fn test_cd_absolute() {
        let mut fs = VirtualFs::new("alice", "bastion");
        assert!(fs.cd("/tmp").is_ok());
        assert_eq!(fs.cwd(), "/tmp");
    }

    #[test]
    fn test_cd_home() {
        let mut fs = VirtualFs::new("alice", "bastion");
        fs.cd("/tmp").unwrap();
        assert!(fs.cd("~").is_ok());
        assert_eq!(fs.cwd(), "/home/alice");
    }

    #[test]
    fn test_cd_parent() {
        let mut fs = VirtualFs::new("alice", "bastion");
        assert!(fs.cd("..").is_ok());
        assert_eq!(fs.cwd(), "/home");
        assert!(fs.cd("..").is_ok());
        assert_eq!(fs.cwd(), "/");
    }

    #[test]
    fn test_cd_nonexistent() {
        let mut fs = VirtualFs::new("alice", "bastion");
        assert!(fs.cd("/nonexistent").is_err());
    }

    #[test]
    fn test_read_file() {
        let fs = VirtualFs::new("alice", "bastion");
        let content = fs.read_file("/etc/hostname").unwrap();
        assert_eq!(content, "bastion\n");
    }

    #[test]
    fn test_read_nonexistent() {
        let fs = VirtualFs::new("alice", "bastion");
        assert!(fs.read_file("/etc/shadow").is_err());
    }

    #[test]
    fn test_list_root() {
        let fs = VirtualFs::new("alice", "bastion");
        let entries = fs.list_dir("/").unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"home"));
        assert!(names.contains(&"etc"));
        assert!(names.contains(&"tmp"));
    }

    #[test]
    fn test_list_etc() {
        let fs = VirtualFs::new("alice", "bastion");
        let entries = fs.list_dir("/etc").unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"hostname"));
        assert!(names.contains(&"os-release"));
        assert!(names.contains(&"passwd"));
    }

    #[test]
    fn test_resolve_relative() {
        let fs = VirtualFs::new("alice", "bastion");
        assert_eq!(fs.resolve_path(".ssh"), "/home/alice/.ssh");
        assert_eq!(fs.resolve_path("../bob"), "/home/bob");
    }
}
