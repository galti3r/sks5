use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, warn};

/// Persisted per-user data.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserData {
    #[serde(default)]
    pub shell_history: Vec<String>,
    #[serde(default)]
    pub bookmarks: HashMap<String, String>,
    #[serde(default)]
    pub preferences: HashMap<String, String>,
}

/// In-memory store for user data with dirty tracking.
///
/// Thread-safe via `DashMap`. Periodic flush writes dirty entries to disk.
pub struct UserDataStore {
    users_dir: PathBuf,
    data: DashMap<String, UserData>,
    dirty: DashMap<String, bool>,
    history_max: usize,
    bookmarks_max: usize,
    available: bool,
}

impl UserDataStore {
    pub fn new(
        users_dir: PathBuf,
        history_max: usize,
        bookmarks_max: usize,
        available: bool,
    ) -> Self {
        if available {
            let _ = std::fs::create_dir_all(&users_dir);
        }
        Self {
            users_dir,
            data: DashMap::new(),
            dirty: DashMap::new(),
            history_max,
            bookmarks_max,
            available,
        }
    }

    /// Load user data from disk, or return default if not found/corrupt.
    pub fn load_user(&self, username: &str) -> UserData {
        if let Some(entry) = self.data.get(username) {
            return entry.clone();
        }

        let data = if self.available {
            let path = self.user_path(username);
            match load_user_file(&path) {
                Ok(Some(mut d)) => {
                    // Enforce limits on load
                    if d.shell_history.len() > self.history_max {
                        let skip = d.shell_history.len() - self.history_max;
                        d.shell_history = d.shell_history.into_iter().skip(skip).collect();
                    }
                    d
                }
                Ok(None) => UserData::default(),
                Err(e) => {
                    warn!(username = username, error = %e, "Failed to load user data");
                    UserData::default()
                }
            }
        } else {
            UserData::default()
        };

        self.data.insert(username.to_string(), data.clone());
        data
    }

    /// Record a shell command for a user.
    pub fn record_command(&self, username: &str, command: String) {
        if command.is_empty() {
            return;
        }

        let mut entry = self.data.entry(username.to_string()).or_default();
        let history = &mut entry.shell_history;

        // Skip duplicates of the last entry
        if history.last().map(|s| s.as_str()) == Some(&command) {
            return;
        }

        history.push(command);

        // FIFO: remove oldest if over limit
        if history.len() > self.history_max {
            let excess = history.len() - self.history_max;
            history.drain(..excess);
        }

        self.dirty.insert(username.to_string(), true);
    }

    /// Get current bookmarks for a user.
    pub fn get_bookmarks(&self, username: &str) -> HashMap<String, String> {
        self.data
            .get(username)
            .map(|e| e.bookmarks.clone())
            .unwrap_or_default()
    }

    /// Update bookmarks for a user.
    pub fn set_bookmarks(&self, username: &str, bookmarks: HashMap<String, String>) {
        let mut entry = self.data.entry(username.to_string()).or_default();

        // Enforce max bookmarks
        let mut bm = bookmarks;
        if bm.len() > self.bookmarks_max && self.bookmarks_max > 0 {
            let excess = bm.len() - self.bookmarks_max;
            let keys: Vec<String> = bm.keys().take(excess).cloned().collect();
            for k in keys {
                bm.remove(&k);
            }
        }

        entry.bookmarks = bm;
        self.dirty.insert(username.to_string(), true);
    }

    /// Get current history for a user (from memory or disk).
    pub fn get_history(&self, username: &str) -> Vec<String> {
        self.data
            .get(username)
            .map(|e| e.shell_history.clone())
            .unwrap_or_default()
    }

    /// Flush all dirty user data to disk.
    pub fn flush_all(&self) {
        if !self.available {
            return;
        }

        let dirty_users: Vec<String> = self
            .dirty
            .iter()
            .filter(|e| *e.value())
            .map(|e| e.key().clone())
            .collect();

        for username in &dirty_users {
            if let Some(data) = self.data.get(username) {
                let path = self.user_path(username);
                if let Err(e) = save_user_file(&path, &data) {
                    warn!(username = username, error = %e, "Failed to save user data");
                } else {
                    self.dirty.insert(username.clone(), false);
                }
            }
        }

        if !dirty_users.is_empty() {
            debug!(users = dirty_users.len(), "User data flushed");
        }
    }

    /// Flush a specific user's data to disk (only if dirty).
    pub fn flush_user(&self, username: &str) {
        if !self.available {
            return;
        }

        let is_dirty = self.dirty.get(username).map(|d| *d).unwrap_or(false);
        if !is_dirty {
            return;
        }

        if let Some(data) = self.data.get(username) {
            let path = self.user_path(username);
            if let Err(e) = save_user_file(&path, &data) {
                warn!(username = username, error = %e, "Failed to save user data");
            } else {
                self.dirty.insert(username.to_string(), false);
            }
        }
    }

    /// Clean up data for users not in the active user list and older than retention days.
    pub fn cleanup_inactive(&self, active_users: &[String], _retention_days: u32) {
        if !self.available {
            return;
        }

        // Remove from memory
        self.data.retain(|k, _| active_users.contains(k));
        self.dirty.retain(|k, _| active_users.contains(k));

        // Note: actual file deletion based on retention_days is deferred
        // to avoid accidental data loss. Files stay on disk until manually
        // cleaned or a future cleanup pass checks mtime.
    }

    fn user_path(&self, username: &str) -> PathBuf {
        // Sanitize username for filesystem safety
        let safe_name: String = username
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.users_dir.join(format!("{}.json", safe_name))
    }
}

fn save_user_file(path: &Path, data: &UserData) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let tmp_path = path.with_extension("tmp");
    let mut file = std::fs::File::create(&tmp_path)?;
    file.write_all(json.as_bytes())?;
    file.sync_all()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&tmp_path, perms)?;
    }

    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

fn load_user_file(path: &Path) -> std::io::Result<Option<UserData>> {
    if !path.exists() {
        return Ok(None);
    }

    let data = std::fs::read_to_string(path)?;

    match serde_json::from_str::<UserData>(&data) {
        Ok(user_data) => Ok(Some(user_data)),
        Err(e) => {
            warn!(path = %path.display(), error = %e, "Corrupt user data file");
            Ok(Some(UserData::default()))
        }
    }
}

/// Spawn a background task that periodically flushes dirty user data.
pub fn spawn_userdata_flush_task(
    store: Arc<UserDataStore>,
    flush_interval_secs: u64,
    shutdown: tokio_util::sync::CancellationToken,
) {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(flush_interval_secs));
        interval.tick().await; // skip first tick

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    tracing::info!("Shutdown: flushing user data to disk");
                    store.flush_all();
                    return;
                }
                _ = interval.tick() => {
                    store.flush_all();
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_store(tmp: &TempDir, history_max: usize) -> UserDataStore {
        UserDataStore::new(tmp.path().join("users"), history_max, 50, true)
    }

    #[test]
    fn test_record_and_get_history() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, 5);

        store.record_command("alice", "ls".to_string());
        store.record_command("alice", "cd /tmp".to_string());
        store.record_command("alice", "pwd".to_string());

        let history = store.get_history("alice");
        assert_eq!(history, vec!["ls", "cd /tmp", "pwd"]);
    }

    #[test]
    fn test_history_fifo_enforcement() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, 3);

        for i in 0..5 {
            store.record_command("bob", format!("cmd{}", i));
        }

        let history = store.get_history("bob");
        assert_eq!(history, vec!["cmd2", "cmd3", "cmd4"]);
    }

    #[test]
    fn test_history_dedup_last() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, 10);

        store.record_command("alice", "ls".to_string());
        store.record_command("alice", "ls".to_string());
        store.record_command("alice", "pwd".to_string());
        store.record_command("alice", "pwd".to_string());

        let history = store.get_history("alice");
        assert_eq!(history, vec!["ls", "pwd"]);
    }

    #[test]
    fn test_empty_command_ignored() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, 10);

        store.record_command("alice", "".to_string());
        assert!(store.get_history("alice").is_empty());
    }

    #[test]
    fn test_bookmarks_crud() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, 10);

        let mut bm = HashMap::new();
        bm.insert("prod".to_string(), "api.example.com:443".to_string());
        bm.insert("dev".to_string(), "dev.example.com:8080".to_string());
        store.set_bookmarks("alice", bm);

        let loaded = store.get_bookmarks("alice");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded["prod"], "api.example.com:443");
    }

    #[test]
    fn test_flush_and_reload() {
        let tmp = TempDir::new().unwrap();

        // First store: write data
        {
            let store = make_store(&tmp, 10);
            store.record_command("alice", "connect example.com:443".to_string());
            store.record_command("alice", "status".to_string());

            let mut bm = HashMap::new();
            bm.insert("prod".to_string(), "api.example.com:443".to_string());
            store.set_bookmarks("alice", bm);

            store.flush_all();
        }

        // Second store: reload from disk
        {
            let store = make_store(&tmp, 10);
            let data = store.load_user("alice");
            assert_eq!(
                data.shell_history,
                vec!["connect example.com:443", "status"]
            );
            assert_eq!(data.bookmarks.len(), 1);
            assert_eq!(data.bookmarks["prod"], "api.example.com:443");
        }
    }

    #[test]
    fn test_corrupt_user_file() {
        let tmp = TempDir::new().unwrap();
        let users_dir = tmp.path().join("users");
        std::fs::create_dir_all(&users_dir).unwrap();
        std::fs::write(users_dir.join("bob.json"), "not json").unwrap();

        let store = make_store(&tmp, 10);
        let data = store.load_user("bob");
        assert!(data.shell_history.is_empty());
    }

    #[test]
    fn test_username_sanitization() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, 10);

        // Username with special chars should be sanitized
        store.record_command("user/../etc", "cmd".to_string());
        store.flush_all();

        // File should exist with sanitized name
        let path = tmp.path().join("users").join("user____etc.json");
        assert!(path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn test_user_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, 10);

        store.record_command("alice", "test".to_string());
        store.flush_all();

        let path = tmp.path().join("users").join("alice.json");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn test_history_enforced_on_load() {
        let tmp = TempDir::new().unwrap();

        // Write a file with more than max history
        {
            let store = UserDataStore::new(
                tmp.path().join("users"),
                100, // large max for writing
                50,
                true,
            );
            for i in 0..20 {
                store.record_command("alice", format!("cmd{}", i));
            }
            store.flush_all();
        }

        // Reload with small max
        {
            let store = UserDataStore::new(
                tmp.path().join("users"),
                5, // small max
                50,
                true,
            );
            let data = store.load_user("alice");
            assert_eq!(data.shell_history.len(), 5);
            assert_eq!(data.shell_history[0], "cmd15");
            assert_eq!(data.shell_history[4], "cmd19");
        }
    }

    #[test]
    fn test_unavailable_store() {
        let tmp = TempDir::new().unwrap();
        let store = UserDataStore::new(
            tmp.path().join("users"),
            10,
            50,
            false, // not available
        );

        store.record_command("alice", "test".to_string());
        store.flush_all(); // should not crash

        // History should still work in memory
        let history = store.get_history("alice");
        assert_eq!(history, vec!["test"]);
    }

    #[test]
    fn test_flush_user_only_when_dirty() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, 10);

        // Load user without modification — no dirty flag set
        let _ = store.load_user("alice");
        store.flush_user("alice");

        // File should NOT exist because nothing was dirty
        let path = tmp.path().join("users").join("alice.json");
        assert!(!path.exists(), "File should not exist for non-dirty user");
    }

    #[test]
    fn test_flush_user_writes_when_dirty() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, 10);

        store.record_command("alice", "whoami".to_string());
        store.flush_user("alice");

        let path = tmp.path().join("users").join("alice.json");
        assert!(path.exists(), "File should exist after flushing dirty user");

        let content = std::fs::read_to_string(&path).unwrap();
        let data: UserData = serde_json::from_str(&content).unwrap();
        assert_eq!(data.shell_history, vec!["whoami"]);

        // Second flush should be a no-op (dirty reset to false)
        let mtime_before = std::fs::metadata(&path).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        store.flush_user("alice");
        let mtime_after = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(mtime_before, mtime_after, "Second flush should be no-op");
    }

    #[test]
    fn test_cleanup_inactive_removes_from_memory() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, 10);

        store.record_command("alice", "cmd1".to_string());
        store.record_command("bob", "cmd2".to_string());
        store.record_command("charlie", "cmd3".to_string());

        // Only alice is active
        store.cleanup_inactive(&["alice".to_string()], 30);

        assert_eq!(store.get_history("alice"), vec!["cmd1"]);
        // bob and charlie should be gone from memory
        assert!(store.get_history("bob").is_empty());
        assert!(store.get_history("charlie").is_empty());
    }

    #[test]
    fn test_cleanup_inactive_keeps_active_users() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, 10);

        store.record_command("alice", "cmd1".to_string());
        store.record_command("bob", "cmd2".to_string());

        // Both are active
        store.cleanup_inactive(&["alice".to_string(), "bob".to_string()], 30);

        assert_eq!(store.get_history("alice"), vec!["cmd1"]);
        assert_eq!(store.get_history("bob"), vec!["cmd2"]);
    }

    #[test]
    fn test_bookmarks_max_enforcement() {
        let tmp = TempDir::new().unwrap();
        let store = UserDataStore::new(tmp.path().join("users"), 10, 3, true);

        let mut bm = HashMap::new();
        for i in 0..10 {
            bm.insert(format!("bm{}", i), format!("host{}:443", i));
        }
        store.set_bookmarks("alice", bm);

        let loaded = store.get_bookmarks("alice");
        assert_eq!(loaded.len(), 3, "Should enforce max bookmarks of 3");
    }

    #[test]
    fn test_bookmarks_max_zero_unlimited() {
        let tmp = TempDir::new().unwrap();
        let store = UserDataStore::new(tmp.path().join("users"), 10, 0, true);

        let mut bm = HashMap::new();
        for i in 0..100 {
            bm.insert(format!("bm{}", i), format!("host{}:443", i));
        }
        store.set_bookmarks("alice", bm);

        let loaded = store.get_bookmarks("alice");
        assert_eq!(loaded.len(), 100, "bookmarks_max=0 should mean unlimited");
    }

    #[tokio::test]
    async fn test_spawn_userdata_flush_task_flushes_on_shutdown() {
        let tmp = TempDir::new().unwrap();
        let store = Arc::new(make_store(&tmp, 10));

        store.record_command("alice", "echo hello".to_string());
        store.record_command("alice", "ls -la".to_string());

        let shutdown = tokio_util::sync::CancellationToken::new();
        spawn_userdata_flush_task(Arc::clone(&store), 3600, shutdown.clone());

        // Cancel immediately to trigger the shutdown flush
        shutdown.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let path = tmp.path().join("users").join("alice.json");
        assert!(path.exists(), "Shutdown flush should have written the file");
        let content = std::fs::read_to_string(&path).unwrap();
        let data: UserData = serde_json::from_str(&content).unwrap();
        assert_eq!(data.shell_history, vec!["echo hello", "ls -la"]);
    }
}
