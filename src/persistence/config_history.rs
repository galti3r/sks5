use std::path::{Path, PathBuf};
use tracing::{debug, warn};

/// Save a snapshot of the current config TOML before a programmatic modification.
///
/// Stores the full file content with an ISO-8601 timestamp filename.
/// Prunes oldest entries when count exceeds `max_entries`.
pub fn save_config_snapshot(
    history_dir: &Path,
    config_content: &str,
    max_entries: u32,
) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(history_dir)?;

    let timestamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let filename = format!("{}.toml", timestamp);
    let path = history_dir.join(&filename);

    super::atomic_write_file(&path, config_content.as_bytes())?;
    debug!(path = %path.display(), "Config snapshot saved");

    // Prune oldest if over limit
    if max_entries > 0 {
        prune_old_entries(history_dir, max_entries)?;
    }

    Ok(path)
}

/// List config history files sorted by name (oldest first).
pub fn list_history(history_dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    if !history_dir.exists() {
        return Ok(Vec::new());
    }

    let mut entries: Vec<PathBuf> = std::fs::read_dir(history_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "toml"))
        .collect();

    entries.sort();
    Ok(entries)
}

/// Remove oldest history files when count exceeds max.
fn prune_old_entries(history_dir: &Path, max_entries: u32) -> std::io::Result<()> {
    let entries = list_history(history_dir)?;
    let max = max_entries as usize;

    if entries.len() > max {
        let to_remove = entries.len() - max;
        for path in entries.into_iter().take(to_remove) {
            if let Err(e) = std::fs::remove_file(&path) {
                warn!(path = %path.display(), error = %e, "Failed to prune config history entry");
            } else {
                debug!(path = %path.display(), "Pruned old config history entry");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_save_and_list() {
        let tmp = TempDir::new().unwrap();
        let history_dir = tmp.path().join("config-history");

        let content = "[server]\nssh_listen = \"0.0.0.0:2222\"\n";
        let path = save_config_snapshot(&history_dir, content, 50).unwrap();

        assert!(path.exists());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), content);

        let entries = list_history(&history_dir).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_prune_oldest() {
        let tmp = TempDir::new().unwrap();
        let history_dir = tmp.path().join("config-history");
        std::fs::create_dir_all(&history_dir).unwrap();

        // Create 5 files manually with different timestamps
        for i in 1..=5 {
            let name = format!("20260218T{:02}0000Z.toml", i);
            std::fs::write(history_dir.join(&name), format!("version={}", i)).unwrap();
        }

        assert_eq!(list_history(&history_dir).unwrap().len(), 5);

        // Prune to max 3
        prune_old_entries(&history_dir, 3).unwrap();

        let remaining = list_history(&history_dir).unwrap();
        assert_eq!(remaining.len(), 3);

        // Should keep the 3 newest (03, 04, 05)
        let names: Vec<String> = remaining
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(names[0].contains("030000"));
        assert!(names[2].contains("050000"));
    }

    #[test]
    fn test_list_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let entries = list_history(&tmp.path().join("nonexistent")).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_save_creates_directory() {
        let tmp = TempDir::new().unwrap();
        let history_dir = tmp.path().join("deep").join("nested").join("history");

        save_config_snapshot(&history_dir, "test", 50).unwrap();

        assert!(history_dir.exists());
    }

    #[cfg(unix)]
    #[test]
    fn test_snapshot_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let history_dir = tmp.path().join("config-history");

        let path = save_config_snapshot(&history_dir, "test", 50).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn test_save_same_second_overwrites() {
        let tmp = TempDir::new().unwrap();
        let history_dir = tmp.path().join("config-history");

        let path1 = save_config_snapshot(&history_dir, "version=1", 50).unwrap();
        let path2 = save_config_snapshot(&history_dir, "version=2", 50).unwrap();

        let entries = list_history(&history_dir).unwrap();

        if path1 == path2 {
            // Same second: single file with v2 content
            assert_eq!(entries.len(), 1);
            assert_eq!(std::fs::read_to_string(&path2).unwrap(), "version=2");
        } else {
            // Crossed second boundary: two distinct files
            assert_eq!(entries.len(), 2);
            assert_eq!(std::fs::read_to_string(&path1).unwrap(), "version=1");
            assert_eq!(std::fs::read_to_string(&path2).unwrap(), "version=2");
        }
    }
}
