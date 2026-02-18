use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use tracing::{debug, warn};

/// Persisted state payload (bans + auth_failures + quotas).
///
/// All fields use `#[serde(default)]` so that partial/old files
/// deserialize gracefully without errors.
#[derive(Debug, Serialize, Deserialize)]
pub struct StatePayload {
    pub version: String,
    pub timestamp: String,
    #[serde(default)]
    pub bans: Vec<BanEntry>,
    #[serde(default)]
    pub auth_failures: Vec<AuthFailureEntry>,
    #[serde(default)]
    pub quotas: HashMap<String, QuotaUsageEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanEntry {
    pub ip: String,
    pub remaining_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthFailureEntry {
    pub ip: String,
    /// Epoch seconds of each recorded failure.
    pub timestamps_epoch: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaUsageEntry {
    pub daily_bytes: u64,
    pub daily_connections: u32,
    pub monthly_bytes: u64,
    pub monthly_connections: u32,
    pub total_bytes: u64,
}

impl Default for StatePayload {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            bans: Vec::new(),
            auth_failures: Vec::new(),
            quotas: HashMap::new(),
        }
    }
}

/// Atomically write a state payload to disk.
///
/// Writes to a temporary file, fsyncs, then renames for crash safety.
/// File permissions are set to 0600 on Unix.
pub fn save_state(path: &Path, payload: &StatePayload) -> std::io::Result<()> {
    let data = serde_json::to_string_pretty(payload)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let tmp_path = path.with_extension("tmp");

    let mut file = std::fs::File::create(&tmp_path)?;
    file.write_all(data.as_bytes())?;
    file.sync_all()?;

    // Set permissions before rename (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&tmp_path, perms)?;
    }

    std::fs::rename(&tmp_path, path)?;
    debug!(path = %path.display(), "State saved");
    Ok(())
}

/// Load a state payload from disk.
///
/// Returns `Ok(None)` if the file does not exist.
/// Returns `Ok(Some(default))` if the file is corrupt (with a warning).
pub fn load_state(path: &Path) -> std::io::Result<Option<StatePayload>> {
    if !path.exists() {
        return Ok(None);
    }

    let data = std::fs::read_to_string(path)?;

    match serde_json::from_str::<StatePayload>(&data) {
        Ok(payload) => {
            debug!(
                path = %path.display(),
                version = %payload.version,
                bans = payload.bans.len(),
                quotas = payload.quotas.len(),
                "State loaded"
            );
            Ok(Some(payload))
        }
        Err(e) => {
            warn!(
                path = %path.display(),
                error = %e,
                "Corrupt state file — starting with empty state"
            );
            Ok(Some(StatePayload::default()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_payload() -> StatePayload {
        StatePayload {
            version: "0.0.13".to_string(),
            timestamp: "2026-02-18T14:30:00Z".to_string(),
            bans: vec![BanEntry {
                ip: "1.2.3.4".to_string(),
                remaining_secs: 600,
            }],
            auth_failures: vec![AuthFailureEntry {
                ip: "5.6.7.8".to_string(),
                timestamps_epoch: vec![1708264200, 1708264210],
            }],
            quotas: {
                let mut m = HashMap::new();
                m.insert(
                    "alice".to_string(),
                    QuotaUsageEntry {
                        daily_bytes: 1_073_741_824,
                        daily_connections: 42,
                        monthly_bytes: 10_737_418_240,
                        monthly_connections: 500,
                        total_bytes: 107_374_182_400,
                    },
                );
                m
            },
        }
    }

    #[test]
    fn test_save_load_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("state.json");

        let payload = sample_payload();
        save_state(&path, &payload).unwrap();

        let loaded = load_state(&path).unwrap().unwrap();
        assert_eq!(loaded.version, "0.0.13");
        assert_eq!(loaded.bans.len(), 1);
        assert_eq!(loaded.bans[0].ip, "1.2.3.4");
        assert_eq!(loaded.bans[0].remaining_secs, 600);
        assert_eq!(loaded.auth_failures.len(), 1);
        assert_eq!(loaded.auth_failures[0].ip, "5.6.7.8");
        assert_eq!(loaded.auth_failures[0].timestamps_epoch.len(), 2);
        assert_eq!(loaded.quotas.len(), 1);
        let alice = &loaded.quotas["alice"];
        assert_eq!(alice.daily_bytes, 1_073_741_824);
        assert_eq!(alice.total_bytes, 107_374_182_400);
    }

    #[test]
    fn test_load_missing_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("nonexistent.json");
        let result = load_state(&path).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_load_corrupt_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("corrupt.json");
        std::fs::write(&path, "not valid json {{{").unwrap();

        let loaded = load_state(&path).unwrap().unwrap();
        // Should return default empty state
        assert!(loaded.bans.is_empty());
        assert!(loaded.quotas.is_empty());
    }

    #[test]
    fn test_load_partial_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("partial.json");
        // Only bans, no quotas or auth_failures
        std::fs::write(
            &path,
            r#"{"version":"0.0.13","timestamp":"2026-02-18T00:00:00Z","bans":[{"ip":"1.1.1.1","remaining_secs":100}]}"#,
        )
        .unwrap();

        let loaded = load_state(&path).unwrap().unwrap();
        assert_eq!(loaded.bans.len(), 1);
        assert!(loaded.auth_failures.is_empty());
        assert!(loaded.quotas.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn test_save_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("state.json");

        save_state(&path, &StatePayload::default()).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn test_atomic_write_no_partial() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("state.json");

        // Write initial state
        save_state(&path, &sample_payload()).unwrap();

        // Verify tmp file is cleaned up
        let tmp_path = path.with_extension("tmp");
        assert!(!tmp_path.exists());
    }

    #[test]
    fn test_state_payload_default_version() {
        let payload = StatePayload::default();
        assert_eq!(payload.version, env!("CARGO_PKG_VERSION"));
        assert!(payload.bans.is_empty());
        assert!(payload.auth_failures.is_empty());
        assert!(payload.quotas.is_empty());
        assert!(
            payload.timestamp.contains('T'),
            "Timestamp should be RFC3339 format"
        );
    }
}
