use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::debug;

/// Persisted IP reputation payload.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReputationPayload {
    pub version: String,
    pub timestamp: String,
    #[serde(default)]
    pub scores: Vec<IpScoreEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpScoreEntry {
    pub ip: String,
    pub score: f64,
    pub last_update_epoch: u64,
    #[serde(default)]
    pub auth_failure_count: u32,
}

impl Default for ReputationPayload {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            scores: Vec::new(),
        }
    }
}

/// Atomically write a reputation payload to disk.
pub fn save_reputation(path: &Path, payload: &ReputationPayload) -> std::io::Result<()> {
    let data = serde_json::to_string_pretty(payload)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    super::atomic_write_file(path, data.as_bytes())?;
    debug!(path = %path.display(), entries = payload.scores.len(), "Reputation saved");
    Ok(())
}

/// Load a reputation payload from disk.
///
/// Returns `Ok(None)` if the file does not exist.
/// Returns `Ok(Some(default))` if the file is corrupt.
pub fn load_reputation(path: &Path) -> std::io::Result<Option<ReputationPayload>> {
    let result = super::load_json_file::<ReputationPayload>(path)?;
    if let Some(ref payload) = result {
        debug!(
            path = %path.display(),
            entries = payload.scores.len(),
            "Reputation loaded"
        );
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_payload() -> ReputationPayload {
        ReputationPayload {
            version: "0.0.13".to_string(),
            timestamp: "2026-02-18T14:30:00Z".to_string(),
            scores: vec![
                IpScoreEntry {
                    ip: "1.2.3.4".to_string(),
                    score: 45.2,
                    last_update_epoch: 1708264200,
                    auth_failure_count: 5,
                },
                IpScoreEntry {
                    ip: "5.6.7.8".to_string(),
                    score: 12.0,
                    last_update_epoch: 1708264100,
                    auth_failure_count: 2,
                },
            ],
        }
    }

    #[test]
    fn test_save_load_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("reputation.json");

        let payload = sample_payload();
        save_reputation(&path, &payload).unwrap();

        let loaded = load_reputation(&path).unwrap().unwrap();
        assert_eq!(loaded.version, "0.0.13");
        assert_eq!(loaded.scores.len(), 2);
        assert_eq!(loaded.scores[0].ip, "1.2.3.4");
        assert!((loaded.scores[0].score - 45.2).abs() < 0.001);
        assert_eq!(loaded.scores[0].auth_failure_count, 5);
    }

    #[test]
    fn test_load_missing_file() {
        let tmp = TempDir::new().unwrap();
        let result = load_reputation(&tmp.path().join("nope.json")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_load_corrupt_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("corrupt.json");
        std::fs::write(&path, "garbage").unwrap();

        let loaded = load_reputation(&path).unwrap().unwrap();
        assert!(loaded.scores.is_empty());
    }

    #[test]
    fn test_load_partial_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("partial.json");
        std::fs::write(
            &path,
            r#"{"version":"0.0.13","timestamp":"2026-02-18T00:00:00Z"}"#,
        )
        .unwrap();

        let loaded = load_reputation(&path).unwrap().unwrap();
        assert!(loaded.scores.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn test_save_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("reputation.json");

        save_reputation(&path, &ReputationPayload::default()).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
