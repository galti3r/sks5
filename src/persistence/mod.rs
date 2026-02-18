pub mod config_history;
pub mod lockfile;
pub mod reputation;
pub mod state;
pub mod userdata;

use crate::config::types::PersistenceConfig;
use crate::metrics::MetricsRegistry;
use crate::quota::QuotaTracker;
use crate::security::SecurityManager;
use reputation::{IpScoreEntry, ReputationPayload};
use state::{AuthFailureEntry, BanEntry, QuotaUsageEntry, StatePayload};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Manages the persistence data directory and coordinates subsystems.
#[derive(Debug)]
pub struct PersistenceManager {
    data_dir: PathBuf,
    available: bool,
    _lock: Option<lockfile::Lockfile>,
}

impl PersistenceManager {
    /// Initialize persistence: resolve data_dir, create directories, acquire lockfile.
    ///
    /// If the data directory cannot be created or locked, falls back to in-memory mode
    /// (available = false) without error — except for lock conflicts which are fatal.
    pub fn init(config: &PersistenceConfig, config_path: Option<&Path>) -> anyhow::Result<Self> {
        let data_dir = resolve_data_dir(config, config_path);

        // Try to create the data directory
        if let Err(e) = create_data_dir(&data_dir) {
            warn!(
                data_dir = %data_dir.display(),
                error = %e,
                "Cannot create data directory — running in memory-only mode"
            );
            return Ok(Self {
                data_dir,
                available: false,
                _lock: None,
            });
        }

        // Try to acquire exclusive lockfile
        match lockfile::Lockfile::acquire(&data_dir) {
            Ok(lock) => {
                info!(data_dir = %data_dir.display(), "Persistence initialized");
                Ok(Self {
                    data_dir,
                    available: true,
                    _lock: Some(lock),
                })
            }
            Err(lockfile::LockError::AlreadyLocked) => {
                anyhow::bail!(
                    "another sks5 instance is using data directory: {}",
                    data_dir.display()
                );
            }
            Err(lockfile::LockError::Io(e)) => {
                warn!(
                    data_dir = %data_dir.display(),
                    error = %e,
                    "Cannot acquire lockfile — running in memory-only mode"
                );
                Ok(Self {
                    data_dir,
                    available: false,
                    _lock: None,
                })
            }
        }
    }

    /// Whether persistence is available (data_dir writable and locked).
    pub fn is_available(&self) -> bool {
        self.available
    }

    /// The resolved data directory path.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Path for the state file (bans + quotas + auth_failures).
    pub fn state_path(&self) -> PathBuf {
        self.data_dir.join("state.json")
    }

    /// Path for the IP reputation file.
    pub fn reputation_path(&self) -> PathBuf {
        self.data_dir.join("reputation.json")
    }

    /// Path for per-user data directory.
    pub fn users_dir(&self) -> PathBuf {
        self.data_dir.join("users")
    }

    /// Path for config history directory.
    pub fn config_history_dir(&self) -> PathBuf {
        self.data_dir.join("config-history")
    }

    /// Load persisted state and restore into SecurityManager + QuotaTracker.
    ///
    /// Does nothing if persistence is unavailable. Logs warnings on errors
    /// but never fails — graceful degradation.
    pub async fn load_and_restore_state(
        &self,
        security: &Arc<RwLock<SecurityManager>>,
        quota_tracker: &Arc<QuotaTracker>,
    ) {
        if !self.available {
            return;
        }

        let path = self.state_path();
        let payload = match state::load_state(&path) {
            Ok(Some(p)) => p,
            Ok(None) => {
                debug!("No persisted state file found — starting fresh");
                return;
            }
            Err(e) => {
                warn!(error = %e, "Failed to read state file — starting fresh");
                return;
            }
        };

        // Restore bans + auth failures under a single read lock
        let (restored_bans, restored_failures) = {
            let security = security.read().await;
            let mut bans_count = 0u32;
            for ban in &payload.bans {
                if ban.remaining_secs > 0 {
                    if let Ok(ip) = ban.ip.parse() {
                        security
                            .ban_manager()
                            .ban(ip, Duration::from_secs(ban.remaining_secs));
                        bans_count += 1;
                    }
                }
            }
            let failures: Vec<(std::net::IpAddr, Vec<u64>)> = payload
                .auth_failures
                .iter()
                .filter_map(|f| {
                    let ip = f.ip.parse().ok()?;
                    Some((ip, f.timestamps_epoch.clone()))
                })
                .collect();
            let failures_count = failures.len() as u32;
            security.ban_manager().import_failures(&failures);
            (bans_count, failures_count)
        };

        // Restore quotas
        let mut restored_quotas = 0u32;
        for (username, usage) in &payload.quotas {
            quota_tracker.restore_user_usage(
                username,
                usage.daily_bytes,
                usage.daily_connections,
                usage.monthly_bytes,
                usage.monthly_connections,
                usage.total_bytes,
            );
            restored_quotas += 1;
        }

        info!(
            bans = restored_bans,
            auth_failures = restored_failures,
            quotas = restored_quotas,
            "Persisted state restored"
        );
    }

    /// Snapshot current state from SecurityManager + QuotaTracker and save to disk.
    ///
    /// Returns `Ok(())` on success, logs warnings but does not crash on failure.
    /// Updates Prometheus metrics when provided.
    pub async fn flush_state(
        &self,
        security: &Arc<RwLock<SecurityManager>>,
        quota_tracker: &Arc<QuotaTracker>,
        metrics: Option<&MetricsRegistry>,
    ) {
        if !self.available {
            return;
        }

        let payload = self.snapshot_state(security, quota_tracker).await;

        let path = self.state_path();
        match state::save_state(&path, &payload) {
            Ok(()) => {
                if let Some(m) = metrics {
                    m.persistence_state_flush_total.inc();
                    if let Ok(meta) = std::fs::metadata(&path) {
                        m.persistence_state_file_bytes.set(meta.len() as i64);
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to flush state — will retry next cycle");
                if let Some(m) = metrics {
                    m.persistence_state_flush_errors_total.inc();
                }
            }
        }
    }

    /// Build a StatePayload from current in-memory state.
    async fn snapshot_state(
        &self,
        security: &Arc<RwLock<SecurityManager>>,
        quota_tracker: &Arc<QuotaTracker>,
    ) -> StatePayload {
        let now = std::time::Instant::now();

        // Snapshot bans + auth failures under a single read lock for consistency
        let (bans, auth_failures) = {
            let sec = security.read().await;
            let bans: Vec<BanEntry> = sec
                .ban_manager()
                .banned_ips()
                .into_iter()
                .map(|(ip, expiry)| {
                    let remaining = expiry.saturating_duration_since(now);
                    BanEntry {
                        ip: ip.to_string(),
                        remaining_secs: remaining.as_secs(),
                    }
                })
                .collect();
            let auth_failures: Vec<AuthFailureEntry> = sec
                .ban_manager()
                .export_failures()
                .into_iter()
                .map(|(ip, epochs)| AuthFailureEntry {
                    ip: ip.to_string(),
                    timestamps_epoch: epochs,
                })
                .collect();
            (bans, auth_failures)
        };

        // Snapshot quotas
        let mut quotas = std::collections::HashMap::new();
        for username in quota_tracker.tracked_users() {
            let usage = quota_tracker.get_user_usage(&username);
            quotas.insert(
                username,
                QuotaUsageEntry {
                    daily_bytes: usage.daily_bytes,
                    daily_connections: usage.daily_connections,
                    monthly_bytes: usage.monthly_bytes,
                    monthly_connections: usage.monthly_connections,
                    total_bytes: usage.total_bytes,
                },
            );
        }

        StatePayload {
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            bans,
            auth_failures,
            quotas,
        }
    }

    /// Load persisted IP reputation scores and restore into SecurityManager.
    pub async fn load_and_restore_reputation(
        &self,
        security: &Arc<RwLock<SecurityManager>>,
        min_score: u32,
    ) {
        if !self.available {
            return;
        }

        let path = self.reputation_path();
        let payload = match reputation::load_reputation(&path) {
            Ok(Some(p)) => p,
            Ok(None) => {
                debug!("No persisted reputation file found — starting fresh");
                return;
            }
            Err(e) => {
                warn!(error = %e, "Failed to read reputation file — starting fresh");
                return;
            }
        };

        let scores: Vec<(std::net::IpAddr, f64, u64, u32)> = payload
            .scores
            .iter()
            .filter_map(|entry| {
                let ip = entry.ip.parse().ok()?;
                if (entry.score.max(0.0) as u32) < min_score {
                    return None;
                }
                Some((
                    ip,
                    entry.score,
                    entry.last_update_epoch,
                    entry.auth_failure_count,
                ))
            })
            .collect();

        let count = scores.len();
        {
            let sec = security.read().await;
            sec.ip_reputation().import_scores(&scores);
        }

        info!(entries = count, "IP reputation scores restored");
    }

    /// Snapshot and save IP reputation to disk.
    /// Updates Prometheus metrics when provided.
    pub async fn flush_reputation(
        &self,
        security: &Arc<RwLock<SecurityManager>>,
        min_score: u32,
        metrics: Option<&MetricsRegistry>,
    ) {
        if !self.available {
            return;
        }

        let payload = {
            let sec = security.read().await;
            let scores: Vec<IpScoreEntry> = sec
                .ip_reputation()
                .export_scores(min_score)
                .into_iter()
                .map(|(ip, score, epoch, failure_count)| IpScoreEntry {
                    ip: ip.to_string(),
                    score,
                    last_update_epoch: epoch,
                    auth_failure_count: failure_count,
                })
                .collect();

            ReputationPayload {
                version: env!("CARGO_PKG_VERSION").to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                scores,
            }
        };

        let path = self.reputation_path();
        match reputation::save_reputation(&path, &payload) {
            Ok(()) => {
                if let Some(m) = metrics {
                    m.persistence_reputation_flush_total.inc();
                    if let Ok(meta) = std::fs::metadata(&path) {
                        m.persistence_reputation_file_bytes.set(meta.len() as i64);
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to flush reputation — will retry next cycle");
                if let Some(m) = metrics {
                    m.persistence_reputation_flush_errors_total.inc();
                }
            }
        }
    }
}

/// Spawn a background task that periodically flushes state to disk.
///
/// The task runs at the configured interval and flushes on cancellation
/// (shutdown) for a final save.
pub fn spawn_state_flush_task(
    persistence: Arc<PersistenceManager>,
    security: Arc<RwLock<SecurityManager>>,
    quota_tracker: Arc<QuotaTracker>,
    flush_interval_secs: u64,
    metrics: Option<Arc<MetricsRegistry>>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    if !persistence.is_available() {
        return;
    }

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(flush_interval_secs));
        // Skip the first immediate tick
        interval.tick().await;

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    // Final flush on shutdown
                    info!("Shutdown: flushing state to disk");
                    persistence.flush_state(&security, &quota_tracker, metrics.as_deref()).await;
                    return;
                }
                _ = interval.tick() => {
                    persistence.flush_state(&security, &quota_tracker, metrics.as_deref()).await;
                }
            }
        }
    });
}

/// Spawn a background task that periodically flushes IP reputation to disk.
///
/// Uses a separate interval from state flushing since the reputation file
/// can be large (100K+ entries) and doesn't need to be saved as frequently.
pub fn spawn_reputation_flush_task(
    persistence: Arc<PersistenceManager>,
    security: Arc<RwLock<SecurityManager>>,
    flush_interval_secs: u64,
    min_score: u32,
    metrics: Option<Arc<MetricsRegistry>>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    if !persistence.is_available() {
        return;
    }

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(flush_interval_secs));
        // Skip the first immediate tick
        interval.tick().await;

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("Shutdown: flushing IP reputation to disk");
                    persistence.flush_reputation(&security, min_score, metrics.as_deref()).await;
                    return;
                }
                _ = interval.tick() => {
                    persistence.flush_reputation(&security, min_score, metrics.as_deref()).await;
                }
            }
        }
    });
}

/// Resolve the data directory from config, environment, or convention.
fn resolve_data_dir(config: &PersistenceConfig, config_path: Option<&Path>) -> PathBuf {
    // 1. Explicit config value (already resolved from CLI > env > TOML)
    if let Some(ref dir) = config.data_dir {
        return dir.clone();
    }

    // 2. Relative to config file directory
    if let Some(path) = config_path {
        if let Some(parent) = path.parent() {
            return parent.join("data");
        }
    }

    // 3. Fallback: ./data/
    PathBuf::from("data")
}

/// Create the data directory with appropriate permissions.
fn create_data_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;

    // Set directory permissions to 0700 on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(path, perms)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::PersistenceConfig;
    use tempfile::TempDir;

    #[test]
    fn test_resolve_data_dir_from_config() {
        let config = PersistenceConfig {
            data_dir: Some(PathBuf::from("/custom/data")),
            ..Default::default()
        };
        let dir = resolve_data_dir(&config, None);
        assert_eq!(dir, PathBuf::from("/custom/data"));
    }

    #[test]
    fn test_resolve_data_dir_relative_to_config() {
        let config = PersistenceConfig::default();
        let dir = resolve_data_dir(&config, Some(Path::new("/etc/sks5/config.toml")));
        assert_eq!(dir, PathBuf::from("/etc/sks5/data"));
    }

    #[test]
    fn test_resolve_data_dir_fallback() {
        let config = PersistenceConfig::default();
        let dir = resolve_data_dir(&config, None);
        assert_eq!(dir, PathBuf::from("data"));
    }

    #[test]
    fn test_init_creates_directory() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("mydata");
        let config = PersistenceConfig {
            data_dir: Some(data_dir.clone()),
            ..Default::default()
        };
        let mgr = PersistenceManager::init(&config, None).unwrap();
        assert!(mgr.is_available());
        assert!(data_dir.exists());
        assert!(data_dir.join("sks5.lock").exists());
    }

    #[test]
    fn test_init_lock_conflict_is_fatal() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("locked");
        let config = PersistenceConfig {
            data_dir: Some(data_dir.clone()),
            ..Default::default()
        };
        let _mgr1 = PersistenceManager::init(&config, None).unwrap();
        let result = PersistenceManager::init(&config, None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("another sks5 instance"));
    }

    #[test]
    fn test_init_unwritable_dir_degrades_gracefully() {
        let config = PersistenceConfig {
            data_dir: Some(PathBuf::from("/nonexistent/root/path/data")),
            ..Default::default()
        };
        let mgr = PersistenceManager::init(&config, None).unwrap();
        assert!(!mgr.is_available());
    }

    #[test]
    fn test_path_accessors() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("d");
        let config = PersistenceConfig {
            data_dir: Some(data_dir.clone()),
            ..Default::default()
        };
        let mgr = PersistenceManager::init(&config, None).unwrap();
        assert_eq!(mgr.state_path(), data_dir.join("state.json"));
        assert_eq!(mgr.reputation_path(), data_dir.join("reputation.json"));
        assert_eq!(mgr.users_dir(), data_dir.join("users"));
        assert_eq!(mgr.config_history_dir(), data_dir.join("config-history"));
    }

    #[cfg(unix)]
    #[test]
    fn test_data_dir_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("secure");
        let config = PersistenceConfig {
            data_dir: Some(data_dir.clone()),
            ..Default::default()
        };
        let _mgr = PersistenceManager::init(&config, None).unwrap();
        let mode = std::fs::metadata(&data_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    /// Helper: build a minimal AppConfig with bans enabled + a user
    fn test_app_config() -> crate::config::types::AppConfig {
        let toml_str = r##"
[server]
ssh_listen = "127.0.0.1:2222"
host_key_path = "/tmp/test-key"

[security]
ban_enabled = true
ban_threshold = 3
ip_reputation_enabled = true

[limits]
max_auth_attempts = 5

[[users]]
username = "testuser"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$fakesalt$fakehash"
allow_forwarding = true
"##;
        toml::from_str(toml_str).unwrap()
    }

    #[tokio::test]
    async fn test_state_flush_and_restore_cycle() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("lifecycle");
        let pconfig = PersistenceConfig {
            data_dir: Some(data_dir.clone()),
            ..Default::default()
        };
        let app_config = test_app_config();

        // Phase 1: Create state, add data, flush
        {
            let mgr = PersistenceManager::init(&pconfig, None).unwrap();
            assert!(mgr.is_available());

            let security = Arc::new(RwLock::new(crate::security::SecurityManager::new(
                &app_config,
            )));
            let quota_tracker = Arc::new(crate::quota::QuotaTracker::new(&app_config.limits));

            // Add a ban
            let ban_ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
            {
                let sec = security.read().await;
                sec.ban_manager().ban(ban_ip, Duration::from_secs(3600));
            }

            // Add quota usage
            quota_tracker.restore_user_usage("testuser", 1024, 5, 50000, 20, 100000);

            // Flush
            mgr.flush_state(&security, &quota_tracker, None).await;

            // Verify file exists
            assert!(mgr.state_path().exists());
        }
        // Lock is dropped here

        // Phase 2: Fresh managers, load persisted state
        {
            let mgr = PersistenceManager::init(&pconfig, None).unwrap();
            assert!(mgr.is_available());

            let security = Arc::new(RwLock::new(crate::security::SecurityManager::new(
                &app_config,
            )));
            let quota_tracker = Arc::new(crate::quota::QuotaTracker::new(&app_config.limits));

            // Load
            mgr.load_and_restore_state(&security, &quota_tracker).await;

            // Verify ban was restored
            let sec = security.read().await;
            let ban_ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
            assert!(sec.ban_manager().is_banned(&ban_ip));

            // Verify quota was restored
            let usage = quota_tracker.get_user_usage("testuser");
            assert_eq!(usage.daily_bytes, 1024);
            assert_eq!(usage.daily_connections, 5);
            assert_eq!(usage.monthly_bytes, 50000);
            assert_eq!(usage.total_bytes, 100000);
        }
    }

    #[tokio::test]
    async fn test_reputation_flush_and_restore_cycle() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("reputation");
        let pconfig = PersistenceConfig {
            data_dir: Some(data_dir.clone()),
            ..Default::default()
        };
        let app_config = test_app_config();

        // Phase 1: Record auth failures to build reputation, flush
        {
            let mgr = PersistenceManager::init(&pconfig, None).unwrap();
            let security = Arc::new(RwLock::new(crate::security::SecurityManager::new(
                &app_config,
            )));

            let bad_ip: std::net::IpAddr = "192.168.1.100".parse().unwrap();
            {
                let sec = security.read().await;
                // Record multiple failures to build up reputation score
                for _ in 0..5 {
                    sec.ip_reputation().record_auth_failure(&bad_ip);
                }
            }

            mgr.flush_reputation(&security, 1, None).await;
            assert!(mgr.reputation_path().exists());
        }

        // Phase 2: Restore
        {
            let mgr = PersistenceManager::init(&pconfig, None).unwrap();
            let security = Arc::new(RwLock::new(crate::security::SecurityManager::new(
                &app_config,
            )));

            mgr.load_and_restore_reputation(&security, 1).await;

            let sec = security.read().await;
            let bad_ip: std::net::IpAddr = "192.168.1.100".parse().unwrap();
            let scores = sec.ip_reputation().export_scores(1);
            let entry = scores.iter().find(|(ip, _, _, _)| *ip == bad_ip);
            assert!(entry.is_some(), "Reputation score should be restored");
            let (_, score, _, failures) = entry.unwrap();
            assert!(*score > 0.0);
            assert_eq!(*failures, 5);
        }
    }

    #[tokio::test]
    async fn test_flush_with_metrics_updates_counters() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("metrics");
        let pconfig = PersistenceConfig {
            data_dir: Some(data_dir.clone()),
            ..Default::default()
        };
        let app_config = test_app_config();
        let metrics = MetricsRegistry::new();

        let mgr = PersistenceManager::init(&pconfig, None).unwrap();
        let security = Arc::new(RwLock::new(crate::security::SecurityManager::new(
            &app_config,
        )));
        let quota_tracker = Arc::new(crate::quota::QuotaTracker::new(&app_config.limits));

        // Initial counters should be 0
        assert_eq!(metrics.persistence_state_flush_total.get(), 0);
        assert_eq!(metrics.persistence_state_flush_errors_total.get(), 0);

        // Flush state
        mgr.flush_state(&security, &quota_tracker, Some(&metrics))
            .await;
        assert_eq!(metrics.persistence_state_flush_total.get(), 1);
        assert_eq!(metrics.persistence_state_flush_errors_total.get(), 0);
        assert!(metrics.persistence_state_file_bytes.get() > 0);

        // Flush reputation
        mgr.flush_reputation(&security, 0, Some(&metrics)).await;
        assert_eq!(metrics.persistence_reputation_flush_total.get(), 1);
        assert_eq!(metrics.persistence_reputation_flush_errors_total.get(), 0);
        assert!(metrics.persistence_reputation_file_bytes.get() > 0);
    }

    #[tokio::test]
    async fn test_unavailable_persistence_skips_flush() {
        let pconfig = PersistenceConfig {
            data_dir: Some(PathBuf::from("/nonexistent/root/path")),
            ..Default::default()
        };
        let app_config = test_app_config();
        let metrics = MetricsRegistry::new();

        let mgr = PersistenceManager::init(&pconfig, None).unwrap();
        assert!(!mgr.is_available());

        let security = Arc::new(RwLock::new(crate::security::SecurityManager::new(
            &app_config,
        )));
        let quota_tracker = Arc::new(crate::quota::QuotaTracker::new(&app_config.limits));

        // Flush should be a no-op, counters stay 0
        mgr.flush_state(&security, &quota_tracker, Some(&metrics))
            .await;
        assert_eq!(metrics.persistence_state_flush_total.get(), 0);

        mgr.flush_reputation(&security, 0, Some(&metrics)).await;
        assert_eq!(metrics.persistence_reputation_flush_total.get(), 0);
    }

    #[tokio::test]
    async fn test_auth_failures_flush_and_restore() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("auth-fail");
        let pconfig = PersistenceConfig {
            data_dir: Some(data_dir.clone()),
            ..Default::default()
        };
        let app_config = test_app_config();

        // Phase 1: Record failures (below threshold=3 so no auto-ban), flush
        {
            let mgr = PersistenceManager::init(&pconfig, None).unwrap();
            let security = Arc::new(RwLock::new(crate::security::SecurityManager::new(
                &app_config,
            )));
            let quota_tracker = Arc::new(crate::quota::QuotaTracker::new(&app_config.limits));

            let bad_ip: std::net::IpAddr = "10.0.0.99".parse().unwrap();
            {
                let sec = security.read().await;
                sec.ban_manager().record_failure(&bad_ip);
                sec.ban_manager().record_failure(&bad_ip);
            }

            mgr.flush_state(&security, &quota_tracker, None).await;
        }

        // Phase 2: Restore and verify failures
        {
            let mgr = PersistenceManager::init(&pconfig, None).unwrap();
            let security = Arc::new(RwLock::new(crate::security::SecurityManager::new(
                &app_config,
            )));
            let quota_tracker = Arc::new(crate::quota::QuotaTracker::new(&app_config.limits));

            mgr.load_and_restore_state(&security, &quota_tracker).await;

            let sec = security.read().await;
            let failures = sec.ban_manager().export_failures();
            let bad_ip: std::net::IpAddr = "10.0.0.99".parse().unwrap();
            let entry = failures.iter().find(|(ip, _)| *ip == bad_ip);
            assert!(
                entry.is_some(),
                "Auth failures should be restored for the IP"
            );
            let (_, timestamps) = entry.unwrap();
            assert_eq!(timestamps.len(), 2, "Should have 2 failure timestamps");
        }
    }

    #[tokio::test]
    async fn test_restore_skips_expired_bans() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("expired-bans");
        let pconfig = PersistenceConfig {
            data_dir: Some(data_dir.clone()),
            ..Default::default()
        };
        let app_config = test_app_config();

        // Write state with one expired and one active ban directly
        {
            let mgr = PersistenceManager::init(&pconfig, None).unwrap();
            let payload = StatePayload {
                version: env!("CARGO_PKG_VERSION").to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                bans: vec![
                    BanEntry {
                        ip: "10.0.0.1".to_string(),
                        remaining_secs: 0,
                    },
                    BanEntry {
                        ip: "10.0.0.2".to_string(),
                        remaining_secs: 3600,
                    },
                ],
                auth_failures: Vec::new(),
                quotas: std::collections::HashMap::new(),
            };
            state::save_state(&mgr.state_path(), &payload).unwrap();
        }

        // Restore and check
        {
            let mgr = PersistenceManager::init(&pconfig, None).unwrap();
            let security = Arc::new(RwLock::new(crate::security::SecurityManager::new(
                &app_config,
            )));
            let quota_tracker = Arc::new(crate::quota::QuotaTracker::new(&app_config.limits));

            mgr.load_and_restore_state(&security, &quota_tracker).await;

            let sec = security.read().await;
            let expired_ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
            let active_ip: std::net::IpAddr = "10.0.0.2".parse().unwrap();
            assert!(
                !sec.ban_manager().is_banned(&expired_ip),
                "Expired ban should not be restored"
            );
            assert!(
                sec.ban_manager().is_banned(&active_ip),
                "Active ban should be restored"
            );
        }
    }

    #[tokio::test]
    async fn test_restore_skips_invalid_ips() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("bad-ips");
        let pconfig = PersistenceConfig {
            data_dir: Some(data_dir.clone()),
            ..Default::default()
        };
        let app_config = test_app_config();

        // Write state with invalid IP strings + one valid
        {
            let mgr = PersistenceManager::init(&pconfig, None).unwrap();
            let payload = StatePayload {
                version: env!("CARGO_PKG_VERSION").to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                bans: vec![
                    BanEntry {
                        ip: "not-an-ip".to_string(),
                        remaining_secs: 3600,
                    },
                    BanEntry {
                        ip: "10.0.0.5".to_string(),
                        remaining_secs: 3600,
                    },
                ],
                auth_failures: vec![AuthFailureEntry {
                    ip: "also-bad".to_string(),
                    timestamps_epoch: vec![1708264200],
                }],
                quotas: std::collections::HashMap::new(),
            };
            state::save_state(&mgr.state_path(), &payload).unwrap();
        }

        // Restore — should not panic, only valid IPs restored
        {
            let mgr = PersistenceManager::init(&pconfig, None).unwrap();
            let security = Arc::new(RwLock::new(crate::security::SecurityManager::new(
                &app_config,
            )));
            let quota_tracker = Arc::new(crate::quota::QuotaTracker::new(&app_config.limits));

            mgr.load_and_restore_state(&security, &quota_tracker).await;

            let sec = security.read().await;
            let valid_ip: std::net::IpAddr = "10.0.0.5".parse().unwrap();
            assert!(sec.ban_manager().is_banned(&valid_ip));
            // Only 1 valid ban
            assert_eq!(sec.ban_manager().banned_ips().len(), 1);
        }
    }

    #[tokio::test]
    async fn test_reputation_min_score_filtering() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("rep-filter");
        let pconfig = PersistenceConfig {
            data_dir: Some(data_dir.clone()),
            ..Default::default()
        };
        let app_config = test_app_config();

        // Write reputation with low and high scores directly
        {
            let mgr = PersistenceManager::init(&pconfig, None).unwrap();
            let payload = reputation::ReputationPayload {
                version: env!("CARGO_PKG_VERSION").to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                scores: vec![
                    reputation::IpScoreEntry {
                        ip: "10.0.0.1".to_string(),
                        score: 5.0,
                        last_update_epoch: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        auth_failure_count: 1,
                    },
                    reputation::IpScoreEntry {
                        ip: "10.0.0.2".to_string(),
                        score: 50.0,
                        last_update_epoch: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        auth_failure_count: 5,
                    },
                ],
            };
            reputation::save_reputation(&mgr.reputation_path(), &payload).unwrap();
        }

        // Restore with min_score=10 — only score=50 should survive
        {
            let mgr = PersistenceManager::init(&pconfig, None).unwrap();
            let security = Arc::new(RwLock::new(crate::security::SecurityManager::new(
                &app_config,
            )));

            mgr.load_and_restore_reputation(&security, 10).await;

            let sec = security.read().await;
            let scores = sec.ip_reputation().export_scores(0);
            // Only the high-score entry should have been imported
            let high_ip: std::net::IpAddr = "10.0.0.2".parse().unwrap();
            let low_ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();
            assert!(
                scores.iter().any(|(ip, _, _, _)| *ip == high_ip),
                "High-score IP should be restored"
            );
            assert!(
                !scores.iter().any(|(ip, _, _, _)| *ip == low_ip),
                "Low-score IP should be filtered out"
            );
        }
    }

    #[tokio::test]
    async fn test_state_flush_and_restore_with_corrupt_file() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("corrupt-state");
        let pconfig = PersistenceConfig {
            data_dir: Some(data_dir.clone()),
            ..Default::default()
        };
        let app_config = test_app_config();

        let mgr = PersistenceManager::init(&pconfig, None).unwrap();

        // Write garbage to state file
        std::fs::write(mgr.state_path(), "garbage{{{not json").unwrap();

        let security = Arc::new(RwLock::new(crate::security::SecurityManager::new(
            &app_config,
        )));
        let quota_tracker = Arc::new(crate::quota::QuotaTracker::new(&app_config.limits));

        // Should not crash — graceful degradation with empty state
        mgr.load_and_restore_state(&security, &quota_tracker).await;

        let sec = security.read().await;
        assert!(sec.ban_manager().banned_ips().is_empty());
    }

    #[tokio::test]
    async fn test_reputation_flush_and_restore_with_corrupt_file() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("corrupt-rep");
        let pconfig = PersistenceConfig {
            data_dir: Some(data_dir.clone()),
            ..Default::default()
        };
        let app_config = test_app_config();

        let mgr = PersistenceManager::init(&pconfig, None).unwrap();

        // Write garbage to reputation file
        std::fs::write(mgr.reputation_path(), "garbage{{{not json").unwrap();

        let security = Arc::new(RwLock::new(crate::security::SecurityManager::new(
            &app_config,
        )));

        // Should not crash — graceful degradation
        mgr.load_and_restore_reputation(&security, 0).await;

        let sec = security.read().await;
        assert!(sec.ip_reputation().export_scores(0).is_empty());
    }

    #[tokio::test]
    async fn test_spawn_state_flush_task_flushes_on_shutdown() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("spawn-state");
        let pconfig = PersistenceConfig {
            data_dir: Some(data_dir.clone()),
            ..Default::default()
        };
        let app_config = test_app_config();

        let mgr = Arc::new(PersistenceManager::init(&pconfig, None).unwrap());
        let security = Arc::new(RwLock::new(crate::security::SecurityManager::new(
            &app_config,
        )));
        let quota_tracker = Arc::new(crate::quota::QuotaTracker::new(&app_config.limits));

        // Ban an IP
        let ban_ip: std::net::IpAddr = "10.0.0.42".parse().unwrap();
        {
            let sec = security.read().await;
            sec.ban_manager().ban(ban_ip, Duration::from_secs(3600));
        }

        let shutdown = tokio_util::sync::CancellationToken::new();
        spawn_state_flush_task(
            Arc::clone(&mgr),
            Arc::clone(&security),
            Arc::clone(&quota_tracker),
            3600, // long interval — won't fire
            None,
            shutdown.clone(),
        );

        // Cancel to trigger shutdown flush
        shutdown.cancel();
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify state was written
        let state_path = mgr.state_path();
        let loaded = state::load_state(&state_path).unwrap();
        assert!(loaded.is_some(), "State file should exist after shutdown");
        let payload = loaded.unwrap();
        assert!(
            payload.bans.iter().any(|b| b.ip == "10.0.0.42"),
            "Banned IP should be in persisted state"
        );
    }

    #[tokio::test]
    async fn test_spawn_reputation_flush_task_flushes_on_shutdown() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("spawn-rep");
        let pconfig = PersistenceConfig {
            data_dir: Some(data_dir.clone()),
            ..Default::default()
        };
        let app_config = test_app_config();

        let mgr = Arc::new(PersistenceManager::init(&pconfig, None).unwrap());
        let security = Arc::new(RwLock::new(crate::security::SecurityManager::new(
            &app_config,
        )));

        // Record auth failures to build reputation score
        let bad_ip: std::net::IpAddr = "10.0.0.77".parse().unwrap();
        {
            let sec = security.read().await;
            for _ in 0..3 {
                sec.ip_reputation().record_auth_failure(&bad_ip);
            }
        }

        let shutdown = tokio_util::sync::CancellationToken::new();
        spawn_reputation_flush_task(
            Arc::clone(&mgr),
            Arc::clone(&security),
            3600, // long interval — won't fire
            1,    // min_score
            None,
            shutdown.clone(),
        );

        // Cancel to trigger shutdown flush
        shutdown.cancel();
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify reputation was written
        let rep_path = mgr.reputation_path();
        let loaded = reputation::load_reputation(&rep_path).unwrap();
        assert!(
            loaded.is_some(),
            "Reputation file should exist after shutdown"
        );
        let payload = loaded.unwrap();
        assert!(
            !payload.scores.is_empty(),
            "Reputation scores should be persisted"
        );
    }
}
