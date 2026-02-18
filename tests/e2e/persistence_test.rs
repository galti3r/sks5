use sks5::config::types::{AppConfig, PersistenceConfig};
use sks5::persistence::userdata::{UserData, UserDataStore};
use sks5::persistence::PersistenceManager;
use sks5::security::SecurityManager;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

fn test_app_config() -> AppConfig {
    toml::from_str(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
host_key_path = "/tmp/sks5-e2e-persist-key"

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
"##,
    )
    .unwrap()
}

#[tokio::test]
async fn test_persistence_state_survives_restart() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().join("e2e-state");
    let pconfig = PersistenceConfig {
        data_dir: Some(data_dir.clone()),
        ..Default::default()
    };
    let app_config = test_app_config();
    let ban_ip: std::net::IpAddr = "10.99.0.1".parse().unwrap();

    // First "session": init, ban an IP, flush, drop everything
    {
        let mgr = PersistenceManager::init(&pconfig, None).unwrap();
        assert!(mgr.is_available());

        let security = Arc::new(RwLock::new(SecurityManager::new(&app_config)));
        let quota_tracker = Arc::new(sks5::quota::QuotaTracker::new(&app_config.limits));

        {
            let sec = security.read().await;
            sec.ban_manager().ban(ban_ip, Duration::from_secs(7200));
        }

        mgr.flush_state(&security, &quota_tracker, None).await;
    }

    // Second "session": re-init same data_dir, restore, verify
    {
        let mgr = PersistenceManager::init(&pconfig, None).unwrap();
        assert!(mgr.is_available());

        let security = Arc::new(RwLock::new(SecurityManager::new(&app_config)));
        let quota_tracker = Arc::new(sks5::quota::QuotaTracker::new(&app_config.limits));

        mgr.load_and_restore_state(&security, &quota_tracker).await;

        let sec = security.read().await;
        assert!(
            sec.ban_manager().is_banned(&ban_ip),
            "Ban should survive restart"
        );
    }
}

#[tokio::test]
async fn test_persistence_shell_history_recorded() {
    let tmp = tempfile::TempDir::new().unwrap();
    let users_dir = tmp.path().join("users");

    // First store: write data
    {
        let store = UserDataStore::new(users_dir.clone(), 100, 50, true);
        store.record_command("alice", "connect example.com:443".to_string());
        store.record_command("alice", "status".to_string());
        store.record_command("alice", "help".to_string());
        store.flush_all();
    }

    // Verify file exists and is valid JSON
    let alice_path = users_dir.join("alice.json");
    assert!(alice_path.exists(), "alice.json should exist after flush");
    let content = std::fs::read_to_string(&alice_path).unwrap();
    let data: UserData = serde_json::from_str(&content).unwrap();
    assert_eq!(
        data.shell_history,
        vec!["connect example.com:443", "status", "help"]
    );

    // Second store: reload from disk
    {
        let store = UserDataStore::new(users_dir, 100, 50, true);
        let loaded = store.load_user("alice");
        assert_eq!(
            loaded.shell_history,
            vec!["connect example.com:443", "status", "help"]
        );
    }
}

#[tokio::test]
async fn test_persistence_graceful_degradation() {
    // PersistenceManager with unwritable path — should degrade gracefully
    let pconfig = PersistenceConfig {
        data_dir: Some(PathBuf::from("/nonexistent/e2e/path")),
        ..Default::default()
    };
    let app_config = test_app_config();

    let mgr = PersistenceManager::init(&pconfig, None).unwrap();
    assert!(
        !mgr.is_available(),
        "Should be unavailable for unwritable path"
    );

    let security = Arc::new(RwLock::new(SecurityManager::new(&app_config)));
    let quota_tracker = Arc::new(sks5::quota::QuotaTracker::new(&app_config.limits));

    // All of these should be no-ops, not panics
    mgr.load_and_restore_state(&security, &quota_tracker).await;
    mgr.flush_state(&security, &quota_tracker, None).await;
    mgr.load_and_restore_reputation(&security, 10).await;
    mgr.flush_reputation(&security, 1, None).await;

    // UserDataStore with available=false works in memory only
    let tmp = tempfile::TempDir::new().unwrap();
    let store = UserDataStore::new(tmp.path().join("users"), 100, 50, false);
    store.record_command("bob", "test".to_string());
    assert_eq!(store.get_history("bob"), vec!["test"]);
    store.flush_all(); // should be no-op, no crash

    // File should not exist since available=false
    let bob_path = tmp.path().join("users").join("bob.json");
    assert!(
        !bob_path.exists(),
        "No file should be written when unavailable"
    );
}
