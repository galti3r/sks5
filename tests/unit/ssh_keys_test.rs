use sks5::ssh::keys;
use tempfile::tempdir;

/// Generate a key to a temp file, then load it back and verify it is the same type (Ed25519).
#[test]
fn generate_and_load_round_trip() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("host_key");

    // First call generates and saves the key
    let key1 = keys::load_or_generate_host_key(&path).unwrap();

    // Second call loads the existing key from disk
    let key2 = keys::load_or_generate_host_key(&path).unwrap();

    // Both keys must be Ed25519
    assert!(
        key1.algorithm().is_ed25519(),
        "generated key should be Ed25519"
    );
    assert!(
        key2.algorithm().is_ed25519(),
        "reloaded key should be Ed25519"
    );
}

/// Calling load_or_generate on a nonexistent path must create the file.
#[test]
fn load_or_generate_creates_new() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("new_host_key");

    assert!(!path.exists(), "key file should not exist yet");

    let _key = keys::load_or_generate_host_key(&path).unwrap();

    assert!(path.exists(), "key file should have been created");
    // The file should be non-empty (PEM-encoded key)
    let metadata = std::fs::metadata(&path).unwrap();
    assert!(metadata.len() > 0, "key file should not be empty");
}

/// Generate a key, save it, then call load_or_generate again on the same path.
/// The second call should succeed by loading the existing key.
#[test]
fn load_existing_key() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("existing_key");

    // Generate and save
    let key1 = keys::load_or_generate_host_key(&path).unwrap();
    assert!(path.exists());

    // Record modification time so we can verify the file is not overwritten
    let mtime_before = std::fs::metadata(&path).unwrap().modified().unwrap();

    // Small delay to ensure mtime would differ if file were rewritten
    std::thread::sleep(std::time::Duration::from_millis(50));

    // Load existing key — should NOT regenerate
    let key2 = keys::load_or_generate_host_key(&path).unwrap();

    let mtime_after = std::fs::metadata(&path).unwrap().modified().unwrap();
    assert_eq!(
        mtime_before, mtime_after,
        "file should not have been rewritten when key already exists"
    );

    // Both must be Ed25519
    assert!(key1.algorithm().is_ed25519());
    assert!(key2.algorithm().is_ed25519());
}

/// On Unix, the generated key file must have mode 0o600 (owner read/write only).
#[cfg(unix)]
#[test]
fn permissions_are_restrictive() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
    let path = dir.path().join("restricted_key");

    keys::load_or_generate_host_key(&path).unwrap();

    let metadata = std::fs::metadata(&path).unwrap();
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "key file permissions should be 0o600, got 0o{:o}",
        mode
    );
}
