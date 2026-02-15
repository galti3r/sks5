use sks5::auth::password;
use sks5::auth::AuthService;
use sks5::config::types::AppConfig;

/// Build an AppConfig from a TOML string with the given password hash for user "alice".
/// Alice has a password_hash, while bob has only an authorized_key (no password).
fn make_config(password_hash: &str) -> AppConfig {
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:2222"
host_key_path = "/tmp/test-key"

[[users]]
username = "alice"
password_hash = "{password_hash}"
allow_forwarding = true
allow_shell = true

[[users]]
username = "bob"
authorized_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTestingPurposesOnly000000000000000 bob@test"]
allow_forwarding = false
allow_shell = false
"##
    );
    toml::from_str(&toml_str).unwrap()
}

/// Build a config where alice has an expiration date in the past.
fn make_config_expired(password_hash: &str) -> AppConfig {
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:2222"
host_key_path = "/tmp/test-key"

[[users]]
username = "alice"
password_hash = "{password_hash}"
expires_at = "2020-01-01T00:00:00Z"
allow_forwarding = true
allow_shell = true
"##
    );
    toml::from_str(&toml_str).unwrap()
}

/// Build a config with a single user "charlie" (used for reload tests).
fn make_config_charlie() -> AppConfig {
    let hash = password::hash_password("charliepass").unwrap();
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:2222"
host_key_path = "/tmp/test-key"

[[users]]
username = "charlie"
password_hash = "{hash}"
allow_forwarding = true
allow_shell = true
"##
    );
    toml::from_str(&toml_str).unwrap()
}

// ---------------------------------------------------------------------------
// Test 1: Correct password authenticates successfully
// ---------------------------------------------------------------------------
#[test]
fn auth_password_valid() {
    let hash = password::hash_password("testpass").unwrap();
    let config = make_config(&hash);
    let service = AuthService::new(&config).unwrap();

    assert!(
        service.auth_password("alice", "testpass"),
        "valid password should authenticate successfully"
    );
}

// ---------------------------------------------------------------------------
// Test 2: Wrong password is rejected
// ---------------------------------------------------------------------------
#[test]
fn auth_password_wrong() {
    let hash = password::hash_password("testpass").unwrap();
    let config = make_config(&hash);
    let service = AuthService::new(&config).unwrap();

    assert!(
        !service.auth_password("alice", "wrongpass"),
        "wrong password should be rejected"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Non-existent user is rejected for password auth
// ---------------------------------------------------------------------------
#[test]
fn auth_password_nonexistent_user() {
    let hash = password::hash_password("testpass").unwrap();
    let config = make_config(&hash);
    let service = AuthService::new(&config).unwrap();

    assert!(
        !service.auth_password("nobody", "testpass"),
        "non-existent user should be rejected"
    );
}

// ---------------------------------------------------------------------------
// Test 4: User without password_hash fails password auth
// ---------------------------------------------------------------------------
#[test]
fn auth_password_no_hash() {
    let hash = password::hash_password("testpass").unwrap();
    let config = make_config(&hash);
    let service = AuthService::new(&config).unwrap();

    // "bob" has authorized_keys but no password_hash
    assert!(
        !service.auth_password("bob", "anypassword"),
        "user without password_hash should fail password auth"
    );
}

// ---------------------------------------------------------------------------
// Test 5: Expired user fails password auth
// ---------------------------------------------------------------------------
#[test]
fn auth_password_expired_user() {
    let hash = password::hash_password("testpass").unwrap();
    let config = make_config_expired(&hash);
    let service = AuthService::new(&config).unwrap();

    // Alice's account expired on 2020-01-01
    assert!(
        !service.auth_password("alice", "testpass"),
        "expired user should fail password auth even with correct password"
    );
}

// ---------------------------------------------------------------------------
// Test 6: Non-existent user is rejected for public key auth
// ---------------------------------------------------------------------------
#[test]
fn auth_publickey_nonexistent_user() {
    let hash = password::hash_password("testpass").unwrap();
    let config = make_config(&hash);
    let service = AuthService::new(&config).unwrap();

    let keypair =
        russh::keys::PrivateKey::random(&mut rand::rngs::OsRng, russh::keys::Algorithm::Ed25519)
            .unwrap();
    let pubkey = russh::keys::PublicKey::from(&keypair);

    assert!(
        !service.auth_publickey("nobody", &pubkey),
        "non-existent user should be rejected for pubkey auth"
    );
}

// ---------------------------------------------------------------------------
// Test 7: Expired user fails public key auth
// ---------------------------------------------------------------------------
#[test]
fn auth_publickey_expired_user() {
    let hash = password::hash_password("testpass").unwrap();
    let config = make_config_expired(&hash);
    let service = AuthService::new(&config).unwrap();

    let keypair =
        russh::keys::PrivateKey::random(&mut rand::rngs::OsRng, russh::keys::Algorithm::Ed25519)
            .unwrap();
    let pubkey = russh::keys::PublicKey::from(&keypair);

    // Alice's account is expired
    assert!(
        !service.auth_publickey("alice", &pubkey),
        "expired user should fail pubkey auth"
    );
}

// ---------------------------------------------------------------------------
// Test 8: user_store().get() returns an existing user
// ---------------------------------------------------------------------------
#[test]
fn user_store_get() {
    let hash = password::hash_password("testpass").unwrap();
    let config = make_config(&hash);
    let service = AuthService::new(&config).unwrap();

    let store = service.user_store();
    let alice = store.get("alice");
    assert!(alice.is_some(), "user_store should contain alice");
    let alice = alice.unwrap();
    assert_eq!(alice.username, "alice");
    assert!(alice.allow_forwarding);
    assert!(alice.allow_shell);

    let bob = store.get("bob");
    assert!(bob.is_some(), "user_store should contain bob");
    let bob = bob.unwrap();
    assert_eq!(bob.username, "bob");
    assert!(!bob.allow_forwarding);
    assert!(!bob.allow_shell);
}

// ---------------------------------------------------------------------------
// Test 9: user_store().get() returns None for a missing user
// ---------------------------------------------------------------------------
#[test]
fn user_store_nonexistent() {
    let hash = password::hash_password("testpass").unwrap();
    let config = make_config(&hash);
    let service = AuthService::new(&config).unwrap();

    let store = service.user_store();
    assert!(
        store.get("nonexistent").is_none(),
        "user_store.get for unknown user should return None"
    );
}

// ---------------------------------------------------------------------------
// Test 10: reload() updates the user store with a new config
// ---------------------------------------------------------------------------
#[test]
fn reload_updates_store() {
    let hash = password::hash_password("testpass").unwrap();
    let config = make_config(&hash);
    let mut service = AuthService::new(&config).unwrap();

    // Before reload: alice and bob exist, charlie does not
    assert!(service.user_store().get("alice").is_some());
    assert!(service.user_store().get("bob").is_some());
    assert!(service.user_store().get("charlie").is_none());

    // Reload with a config that only has "charlie"
    let new_config = make_config_charlie();
    service.reload(&new_config).unwrap();

    // After reload: alice and bob are gone, charlie exists
    assert!(
        service.user_store().get("alice").is_none(),
        "alice should be gone after reload"
    );
    assert!(
        service.user_store().get("bob").is_none(),
        "bob should be gone after reload"
    );
    assert!(
        service.user_store().get("charlie").is_some(),
        "charlie should exist after reload"
    );

    // Verify charlie can authenticate
    assert!(service.auth_password("charlie", "charliepass"));
    assert!(!service.auth_password("charlie", "wrongpass"));
}
