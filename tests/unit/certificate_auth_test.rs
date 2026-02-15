//! Unit tests for SSH certificate authentication via AuthService.
//!
//! Tests the full AuthService path: config loading, trusted CA parsing,
//! certificate verification, and the auth_publickey_certificate method.

use crate::test_support::{default_user_config, full_app_config};
use sks5::auth::certificate::{parse_trusted_ca_keys, verify_certificate};
use sks5::auth::AuthService;
use sks5::config::types::*;
use ssh_key::certificate::CertType;
use ssh_key::private::KeypairData;
use ssh_key::public::KeyData;
use ssh_key::PrivateKey;

/// Helper: generate an Ed25519 CA key pair and return (PrivateKey, openssh_string).
fn gen_ca_keypair() -> (PrivateKey, String) {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();
    let keypair_data = KeypairData::Ed25519(ssh_key::private::Ed25519Keypair {
        public: ssh_key::public::Ed25519PublicKey(verifying_key.to_bytes()),
        private: ssh_key::private::Ed25519PrivateKey::from_bytes(&signing_key.to_bytes()),
    });
    let private_key = PrivateKey::new(keypair_data, "test-ca").expect("CA key creation");
    let openssh_str = private_key
        .public_key()
        .to_openssh()
        .expect("CA public key to openssh");
    (private_key, openssh_str)
}

/// Helper: generate an Ed25519 user key pair and return KeyData.
fn gen_user_key() -> KeyData {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();
    KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(verifying_key.to_bytes()))
}

/// Helper: sign a user certificate with the given CA.
fn sign_user_cert(
    ca_key: &PrivateKey,
    user_key_data: KeyData,
    username: &str,
) -> ssh_key::Certificate {
    let mut builder = ssh_key::certificate::Builder::new_with_random_nonce(
        &mut rand::rngs::OsRng,
        user_key_data,
        0,
        0xFFFF_FFFF_FFFE,
    )
    .expect("Builder creation");

    builder.serial(1).expect("set serial");
    builder
        .key_id(format!("{username}-cert"))
        .expect("set key_id");
    builder.cert_type(CertType::User).expect("set cert_type");
    builder.valid_principal(username).expect("set principal");

    builder.sign(ca_key).expect("Certificate signing")
}

fn make_minimal_config(ca_key_str: Option<&str>) -> AppConfig {
    let fake_hash = "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let mut user = default_user_config("alice");
    user.password_hash = Some(fake_hash.to_string());

    let security = SecurityConfig {
        trusted_user_ca_keys: ca_key_str.map(|s| vec![s.to_string()]).unwrap_or_default(),
        ..SecurityConfig::default()
    };

    full_app_config(vec![user], security)
}

#[test]
fn test_auth_service_loads_trusted_cas() {
    let (_, ca_str) = gen_ca_keypair();
    let config = make_minimal_config(Some(&ca_str));
    let auth = AuthService::new(&config).expect("AuthService creation");

    assert_eq!(auth.trusted_cas().len(), 1, "Should load one trusted CA");
}

#[test]
fn test_auth_service_no_trusted_cas_by_default() {
    let config = make_minimal_config(None);
    let auth = AuthService::new(&config).expect("AuthService creation");

    assert!(auth.trusted_cas().is_empty(), "No trusted CAs by default");
}

#[test]
fn test_auth_publickey_certificate_valid() {
    let (ca_key, ca_str) = gen_ca_keypair();
    let config = make_minimal_config(Some(&ca_str));
    let auth = AuthService::new(&config).expect("AuthService creation");

    let user_key = gen_user_key();
    let cert = sign_user_cert(&ca_key, user_key, "alice");

    assert!(
        auth.auth_publickey_certificate("alice", &cert),
        "Valid certificate for configured user should authenticate"
    );
}

#[test]
fn test_auth_publickey_certificate_wrong_user() {
    let (ca_key, ca_str) = gen_ca_keypair();
    let config = make_minimal_config(Some(&ca_str));
    let auth = AuthService::new(&config).expect("AuthService creation");

    let user_key = gen_user_key();
    let cert = sign_user_cert(&ca_key, user_key, "alice");

    // User "bob" is not in the config and not in the certificate principals
    assert!(
        !auth.auth_publickey_certificate("bob", &cert),
        "Certificate should fail for unknown user"
    );
}

#[test]
fn test_auth_publickey_certificate_no_cas_configured() {
    let (ca_key, _) = gen_ca_keypair();
    let config = make_minimal_config(None); // No CAs
    let auth = AuthService::new(&config).expect("AuthService creation");

    let user_key = gen_user_key();
    let cert = sign_user_cert(&ca_key, user_key, "alice");

    assert!(
        !auth.auth_publickey_certificate("alice", &cert),
        "Without trusted CAs, certificate auth should fail"
    );
}

#[test]
fn test_auth_service_reload_updates_cas() {
    let (_, ca_str1) = gen_ca_keypair();
    let config1 = make_minimal_config(Some(&ca_str1));
    let mut auth = AuthService::new(&config1).expect("AuthService creation");
    assert_eq!(auth.trusted_cas().len(), 1);

    // Reload with no CAs
    let config2 = make_minimal_config(None);
    auth.reload(&config2).expect("reload");
    assert!(auth.trusted_cas().is_empty(), "After reload, no CAs");

    // Reload again with a new CA
    let (_, ca_str2) = gen_ca_keypair();
    let config3 = make_minimal_config(Some(&ca_str2));
    auth.reload(&config3).expect("reload");
    assert_eq!(auth.trusted_cas().len(), 1, "After reload, new CA loaded");
}

#[test]
fn test_certificate_roundtrip_openssh_format() {
    let (ca_key, ca_str) = gen_ca_keypair();
    let user_key = gen_user_key();
    let cert = sign_user_cert(&ca_key, user_key, "testuser");

    // Serialize to OpenSSH format and parse back
    let openssh_str = cert.to_openssh().expect("to_openssh");
    let parsed = ssh_key::Certificate::from_openssh(&openssh_str).expect("from_openssh");

    assert_eq!(parsed.key_id(), cert.key_id());
    assert_eq!(parsed.serial(), cert.serial());
    assert_eq!(parsed.cert_type(), CertType::User);
    assert_eq!(parsed.valid_principals(), cert.valid_principals());

    // Validate against the CA
    let trusted_cas = parse_trusted_ca_keys(&[ca_str]);
    assert!(
        verify_certificate(&parsed, &trusted_cas, "testuser"),
        "Parsed certificate should validate"
    );
}

#[test]
fn test_certificate_bytes_roundtrip() {
    let (ca_key, ca_str) = gen_ca_keypair();
    let user_key = gen_user_key();
    let cert = sign_user_cert(&ca_key, user_key, "testuser");

    // Serialize to bytes and parse back
    let cert_bytes = cert.to_bytes().expect("to_bytes");
    let parsed = ssh_key::Certificate::from_bytes(&cert_bytes).expect("from_bytes");

    assert_eq!(parsed.key_id(), cert.key_id());

    let trusted_cas = parse_trusted_ca_keys(&[ca_str]);
    assert!(
        verify_certificate(&parsed, &trusted_cas, "testuser"),
        "Certificate from bytes should validate"
    );
}

#[test]
fn test_multiple_trusted_cas() {
    let (ca_key1, ca_str1) = gen_ca_keypair();
    let (ca_key2, ca_str2) = gen_ca_keypair();

    // Both CAs are trusted
    let trusted_cas = parse_trusted_ca_keys(&[ca_str1, ca_str2]);
    assert_eq!(trusted_cas.len(), 2);

    // Certificate signed by CA1
    let user_key1 = gen_user_key();
    let cert1 = sign_user_cert(&ca_key1, user_key1, "alice");
    assert!(
        verify_certificate(&cert1, &trusted_cas, "alice"),
        "Cert from CA1 should validate"
    );

    // Certificate signed by CA2
    let user_key2 = gen_user_key();
    let cert2 = sign_user_cert(&ca_key2, user_key2, "alice");
    assert!(
        verify_certificate(&cert2, &trusted_cas, "alice"),
        "Cert from CA2 should validate"
    );

    // Certificate signed by unknown CA
    let (ca_key3, _) = gen_ca_keypair();
    let user_key3 = gen_user_key();
    let cert3 = sign_user_cert(&ca_key3, user_key3, "alice");
    assert!(
        !verify_certificate(&cert3, &trusted_cas, "alice"),
        "Cert from unknown CA3 should fail"
    );
}
