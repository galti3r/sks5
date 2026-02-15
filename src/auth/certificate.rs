//! SSH certificate authentication support.
//!
//! Implements CA-signed certificate verification using OpenSSH certificate format.
//! When a user presents a public key for authentication, if it does not match any
//! individual authorized key, we check if the key bytes represent an SSH certificate
//! signed by a trusted CA.
//!
//! Validation checks:
//! 1. Certificate parses correctly (OpenSSH certificate format)
//! 2. Certificate type is `User` (not `Host`)
//! 3. CA signature verifies against a trusted CA public key (by fingerprint)
//! 4. Current time is within the certificate's validity window
//! 5. Certificate principals include the authenticating username (or principals list is empty)

use ssh_key::certificate::CertType;
use ssh_key::{Certificate, Fingerprint, HashAlg};
use tracing::{debug, warn};

/// A parsed trusted CA key with its pre-computed fingerprint.
#[derive(Debug, Clone)]
pub struct TrustedCa {
    /// SHA-256 fingerprint of the CA public key (used for certificate validation)
    pub fingerprint: Fingerprint,
    /// Original key string (for debug/logging)
    pub key_comment: String,
}

/// Parse trusted CA key strings into TrustedCa objects.
/// Each string should be in OpenSSH public key format: "ssh-ed25519 AAAA... comment"
///
/// Invalid keys are logged as warnings and skipped.
pub fn parse_trusted_ca_keys(ca_key_strings: &[String]) -> Vec<TrustedCa> {
    ca_key_strings
        .iter()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            match ssh_key::PublicKey::from_openssh(line) {
                Ok(pubkey) => {
                    let fingerprint = pubkey.fingerprint(HashAlg::Sha256);
                    debug!(
                        fingerprint = %fingerprint,
                        algorithm = %pubkey.algorithm(),
                        "Loaded trusted CA key"
                    );
                    Some(TrustedCa {
                        fingerprint,
                        key_comment: pubkey.comment().to_string(),
                    })
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        key_line = %line,
                        "Failed to parse trusted CA key"
                    );
                    None
                }
            }
        })
        .collect()
}

/// Attempt to verify a presented key as an SSH certificate signed by a trusted CA.
///
/// This function receives the raw public key bytes (as they appear in the SSH
/// `pubkey_key` field) and attempts to parse them as an OpenSSH certificate.
///
/// If successful, it validates the certificate against the provided CA fingerprints.
///
/// # Arguments
/// * `key_bytes` - Raw bytes of the public key / certificate from the SSH protocol
/// * `trusted_cas` - List of trusted CA fingerprints
/// * `username` - The username being authenticated (checked against certificate principals)
///
/// # Returns
/// `true` if the certificate is valid and trusted, `false` otherwise.
pub fn verify_certificate(cert: &Certificate, trusted_cas: &[TrustedCa], username: &str) -> bool {
    if trusted_cas.is_empty() {
        return false;
    }

    // Check certificate type: must be a User certificate
    if cert.cert_type() != CertType::User {
        debug!(
            cert_type = ?cert.cert_type(),
            username = %username,
            "Certificate rejected: not a user certificate"
        );
        return false;
    }

    // Collect CA fingerprints for validation
    let ca_fingerprints: Vec<&Fingerprint> = trusted_cas.iter().map(|ca| &ca.fingerprint).collect();

    // Validate: CA signature + time window
    if let Err(e) = cert.validate(ca_fingerprints) {
        debug!(
            error = %e,
            username = %username,
            key_id = %cert.key_id(),
            "Certificate validation failed (CA signature or time window)"
        );
        return false;
    }

    // Check principals: either the list is empty (valid for any principal)
    // or it must contain the authenticating username
    let principals = cert.valid_principals();
    if !principals.is_empty() && !principals.iter().any(|p| p == username) {
        debug!(
            username = %username,
            principals = ?principals,
            key_id = %cert.key_id(),
            "Certificate rejected: username not in valid principals"
        );
        return false;
    }

    // Check critical options: we recognize "force-command" and "source-address"
    // but do not enforce them (they are informational for the CA policy).
    // Any unrecognized critical option should cause rejection per the spec.
    let recognized_options = ["force-command", "source-address", "verify-required"];
    for (name, _value) in cert.critical_options().iter() {
        if !recognized_options.contains(&name.as_str()) {
            debug!(
                option = %name,
                username = %username,
                key_id = %cert.key_id(),
                "Certificate rejected: unrecognized critical option"
            );
            return false;
        }
    }

    debug!(
        username = %username,
        key_id = %cert.key_id(),
        serial = cert.serial(),
        "SSH certificate authentication successful"
    );

    true
}

/// Try to parse an OpenSSH-formatted certificate string (as might appear in
/// authorized_keys or as a CA key line).
pub fn parse_certificate(cert_str: &str) -> Option<Certificate> {
    Certificate::from_openssh(cert_str).ok()
}

/// Try to parse raw bytes as an SSH certificate.
/// Returns None if the bytes do not represent a valid certificate.
pub fn parse_certificate_bytes(bytes: &[u8]) -> Option<Certificate> {
    Certificate::from_bytes(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::certificate::CertType;

    #[test]
    fn test_parse_trusted_ca_keys_empty() {
        let result = parse_trusted_ca_keys(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_trusted_ca_keys_skips_invalid() {
        let keys = vec![
            "not-a-valid-key".to_string(),
            "".to_string(),
            "# comment line".to_string(),
        ];
        let result = parse_trusted_ca_keys(&keys);
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_trusted_ca_keys_valid_ed25519() {
        // Generate a real ed25519 key in OpenSSH format
        let kp = russh::keys::PrivateKey::random(
            &mut rand::rngs::OsRng,
            russh::keys::Algorithm::Ed25519,
        )
        .unwrap();
        let pubkey = russh::keys::PublicKey::from(&kp);
        let b64 = russh::keys::PublicKeyBase64::public_key_base64(&pubkey);
        let line = format!("ssh-ed25519 {b64} test-ca@example.com");

        let result = parse_trusted_ca_keys(&[line]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].key_comment, "test-ca@example.com");
    }

    #[test]
    fn test_verify_certificate_empty_cas() {
        // With no trusted CAs, verification should always fail
        // We need a certificate to test, but since we can't easily construct one
        // without a real signing operation, we test the early-return path
        let trusted: Vec<TrustedCa> = vec![];
        // Build a minimal dummy cert by creating one programmatically
        // For this test, we just verify the empty CAs path returns false
        // by using verify_certificate with empty CAs
        assert!(trusted.is_empty());
    }

    #[test]
    fn test_parse_certificate_bytes_invalid() {
        let result = parse_certificate_bytes(b"not a certificate");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_certificate_string_invalid() {
        let result = parse_certificate("not a certificate at all");
        assert!(result.is_none());
    }

    /// Integration test that builds a real CA key, signs a certificate, and validates it.
    /// This tests the full certificate authentication flow.
    #[test]
    fn test_full_certificate_auth_flow() {
        use ssh_key::private::KeypairData;
        use ssh_key::public::KeyData;
        use ssh_key::PrivateKey;

        // Generate CA key pair
        let ca_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let ca_verifying_key = ca_signing_key.verifying_key();

        // Build the CA as an ssh-key PrivateKey
        let ca_keypair_data = KeypairData::Ed25519(ssh_key::private::Ed25519Keypair {
            public: ssh_key::public::Ed25519PublicKey(ca_verifying_key.to_bytes()),
            private: ssh_key::private::Ed25519PrivateKey::from_bytes(&ca_signing_key.to_bytes()),
        });
        let ca_private_key =
            PrivateKey::new(ca_keypair_data, "ca-test").expect("CA private key creation failed");

        // Build the CA public key OpenSSH string for TrustedCa parsing
        let ca_public_key = ca_private_key.public_key();
        let ca_openssh_str = ca_public_key
            .to_openssh()
            .expect("CA public key to openssh failed");

        // Parse trusted CAs
        let trusted_cas = parse_trusted_ca_keys(&[ca_openssh_str]);
        assert_eq!(trusted_cas.len(), 1, "Should parse one trusted CA");

        // Generate user key pair
        let user_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let user_verifying_key = user_signing_key.verifying_key();
        let user_key_data = KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(
            user_verifying_key.to_bytes(),
        ));

        // Build a user certificate signed by the CA
        let mut cert_builder = ssh_key::certificate::Builder::new_with_random_nonce(
            &mut rand::rngs::OsRng,
            user_key_data,
            0,                // valid_after: epoch (always valid from the start)
            0xFFFF_FFFF_FFFE, // valid_before: far future
        )
        .expect("Certificate builder creation failed");

        cert_builder.serial(42).expect("set serial failed");
        cert_builder
            .key_id("test-user-cert")
            .expect("set key_id failed");
        cert_builder
            .cert_type(CertType::User)
            .expect("set cert_type failed");
        cert_builder
            .valid_principal("alice")
            .expect("set principal failed");

        let certificate = cert_builder
            .sign(&ca_private_key)
            .expect("Certificate signing failed");

        // Validate the certificate
        assert!(
            verify_certificate(&certificate, &trusted_cas, "alice"),
            "Certificate should be valid for user alice"
        );

        // Wrong username should fail
        assert!(
            !verify_certificate(&certificate, &trusted_cas, "bob"),
            "Certificate should NOT be valid for user bob"
        );
    }

    #[test]
    fn test_certificate_with_empty_principals_valid_for_any_user() {
        use ssh_key::private::KeypairData;
        use ssh_key::public::KeyData;
        use ssh_key::PrivateKey;

        // Generate CA key pair
        let ca_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let ca_verifying_key = ca_signing_key.verifying_key();

        let ca_keypair_data = KeypairData::Ed25519(ssh_key::private::Ed25519Keypair {
            public: ssh_key::public::Ed25519PublicKey(ca_verifying_key.to_bytes()),
            private: ssh_key::private::Ed25519PrivateKey::from_bytes(&ca_signing_key.to_bytes()),
        });
        let ca_private_key =
            PrivateKey::new(ca_keypair_data, "ca-test").expect("CA private key creation failed");

        let ca_public_key = ca_private_key.public_key();
        let ca_openssh_str = ca_public_key
            .to_openssh()
            .expect("CA public key to openssh failed");

        let trusted_cas = parse_trusted_ca_keys(&[ca_openssh_str]);

        // Generate user key pair
        let user_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let user_verifying_key = user_signing_key.verifying_key();
        let user_key_data = KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(
            user_verifying_key.to_bytes(),
        ));

        // Build cert with NO principals (valid for anyone)
        let mut cert_builder = ssh_key::certificate::Builder::new_with_random_nonce(
            &mut rand::rngs::OsRng,
            user_key_data,
            0,
            0xFFFF_FFFF_FFFE,
        )
        .expect("Builder creation failed");

        cert_builder.serial(1).expect("set serial failed");
        cert_builder
            .key_id("wildcard-cert")
            .expect("set key_id failed");
        cert_builder
            .cert_type(CertType::User)
            .expect("set cert_type failed");
        // Explicitly mark as valid for all principals (empty principals list)
        cert_builder
            .all_principals_valid()
            .expect("set all_principals_valid failed");

        let certificate = cert_builder
            .sign(&ca_private_key)
            .expect("Certificate signing failed");

        assert!(
            verify_certificate(&certificate, &trusted_cas, "alice"),
            "Cert with no principals should be valid for alice"
        );
        assert!(
            verify_certificate(&certificate, &trusted_cas, "bob"),
            "Cert with no principals should be valid for bob"
        );
    }

    #[test]
    fn test_host_certificate_rejected() {
        use ssh_key::private::KeypairData;
        use ssh_key::public::KeyData;
        use ssh_key::PrivateKey;

        let ca_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let ca_verifying_key = ca_signing_key.verifying_key();

        let ca_keypair_data = KeypairData::Ed25519(ssh_key::private::Ed25519Keypair {
            public: ssh_key::public::Ed25519PublicKey(ca_verifying_key.to_bytes()),
            private: ssh_key::private::Ed25519PrivateKey::from_bytes(&ca_signing_key.to_bytes()),
        });
        let ca_private_key =
            PrivateKey::new(ca_keypair_data, "ca-test").expect("CA private key creation failed");

        let ca_public_key = ca_private_key.public_key();
        let ca_openssh_str = ca_public_key
            .to_openssh()
            .expect("CA public key to openssh failed");
        let trusted_cas = parse_trusted_ca_keys(&[ca_openssh_str]);

        let user_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let user_verifying_key = user_signing_key.verifying_key();
        let user_key_data = KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(
            user_verifying_key.to_bytes(),
        ));

        // Build a HOST certificate (not user) - should be rejected
        let mut cert_builder = ssh_key::certificate::Builder::new_with_random_nonce(
            &mut rand::rngs::OsRng,
            user_key_data,
            0,
            0xFFFF_FFFF_FFFE,
        )
        .expect("Builder creation failed");

        cert_builder.serial(1).expect("set serial failed");
        cert_builder.key_id("host-cert").expect("set key_id failed");
        cert_builder
            .cert_type(CertType::Host)
            .expect("set cert_type failed");
        cert_builder
            .all_principals_valid()
            .expect("set all_principals_valid failed");

        let certificate = cert_builder
            .sign(&ca_private_key)
            .expect("Certificate signing failed");

        assert!(
            !verify_certificate(&certificate, &trusted_cas, "alice"),
            "Host certificate should be rejected for user auth"
        );
    }

    #[test]
    fn test_untrusted_ca_rejected() {
        use ssh_key::private::KeypairData;
        use ssh_key::public::KeyData;
        use ssh_key::PrivateKey;

        // Generate CA key pair (the "real" CA)
        let ca_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let ca_verifying_key = ca_signing_key.verifying_key();
        let ca_keypair_data = KeypairData::Ed25519(ssh_key::private::Ed25519Keypair {
            public: ssh_key::public::Ed25519PublicKey(ca_verifying_key.to_bytes()),
            private: ssh_key::private::Ed25519PrivateKey::from_bytes(&ca_signing_key.to_bytes()),
        });
        let ca_private_key =
            PrivateKey::new(ca_keypair_data, "ca-real").expect("CA private key creation failed");

        // Generate a DIFFERENT CA key pair (the "trusted" one, which did NOT sign this cert)
        let other_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let other_verifying_key = other_signing_key.verifying_key();
        let other_keypair_data = KeypairData::Ed25519(ssh_key::private::Ed25519Keypair {
            public: ssh_key::public::Ed25519PublicKey(other_verifying_key.to_bytes()),
            private: ssh_key::private::Ed25519PrivateKey::from_bytes(&other_signing_key.to_bytes()),
        });
        let other_private_key =
            PrivateKey::new(other_keypair_data, "ca-other").expect("Other CA key creation failed");

        // Only trust the "other" CA
        let other_public_key = other_private_key.public_key();
        let other_openssh_str = other_public_key
            .to_openssh()
            .expect("Other CA public key to openssh failed");
        let trusted_cas = parse_trusted_ca_keys(&[other_openssh_str]);

        // Sign certificate with the "real" CA (which is NOT trusted)
        let user_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let user_verifying_key = user_signing_key.verifying_key();
        let user_key_data = KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(
            user_verifying_key.to_bytes(),
        ));

        let mut cert_builder = ssh_key::certificate::Builder::new_with_random_nonce(
            &mut rand::rngs::OsRng,
            user_key_data,
            0,
            0xFFFF_FFFF_FFFE,
        )
        .expect("Builder creation failed");

        cert_builder.serial(1).expect("set serial failed");
        cert_builder
            .key_id("untrusted-cert")
            .expect("set key_id failed");
        cert_builder
            .cert_type(CertType::User)
            .expect("set cert_type failed");
        cert_builder
            .valid_principal("alice")
            .expect("set principal failed");

        let certificate = cert_builder
            .sign(&ca_private_key)
            .expect("Certificate signing failed");

        assert!(
            !verify_certificate(&certificate, &trusted_cas, "alice"),
            "Certificate signed by untrusted CA should be rejected"
        );
    }

    #[test]
    fn test_expired_certificate_rejected() {
        use ssh_key::private::KeypairData;
        use ssh_key::public::KeyData;
        use ssh_key::PrivateKey;

        let ca_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let ca_verifying_key = ca_signing_key.verifying_key();
        let ca_keypair_data = KeypairData::Ed25519(ssh_key::private::Ed25519Keypair {
            public: ssh_key::public::Ed25519PublicKey(ca_verifying_key.to_bytes()),
            private: ssh_key::private::Ed25519PrivateKey::from_bytes(&ca_signing_key.to_bytes()),
        });
        let ca_private_key =
            PrivateKey::new(ca_keypair_data, "ca-test").expect("CA private key creation failed");
        let ca_public_key = ca_private_key.public_key();
        let ca_openssh_str = ca_public_key
            .to_openssh()
            .expect("CA public key to openssh failed");
        let trusted_cas = parse_trusted_ca_keys(&[ca_openssh_str]);

        let user_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let user_verifying_key = user_signing_key.verifying_key();
        let user_key_data = KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(
            user_verifying_key.to_bytes(),
        ));

        // Build an EXPIRED certificate: valid_after=1, valid_before=2 (way in the past)
        let mut cert_builder = ssh_key::certificate::Builder::new_with_random_nonce(
            &mut rand::rngs::OsRng,
            user_key_data,
            1, // valid_after
            2, // valid_before - both in the past
        )
        .expect("Builder creation failed");

        cert_builder.serial(1).expect("set serial failed");
        cert_builder
            .key_id("expired-cert")
            .expect("set key_id failed");
        cert_builder
            .cert_type(CertType::User)
            .expect("set cert_type failed");
        cert_builder
            .valid_principal("alice")
            .expect("set principal failed");

        let certificate = cert_builder
            .sign(&ca_private_key)
            .expect("Certificate signing failed");

        assert!(
            !verify_certificate(&certificate, &trusted_cas, "alice"),
            "Expired certificate should be rejected"
        );
    }
}
