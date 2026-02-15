pub mod certificate;
pub mod password;
pub mod pubkey;
pub mod user;

use crate::config::types::AppConfig;
use anyhow::Result;
use certificate::TrustedCa;
use dashmap::DashMap;
use std::sync::Arc;
use user::UserStore;

/// TOTP replay protection: tracks (username, code) -> expiry_timestamp.
/// Prevents the same TOTP code from being reused within its validity window.
static USED_TOTP_CODES: std::sync::OnceLock<DashMap<(String, String), u64>> =
    std::sync::OnceLock::new();

fn used_totp_codes() -> &'static DashMap<(String, String), u64> {
    USED_TOTP_CODES.get_or_init(DashMap::new)
}

/// Maximum tracked TOTP codes before forced cleanup.
const MAX_TOTP_CODES: usize = 10_000;

/// Dummy hash for timing-safe user enumeration prevention (M-1)
const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Central authentication service
#[derive(Debug)]
pub struct AuthService {
    user_store: Arc<UserStore>,
    /// Pre-parsed trusted CA keys for SSH certificate authentication
    trusted_cas: Arc<Vec<TrustedCa>>,
}

impl AuthService {
    pub fn new(config: &AppConfig) -> Result<Self> {
        let user_store = Arc::new(UserStore::from_config(
            &config.users,
            &config.groups,
            &config.acl,
            &config.limits,
            &config.server,
            &config.shell,
        )?);
        let trusted_cas = Arc::new(certificate::parse_trusted_ca_keys(
            &config.security.trusted_user_ca_keys,
        ));
        if !trusted_cas.is_empty() {
            tracing::info!(
                count = trusted_cas.len(),
                "Loaded trusted CA keys for SSH certificate authentication"
            );
        }
        Ok(Self {
            user_store,
            trusted_cas,
        })
    }

    pub fn user_store(&self) -> &Arc<UserStore> {
        &self.user_store
    }

    /// Get trusted CA keys (for certificate authentication)
    pub fn trusted_cas(&self) -> &[TrustedCa] {
        &self.trusted_cas
    }

    /// Authenticate with password
    pub fn auth_password(&self, username: &str, password: &str) -> bool {
        let user = match self.user_store.get(username) {
            Some(u) => u,
            None => {
                tracing::debug!(username = %username, "User not found, performing dummy verification");
                // M-1: Perform dummy verification to prevent user enumeration timing attacks
                let _ = password::verify_password(password, DUMMY_HASH);
                return false;
            }
        };

        // Always perform password verification before checking expiration
        // to prevent timing-based user enumeration (AUTH-002)
        let password_valid = match &user.password_hash {
            Some(hash) => password::verify_password(password, hash),
            None => {
                let _ = password::verify_password(password, DUMMY_HASH);
                false
            }
        };

        if user.is_expired() {
            tracing::debug!(username = %username, "User account expired");
            return false;
        }

        if password_valid {
            tracing::debug!(username = %username, "Password verification succeeded");
        } else {
            tracing::debug!(username = %username, "Password verification failed");
        }

        password_valid
    }

    /// Verify TOTP code for a user. Returns true if:
    /// - User doesn't have TOTP enabled (skip check)
    /// - TOTP code is valid
    pub fn verify_totp(&self, username: &str, code: &str) -> bool {
        let user = match self.user_store.get(username) {
            Some(u) => u,
            None => return false,
        };

        // If user doesn't have TOTP enabled, always pass
        if !user.totp_enabled {
            tracing::debug!(username = %username, "TOTP not enabled, skipping verification");
            return true;
        }

        tracing::debug!(username = %username, "TOTP verification required");

        let secret = match &user.totp_secret {
            Some(s) => s,
            None => return false, // TOTP enabled but no secret configured
        };

        // Verify TOTP — reject if secret is malformed instead of silently bypassing (PASS-001)
        // Wrap secret bytes in Zeroizing to ensure they are cleared from memory after use
        let secret_bytes = match totp_rs::Secret::Encoded(secret.clone()).to_bytes() {
            Ok(bytes) if !bytes.is_empty() => zeroize::Zeroizing::new(bytes),
            _ => {
                tracing::error!(user = %username, "TOTP secret is malformed or empty, rejecting authentication");
                return false;
            }
        };

        match totp_rs::TOTP::new(
            totp_rs::Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes.to_vec(),
            Some("sks5".to_string()),
            username.to_string(),
        ) {
            Ok(totp) => {
                let valid = totp.check_current(code).unwrap_or(false);
                if valid {
                    // Replay protection: reject if this exact code was already used
                    let key = (username.to_string(), code.to_string());
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    if used_totp_codes().contains_key(&key) {
                        tracing::warn!(username = %username, "TOTP code replay rejected");
                        return false;
                    }
                    // Enforce capacity bound (soft cleanup + hard cap eviction)
                    enforce_totp_hard_cap(used_totp_codes(), MAX_TOTP_CODES, now);
                    // Mark code as used (valid for 60s to cover ±1 step tolerance)
                    used_totp_codes().insert(key, now + 60);
                    tracing::debug!(username = %username, "TOTP verification succeeded");
                } else {
                    tracing::debug!(username = %username, "TOTP verification failed");
                }
                valid
            }
            Err(e) => {
                tracing::error!(user = %username, error = %e, "Failed to create TOTP validator");
                false
            }
        }
    }

    /// Authenticate with public key.
    ///
    /// Two-phase check:
    /// 1. Match against individual authorized_keys (existing behavior)
    /// 2. If no match and trusted CAs are configured, check if the presented
    ///    key bytes are an SSH certificate signed by a trusted CA
    pub fn auth_publickey(&self, username: &str, key: &russh::keys::PublicKey) -> bool {
        let user = match self.user_store.get(username) {
            Some(u) => u,
            None => return false,
        };

        if user.is_expired() {
            return false;
        }

        // Phase 1: Check individual authorized keys
        if pubkey::key_matches_parsed(key, &user.parsed_authorized_keys) {
            return true;
        }

        // Phase 2: Certificate authentication is handled separately in auth_publickey_certificate
        // because russh strips the certificate wrapper before calling auth_publickey.
        // See auth_publickey_certificate() for certificate-based auth.
        false
    }

    /// Authenticate with an SSH certificate.
    ///
    /// This is called when the presented key bytes contain a certificate
    /// (detected by the certificate algorithm prefix like `ssh-ed25519-cert-v01@openssh.com`).
    ///
    /// Validates:
    /// - Certificate is signed by a trusted CA
    /// - Certificate is within its validity period
    /// - Certificate principals include the authenticating user (or are empty)
    /// - Certificate type is User (not Host)
    /// - All critical options are recognized
    pub fn auth_publickey_certificate(&self, username: &str, cert: &ssh_key::Certificate) -> bool {
        if self.trusted_cas.is_empty() {
            tracing::debug!(
                username = %username,
                "No trusted CAs configured, certificate auth not available"
            );
            return false;
        }

        let user = match self.user_store.get(username) {
            Some(u) => u,
            None => return false,
        };

        if user.is_expired() {
            return false;
        }

        certificate::verify_certificate(cert, &self.trusted_cas, username)
    }

    /// Reload user store and trusted CA keys from new config
    pub fn reload(&mut self, config: &AppConfig) -> Result<()> {
        let new_store = Arc::new(UserStore::from_config(
            &config.users,
            &config.groups,
            &config.acl,
            &config.limits,
            &config.server,
            &config.shell,
        )?);
        let new_trusted_cas = Arc::new(certificate::parse_trusted_ca_keys(
            &config.security.trusted_user_ca_keys,
        ));
        if !new_trusted_cas.is_empty() {
            tracing::info!(
                count = new_trusted_cas.len(),
                "Reloaded trusted CA keys for SSH certificate authentication"
            );
        }
        self.user_store = new_store;
        self.trusted_cas = new_trusted_cas;
        Ok(())
    }
}

/// Enforce the TOTP replay map hard cap on a given DashMap.
/// Extracted to allow unit testing without touching the global static.
///
/// Step 1: If at capacity, remove expired entries.
/// Step 2: If still at capacity (all entries valid), evict the oldest 10% by expiry.
fn enforce_totp_hard_cap(map: &DashMap<(String, String), u64>, max_codes: usize, now: u64) {
    // Step 1: remove expired entries
    if map.len() >= max_codes {
        map.retain(|_, expiry| *expiry > now);
    }
    // Step 2: hard cap — evict oldest if still at capacity
    if map.len() >= max_codes {
        let evict_count = std::cmp::max(max_codes / 10, 1);
        let mut entries: Vec<((String, String), u64)> =
            map.iter().map(|e| (e.key().clone(), *e.value())).collect();
        entries.sort_by_key(|(_, expiry)| *expiry);
        for (evict_key, _) in entries.into_iter().take(evict_count) {
            map.remove(&evict_key);
        }
        tracing::warn!(
            evicted = evict_count,
            "TOTP replay map at hard cap, evicted oldest entries"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashmap::DashMap;

    #[test]
    fn test_totp_hard_cap_evicts_expired_first() {
        let map: DashMap<(String, String), u64> = DashMap::new();
        let max = 100;
        let now = 1000;

        // Fill map to capacity: 60 expired, 40 still valid
        for i in 0..60 {
            map.insert(
                (format!("user{i}"), format!("code{i}")),
                now - 1, // expired
            );
        }
        for i in 60..100 {
            map.insert(
                (format!("user{i}"), format!("code{i}")),
                now + 100, // still valid
            );
        }
        assert_eq!(map.len(), 100);

        enforce_totp_hard_cap(&map, max, now);

        // After cleanup: 60 expired entries removed, 40 valid remain
        assert_eq!(map.len(), 40);
        // All remaining entries should be valid (expiry > now)
        for entry in map.iter() {
            assert!(*entry.value() > now);
        }
    }

    #[test]
    fn test_totp_hard_cap_evicts_oldest_when_all_valid() {
        let map: DashMap<(String, String), u64> = DashMap::new();
        let max = 100;
        let now = 1000;

        // Fill map to capacity: all entries are still valid (expiry > now)
        for i in 0..100u64 {
            map.insert(
                (format!("user{i}"), format!("code{i}")),
                now + 10 + i, // all valid, staggered expiry
            );
        }
        assert_eq!(map.len(), 100);

        enforce_totp_hard_cap(&map, max, now);

        // Evicted 10% = 10 entries (the ones with lowest expiry)
        assert_eq!(map.len(), 90);

        // The 10 entries with expiry now+10..now+19 should be gone
        for i in 0..10u64 {
            assert!(
                !map.contains_key(&(format!("user{i}"), format!("code{i}"))),
                "entry {i} with lowest expiry should have been evicted"
            );
        }
        // The 90 entries with expiry now+20..now+109 should remain
        for i in 10..100u64 {
            assert!(
                map.contains_key(&(format!("user{i}"), format!("code{i}"))),
                "entry {i} should still be present"
            );
        }
    }

    #[test]
    fn test_totp_hard_cap_noop_below_limit() {
        let map: DashMap<(String, String), u64> = DashMap::new();
        let max = 100;
        let now = 1000;

        // Only 50 entries — below cap
        for i in 0..50 {
            map.insert((format!("user{i}"), format!("code{i}")), now + 100);
        }

        enforce_totp_hard_cap(&map, max, now);

        // Nothing evicted
        assert_eq!(map.len(), 50);
    }

    #[test]
    fn test_totp_hard_cap_ensures_room_after_eviction() {
        let map: DashMap<(String, String), u64> = DashMap::new();
        let max = 100;
        let now = 1000;

        // Fill exactly to capacity with all valid entries
        for i in 0..100u64 {
            map.insert((format!("user{i}"), format!("code{i}")), now + 1 + i);
        }

        enforce_totp_hard_cap(&map, max, now);

        // After eviction, map size must be strictly less than max
        assert!(
            map.len() < max,
            "map size {} should be < max {} after hard cap eviction",
            map.len(),
            max
        );
    }
}
