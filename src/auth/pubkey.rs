use anyhow::Result;
use russh::keys::PublicKey;
use tracing::warn;

/// Parse an OpenSSH authorized_keys line into a PublicKey
pub fn parse_authorized_key(line: &str) -> Result<PublicKey> {
    let key = russh::keys::parse_public_key_base64(
        line.split_whitespace()
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("invalid authorized_key format: {}", line))?,
    )
    .map_err(|e| anyhow::anyhow!("failed to parse public key: {}", e))?;
    Ok(key)
}

/// Pre-parse authorized_keys strings into PublicKey objects.
/// Invalid keys are logged and skipped.
pub fn parse_authorized_keys(key_lines: &[String]) -> Vec<PublicKey> {
    key_lines
        .iter()
        .filter_map(|line| match parse_authorized_key(line) {
            Ok(key) => Some(key),
            Err(e) => {
                warn!(error = %e, key_line = %line, "Failed to parse authorized key at load time");
                None
            }
        })
        .collect()
}

/// Check if a presented key matches any of the pre-parsed authorized keys
pub fn key_matches_parsed(presented: &PublicKey, authorized_keys: &[PublicKey]) -> bool {
    authorized_keys.iter().any(|k| presented == k)
}

/// Check if a presented key matches any of the authorized keys (string version, for backwards compat)
pub fn key_matches(presented: &PublicKey, authorized_keys: &[String]) -> bool {
    for key_line in authorized_keys {
        match parse_authorized_key(key_line) {
            Ok(authorized) => {
                if presented == &authorized {
                    return true;
                }
            }
            Err(e) => {
                warn!(error = %e, key_line = %key_line, "Failed to parse authorized key");
            }
        }
    }
    false
}
