use crate::config::types::AppConfig;

/// Redact sensitive fields in a config for safe display.
/// Replaces password_hash, api.token, totp_secret, webhook secrets with "***".
pub fn redact_config(cfg: &AppConfig) -> AppConfig {
    let mut redacted = cfg.clone();

    // Redact API token
    if !redacted.api.token.is_empty() {
        redacted.api.token = "***".to_string();
    }

    // Redact user sensitive fields
    for user in &mut redacted.users {
        if user.password_hash.is_some() {
            user.password_hash = Some("***".to_string());
        }
        if user.totp_secret.is_some() {
            user.totp_secret = Some("***".to_string());
        }
    }

    // Redact webhook secrets
    for webhook in &mut redacted.webhooks {
        if webhook.secret.is_some() {
            webhook.secret = Some("***".to_string());
        }
    }

    redacted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_config;

    const FAKE_HASH: &str = "argon2id-fakehash-for-testing";

    #[test]
    fn test_redact_password_hash() {
        let toml = format!(
            r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "alice"
password_hash = "{hash}"
"##,
            hash = FAKE_HASH,
        );
        let config = parse_config(&toml).unwrap();
        let redacted = redact_config(&config);
        assert_eq!(redacted.users[0].password_hash.as_deref(), Some("***"));
    }

    #[test]
    fn test_redact_api_token() {
        let toml = format!(
            r##"
[server]
ssh_listen = "0.0.0.0:2222"

[api]
enabled = true
token = "my-secret-token!!"

[[users]]
username = "alice"
password_hash = "{hash}"
"##,
            hash = FAKE_HASH,
        );
        let config = parse_config(&toml).unwrap();
        let redacted = redact_config(&config);
        assert_eq!(redacted.api.token, "***");
    }

    #[test]
    fn test_redact_totp_secret() {
        let toml = format!(
            r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "alice"
password_hash = "{hash}"
totp_secret = "JBSWY3DPEHPK3PXP"
totp_enabled = true
"##,
            hash = FAKE_HASH,
        );
        let config = parse_config(&toml).unwrap();
        let redacted = redact_config(&config);
        assert_eq!(redacted.users[0].totp_secret.as_deref(), Some("***"));
    }

    #[test]
    fn test_redact_webhook_secret() {
        let toml = format!(
            r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "alice"
password_hash = "{hash}"

[[webhooks]]
url = "https://example.com/hook"
secret = "webhook-secret"
events = ["auth_failure"]
allow_private_ips = true
"##,
            hash = FAKE_HASH,
        );
        let config = parse_config(&toml).unwrap();
        let redacted = redact_config(&config);
        assert_eq!(redacted.webhooks[0].secret.as_deref(), Some("***"));
    }

    #[test]
    fn test_redact_preserves_non_sensitive() {
        let toml = format!(
            r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "alice"
password_hash = "{hash}"
allow_forwarding = true
"##,
            hash = FAKE_HASH,
        );
        let config = parse_config(&toml).unwrap();
        let redacted = redact_config(&config);
        assert_eq!(redacted.server.ssh_listen, "0.0.0.0:2222");
        assert_eq!(redacted.users[0].username, "alice");
        assert!(redacted.users[0].allow_forwarding);
    }
}
