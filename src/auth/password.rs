use anyhow::Result;
use argon2::password_hash::rand_core::RngCore;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

/// Hash a password using Argon2id with configurable parameters.
///
/// - `memory_cost`: memory in KiB (default 19456 = 19 MiB)
/// - `time_cost`: number of iterations (default 2)
/// - `parallelism`: number of lanes (default 1)
pub fn hash_password_with_params(
    password: &str,
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(memory_cost, time_cost, parallelism, None)
            .map_err(|e| anyhow::anyhow!("invalid argon2 params: {}", e))?,
    );
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("failed to hash password: {}", e))?;
    Ok(hash.to_string())
}

/// Hash a password using Argon2id with default OWASP-recommended parameters.
pub fn hash_password(password: &str) -> Result<String> {
    hash_password_with_params(password, 19456, 2, 1)
}

/// Verify a password against an Argon2id hash
pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to parse password hash");
            return false;
        }
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Generate a random alphanumeric password of the given length
pub fn generate_password(length: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let charset_len = CHARSET.len() as u32;
    // Rejection sampling: reject values >= largest multiple of charset_len
    let limit = (u32::MAX / charset_len) * charset_len;
    let mut password = Vec::with_capacity(length);
    for _ in 0..length {
        loop {
            let val = OsRng.next_u32();
            if val < limit {
                password.push(CHARSET[(val % charset_len) as usize]);
                break;
            }
        }
    }
    String::from_utf8(password).expect("charset is ASCII")
}

/// CLI entrypoint for hash-password subcommand
pub fn hash_password_cli(password: Option<&str>) -> Result<()> {
    let password = match password {
        Some(p) => p.to_string(),
        None => {
            eprintln!("Enter password: ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            input.trim().to_string()
        }
    };

    if password.is_empty() {
        anyhow::bail!("password must not be empty");
    }

    let hash = hash_password(&password)?;
    println!("{}", hash);
    Ok(())
}

/// Extract TOTP code from a combined password string (AUTH-001).
/// Supports two formats:
/// 1. Delimiter: "password:123456" (colon separator, TOTP must be 6 digits)
/// 2. Suffix: "password123456" (last 6 chars must all be digits)
///
/// Returns (actual_password, Some(totp_code)) or (password, None) if no valid TOTP found.
pub fn extract_totp_from_password(combined: &str) -> (String, Option<String>) {
    // Try delimiter-based extraction first (preferred, unambiguous)
    if let Some(colon_pos) = combined.rfind(':') {
        let candidate_code = &combined[colon_pos + 1..];
        if candidate_code.len() == 6 && candidate_code.chars().all(|c| c.is_ascii_digit()) {
            let password = &combined[..colon_pos];
            if !password.is_empty() {
                return (password.to_string(), Some(candidate_code.to_string()));
            }
        }
    }

    // Fall back to suffix-based extraction (last 6 chars must be digits)
    if combined.len() > 6 {
        let (password, candidate_code) = combined.split_at(combined.len() - 6);
        if candidate_code.chars().all(|c| c.is_ascii_digit()) && !password.is_empty() {
            return (password.to_string(), Some(candidate_code.to_string()));
        }
    }

    // No valid TOTP found — password is too short or doesn't end with 6 digits
    // Return full string as password with empty TOTP (will fail TOTP check)
    (combined.to_string(), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify() {
        let password = "test-password-123";
        let hash = hash_password(password).unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password(password, &hash));
    }

    #[test]
    fn test_verify_wrong_password() {
        let hash = hash_password("correct").unwrap();
        assert!(!verify_password("wrong", &hash));
    }

    #[test]
    fn test_verify_invalid_hash() {
        assert!(!verify_password("pass", "not-a-valid-hash"));
    }

    #[test]
    fn test_different_salts() {
        let h1 = hash_password("same").unwrap();
        let h2 = hash_password("same").unwrap();
        assert_ne!(h1, h2); // Different salts
        assert!(verify_password("same", &h1));
        assert!(verify_password("same", &h2));
    }
}
