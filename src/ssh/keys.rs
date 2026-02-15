use anyhow::{Context, Result};
use russh::keys::{Algorithm, PrivateKey};
use std::path::Path;

/// Load or generate an Ed25519 host key
pub fn load_or_generate_host_key(path: &Path) -> Result<PrivateKey> {
    if path.exists() {
        load_host_key(path)
    } else {
        let key = generate_host_key()?;
        save_host_key(&key, path)?;
        Ok(key)
    }
}

fn load_host_key(path: &Path) -> Result<PrivateKey> {
    let key_bytes = std::fs::read_to_string(path)
        .with_context(|| format!("reading host key: {}", path.display()))?;
    let key = russh::keys::decode_secret_key(&key_bytes, None)
        .map_err(|e| anyhow::anyhow!("decoding host key: {}", e))?;
    Ok(key)
}

fn generate_host_key() -> Result<PrivateKey> {
    PrivateKey::random(&mut rand::rngs::OsRng, Algorithm::Ed25519)
        .map_err(|e| anyhow::anyhow!("Ed25519 key generation failed: {}", e))
}

fn save_host_key(key: &PrivateKey, path: &Path) -> Result<()> {
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating directory: {}", parent.display()))?;
        }
    }

    let mut buf = Vec::new();
    russh::keys::encode_pkcs8_pem(key, &mut buf)
        .map_err(|e| anyhow::anyhow!("encoding host key: {}", e))?;

    // Write with restrictive permissions from the start (no TOCTOU window)
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating host key file: {}", path.display()))?;
        file.write_all(&buf)
            .with_context(|| format!("writing host key: {}", path.display()))?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, &buf)
            .with_context(|| format!("writing host key: {}", path.display()))?;
    }

    Ok(())
}
