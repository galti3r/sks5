use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

// RFC 1929 username/password subnegotiation
pub const SUBNEG_VERSION: u8 = 0x01;
pub const AUTH_SUCCESS: u8 = 0x00;
pub const AUTH_FAILURE: u8 = 0x01;

pub struct Credentials {
    pub username: String,
    pub password: Zeroizing<String>,
}

/// Read RFC 1929 username/password subnegotiation
pub async fn read_credentials(stream: &mut (impl AsyncRead + Unpin)) -> Result<Credentials> {
    let ver = stream.read_u8().await.context("reading subneg version")?;
    if ver != SUBNEG_VERSION {
        anyhow::bail!("unsupported subneg version: {}", ver);
    }

    let ulen = stream.read_u8().await.context("reading username length")? as usize;
    if ulen == 0 {
        anyhow::bail!("username length must be at least 1 (RFC 1929)");
    }
    let mut username_bytes = vec![0u8; ulen];
    stream
        .read_exact(&mut username_bytes)
        .await
        .context("reading username")?;

    let plen = stream.read_u8().await.context("reading password length")? as usize;
    if plen == 0 {
        anyhow::bail!("password length must be at least 1 (RFC 1929)");
    }
    let mut password_bytes = Zeroizing::new(vec![0u8; plen]);
    stream
        .read_exact(&mut password_bytes)
        .await
        .context("reading password")?;

    let username = String::from_utf8(username_bytes).context("invalid username encoding")?;
    let password = Zeroizing::new(
        String::from_utf8(password_bytes.to_vec()).context("invalid password encoding")?,
    );

    Ok(Credentials { username, password })
}

/// Send authentication result
pub async fn send_auth_result(stream: &mut (impl AsyncWrite + Unpin), success: bool) -> Result<()> {
    let status = if success { AUTH_SUCCESS } else { AUTH_FAILURE };
    stream
        .write_all(&[SUBNEG_VERSION, status])
        .await
        .context("sending auth result")?;
    Ok(())
}
