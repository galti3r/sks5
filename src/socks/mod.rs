pub mod auth;
pub mod handler;
pub mod protocol;
pub mod udp_relay;

use crate::config::types::AppConfig;
use crate::context::AppContext;
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

/// Build the handshake timeout from config.
pub(crate) fn socks5_handshake_timeout(config: &AppConfig) -> Duration {
    Duration::from_secs(config.limits.socks5_handshake_timeout)
}

/// Load TLS config if cert/key are provided.
fn load_tls_config(config: &AppConfig) -> Result<Option<Arc<tokio_rustls::rustls::ServerConfig>>> {
    let (cert_path, key_path) = match (
        &config.server.socks5_tls_cert,
        &config.server.socks5_tls_key,
    ) {
        (Some(c), Some(k)) => (c, k),
        _ => return Ok(None),
    };

    use std::io::BufReader;
    let cert_file = std::fs::File::open(cert_path)
        .map_err(|e| anyhow::anyhow!("reading TLS cert {}: {}", cert_path.display(), e))?;
    let key_file = std::fs::File::open(key_path)
        .map_err(|e| anyhow::anyhow!("reading TLS key {}: {}", key_path.display(), e))?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("parsing TLS certs: {}", e))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {}", cert_path.display());
    }

    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .map_err(|e| anyhow::anyhow!("parsing TLS key: {}", e))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", key_path.display()))?;

    let tls_config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("TLS config error: {}", e))?;

    Ok(Some(Arc::new(tls_config)))
}

/// Start the standalone SOCKS5 listener with graceful shutdown support.
pub async fn start_socks5_server(
    listen_addr: &str,
    ctx: Arc<AppContext>,
    shutdown: CancellationToken,
) -> Result<()> {
    let tls_acceptor = load_tls_config(&ctx.config)?.map(tokio_rustls::TlsAcceptor::from);

    let listener = TcpListener::bind(listen_addr).await?;

    if tls_acceptor.is_some() {
        info!(addr = %listen_addr, "SOCKS5 server listening (TLS enabled)");
    } else {
        info!(addr = %listen_addr, "SOCKS5 server listening");
    }

    // Limit concurrent SOCKS5 connections
    let semaphore = Arc::new(Semaphore::new(ctx.config.limits.max_connections as usize));

    loop {
        let stream = tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, _peer)) => stream,
                    Err(e) => {
                        error!(error = %e, "SOCKS5 accept error");
                        continue;
                    }
                }
            }
            _ = shutdown.cancelled() => {
                info!("SOCKS5 server shutting down (no new connections)");
                break;
            }
        };

        // Check connection limit before spawning
        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                warn!("SOCKS5 connection limit reached, dropping connection");
                drop(stream);
                continue;
            }
        };

        let ctx = ctx.clone();
        let tls = tls_acceptor.clone();

        tokio::spawn(async move {
            let _permit = permit;

            if let Some(acceptor) = tls {
                // P3-1: TLS-wrapped SOCKS5
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        if let Err(e) = handler::handle_tls_connection(tls_stream, ctx).await {
                            error!(error = %e, "SOCKS5 TLS connection error");
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "SOCKS5 TLS handshake failed");
                    }
                }
            } else if let Err(e) = handler::handle_connection(stream, ctx).await {
                error!(error = %e, "SOCKS5 connection error");
            }
        });
    }

    Ok(())
}
