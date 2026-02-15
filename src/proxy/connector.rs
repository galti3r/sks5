use super::dns_cache::DnsCache;
use super::ip_guard;
use crate::metrics::MetricsRegistry;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::{debug, warn};

/// Resolve hostname and check all addresses against ip_guard.
/// Returns only safe addresses (H-6: prevents port scanning oracle).
pub async fn resolve_and_check(
    host: &str,
    port: u16,
    timeout_secs: u64,
    ip_guard_enabled: bool,
) -> Result<Vec<SocketAddr>> {
    let addr_str = if host.contains(':') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    };

    let dns_timeout = std::time::Duration::from_secs(timeout_secs.min(30));
    let addrs: Vec<SocketAddr> =
        tokio::time::timeout(dns_timeout, tokio::net::lookup_host(&addr_str))
            .await
            .context("DNS lookup timeout")?
            .with_context(|| format!("DNS lookup failed for {}", addr_str))?
            .collect();

    if addrs.is_empty() {
        anyhow::bail!("no addresses found for {}", addr_str);
    }

    if !ip_guard_enabled {
        return Ok(addrs);
    }

    let safe_addrs: Vec<SocketAddr> = addrs
        .into_iter()
        .filter(|addr| {
            if let Some(range_name) = ip_guard::classify_dangerous_ip(&addr.ip()) {
                warn!(
                    target_host = %host,
                    resolved_ip = %addr.ip(),
                    range = %range_name,
                    "Blocked connection to {} IP (anti-SSRF)", range_name
                );
                false
            } else {
                true
            }
        })
        .collect();

    if safe_addrs.is_empty() {
        anyhow::bail!(
            "all resolved addresses for {} are blocked by ip_guard",
            host
        );
    }

    Ok(safe_addrs)
}

/// DNS resolve + TCP connect with timeout.
/// Blocks connections to private/reserved IPs (anti-SSRF) when ip_guard_enabled is true.
pub async fn connect(
    host: &str,
    port: u16,
    timeout_secs: u64,
    ip_guard_enabled: bool,
) -> Result<(TcpStream, SocketAddr)> {
    // M-9: Reject port 0
    if port == 0 {
        anyhow::bail!("port 0 is not allowed");
    }

    let addrs = resolve_and_check(host, port, timeout_secs, ip_guard_enabled).await?;

    debug!(target_host = %host, resolved = ?addrs, "Resolved target (ip_guard filtered)");

    // Try to connect to each resolved address
    let timeout_duration = std::time::Duration::from_secs(timeout_secs);
    let mut last_err = None;

    for addr in &addrs {
        match tokio::time::timeout(timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                debug!(target_addr = %addr, "TCP connected");
                configure_tcp_socket(&stream);
                return Ok((stream, *addr));
            }
            Ok(Err(e)) => {
                debug!(target_addr = %addr, error = %e, "TCP connect failed");
                last_err = Some(e);
            }
            Err(_) => {
                debug!(target_addr = %addr, "TCP connect timeout");
                last_err = Some(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "connection timeout",
                ));
            }
        }
    }

    Err(last_err
        .map(|e| anyhow::anyhow!(e))
        .unwrap_or_else(|| anyhow::anyhow!("failed to connect to {}:{}", host, port)))
}

/// P3-3: DNS resolve + TCP connect with DNS cache support.
pub async fn connect_with_cache(
    host: &str,
    port: u16,
    timeout_secs: u64,
    ip_guard_enabled: bool,
    dns_cache: &DnsCache,
    metrics: Option<&MetricsRegistry>,
) -> Result<(TcpStream, SocketAddr)> {
    if port == 0 {
        anyhow::bail!("port 0 is not allowed");
    }

    // Build cache key on the stack to avoid heap allocation in hot path
    let mut cache_key = String::with_capacity(host.len() + 6);
    cache_key.push_str(host);
    cache_key.push(':');
    {
        use std::fmt::Write;
        let _ = write!(cache_key, "{}", port);
    }

    // Check cache first
    if let Some(cached_addrs) = dns_cache.get(&cache_key, ip_guard_enabled) {
        debug!(target_host = %host, cached_addrs = ?cached_addrs, "DNS cache hit");
        if let Some(m) = metrics {
            m.dns_cache_hits_total.inc();
        }
        return connect_to_addrs(&cached_addrs, timeout_secs, host, port).await;
    }

    // Cache miss — resolve normally
    if let Some(m) = metrics {
        m.dns_cache_misses_total.inc();
    }
    let addrs = resolve_and_check(host, port, timeout_secs, ip_guard_enabled).await?;

    debug!(target_host = %host, resolved = ?addrs, "Resolved target (ip_guard filtered)");

    // Store in cache (use default TTL since we don't have native TTL from tokio::net::lookup_host)
    dns_cache.insert(&cache_key, addrs.clone(), None);

    connect_to_addrs(&addrs, timeout_secs, host, port).await
}

/// Connect to a list of already-resolved addresses.
async fn connect_to_addrs(
    addrs: &[SocketAddr],
    timeout_secs: u64,
    host: &str,
    port: u16,
) -> Result<(TcpStream, SocketAddr)> {
    let timeout_duration = std::time::Duration::from_secs(timeout_secs);
    let mut last_err = None;

    for addr in addrs {
        match tokio::time::timeout(timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                debug!(target_addr = %addr, "TCP connected");
                configure_tcp_socket(&stream);
                return Ok((stream, *addr));
            }
            Ok(Err(e)) => {
                debug!(target_addr = %addr, error = %e, "TCP connect failed");
                last_err = Some(e);
            }
            Err(_) => {
                debug!(target_addr = %addr, "TCP connect timeout");
                last_err = Some(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "connection timeout",
                ));
            }
        }
    }

    Err(last_err
        .map(|e| anyhow::anyhow!(e))
        .unwrap_or_else(|| anyhow::anyhow!("failed to connect to {}:{}", host, port)))
}

/// Connect to a target host:port via an upstream SOCKS5 proxy.
///
/// Performs the full SOCKS5 client handshake (greeting, optional auth, CONNECT),
/// then returns the tunnelled TCP stream. DNS resolution of the target is delegated
/// to the upstream proxy (ATYP_DOMAIN).
pub async fn connect_via_socks5(
    proxy: &crate::config::types::ParsedUpstreamProxy,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
) -> Result<TcpStream> {
    use crate::socks::protocol::{
        ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, AUTH_NONE, AUTH_PASSWORD, CMD_CONNECT, REPLY_SUCCESS,
        SOCKS_VERSION,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Step 1: TCP connect to the upstream proxy
    let proxy_addr = format!("{}:{}", proxy.host, proxy.port);
    let stream = tokio::time::timeout(timeout, TcpStream::connect(&proxy_addr))
        .await
        .map_err(|_| anyhow::anyhow!("timeout connecting to upstream proxy {}", proxy_addr))?
        .with_context(|| format!("failed to connect to upstream proxy {}", proxy_addr))?;

    configure_tcp_socket(&stream);

    let (reader, writer) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(reader);
    let mut writer = writer;

    // Step 2: Send SOCKS5 greeting
    let has_auth = proxy.username.is_some();
    let greeting = if has_auth {
        vec![SOCKS_VERSION, 2, AUTH_NONE, AUTH_PASSWORD]
    } else {
        vec![SOCKS_VERSION, 1, AUTH_NONE]
    };
    tokio::time::timeout(timeout, writer.write_all(&greeting))
        .await
        .map_err(|_| anyhow::anyhow!("timeout sending greeting to upstream proxy"))?
        .context("failed to send greeting to upstream proxy")?;

    // Step 3: Read method selection (2 bytes)
    let mut method_resp = [0u8; 2];
    tokio::time::timeout(timeout, reader.read_exact(&mut method_resp))
        .await
        .map_err(|_| anyhow::anyhow!("timeout reading method selection from upstream proxy"))?
        .context("failed to read method selection from upstream proxy")?;

    if method_resp[0] != SOCKS_VERSION {
        anyhow::bail!(
            "upstream proxy returned invalid SOCKS version: {}",
            method_resp[0]
        );
    }

    let selected_method = method_resp[1];
    if selected_method == 0xFF {
        anyhow::bail!("upstream proxy rejected all authentication methods");
    }

    // Step 4: Handle authentication if required
    if selected_method == AUTH_PASSWORD {
        let username = proxy.username.as_deref().ok_or_else(|| {
            anyhow::anyhow!("upstream proxy requires auth but no username configured")
        })?;
        let password = proxy.password.as_deref().unwrap_or("");

        // RFC 1929: VER(1) + ULEN(1) + UNAME(1-255) + PLEN(1) + PASSWD(1-255)
        let mut auth_req = Vec::with_capacity(3 + username.len() + password.len());
        auth_req.push(0x01); // subnegotiation version
        auth_req.push(username.len() as u8);
        auth_req.extend_from_slice(username.as_bytes());
        auth_req.push(password.len() as u8);
        auth_req.extend_from_slice(password.as_bytes());

        tokio::time::timeout(timeout, writer.write_all(&auth_req))
            .await
            .map_err(|_| anyhow::anyhow!("timeout sending auth to upstream proxy"))?
            .context("failed to send auth to upstream proxy")?;

        let mut auth_resp = [0u8; 2];
        tokio::time::timeout(timeout, reader.read_exact(&mut auth_resp))
            .await
            .map_err(|_| anyhow::anyhow!("timeout reading auth response from upstream proxy"))?
            .context("failed to read auth response from upstream proxy")?;

        if auth_resp[1] != 0x00 {
            anyhow::bail!(
                "upstream proxy authentication failed (status {})",
                auth_resp[1]
            );
        }
    } else if selected_method != AUTH_NONE {
        anyhow::bail!(
            "upstream proxy selected unsupported auth method: {}",
            selected_method
        );
    }

    // Step 5: Send CONNECT request with ATYP_DOMAIN (DNS resolution by upstream proxy)
    let mut connect_req = Vec::with_capacity(7 + target_host.len());
    connect_req.push(SOCKS_VERSION);
    connect_req.push(CMD_CONNECT);
    connect_req.push(0x00); // reserved
    connect_req.push(ATYP_DOMAIN);
    connect_req.push(target_host.len() as u8);
    connect_req.extend_from_slice(target_host.as_bytes());
    connect_req.extend_from_slice(&target_port.to_be_bytes());

    tokio::time::timeout(timeout, writer.write_all(&connect_req))
        .await
        .map_err(|_| anyhow::anyhow!("timeout sending CONNECT to upstream proxy"))?
        .context("failed to send CONNECT to upstream proxy")?;

    // Step 6: Read CONNECT reply
    // Header: VER(1) + REP(1) + RSV(1) + ATYP(1)
    let mut reply_header = [0u8; 4];
    tokio::time::timeout(timeout, reader.read_exact(&mut reply_header))
        .await
        .map_err(|_| anyhow::anyhow!("timeout reading CONNECT reply from upstream proxy"))?
        .context("failed to read CONNECT reply from upstream proxy")?;

    if reply_header[0] != SOCKS_VERSION {
        anyhow::bail!(
            "upstream proxy CONNECT reply has invalid version: {}",
            reply_header[0]
        );
    }

    if reply_header[1] != REPLY_SUCCESS {
        anyhow::bail!(
            "upstream proxy CONNECT failed with reply code 0x{:02X}",
            reply_header[1]
        );
    }

    // Read and discard the bind address (variable length depending on ATYP)
    match reply_header[3] {
        ATYP_IPV4 => {
            let mut buf = [0u8; 6]; // 4 IP + 2 port
            tokio::time::timeout(timeout, reader.read_exact(&mut buf))
                .await
                .map_err(|_| anyhow::anyhow!("timeout reading bind addr from upstream proxy"))?
                .context("failed to read bind address")?;
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 18]; // 16 IP + 2 port
            tokio::time::timeout(timeout, reader.read_exact(&mut buf))
                .await
                .map_err(|_| anyhow::anyhow!("timeout reading bind addr from upstream proxy"))?
                .context("failed to read bind address")?;
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            tokio::time::timeout(timeout, reader.read_exact(&mut len_buf))
                .await
                .map_err(|_| anyhow::anyhow!("timeout reading bind addr from upstream proxy"))?
                .context("failed to read bind address length")?;
            let mut buf = vec![0u8; len_buf[0] as usize + 2]; // domain + 2 port
            tokio::time::timeout(timeout, reader.read_exact(&mut buf))
                .await
                .map_err(|_| anyhow::anyhow!("timeout reading bind addr from upstream proxy"))?
                .context("failed to read bind address")?;
        }
        other => {
            anyhow::bail!(
                "upstream proxy returned unknown ATYP in bind address: {}",
                other
            );
        }
    }

    // Step 7: Reunite the split stream and return the tunnel
    let stream = reader
        .into_inner()
        .reunite(writer)
        .map_err(|_| anyhow::anyhow!("failed to reunite upstream proxy stream"))?;

    debug!(
        proxy = %proxy_addr,
        target = %format!("{}:{}", target_host, target_port),
        "SOCKS5 upstream tunnel established"
    );

    Ok(stream)
}

/// Set TCP keepalive and nodelay on a connected stream.
fn configure_tcp_socket(stream: &TcpStream) {
    use socket2::SockRef;
    let sock = SockRef::from(stream);
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(15));
    let _ = sock.set_tcp_keepalive(&ka);
    let _ = stream.set_nodelay(true);
}
