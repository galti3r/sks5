use crate::context::AppContext;
use crate::socks::{auth as socks_auth, protocol, socks5_handshake_timeout};
use crate::utils::generate_correlation_id;
use anyhow::Result;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tracing::{debug, info, info_span, warn, Instrument};

/// Handle a single SOCKS5 connection
pub async fn handle_connection(mut stream: TcpStream, ctx: Arc<AppContext>) -> Result<()> {
    let peer_addr = stream.peer_addr()?;
    let conn_id = generate_correlation_id();
    let span = info_span!("socks5", conn_id = %conn_id, peer = %peer_addr.ip());
    async {
        debug!(conn_id = %conn_id, peer = %peer_addr, "New SOCKS5 connection");
        ctx.audit
            .log_connection_new_cid(&peer_addr, "socks5", &conn_id);

        // H-7: Timeout only covers handshake phase, not relay
        let handshake_timeout = socks5_handshake_timeout(&ctx.config);
        let handshake_result = tokio::time::timeout(
            handshake_timeout,
            socks5_handshake(&mut stream, &ctx, &peer_addr, &conn_id),
        )
        .await;

        match handshake_result {
            Ok(Ok(Some(relay_info))) => {
                // Register session for tracking
                let session = ctx.proxy_engine.register_session(
                    &relay_info.username,
                    &relay_info.host,
                    relay_info.port,
                    &peer_addr.ip().to_string(),
                    "socks5",
                );
                // Relay phase - uses its own idle timeout, no handshake timeout
                let relay_cfg = relay_info.to_relay_config(
                    ctx.config.limits.idle_timeout,
                    ctx.quota_tracker.clone(),
                    Some(ctx.audit.clone()),
                    Some(session.clone()),
                );
                let rlog = relay_info.log_info();
                let relay_start = Instant::now();
                let (bytes_up, bytes_down) =
                    crate::proxy::forwarder::relay(stream, relay_info.target_stream, relay_cfg)
                        .await?;
                let duration_ms = relay_start.elapsed().as_millis() as u64;

                // Unregister session after relay completes
                ctx.proxy_engine.unregister_session(&session.session_id);

                log_relay_complete(
                    &rlog,
                    bytes_up,
                    bytes_down,
                    duration_ms,
                    &peer_addr,
                    &ctx,
                    "SOCKS5",
                    &conn_id,
                )
                .await;
            }
            Ok(Ok(None)) => {
                // Handshake completed but no relay needed (auth failure, rejection, etc.)
            }
            Ok(Err(e)) => {
                return Err(e);
            }
            Err(_) => {
                warn!(conn_id = %conn_id, peer = %peer_addr, "SOCKS5 handshake timeout");
            }
        }

        ctx.audit
            .log_connection_closed_cid(&peer_addr, "socks5", &conn_id);
        Ok(())
    }
    .instrument(span)
    .await
}

struct RelayInfo {
    target_stream: TcpStream,
    resolved_addr: std::net::SocketAddr,
    username: String,
    host: String,
    port: u16,
    bandwidth_limit_kbps: u64,
    aggregate_bandwidth_kbps: u64,
    quotas: Option<crate::config::types::QuotaConfig>,
    _guard: crate::proxy::ConnectionGuard,
}

impl RelayInfo {
    fn to_relay_config(
        &self,
        idle_timeout_secs: u64,
        qt: Arc<crate::quota::QuotaTracker>,
        audit: Option<Arc<crate::audit::AuditLogger>>,
        session: Option<std::sync::Arc<crate::proxy::LiveSession>>,
    ) -> crate::proxy::forwarder::RelayConfig {
        crate::proxy::forwarder::RelayConfig {
            idle_timeout: Duration::from_secs(idle_timeout_secs),
            context: format!("{}@{}:{}", self.username, self.host, self.port),
            per_conn_bandwidth_kbps: self.bandwidth_limit_kbps,
            aggregate_bandwidth_kbps: self.aggregate_bandwidth_kbps,
            quota_tracker: Some(qt),
            username: Some(self.username.clone()),
            quotas: self.quotas.clone(),
            audit,
            session,
        }
    }
}

/// Fields needed for post-relay logging, extracted before the relay consumes the stream.
struct RelayLogInfo {
    username: String,
    host: String,
    port: u16,
    resolved_addr: std::net::SocketAddr,
}

impl RelayInfo {
    fn log_info(&self) -> RelayLogInfo {
        RelayLogInfo {
            username: self.username.clone(),
            host: self.host.clone(),
            port: self.port,
            resolved_addr: self.resolved_addr,
        }
    }
}

/// Log relay completion: info log + audit + metrics
#[allow(clippy::too_many_arguments)]
async fn log_relay_complete(
    info: &RelayLogInfo,
    bytes_up: u64,
    bytes_down: u64,
    duration_ms: u64,
    peer_addr: &std::net::SocketAddr,
    ctx: &AppContext,
    protocol_label: &str,
    conn_id: &str,
) {
    tracing::info!(
        conn_id = %conn_id,
        user = %info.username,
        target = %format!("{}:{}", info.host, info.port),
        resolved_ip = %info.resolved_addr.ip(),
        bytes_up = bytes_up,
        bytes_down = bytes_down,
        duration_ms = duration_ms,
        "{} relay completed", protocol_label
    );
    ctx.audit
        .log_proxy_complete_cid(
            &info.username,
            &info.host,
            info.port,
            bytes_up,
            bytes_down,
            duration_ms,
            peer_addr,
            Some(info.resolved_addr.ip().to_string()),
            conn_id,
        )
        .await;
    ctx.metrics
        .record_bytes_transferred(&info.username, bytes_up + bytes_down);
    ctx.metrics.record_typed_connection_duration(
        &info.username,
        "socks5",
        duration_ms as f64 / 1000.0,
    );
}

/// P3-1: Handle a TLS-wrapped SOCKS5 connection.
/// The TLS handshake has already been performed by the TLS acceptor.
pub async fn handle_tls_connection(
    tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
    ctx: Arc<AppContext>,
) -> Result<()> {
    let (io, _) = tls_stream.get_ref();
    let peer_addr = io.peer_addr()?;
    let conn_id = generate_correlation_id();
    let span = info_span!("socks5-tls", conn_id = %conn_id, peer = %peer_addr.ip());
    async {
        debug!(conn_id = %conn_id, peer = %peer_addr, "New SOCKS5 TLS connection");
        ctx.audit
            .log_connection_new_cid(&peer_addr, "socks5-tls", &conn_id);

        let handshake_timeout = socks5_handshake_timeout(&ctx.config);

        // Split TLS stream for handshake
        let (read_half, write_half) = tokio::io::split(tls_stream);
        let mut rw = tokio::io::join(read_half, write_half);

        let handshake_result = tokio::time::timeout(
            handshake_timeout,
            socks5_handshake(&mut rw, &ctx, &peer_addr, &conn_id),
        )
        .await;

        match handshake_result {
            Ok(Ok(Some(relay_info))) => {
                // Register session for tracking
                let session = ctx.proxy_engine.register_session(
                    &relay_info.username,
                    &relay_info.host,
                    relay_info.port,
                    &peer_addr.ip().to_string(),
                    "socks5-tls",
                );
                let relay_cfg = relay_info.to_relay_config(
                    ctx.config.limits.idle_timeout,
                    ctx.quota_tracker.clone(),
                    Some(ctx.audit.clone()),
                    Some(session.clone()),
                );
                let rlog = relay_info.log_info();
                let relay_start = Instant::now();
                let (bytes_up, bytes_down) =
                    crate::proxy::forwarder::relay(rw, relay_info.target_stream, relay_cfg).await?;
                let duration_ms = relay_start.elapsed().as_millis() as u64;

                // Unregister session after relay completes
                ctx.proxy_engine.unregister_session(&session.session_id);

                log_relay_complete(
                    &rlog,
                    bytes_up,
                    bytes_down,
                    duration_ms,
                    &peer_addr,
                    &ctx,
                    "SOCKS5 TLS",
                    &conn_id,
                )
                .await;
            }
            Ok(Ok(None)) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                warn!(conn_id = %conn_id, peer = %peer_addr, "SOCKS5 TLS handshake timeout");
            }
        }

        ctx.audit
            .log_connection_closed_cid(&peer_addr, "socks5-tls", &conn_id);
        Ok(())
    }
    .instrument(span)
    .await
}

/// Perform SOCKS5 handshake (greeting, auth, CONNECT). Returns relay info if successful.
/// Works with any AsyncRead + AsyncWrite stream (TcpStream, TLS, etc.)
async fn socks5_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    ctx: &Arc<AppContext>,
    peer_addr: &std::net::SocketAddr,
    conn_id: &str,
) -> Result<Option<RelayInfo>> {
    // Phase 1 (pre-auth): Single security read for ban check and pre-auth rate limit
    if let Err(reason) = ctx.security.read().await.pre_auth_check(&peer_addr.ip()) {
        warn!(conn_id = %conn_id, ip = %peer_addr.ip(), reason = %reason, "SOCKS5 connection rejected");
        let metric_reason = if reason == "banned IP" {
            let _ = protocol::read_greeting(stream).await;
            let _ = protocol::send_method_selection(stream, protocol::AUTH_NO_ACCEPTABLE).await;
            "banned"
        } else if reason.contains("rate") {
            "rate_limited"
        } else {
            "acl_denied"
        };
        ctx.metrics.record_connection_rejected(metric_reason);
        return Ok(None);
    }

    let methods = protocol::read_greeting(stream).await?;

    if !methods.contains(&protocol::AUTH_PASSWORD) {
        protocol::send_method_selection(stream, protocol::AUTH_NO_ACCEPTABLE).await?;
        return Ok(None);
    }

    protocol::send_method_selection(stream, protocol::AUTH_PASSWORD).await?;

    let creds = socks_auth::read_credentials(stream).await?;

    let totp_required = ctx
        .config
        .security
        .totp_required_for
        .contains(&"socks5".to_string());

    // Phase 2 (post-auth): Single auth_service read for TOTP check, password verify, and user lookup
    let (password_ok, totp_ok, totp_code, user_opt) = {
        let auth = ctx.auth_service.read().await;

        // AUTH-001: Determine TOTP extraction based on user config
        let (actual_password, totp_code) = if totp_required {
            let user_has_totp = auth
                .user_store()
                .get(&creds.username)
                .map(|u| u.totp_enabled && u.totp_secret.is_some())
                .unwrap_or(false);

            if user_has_totp {
                extract_totp_from_password(&creds.password)
            } else {
                (creds.password.to_string(), None)
            }
        } else {
            (creds.password.to_string(), None)
        };

        let pass_ok = auth.auth_password(&creds.username, &actual_password);
        let t_ok = if pass_ok {
            match &totp_code {
                Some(code) => auth.verify_totp(&creds.username, code),
                None => true,
            }
        } else {
            false
        };
        let user = auth.user_store().get(&creds.username).cloned();
        (pass_ok, t_ok, totp_code, user)
    };

    if !password_ok || !totp_ok {
        let audit_method = if totp_code.is_some() && password_ok {
            "socks5+totp"
        } else {
            "socks5"
        };
        let metric_method = if totp_code.is_some() && password_ok {
            "totp"
        } else {
            "password"
        };
        warn!(conn_id = %conn_id, user = %creds.username, ip = %peer_addr, "SOCKS5 auth failed");
        socks_auth::send_auth_result(stream, false).await?;
        // Consolidated security read: record auth failure
        {
            let sec = ctx.security.read().await;
            sec.record_auth_failure(&peer_addr.ip());
        }
        ctx.audit
            .log_auth_failure_cid(&creds.username, peer_addr, audit_method, conn_id)
            .await;
        ctx.metrics.record_auth_failure(metric_method);
        ctx.metrics
            .record_error(crate::metrics::error_types::AUTH_FAILURE);
        ctx.metrics.record_connection_rejected("auth_failed");
        return Ok(None);
    }

    socks_auth::send_auth_result(stream, true).await?;
    info!(conn_id = %conn_id, user = %creds.username, ip = %peer_addr, "SOCKS5 auth success");
    ctx.audit
        .log_auth_success_cid(&creds.username, peer_addr, "socks5", conn_id)
        .await;
    let socks5_method = if totp_required && totp_code.is_some() {
        "password+totp"
    } else {
        "password"
    };
    ctx.audit.log_session_authenticated_cid(
        &creds.username,
        peer_addr,
        "socks5",
        socks5_method,
        conn_id,
    );
    ctx.metrics
        .record_auth_success(&creds.username, socks5_method);

    // User was already fetched in Phase 2 auth read — no additional lock acquisition
    let user = user_opt.ok_or_else(|| anyhow::anyhow!("user disappeared after auth"))?;

    if !user.is_source_ip_allowed(&peer_addr.ip()) {
        warn!(conn_id = %conn_id, user = %creds.username, ip = %peer_addr.ip(), "SOCKS5 connection from IP not in user's allowed source_ips");
        return Ok(None);
    }

    // Time-based access check
    if !user.check_time_access() {
        warn!(conn_id = %conn_id, user = %creds.username, ip = %peer_addr.ip(), "SOCKS5 connection denied: outside allowed access hours/days");
        ctx.metrics.record_connection_rejected("time_access_denied");
        return Ok(None);
    }

    // Post-auth rate limit check (security read)
    if !ctx
        .security
        .read()
        .await
        .check_rate_limit(&creds.username, user.max_new_connections_per_minute)
    {
        warn!(conn_id = %conn_id, user = %creds.username, limit = user.max_new_connections_per_minute, "SOCKS5 rate limit exceeded (legacy)");
        ctx.audit.log_rate_limit_exceeded_cid(
            &creds.username,
            peer_addr,
            "legacy_per_minute",
            conn_id,
        );
        ctx.metrics.record_connection_rejected("rate_limited");
        return Ok(None);
    }

    // Multi-window rate limiting (QuotaTracker)
    if let Err(reason) = ctx.quota_tracker.check_connection_rate(
        &creds.username,
        &user.rate_limits,
        &ctx.config.limits,
    ) {
        warn!(conn_id = %conn_id, user = %creds.username, reason = %reason, "SOCKS5 quota rate limit exceeded");
        ctx.audit
            .log_rate_limit_exceeded_cid(&creds.username, peer_addr, &reason, conn_id);
        ctx.metrics.record_connection_rejected("rate_limited");
        return Ok(None);
    }

    // Record connection in quota tracker (checks daily/monthly quotas)
    if let Err(reason) = ctx
        .quota_tracker
        .record_connection(&creds.username, user.quotas.as_ref())
    {
        warn!(conn_id = %conn_id, user = %creds.username, reason = %reason, "SOCKS5 connection quota exceeded");
        ctx.audit.log_quota_exceeded(&creds.username, &reason, 0, 0);
        ctx.metrics
            .record_error(crate::metrics::error_types::QUOTA_EXCEEDED);
        ctx.metrics.record_connection_rejected("quota_exceeded");
        return Ok(None);
    }

    // Pre-check bandwidth quotas before starting relay
    if let Err(reason) = ctx
        .quota_tracker
        .check_bandwidth_quota(&creds.username, user.quotas.as_ref())
    {
        warn!(conn_id = %conn_id, user = %creds.username, reason = %reason, "SOCKS5 bandwidth quota already exhausted");
        ctx.audit.log_quota_exceeded(&creds.username, &reason, 0, 0);
        ctx.metrics
            .record_error(crate::metrics::error_types::QUOTA_EXCEEDED);
        ctx.metrics.record_connection_rejected("quota_exceeded");
        return Ok(None);
    }

    if !user.allow_forwarding {
        warn!(conn_id = %conn_id, user = %creds.username, "SOCKS5 forwarding denied");
        return Ok(None);
    }

    let target = protocol::read_connect_request(stream).await?;
    let host = target.host_string();
    let port = target.port();

    debug!(conn_id = %conn_id, user = %creds.username, target = %format!("{}:{}", host, port), "SOCKS5 CONNECT request");

    let source_ip_str = peer_addr.ip().to_string();

    // Resolve upstream proxy (user-level > global-level)
    let upstream_proxy = crate::proxy::ProxyEngine::resolve_upstream_proxy(&user, &ctx.config);

    match ctx
        .proxy_engine
        .connect_for_socks(
            &creds.username,
            &host,
            port,
            &user.acl,
            &source_ip_str,
            user.max_connections,
            upstream_proxy.as_ref(),
        )
        .await
    {
        Ok((target_stream, resolved_addr, guard)) => {
            let bind_addr = match resolved_addr {
                std::net::SocketAddr::V4(a) => {
                    protocol::TargetAddr::Ipv4(a.ip().octets(), a.port())
                }
                std::net::SocketAddr::V6(a) => {
                    protocol::TargetAddr::Ipv6(a.ip().octets(), a.port())
                }
            };
            protocol::send_reply(stream, protocol::REPLY_SUCCESS, &bind_addr).await?;

            Ok(Some(RelayInfo {
                target_stream,
                resolved_addr,
                username: creds.username,
                host,
                port,
                bandwidth_limit_kbps: user.max_bandwidth_kbps,
                aggregate_bandwidth_kbps: user.max_aggregate_bandwidth_kbps,
                quotas: user.quotas.clone(),
                _guard: guard,
            }))
        }
        Err(e) => {
            let error_type = classify_connect_error(&e);
            warn!(conn_id = %conn_id, user = %creds.username, target = %format!("{}:{}", host, port), error = %e, error_type = %error_type, "SOCKS5 connect failed");
            ctx.metrics.record_error(error_type);
            let reply_code = classify_error_reply(&e);
            protocol::send_reply(stream, reply_code, &protocol::TargetAddr::Ipv4([0; 4], 0))
                .await?;
            Ok(None)
        }
    }
}

// Re-export for backward compatibility (used by tests and other modules)
pub use crate::auth::password::extract_totp_from_password;

/// Classify a connect/proxy error into a metric error_type label.
fn classify_connect_error(err: &anyhow::Error) -> &'static str {
    use crate::metrics::error_types;
    let msg = err.to_string();
    if msg.contains("ACL denied") {
        error_types::ACL_DENIED
    } else if msg.contains("connection limit") {
        error_types::CONNECTION_REFUSED
    } else if msg.contains("DNS") || msg.contains("dns") || msg.contains("lookup") {
        error_types::DNS_FAILURE
    } else if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
        match io_err.kind() {
            std::io::ErrorKind::ConnectionRefused => error_types::CONNECTION_REFUSED,
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted => {
                error_types::RELAY_ERROR
            }
            std::io::ErrorKind::TimedOut => error_types::CONNECTION_TIMEOUT,
            _ => error_types::RELAY_ERROR,
        }
    } else {
        error_types::RELAY_ERROR
    }
}

/// Map proxy errors to specific SOCKS5 reply codes per RFC 1928
fn classify_error_reply(err: &anyhow::Error) -> u8 {
    let msg = err.to_string();
    if msg.contains("ACL denied") || msg.contains("connection limit") {
        protocol::REPLY_NOT_ALLOWED
    } else if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
        match io_err.kind() {
            std::io::ErrorKind::ConnectionRefused => protocol::REPLY_CONNECTION_REFUSED,
            std::io::ErrorKind::PermissionDenied => protocol::REPLY_NOT_ALLOWED,
            _ => protocol::REPLY_HOST_UNREACHABLE,
        }
    } else {
        protocol::REPLY_GENERAL_FAILURE
    }
}
