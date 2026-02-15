pub mod acl;
pub mod connector;
pub mod dns_cache;
pub mod forwarder;
pub mod ip_guard;
pub mod pool;
pub mod retry;

use crate::audit::AuditLogger;
use crate::auth::user::User;
use crate::config::acl::ParsedAcl;
use crate::config::types::{AppConfig, ParsedUpstreamProxy, QuotaConfig};
use crate::metrics::MetricsRegistry;
use crate::quota::QuotaTracker;
use anyhow::Result;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::atomic::{
    AtomicU32, AtomicU64,
    Ordering::{self, AcqRel, Acquire},
};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Serializable snapshot of an active session (for API responses).
#[derive(Debug, Clone, Serialize)]
pub struct SessionSnapshot {
    pub session_id: String,
    pub username: String,
    pub target_host: String,
    pub target_port: u16,
    pub source_ip: String,
    pub started_at: DateTime<Utc>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub protocol: String,
}

/// Live session state tracked at runtime with atomic byte counters.
pub struct LiveSession {
    pub session_id: String,
    pub username: String,
    pub target_host: String,
    pub target_port: u16,
    pub source_ip: String,
    pub started_at: DateTime<Utc>,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub protocol: String,
}

impl LiveSession {
    /// Create a serializable snapshot of the current session state.
    pub fn snapshot(&self) -> SessionSnapshot {
        SessionSnapshot {
            session_id: self.session_id.clone(),
            username: self.username.clone(),
            target_host: self.target_host.clone(),
            target_port: self.target_port,
            source_ip: self.source_ip.clone(),
            started_at: self.started_at,
            bytes_up: self.bytes_up.load(Ordering::Relaxed),
            bytes_down: self.bytes_down.load(Ordering::Relaxed),
            protocol: self.protocol.clone(),
        }
    }
}

/// RAII guard for connection counting
pub struct ConnectionGuard {
    global_counter: Arc<AtomicU32>,
    user_counters: Arc<DashMap<String, AtomicU32>>,
    username: String,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.global_counter.fetch_sub(1, Ordering::Relaxed);
        if let Some(counter) = self.user_counters.get(&self.username) {
            let prev = counter.fetch_sub(1, Ordering::AcqRel);
            drop(counter);
            // Clean up the DashMap entry if this was the last connection
            if prev == 1 {
                self.user_counters
                    .remove_if(&self.username, |_, c| c.load(Ordering::Acquire) == 0);
            }
        }
    }
}

/// Parameters for an SSH relay request, grouping user-specific settings
/// that would otherwise require many individual function arguments.
pub struct SshRelayRequest<'a> {
    /// Username of the connected user.
    pub username: &'a str,
    /// Target hostname.
    pub host: &'a str,
    /// Target port.
    pub port: u16,
    /// SSH channel to relay through.
    pub channel: russh::Channel<russh::server::Msg>,
    /// Parsed ACL rules for this user.
    pub user_acl: &'a ParsedAcl,
    /// Source IP address of the client.
    pub source_ip: &'a str,
    /// Per-connection bandwidth limit in kbps (0 = unlimited).
    pub bandwidth_limit_kbps: u64,
    /// Maximum concurrent connections for this user (0 = unlimited).
    pub max_per_user: u32,
    /// Aggregate bandwidth limit across all connections in kbps (0 = unlimited).
    pub aggregate_bandwidth_kbps: u64,
    /// Optional quota tracker for bandwidth/connection accounting.
    pub quota_tracker: Option<Arc<QuotaTracker>>,
    /// Optional per-user quota configuration.
    pub quotas: Option<QuotaConfig>,
    /// Optional upstream SOCKS5 proxy for chaining.
    pub upstream_proxy: Option<ParsedUpstreamProxy>,
}

/// Shared proxy engine - used by both SSH direct-tcpip and SOCKS5
pub struct ProxyEngine {
    config: Arc<AppConfig>,
    audit: Arc<AuditLogger>,
    metrics: Option<Arc<MetricsRegistry>>,
    global_connections: Arc<AtomicU32>,
    user_connections: Arc<DashMap<String, AtomicU32>>,
    dns_cache: dns_cache::DnsCache,
    active_sessions: DashMap<String, Arc<LiveSession>>,
    session_counter: AtomicU64,
}

impl ProxyEngine {
    pub fn new(config: Arc<AppConfig>, audit: Arc<AuditLogger>) -> Self {
        let dns_cache = dns_cache::DnsCache::new(
            config.server.dns_cache_ttl,
            config.server.dns_cache_max_entries,
        );
        Self {
            config,
            audit,
            metrics: None,
            global_connections: Arc::new(AtomicU32::new(0)),
            user_connections: Arc::new(DashMap::new()),
            dns_cache,
            active_sessions: DashMap::new(),
            session_counter: AtomicU64::new(0),
        }
    }

    /// Set the metrics registry reference for lifetime connection counting.
    pub fn set_metrics(&mut self, metrics: Arc<MetricsRegistry>) {
        self.metrics = Some(metrics);
    }

    /// Try to acquire a connection slot. Returns a guard that auto-decrements on drop.
    /// `max_per_user` overrides the global `limits.max_connections_per_user` for this user.
    /// A value of 0 means unlimited (no per-user cap).
    pub fn acquire_connection(&self, username: &str, max_per_user: u32) -> Result<ConnectionGuard> {
        let max_global = self.config.limits.max_connections;
        self.global_connections
            .fetch_update(AcqRel, Acquire, |c| {
                if c >= max_global {
                    None
                } else {
                    Some(c + 1)
                }
            })
            .map_err(|_| anyhow::anyhow!("global connection limit reached"))?;

        // 0 = unlimited per-user connections
        if max_per_user > 0 {
            let user_entry = self
                .user_connections
                .entry(username.to_string())
                .or_insert_with(|| AtomicU32::new(0));
            if user_entry
                .fetch_update(AcqRel, Acquire, |c| {
                    if c >= max_per_user {
                        None
                    } else {
                        Some(c + 1)
                    }
                })
                .is_err()
            {
                self.global_connections.fetch_sub(1, Ordering::Relaxed);
                anyhow::bail!("per-user connection limit reached for '{}'", username);
            }
        } else {
            // Unlimited: still track the count but don't enforce
            let user_entry = self
                .user_connections
                .entry(username.to_string())
                .or_insert_with(|| AtomicU32::new(0));
            user_entry.fetch_add(1, Ordering::AcqRel);
        }

        Ok(ConnectionGuard {
            global_counter: self.global_connections.clone(),
            user_counters: self.user_connections.clone(),
            username: username.to_string(),
        })
    }

    /// Resolve which upstream proxy (if any) to use for a connection.
    /// Priority: user-level > global-level. Returns None for direct connection.
    pub fn resolve_upstream_proxy(
        user: &User,
        global_config: &AppConfig,
    ) -> Option<ParsedUpstreamProxy> {
        // User-level upstream proxy takes priority
        let url = user.upstream_proxy.as_deref().or_else(|| {
            global_config
                .upstream_proxy
                .as_ref()
                .map(|u| u.url.as_str())
        });

        let url = url?;

        match ParsedUpstreamProxy::from_url(url) {
            Ok(parsed) => Some(parsed),
            Err(e) => {
                warn!(
                    user = %user.username,
                    url = %url,
                    error = %e,
                    "Invalid upstream proxy URL, falling back to direct connection"
                );
                None
            }
        }
    }

    /// Internal: ACL pre-check + acquire connection + connect + ACL post-check.
    /// Returns (TcpStream, resolved_addr, ConnectionGuard).
    ///
    /// When `upstream_proxy` is `Some`, the connection is established through the
    /// upstream SOCKS5 proxy. In that case the ACL post-check (CIDR by resolved IP)
    /// is skipped because DNS resolution happens on the upstream proxy side.
    #[allow(clippy::too_many_arguments)]
    async fn connect_checked(
        &self,
        username: &str,
        host: &str,
        port: u16,
        user_acl: &ParsedAcl,
        source_ip: &str,
        max_per_user: u32,
        upstream_proxy: Option<&ParsedUpstreamProxy>,
    ) -> Result<(tokio::net::TcpStream, SocketAddr, ConnectionGuard)> {
        // Pre-check ACL with hostname only (before connect, prevents port scanning)
        let pre_decision = acl::pre_check_hostname_and_log(user_acl, username, host, port);
        if !pre_decision.allowed {
            self.audit.log_acl_deny(
                username,
                host,
                port,
                None,
                source_ip,
                pre_decision.matched_rule,
                "hostname pre-check",
            );
            anyhow::bail!("ACL denied: {}:{}", host, port);
        }

        // Acquire connection slot (RAII)
        let guard = self.acquire_connection(username, max_per_user)?;

        if let Some(proxy) = upstream_proxy {
            // Connect via upstream SOCKS5 proxy — DNS resolution delegated to proxy
            let timeout = Duration::from_secs(self.config.limits.connection_timeout);
            let tcp_stream = connector::connect_via_socks5(proxy, host, port, timeout).await?;

            // Use sentinel address for logs/metrics (real IP unknown when proxied)
            let sentinel_addr: SocketAddr = ([0, 0, 0, 0], 0).into();

            // Skip ACL post-check (CIDR): we don't know the resolved IP
            info!(
                user = %username,
                target = %format!("{}:{}", host, port),
                via_proxy = %proxy.display_addr(),
                "Connected via upstream proxy"
            );

            Ok((tcp_stream, sentinel_addr, guard))
        } else {
            // Direct connection (existing path)
            let ip_guard_enabled = self.config.security.ip_guard_enabled;
            let (tcp_stream, resolved_addr) = connector::connect_with_cache(
                host,
                port,
                self.config.limits.connection_timeout,
                ip_guard_enabled,
                &self.dns_cache,
                self.metrics.as_deref(),
            )
            .await?;

            // Post-check ACL with resolved IP (for CIDR rules)
            let post_decision =
                acl::check_and_log(user_acl, username, host, port, Some(resolved_addr.ip()));
            if !post_decision.allowed {
                self.audit.log_acl_deny(
                    username,
                    host,
                    port,
                    Some(resolved_addr.ip().to_string()),
                    source_ip,
                    post_decision.matched_rule,
                    "post-check",
                );
                anyhow::bail!("ACL denied: {}:{}", host, port);
            }

            Ok((tcp_stream, resolved_addr, guard))
        }
    }

    /// Connect to a target and relay data through an SSH channel.
    /// Returns (bytes_up, bytes_down, resolved_addr).
    pub async fn connect_and_relay(
        &self,
        req: SshRelayRequest<'_>,
    ) -> Result<(u64, u64, SocketAddr)> {
        let (tcp_stream, resolved_addr, _guard) = self
            .connect_checked(
                req.username,
                req.host,
                req.port,
                req.user_acl,
                req.source_ip,
                req.max_per_user,
                req.upstream_proxy.as_ref(),
            )
            .await?;

        // Register the live session for tracking
        let session = self.register_session(req.username, req.host, req.port, req.source_ip, "ssh");

        info!(
            user = %req.username,
            target = %format!("{}:{}", req.host, req.port),
            resolved_ip = %resolved_addr.ip(),
            session_id = %session.session_id,
            "Relay started"
        );

        // Convert SSH channel to stream and relay
        let channel_stream = req.channel.into_stream();
        let relay_cfg = forwarder::RelayConfig {
            idle_timeout: Duration::from_secs(self.config.limits.idle_timeout),
            context: format!("{}@{}:{}", req.username, req.host, req.port),
            per_conn_bandwidth_kbps: req.bandwidth_limit_kbps,
            aggregate_bandwidth_kbps: req.aggregate_bandwidth_kbps,
            quota_tracker: req.quota_tracker,
            username: Some(req.username.to_string()),
            quotas: req.quotas,
            audit: Some(self.audit.clone()),
            session: Some(session.clone()),
        };
        let (bytes_up, bytes_down) =
            forwarder::relay(channel_stream, tcp_stream, relay_cfg).await?;

        // Unregister the session after relay completes
        self.unregister_session(&session.session_id);

        Ok((bytes_up, bytes_down, resolved_addr))
    }

    /// Connect to a target for SOCKS5 (returns the TCP stream directly).
    /// ACL check is performed before and after connecting.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_for_socks(
        &self,
        username: &str,
        host: &str,
        port: u16,
        user_acl: &ParsedAcl,
        source_ip: &str,
        max_per_user: u32,
        upstream_proxy: Option<&ParsedUpstreamProxy>,
    ) -> Result<(tokio::net::TcpStream, std::net::SocketAddr, ConnectionGuard)> {
        self.connect_checked(
            username,
            host,
            port,
            user_acl,
            source_ip,
            max_per_user,
            upstream_proxy,
        )
        .await
    }

    pub fn active_connections(&self) -> u32 {
        self.global_connections.load(Ordering::Relaxed)
    }

    pub fn user_connections(&self, username: &str) -> u32 {
        self.user_connections
            .get(username)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// P2-2: Return per-user connection counts for shutdown drain logging.
    pub fn active_connection_details(&self) -> Vec<(String, u32)> {
        self.user_connections
            .iter()
            .map(|entry| {
                let count = entry.value().load(Ordering::Relaxed);
                (entry.key().clone(), count)
            })
            .filter(|(_, count)| *count > 0)
            .collect()
    }

    /// Register a new live session and return its ID + Arc.
    /// Also increments the lifetime `connections_total` counter if metrics are set.
    pub fn register_session(
        &self,
        username: &str,
        target_host: &str,
        target_port: u16,
        source_ip: &str,
        protocol: &str,
    ) -> Arc<LiveSession> {
        let id = self.session_counter.fetch_add(1, Ordering::Relaxed);
        let session_id = format!("s{}", id);
        let session = Arc::new(LiveSession {
            session_id: session_id.clone(),
            username: username.to_string(),
            target_host: target_host.to_string(),
            target_port,
            source_ip: source_ip.to_string(),
            started_at: Utc::now(),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            protocol: protocol.to_string(),
        });
        self.active_sessions.insert(session_id, session.clone());

        // Increment lifetime connection counter
        if let Some(ref metrics) = self.metrics {
            metrics.connections_total.inc();
        }

        session
    }

    /// Unregister a session by ID.
    pub fn unregister_session(&self, session_id: &str) {
        self.active_sessions.remove(session_id);
    }

    /// Get snapshots of all active sessions.
    pub fn get_sessions(&self) -> Vec<SessionSnapshot> {
        self.active_sessions
            .iter()
            .map(|e| e.value().snapshot())
            .collect()
    }

    /// Get snapshots of sessions for a specific user.
    pub fn get_user_sessions(&self, username: &str) -> Vec<SessionSnapshot> {
        self.active_sessions
            .iter()
            .filter(|e| e.value().username == username)
            .map(|e| e.value().snapshot())
            .collect()
    }
}
