use crate::auth::user::User;
use crate::context::AppContext;
use crate::motd;
use crate::proxy::SshRelayRequest;
use crate::shell::context::ShellContext;
use crate::shell::executor::CommandExecutor;
use crate::shell::ShellSession;
use crate::ssh::session::ClientSession;
use crate::utils::generate_correlation_id;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use russh::CryptoVec;
use tokio::sync::Mutex;
use tracing::{debug, info, info_span, warn, Instrument};

/// Maximum number of shell channels per SSH connection to prevent resource exhaustion.
pub const MAX_CHANNELS_PER_CONNECTION: usize = 10;

/// Per-connection SSH handler
pub struct SshHandler {
    ctx: Arc<AppContext>,
    peer_addr: std::net::SocketAddr,
    conn_id: String,
    session_state: ClientSession,
    shells: DashMap<russh::ChannelId, Arc<Mutex<ShellSession>>>,
    total_auth_attempts: u32,
    connected_at: Instant,
}

impl SshHandler {
    pub fn new(ctx: Arc<AppContext>, peer_addr: std::net::SocketAddr) -> Self {
        let conn_id = generate_correlation_id();
        Self {
            ctx,
            peer_addr,
            conn_id,
            session_state: ClientSession::new(),
            shells: DashMap::new(),
            total_auth_attempts: 0,
            connected_at: Instant::now(),
        }
    }

    /// Check if the SSH auth timeout has been exceeded (slow-client DoS protection).
    fn is_auth_timed_out(&self) -> bool {
        if self.session_state.authenticated {
            return false;
        }
        let timeout_secs = self.ctx.config.server.ssh_auth_timeout.clamp(10, 600);
        self.connected_at.elapsed() > std::time::Duration::from_secs(timeout_secs)
    }

    /// Validate a forwarding request: check auth, user existence, forwarding
    /// permission, rate limit, source IP, and port validity.
    /// Returns Ok((Arc<User>, username, port)) on success or Ok(None) if the request should be rejected.
    async fn validate_forwarding_request(
        &self,
        host_to_connect: &str,
        port_to_connect: u32,
    ) -> Result<Option<(Arc<User>, String, u16)>, anyhow::Error> {
        if !self.session_state.authenticated {
            return Ok(None);
        }

        let username = match &self.session_state.username {
            Some(u) => u.clone(),
            None => return Ok(None),
        };

        let user = match self
            .ctx
            .auth_service
            .read()
            .await
            .user_store()
            .get(&username)
            .cloned()
        {
            Some(u) => u,
            None => return Ok(None),
        };

        if !user.allow_forwarding {
            warn!(
                conn_id = %self.conn_id,
                user = %username,
                host = %host_to_connect,
                port = port_to_connect,
                "Forwarding denied by config"
            );
            return Ok(None);
        }

        // Time-based access check
        if !user.check_time_access() {
            warn!(
                conn_id = %self.conn_id,
                user = %username,
                host = %host_to_connect,
                port = port_to_connect,
                "Forwarding denied: outside allowed access hours/days"
            );
            self.ctx
                .metrics
                .record_connection_rejected("time_access_denied");
            return Ok(None);
        }

        if !self
            .ctx
            .security
            .read()
            .await
            .check_rate_limit(&username, user.max_new_connections_per_minute)
        {
            warn!(
                conn_id = %self.conn_id,
                user = %username,
                limit = user.max_new_connections_per_minute,
                "SSH direct-tcpip rate limit exceeded (legacy)"
            );
            self.ctx.audit.log_rate_limit_exceeded_cid(
                &username,
                &self.peer_addr,
                "legacy_per_minute",
                &self.conn_id,
            );
            self.ctx.metrics.record_connection_rejected("rate_limited");
            return Ok(None);
        }

        // Multi-window rate limiting (QuotaTracker)
        if let Err(reason) = self.ctx.quota_tracker.check_connection_rate(
            &username,
            &user.rate_limits,
            &self.ctx.config.limits,
        ) {
            warn!(
                conn_id = %self.conn_id,
                user = %username,
                reason = %reason,
                "SSH direct-tcpip quota rate limit exceeded"
            );
            self.ctx.audit.log_rate_limit_exceeded_cid(
                &username,
                &self.peer_addr,
                &reason,
                &self.conn_id,
            );
            self.ctx.metrics.record_connection_rejected("rate_limited");
            return Ok(None);
        }

        // Record connection in quota tracker (checks daily/monthly quotas)
        if let Err(reason) = self
            .ctx
            .quota_tracker
            .record_connection(&username, user.quotas.as_ref())
        {
            warn!(
                conn_id = %self.conn_id,
                user = %username,
                reason = %reason,
                "SSH direct-tcpip connection quota exceeded"
            );
            self.ctx.audit.log_quota_exceeded(&username, &reason, 0, 0);
            self.ctx
                .metrics
                .record_error(crate::metrics::error_types::QUOTA_EXCEEDED);
            self.ctx
                .metrics
                .record_connection_rejected("quota_exceeded");
            return Ok(None);
        }

        // Pre-check bandwidth quotas before starting relay
        if let Err(reason) = self
            .ctx
            .quota_tracker
            .check_bandwidth_quota(&username, user.quotas.as_ref())
        {
            warn!(
                conn_id = %self.conn_id,
                user = %username,
                reason = %reason,
                "SSH direct-tcpip bandwidth quota already exhausted"
            );
            self.ctx.audit.log_quota_exceeded(&username, &reason, 0, 0);
            self.ctx
                .metrics
                .record_error(crate::metrics::error_types::QUOTA_EXCEEDED);
            self.ctx
                .metrics
                .record_connection_rejected("quota_exceeded");
            return Ok(None);
        }

        if !user.is_source_ip_allowed(&self.peer_addr.ip()) {
            warn!(
                conn_id = %self.conn_id,
                user = %username,
                ip = %self.peer_addr.ip(),
                "SSH direct-tcpip from IP not in user's allowed source_ips"
            );
            return Ok(None);
        }

        let port = match u16::try_from(port_to_connect) {
            Ok(p) => p,
            Err(_) => {
                warn!(conn_id = %self.conn_id, user = %username, port = port_to_connect, "Invalid port number");
                return Ok(None);
            }
        };

        Ok(Some((user, username, port)))
    }

    /// Record an auth failure: log, audit, metrics, ban, check max attempts
    async fn record_auth_failure(
        &mut self,
        username: &str,
        method: &str,
        attempts: u32,
    ) -> russh::server::Auth {
        warn!(
            conn_id = %self.conn_id,
            user = %username,
            ip = %self.peer_addr,
            attempt = attempts,
            method = %method,
            "Auth failed"
        );
        self.ctx
            .audit
            .log_auth_failure_cid(username, &self.peer_addr, method, &self.conn_id)
            .await;
        let metric_method = if method == "publickey" {
            "pubkey"
        } else {
            method
        };
        self.ctx.metrics.record_auth_failure(metric_method);
        self.ctx
            .metrics
            .record_error(crate::metrics::error_types::AUTH_FAILURE);
        self.ctx.metrics.record_connection_rejected("auth_failed");
        self.ctx
            .security
            .read()
            .await
            .record_auth_failure(&self.peer_addr.ip());

        if attempts >= self.ctx.config.limits.max_auth_attempts {
            return russh::server::Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            };
        }

        russh::server::Auth::Reject {
            proceed_with_methods: Some(russh::MethodSet::from(
                [russh::MethodKind::Password, russh::MethodKind::PublicKey].as_slice(),
            )),
            partial_success: false,
        }
    }
}

/// Test helper methods for inspecting SshHandler internal state.
/// These are always compiled to allow external integration/unit tests in tests/.
impl SshHandler {
    /// Test helper: get current total auth attempts
    pub fn total_auth_attempts(&self) -> u32 {
        self.total_auth_attempts
    }

    /// Test helper: increment total auth attempts (simulates auth attempt)
    pub fn increment_auth_attempts(&mut self) {
        self.total_auth_attempts += 1;
    }

    /// Test helper: get number of active shell channels
    pub fn shell_count(&self) -> usize {
        self.shells.len()
    }

    /// Test helper: check if session is authenticated
    pub fn is_authenticated(&self) -> bool {
        self.session_state.authenticated
    }

    /// Test helper: get the session username
    pub fn session_username(&self) -> Option<&str> {
        self.session_state.username.as_deref()
    }

    /// Test helper: get the auth method
    pub fn auth_method(&self) -> &str {
        &self.session_state.auth_method
    }

    /// Test helper: get the connection ID
    pub fn conn_id(&self) -> &str {
        &self.conn_id
    }

    /// Test helper: get the peer address
    pub fn peer_addr(&self) -> std::net::SocketAddr {
        self.peer_addr
    }

    /// Test helper: set session authenticated state
    pub fn set_authenticated(&mut self, username: &str, method: &str) {
        self.session_state.authenticated = true;
        self.session_state.username = Some(username.to_string());
        self.session_state.auth_method = method.to_string();
    }

    /// Test helper: set session unauthenticated
    pub fn set_unauthenticated(&mut self) {
        self.session_state.authenticated = false;
        self.session_state.username = None;
        self.session_state.auth_method = String::new();
    }

    /// Test helper: get the ssh key fingerprint
    pub fn ssh_key_fingerprint(&self) -> Option<&str> {
        self.session_state.ssh_key_fingerprint.as_deref()
    }

    /// Test helper: set the ssh key fingerprint
    pub fn set_ssh_key_fingerprint(&mut self, fp: &str) {
        self.session_state.ssh_key_fingerprint = Some(fp.to_string());
    }

    /// Test helper: check if a new channel would be accepted based on current shell count
    pub fn would_accept_new_channel(&self) -> bool {
        self.shells.len() < MAX_CHANNELS_PER_CONNECTION
    }

    /// Test helper: get access to the record_auth_failure method
    pub async fn test_record_auth_failure(
        &mut self,
        username: &str,
        method: &str,
        attempts: u32,
    ) -> russh::server::Auth {
        self.record_auth_failure(username, method, attempts).await
    }

    /// Test helper: get access to validate_forwarding_request
    pub async fn test_validate_forwarding_request(
        &self,
        host: &str,
        port: u32,
    ) -> Result<Option<(Arc<crate::auth::user::User>, String, u16)>, anyhow::Error> {
        self.validate_forwarding_request(host, port).await
    }

    /// Test helper: override the connected_at timestamp to simulate auth timeout
    pub fn set_connected_at(&mut self, instant: Instant) {
        self.connected_at = instant;
    }

    /// Test helper: check if auth is timed out
    pub fn test_is_auth_timed_out(&self) -> bool {
        self.is_auth_timed_out()
    }
}

impl russh::server::Handler for SshHandler {
    type Error = anyhow::Error;

    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        _session: &mut russh::server::Session,
    ) -> Result<bool, Self::Error> {
        if !self.session_state.authenticated {
            return Ok(false);
        }

        let username = match &self.session_state.username {
            Some(u) => u.clone(),
            None => return Ok(false),
        };

        let user = match self
            .ctx
            .auth_service
            .read()
            .await
            .user_store()
            .get(&username)
            .cloned()
        {
            Some(u) => u,
            None => return Ok(false),
        };

        if !user.allow_shell {
            warn!(conn_id = %self.conn_id, user = %username, "Shell access denied by config");
            return Ok(false);
        }

        // Enforce per-connection channel limit to prevent resource exhaustion
        if self.shells.len() >= MAX_CHANNELS_PER_CONNECTION {
            warn!(
                user = %username,
                conn_id = %self.conn_id,
                max = MAX_CHANNELS_PER_CONNECTION,
                "Max shell channels per connection exceeded"
            );
            return Ok(false);
        }

        let channel_id = channel.id();
        let mut shell = ShellSession::new(
            username.clone(),
            self.ctx.config.shell.hostname.clone(),
            channel,
        );

        // Build ShellContext from user data for extended shell commands
        let shell_ctx = ShellContext {
            username: username.clone(),
            auth_method: self.session_state.auth_method.clone(),
            source_ip: self.peer_addr.ip().to_string(),
            role: user.role,
            group: user.group.clone(),
            permissions: user.shell_permissions.clone(),
            acl: user.acl.clone(),
            colors: user.colors,
            expires_at: user.expires_at.map(|dt| dt.to_rfc3339()),
            max_bandwidth_kbps: user.max_bandwidth_kbps,
            server_start_time: self.ctx.start_time,
            bookmarks: HashMap::new(),
            aliases: user.aliases.clone(),
            ssh_key_fingerprint: self.session_state.ssh_key_fingerprint.clone(),
            proxy_engine: Some(self.ctx.proxy_engine.clone()),
            quota_tracker: Some(self.ctx.quota_tracker.clone()),
            quota_config: user.quotas.clone(),
        };
        shell.set_context(shell_ctx);

        // Render MOTD
        let (motd_enabled, motd_template, motd_colors) = motd::resolve_motd_config(
            &self.ctx.config.motd,
            user.motd_config.as_ref(),
            None, // per-shell override not supported yet
        );
        if motd_enabled {
            let template_str = motd_template.unwrap_or_else(motd::default_motd_template);
            let live_connections = self.ctx.proxy_engine.user_connections(&username);
            let live_bandwidth_used = self.ctx.quota_tracker.get_user_usage(&username).daily_bytes;
            let motd_ctx = motd::MotdContext {
                user: username.clone(),
                auth_method: self.session_state.auth_method.clone(),
                source_ip: self.peer_addr.ip().to_string(),
                connections: live_connections,
                acl_policy: match user.acl.default_policy {
                    crate::config::acl::AclPolicy::Allow => "allow".to_string(),
                    crate::config::acl::AclPolicy::Deny => "deny".to_string(),
                },
                expires_at: user.expires_at.map(|dt| dt.to_rfc3339()),
                bandwidth_used: live_bandwidth_used,
                bandwidth_limit: user.max_bandwidth_kbps * 1024 / 8, // kbps to bytes
                last_login: None,
                uptime: self.ctx.start_time.elapsed().as_secs(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                group: user.group.clone(),
                role: user.role.to_string(),
                denied: user.acl.deny_rules.iter().map(|r| r.to_string()).collect(),
            };
            let rendered = motd::render_motd(&template_str, &motd_ctx, motd_colors);
            shell.set_motd(rendered);
        }

        self.shells.insert(channel_id, Arc::new(Mutex::new(shell)));
        Ok(true)
    }

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<russh::server::Auth, Self::Error> {
        self.total_auth_attempts += 1;

        if self.is_auth_timed_out() {
            warn!(conn_id = %self.conn_id, ip = %self.peer_addr.ip(), "SSH auth timeout exceeded");
            self.ctx.metrics.record_connection_rejected("auth_timeout");
            return Ok(russh::server::Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            });
        }

        if let Err(reason) = self
            .ctx
            .security
            .read()
            .await
            .pre_auth_check(&self.peer_addr.ip())
        {
            warn!(conn_id = %self.conn_id, ip = %self.peer_addr.ip(), reason = %reason, "SSH password auth rejected");
            let metric_reason = if reason == "banned IP" {
                "banned"
            } else {
                "acl_denied"
            };
            self.ctx.metrics.record_connection_rejected(metric_reason);
            return Ok(russh::server::Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            });
        }

        // Determine if TOTP is required for SSH
        let totp_required = self
            .ctx
            .config
            .security
            .totp_required_for
            .contains(&"ssh".to_string());

        // AUTH-001: Consolidated auth reads to reduce RwLock contention
        // Single auth_service read for TOTP check, password verify, and user_has_totp flag
        let (auth_result, user_has_totp) = {
            let auth = self.ctx.auth_service.read().await;

            if totp_required {
                let has_totp = auth
                    .user_store()
                    .get(user)
                    .map(|u| u.totp_enabled && u.totp_secret.is_some())
                    .unwrap_or(false);

                if has_totp {
                    // Secure TOTP extraction with delimiter + suffix support
                    let (actual_pass, totp_code) =
                        crate::auth::password::extract_totp_from_password(password);
                    let pass_ok = auth.auth_password(user, &actual_pass);
                    let result = pass_ok
                        && match totp_code {
                            Some(code) => auth.verify_totp(user, &code),
                            None => false,
                        };
                    (result, has_totp)
                } else {
                    (auth.auth_password(user, password), false)
                }
            } else {
                (auth.auth_password(user, password), false)
            }
        };

        if auth_result {
            info!(conn_id = %self.conn_id, user = %user, ip = %self.peer_addr, "Password auth success");
            self.session_state.username = Some(user.to_string());
            self.session_state.authenticated = true;
            self.session_state.auth_method = if totp_required && user_has_totp {
                "password+totp".to_string()
            } else {
                "password".to_string()
            };
            self.ctx
                .audit
                .log_auth_success_cid(user, &self.peer_addr, "password", &self.conn_id)
                .await;
            self.ctx.audit.log_session_authenticated_cid(
                user,
                &self.peer_addr,
                "ssh",
                &self.session_state.auth_method,
                &self.conn_id,
            );
            self.ctx.metrics.record_auth_success(user, "password");
            Ok(russh::server::Auth::Accept)
        } else {
            Ok(self
                .record_auth_failure(user, "password", self.total_auth_attempts)
                .await)
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &russh::keys::PublicKey,
    ) -> Result<russh::server::Auth, Self::Error> {
        self.total_auth_attempts += 1;

        if self.is_auth_timed_out() {
            warn!(conn_id = %self.conn_id, ip = %self.peer_addr.ip(), "SSH auth timeout exceeded");
            self.ctx.metrics.record_connection_rejected("auth_timeout");
            return Ok(russh::server::Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            });
        }

        if let Err(reason) = self
            .ctx
            .security
            .read()
            .await
            .pre_auth_check(&self.peer_addr.ip())
        {
            warn!(conn_id = %self.conn_id, ip = %self.peer_addr.ip(), reason = %reason, "SSH pubkey auth rejected");
            let metric_reason = if reason == "banned IP" {
                "banned"
            } else {
                "acl_denied"
            };
            self.ctx.metrics.record_connection_rejected(metric_reason);
            return Ok(russh::server::Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            });
        }

        if self
            .ctx
            .auth_service
            .read()
            .await
            .auth_publickey(user, public_key)
        {
            info!(conn_id = %self.conn_id, user = %user, ip = %self.peer_addr, "Public key auth success");
            self.session_state.username = Some(user.to_string());
            self.session_state.authenticated = true;
            self.session_state.auth_method = "publickey".to_string();
            // Compute SSH key fingerprint (SHA256 of base64-decoded public key bytes)
            let fingerprint = {
                use base64::Engine;
                use russh::keys::PublicKeyBase64;
                use sha2::{Digest, Sha256};
                let key_b64 = public_key.public_key_base64();
                let key_bytes = base64::engine::general_purpose::STANDARD
                    .decode(&key_b64)
                    .unwrap_or_default();
                let hash = Sha256::digest(&key_bytes);
                let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(hash);
                format!("SHA256:{}", b64)
            };
            self.session_state.ssh_key_fingerprint = Some(fingerprint);
            self.ctx
                .audit
                .log_auth_success_cid(user, &self.peer_addr, "publickey", &self.conn_id)
                .await;
            self.ctx.audit.log_session_authenticated_cid(
                user,
                &self.peer_addr,
                "ssh",
                "publickey",
                &self.conn_id,
            );
            self.ctx.metrics.record_auth_success(user, "pubkey");
            Ok(russh::server::Auth::Accept)
        } else {
            Ok(self
                .record_auth_failure(user, "publickey", self.total_auth_attempts)
                .await)
        }
    }

    async fn auth_none(&mut self, user: &str) -> Result<russh::server::Auth, Self::Error> {
        self.total_auth_attempts += 1;

        if self.is_auth_timed_out() {
            warn!(conn_id = %self.conn_id, ip = %self.peer_addr.ip(), "SSH auth timeout exceeded");
            self.ctx.metrics.record_connection_rejected("auth_timeout");
            return Ok(russh::server::Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            });
        }

        // P1-1: Pre-auth ban check — reject banned IPs immediately (0 auth attempts)
        if let Err(reason) = self
            .ctx
            .security
            .read()
            .await
            .pre_auth_check(&self.peer_addr.ip())
        {
            warn!(conn_id = %self.conn_id, ip = %self.peer_addr.ip(), reason = %reason, "SSH auth_none rejected (pre-auth)");
            let metric_reason = if reason == "banned IP" {
                "banned"
            } else {
                "acl_denied"
            };
            self.ctx.metrics.record_connection_rejected(metric_reason);
            return Ok(russh::server::Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            });
        }

        info!(conn_id = %self.conn_id, user = %user, ip = %self.peer_addr, "auth_none attempt (rejected)");
        Ok(russh::server::Auth::Reject {
            proceed_with_methods: Some(russh::MethodSet::from(
                [russh::MethodKind::Password, russh::MethodKind::PublicKey].as_slice(),
            )),
            partial_success: false,
        })
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut russh::server::Session,
    ) -> Result<bool, Self::Error> {
        let (user, username, port) = match self
            .validate_forwarding_request(host_to_connect, port_to_connect)
            .await?
        {
            Some(v) => v,
            None => return Ok(false),
        };
        let host = host_to_connect.to_string();

        debug!(
            conn_id = %self.conn_id,
            user = %username,
            target = %format!("{}:{}", host, port),
            originator = %format!("{}:{}", originator_address, originator_port),
            "direct-tcpip channel open"
        );

        let proxy = self.ctx.proxy_engine.clone();
        let audit = self.ctx.audit.clone();
        let metrics = self.ctx.metrics.clone();
        let quota_tracker = self.ctx.quota_tracker.clone();
        let peer = self.peer_addr;
        let source_ip_str = peer.ip().to_string();
        let user_quotas = user.quotas.clone();
        let aggregate_bw = user.max_aggregate_bandwidth_kbps;

        // Resolve upstream proxy (user-level > global-level)
        let upstream_proxy =
            crate::proxy::ProxyEngine::resolve_upstream_proxy(&user, &self.ctx.config);

        let conn_id = self.conn_id.clone();
        let relay_span = info_span!("ssh-relay", conn_id = %conn_id, user = %username, target = %format!("{}:{}", host, port));
        tokio::spawn(
            async move {
                let start = Instant::now();
                let relay_req = SshRelayRequest {
                    username: &username,
                    host: &host,
                    port,
                    channel,
                    user_acl: &user.acl,
                    source_ip: &source_ip_str,
                    bandwidth_limit_kbps: user.max_bandwidth_kbps,
                    max_per_user: user.max_connections,
                    aggregate_bandwidth_kbps: aggregate_bw,
                    quota_tracker: Some(quota_tracker),
                    quotas: user_quotas,
                    upstream_proxy,
                };
                match proxy.connect_and_relay(relay_req).await {
                    Ok((bytes_up, bytes_down, resolved_addr)) => {
                        let duration_ms = start.elapsed().as_millis() as u64;
                        info!(
                            conn_id = %conn_id,
                            user = %username,
                            target = %format!("{}:{}", host, port),
                            resolved_ip = %resolved_addr.ip(),
                            bytes_up = bytes_up,
                            bytes_down = bytes_down,
                            duration_ms = duration_ms,
                            "Forwarding completed"
                        );
                        audit
                            .log_proxy_complete_cid(
                                &username,
                                &host,
                                port,
                                bytes_up,
                                bytes_down,
                                duration_ms,
                                &peer,
                                Some(resolved_addr.ip().to_string()),
                                &conn_id,
                            )
                            .await;
                        metrics.record_bytes_transferred(&username, bytes_up + bytes_down);
                        metrics.record_typed_connection_duration(
                            &username,
                            "ssh",
                            duration_ms as f64 / 1000.0,
                        );
                    }
                    Err(e) => {
                        let error_type = classify_relay_error(&e);
                        warn!(
                            conn_id = %conn_id,
                            user = %username,
                            target = %format!("{}:{}", host, port),
                            error = %e,
                            error_type = %error_type,
                            "Forwarding failed"
                        );
                        metrics.record_error(error_type);
                    }
                }
            }
            .instrument(relay_span),
        );

        Ok(true)
    }

    async fn data(
        &mut self,
        channel: russh::ChannelId,
        data: &[u8],
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        // H-2: Defense-in-depth - verify authentication
        if !self.session_state.authenticated {
            return Ok(());
        }

        if let Some(shell) = self.shells.get(&channel) {
            let mut shell = shell.lock().await;
            shell.handle_input(data, session, channel).await?;
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: russh::ChannelId,
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        // H-2: Defense-in-depth - verify authentication
        if !self.session_state.authenticated {
            return Ok(());
        }

        if let Some(shell) = self.shells.get(&channel) {
            let mut shell = shell.lock().await;
            // Send MOTD before the first prompt
            if let Some(motd) = shell.take_motd() {
                let _ = session.data(channel, CryptoVec::from_slice(motd.as_bytes()));
                let _ = session.data(channel, CryptoVec::from_slice(b"\r\n"));
            }
            shell.send_prompt(session, channel).await?;
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: russh::ChannelId,
        _term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        if let Some(shell) = self.shells.get(&channel) {
            let mut shell = shell.lock().await;
            shell.set_terminal_size(col_width, row_height);
        }
        let _ = session.channel_success(channel);
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: russh::ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        if let Some(shell) = self.shells.get(&channel) {
            let mut shell = shell.lock().await;
            shell.set_terminal_size(col_width, row_height);
        }
        Ok(())
    }

    /// Handle exec_request: execute the command in the virtual shell and return the result.
    /// This handles `ssh user@host "command"` style invocations.
    async fn exec_request(
        &mut self,
        channel: russh::ChannelId,
        data: &[u8],
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        // H-2: Defense-in-depth - verify authentication
        if !self.session_state.authenticated {
            let _ = session.channel_failure(channel);
            return Ok(());
        }

        // M-12: Limit exec data size to prevent abuse
        if data.len() > 4096 {
            warn!(
                user = ?self.session_state.username,
                data_len = data.len(),
                "exec_request data too large, rejecting"
            );
            let _ = session.channel_failure(channel);
            return Ok(());
        }

        let command = String::from_utf8_lossy(data).to_string();
        debug!(channel = ?channel, command = %command, "exec_request received");

        let username = match &self.session_state.username {
            Some(u) => u.clone(),
            None => {
                let _ = session.channel_failure(channel);
                return Ok(());
            }
        };

        // Execute command in the virtual shell
        let mut executor = CommandExecutor::new(username, self.ctx.config.shell.hostname.clone());
        let result = executor.execute(&command);

        if !result.output.is_empty() {
            let _ = session.data(channel, CryptoVec::from_slice(result.output.as_bytes()));
        }

        // Send exit status 0 and close channel
        let _ = session.exit_status_request(channel, 0);
        let _ = session.close(channel);
        Ok(())
    }

    /// Reject SFTP/SCP subsystem requests explicitly.
    async fn subsystem_request(
        &mut self,
        channel: russh::ChannelId,
        name: &str,
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        warn!(
            conn_id = %self.conn_id,
            subsystem = %name,
            user = ?self.session_state.username,
            ip = %self.peer_addr,
            "Subsystem denied (SFTP/SCP not allowed)"
        );
        let _ = session.channel_failure(channel);
        Ok(())
    }

    /// Reject reverse port forwarding (ssh -R).
    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        _session: &mut russh::server::Session,
    ) -> Result<bool, Self::Error> {
        warn!(
            conn_id = %self.conn_id,
            address = %address,
            port = %port,
            user = ?self.session_state.username,
            ip = %self.peer_addr,
            "Reverse forwarding denied (tcpip_forward)"
        );
        Ok(false)
    }

    /// Reject cancel of reverse port forwarding.
    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut russh::server::Session,
    ) -> Result<bool, Self::Error> {
        warn!(
            conn_id = %self.conn_id,
            address = %address,
            port = %port,
            "cancel_tcpip_forward denied"
        );
        Ok(false)
    }

    /// Reject forwarded-tcpip channel opens (remote forwarding).
    async fn channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut russh::server::Session,
    ) -> Result<bool, Self::Error> {
        warn!(
            conn_id = %self.conn_id,
            host = %host_to_connect,
            port = %port_to_connect,
            originator = %format!("{}:{}", originator_address, originator_port),
            "Forwarded-tcpip channel denied"
        );
        drop(channel);
        Ok(false)
    }
}

/// Classify a relay/forwarding error into a metric error_type label.
pub fn classify_relay_error(err: &anyhow::Error) -> &'static str {
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
