pub mod events;

use crate::webhooks::WebhookDispatcher;
use events::AuditEvent;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

const AUDIT_CHANNEL_CAPACITY: usize = 10_000;
const RECENT_EVENTS_CAPACITY: usize = 100;

/// Asynchronous audit logger
pub struct AuditLogger {
    sender: mpsc::Sender<AuditEvent>,
    dropped_count: AtomicU64,
    dropped_metric: std::sync::OnceLock<prometheus_client::metrics::counter::Counter>,
    recent_events: Arc<Mutex<VecDeque<AuditEvent>>>,
}

impl AuditLogger {
    pub fn new(
        log_path: Option<PathBuf>,
        max_size_bytes: u64,
        max_files: u32,
        webhook_dispatcher: Option<Arc<WebhookDispatcher>>,
    ) -> Self {
        let (sender, receiver) = mpsc::channel(AUDIT_CHANNEL_CAPACITY);

        tokio::spawn(audit_writer_task(
            receiver,
            log_path,
            max_size_bytes,
            max_files,
            webhook_dispatcher,
        ));

        Self {
            sender,
            dropped_count: AtomicU64::new(0),
            dropped_metric: std::sync::OnceLock::new(),
            recent_events: Arc::new(Mutex::new(VecDeque::with_capacity(RECENT_EVENTS_CAPACITY))),
        }
    }

    /// Create a no-op audit logger for testing (no tokio runtime required).
    /// Events sent to this logger are silently dropped.
    pub fn new_noop() -> Self {
        let (sender, _receiver) = mpsc::channel(1);
        Self {
            sender,
            dropped_count: AtomicU64::new(0),
            dropped_metric: std::sync::OnceLock::new(),
            recent_events: Arc::new(Mutex::new(VecDeque::with_capacity(RECENT_EVENTS_CAPACITY))),
        }
    }

    /// Wire the Prometheus counter for dropped audit events.
    pub fn set_dropped_metric(&self, counter: prometheus_client::metrics::counter::Counter) {
        let _ = self.dropped_metric.set(counter);
    }

    /// Number of audit events dropped due to channel overflow
    pub fn dropped_count(&self) -> u64 {
        self.dropped_count.load(Ordering::Relaxed)
    }

    pub async fn log_auth_success(&self, username: &str, source: &SocketAddr, method: &str) {
        let event = AuditEvent::auth_success(username, source, method);
        self.try_send(event);
    }

    pub async fn log_auth_failure(&self, username: &str, source: &SocketAddr, method: &str) {
        let event = AuditEvent::auth_failure(username, source, method);
        self.try_send(event);
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn log_proxy_complete(
        &self,
        username: &str,
        host: &str,
        port: u16,
        bytes_up: u64,
        bytes_down: u64,
        duration_ms: u64,
        source: &SocketAddr,
        resolved_ip: Option<String>,
    ) {
        let event = AuditEvent::proxy_complete(
            username,
            host,
            port,
            bytes_up,
            bytes_down,
            duration_ms,
            source,
            resolved_ip,
        );
        self.try_send(event);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn log_acl_deny(
        &self,
        username: &str,
        host: &str,
        port: u16,
        resolved_ip: Option<String>,
        source_ip: &str,
        matched_rule: Option<String>,
        reason: &str,
    ) {
        let event = AuditEvent::acl_deny(
            username,
            host,
            port,
            resolved_ip,
            source_ip,
            matched_rule,
            reason,
        );
        self.try_send(event);
    }

    pub fn log_connection_new(&self, source: &SocketAddr, protocol: &str) {
        let event = AuditEvent::connection_new(source, protocol);
        self.try_send(event);
    }

    pub fn log_connection_closed(&self, source: &SocketAddr, protocol: &str) {
        let event = AuditEvent::connection_closed(source, protocol);
        self.try_send(event);
    }

    pub fn log_config_reload(&self, users_count: usize, success: bool, error: Option<String>) {
        let event = AuditEvent::config_reload(users_count, success, error);
        self.try_send(event);
    }

    pub fn log_quota_exceeded(
        &self,
        username: &str,
        quota_type: &str,
        current_usage: u64,
        limit: u64,
    ) {
        let event = AuditEvent::quota_exceeded(username, quota_type, current_usage, limit);
        self.try_send(event);
    }

    pub fn log_session_authenticated(
        &self,
        username: &str,
        source: &SocketAddr,
        protocol: &str,
        method: &str,
    ) {
        let event = AuditEvent::session_authenticated(username, source, protocol, method);
        self.try_send(event);
    }

    pub fn log_session_ended(
        &self,
        username: &str,
        source: &SocketAddr,
        protocol: &str,
        duration_secs: u64,
        total_bytes: u64,
    ) {
        let event =
            AuditEvent::session_ended(username, source, protocol, duration_secs, total_bytes);
        self.try_send(event);
    }

    pub fn log_rate_limit_exceeded(&self, username: &str, source: &SocketAddr, limit_type: &str) {
        let event = AuditEvent::rate_limit_exceeded(username, source, limit_type);
        self.try_send(event);
    }

    pub fn log_maintenance_toggled(&self, enabled: bool, source: &str) {
        let event = AuditEvent::maintenance_toggled(enabled, source);
        self.try_send(event);
    }

    pub fn log_ban_created(&self, ip: &std::net::IpAddr, duration_secs: u64) {
        let event = AuditEvent::ban_created(ip, duration_secs);
        self.try_send(event);
    }

    pub fn log_ban_expired(&self, ip: &std::net::IpAddr) {
        let event = AuditEvent::ban_expired(ip);
        self.try_send(event);
    }

    // --- Correlation-ID-aware variants ---

    pub async fn log_auth_success_cid(
        &self,
        username: &str,
        source: &SocketAddr,
        method: &str,
        cid: &str,
    ) {
        let event = AuditEvent::auth_success_with_cid(username, source, method, cid);
        self.try_send(event);
    }

    pub async fn log_auth_failure_cid(
        &self,
        username: &str,
        source: &SocketAddr,
        method: &str,
        cid: &str,
    ) {
        let event = AuditEvent::auth_failure_with_cid(username, source, method, cid);
        self.try_send(event);
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn log_proxy_complete_cid(
        &self,
        username: &str,
        host: &str,
        port: u16,
        bytes_up: u64,
        bytes_down: u64,
        duration_ms: u64,
        source: &SocketAddr,
        resolved_ip: Option<String>,
        cid: &str,
    ) {
        let event = AuditEvent::proxy_complete_with_cid(
            username,
            host,
            port,
            bytes_up,
            bytes_down,
            duration_ms,
            source,
            resolved_ip,
            cid,
        );
        self.try_send(event);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn log_acl_deny_cid(
        &self,
        username: &str,
        host: &str,
        port: u16,
        resolved_ip: Option<String>,
        source_ip: &str,
        matched_rule: Option<String>,
        reason: &str,
        cid: &str,
    ) {
        let event = AuditEvent::acl_deny_with_cid(
            username,
            host,
            port,
            resolved_ip,
            source_ip,
            matched_rule,
            reason,
            cid,
        );
        self.try_send(event);
    }

    pub fn log_connection_new_cid(&self, source: &SocketAddr, protocol: &str, cid: &str) {
        let event = AuditEvent::connection_new_with_cid(source, protocol, cid);
        self.try_send(event);
    }

    pub fn log_connection_closed_cid(&self, source: &SocketAddr, protocol: &str, cid: &str) {
        let event = AuditEvent::connection_closed_with_cid(source, protocol, cid);
        self.try_send(event);
    }

    pub fn log_session_authenticated_cid(
        &self,
        username: &str,
        source: &SocketAddr,
        protocol: &str,
        method: &str,
        cid: &str,
    ) {
        let event =
            AuditEvent::session_authenticated_with_cid(username, source, protocol, method, cid);
        self.try_send(event);
    }

    pub fn log_rate_limit_exceeded_cid(
        &self,
        username: &str,
        source: &SocketAddr,
        limit_type: &str,
        cid: &str,
    ) {
        let event = AuditEvent::rate_limit_exceeded_with_cid(username, source, limit_type, cid);
        self.try_send(event);
    }

    pub fn log_event(&self, event: AuditEvent) {
        self.try_send(event);
    }

    /// Return the most recent audit events (up to `max`), newest last.
    pub fn get_recent_events(&self, max: usize) -> Vec<AuditEvent> {
        let buf = self.recent_events.lock().unwrap();
        let skip = buf.len().saturating_sub(max);
        buf.iter().skip(skip).cloned().collect()
    }

    fn try_send(&self, event: AuditEvent) {
        // Store a clone in the in-memory ring buffer before sending
        {
            let mut buf = self.recent_events.lock().unwrap();
            if buf.len() >= RECENT_EVENTS_CAPACITY {
                buf.pop_front();
            }
            buf.push_back(event.clone());
        }
        let is_critical = event.is_critical();

        // M-6: Critical events use reserve() with a short timeout to avoid being
        // dropped during channel pressure (e.g. brute-force floods filling the buffer
        // with connection_new/closed events).
        if is_critical {
            match self.sender.try_send(event) {
                Ok(()) => return,
                Err(mpsc::error::TrySendError::Full(event)) => {
                    // Channel full — try once more for critical events
                    match self.sender.try_reserve() {
                        Ok(permit) => {
                            permit.send(event);
                            return;
                        }
                        Err(_) => {
                            let dropped = self.dropped_count.fetch_add(1, Ordering::Relaxed) + 1;
                            if let Some(counter) = self.dropped_metric.get() {
                                counter.inc();
                            }
                            if dropped % 100 == 1 {
                                warn!(
                                    total_dropped = dropped,
                                    "Audit events being dropped due to channel overflow"
                                );
                            }
                            return;
                        }
                    }
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    let dropped = self.dropped_count.fetch_add(1, Ordering::Relaxed) + 1;
                    if let Some(counter) = self.dropped_metric.get() {
                        counter.inc();
                    }
                    if dropped % 100 == 1 {
                        warn!(
                            total_dropped = dropped,
                            "Audit events being dropped due to channel overflow"
                        );
                    }
                    return;
                }
            }
        }

        match self.sender.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                let dropped = self.dropped_count.fetch_add(1, Ordering::Relaxed) + 1;
                if let Some(counter) = self.dropped_metric.get() {
                    counter.inc();
                }
                if dropped % 100 == 1 {
                    warn!(
                        total_dropped = dropped,
                        "Audit events being dropped due to channel overflow"
                    );
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                let dropped = self.dropped_count.fetch_add(1, Ordering::Relaxed) + 1;
                if let Some(counter) = self.dropped_metric.get() {
                    counter.inc();
                }
                if dropped % 100 == 1 {
                    warn!(
                        total_dropped = dropped,
                        "Audit events being dropped due to channel overflow"
                    );
                }
            }
        }
    }
}

async fn audit_writer_task(
    mut receiver: mpsc::Receiver<AuditEvent>,
    log_path: Option<PathBuf>,
    max_size_bytes: u64,
    max_files: u32,
    webhook_dispatcher: Option<Arc<WebhookDispatcher>>,
) {
    let mut file = if let Some(path) = &log_path {
        if let Some(parent) = path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        match tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
        {
            Ok(f) => Some(f),
            Err(e) => {
                error!(path = %path.display(), error = %e, "Failed to open audit log");
                None
            }
        }
    } else {
        None
    };

    // Track current file size
    let mut current_size: u64 = if let (Some(ref path), Some(_)) = (&log_path, &file) {
        tokio::fs::metadata(path)
            .await
            .map(|m| m.len())
            .unwrap_or(0)
    } else {
        0
    };

    while let Some(event) = receiver.recv().await {
        match serde_json::to_string(&event) {
            Ok(json) => {
                debug!(event = %json, "Audit event");
                // Dispatch to webhooks (fire-and-forget)
                if let Some(ref dispatcher) = webhook_dispatcher {
                    if let Ok(data) = serde_json::to_value(&event) {
                        dispatcher.dispatch(event.event_type(), data);
                    }
                }
                if let Some(ref mut f) = file {
                    let line = format!("{}\n", json);
                    let line_bytes = line.as_bytes();
                    if let Err(e) = f.write_all(line_bytes).await {
                        error!(error = %e, "Failed to write audit log");
                        continue;
                    }
                    if let Err(e) = f.flush().await {
                        error!(error = %e, "Failed to flush audit log");
                    }
                    current_size += line_bytes.len() as u64;

                    // Check rotation
                    if max_size_bytes > 0 && current_size >= max_size_bytes {
                        if let Some(ref path) = log_path {
                            drop(file.take());
                            rotate_audit_files(path, max_files).await;
                            match tokio::fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open(path)
                                .await
                            {
                                Ok(new_file) => {
                                    file = Some(new_file);
                                    current_size = 0;
                                }
                                Err(e) => {
                                    error!(error = %e, "Failed to reopen audit log after rotation");
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to serialize audit event");
            }
        }
    }
}

/// Rotate audit log files: audit.json -> audit.json.1, audit.json.1 -> audit.json.2, etc.
async fn rotate_audit_files(path: &std::path::Path, max_files: u32) {
    // Shift existing rotated files
    for i in (1..max_files).rev() {
        let from = format!("{}.{}", path.display(), i);
        let to = format!("{}.{}", path.display(), i + 1);
        let _ = tokio::fs::rename(&from, &to).await;
    }
    // Rename current file to .1
    let rotated = format!("{}.1", path.display());
    if let Err(e) = tokio::fs::rename(path, &rotated).await {
        error!(error = %e, "Failed to rotate audit log");
    }
}
