use std::collections::HashMap;
use std::sync::Arc;

use crate::config::acl::ParsedAcl;
use crate::config::types::{QuotaConfig, ShellPermissions, UserRole};
use crate::proxy::ProxyEngine;
use crate::quota::QuotaTracker;

/// Runtime context for shell commands (read-only snapshot of user state).
///
/// Provides access to session metadata, ACL, permissions, bookmarks, and
/// aliases. Passed mutably into command execution so that bookmark/alias
/// commands can modify in-memory state.
#[derive(Clone)]
pub struct ShellContext {
    pub username: String,
    pub auth_method: String,
    pub source_ip: String,
    pub role: UserRole,
    pub group: Option<String>,
    pub permissions: ShellPermissions,
    pub acl: ParsedAcl,
    pub colors: bool,
    pub expires_at: Option<String>,
    pub max_bandwidth_kbps: u64,
    pub server_start_time: std::time::Instant,
    /// In-memory bookmarks: name -> host:port
    pub bookmarks: HashMap<String, String>,
    /// Command aliases: alias -> command
    pub aliases: HashMap<String, String>,
    pub ssh_key_fingerprint: Option<String>,
    /// Live proxy engine for connection counts.
    pub proxy_engine: Option<Arc<ProxyEngine>>,
    /// Live quota tracker for bandwidth/connection data.
    pub quota_tracker: Option<Arc<QuotaTracker>>,
    /// Configured quota limits for this user (from config).
    pub quota_config: Option<QuotaConfig>,
}

impl ShellContext {
    /// Format the session uptime as a human-readable string.
    pub fn uptime(&self) -> String {
        let elapsed = self.server_start_time.elapsed();
        let secs = elapsed.as_secs();
        if secs < 60 {
            format!("{}s", secs)
        } else if secs < 3600 {
            format!("{}m {}s", secs / 60, secs % 60)
        } else {
            format!("{}h {}m {}s", secs / 3600, (secs % 3600) / 60, secs % 60)
        }
    }
}
