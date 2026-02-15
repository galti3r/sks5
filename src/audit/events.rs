use chrono::{DateTime, Utc};
use serde::Serialize;
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event_type")]
pub enum AuditEvent {
    #[serde(rename = "auth.success")]
    AuthSuccess {
        timestamp: DateTime<Utc>,
        #[serde(skip_serializing_if = "Option::is_none")]
        correlation_id: Option<String>,
        username: String,
        source_ip: String,
        method: String,
    },
    #[serde(rename = "auth.failure")]
    AuthFailure {
        timestamp: DateTime<Utc>,
        #[serde(skip_serializing_if = "Option::is_none")]
        correlation_id: Option<String>,
        username: String,
        source_ip: String,
        method: String,
    },
    #[serde(rename = "proxy.complete")]
    ProxyComplete {
        timestamp: DateTime<Utc>,
        #[serde(skip_serializing_if = "Option::is_none")]
        correlation_id: Option<String>,
        username: String,
        target_host: String,
        target_port: u16,
        bytes_transferred: u64,
        bytes_uploaded: u64,
        bytes_downloaded: u64,
        duration_ms: u64,
        source_ip: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        resolved_ip: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        via_proxy: Option<String>,
    },
    #[serde(rename = "acl.deny")]
    AclDeny {
        timestamp: DateTime<Utc>,
        #[serde(skip_serializing_if = "Option::is_none")]
        correlation_id: Option<String>,
        username: String,
        target_host: String,
        target_port: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        resolved_ip: Option<String>,
        source_ip: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        matched_rule: Option<String>,
        reason: String,
    },
    #[serde(rename = "ban.created")]
    BanCreated {
        timestamp: DateTime<Utc>,
        ip: String,
        duration_secs: u64,
    },
    #[serde(rename = "ban.expired")]
    BanExpired {
        timestamp: DateTime<Utc>,
        ip: String,
    },
    #[serde(rename = "connection.new")]
    ConnectionNew {
        timestamp: DateTime<Utc>,
        #[serde(skip_serializing_if = "Option::is_none")]
        correlation_id: Option<String>,
        source_ip: String,
        protocol: String,
    },
    #[serde(rename = "connection.closed")]
    ConnectionClosed {
        timestamp: DateTime<Utc>,
        #[serde(skip_serializing_if = "Option::is_none")]
        correlation_id: Option<String>,
        source_ip: String,
        protocol: String,
    },
    #[serde(rename = "config.reload")]
    ConfigReload {
        timestamp: DateTime<Utc>,
        users_count: usize,
        success: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },

    #[serde(rename = "quota.exceeded")]
    QuotaExceeded {
        timestamp: DateTime<Utc>,
        #[serde(skip_serializing_if = "Option::is_none")]
        correlation_id: Option<String>,
        username: String,
        quota_type: String,
        current_usage: u64,
        limit: u64,
    },

    #[serde(rename = "session.authenticated")]
    SessionAuthenticated {
        timestamp: DateTime<Utc>,
        #[serde(skip_serializing_if = "Option::is_none")]
        correlation_id: Option<String>,
        username: String,
        source_ip: String,
        protocol: String,
        method: String,
    },

    #[serde(rename = "session.ended")]
    SessionEnded {
        timestamp: DateTime<Utc>,
        #[serde(skip_serializing_if = "Option::is_none")]
        correlation_id: Option<String>,
        username: String,
        source_ip: String,
        protocol: String,
        duration_secs: u64,
        total_bytes: u64,
    },

    #[serde(rename = "rate_limit.exceeded")]
    RateLimitExceeded {
        timestamp: DateTime<Utc>,
        #[serde(skip_serializing_if = "Option::is_none")]
        correlation_id: Option<String>,
        username: String,
        source_ip: String,
        limit_type: String,
    },

    #[serde(rename = "maintenance.toggled")]
    MaintenanceToggled {
        timestamp: DateTime<Utc>,
        enabled: bool,
        source: String,
    },
}

impl AuditEvent {
    pub fn auth_success(username: &str, source: &SocketAddr, method: &str) -> Self {
        Self::AuthSuccess {
            timestamp: Utc::now(),
            correlation_id: None,
            username: username.to_string(),
            source_ip: source.ip().to_string(),
            method: method.to_string(),
        }
    }

    pub fn auth_success_with_cid(
        username: &str,
        source: &SocketAddr,
        method: &str,
        cid: &str,
    ) -> Self {
        Self::AuthSuccess {
            timestamp: Utc::now(),
            correlation_id: Some(cid.to_string()),
            username: username.to_string(),
            source_ip: source.ip().to_string(),
            method: method.to_string(),
        }
    }

    pub fn auth_failure(username: &str, source: &SocketAddr, method: &str) -> Self {
        Self::AuthFailure {
            timestamp: Utc::now(),
            correlation_id: None,
            username: username.to_string(),
            source_ip: source.ip().to_string(),
            method: method.to_string(),
        }
    }

    pub fn auth_failure_with_cid(
        username: &str,
        source: &SocketAddr,
        method: &str,
        cid: &str,
    ) -> Self {
        Self::AuthFailure {
            timestamp: Utc::now(),
            correlation_id: Some(cid.to_string()),
            username: username.to_string(),
            source_ip: source.ip().to_string(),
            method: method.to_string(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn proxy_complete(
        username: &str,
        host: &str,
        port: u16,
        bytes_up: u64,
        bytes_down: u64,
        duration_ms: u64,
        source: &SocketAddr,
        resolved_ip: Option<String>,
    ) -> Self {
        Self::ProxyComplete {
            timestamp: Utc::now(),
            correlation_id: None,
            username: username.to_string(),
            target_host: host.to_string(),
            target_port: port,
            bytes_transferred: bytes_up + bytes_down,
            bytes_uploaded: bytes_up,
            bytes_downloaded: bytes_down,
            duration_ms,
            source_ip: source.ip().to_string(),
            resolved_ip,
            via_proxy: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn proxy_complete_with_cid(
        username: &str,
        host: &str,
        port: u16,
        bytes_up: u64,
        bytes_down: u64,
        duration_ms: u64,
        source: &SocketAddr,
        resolved_ip: Option<String>,
        cid: &str,
    ) -> Self {
        Self::ProxyComplete {
            timestamp: Utc::now(),
            correlation_id: Some(cid.to_string()),
            username: username.to_string(),
            target_host: host.to_string(),
            target_port: port,
            bytes_transferred: bytes_up + bytes_down,
            bytes_uploaded: bytes_up,
            bytes_downloaded: bytes_down,
            duration_ms,
            source_ip: source.ip().to_string(),
            resolved_ip,
            via_proxy: None,
        }
    }

    pub fn acl_deny(
        username: &str,
        host: &str,
        port: u16,
        resolved_ip: Option<String>,
        source_ip: &str,
        matched_rule: Option<String>,
        reason: &str,
    ) -> Self {
        Self::AclDeny {
            timestamp: Utc::now(),
            correlation_id: None,
            username: username.to_string(),
            target_host: host.to_string(),
            target_port: port,
            resolved_ip,
            source_ip: source_ip.to_string(),
            matched_rule,
            reason: reason.to_string(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn acl_deny_with_cid(
        username: &str,
        host: &str,
        port: u16,
        resolved_ip: Option<String>,
        source_ip: &str,
        matched_rule: Option<String>,
        reason: &str,
        cid: &str,
    ) -> Self {
        Self::AclDeny {
            timestamp: Utc::now(),
            correlation_id: Some(cid.to_string()),
            username: username.to_string(),
            target_host: host.to_string(),
            target_port: port,
            resolved_ip,
            source_ip: source_ip.to_string(),
            matched_rule,
            reason: reason.to_string(),
        }
    }

    pub fn connection_new(source: &SocketAddr, protocol: &str) -> Self {
        Self::ConnectionNew {
            timestamp: Utc::now(),
            correlation_id: None,
            source_ip: source.ip().to_string(),
            protocol: protocol.to_string(),
        }
    }

    pub fn connection_new_with_cid(source: &SocketAddr, protocol: &str, cid: &str) -> Self {
        Self::ConnectionNew {
            timestamp: Utc::now(),
            correlation_id: Some(cid.to_string()),
            source_ip: source.ip().to_string(),
            protocol: protocol.to_string(),
        }
    }

    pub fn connection_closed(source: &SocketAddr, protocol: &str) -> Self {
        Self::ConnectionClosed {
            timestamp: Utc::now(),
            correlation_id: None,
            source_ip: source.ip().to_string(),
            protocol: protocol.to_string(),
        }
    }

    pub fn connection_closed_with_cid(source: &SocketAddr, protocol: &str, cid: &str) -> Self {
        Self::ConnectionClosed {
            timestamp: Utc::now(),
            correlation_id: Some(cid.to_string()),
            source_ip: source.ip().to_string(),
            protocol: protocol.to_string(),
        }
    }

    pub fn config_reload(users_count: usize, success: bool, error: Option<String>) -> Self {
        Self::ConfigReload {
            timestamp: Utc::now(),
            users_count,
            success,
            error,
        }
    }

    pub fn quota_exceeded(
        username: &str,
        quota_type: &str,
        current_usage: u64,
        limit: u64,
    ) -> Self {
        Self::QuotaExceeded {
            timestamp: Utc::now(),
            correlation_id: None,
            username: username.to_string(),
            quota_type: quota_type.to_string(),
            current_usage,
            limit,
        }
    }

    pub fn quota_exceeded_with_cid(
        username: &str,
        quota_type: &str,
        current_usage: u64,
        limit: u64,
        cid: &str,
    ) -> Self {
        Self::QuotaExceeded {
            timestamp: Utc::now(),
            correlation_id: Some(cid.to_string()),
            username: username.to_string(),
            quota_type: quota_type.to_string(),
            current_usage,
            limit,
        }
    }

    pub fn session_authenticated(
        username: &str,
        source: &SocketAddr,
        protocol: &str,
        method: &str,
    ) -> Self {
        Self::SessionAuthenticated {
            timestamp: Utc::now(),
            correlation_id: None,
            username: username.to_string(),
            source_ip: source.ip().to_string(),
            protocol: protocol.to_string(),
            method: method.to_string(),
        }
    }

    pub fn session_authenticated_with_cid(
        username: &str,
        source: &SocketAddr,
        protocol: &str,
        method: &str,
        cid: &str,
    ) -> Self {
        Self::SessionAuthenticated {
            timestamp: Utc::now(),
            correlation_id: Some(cid.to_string()),
            username: username.to_string(),
            source_ip: source.ip().to_string(),
            protocol: protocol.to_string(),
            method: method.to_string(),
        }
    }

    pub fn session_ended(
        username: &str,
        source: &SocketAddr,
        protocol: &str,
        duration_secs: u64,
        total_bytes: u64,
    ) -> Self {
        Self::SessionEnded {
            timestamp: Utc::now(),
            correlation_id: None,
            username: username.to_string(),
            source_ip: source.ip().to_string(),
            protocol: protocol.to_string(),
            duration_secs,
            total_bytes,
        }
    }

    pub fn session_ended_with_cid(
        username: &str,
        source: &SocketAddr,
        protocol: &str,
        duration_secs: u64,
        total_bytes: u64,
        cid: &str,
    ) -> Self {
        Self::SessionEnded {
            timestamp: Utc::now(),
            correlation_id: Some(cid.to_string()),
            username: username.to_string(),
            source_ip: source.ip().to_string(),
            protocol: protocol.to_string(),
            duration_secs,
            total_bytes,
        }
    }

    pub fn rate_limit_exceeded(username: &str, source: &SocketAddr, limit_type: &str) -> Self {
        Self::RateLimitExceeded {
            timestamp: Utc::now(),
            correlation_id: None,
            username: username.to_string(),
            source_ip: source.ip().to_string(),
            limit_type: limit_type.to_string(),
        }
    }

    pub fn rate_limit_exceeded_with_cid(
        username: &str,
        source: &SocketAddr,
        limit_type: &str,
        cid: &str,
    ) -> Self {
        Self::RateLimitExceeded {
            timestamp: Utc::now(),
            correlation_id: Some(cid.to_string()),
            username: username.to_string(),
            source_ip: source.ip().to_string(),
            limit_type: limit_type.to_string(),
        }
    }

    pub fn maintenance_toggled(enabled: bool, source: &str) -> Self {
        Self::MaintenanceToggled {
            timestamp: Utc::now(),
            enabled,
            source: source.to_string(),
        }
    }

    pub fn ban_created(ip: &std::net::IpAddr, duration_secs: u64) -> Self {
        Self::BanCreated {
            timestamp: Utc::now(),
            ip: ip.to_string(),
            duration_secs,
        }
    }

    pub fn ban_expired(ip: &std::net::IpAddr) -> Self {
        Self::BanExpired {
            timestamp: Utc::now(),
            ip: ip.to_string(),
        }
    }

    /// Returns the event type string for webhook dispatch.
    pub fn event_type(&self) -> &'static str {
        match self {
            Self::AuthSuccess { .. } => "auth.success",
            Self::AuthFailure { .. } => "auth.failure",
            Self::ProxyComplete { .. } => "proxy.complete",
            Self::AclDeny { .. } => "acl.deny",
            Self::BanCreated { .. } => "ban.created",
            Self::BanExpired { .. } => "ban.expired",
            Self::ConnectionNew { .. } => "connection.new",
            Self::ConnectionClosed { .. } => "connection.closed",
            Self::ConfigReload { .. } => "config.reload",
            Self::QuotaExceeded { .. } => "quota.exceeded",
            Self::SessionAuthenticated { .. } => "session.authenticated",
            Self::SessionEnded { .. } => "session.ended",
            Self::RateLimitExceeded { .. } => "rate_limit.exceeded",
            Self::MaintenanceToggled { .. } => "maintenance.toggled",
        }
    }

    /// Whether this event is critical and should use priority delivery.
    /// Critical events: ACL denials, bans, config reloads, auth failures.
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::AclDeny { .. }
                | Self::BanCreated { .. }
                | Self::BanExpired { .. }
                | Self::ConfigReload { .. }
                | Self::AuthFailure { .. }
                | Self::QuotaExceeded { .. }
                | Self::RateLimitExceeded { .. }
                | Self::MaintenanceToggled { .. }
        )
    }
}
