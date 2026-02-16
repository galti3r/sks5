use super::{ApiResponse, AppState};
use crate::config::types::ShellPermissions;
use crate::quota::UserQuotaUsage;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize)]
pub struct UsersQuery {
    details: Option<String>,
}

#[derive(Serialize)]
pub struct UserInfo {
    pub username: String,
    pub allow_shell: bool,
    pub authorized_keys_count: usize,
    pub source_ips: Vec<String>,
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_connections: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_bytes_transferred: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_usage: Option<UserQuotaUsage>,
}

pub async fn list_users(
    State(state): State<AppState>,
    Query(query): Query<UsersQuery>,
) -> impl IntoResponse {
    let include_details = super::is_truthy(query.details.as_deref());

    let auth = state.auth_service.read().await;
    let store = auth.user_store();
    let usernames = store.usernames();

    let users: Vec<UserInfo> = usernames
        .iter()
        .filter_map(|name| {
            store.get(name).map(|u| {
                let (current_connections, total_bytes_transferred, quota_usage) = if include_details
                {
                    let conns = state.proxy_engine.user_connections(name);
                    let bytes = state
                        .metrics
                        .bytes_transferred
                        .get_or_create(&crate::metrics::collectors::UserLabel {
                            user: name.clone(),
                        })
                        .get();
                    let usage = state
                        .quota_tracker
                        .as_ref()
                        .map(|qt| qt.get_user_usage(name));
                    (Some(conns), Some(bytes), usage)
                } else {
                    (None, None, None)
                };

                UserInfo {
                    username: u.username.clone(),
                    allow_shell: u.allow_shell,
                    authorized_keys_count: u.authorized_keys.len(),
                    source_ips: u.source_ips.iter().map(|ip| ip.to_string()).collect(),
                    expires_at: u.expires_at.map(|e| e.to_rfc3339()),
                    current_connections,
                    total_bytes_transferred,
                    quota_usage,
                }
            })
        })
        .collect();

    ApiResponse::ok(users)
}

#[derive(Serialize)]
pub struct UserDetailInfo {
    pub username: String,
    pub role: String,
    pub group: Option<String>,
    pub allow_shell: bool,
    pub has_password: bool,
    pub authorized_keys_fingerprints: Vec<String>,
    pub totp_enabled: bool,
    pub source_ips: Vec<String>,
    pub expires_at: Option<String>,
    pub max_bandwidth_kbps: u64,
    pub max_aggregate_bandwidth_kbps: u64,
    pub max_new_connections_per_minute: u32,
    pub max_connections: u32,
    pub acl: AclDetail,
    pub shell_permissions: ShellPermissions,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quotas: Option<crate::config::types::QuotaConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_access: Option<crate::config::types::TimeAccessConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_methods: Option<Vec<String>>,
    pub aliases: HashMap<String, String>,
    pub idle_warning_secs: u64,
    pub colors: bool,
    pub connect_retry: u32,
    pub connect_retry_delay_ms: u64,
    pub current_connections: u32,
    pub total_bytes_transferred: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_usage: Option<UserQuotaUsage>,
}

#[derive(Serialize)]
pub struct AclDetail {
    pub default_policy: String,
    pub allow_rules: Vec<String>,
    pub deny_rules: Vec<String>,
}

pub async fn get_user_detail(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    let auth = state.auth_service.read().await;
    let store = auth.user_store();

    let user = match store.get(&username) {
        Some(u) => u,
        None => {
            return ApiResponse::err(
                StatusCode::NOT_FOUND,
                format!("user '{}' not found", username),
            )
            .into_response();
        }
    };

    let conns = state.proxy_engine.user_connections(&username);
    let bytes = state
        .metrics
        .bytes_transferred
        .get_or_create(&crate::metrics::collectors::UserLabel {
            user: username.clone(),
        })
        .get();
    let quota_usage = state
        .quota_tracker
        .as_ref()
        .map(|qt| qt.get_user_usage(&username));

    let fingerprints: Vec<String> = user
        .authorized_keys
        .iter()
        .enumerate()
        .map(|(i, _)| {
            use base64::Engine;
            use sha2::{Digest, Sha256};
            if let Some(pk) = user.parsed_authorized_keys.get(i) {
                use russh::keys::PublicKeyBase64;
                let key_b64 = pk.public_key_base64();
                let key_bytes = base64::engine::general_purpose::STANDARD
                    .decode(&key_b64)
                    .unwrap_or_default();
                let hash = Sha256::digest(&key_bytes);
                let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(hash);
                format!("SHA256:{}", b64)
            } else {
                "invalid-key".to_string()
            }
        })
        .collect();

    let detail = UserDetailInfo {
        username: user.username.clone(),
        role: user.role.to_string(),
        group: user.group.clone(),
        allow_shell: user.allow_shell,
        has_password: user.password_hash.is_some(),
        authorized_keys_fingerprints: fingerprints,
        totp_enabled: user.totp_enabled,
        source_ips: user.source_ips.iter().map(|ip| ip.to_string()).collect(),
        expires_at: user.expires_at.map(|e| e.to_rfc3339()),
        max_bandwidth_kbps: user.max_bandwidth_kbps,
        max_aggregate_bandwidth_kbps: user.max_aggregate_bandwidth_kbps,
        max_new_connections_per_minute: user.max_new_connections_per_minute,
        max_connections: user.max_connections,
        acl: AclDetail {
            default_policy: match user.acl.default_policy {
                crate::config::acl::AclPolicy::Allow => "allow".to_string(),
                crate::config::acl::AclPolicy::Deny => "deny".to_string(),
            },
            allow_rules: user.acl.allow_rules.iter().map(|r| r.to_string()).collect(),
            deny_rules: user.acl.deny_rules.iter().map(|r| r.to_string()).collect(),
        },
        shell_permissions: user.shell_permissions.clone(),
        quotas: user.quotas.clone(),
        time_access: user.time_access.clone(),
        auth_methods: user.auth_methods.clone(),
        aliases: user.aliases.clone(),
        idle_warning_secs: user.idle_warning_secs,
        colors: user.colors,
        connect_retry: user.connect_retry,
        connect_retry_delay_ms: user.connect_retry_delay_ms,
        current_connections: conns,
        total_bytes_transferred: bytes,
        quota_usage,
    };

    ApiResponse::ok(detail).into_response()
}
