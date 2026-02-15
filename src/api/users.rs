use super::{ApiResponse, AppState};
use crate::quota::UserQuotaUsage;
use axum::{
    extract::{Query, State},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct UsersQuery {
    details: Option<String>,
}

#[derive(Serialize)]
pub struct UserInfo {
    pub username: String,
    pub allow_forwarding: bool,
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
                    allow_forwarding: u.allow_forwarding,
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
