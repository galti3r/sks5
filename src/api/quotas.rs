use super::{ApiResponse, AppState};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Serialize;
use tracing::info;

#[derive(Serialize)]
pub struct QuotaSummary {
    pub username: String,
    pub daily_bytes: u64,
    pub daily_connections: u32,
    pub monthly_bytes: u64,
    pub monthly_connections: u32,
    pub current_rate_bps: u64,
    pub hourly_bytes: u64,
    pub total_bytes: u64,
    // Configured limits (0 = unlimited)
    pub daily_bytes_limit: u64,
    pub monthly_bytes_limit: u64,
    pub hourly_bytes_limit: u64,
    pub total_bytes_limit: u64,
    pub daily_connections_limit: u32,
    pub monthly_connections_limit: u32,
}

/// GET /api/quotas — summary of all tracked users' quota usage.
pub async fn list_quotas(State(state): State<AppState>) -> impl IntoResponse {
    let Some(ref qt) = state.quota_tracker else {
        return ApiResponse::ok(Vec::<QuotaSummary>::new()).into_response();
    };

    let auth = state.auth_service.read().await;
    let usernames = qt.tracked_users();
    let summaries: Vec<QuotaSummary> = usernames
        .into_iter()
        .map(|username| {
            let usage = qt.get_user_usage(&username);
            let quotas = auth
                .user_store()
                .get(&username)
                .and_then(|u| u.quotas.as_ref());
            QuotaSummary {
                username,
                daily_bytes: usage.daily_bytes,
                daily_connections: usage.daily_connections,
                monthly_bytes: usage.monthly_bytes,
                monthly_connections: usage.monthly_connections,
                current_rate_bps: usage.current_rate_bps,
                hourly_bytes: usage.hourly_bytes,
                total_bytes: usage.total_bytes,
                daily_bytes_limit: quotas.map_or(0, |q| q.daily_bandwidth_bytes),
                monthly_bytes_limit: quotas.map_or(0, |q| q.monthly_bandwidth_bytes),
                hourly_bytes_limit: quotas.map_or(0, |q| q.bandwidth_per_hour_bytes),
                total_bytes_limit: quotas.map_or(0, |q| q.total_bandwidth_bytes),
                daily_connections_limit: quotas.map_or(0, |q| q.daily_connection_limit),
                monthly_connections_limit: quotas.map_or(0, |q| q.monthly_connection_limit),
            }
        })
        .collect();

    ApiResponse::ok(summaries).into_response()
}

/// GET /api/quotas/:username — detail for a specific user.
pub async fn get_user_quota(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    let Some(ref qt) = state.quota_tracker else {
        return ApiResponse::err(StatusCode::NOT_FOUND, "quota tracking not available")
            .into_response();
    };

    let auth = state.auth_service.read().await;
    let quotas = auth
        .user_store()
        .get(&username)
        .and_then(|u| u.quotas.as_ref());
    let usage = qt.get_user_usage(&username);
    ApiResponse::ok(QuotaSummary {
        username,
        daily_bytes: usage.daily_bytes,
        daily_connections: usage.daily_connections,
        monthly_bytes: usage.monthly_bytes,
        monthly_connections: usage.monthly_connections,
        current_rate_bps: usage.current_rate_bps,
        hourly_bytes: usage.hourly_bytes,
        total_bytes: usage.total_bytes,
        daily_bytes_limit: quotas.map_or(0, |q| q.daily_bandwidth_bytes),
        monthly_bytes_limit: quotas.map_or(0, |q| q.monthly_bandwidth_bytes),
        hourly_bytes_limit: quotas.map_or(0, |q| q.bandwidth_per_hour_bytes),
        total_bytes_limit: quotas.map_or(0, |q| q.total_bandwidth_bytes),
        daily_connections_limit: quotas.map_or(0, |q| q.daily_connection_limit),
        monthly_connections_limit: quotas.map_or(0, |q| q.monthly_connection_limit),
    })
    .into_response()
}

#[derive(Serialize)]
pub struct QuotaResetResult {
    pub username: String,
    pub reset: bool,
}

/// POST /api/quotas/:username/reset — reset quotas for a specific user.
pub async fn reset_user_quota(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    let Some(ref qt) = state.quota_tracker else {
        return ApiResponse::err(StatusCode::NOT_FOUND, "quota tracking not available")
            .into_response();
    };

    qt.reset_user(&username);
    info!(user = %username, "Quota reset via API");

    ApiResponse::ok(QuotaResetResult {
        username,
        reset: true,
    })
    .into_response()
}
