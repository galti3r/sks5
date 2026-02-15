use super::{ApiResponse, AppState};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Serialize;
use std::net::IpAddr;

#[derive(Serialize)]
pub struct BanInfo {
    pub ip: String,
    pub remaining_secs: u64,
}

pub async fn list_bans(State(state): State<AppState>) -> impl IntoResponse {
    let security = state.security.read().await;
    let banned = security.ban_manager().banned_ips();
    let now = std::time::Instant::now();

    let bans: Vec<BanInfo> = banned
        .iter()
        .map(|(ip, expiry)| {
            let remaining = if *expiry > now {
                (*expiry - now).as_secs()
            } else {
                0
            };
            BanInfo {
                ip: ip.to_string(),
                remaining_secs: remaining,
            }
        })
        .collect();

    ApiResponse::ok(bans)
}

#[derive(Serialize)]
pub struct UnbanResult {
    pub ip: String,
    pub unbanned: bool,
}

pub async fn delete_ban(
    State(state): State<AppState>,
    Path(ip_str): Path<String>,
) -> impl IntoResponse {
    let ip: IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return ApiResponse::err(StatusCode::BAD_REQUEST, "invalid IP address").into_response()
        }
    };

    let security = state.security.read().await;
    if security.ban_manager().unban(&ip) {
        ApiResponse::ok(UnbanResult {
            ip: ip_str,
            unbanned: true,
        })
        .into_response()
    } else {
        ApiResponse::err(StatusCode::NOT_FOUND, "IP not banned").into_response()
    }
}
