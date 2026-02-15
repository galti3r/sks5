use crate::api::{ApiResponse, AppState};
use axum::{
    extract::{Path, State},
    response::IntoResponse,
};
use serde::Serialize;

#[derive(Serialize)]
struct SessionResponse {
    session_id: String,
    username: String,
    target_host: String,
    target_port: u16,
    source_ip: String,
    started_at: String,
    bytes_up: u64,
    bytes_down: u64,
    duration_secs: u64,
    protocol: String,
}

fn to_response(snap: crate::proxy::SessionSnapshot) -> SessionResponse {
    let duration = chrono::Utc::now().signed_duration_since(snap.started_at);
    SessionResponse {
        session_id: snap.session_id,
        username: snap.username,
        target_host: snap.target_host,
        target_port: snap.target_port,
        source_ip: snap.source_ip,
        started_at: snap.started_at.to_rfc3339(),
        bytes_up: snap.bytes_up,
        bytes_down: snap.bytes_down,
        duration_secs: duration.num_seconds().max(0) as u64,
        protocol: snap.protocol,
    }
}

pub async fn list_sessions(State(state): State<AppState>) -> impl IntoResponse {
    let sessions: Vec<SessionResponse> = state
        .proxy_engine
        .get_sessions()
        .into_iter()
        .map(to_response)
        .collect();
    ApiResponse::ok(sessions)
}

pub async fn get_user_sessions(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    let sessions: Vec<SessionResponse> = state
        .proxy_engine
        .get_user_sessions(&username)
        .into_iter()
        .map(to_response)
        .collect();
    ApiResponse::ok(sessions)
}
