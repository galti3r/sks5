use super::{ApiResponse, AppState};
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Deserialize)]
pub struct KickRequest {
    #[serde(default = "default_kick_message")]
    pub message: String,
}

fn default_kick_message() -> String {
    "Disconnected by administrator".to_string()
}

#[derive(Serialize)]
pub struct KickResponse {
    pub kicked: bool,
    pub username: String,
    pub sessions_cancelled: usize,
}

pub async fn kick_user(
    State(state): State<AppState>,
    Path(username): Path<String>,
    body: Option<Json<KickRequest>>,
) -> impl IntoResponse {
    let message = body
        .map(|b| b.message.clone())
        .unwrap_or_else(default_kick_message);

    let sessions_cancelled = if let Some(ref kick_tokens) = state.kick_tokens {
        if let Some(tokens) = kick_tokens.get(&username) {
            let count = tokens.value().len();
            for token in tokens.value() {
                token.cancel();
            }
            info!(user = %username, sessions = count, reason = %message, "User kicked via API");
            count
        } else {
            0
        }
    } else {
        0
    };

    ApiResponse::ok(KickResponse {
        kicked: sessions_cancelled > 0,
        username,
        sessions_cancelled,
    })
}
