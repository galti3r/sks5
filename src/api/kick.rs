use super::{ApiResponse, AppState};
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

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
}

pub async fn kick_user(
    State(state): State<AppState>,
    Path(username): Path<String>,
    body: Option<Json<KickRequest>>,
) -> impl IntoResponse {
    let message = body
        .map(|b| b.message.clone())
        .unwrap_or_else(default_kick_message);
    let kicked = if let Some(ref tx) = state.broadcast_tx {
        let _ = tx.send((format!("__KICK__:{}", message), vec![username.clone()]));
        true
    } else {
        false
    };
    ApiResponse::ok(KickResponse { kicked, username })
}
