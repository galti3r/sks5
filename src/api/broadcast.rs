use super::{ApiResponse, AppState};
use axum::{extract::State, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct BroadcastRequest {
    pub message: String,
    #[serde(default)]
    pub users: Vec<String>,
}

#[derive(Serialize)]
pub struct BroadcastResponse {
    pub delivered_to: usize,
}

pub async fn broadcast_message(
    State(state): State<AppState>,
    Json(req): Json<BroadcastRequest>,
) -> impl IntoResponse {
    let count = if let Some(ref tx) = state.broadcast_tx {
        let _ = tx.send((req.message, req.users));
        tx.receiver_count()
    } else {
        0
    };
    ApiResponse::ok(BroadcastResponse {
        delivered_to: count,
    })
}
