use super::{ApiResponse, AppState};
use axum::{extract::State, response::IntoResponse};
use serde::Serialize;

#[derive(Serialize)]
pub struct MaintenanceStatus {
    pub maintenance: bool,
}

pub async fn toggle_maintenance(State(state): State<AppState>) -> impl IntoResponse {
    let prev = state
        .maintenance
        .fetch_xor(true, std::sync::atomic::Ordering::SeqCst);
    let new_state = !prev;

    if let Some(ref audit) = state.audit {
        audit.log_maintenance_toggled(new_state, "api");
    }

    ApiResponse::ok(MaintenanceStatus {
        maintenance: new_state,
    })
}
