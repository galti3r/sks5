use super::{ApiResponse, AppState};
use axum::{extract::State, response::IntoResponse};
use serde::Serialize;
use tracing::{error, info};

#[derive(Serialize)]
pub struct ReloadResult {
    pub users_count: usize,
}

pub async fn reload_config(State(state): State<AppState>) -> impl IntoResponse {
    let config_path = match &state.config_path {
        Some(p) => p.clone(),
        None => {
            return ApiResponse::err(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "config path not available",
            )
            .into_response();
        }
    };

    match crate::config::load_config(&config_path) {
        Ok(new_config) => {
            let users_count = new_config.users.len();
            match state.auth_service.write().await.reload(&new_config) {
                Ok(()) => {
                    state.security.write().await.reload(&new_config);
                    if let Some(ref audit) = state.audit {
                        audit.log_config_reload(users_count, true, None);
                    }
                    info!(users = users_count, "Config reloaded via API");
                    ApiResponse::ok(ReloadResult { users_count }).into_response()
                }
                Err(e) => {
                    error!(error = %e, "Failed to reload auth service via API");
                    if let Some(ref audit) = state.audit {
                        audit.log_config_reload(0, false, Some(e.to_string()));
                    }
                    ApiResponse::err(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
                        .into_response()
                }
            }
        }
        Err(e) => {
            error!(error = %e, "Failed to load config via API");
            if let Some(ref audit) = state.audit {
                audit.log_config_reload(0, false, Some(e.to_string()));
            }
            ApiResponse::err(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
                .into_response()
        }
    }
}
