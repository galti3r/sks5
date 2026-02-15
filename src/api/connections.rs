use super::{ApiResponse, AppState};
use axum::{extract::State, response::IntoResponse};
use serde::Serialize;

#[derive(Serialize)]
pub struct ConnectionsInfo {
    pub active_connections: u32,
    pub user_connections: Vec<UserConnectionInfo>,
}

#[derive(Serialize)]
pub struct UserConnectionInfo {
    pub username: String,
    pub connections: u32,
}

pub async fn list_connections(State(state): State<AppState>) -> impl IntoResponse {
    let active = state.proxy_engine.active_connections();

    let auth = state.auth_service.read().await;
    let store = auth.user_store();
    let usernames = store.usernames();

    let user_connections: Vec<UserConnectionInfo> = usernames
        .iter()
        .map(|name| UserConnectionInfo {
            username: name.clone(),
            connections: state.proxy_engine.user_connections(name),
        })
        .filter(|uc| uc.connections > 0)
        .collect();

    ApiResponse::ok(ConnectionsInfo {
        active_connections: active,
        user_connections,
    })
}
