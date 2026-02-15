use super::AppState;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct SshConfigQuery {
    pub user: String,
    #[serde(default = "default_host")]
    pub host: String,
}

fn default_host() -> String {
    "localhost".to_string()
}

pub async fn ssh_config_snippet(
    State(state): State<AppState>,
    Query(query): Query<SshConfigQuery>,
) -> impl IntoResponse {
    // Extract the port from the SSH listen address stored in AppState
    let port = state
        .ssh_listen_addr
        .as_deref()
        .and_then(|addr| addr.rsplit(':').next())
        .unwrap_or("2222");

    let snippet = format!(
        "Host {host}\n\
         \x20 HostName {host}\n\
         \x20 Port {port}\n\
         \x20 User {user}\n\
         \x20 DynamicForward 1080\n\
         \x20 StrictHostKeyChecking no\n\
         \x20 UserKnownHostsFile /dev/null\n",
        host = query.host,
        port = port,
        user = query.user,
    );

    (
        StatusCode::OK,
        [("content-type", "text/plain; charset=utf-8")],
        snippet,
    )
}
