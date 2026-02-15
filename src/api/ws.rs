use crate::api::AppState;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, warn};

#[derive(Deserialize)]
struct WsCommand {
    action: String,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Serialize)]
struct WsResponse {
    success: bool,
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

pub async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    // API-001: Auth is handled by the router middleware (Bearer header or HMAC ticket).
    // No duplicate auth check needed here.
    ws.on_upgrade(move |socket| handle_ws(socket, state))
        .into_response()
}

async fn handle_ws(mut socket: WebSocket, state: AppState) {
    debug!("WebSocket client connected");

    let mut interval = tokio::time::interval(Duration::from_secs(2));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let payload = crate::api::sse::build_ws_payload(&state).await;
                let json = serde_json::to_string(&payload).unwrap_or_default();
                if socket.send(Message::Text(json)).await.is_err() {
                    break;
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        let response = handle_command(&text, &state).await;
                        let json = serde_json::to_string(&response).unwrap_or_default();
                        if socket.send(Message::Text(json)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }
    debug!("WebSocket client disconnected");
}

async fn handle_command(text: &str, state: &AppState) -> WsResponse {
    let cmd: WsCommand = match serde_json::from_str(text) {
        Ok(c) => c,
        Err(e) => {
            return WsResponse {
                success: false,
                action: "unknown".to_string(),
                error: Some(format!("invalid command: {}", e)),
            };
        }
    };

    match cmd.action.as_str() {
        "kick" => {
            if let Some(username) = &cmd.username {
                let auth = state.auth_service.read().await;
                if auth.user_store().get(username).is_some() {
                    if let Some(ref tx) = state.broadcast_tx {
                        let _ = tx.send(("__kick__".to_string(), vec![username.clone()]));
                    }
                    WsResponse {
                        success: true,
                        action: "kick".to_string(),
                        error: None,
                    }
                } else {
                    WsResponse {
                        success: false,
                        action: "kick".to_string(),
                        error: Some("user not found".to_string()),
                    }
                }
            } else {
                WsResponse {
                    success: false,
                    action: "kick".to_string(),
                    error: Some("username required".to_string()),
                }
            }
        }
        "maintenance" => {
            let enabled = cmd.enabled.unwrap_or(true);
            state
                .maintenance
                .store(enabled, std::sync::atomic::Ordering::Relaxed);
            WsResponse {
                success: true,
                action: "maintenance".to_string(),
                error: None,
            }
        }
        "unban" => {
            if let Some(ip_str) = &cmd.ip {
                if let Ok(ip) = ip_str.parse() {
                    let security = state.security.read().await;
                    security.ban_manager().unban(&ip);
                    WsResponse {
                        success: true,
                        action: "unban".to_string(),
                        error: None,
                    }
                } else {
                    WsResponse {
                        success: false,
                        action: "unban".to_string(),
                        error: Some("invalid IP".to_string()),
                    }
                }
            } else {
                WsResponse {
                    success: false,
                    action: "unban".to_string(),
                    error: Some("ip required".to_string()),
                }
            }
        }
        "broadcast" => {
            if let Some(message) = &cmd.message {
                if let Some(ref tx) = state.broadcast_tx {
                    let _ = tx.send((message.clone(), vec![]));
                }
                WsResponse {
                    success: true,
                    action: "broadcast".to_string(),
                    error: None,
                }
            } else {
                WsResponse {
                    success: false,
                    action: "broadcast".to_string(),
                    error: Some("message required".to_string()),
                }
            }
        }
        _ => {
            warn!(action = %cmd.action, "Unknown WebSocket command");
            WsResponse {
                success: false,
                action: cmd.action.clone(),
                error: Some("unknown action".to_string()),
            }
        }
    }
}
