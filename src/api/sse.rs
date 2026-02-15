use crate::api::AppState;
use crate::audit::events::AuditEvent;
use axum::{
    extract::State,
    response::{
        sse::{Event, Sse},
        IntoResponse,
    },
};
use serde::Serialize;
use std::convert::Infallible;
use std::time::Duration;
use tokio_stream::StreamExt;

#[derive(Serialize)]
pub struct SsePayload {
    active_connections: u32,
    banned_count: usize,
    total_users: usize,
    maintenance: bool,
    uptime_secs: u64,
    users: Vec<UserInfo>,
    bans: Vec<BanInfo>,
    connections: std::collections::HashMap<String, u32>,
    quotas: Vec<SseQuotaInfo>,
    groups: Vec<SseGroupInfo>,
    sessions: SseSessionSummary,
    recent_events: Vec<AuditEvent>,
}

#[derive(Serialize)]
struct SseSessionSummary {
    total_active: usize,
    sessions: Vec<SseSessionInfo>,
}

#[derive(Serialize)]
struct SseSessionInfo {
    session_id: String,
    username: String,
    target_host: String,
    target_port: u16,
    bytes_up: u64,
    bytes_down: u64,
    duration_secs: u64,
    protocol: String,
}

#[derive(Serialize)]
struct SseGroupInfo {
    name: String,
    active_connections: u32,
    member_count: usize,
    total_daily_bytes: u64,
    total_monthly_bytes: u64,
}

#[derive(Serialize)]
struct UserInfo {
    username: String,
    allow_forwarding: bool,
    allow_shell: bool,
}

#[derive(Serialize)]
struct SseQuotaInfo {
    username: String,
    daily_bytes: u64,
    daily_connections: u64,
    monthly_bytes: u64,
    monthly_connections: u64,
    current_rate_bps: u64,
    total_bytes: u64,
}

#[derive(Serialize)]
struct BanInfo {
    ip: String,
    expires_at: Option<String>,
}

pub async fn sse_events(State(state): State<AppState>) -> impl IntoResponse {
    // API-001: Auth is handled by the router middleware (Bearer header or HMAC ticket).
    // No duplicate auth check needed here.

    let stream =
        tokio_stream::wrappers::IntervalStream::new(tokio::time::interval(Duration::from_secs(2)))
            .map(move |_| {
                let state = state.clone();
                async move {
                    let payload = build_payload(&state).await;
                    let json = serde_json::to_string(&payload).unwrap_or_default();
                    Ok::<_, Infallible>(Event::default().data(json))
                }
            })
            .then(|fut| fut);

    Sse::new(stream)
        .keep_alive(
            axum::response::sse::KeepAlive::new()
                .interval(Duration::from_secs(10))
                .text("ping"),
        )
        .into_response()
}

/// Build the SSE/WS payload. Public for WebSocket reuse.
pub async fn build_ws_payload(state: &AppState) -> SsePayload {
    build_payload(state).await
}

async fn build_payload(state: &AppState) -> SsePayload {
    let active_connections = state.proxy_engine.active_connections();
    let uptime_secs = state.start_time.elapsed().as_secs();
    let maintenance = state.maintenance.load(std::sync::atomic::Ordering::Relaxed);

    let auth = state.auth_service.read().await;
    let usernames = auth.user_store().usernames();
    let total_users = usernames.len();
    let users: Vec<UserInfo> = usernames
        .iter()
        .filter_map(|u| auth.user_store().get(u))
        .map(|u| UserInfo {
            username: u.username.clone(),
            allow_forwarding: u.allow_forwarding,
            allow_shell: u.allow_shell,
        })
        .collect();

    let group_names = auth.user_store().group_names();
    let groups: Vec<SseGroupInfo> = group_names
        .iter()
        .map(|gname| {
            let members = auth.user_store().users_in_group(gname);
            let mut active_conns: u32 = 0;
            let mut daily: u64 = 0;
            let mut monthly: u64 = 0;
            for user in &members {
                active_conns += state.proxy_engine.user_connections(&user.username);
                if let Some(ref qt) = state.quota_tracker {
                    let usage = qt.get_user_usage(&user.username);
                    daily += usage.daily_bytes;
                    monthly += usage.monthly_bytes;
                }
            }
            SseGroupInfo {
                name: gname.clone(),
                active_connections: active_conns,
                member_count: members.len(),
                total_daily_bytes: daily,
                total_monthly_bytes: monthly,
            }
        })
        .collect();
    drop(auth);

    let security = state.security.read().await;
    let ban_list = security.ban_manager().banned_ips();
    let banned_count = ban_list.len();
    let bans: Vec<BanInfo> = ban_list
        .into_iter()
        .map(|(ip, expires)| {
            let remaining = expires.saturating_duration_since(std::time::Instant::now());
            BanInfo {
                ip: ip.to_string(),
                expires_at: Some(format!("{}s", remaining.as_secs())),
            }
        })
        .collect();
    drop(security);

    let connections: std::collections::HashMap<String, u32> = usernames
        .iter()
        .filter_map(|u| {
            let c = state.proxy_engine.user_connections(u);
            if c > 0 {
                Some((u.clone(), c))
            } else {
                None
            }
        })
        .collect();

    let quotas: Vec<SseQuotaInfo> = if let Some(ref qt) = state.quota_tracker {
        qt.tracked_users()
            .iter()
            .map(|u| {
                let usage = qt.get_user_usage(u);
                SseQuotaInfo {
                    username: u.clone(),
                    daily_bytes: usage.daily_bytes,
                    daily_connections: usage.daily_connections as u64,
                    monthly_bytes: usage.monthly_bytes,
                    monthly_connections: usage.monthly_connections as u64,
                    current_rate_bps: usage.current_rate_bps,
                    total_bytes: usage.total_bytes,
                }
            })
            .collect()
    } else {
        vec![]
    };

    let session_snapshots = state.proxy_engine.get_sessions();
    let sessions = SseSessionSummary {
        total_active: session_snapshots.len(),
        sessions: session_snapshots
            .into_iter()
            .map(|s| {
                let duration = chrono::Utc::now().signed_duration_since(s.started_at);
                SseSessionInfo {
                    session_id: s.session_id,
                    username: s.username,
                    target_host: s.target_host,
                    target_port: s.target_port,
                    bytes_up: s.bytes_up,
                    bytes_down: s.bytes_down,
                    duration_secs: duration.num_seconds().max(0) as u64,
                    protocol: s.protocol,
                }
            })
            .collect(),
    };

    let recent_events = state
        .audit
        .as_ref()
        .map(|a| a.get_recent_events(50))
        .unwrap_or_default();

    SsePayload {
        active_connections,
        banned_count,
        total_users,
        maintenance,
        uptime_secs,
        users,
        bans,
        connections,
        quotas,
        groups,
        sessions,
        recent_events,
    }
}
