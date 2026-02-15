use crate::api::{ApiResponse, AppState};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Serialize;

#[derive(Serialize)]
struct GroupStats {
    name: String,
    member_count: usize,
    active_connections: u32,
    total_daily_bytes: u64,
    total_monthly_bytes: u64,
    members: Vec<GroupMemberInfo>,
}

#[derive(Serialize)]
struct GroupMemberInfo {
    username: String,
    active_connections: u32,
    daily_bytes: u64,
    monthly_bytes: u64,
}

pub async fn list_groups(State(state): State<AppState>) -> impl IntoResponse {
    let auth = state.auth_service.read().await;
    let group_names = auth.user_store().group_names();

    let mut groups = Vec::new();
    for name in &group_names {
        let members_users = auth.user_store().users_in_group(name);
        let mut active_connections: u32 = 0;
        let mut total_daily_bytes: u64 = 0;
        let mut total_monthly_bytes: u64 = 0;
        let mut members = Vec::new();

        for user in &members_users {
            let conns = state.proxy_engine.user_connections(&user.username);
            active_connections += conns;

            let (daily, monthly) = if let Some(ref qt) = state.quota_tracker {
                let usage = qt.get_user_usage(&user.username);
                (usage.daily_bytes, usage.monthly_bytes)
            } else {
                (0, 0)
            };
            total_daily_bytes += daily;
            total_monthly_bytes += monthly;

            members.push(GroupMemberInfo {
                username: user.username.clone(),
                active_connections: conns,
                daily_bytes: daily,
                monthly_bytes: monthly,
            });
        }

        groups.push(GroupStats {
            name: name.clone(),
            member_count: members_users.len(),
            active_connections,
            total_daily_bytes,
            total_monthly_bytes,
            members,
        });
    }

    ApiResponse::ok(groups)
}

pub async fn get_group(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let auth = state.auth_service.read().await;
    let members_users = auth.user_store().users_in_group(&name);

    if members_users.is_empty() {
        // Check if the group exists at all (might have no current users)
        let group_names = auth.user_store().group_names();
        if !group_names.contains(&name) {
            return ApiResponse::err(StatusCode::NOT_FOUND, format!("group '{}' not found", name))
                .into_response();
        }
    }

    let mut active_connections: u32 = 0;
    let mut total_daily_bytes: u64 = 0;
    let mut total_monthly_bytes: u64 = 0;
    let mut members = Vec::new();

    for user in &members_users {
        let conns = state.proxy_engine.user_connections(&user.username);
        active_connections += conns;

        let (daily, monthly) = if let Some(ref qt) = state.quota_tracker {
            let usage = qt.get_user_usage(&user.username);
            (usage.daily_bytes, usage.monthly_bytes)
        } else {
            (0, 0)
        };
        total_daily_bytes += daily;
        total_monthly_bytes += monthly;

        members.push(GroupMemberInfo {
            username: user.username.clone(),
            active_connections: conns,
            daily_bytes: daily,
            monthly_bytes: monthly,
        });
    }

    let stats = GroupStats {
        name,
        member_count: members_users.len(),
        active_connections,
        total_daily_bytes,
        total_monthly_bytes,
        members,
    };

    ApiResponse::ok(stats).into_response()
}
