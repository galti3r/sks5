use crate::api::{ApiResponse, AppState};
use axum::{extract::State, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
pub struct BackupPayload {
    pub version: String,
    pub timestamp: String,
    pub bans: Vec<BanEntry>,
    pub quotas: HashMap<String, QuotaUsageEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct BanEntry {
    pub ip: String,
    pub remaining_secs: u64,
}

#[derive(Serialize, Deserialize)]
pub struct QuotaUsageEntry {
    pub daily_bytes: u64,
    pub daily_connections: u32,
    pub monthly_bytes: u64,
    pub monthly_connections: u32,
    pub total_bytes: u64,
}

/// GET /api/backup — export bans + quotas as JSON
pub async fn backup_handler(State(state): State<AppState>) -> impl IntoResponse {
    let security = state.security.read().await;
    let ban_list = security.ban_manager().banned_ips();
    let bans: Vec<BanEntry> = ban_list
        .into_iter()
        .map(|(ip, expires)| {
            let remaining = expires.saturating_duration_since(std::time::Instant::now());
            BanEntry {
                ip: ip.to_string(),
                remaining_secs: remaining.as_secs(),
            }
        })
        .collect();
    drop(security);

    let mut quotas = HashMap::new();
    if let Some(ref qt) = state.quota_tracker {
        for username in qt.tracked_users() {
            let usage = qt.get_user_usage(&username);
            quotas.insert(
                username,
                QuotaUsageEntry {
                    daily_bytes: usage.daily_bytes,
                    daily_connections: usage.daily_connections,
                    monthly_bytes: usage.monthly_bytes,
                    monthly_connections: usage.monthly_connections,
                    total_bytes: usage.total_bytes,
                },
            );
        }
    }

    let payload = BackupPayload {
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        bans,
        quotas,
    };

    ApiResponse::ok(payload)
}

/// POST /api/restore — import bans + quotas from JSON
pub async fn restore_handler(
    State(state): State<AppState>,
    Json(payload): Json<BackupPayload>,
) -> impl IntoResponse {
    let mut restored_bans = 0u32;
    let mut restored_quotas = 0u32;

    // Restore bans
    {
        let security = state.security.read().await;
        for ban in &payload.bans {
            if ban.remaining_secs > 0 {
                if let Ok(ip) = ban.ip.parse() {
                    security
                        .ban_manager()
                        .ban(ip, std::time::Duration::from_secs(ban.remaining_secs));
                    restored_bans += 1;
                }
            }
        }
    }

    // Restore quotas
    if let Some(ref qt) = state.quota_tracker {
        for (username, usage) in &payload.quotas {
            qt.restore_user_usage(
                username,
                usage.daily_bytes,
                usage.daily_connections,
                usage.monthly_bytes,
                usage.monthly_connections,
                usage.total_bytes,
            );
            restored_quotas += 1;
        }
    }

    ApiResponse::ok(serde_json::json!({
        "restored_bans": restored_bans,
        "restored_quotas": restored_quotas,
    }))
}
