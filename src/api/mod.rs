pub mod backup;
pub mod bans;
pub mod broadcast;
pub mod connections;
pub mod dashboard;
pub mod groups;
pub mod kick;
pub mod maintenance;
pub mod pagination;
pub mod quotas;
pub mod reload;
pub mod sessions;
pub mod sse;
pub mod ssh_config;
pub mod users;
pub mod ws;

use crate::audit::AuditLogger;
use crate::auth::AuthService;
use crate::metrics::MetricsRegistry;
use crate::proxy::ProxyEngine;
use crate::quota::QuotaTracker;
use crate::security::SecurityManager;
use crate::webhooks::WebhookDispatcher;
use axum::{
    extract::{DefaultBodyLimit, MatchedPath, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Redirect},
    routing::{delete, get, post},
    Router,
};
use dashmap::DashMap;
use prometheus_client::encoding::text::encode;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::info;

/// Used HMAC tickets for replay protection (ticket_hash -> expiry timestamp).
/// Bounded to MAX_USED_TICKETS entries to prevent memory exhaustion.
static USED_TICKETS: std::sync::OnceLock<DashMap<String, u64>> = std::sync::OnceLock::new();

/// Maximum number of tracked used tickets before forced cleanup.
const MAX_USED_TICKETS: usize = 10_000;

fn used_tickets() -> &'static DashMap<String, u64> {
    USED_TICKETS.get_or_init(DashMap::new)
}

/// Spawn a background task that periodically cleans up expired SSE tickets.
/// Should be called once at server startup.
pub fn spawn_ticket_cleanup_task(shutdown: tokio_util::sync::CancellationToken) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        interval.tick().await; // skip immediate first tick
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    used_tickets().retain(|_, expiry| *expiry > now);
                }
                _ = shutdown.cancelled() => break,
            }
        }
    });
}

/// Parse a query param value as boolean (true/1/yes = true, anything else = false).
pub fn is_truthy(val: Option<&str>) -> bool {
    matches!(val, Some("true" | "1" | "yes"))
}

/// Unified API response envelope for consistent JSON output.
#[derive(Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> (StatusCode, axum::Json<Self>) {
        (
            StatusCode::OK,
            axum::Json(Self {
                success: true,
                data: Some(data),
                error: None,
            }),
        )
    }

    pub fn ok_with_status(status: StatusCode, data: T) -> (StatusCode, axum::Json<Self>) {
        (
            status,
            axum::Json(Self {
                success: status.is_success(),
                data: Some(data),
                error: None,
            }),
        )
    }
}

impl ApiResponse<()> {
    pub fn err(status: StatusCode, msg: impl Into<String>) -> (StatusCode, axum::Json<Self>) {
        (
            status,
            axum::Json(Self {
                success: false,
                data: None,
                error: Some(msg.into()),
            }),
        )
    }
}

#[derive(Clone)]
pub struct AppState {
    pub auth_service: Arc<RwLock<AuthService>>,
    pub proxy_engine: Arc<ProxyEngine>,
    pub security: Arc<RwLock<SecurityManager>>,
    pub metrics: Arc<MetricsRegistry>,
    pub api_token: String,
    pub maintenance: Arc<std::sync::atomic::AtomicBool>,
    pub start_time: std::time::Instant,
    pub config_path: Option<PathBuf>,
    pub audit: Option<Arc<AuditLogger>>,
    pub broadcast_tx: Option<tokio::sync::broadcast::Sender<(String, Vec<String>)>>,
    pub ssh_listen_addr: Option<String>,
    pub quota_tracker: Option<Arc<QuotaTracker>>,
    pub webhook_dispatcher: Option<Arc<WebhookDispatcher>>,
    pub kick_tokens: Option<Arc<DashMap<String, Vec<CancellationToken>>>>,
}

/// Start the metrics/health HTTP server with graceful shutdown support.
pub async fn start_metrics_server(
    listen_addr: &str,
    metrics: Arc<MetricsRegistry>,
    maintenance: Arc<std::sync::atomic::AtomicBool>,
    shutdown: tokio_util::sync::CancellationToken,
) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/health", get(health_handler))
        .route("/livez", get(|| async { "ok" }))
        .route("/readyz", get(metrics_readyz_handler))
        .with_state((metrics, maintenance));

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    info!(addr = %listen_addr, "Metrics server listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await?;
    Ok(())
}

async fn metrics_handler(
    State((metrics, _)): State<(Arc<MetricsRegistry>, Arc<std::sync::atomic::AtomicBool>)>,
) -> impl IntoResponse {
    let mut buffer = String::new();
    if encode(&mut buffer, &metrics.registry).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "encoding error").into_response();
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        buffer,
    )
        .into_response()
}

async fn health_handler(
    State((_, maintenance)): State<(Arc<MetricsRegistry>, Arc<std::sync::atomic::AtomicBool>)>,
) -> impl IntoResponse {
    if maintenance.load(std::sync::atomic::Ordering::Relaxed) {
        (StatusCode::SERVICE_UNAVAILABLE, "maintenance")
    } else {
        (StatusCode::OK, "ok")
    }
}

/// Simplified readiness probe for the metrics server (no auth_service access).
async fn metrics_readyz_handler(
    State((_, maintenance)): State<(Arc<MetricsRegistry>, Arc<std::sync::atomic::AtomicBool>)>,
) -> impl IntoResponse {
    let maint = maintenance.load(std::sync::atomic::Ordering::Relaxed);
    let ready = !maint;

    let body = ReadyzResponse {
        ready,
        checks: ReadyzChecks {
            auth: "ok", // Not available on metrics server; assume ok
            metrics: "ok",
            maintenance: if ready { "disabled" } else { "enabled" },
        },
    };

    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status, axum::Json(body)).into_response()
}

/// Readiness probe response body.
#[derive(Serialize)]
struct ReadyzResponse {
    ready: bool,
    checks: ReadyzChecks,
}

#[derive(Serialize)]
struct ReadyzChecks {
    auth: &'static str,
    metrics: &'static str,
    maintenance: &'static str,
}

async fn readyz_handler(State(state): State<AppState>) -> impl IntoResponse {
    let maint = state.maintenance.load(std::sync::atomic::Ordering::Relaxed);

    // Check auth service is loaded and has users
    let auth_ok = {
        let auth = state.auth_service.read().await;
        !auth.user_store().is_empty()
    };

    // Metrics are always available if we got this far (they are created at startup)
    let metrics_ok = true;

    let maintenance_check = !maint;

    let all_ok = auth_ok && metrics_ok && maintenance_check;

    let body = ReadyzResponse {
        ready: all_ok,
        checks: ReadyzChecks {
            auth: if auth_ok { "ok" } else { "no_users_loaded" },
            metrics: if metrics_ok { "ok" } else { "unavailable" },
            maintenance: if maintenance_check {
                "disabled"
            } else {
                "enabled"
            },
        },
    };

    let status = if all_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status, axum::Json(body)).into_response()
}

/// API metrics middleware: records request count and duration per route pattern.
async fn api_metrics_middleware(
    State(state): State<AppState>,
    matched_path: Option<MatchedPath>,
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> impl IntoResponse {
    let method = req.method().to_string();
    let path = matched_path
        .map(|mp| mp.as_str().to_string())
        .unwrap_or_else(|| "unmatched".to_string());
    let start = std::time::Instant::now();

    let response = next.run(req).await;

    let duration = start.elapsed().as_secs_f64();
    let status = response.status().as_u16();

    state.metrics.record_http_request(&method, &path, status);
    state
        .metrics
        .record_http_request_duration(&method, &path, duration);

    response
}

/// Bearer token auth middleware.
/// Accepts `Authorization: Bearer <token>` header, `?token=<token>` query param,
/// or `?ticket=<ticket>` HMAC ticket (for SSE connections).
/// The query param fallback is needed for SSE (EventSource can't set headers) and browser dashboard.
async fn auth_middleware(
    State(state): State<AppState>,
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> impl IntoResponse {
    // Defense-in-depth: if token is empty, reject all requests (config validation
    // should prevent this, but guard against misconfiguration).
    if state.api_token.is_empty() {
        return (StatusCode::SERVICE_UNAVAILABLE, "service unavailable").into_response();
    }

    use subtle::ConstantTimeEq;
    let expected = state.api_token.as_bytes();

    // Check Authorization: Bearer header first
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    if let Some(h) = auth_header {
        if h.starts_with("Bearer ") {
            let provided = &h.as_bytes()[7..];
            if provided.len() == expected.len() && bool::from(provided.ct_eq(expected)) {
                return next.run(req).await;
            }
            return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
        }
    }

    // API-001: Only accept HMAC ticket for query-based auth (no raw token in URL).
    // The ?ticket= mechanism uses short-lived HMAC-signed tokens issued via POST /api/sse-ticket.
    if let Some(query) = req.uri().query() {
        for pair in query.split('&') {
            if let Some(value) = pair.strip_prefix("ticket=") {
                // URL-decode the ticket (encodeURIComponent encodes ':' as '%3A')
                let decoded = percent_encoding::percent_decode_str(value).decode_utf8_lossy();
                if verify_sse_ticket(&decoded, &state.api_token) {
                    return next.run(req).await;
                }
            }
        }
    }

    (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
}

#[derive(Serialize)]
struct StatusInfo {
    status: String,
    uptime_secs: u64,
    active_connections: u32,
    total_users: usize,
    maintenance: bool,
}

async fn status_handler(State(state): State<AppState>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed().as_secs();
    let active = state.proxy_engine.active_connections();
    let auth = state.auth_service.read().await;
    let total_users = auth.user_store().len();
    let maint = state.maintenance.load(std::sync::atomic::Ordering::Relaxed);

    ApiResponse::ok(StatusInfo {
        status: if maint {
            "maintenance".to_string()
        } else {
            "ok".to_string()
        },
        uptime_secs: uptime,
        active_connections: active,
        total_users,
        maintenance: maint,
    })
}

#[derive(Serialize)]
struct HealthDetail {
    status: &'static str,
    maintenance: bool,
    active_connections: u32,
    uptime_secs: u64,
}

async fn api_health_handler(State(state): State<AppState>) -> impl IntoResponse {
    let maint = state.maintenance.load(std::sync::atomic::Ordering::Relaxed);
    let active = state.proxy_engine.active_connections();
    let uptime = state.start_time.elapsed().as_secs();

    let detail = HealthDetail {
        status: if maint { "maintenance" } else { "ok" },
        maintenance: maint,
        active_connections: active,
        uptime_secs: uptime,
    };

    let status = if maint {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };

    ApiResponse::ok_with_status(status, detail)
}

/// SSE ticket validity in seconds
const SSE_TICKET_VALIDITY_SECS: u64 = 30;

#[derive(Serialize)]
struct SseTicketResponse {
    ticket: String,
    expires_in: u64,
}

/// P0-2: Issue an HMAC-SHA256 ticket for SSE connections.
/// POST /api/sse-ticket (requires Bearer auth) -> { ticket, expires_in }
async fn sse_ticket_handler(State(state): State<AppState>) -> impl IntoResponse {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Add a random 128-bit nonce to prevent ticket prediction (S-7)
    let nonce: u128 = rand::random();

    // Derive a signing key from the API token
    let signing_key = format!("sks5-sse-ticket:{}", state.api_token);
    let mut mac = match Hmac::<Sha256>::new_from_slice(signing_key.as_bytes()) {
        Ok(m) => m,
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "hmac error").into_response();
        }
    };
    mac.update(format!("{}:{}", timestamp, nonce).as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    let ticket = format!("{}:{}:{}", timestamp, nonce, signature);

    ApiResponse::ok(SseTicketResponse {
        ticket,
        expires_in: SSE_TICKET_VALIDITY_SECS,
    })
    .into_response()
}

/// Verify an SSE ticket (HMAC-SHA256 with timestamp and nonce).
/// Ticket format: `timestamp:nonce:signature`
pub fn verify_sse_ticket(ticket: &str, api_token: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let parts: Vec<&str> = ticket.splitn(3, ':').collect();
    if parts.len() != 3 {
        return false;
    }

    let timestamp: u64 = match parts[0].parse() {
        Ok(t) => t,
        Err(_) => return false,
    };

    // Validate nonce is a valid u128 (prevents malformed tickets)
    let nonce: u128 = match parts[1].parse() {
        Ok(n) => n,
        Err(_) => return false,
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Check ticket age
    if now.saturating_sub(timestamp) > SSE_TICKET_VALIDITY_SECS {
        return false;
    }

    let signing_key = format!("sks5-sse-ticket:{}", api_token);
    let mut mac = match Hmac::<Sha256>::new_from_slice(signing_key.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(format!("{}:{}", timestamp, nonce).as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    // Constant-time comparison
    use subtle::ConstantTimeEq;
    let a = parts[2].as_bytes();
    let b = expected.as_bytes();
    let valid = a.len() == b.len() && bool::from(a.ct_eq(b));

    if valid {
        // Replay protection: reject if this ticket was already used
        let ticket_key = format!("{}:{}", timestamp, nonce);
        if used_tickets().contains_key(&ticket_key) {
            return false;
        }
        // Enforce capacity bound to prevent memory exhaustion under sustained traffic
        if used_tickets().len() >= MAX_USED_TICKETS {
            used_tickets().retain(|_, expiry| *expiry > now);
        }
        // Mark ticket as used with its expiry time
        used_tickets().insert(ticket_key, timestamp + SSE_TICKET_VALIDITY_SECS);
    }

    valid
}

/// Start the management API server with graceful shutdown support.
pub async fn start_api_server(
    listen_addr: &str,
    state: AppState,
    shutdown: tokio_util::sync::CancellationToken,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    info!(addr = %listen_addr, "API server listening");
    start_api_server_on_listener(listener, state, shutdown).await
}

/// Start the API server on a pre-bound listener (avoids TOCTOU port races in tests).
pub async fn start_api_server_on_listener(
    listener: tokio::net::TcpListener,
    state: AppState,
    shutdown: tokio_util::sync::CancellationToken,
) -> anyhow::Result<()> {
    // Authenticated routes
    let authed = Router::new()
        .route("/api/health", get(api_health_handler))
        .route("/api/status", get(status_handler))
        .route("/api/users", get(users::list_users))
        .route("/api/users/{username}", get(users::get_user_detail))
        .route("/api/connections", get(connections::list_connections))
        .route("/api/bans", get(bans::list_bans))
        .route("/api/bans/{ip}", delete(bans::delete_ban))
        .route("/api/maintenance", post(maintenance::toggle_maintenance))
        .route("/api/reload", post(reload::reload_config))
        .route("/api/broadcast", post(broadcast::broadcast_message))
        .route("/api/kick/{username}", post(kick::kick_user))
        .route("/api/ssh-config", get(ssh_config::ssh_config_snippet))
        .route("/api/quotas", get(quotas::list_quotas))
        .route("/api/quotas/{username}", get(quotas::get_user_quota))
        .route(
            "/api/quotas/{username}/reset",
            post(quotas::reset_user_quota),
        )
        .route("/api/groups", get(groups::list_groups))
        .route("/api/groups/{name}", get(groups::get_group))
        .route("/api/sessions", get(sessions::list_sessions))
        .route("/api/sessions/{username}", get(sessions::get_user_sessions))
        .route("/api/sse-ticket", post(sse_ticket_handler))
        .route("/api/backup", get(backup::backup_handler))
        .route("/api/restore", post(backup::restore_handler))
        .route("/api/ws", get(ws::ws_handler))
        .route("/api/events", get(sse::sse_events))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // Unauthenticated routes: liveness/readiness probes + static dashboard (no sensitive data)
    let app = Router::new()
        .route("/livez", get(|| async { "ok" }))
        .route("/readyz", get(readyz_handler))
        .route("/", get(|| async { Redirect::permanent("/dashboard") }))
        .route("/dashboard", get(dashboard::serve_dashboard))
        .merge(authed)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            api_metrics_middleware,
        ))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(state);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await?;
    Ok(())
}
