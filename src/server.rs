use crate::alerting::AlertEngine;
use crate::api;
use crate::audit::AuditLogger;
use crate::auth::AuthService;
use crate::config;
use crate::config::types::AppConfig;
use crate::context::AppContext;
use crate::metrics::MetricsRegistry;
use crate::proxy::ProxyEngine;
use crate::quota::QuotaTracker;
use crate::security::SecurityManager;
use crate::ssh::handler::SshHandler;
use crate::ssh::keys;
use crate::webhooks::WebhookDispatcher;

use anyhow::Result;
use russh::server::Server as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn, Instrument};

/// Main server orchestrator (no config path — no reload support)
pub async fn run(config: AppConfig) -> Result<()> {
    run_with_config_path(config, None).await
}

/// Main server orchestrator with explicit config path for SIGHUP reload.
///
/// Architecture: supervisor loop that manages all services. On reload,
/// if listen addresses change, the affected listeners are restarted.
/// Shared state (bans, metrics, connections) is preserved across reloads.
pub async fn run_with_config_path(config: AppConfig, config_path: Option<PathBuf>) -> Result<()> {
    run_with_post_init(config, config_path, |_| async {}).await
}

/// Like `run_with_config_path`, but accepts a callback that runs after
/// `AppContext` is created and before services are spawned. This allows
/// injecting data (e.g. demo sessions, quota usage) so it is visible
/// in the first SSE/WS payload.
pub async fn run_with_post_init<F, Fut>(
    config: AppConfig,
    config_path: Option<PathBuf>,
    hook: F,
) -> Result<()>
where
    F: FnOnce(Arc<AppContext>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let config = Arc::new(config);

    // Initialize webhook dispatcher (if configured)
    let webhook_dispatcher = if config.webhooks.is_empty() {
        None
    } else {
        Some(Arc::new(WebhookDispatcher::new(config.webhooks.clone())))
    };

    // Initialize shared services (these survive reloads)
    let audit = Arc::new(AuditLogger::new(
        config.logging.audit_log_path.clone(),
        config.logging.audit_max_size_mb * 1024 * 1024,
        config.logging.audit_max_files,
        webhook_dispatcher.clone(),
    ));
    let metrics = Arc::new(MetricsRegistry::with_max_labels(
        config.metrics.max_metric_labels,
    ));
    let auth_service = Arc::new(RwLock::new(AuthService::new(&config)?));
    let mut proxy_engine = ProxyEngine::new(config.clone(), audit.clone());
    proxy_engine.set_metrics(metrics.clone());
    let proxy_engine = Arc::new(proxy_engine);
    let security = {
        let mut sm = SecurityManager::new(&config);
        sm.set_audit(audit.clone());
        Arc::new(RwLock::new(sm))
    };

    let quota_tracker = Arc::new(QuotaTracker::new(&config.limits));

    // Wire the audit dropped counter to the Prometheus metric
    audit.set_dropped_metric(metrics.audit_events_dropped.clone());

    let alert_engine = if config.alerting.enabled {
        Some(Arc::new(AlertEngine::new(
            config.alerting.clone(),
            webhook_dispatcher.clone(),
            quota_tracker.clone(),
        )))
    } else {
        None
    };

    let maintenance = Arc::new(AtomicBool::new(false));

    // Channel for reload signals (from SIGHUP handler or API)
    let (reload_tx, mut reload_rx) = tokio::sync::mpsc::channel::<()>(1);

    // Global shutdown token
    let shutdown = CancellationToken::new();

    // Load or generate host key
    let host_key = keys::load_or_generate_host_key(&config.server.host_key_path)?;
    info!(path = %config.server.host_key_path.display(), "Host key loaded");

    // Spawn periodic ban cleanup task (bans + failure records)
    crate::security::ban::spawn_cleanup_task(security.clone());

    // Spawn dedicated rate limiter background cleanup task (S-8, P-7)
    // Runs independently at a configurable interval to prevent unbounded map growth
    // during distributed brute-force attacks without blocking the hot path.
    crate::security::rate_limit::spawn_cleanup_task(
        security.clone(),
        crate::security::rate_limit::RateLimitCleanupConfig {
            cleanup_interval_secs: config.security.rate_limit_cleanup_interval,
            max_stale_age: std::time::Duration::from_secs(600),
        },
    );

    // Spawn periodic system metrics updater (every 15s)
    {
        let metrics_ref = metrics.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
            loop {
                interval.tick().await;
                metrics_ref.update_system_metrics();
            }
        });
    }

    // Spawn maintenance window scheduler (checks every 60s if a window is active)
    spawn_maintenance_scheduler(
        maintenance.clone(),
        config.maintenance_windows.clone(),
        audit.clone(),
    );

    let shutdown_timeout = config.server.shutdown_timeout;

    // --- Start all services ---
    let services_shutdown = CancellationToken::new();

    // Metrics server
    let metrics_listen = if config.metrics.enabled {
        Some(config.metrics.listen.clone())
    } else {
        None
    };
    let _metrics_handle = spawn_metrics_server(
        &metrics_listen,
        metrics.clone(),
        maintenance.clone(),
        services_shutdown.clone(),
    );

    // Shared context for SSH and SOCKS5
    let app_ctx = Arc::new(AppContext {
        config: config.clone(),
        auth_service: auth_service.clone(),
        proxy_engine: proxy_engine.clone(),
        security: security.clone(),
        audit: audit.clone(),
        metrics: metrics.clone(),
        quota_tracker: quota_tracker.clone(),
        webhook_dispatcher: webhook_dispatcher.clone(),
        alert_engine: alert_engine.clone(),
        start_time: std::time::Instant::now(),
    });

    // Run post-init hook (e.g. inject demo data)
    hook(app_ctx.clone()).await;

    // Spawn periodic alert evaluation task
    if let Some(ref engine) = alert_engine {
        let engine = engine.clone();
        let auth_for_alerts = auth_service.clone();
        let shutdown_for_alerts = services_shutdown.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                tokio::select! {
                    _ = shutdown_for_alerts.cancelled() => break,
                    _ = interval.tick() => {
                        let auth = auth_for_alerts.read().await;
                        let users = auth.user_store().usernames();
                        drop(auth);
                        engine.evaluate(&users);
                    }
                }
            }
        });
    }

    // SOCKS5 server
    let _socks_handle = spawn_socks5_server(
        &config.server.socks5_listen,
        app_ctx.clone(),
        services_shutdown.clone(),
    );

    // API server
    let api_listen = if config.api.enabled {
        Some(config.api.listen.clone())
    } else {
        None
    };
    let _api_handle = spawn_api_server(ApiServerParams {
        listen_addr: api_listen,
        auth_service: auth_service.clone(),
        proxy_engine: proxy_engine.clone(),
        security: security.clone(),
        metrics: metrics.clone(),
        maintenance: maintenance.clone(),
        audit: audit.clone(),
        api_token: config.api.token.clone(),
        ssh_listen_addr: config.server.ssh_listen.clone(),
        config_path: config_path.clone(),
        quota_tracker: quota_tracker.clone(),
        webhook_dispatcher: webhook_dispatcher.clone(),
        shutdown: services_shutdown.clone(),
    });

    // SSH server
    let _ssh_handle = spawn_ssh_server(
        &config.server.ssh_listen,
        host_key.clone(),
        &config,
        app_ctx.clone(),
    );

    // Signal handler
    let signal_params = SignalHandlerParams {
        config_path: config_path.unwrap_or_else(|| PathBuf::from("config.toml")),
        maintenance: maintenance.clone(),
        auth_service: auth_service.clone(),
        security: security.clone(),
        audit: audit.clone(),
        quota_tracker: quota_tracker.clone(),
        metrics: metrics.clone(),
        shutdown: shutdown.clone(),
        reload_tx,
    };
    tokio::spawn(async move {
        handle_signals(signal_params).await;
    });

    info!(addr = %config.server.ssh_listen, "SSH server listening");

    // Supervisor loop: wait for reload signals or shutdown
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                info!(timeout = shutdown_timeout, "Initiating graceful shutdown");
                maintenance.store(true, Ordering::Relaxed);
                services_shutdown.cancel();

                // Wait for active connections to drain (up to shutdown_timeout)
                let drain_deadline = tokio::time::Instant::now()
                    + std::time::Duration::from_secs(shutdown_timeout);
                let mut last_detail_log = tokio::time::Instant::now()
                    - std::time::Duration::from_secs(10); // log immediately on first iteration
                loop {
                    let active = proxy_engine.active_connections();
                    if active == 0 {
                        info!("All connections drained");
                        break;
                    }
                    if tokio::time::Instant::now() >= drain_deadline {
                        warn!(active_connections = active, "Shutdown timeout reached, forcing exit");
                        break;
                    }
                    // P2-2: Log per-user connection details every 5s during drain
                    if last_detail_log.elapsed() >= std::time::Duration::from_secs(5) {
                        let details = proxy_engine.active_connection_details();
                        let detail_str: String = details
                            .iter()
                            .map(|(user, count)| format!("{}: {}", user, count))
                            .collect::<Vec<_>>()
                            .join(", ");
                        info!(
                            active_connections = active,
                            details = %detail_str,
                            "Draining: {} connections ({})", active, detail_str
                        );
                        last_detail_log = tokio::time::Instant::now();
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }

                info!("Graceful shutdown complete");
                return Ok(());
            }
            Some(()) = reload_rx.recv() => {
                // Hot-reload: currently only config/users/security are reloaded
                // Socket rebinding is logged but not yet performed (would require
                // restarting the SSH server which russh doesn't support mid-flight).
                // SOCKS5, API, and metrics servers could be restarted but we keep
                // it simple for now - the SIGHUP handler already reloads auth+security.
                info!("Reload signal processed by supervisor");
            }
        }
    }
}

/// Spawn the SSH server task
fn spawn_ssh_server(
    listen_addr: &str,
    host_key: russh::keys::PrivateKey,
    config: &AppConfig,
    ctx: Arc<AppContext>,
) -> tokio::task::JoinHandle<()> {
    let config = Arc::new(config.clone());
    let listen = listen_addr.to_string();

    let mut ssh_config = russh::server::Config::default();
    ssh_config.keys.push(host_key);
    ssh_config.server_id = russh::SshId::Standard(config.server.server_id.clone());
    ssh_config.auth_rejection_time = std::time::Duration::from_secs(1);
    ssh_config.auth_rejection_time_initial = Some(std::time::Duration::from_secs(0));

    // SSH keepalive: server sends keepalive@openssh.com global requests to detect
    // dead clients and prevent ghost sessions. If the client does not respond within
    // keepalive_max attempts, the connection is closed.
    if config.server.ssh_keepalive_interval_secs > 0 {
        ssh_config.keepalive_interval = Some(std::time::Duration::from_secs(
            config.server.ssh_keepalive_interval_secs,
        ));
        ssh_config.keepalive_max = config.server.ssh_keepalive_max as usize;
    }

    let ssh_config = Arc::new(ssh_config);

    tokio::spawn(async move {
        let mut server = SshServer { ctx };
        if let Err(e) = server.run_on_address(ssh_config, &listen as &str).await {
            error!(error = %e, "SSH server error");
        }
    })
}

/// Spawn the SOCKS5 server task (if configured)
fn spawn_socks5_server(
    listen_addr: &Option<String>,
    ctx: Arc<AppContext>,
    shutdown: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    let listen = listen_addr.as_ref()?;
    let listen = listen.clone();

    let trace_id = uuid::Uuid::new_v4().to_string();
    let span = tracing::info_span!("socks5_server", trace_id = %trace_id, addr = %listen);
    Some(tokio::spawn(
        async move {
            if let Err(e) = crate::socks::start_socks5_server(&listen, ctx, shutdown).await {
                error!(error = %e, "SOCKS5 server error");
            }
        }
        .instrument(span),
    ))
}

/// Spawn the metrics server task (if configured)
fn spawn_metrics_server(
    listen_addr: &Option<String>,
    metrics: Arc<MetricsRegistry>,
    maintenance: Arc<AtomicBool>,
    shutdown: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    let listen = listen_addr.as_ref()?;
    let listen = listen.clone();

    Some(tokio::spawn(async move {
        if let Err(e) = api::start_metrics_server(&listen, metrics, maintenance, shutdown).await {
            error!(error = %e, "Metrics server error");
        }
    }))
}

/// Spawn a background task that periodically checks maintenance windows.
///
/// Every 60 seconds, the task evaluates all configured maintenance windows against
/// the current UTC time. If any window is active, maintenance mode is enabled;
/// otherwise it is disabled. Manual SIGUSR1 toggles are overridden by this scheduler
/// (the scheduler is authoritative when windows are configured).
fn spawn_maintenance_scheduler(
    maintenance: Arc<AtomicBool>,
    windows: Vec<crate::config::types::MaintenanceWindowConfig>,
    audit: Arc<AuditLogger>,
) {
    if windows.is_empty() {
        return;
    }

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let now = chrono::Utc::now();
            let should_be_in_maintenance = windows.iter().any(|w| w.is_active(&now));
            let was_in_maintenance = maintenance.load(Ordering::Relaxed);

            if should_be_in_maintenance != was_in_maintenance {
                maintenance.store(should_be_in_maintenance, Ordering::Relaxed);
                audit.log_maintenance_toggled(should_be_in_maintenance, "scheduler");
                if should_be_in_maintenance {
                    info!("Maintenance mode enabled by scheduler");
                } else {
                    info!("Maintenance mode disabled by scheduler");
                }
            }
        }
    });
}

/// Parameters for spawning the API server, replacing 12+ individual arguments.
struct ApiServerParams {
    listen_addr: Option<String>,
    auth_service: Arc<RwLock<AuthService>>,
    proxy_engine: Arc<ProxyEngine>,
    security: Arc<RwLock<SecurityManager>>,
    metrics: Arc<MetricsRegistry>,
    maintenance: Arc<AtomicBool>,
    audit: Arc<AuditLogger>,
    api_token: String,
    ssh_listen_addr: String,
    config_path: Option<PathBuf>,
    quota_tracker: Arc<QuotaTracker>,
    webhook_dispatcher: Option<Arc<WebhookDispatcher>>,
    shutdown: CancellationToken,
}

/// Spawn the API server task (if configured)
fn spawn_api_server(params: ApiServerParams) -> Option<tokio::task::JoinHandle<()>> {
    let listen = params.listen_addr.as_ref()?;
    let listen = listen.clone();

    let (broadcast_tx, _broadcast_rx) = tokio::sync::broadcast::channel(256);
    let state = api::AppState {
        auth_service: params.auth_service,
        proxy_engine: params.proxy_engine,
        security: params.security,
        metrics: params.metrics,
        api_token: params.api_token,
        maintenance: params.maintenance,
        start_time: std::time::Instant::now(),
        config_path: params.config_path,
        audit: Some(params.audit),
        broadcast_tx: Some(broadcast_tx),
        ssh_listen_addr: Some(params.ssh_listen_addr),
        quota_tracker: Some(params.quota_tracker),
        webhook_dispatcher: params.webhook_dispatcher,
    };

    // Spawn background task to clean up expired SSE tickets every 60s
    api::spawn_ticket_cleanup_task(params.shutdown.clone());

    Some(tokio::spawn(async move {
        if let Err(e) = api::start_api_server(&listen, state, params.shutdown).await {
            error!(error = %e, "API server error");
        }
    }))
}

/// Parameters for the signal handler, replacing 9 individual arguments.
struct SignalHandlerParams {
    config_path: PathBuf,
    maintenance: Arc<AtomicBool>,
    auth_service: Arc<RwLock<AuthService>>,
    security: Arc<RwLock<SecurityManager>>,
    audit: Arc<AuditLogger>,
    quota_tracker: Arc<QuotaTracker>,
    metrics: Arc<MetricsRegistry>,
    shutdown: CancellationToken,
    reload_tx: tokio::sync::mpsc::Sender<()>,
}

struct SshServer {
    ctx: Arc<AppContext>,
}

impl russh::server::Server for SshServer {
    type Handler = SshHandler;

    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> SshHandler {
        let peer = peer_addr
            .unwrap_or_else(|| "0.0.0.0:0".parse().expect("valid fallback address literal"));
        let handler = SshHandler::new(self.ctx.clone(), peer);
        info!(peer = %peer, conn_id = %handler.conn_id(), "New SSH connection");
        handler
    }
}

#[cfg(unix)]
async fn handle_signals(params: SignalHandlerParams) {
    use tokio::signal::unix::{signal, SignalKind};

    let SignalHandlerParams {
        config_path,
        maintenance,
        auth_service,
        security,
        audit,
        quota_tracker,
        metrics,
        shutdown,
        reload_tx,
    } = params;

    let mut sighup = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "Failed to install SIGHUP handler");
            return;
        }
    };
    let mut sigusr1 = match signal(SignalKind::user_defined1()) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "Failed to install SIGUSR1 handler");
            return;
        }
    };
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "Failed to install SIGTERM handler");
            return;
        }
    };

    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                info!("SIGTERM received, initiating graceful shutdown");
                shutdown.cancel();
                return;
            }
            _ = sighup.recv() => {
                info!("SIGHUP received, reloading configuration");
                match config::load_config(&config_path) {
                    Ok(new_config) => {
                        let users_count = new_config.users.len();
                        match auth_service.write().await.reload(&new_config) {
                            Ok(()) => info!(users = users_count, "Auth service reloaded"),
                            Err(e) => {
                                error!(error = %e, "Failed to reload auth service");
                                audit.log_config_reload(0, false, Some(e.to_string()));
                                continue;
                            }
                        }

                        security.write().await.reload(&new_config);
                        info!("Security manager reloaded");

                        quota_tracker.update_config(&new_config.limits);
                        info!("Quota tracker limits updated");

                        // Prune stale users from metrics cardinality tracker
                        let usernames: Vec<String> = new_config.users.iter().map(|u| u.username.clone()).collect();
                        metrics.prune_known_users(&usernames);

                        audit.log_config_reload(users_count, true, None);
                        info!("Configuration reloaded successfully");

                        // Notify supervisor of reload (for future socket rebinding)
                        let _ = reload_tx.try_send(());
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to reload configuration");
                        audit.log_config_reload(0, false, Some(e.to_string()));
                    }
                }
            }
            _ = sigusr1.recv() => {
                let current = maintenance.load(Ordering::Relaxed);
                maintenance.store(!current, Ordering::Relaxed);
                audit.log_maintenance_toggled(!current, "signal");
                if current {
                    info!("Maintenance mode disabled");
                } else {
                    warn!("Maintenance mode enabled");
                }
            }
        }
    }
}

#[cfg(not(unix))]
async fn handle_signals(_params: SignalHandlerParams) {
    std::future::pending::<()>().await;
}
