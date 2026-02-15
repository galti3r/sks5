use crate::alerting::AlertEngine;
use crate::audit::AuditLogger;
use crate::auth::AuthService;
use crate::config::types::AppConfig;
use crate::metrics::MetricsRegistry;
use crate::proxy::ProxyEngine;
use crate::quota::QuotaTracker;
use crate::security::SecurityManager;
use crate::webhooks::WebhookDispatcher;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Shared application context, replacing scattered Arc parameters
pub struct AppContext {
    pub config: Arc<AppConfig>,
    pub auth_service: Arc<RwLock<AuthService>>,
    pub proxy_engine: Arc<ProxyEngine>,
    pub security: Arc<RwLock<SecurityManager>>,
    pub audit: Arc<AuditLogger>,
    pub metrics: Arc<MetricsRegistry>,
    pub quota_tracker: Arc<QuotaTracker>,
    pub webhook_dispatcher: Option<Arc<WebhookDispatcher>>,
    pub alert_engine: Option<Arc<AlertEngine>>,
    pub start_time: Instant,
}
