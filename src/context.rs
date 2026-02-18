use crate::alerting::AlertEngine;
use crate::audit::AuditLogger;
use crate::auth::AuthService;
use crate::config::types::AppConfig;
use crate::metrics::MetricsRegistry;
use crate::persistence::userdata::UserDataStore;
use crate::proxy::ProxyEngine;
use crate::quota::QuotaTracker;
use crate::security::SecurityManager;
use crate::webhooks::WebhookDispatcher;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

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
    /// Per-user cancellation tokens for kick functionality.
    /// Each authenticated SSH session registers its token here;
    /// the kick API cancels all tokens for a given username.
    pub kick_tokens: Arc<DashMap<String, Vec<CancellationToken>>>,
    /// Per-user data store for shell history, bookmarks, preferences.
    pub userdata_store: Option<Arc<UserDataStore>>,
}
