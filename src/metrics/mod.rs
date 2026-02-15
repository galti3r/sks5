pub mod collectors;

/// Well-known error type constants for metrics
pub mod error_types {
    pub const AUTH_FAILURE: &str = "auth_failure";
    pub const ACL_DENIED: &str = "acl_denied";
    pub const CONNECTION_REFUSED: &str = "connection_refused";
    pub const CONNECTION_TIMEOUT: &str = "connection_timeout";
    pub const DNS_FAILURE: &str = "dns_failure";
    pub const QUOTA_EXCEEDED: &str = "quota_exceeded";
    pub const RATE_LIMITED: &str = "rate_limited";
    pub const PROTOCOL_ERROR: &str = "protocol_error";
    pub const RELAY_ERROR: &str = "relay_error";
    pub const INTERNAL_ERROR: &str = "internal_error";
}

use collectors::{
    AuthMethodLabel, AuthMethodUserLabel, ConnectionTypeUserLabel, ErrorTypeLabel,
    HttpDurationLabel, HttpRequestLabel, ReasonLabel, UserLabel, UserTypeLabel, UserWindowLabel,
};
use dashmap::DashSet;
use prometheus_client::metrics::counter::{Atomic as CounterAtomic, Counter};
use prometheus_client::metrics::family::{Family, MetricConstructor};
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;
use std::sync::atomic::AtomicU64;

/// Constructor for connection duration histograms with predefined buckets.
#[derive(Clone)]
pub struct DurationHistogramBuilder;

/// Constructor for HTTP request duration histograms with predefined buckets.
#[derive(Clone)]
pub struct HttpDurationHistogramBuilder;

impl MetricConstructor<Histogram> for DurationHistogramBuilder {
    fn new_metric(&self) -> Histogram {
        // Buckets: 1s, 5s, 15s, 30s, 60s, 300s, 600s, 1800s, 3600s
        Histogram::new([1.0, 5.0, 15.0, 30.0, 60.0, 300.0, 600.0, 1800.0, 3600.0])
    }
}

impl MetricConstructor<Histogram> for HttpDurationHistogramBuilder {
    fn new_metric(&self) -> Histogram {
        // Buckets: 1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 5s
        Histogram::new([0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0])
    }
}

/// Constructor for connection duration histograms with network-optimized buckets.
/// Covers short-lived (sub-second) to long-lived (1 hour) connections.
#[derive(Clone)]
pub struct ConnectionDurationHistogramBuilder;

impl MetricConstructor<Histogram> for ConnectionDurationHistogramBuilder {
    fn new_metric(&self) -> Histogram {
        // Buckets: 0.1s, 0.5s, 1s, 5s, 10s, 30s, 60s, 300s (5m), 600s (10m), 1800s (30m), 3600s (1h)
        Histogram::new([
            0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0, 600.0, 1800.0, 3600.0,
        ])
    }
}

/// Centralized metrics registry with cardinality protection
pub struct MetricsRegistry {
    pub registry: Registry,
    pub connections_active: Family<UserLabel, Gauge>,
    pub connections_total: Counter,
    pub bytes_transferred: Family<UserLabel, Counter<f64, AtomicU64>>,
    pub auth_failures_total: Family<AuthMethodLabel, Counter>,
    pub auth_successes_total: Family<AuthMethodUserLabel, Counter>,
    pub errors_total: Family<ErrorTypeLabel, Counter>,
    pub banned_ips_current: Gauge,
    pub audit_events_dropped: Counter,
    pub cardinality_capped_total: Counter,
    pub quota_bandwidth_used_bytes: Family<UserWindowLabel, Counter<f64, AtomicU64>>,
    pub quota_connections_used: Family<UserWindowLabel, Counter>,
    pub quota_exceeded_total: Family<UserTypeLabel, Counter>,
    pub connection_duration_seconds: Family<UserLabel, Histogram, DurationHistogramBuilder>,
    pub connection_duration_by_type_seconds:
        Family<ConnectionTypeUserLabel, Histogram, ConnectionDurationHistogramBuilder>,
    pub connections_rejected_total: Family<ReasonLabel, Counter>,
    pub http_requests_total: Family<HttpRequestLabel, Counter>,
    pub http_request_duration_seconds:
        Family<HttpDurationLabel, Histogram, HttpDurationHistogramBuilder>,
    /// DNS cache hit counter (incremented in connector::connect_with_cache).
    pub dns_cache_hits_total: Counter,
    /// DNS cache miss counter (incremented in connector::connect_with_cache).
    pub dns_cache_misses_total: Counter,
    /// Process resident memory in bytes (updated periodically)
    pub process_resident_memory_bytes: Gauge,
    /// Process open file descriptors (updated periodically)
    pub process_open_fds: Gauge,
    /// Track known label values for cardinality cap
    known_users: DashSet<String>,
    max_labels: u32,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self::with_max_labels(100)
    }

    pub fn with_max_labels(max_labels: u32) -> Self {
        let mut registry = Registry::default();

        let connections_active = Family::<UserLabel, Gauge>::default();
        registry.register(
            "sks5_connections_active",
            "Currently active connections",
            connections_active.clone(),
        );

        let connections_total = Counter::default();
        registry.register(
            "sks5_connections_total",
            "Total connections since start (lifetime counter)",
            connections_total.clone(),
        );

        let bytes_transferred = Family::<UserLabel, Counter<f64, AtomicU64>>::default();
        registry.register(
            "sks5_bytes_transferred",
            "Total bytes transferred",
            bytes_transferred.clone(),
        );

        let auth_failures_total = Family::<AuthMethodLabel, Counter>::default();
        registry.register(
            "sks5_auth_failures_total",
            "Total authentication failures",
            auth_failures_total.clone(),
        );

        let auth_successes_total = Family::<AuthMethodUserLabel, Counter>::default();
        registry.register(
            "sks5_auth_successes_total",
            "Total authentication successes",
            auth_successes_total.clone(),
        );

        let errors_total = Family::<ErrorTypeLabel, Counter>::default();
        registry.register(
            "sks5_errors_total",
            "Total errors by type",
            errors_total.clone(),
        );

        let banned_ips_current = Gauge::default();
        registry.register(
            "sks5_banned_ips_current",
            "Currently banned IPs",
            banned_ips_current.clone(),
        );

        let audit_events_dropped = Counter::default();
        registry.register(
            "sks5_audit_events_dropped_total",
            "Total audit events dropped due to channel overflow",
            audit_events_dropped.clone(),
        );

        let cardinality_capped_total = Counter::default();
        registry.register(
            "sks5_metrics_cardinality_capped_total",
            "Times a metric label was aggregated under _other due to cardinality cap",
            cardinality_capped_total.clone(),
        );

        let quota_bandwidth_used_bytes =
            Family::<UserWindowLabel, Counter<f64, AtomicU64>>::default();
        registry.register(
            "sks5_quota_bandwidth_used_bytes",
            "Bandwidth bytes used per user and time window",
            quota_bandwidth_used_bytes.clone(),
        );

        let quota_connections_used = Family::<UserWindowLabel, Counter>::default();
        registry.register(
            "sks5_quota_connections_used",
            "Connections used per user and time period",
            quota_connections_used.clone(),
        );

        let quota_exceeded_total = Family::<UserTypeLabel, Counter>::default();
        registry.register(
            "sks5_quota_exceeded_total",
            "Total times a quota was exceeded",
            quota_exceeded_total.clone(),
        );

        let connection_duration_seconds =
            Family::<UserLabel, Histogram, DurationHistogramBuilder>::new_with_constructor(
                DurationHistogramBuilder,
            );
        registry.register(
            "sks5_connection_duration_seconds",
            "Connection duration in seconds",
            connection_duration_seconds.clone(),
        );

        let connection_duration_by_type_seconds = Family::<
            ConnectionTypeUserLabel,
            Histogram,
            ConnectionDurationHistogramBuilder,
        >::new_with_constructor(
            ConnectionDurationHistogramBuilder
        );
        registry.register(
            "sks5_connection_duration_by_type_seconds",
            "Connection duration in seconds by connection type (ssh/socks5)",
            connection_duration_by_type_seconds.clone(),
        );

        let connections_rejected_total = Family::<ReasonLabel, Counter>::default();
        registry.register(
            "sks5_connections_rejected_total",
            "Total connections rejected",
            connections_rejected_total.clone(),
        );

        let http_requests_total = Family::<HttpRequestLabel, Counter>::default();
        registry.register(
            "sks5_http_requests_total",
            "Total HTTP API requests",
            http_requests_total.clone(),
        );

        let http_request_duration_seconds = Family::<
            HttpDurationLabel,
            Histogram,
            HttpDurationHistogramBuilder,
        >::new_with_constructor(
            HttpDurationHistogramBuilder
        );
        registry.register(
            "sks5_http_request_duration_seconds",
            "HTTP request duration in seconds",
            http_request_duration_seconds.clone(),
        );

        let dns_cache_hits_total = Counter::default();
        registry.register(
            "sks5_dns_cache_hits_total",
            "Total DNS cache hits",
            dns_cache_hits_total.clone(),
        );

        let dns_cache_misses_total = Counter::default();
        registry.register(
            "sks5_dns_cache_misses_total",
            "Total DNS cache misses",
            dns_cache_misses_total.clone(),
        );

        let process_resident_memory_bytes = Gauge::default();
        registry.register(
            "process_resident_memory_bytes",
            "Resident memory size in bytes",
            process_resident_memory_bytes.clone(),
        );

        let process_open_fds = Gauge::default();
        registry.register(
            "process_open_fds",
            "Number of open file descriptors",
            process_open_fds.clone(),
        );

        Self {
            registry,
            connections_active,
            connections_total,
            bytes_transferred,
            auth_failures_total,
            auth_successes_total,
            errors_total,
            banned_ips_current,
            audit_events_dropped,
            cardinality_capped_total,
            quota_bandwidth_used_bytes,
            quota_connections_used,
            quota_exceeded_total,
            connection_duration_seconds,
            connection_duration_by_type_seconds,
            connections_rejected_total,
            http_requests_total,
            http_request_duration_seconds,
            dns_cache_hits_total,
            dns_cache_misses_total,
            process_resident_memory_bytes,
            process_open_fds,
            known_users: DashSet::new(),
            max_labels,
        }
    }

    /// Resolve a username label, capping cardinality at max_labels.
    /// Returns "_other" if the cap is exceeded for a previously unseen user.
    fn resolve_label(&self, username: &str) -> String {
        if self.known_users.contains(username) {
            return username.to_string();
        }
        if (self.known_users.len() as u32) < self.max_labels {
            let owned = username.to_string();
            self.known_users.insert(owned.clone());
            return owned;
        }
        // Cardinality cap exceeded
        self.cardinality_capped_total.inc();
        "_other".to_string()
    }

    pub fn record_auth_success(&self, username: &str, method: &str) {
        let label = self.resolve_label(username);
        self.auth_successes_total
            .get_or_create(&AuthMethodUserLabel {
                user: label,
                method: method.to_string(),
            })
            .inc();
    }

    pub fn record_auth_failure(&self, method: &str) {
        self.auth_failures_total
            .get_or_create(&AuthMethodLabel {
                method: method.to_string(),
            })
            .inc();
    }

    pub fn record_error(&self, error_type: &str) {
        self.errors_total
            .get_or_create(&ErrorTypeLabel {
                error_type: error_type.to_string(),
            })
            .inc();
    }

    pub fn record_bytes_transferred(&self, username: &str, bytes: u64) {
        let label = self.resolve_label(username);
        self.bytes_transferred
            .get_or_create(&UserLabel { user: label })
            .inner()
            .inc_by(bytes as f64);
    }

    pub fn record_quota_bandwidth(&self, username: &str, window: &str, bytes: u64) {
        let label = self.resolve_label(username);
        self.quota_bandwidth_used_bytes
            .get_or_create(&UserWindowLabel {
                user: label,
                window: window.to_string(),
            })
            .inner()
            .inc_by(bytes as f64);
    }

    pub fn record_quota_connection(&self, username: &str, period: &str) {
        let label = self.resolve_label(username);
        self.quota_connections_used
            .get_or_create(&UserWindowLabel {
                user: label,
                window: period.to_string(),
            })
            .inc();
    }

    pub fn record_connection_duration(&self, username: &str, duration_secs: f64) {
        let label = self.resolve_label(username);
        self.connection_duration_seconds
            .get_or_create(&UserLabel { user: label })
            .observe(duration_secs);
    }

    /// Record connection duration with connection type label (ssh/socks5).
    /// Also records into the existing user-only histogram for backward compatibility.
    pub fn record_typed_connection_duration(
        &self,
        username: &str,
        conn_type: &str,
        duration_secs: f64,
    ) {
        let label = self.resolve_label(username);
        // Record into the type-labeled histogram
        self.connection_duration_by_type_seconds
            .get_or_create(&ConnectionTypeUserLabel {
                conn_type: conn_type.to_string(),
                user: label.clone(),
            })
            .observe(duration_secs);
        // Also record into the existing user-only histogram for backward compatibility
        self.connection_duration_seconds
            .get_or_create(&UserLabel { user: label })
            .observe(duration_secs);
    }

    pub fn record_quota_exceeded(&self, username: &str, quota_type: &str) {
        let label = self.resolve_label(username);
        self.quota_exceeded_total
            .get_or_create(&UserTypeLabel {
                user: label,
                r#type: quota_type.to_string(),
            })
            .inc();
    }

    pub fn record_connection_rejected(&self, reason: &str) {
        self.connections_rejected_total
            .get_or_create(&ReasonLabel {
                reason: reason.to_string(),
            })
            .inc();
    }

    pub fn record_http_request(&self, method: &str, path: &str, status: u16) {
        // Pre-format status to avoid itoa allocation each time
        let status_str = match status {
            200 => "200".to_string(),
            201 => "201".to_string(),
            204 => "204".to_string(),
            400 => "400".to_string(),
            401 => "401".to_string(),
            404 => "404".to_string(),
            500 => "500".to_string(),
            503 => "503".to_string(),
            _ => status.to_string(),
        };
        self.http_requests_total
            .get_or_create(&HttpRequestLabel {
                method: method.to_string(),
                path: path.to_string(),
                status: status_str,
            })
            .inc();
    }

    pub fn record_http_request_duration(&self, method: &str, path: &str, duration_secs: f64) {
        self.http_request_duration_seconds
            .get_or_create(&HttpDurationLabel {
                method: method.to_string(),
                path: path.to_string(),
            })
            .observe(duration_secs);
    }
}

impl MetricsRegistry {
    /// Update system resource metrics (RSS memory, open FDs).
    /// Reads from /proc/self on Linux.
    pub fn update_system_metrics(&self) {
        // Read RSS from /proc/self/statm (Linux-specific)
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            if let Some(rss_pages) = statm.split_whitespace().nth(1) {
                if let Ok(pages) = rss_pages.parse::<i64>() {
                    let page_size = 4096i64; // standard page size
                    self.process_resident_memory_bytes.set(pages * page_size);
                }
            }
        }

        // Count open FDs from /proc/self/fd
        if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
            self.process_open_fds.set(entries.count() as i64);
        }
    }

    /// Remove stale users from the known_users set.
    /// Call after config reload to prevent unbounded growth.
    pub fn prune_known_users(&self, active_usernames: &[String]) {
        let active_set: std::collections::HashSet<&str> =
            active_usernames.iter().map(|s| s.as_str()).collect();
        self.known_users.retain(|u| active_set.contains(u.as_str()));
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}
