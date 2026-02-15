use crate::config::types::{AlertRule, AlertingConfig, WebhookConfig};
use crate::quota::QuotaTracker;
use crate::webhooks::WebhookDispatcher;
use dashmap::DashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::info;

/// Alert engine that evaluates rules against quota tracker data.
/// Fires webhooks when conditions are met, with deduplication to avoid spam.
pub struct AlertEngine {
    config: AlertingConfig,
    dispatcher: Option<Arc<WebhookDispatcher>>,
    quota_tracker: Arc<QuotaTracker>,
    /// Tracks which (rule_name, username) alerts have been fired to avoid spam.
    /// Cleared periodically or on reset.
    fired_alerts: DashSet<String>,
    /// Global auth failure counter (incremented externally, checked by auth_failures rules).
    auth_failure_count: AtomicU64,
}

impl AlertEngine {
    pub fn new(
        config: AlertingConfig,
        dispatcher: Option<Arc<WebhookDispatcher>>,
        quota_tracker: Arc<QuotaTracker>,
    ) -> Self {
        Self {
            config,
            dispatcher,
            quota_tracker,
            fired_alerts: DashSet::new(),
            auth_failure_count: AtomicU64::new(0),
        }
    }

    /// Check if alerting is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Record an auth failure. Called externally when authentication fails.
    /// The counter is server-wide (not per-user).
    pub fn record_auth_failure(&self) {
        self.auth_failure_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the current auth failure count.
    pub fn auth_failure_count(&self) -> u64 {
        self.auth_failure_count.load(Ordering::Relaxed)
    }

    /// Evaluate all rules against current state.
    /// Call this periodically (e.g., every 30 seconds from a background task).
    pub fn evaluate(&self, known_users: &[String]) {
        if !self.config.enabled {
            return;
        }

        for rule in &self.config.rules {
            let users_to_check: Vec<&String> = if rule.users.is_empty() {
                known_users.iter().collect()
            } else {
                rule.users.iter().collect()
            };

            for username in users_to_check {
                if self.check_rule(rule, username) {
                    self.fire_alert(rule, username);
                }
            }
        }
    }

    /// Select the bandwidth value matching the rule's `window_secs`.
    /// - <= 3600  -> hourly rolling window
    /// - <= 86400 -> daily cumulative
    /// - > 86400  -> monthly cumulative
    fn bandwidth_for_window(usage: &crate::quota::UserQuotaUsage, window_secs: u64) -> u64 {
        if window_secs <= 3600 {
            usage.hourly_bytes
        } else if window_secs <= 86400 {
            usage.daily_bytes
        } else {
            usage.monthly_bytes
        }
    }

    /// Select the connection count matching the rule's `window_secs`.
    fn connections_for_window(usage: &crate::quota::UserQuotaUsage, window_secs: u64) -> u64 {
        if window_secs <= 86400 {
            usage.daily_connections as u64
        } else {
            usage.monthly_connections as u64
        }
    }

    /// Check a single rule against a single user. Returns true if threshold exceeded.
    fn check_rule(&self, rule: &AlertRule, username: &str) -> bool {
        use crate::config::types::AlertCondition;
        let usage = self.quota_tracker.get_user_usage(username);

        match rule.condition {
            AlertCondition::BandwidthExceeded => {
                Self::bandwidth_for_window(&usage, rule.window_secs) > rule.threshold
            }
            AlertCondition::ConnectionsExceeded => {
                Self::connections_for_window(&usage, rule.window_secs) > rule.threshold
            }
            AlertCondition::MonthlyBandwidthExceeded => usage.monthly_bytes > rule.threshold,
            AlertCondition::HourlyBandwidthExceeded => usage.hourly_bytes > rule.threshold,
            AlertCondition::AuthFailures => {
                // Auth failures are server-wide, not per-user.
                // The same counter is checked for every user in the rule's scope.
                self.auth_failure_count.load(Ordering::Relaxed) > rule.threshold
            }
        }
    }

    /// Fire an alert webhook (with deduplication).
    fn fire_alert(&self, rule: &AlertRule, username: &str) {
        let key = format!("{}:{}", rule.name, username);

        // Skip if already fired
        if self.fired_alerts.contains(&key) {
            return;
        }

        self.fired_alerts.insert(key);

        info!(
            rule = %rule.name,
            user = %username,
            condition = %format!("{}", rule.condition),
            threshold = rule.threshold,
            "Alert triggered"
        );

        // Dispatch to rule-specific webhook URL if configured
        if let Some(ref url) = rule.webhook_url {
            let payload = serde_json::json!({
                "alert": rule.name,
                "condition": format!("{}", rule.condition),
                "threshold": rule.threshold,
                "username": username,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            });

            let config = WebhookConfig {
                url: url.clone(),
                events: vec![],
                secret: None,
                allow_private_ips: false,
                max_retries: 3,
                retry_delay_ms: 1000,
                max_retry_delay_ms: 30000,
            };
            let dispatcher = WebhookDispatcher::new(vec![config]);
            dispatcher.dispatch("alert.triggered", payload);
        }

        // Also dispatch to the global webhook dispatcher if available
        if let Some(ref dispatcher) = self.dispatcher {
            let payload = serde_json::json!({
                "alert": rule.name,
                "condition": format!("{}", rule.condition),
                "threshold": rule.threshold,
                "username": username,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            });
            dispatcher.dispatch("alert.triggered", payload);
        }
    }

    /// Reset fired alerts and auth failure counter (call periodically, e.g., when quotas reset).
    pub fn reset_fired(&self) {
        self.fired_alerts.clear();
        self.auth_failure_count.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{AlertCondition, AlertRule, AlertingConfig, LimitsConfig};
    use crate::quota::QuotaTracker;

    fn test_tracker() -> Arc<QuotaTracker> {
        Arc::new(QuotaTracker::new(&LimitsConfig::default()))
    }

    #[test]
    fn test_disabled_engine_does_not_evaluate() {
        let config = AlertingConfig {
            enabled: false,
            rules: vec![AlertRule {
                name: "test".to_string(),
                condition: AlertCondition::BandwidthExceeded,
                threshold: 100,
                window_secs: 3600,
                users: vec![],
                webhook_url: None,
            }],
        };
        let engine = AlertEngine::new(config, None, test_tracker());
        assert!(!engine.is_enabled());
        // Should not panic or fire anything
        engine.evaluate(&["alice".to_string()]);
        assert!(engine.fired_alerts.is_empty());
    }

    #[test]
    fn test_bandwidth_exceeded_fires_alert() {
        let tracker = test_tracker();
        // Record enough bytes to exceed threshold of 1000
        let _ = tracker.record_bytes("alice", 2000, 0, 0, None);

        let config = AlertingConfig {
            enabled: true,
            rules: vec![AlertRule {
                name: "high_bandwidth".to_string(),
                condition: AlertCondition::BandwidthExceeded,
                threshold: 1000,
                window_secs: 3600,
                users: vec![],
                webhook_url: None,
            }],
        };
        let engine = AlertEngine::new(config, None, tracker);
        engine.evaluate(&["alice".to_string()]);
        assert!(engine
            .fired_alerts
            .contains(&"high_bandwidth:alice".to_string()));
    }

    #[test]
    fn test_connections_exceeded_fires_alert() {
        let tracker = test_tracker();
        // Record 5 connections
        for _ in 0..5 {
            let _ = tracker.record_connection("bob", None);
        }

        let config = AlertingConfig {
            enabled: true,
            rules: vec![AlertRule {
                name: "conn_limit".to_string(),
                condition: AlertCondition::ConnectionsExceeded,
                threshold: 3,
                window_secs: 3600,
                users: vec![],
                webhook_url: None,
            }],
        };
        let engine = AlertEngine::new(config, None, tracker);
        engine.evaluate(&["bob".to_string()]);
        assert!(engine.fired_alerts.contains(&"conn_limit:bob".to_string()));
    }

    #[test]
    fn test_deduplication_prevents_repeat_fires() {
        let tracker = test_tracker();
        let _ = tracker.record_bytes("alice", 2000, 0, 0, None);

        let config = AlertingConfig {
            enabled: true,
            rules: vec![AlertRule {
                name: "bw_alert".to_string(),
                condition: AlertCondition::BandwidthExceeded,
                threshold: 1000,
                window_secs: 3600,
                users: vec![],
                webhook_url: None,
            }],
        };
        let engine = AlertEngine::new(config, None, tracker);
        engine.evaluate(&["alice".to_string()]);
        assert_eq!(engine.fired_alerts.len(), 1);

        // Evaluate again -- should not add another entry
        engine.evaluate(&["alice".to_string()]);
        assert_eq!(engine.fired_alerts.len(), 1);
    }

    #[test]
    fn test_reset_fired_clears_dedup() {
        let tracker = test_tracker();
        let _ = tracker.record_bytes("alice", 2000, 0, 0, None);

        let config = AlertingConfig {
            enabled: true,
            rules: vec![AlertRule {
                name: "bw_alert".to_string(),
                condition: AlertCondition::BandwidthExceeded,
                threshold: 1000,
                window_secs: 3600,
                users: vec![],
                webhook_url: None,
            }],
        };
        let engine = AlertEngine::new(config, None, tracker);
        engine.evaluate(&["alice".to_string()]);
        assert_eq!(engine.fired_alerts.len(), 1);

        engine.reset_fired();
        assert!(engine.fired_alerts.is_empty());
    }

    #[test]
    fn test_rule_scoped_to_specific_users() {
        let tracker = test_tracker();
        let _ = tracker.record_bytes("alice", 2000, 0, 0, None);
        let _ = tracker.record_bytes("bob", 2000, 0, 0, None);

        let config = AlertingConfig {
            enabled: true,
            rules: vec![AlertRule {
                name: "alice_bw".to_string(),
                condition: AlertCondition::BandwidthExceeded,
                threshold: 1000,
                window_secs: 3600,
                users: vec!["alice".to_string()],
                webhook_url: None,
            }],
        };
        let engine = AlertEngine::new(config, None, tracker);
        // Even though both users are known, only alice should be checked
        engine.evaluate(&["alice".to_string(), "bob".to_string()]);
        assert!(engine.fired_alerts.contains(&"alice_bw:alice".to_string()));
        assert!(!engine.fired_alerts.contains(&"alice_bw:bob".to_string()));
    }

    #[test]
    fn test_below_threshold_does_not_fire() {
        let tracker = test_tracker();
        let _ = tracker.record_bytes("alice", 500, 0, 0, None);

        let config = AlertingConfig {
            enabled: true,
            rules: vec![AlertRule {
                name: "bw_alert".to_string(),
                condition: AlertCondition::BandwidthExceeded,
                threshold: 1000,
                window_secs: 3600,
                users: vec![],
                webhook_url: None,
            }],
        };
        let engine = AlertEngine::new(config, None, tracker);
        engine.evaluate(&["alice".to_string()]);
        assert!(engine.fired_alerts.is_empty());
    }

    #[test]
    fn test_hourly_bandwidth_below_threshold_does_not_fire() {
        let tracker = test_tracker();
        // Record only 50 bytes — below threshold of 100000
        let _ = tracker.record_bytes("alice", 50, 0, 0, None);

        let config = AlertingConfig {
            enabled: true,
            rules: vec![AlertRule {
                name: "hourly_check".to_string(),
                condition: AlertCondition::HourlyBandwidthExceeded,
                threshold: 100_000,
                window_secs: 3600,
                users: vec![],
                webhook_url: None,
            }],
        };
        let engine = AlertEngine::new(config, None, tracker);
        engine.evaluate(&["alice".to_string()]);
        assert!(engine.fired_alerts.is_empty());
    }

    #[test]
    fn test_monthly_bandwidth_exceeded() {
        let tracker = test_tracker();
        let _ = tracker.record_bytes("alice", 5000, 0, 0, None);

        let config = AlertingConfig {
            enabled: true,
            rules: vec![AlertRule {
                name: "monthly_bw".to_string(),
                condition: AlertCondition::MonthlyBandwidthExceeded,
                threshold: 4000,
                window_secs: 3600,
                users: vec![],
                webhook_url: None,
            }],
        };
        let engine = AlertEngine::new(config, None, tracker);
        engine.evaluate(&["alice".to_string()]);
        assert!(engine
            .fired_alerts
            .contains(&"monthly_bw:alice".to_string()));
    }

    #[test]
    fn test_window_secs_selects_monthly_bucket() {
        // Restore user usage so monthly is high but daily/hourly are zero.
        // This proves window_secs > 86400 uses monthly data.
        let tracker = test_tracker();
        tracker.restore_user_usage("alice", 0, 0, 5000, 0, 5000);

        // window_secs = 86401 -> monthly bucket -> 5000 > 1000 -> fires
        let config = AlertingConfig {
            enabled: true,
            rules: vec![AlertRule {
                name: "monthly_window".to_string(),
                condition: AlertCondition::BandwidthExceeded,
                threshold: 1000,
                window_secs: 86401,
                users: vec![],
                webhook_url: None,
            }],
        };
        let engine = AlertEngine::new(config, None, tracker);
        engine.evaluate(&["alice".to_string()]);
        assert!(
            engine
                .fired_alerts
                .contains(&"monthly_window:alice".to_string()),
            "window_secs > 86400 should use monthly bytes"
        );
    }

    #[test]
    fn test_window_secs_selects_daily_bucket() {
        // Restore user usage: daily is high, hourly rolling window is zero.
        let tracker = test_tracker();
        tracker.restore_user_usage("alice", 5000, 0, 5000, 0, 5000);

        // window_secs = 86400 -> daily bucket -> 5000 > 1000 -> fires
        let config = AlertingConfig {
            enabled: true,
            rules: vec![AlertRule {
                name: "daily_window".to_string(),
                condition: AlertCondition::BandwidthExceeded,
                threshold: 1000,
                window_secs: 86400,
                users: vec![],
                webhook_url: None,
            }],
        };
        let engine = AlertEngine::new(config, None, tracker);
        engine.evaluate(&["alice".to_string()]);
        assert!(
            engine
                .fired_alerts
                .contains(&"daily_window:alice".to_string()),
            "window_secs <= 86400 (but > 3600) should use daily bytes"
        );
    }

    #[test]
    fn test_window_secs_selects_hourly_bucket() {
        // Restore user usage: daily is high but hourly rolling window is zero
        // (restore_user_usage only sets cumulative counters, not rolling windows).
        let tracker = test_tracker();
        tracker.restore_user_usage("alice", 5000, 0, 5000, 0, 5000);

        // window_secs = 3600 -> hourly rolling window (which is 0) -> should NOT fire
        let config = AlertingConfig {
            enabled: true,
            rules: vec![AlertRule {
                name: "hourly_window".to_string(),
                condition: AlertCondition::BandwidthExceeded,
                threshold: 1000,
                window_secs: 3600,
                users: vec![],
                webhook_url: None,
            }],
        };
        let engine = AlertEngine::new(config, None, tracker);
        engine.evaluate(&["alice".to_string()]);
        assert!(
            engine.fired_alerts.is_empty(),
            "window_secs <= 3600 should use hourly rolling window (which is 0 here)"
        );
    }

    #[test]
    fn test_window_secs_connections_monthly() {
        // Restore: monthly connections = 10, daily connections = 0
        let tracker = test_tracker();
        tracker.restore_user_usage("alice", 0, 0, 0, 10, 0);

        // window_secs = 86401 -> monthly connections -> 10 > 5 -> fires
        let config = AlertingConfig {
            enabled: true,
            rules: vec![AlertRule {
                name: "conn_monthly".to_string(),
                condition: AlertCondition::ConnectionsExceeded,
                threshold: 5,
                window_secs: 86401,
                users: vec![],
                webhook_url: None,
            }],
        };
        let engine = AlertEngine::new(config, None, tracker);
        engine.evaluate(&["alice".to_string()]);
        assert!(
            engine
                .fired_alerts
                .contains(&"conn_monthly:alice".to_string()),
            "connections_exceeded with window_secs > 86400 should use monthly connections"
        );
    }
}
