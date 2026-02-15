#[allow(dead_code, unused_imports)]
mod helpers;

use helpers::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Test 1: Health endpoint returns 200 "ok"
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_health_endpoint_ok() {
    let port = free_port().await;
    let hash = hash_pass("pass");

    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
host_key_path = "/tmp/sks5-e2e-status-key"

[metrics]
enabled = true
listen = "127.0.0.1:{port}"

[logging]
level = "debug"

[[users]]
username = "testuser"
password_hash = "{hash}"
"##
    );
    let config: sks5::config::types::AppConfig = toml::from_str(&toml_str).unwrap();

    let metrics = Arc::new(sks5::metrics::MetricsRegistry::new());
    let maintenance = Arc::new(AtomicBool::new(false));

    let metrics_addr = config.metrics.listen.clone();
    let m = metrics.clone();
    let maint = maintenance.clone();
    let _task = tokio::spawn(async move {
        let _ = sks5::api::start_metrics_server(
            &metrics_addr,
            m,
            maint,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
    });
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/health", port))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
}

// ---------------------------------------------------------------------------
// Test 2: Metrics endpoint returns Prometheus format
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_metrics_endpoint_prometheus() {
    let port = free_port().await;
    let hash = hash_pass("pass");

    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
host_key_path = "/tmp/sks5-e2e-metrics-key"

[metrics]
enabled = true
listen = "127.0.0.1:{port}"

[logging]
level = "debug"

[[users]]
username = "testuser"
password_hash = "{hash}"
"##
    );
    let config: sks5::config::types::AppConfig = toml::from_str(&toml_str).unwrap();

    let metrics = Arc::new(sks5::metrics::MetricsRegistry::new());
    let maintenance = Arc::new(AtomicBool::new(false));

    // Record some metrics
    metrics.record_auth_success("testuser", "password");
    metrics.record_auth_failure("password");

    let metrics_addr = config.metrics.listen.clone();
    let m = metrics.clone();
    let maint = maintenance.clone();
    let _task = tokio::spawn(async move {
        let _ = sks5::api::start_metrics_server(
            &metrics_addr,
            m,
            maint,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
    });
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/metrics", port))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("sks5_auth_failures_total"),
        "metrics should contain auth failures"
    );
    assert!(
        body.contains("sks5_auth_successes_total"),
        "metrics should contain auth successes"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Maintenance mode returns 503
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_maintenance_mode_503() {
    let port = free_port().await;
    let hash = hash_pass("pass");

    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
host_key_path = "/tmp/sks5-e2e-maint-key"

[metrics]
enabled = true
listen = "127.0.0.1:{port}"

[logging]
level = "debug"

[[users]]
username = "testuser"
password_hash = "{hash}"
"##
    );
    let config: sks5::config::types::AppConfig = toml::from_str(&toml_str).unwrap();

    let metrics = Arc::new(sks5::metrics::MetricsRegistry::new());
    let maintenance = Arc::new(AtomicBool::new(false));

    let metrics_addr = config.metrics.listen.clone();
    let m = metrics.clone();
    let maint = maintenance.clone();
    let _task = tokio::spawn(async move {
        let _ = sks5::api::start_metrics_server(
            &metrics_addr,
            m,
            maint,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
    });
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Enable maintenance
    maintenance.store(true, Ordering::Relaxed);

    let resp = reqwest::get(format!("http://127.0.0.1:{}/health", port))
        .await
        .unwrap();
    assert_eq!(resp.status(), 503);
    assert_eq!(resp.text().await.unwrap(), "maintenance");
}
