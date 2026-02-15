use sks5::api;
use sks5::metrics::MetricsRegistry;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::time::{sleep, Duration};

async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

async fn start_test_metrics_server() -> (u16, Arc<MetricsRegistry>, Arc<AtomicBool>) {
    let port = free_port().await;
    let metrics = Arc::new(MetricsRegistry::new());
    let maintenance = Arc::new(AtomicBool::new(false));

    let m = metrics.clone();
    let maint = maintenance.clone();
    let addr = format!("127.0.0.1:{}", port);

    tokio::spawn(async move {
        api::start_metrics_server(&addr, m, maint, tokio_util::sync::CancellationToken::new())
            .await
            .unwrap();
    });

    // Wait for server to start
    sleep(Duration::from_millis(100)).await;

    (port, metrics, maintenance)
}

// ---------------------------------------------------------------------------
// Test 1: Health endpoint returns 200 "ok" via start_metrics_server
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_real_metrics_server_health() {
    let (port, _metrics, _maintenance) = start_test_metrics_server().await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/health", port))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
}

// ---------------------------------------------------------------------------
// Test 2: Metrics endpoint returns Prometheus format with recorded data
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_real_metrics_server_prometheus() {
    let (port, metrics, _maintenance) = start_test_metrics_server().await;

    // Record some metrics
    metrics.record_auth_success("testuser", "password");
    metrics.record_auth_success("testuser", "password");
    metrics.record_auth_failure("password");
    metrics.record_bytes_transferred("testuser", 4096);

    let resp = reqwest::get(format!("http://127.0.0.1:{}/metrics", port))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body = resp.text().await.unwrap();
    assert!(
        body.contains("sks5_auth_failures_total"),
        "should contain auth failures metric"
    );
    assert!(
        body.contains("sks5_auth_successes_total"),
        "should contain auth successes metric"
    );
    assert!(
        body.contains("sks5_bytes_transferred"),
        "should contain bytes transferred metric"
    );
    assert!(body.contains("testuser"), "should contain user label");
}

// ---------------------------------------------------------------------------
// Test 3: Maintenance mode toggles health endpoint to 503
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_real_metrics_server_maintenance_toggle() {
    let (port, _metrics, maintenance) = start_test_metrics_server().await;

    // Initially healthy
    let resp = reqwest::get(format!("http://127.0.0.1:{}/health", port))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Enable maintenance mode
    maintenance.store(true, Ordering::Relaxed);

    let resp = reqwest::get(format!("http://127.0.0.1:{}/health", port))
        .await
        .unwrap();
    assert_eq!(resp.status(), 503);
    assert_eq!(resp.text().await.unwrap(), "maintenance");

    // Disable maintenance mode
    maintenance.store(false, Ordering::Relaxed);

    let resp = reqwest::get(format!("http://127.0.0.1:{}/health", port))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
}
