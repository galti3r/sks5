#[allow(dead_code, unused_imports)]
mod helpers;

use futures::StreamExt;
use helpers::*;
use sks5::audit::events::AuditEvent;
use sks5::proxy::LiveSession;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OnceCell;

// ---------------------------------------------------------------------------
// Shared Chrome container — one per test binary execution
// ---------------------------------------------------------------------------

struct ChromeState {
    _container_id: String,
    cdp_port: u16,
}

static CHROME: OnceCell<ChromeState> = OnceCell::const_new();

async fn ensure_chrome() -> u16 {
    CHROME
        .get_or_init(|| async {
            let _ = Command::new("sh")
                .args([
                    "-c",
                    "podman ps -aq --filter name=sks5-chrome | xargs -r podman rm -f 2>/dev/null",
                ])
                .output();

            let cdp_port = free_port().await;
            let container_name = format!("sks5-chrome-screenshots-{}", std::process::id());

            let output = Command::new("podman")
                .args([
                    "run",
                    "-d",
                    "--rm",
                    "--network=host",
                    "--name",
                    &container_name,
                    "docker.io/chromedp/headless-shell:latest",
                    "--remote-debugging-address=0.0.0.0",
                    &format!("--remote-debugging-port={}", cdp_port),
                    "--no-sandbox",
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                ])
                .output()
                .expect("podman run");

            assert!(
                output.status.success(),
                "podman run failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );

            let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();

            let client = reqwest::Client::new();
            let url = format!("http://127.0.0.1:{}/json/version", cdp_port);
            for i in 0..20 {
                tokio::time::sleep(Duration::from_millis(500)).await;
                if client.get(&url).send().await.is_ok() {
                    eprintln!("Chrome CDP ready on port {} (attempt {})", cdp_port, i + 1);
                    return ChromeState {
                        _container_id: container_id,
                        cdp_port,
                    };
                }
            }
            panic!("Chrome DevTools not ready at {} after 10s", url);
        })
        .await
        .cdp_port
}

fn podman_available() -> bool {
    Command::new("podman")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

async fn connect_browser(cdp_port: u16) -> (chromiumoxide::Browser, tokio::task::JoinHandle<()>) {
    let url = format!("http://127.0.0.1:{}", cdp_port);
    let (browser, mut handler) = chromiumoxide::Browser::connect(&url)
        .await
        .expect("connect to Chrome CDP");
    let handle = tokio::spawn(async move { while handler.next().await.is_some() {} });
    (browser, handle)
}

async fn wait_api_ready(api_port: u16, token: &str) {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/api/status", api_port);
    for _ in 0..20 {
        if let Ok(resp) = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
        {
            if resp.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("API server not ready on port {} after 2s", api_port);
}

fn screenshot_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(
        std::env::var("SCREENSHOT_DIR").unwrap_or_else(|_| "/tmp/sks5-screenshots".to_string()),
    )
}

/// Build an enriched config with 3 users, quotas, ACLs, and groups for realistic screenshots.
fn screenshot_config(
    api_port: u16,
    token: &str,
    password_hash: &str,
) -> sks5::config::types::AppConfig {
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
host_key_path = "/tmp/sks5-screenshot-key"

[api]
enabled = true
listen = "127.0.0.1:{api_port}"
token = "{token}"

[security]
ban_enabled = true
ip_guard_enabled = false

[logging]
level = "debug"

[acl]
default_policy = "deny"
allow = ["*.example.com:443", "*.github.com:443", "httpbin.org:*"]
deny = ["*.internal:*", "10.0.0.0/8:*"]

[[groups]]
name = "developers"
max_bandwidth_kbps = 10240
allow_forwarding = true
allow_shell = true

[[users]]
username = "alice"
password_hash = "{password_hash}"
allow_forwarding = true
allow_shell = true
group = "developers"

[users.quotas]
daily_bandwidth_bytes = 5368709120
monthly_bandwidth_bytes = 53687091200
bandwidth_per_hour_bytes = 1073741824
daily_connection_limit = 100
monthly_connection_limit = 1000

[[users]]
username = "bob"
password_hash = "{password_hash}"
allow_forwarding = true
allow_shell = false
group = "developers"

[users.quotas]
daily_bandwidth_bytes = 2147483648
monthly_bandwidth_bytes = 21474836480
daily_connection_limit = 50
monthly_connection_limit = 500

[[users]]
username = "charlie"
password_hash = "{password_hash}"
allow_forwarding = true
allow_shell = true

[users.quotas]
daily_bandwidth_bytes = 536870912
monthly_bandwidth_bytes = 5368709120
daily_connection_limit = 20
monthly_connection_limit = 200
"##
    );
    toml::from_str(&toml_str).unwrap()
}

/// Populate realistic data into the server state for screenshots.
/// Returns live sessions that must be kept alive during screenshots.
async fn populate_screenshot_data(server: &TestApiServerWithState) -> Vec<Arc<LiveSession>> {
    let qt = &server.quota_tracker;
    let pe = &server.proxy_engine;
    let audit = &server.audit;

    // --- Quota data (exact values via restore_user_usage) ---
    qt.restore_user_usage(
        "alice",
        1_288_490_189, // ~1.2 GB daily
        42,
        13_314_398_618, // ~12.4 GB monthly
        350,
        48_535_150_182, // ~45.2 GB total
    );
    qt.restore_user_usage(
        "bob",
        268_435_456, // 256 MB daily
        15,
        3_328_599_654, // ~3.1 GB monthly
        120,
        9_126_805_504, // ~8.5 GB total
    );
    qt.restore_user_usage(
        "charlie",
        52_428_800, // 50 MB daily
        5,
        524_288_000, // 500 MB monthly
        25,
        1_288_490_189, // ~1.2 GB total
    );

    // --- Active sessions (visible in dashboard with target hosts + bytes) ---
    let mut sessions = Vec::new();

    let s1 = pe.register_session("alice", "github.com", 443, "10.0.1.42", "ssh");
    s1.bytes_up.store(15_728_640, Ordering::Relaxed); // 15 MB
    s1.bytes_down.store(148_897_792, Ordering::Relaxed); // ~142 MB
    sessions.push(s1);

    let s2 = pe.register_session("alice", "api.example.com", 8080, "10.0.1.42", "ssh");
    s2.bytes_up.store(2_097_152, Ordering::Relaxed); // 2 MB
    s2.bytes_down.store(8_388_608, Ordering::Relaxed); // 8 MB
    sessions.push(s2);

    let s3 = pe.register_session("bob", "cdn.example.com", 443, "10.0.1.55", "socks5");
    s3.bytes_up.store(512_000, Ordering::Relaxed); // ~500 KB
    s3.bytes_down.store(89_128_960, Ordering::Relaxed); // ~85 MB
    sessions.push(s3);

    // --- Audit events ---
    let alice_addr: SocketAddr = "10.0.1.42:54321".parse().unwrap();
    let bob_addr: SocketAddr = "10.0.1.55:44332".parse().unwrap();
    let charlie_addr: SocketAddr = "192.168.1.10:61200".parse().unwrap();
    let attacker_addr: SocketAddr = "192.168.99.1:12345".parse().unwrap();

    audit.log_event(AuditEvent::auth_success("alice", &alice_addr, "publickey"));
    audit.log_event(AuditEvent::auth_success("bob", &bob_addr, "password"));
    audit.log_event(AuditEvent::connection_new(&alice_addr, "ssh"));
    audit.log_event(AuditEvent::connection_new(&bob_addr, "socks5"));
    audit.log_event(AuditEvent::acl_deny(
        "charlie",
        "blocked.internal",
        22,
        None,
        &charlie_addr.ip().to_string(),
        Some("*.internal:*".to_string()),
        "ACL deny rule matched",
    ));
    audit.log_event(AuditEvent::auth_failure(
        "admin",
        &attacker_addr,
        "password",
    ));

    // --- Ban an IP ---
    {
        let security = server.security.write().await;
        security
            .ban_manager()
            .ban("192.168.99.1".parse().unwrap(), Duration::from_secs(1800));
    }

    sessions
}

async fn open_dashboard(
    browser: &chromiumoxide::Browser,
    api_port: u16,
    token: &str,
) -> chromiumoxide::Page {
    let page = browser
        .new_page(format!(
            "http://127.0.0.1:{}/dashboard?token={}",
            api_port, token
        ))
        .await
        .expect("open new page");

    // Set viewport to 1280x800 for deterministic screenshots via CDP
    let set_metrics =
        chromiumoxide::cdp::browser_protocol::emulation::SetDeviceMetricsOverrideParams::builder()
            .width(1280)
            .height(800)
            .device_scale_factor(2.0)
            .mobile(false)
            .build()
            .unwrap();
    page.execute(set_metrics).await.expect("set viewport");

    // Wait for page DOM + initial scripts to load
    tokio::time::sleep(Duration::from_millis(1500)).await;
    page
}

async fn wait_for_text(page: &chromiumoxide::Page, expr: &str, expected: &str, timeout_secs: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if let Ok(result) = page.evaluate(expr).await {
            if let Ok(val) = result.into_value::<String>() {
                if val == expected {
                    return;
                }
            }
        }
        if tokio::time::Instant::now() > deadline {
            panic!(
                "Timeout ({}s) waiting for `{}` == {:?}",
                timeout_secs, expr, expected
            );
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

async fn wait_for_text_ne(
    page: &chromiumoxide::Page,
    expr: &str,
    not_expected: &str,
    timeout_secs: u64,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if let Ok(result) = page.evaluate(expr).await {
            if let Ok(val) = result.into_value::<String>() {
                if val != not_expected {
                    return;
                }
            }
        }
        if tokio::time::Instant::now() > deadline {
            panic!(
                "Timeout ({}s) waiting for `{}` != {:?}",
                timeout_secs, expr, not_expected
            );
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

async fn save_screenshot(page: &chromiumoxide::Page, name: &str) {
    let dir = screenshot_dir();
    std::fs::create_dir_all(&dir).expect("create screenshot dir");
    let path = dir.join(name);

    // Measure the full page height and temporarily expand the viewport
    let scroll_height: u32 = page
        .evaluate("document.documentElement.scrollHeight")
        .await
        .ok()
        .and_then(|v| v.into_value::<u32>().ok())
        .unwrap_or(800);
    let full_height = scroll_height.max(800);

    let expand =
        chromiumoxide::cdp::browser_protocol::emulation::SetDeviceMetricsOverrideParams::builder()
            .width(1280)
            .height(full_height)
            .device_scale_factor(2.0)
            .mobile(false)
            .build()
            .unwrap();
    page.execute(expand).await.expect("expand viewport");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let params = chromiumoxide::page::ScreenshotParams::builder()
        .format(chromiumoxide::cdp::browser_protocol::page::CaptureScreenshotFormat::Png)
        .build();
    let png_data = page.screenshot(params).await.expect("capture screenshot");

    // Restore the original viewport height
    let restore =
        chromiumoxide::cdp::browser_protocol::emulation::SetDeviceMetricsOverrideParams::builder()
            .width(1280)
            .height(800)
            .device_scale_factor(2.0)
            .mobile(false)
            .build()
            .unwrap();
    page.execute(restore).await.expect("restore viewport");

    std::fs::write(&path, png_data).expect("write screenshot");
    eprintln!("Screenshot saved: {}", path.display());
}

// ===========================================================================
// Tests
// ===========================================================================

const TOKEN: &str = "screenshot-test-token";

// ---------------------------------------------------------------------------
// Screenshot 1: Dashboard dark theme with live data
// ---------------------------------------------------------------------------
#[tokio::test]
#[ignore]
async fn screenshot_dashboard_dark() {
    if !podman_available() {
        eprintln!("SKIPPED: podman not available");
        return;
    }

    let cdp_port = ensure_chrome().await;
    let api_port = free_port().await;
    let hash = hash_pass("pass");
    let server = start_api_with_state(screenshot_config(api_port, TOKEN, &hash)).await;
    wait_api_ready(api_port, TOKEN).await;
    let _guards = populate_screenshot_data(&server).await;

    let (browser, _handler) = connect_browser(cdp_port).await;
    let page = open_dashboard(&browser, api_port, TOKEN).await;

    // Wait for WebSocket to connect and data to populate
    wait_for_text(
        &page,
        "document.getElementById('connStatus').textContent",
        "Connected",
        10,
    )
    .await;
    wait_for_text_ne(
        &page,
        "document.getElementById('totalUsers').textContent",
        "-",
        10,
    )
    .await;

    // Ensure dark theme (default)
    page.evaluate("document.documentElement.classList.remove('light')")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    save_screenshot(&page, "dashboard-dark.png").await;
}

// ---------------------------------------------------------------------------
// Screenshot 2: Dashboard light theme
// ---------------------------------------------------------------------------
#[tokio::test]
#[ignore]
async fn screenshot_dashboard_light() {
    if !podman_available() {
        eprintln!("SKIPPED: podman not available");
        return;
    }

    let cdp_port = ensure_chrome().await;
    let api_port = free_port().await;
    let hash = hash_pass("pass");
    let server = start_api_with_state(screenshot_config(api_port, TOKEN, &hash)).await;
    wait_api_ready(api_port, TOKEN).await;
    let _guards = populate_screenshot_data(&server).await;

    let (browser, _handler) = connect_browser(cdp_port).await;
    let page = open_dashboard(&browser, api_port, TOKEN).await;

    wait_for_text(
        &page,
        "document.getElementById('connStatus').textContent",
        "Connected",
        10,
    )
    .await;
    wait_for_text_ne(
        &page,
        "document.getElementById('totalUsers').textContent",
        "-",
        10,
    )
    .await;

    // Switch to light theme
    page.evaluate("document.documentElement.classList.add('light')")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    save_screenshot(&page, "dashboard-light.png").await;
}

// ---------------------------------------------------------------------------
// Screenshot 3: User detail modal with enriched data
// ---------------------------------------------------------------------------
#[tokio::test]
#[ignore]
async fn screenshot_user_detail_modal() {
    if !podman_available() {
        eprintln!("SKIPPED: podman not available");
        return;
    }

    let cdp_port = ensure_chrome().await;
    let api_port = free_port().await;
    let hash = hash_pass("pass");
    let server = start_api_with_state(screenshot_config(api_port, TOKEN, &hash)).await;
    wait_api_ready(api_port, TOKEN).await;
    let _guards = populate_screenshot_data(&server).await;

    let (browser, _handler) = connect_browser(cdp_port).await;
    let page = open_dashboard(&browser, api_port, TOKEN).await;

    // Wait for data to populate
    wait_for_text(
        &page,
        "document.getElementById('connStatus').textContent",
        "Connected",
        10,
    )
    .await;
    wait_for_text_ne(
        &page,
        "document.getElementById('totalUsers').textContent",
        "-",
        10,
    )
    .await;

    // Ensure dark theme
    page.evaluate("document.documentElement.classList.remove('light')")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Click first username in user table to open modal
    page.evaluate("document.querySelector('#userTable a[onclick]').click()")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;

    save_screenshot(&page, "user-detail-modal.png").await;
}
