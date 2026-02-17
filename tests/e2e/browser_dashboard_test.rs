#[allow(dead_code, unused_imports)]
mod helpers;

use futures::StreamExt;
use helpers::*;
use std::process::Command;
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

/// Start a shared Chrome container (once) and return its CDP port.
async fn ensure_chrome() -> u16 {
    CHROME
        .get_or_init(|| async {
            // Clean up leftover containers from previous runs
            let _ = Command::new("sh")
                .args([
                    "-c",
                    "podman ps -aq --filter name=sks5-chrome | xargs -r podman rm -f 2>/dev/null",
                ])
                .output();

            let cdp_port = free_port().await;
            let container_name = format!("sks5-chrome-{}", std::process::id());

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

            // Wait for Chrome DevTools Protocol to be ready
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

/// Check if podman is available on the system.
fn podman_available() -> bool {
    Command::new("podman")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Connect to a remote Chrome instance via CDP.
async fn connect_browser(cdp_port: u16) -> (chromiumoxide::Browser, tokio::task::JoinHandle<()>) {
    let url = format!("http://127.0.0.1:{}", cdp_port);
    let (browser, mut handler) = chromiumoxide::Browser::connect(&url)
        .await
        .expect("connect to Chrome CDP");

    let handle = tokio::spawn(async move { while handler.next().await.is_some() {} });

    (browser, handle)
}

/// Wait for the API server to be ready (HTTP 200 on /api/status).
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

/// Open the dashboard in a new browser tab.
/// The token is passed as a query parameter so the JS can extract it
/// and use it for Bearer auth on API calls (WS/SSE ticket negotiation).
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

    // Wait for page DOM + initial scripts to load
    tokio::time::sleep(Duration::from_millis(1000)).await;
    page
}

/// Evaluate a JS expression and return the string result.
async fn eval_str(page: &chromiumoxide::Page, expr: &str) -> String {
    page.evaluate(expr)
        .await
        .unwrap_or_else(|e| panic!("JS eval failed for `{}`: {}", expr, e))
        .into_value::<String>()
        .unwrap_or_else(|e| panic!("JS eval returned non-string for `{}`: {}", expr, e))
}

/// Evaluate a JS expression and return the bool result.
async fn eval_bool(page: &chromiumoxide::Page, expr: &str) -> bool {
    page.evaluate(expr)
        .await
        .unwrap_or_else(|e| panic!("JS eval failed for `{}`: {}", expr, e))
        .into_value::<bool>()
        .unwrap_or_else(|e| panic!("JS eval returned non-bool for `{}`: {}", expr, e))
}

/// Wait until a JS expression returns the expected string value, with timeout.
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
            let actual = page
                .evaluate(expr)
                .await
                .ok()
                .and_then(|r| r.into_value::<String>().ok())
                .unwrap_or_else(|| "<eval-error>".to_string());
            panic!(
                "Timeout ({}s) waiting for `{}` == {:?}, got {:?}",
                timeout_secs, expr, expected, actual
            );
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

/// Wait until a JS expression returns a string different from the given value.
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

/// Wait until a JS boolean expression becomes true.
async fn wait_for_true(page: &chromiumoxide::Page, expr: &str, timeout_secs: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if let Ok(result) = page.evaluate(expr).await {
            if let Ok(true) = result.into_value::<bool>() {
                return;
            }
        }
        if tokio::time::Instant::now() > deadline {
            panic!(
                "Timeout ({}s) waiting for `{}` to be true",
                timeout_secs, expr
            );
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

// ===========================================================================
// Tests
// ===========================================================================

const TOKEN: &str = "browser-test-token";

// ---------------------------------------------------------------------------
// Test 1: Dashboard page loads with expected structure
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_dashboard_page_loads() {
    if !podman_available() {
        eprintln!("SKIPPED: podman not available");
        return;
    }

    let cdp_port = ensure_chrome().await;
    let api_port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_api(api_config(api_port, TOKEN, &hash)).await;
    wait_api_ready(api_port, TOKEN).await;

    let (browser, _handler) = connect_browser(cdp_port).await;
    let page = open_dashboard(&browser, api_port, TOKEN).await;

    let title = page.get_title().await.unwrap();
    assert_eq!(title.as_deref(), Some("sks5 Dashboard"), "page title");

    let h1_text = eval_str(&page, "document.querySelector('header h1').textContent").await;
    assert!(
        h1_text.contains("sks5 Dashboard"),
        "h1 should contain 'sks5 Dashboard', got: {}",
        h1_text
    );

    // Verify stat card elements exist
    for id in &["activeConn", "bannedCount", "totalUsers", "uptime"] {
        let exists = eval_bool(
            &page,
            &format!("document.getElementById('{}') !== null", id),
        )
        .await;
        assert!(exists, "element #{} should exist", id);
    }
}

// ---------------------------------------------------------------------------
// Test 2: Theme toggle switches between dark and light
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_dashboard_theme_toggle() {
    if !podman_available() {
        eprintln!("SKIPPED: podman not available");
        return;
    }

    let cdp_port = ensure_chrome().await;
    let api_port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_api(api_config(api_port, TOKEN, &hash)).await;
    wait_api_ready(api_port, TOKEN).await;

    let (browser, _handler) = connect_browser(cdp_port).await;
    let page = open_dashboard(&browser, api_port, TOKEN).await;

    // Check initial state (headless Chrome may default to light or dark)
    let initial_light = eval_bool(
        &page,
        "document.documentElement.classList.contains('light')",
    )
    .await;

    // Toggle once
    page.evaluate("toggleTheme()").await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let after_first = eval_bool(
        &page,
        "document.documentElement.classList.contains('light')",
    )
    .await;
    assert_ne!(
        initial_light, after_first,
        "theme should change after first toggle"
    );

    // Toggle again — should return to initial state
    page.evaluate("toggleTheme()").await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let after_second = eval_bool(
        &page,
        "document.documentElement.classList.contains('light')",
    )
    .await;
    assert_eq!(
        initial_light, after_second,
        "theme should return to initial state after second toggle"
    );
}

// ---------------------------------------------------------------------------
// Test 3: WebSocket connects and shows Connected status
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_dashboard_websocket_connects() {
    if !podman_available() {
        eprintln!("SKIPPED: podman not available");
        return;
    }

    let cdp_port = ensure_chrome().await;
    let api_port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_api(api_config(api_port, TOKEN, &hash)).await;
    wait_api_ready(api_port, TOKEN).await;

    let (browser, _handler) = connect_browser(cdp_port).await;
    let page = open_dashboard(&browser, api_port, TOKEN).await;

    // Wait for WebSocket to connect
    wait_for_text(
        &page,
        "document.getElementById('connStatus').textContent",
        "Connected",
        10,
    )
    .await;

    let conn_type = eval_str(
        &page,
        "document.getElementById('connTypeBadge').textContent",
    )
    .await;
    assert!(
        conn_type == "WS" || conn_type == "SSE",
        "connection type should be WS or SSE, got: {}",
        conn_type
    );

    let dot_class = eval_str(&page, "document.getElementById('connDot').className").await;
    assert_eq!(dot_class, "dot", "dot should not have 'offline' class");
}

// ---------------------------------------------------------------------------
// Test 4: Live data updates arrive via WebSocket
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_dashboard_live_data_updates() {
    if !podman_available() {
        eprintln!("SKIPPED: podman not available");
        return;
    }

    let cdp_port = ensure_chrome().await;
    let api_port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_api(api_config(api_port, TOKEN, &hash)).await;
    wait_api_ready(api_port, TOKEN).await;

    let (browser, _handler) = connect_browser(cdp_port).await;
    let page = open_dashboard(&browser, api_port, TOKEN).await;

    // Wait for data to populate (WS sends every 2s)
    wait_for_text_ne(
        &page,
        "document.getElementById('totalUsers').textContent",
        "-",
        10,
    )
    .await;

    let total_users = eval_str(&page, "document.getElementById('totalUsers').textContent").await;
    assert_eq!(total_users, "1", "should show 1 configured user");

    let active_conn = eval_str(&page, "document.getElementById('activeConn').textContent").await;
    assert_eq!(active_conn, "0", "no active SSH connections");

    let uptime = eval_str(&page, "document.getElementById('uptime').textContent").await;
    assert!(
        uptime.contains('m'),
        "uptime should contain 'm' (fmtUptime format), got: {}",
        uptime
    );
}

// ---------------------------------------------------------------------------
// Test 5: User table is populated with configured user
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_dashboard_user_table_populated() {
    if !podman_available() {
        eprintln!("SKIPPED: podman not available");
        return;
    }

    let cdp_port = ensure_chrome().await;
    let api_port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_api(api_config(api_port, TOKEN, &hash)).await;
    wait_api_ready(api_port, TOKEN).await;

    let (browser, _handler) = connect_browser(cdp_port).await;
    let page = open_dashboard(&browser, api_port, TOKEN).await;

    // Wait for user table to be populated
    wait_for_true(
        &page,
        "document.getElementById('userTable').innerHTML.includes('testuser')",
        10,
    )
    .await;

    let table_html = eval_str(&page, "document.getElementById('userTable').innerHTML").await;
    assert!(
        table_html.contains("testuser"),
        "user table should contain 'testuser'"
    );
    assert!(
        table_html.contains("Yes"),
        "user table should show 'Yes' for forwarding/shell"
    );
}

// ---------------------------------------------------------------------------
// Test 6: Maintenance toggle via WS command
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_dashboard_maintenance_toggle() {
    if !podman_available() {
        eprintln!("SKIPPED: podman not available");
        return;
    }

    let cdp_port = ensure_chrome().await;
    let api_port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_api(api_config(api_port, TOKEN, &hash)).await;
    wait_api_ready(api_port, TOKEN).await;

    let (browser, _handler) = connect_browser(cdp_port).await;
    let page = open_dashboard(&browser, api_port, TOKEN).await;

    // Wait for connection to be established
    wait_for_text(
        &page,
        "document.getElementById('connStatus').textContent",
        "Connected",
        10,
    )
    .await;

    // Verify initial state is OFF
    let maint = eval_str(&page, "document.getElementById('maintBadge').textContent").await;
    assert_eq!(maint, "OFF", "maintenance should initially be OFF");

    // Click the Toggle Maintenance button via JS
    page.evaluate("document.querySelector('button.btn.primary').click()")
        .await
        .unwrap();

    // Wait for the maintenance badge to change to ON (next WS payload after toggle)
    wait_for_text(
        &page,
        "document.getElementById('maintBadge').textContent",
        "ON",
        8,
    )
    .await;

    // Verify actionMsg was set
    let action_msg = eval_str(&page, "document.getElementById('actionMsg').textContent").await;
    assert!(
        !action_msg.is_empty(),
        "actionMsg should not be empty after toggle"
    );
}

// ---------------------------------------------------------------------------
// Test 7: Disconnecting WebSocket shows offline status
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_dashboard_disconnect_shows_offline() {
    if !podman_available() {
        eprintln!("SKIPPED: podman not available");
        return;
    }

    let cdp_port = ensure_chrome().await;
    let api_port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_api(api_config(api_port, TOKEN, &hash)).await;
    wait_api_ready(api_port, TOKEN).await;

    let (browser, _handler) = connect_browser(cdp_port).await;
    let page = open_dashboard(&browser, api_port, TOKEN).await;

    // Wait for WS to connect
    wait_for_text(
        &page,
        "document.getElementById('connStatus').textContent",
        "Connected",
        10,
    )
    .await;

    // Force-close all live connections from JS
    page.evaluate(
        "if (ws) ws.close(); if (evtSource) evtSource.close(); clearInterval(window._pollInterval);",
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    let dot_class = eval_str(&page, "document.getElementById('connDot').className").await;
    assert!(
        dot_class.contains("offline"),
        "dot should have 'offline' class after disconnect, got: {}",
        dot_class
    );

    let status = eval_str(&page, "document.getElementById('connStatus').textContent").await;
    assert_eq!(status, "Disconnected", "status should show Disconnected");
}

// ---------------------------------------------------------------------------
// Test 8: Stat cards have correct structure (4 cards with expected headings)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_dashboard_stat_cards_structure() {
    if !podman_available() {
        eprintln!("SKIPPED: podman not available");
        return;
    }

    let cdp_port = ensure_chrome().await;
    let api_port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_api(api_config(api_port, TOKEN, &hash)).await;
    wait_api_ready(api_port, TOKEN).await;

    let (browser, _handler) = connect_browser(cdp_port).await;
    let page = open_dashboard(&browser, api_port, TOKEN).await;

    let card_count: i64 = page
        .evaluate("document.querySelectorAll('.card h3').length")
        .await
        .unwrap()
        .into_value()
        .unwrap();
    assert_eq!(card_count, 4, "should have exactly 4 stat cards");

    let headings: Vec<String> = page
        .evaluate("Array.from(document.querySelectorAll('.card h3')).map(e => e.textContent)")
        .await
        .unwrap()
        .into_value()
        .unwrap();

    for expected in &["Active Connections", "Banned IPs", "Total Users", "Uptime"] {
        assert!(
            headings.iter().any(|h| h == expected),
            "stat cards should contain '{}', got: {:?}",
            expected,
            headings
        );
    }
}

// ---------------------------------------------------------------------------
// Test 9: Controls panel has expected elements
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_dashboard_controls_panel_exists() {
    if !podman_available() {
        eprintln!("SKIPPED: podman not available");
        return;
    }

    let cdp_port = ensure_chrome().await;
    let api_port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_api(api_config(api_port, TOKEN, &hash)).await;
    wait_api_ready(api_port, TOKEN).await;

    let (browser, _handler) = connect_browser(cdp_port).await;
    let page = open_dashboard(&browser, api_port, TOKEN).await;

    // Check buttons exist with correct labels
    let buttons: Vec<String> = page
        .evaluate("Array.from(document.querySelectorAll('.btn.primary')).map(b => b.textContent)")
        .await
        .unwrap()
        .into_value()
        .unwrap();

    assert!(
        buttons.iter().any(|b| b.contains("Toggle Maintenance")),
        "should have 'Toggle Maintenance' button, got: {:?}",
        buttons
    );
    assert!(
        buttons.iter().any(|b| b.contains("Reload Config")),
        "should have 'Reload Config' button, got: {:?}",
        buttons
    );

    // Check control elements exist
    for id in &["maintBadge", "actionMsg", "logArea"] {
        let exists = eval_bool(
            &page,
            &format!("document.getElementById('{}') !== null", id),
        )
        .await;
        assert!(exists, "element #{} should exist", id);
    }
}

// ---------------------------------------------------------------------------
// Test 10: User detail modal opens on username click
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_dashboard_user_detail_modal() {
    if !podman_available() {
        eprintln!("SKIPPED: podman not available");
        return;
    }

    let cdp_port = ensure_chrome().await;
    let api_port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_api(api_config(api_port, TOKEN, &hash)).await;
    wait_api_ready(api_port, TOKEN).await;

    let (browser, _handler) = connect_browser(cdp_port).await;
    let page = open_dashboard(&browser, api_port, TOKEN).await;

    // Wait for user table to be populated
    wait_for_true(
        &page,
        "document.getElementById('userTable').innerHTML.includes('testuser')",
        10,
    )
    .await;

    // Click the username link to open modal
    page.evaluate("document.querySelector('#userTable a[onclick]').click()")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // Verify modal is visible
    let modal_active = eval_bool(
        &page,
        "document.getElementById('userModal').classList.contains('active')",
    )
    .await;
    assert!(modal_active, "user detail modal should be active");

    // Verify modal title contains username
    let title = eval_str(&page, "document.getElementById('modalTitle').textContent").await;
    assert!(
        title.contains("testuser"),
        "modal title should contain 'testuser', got: {}",
        title
    );

    // Verify modal has key sections
    let content = eval_str(&page, "document.getElementById('modalContent').innerHTML").await;
    assert!(
        content.contains("Identity"),
        "modal should have Identity section"
    );
    assert!(
        content.contains("Authentication"),
        "modal should have Authentication section"
    );
    assert!(
        content.contains("Network"),
        "modal should have Network section"
    );
    assert!(content.contains("ACL"), "modal should have ACL section");

    // Close modal
    page.evaluate("closeUserModal()").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let modal_closed = eval_bool(
        &page,
        "!document.getElementById('userModal').classList.contains('active')",
    )
    .await;
    assert!(
        modal_closed,
        "modal should be closed after closeUserModal()"
    );
}
