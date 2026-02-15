#[allow(dead_code, unused_imports)]
mod helpers;

use helpers::*;

// ---------------------------------------------------------------------------
// Helper: build an API config with no groups (single user, no group field)
// ---------------------------------------------------------------------------
fn config_no_groups(api_port: u16, hash: &str) -> sks5::config::types::AppConfig {
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
host_key_path = "/tmp/sks5-e2e-groups-key"

[api]
enabled = true
listen = "127.0.0.1:{api_port}"
token = "groups-test-token"

[security]
ban_enabled = false

[logging]
level = "debug"

[[users]]
username = "solo"
password_hash = "{hash}"
allow_forwarding = true
allow_shell = true
"##
    );
    toml::from_str(&toml_str).unwrap()
}

// ---------------------------------------------------------------------------
// Helper: build an API config with 2 groups (admins=2, devs=1)
// ---------------------------------------------------------------------------
fn config_with_groups(api_port: u16, hash: &str) -> sks5::config::types::AppConfig {
    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
host_key_path = "/tmp/sks5-e2e-groups-key"

[api]
enabled = true
listen = "127.0.0.1:{api_port}"
token = "groups-test-token"

[security]
ban_enabled = false

[logging]
level = "debug"

[[users]]
username = "alice"
password_hash = "{hash}"
group = "admins"
allow_forwarding = true
allow_shell = true

[[users]]
username = "bob"
password_hash = "{hash}"
group = "admins"
allow_forwarding = true
allow_shell = true

[[users]]
username = "charlie"
password_hash = "{hash}"
group = "devs"
allow_forwarding = true
allow_shell = true
"##
    );
    toml::from_str(&toml_str).unwrap()
}

// ---------------------------------------------------------------------------
// Test 1: GET /api/groups with no groups configured returns empty array
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_groups_list_empty() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = config_no_groups(port, &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/groups"))
        .header("Authorization", "Bearer groups-test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    let groups = body["data"].as_array().unwrap();
    assert!(groups.is_empty(), "expected empty groups, got {:?}", groups);
}

// ---------------------------------------------------------------------------
// Test 2: GET /api/groups with 2 groups returns both with correct stats
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_groups_list_with_groups() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = config_with_groups(port, &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/groups"))
        .header("Authorization", "Bearer groups-test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    let groups = body["data"].as_array().unwrap();
    assert_eq!(groups.len(), 2, "expected 2 groups, got {}", groups.len());

    // group_names() sorts alphabetically, so admins comes first, devs second
    let admins = &groups[0];
    assert_eq!(admins["name"], "admins");
    assert_eq!(admins["member_count"], 2);
    assert_eq!(admins["active_connections"], 0);
    assert_eq!(admins["total_daily_bytes"], 0);
    assert_eq!(admins["total_monthly_bytes"], 0);
    let admin_members = admins["members"].as_array().unwrap();
    assert_eq!(admin_members.len(), 2);
    let admin_names: Vec<&str> = admin_members
        .iter()
        .map(|m| m["username"].as_str().unwrap())
        .collect();
    assert!(
        admin_names.contains(&"alice"),
        "admins should contain alice"
    );
    assert!(admin_names.contains(&"bob"), "admins should contain bob");

    let devs = &groups[1];
    assert_eq!(devs["name"], "devs");
    assert_eq!(devs["member_count"], 1);
    assert_eq!(devs["active_connections"], 0);
    let dev_members = devs["members"].as_array().unwrap();
    assert_eq!(dev_members.len(), 1);
    assert_eq!(dev_members[0]["username"], "charlie");
}

// ---------------------------------------------------------------------------
// Test 3: GET /api/groups/:name returns correct group detail
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_groups_detail() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = config_with_groups(port, &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/groups/devs"))
        .header("Authorization", "Bearer groups-test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);
    let data = &body["data"];
    assert_eq!(data["name"], "devs");
    assert_eq!(data["member_count"], 1);
    assert_eq!(data["active_connections"], 0);
    assert_eq!(data["total_daily_bytes"], 0);
    assert_eq!(data["total_monthly_bytes"], 0);
    let members = data["members"].as_array().unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0]["username"], "charlie");
    assert_eq!(members[0]["active_connections"], 0);
    assert_eq!(members[0]["daily_bytes"], 0);
    assert_eq!(members[0]["monthly_bytes"], 0);
}

// ---------------------------------------------------------------------------
// Test 4: GET /api/groups/:name for nonexistent group returns 404
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_groups_detail_not_found() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = config_with_groups(port, &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/groups/nonexistent"))
        .header("Authorization", "Bearer groups-test-token")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], false);
    assert!(
        body["error"].as_str().unwrap().contains("not found"),
        "error message should mention not found"
    );
}

// ---------------------------------------------------------------------------
// Test 5: GET /api/groups without auth token returns 401
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_groups_requires_auth() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = config_with_groups(port, &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();

    // No auth header at all
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/groups"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Wrong token
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/groups"))
        .header("Authorization", "Bearer wrong-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Also test detail endpoint without auth
    let resp = client
        .get(format!("http://127.0.0.1:{port}/api/groups/admins"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}
