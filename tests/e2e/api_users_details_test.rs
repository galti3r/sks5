#[allow(dead_code, unused_imports)]
mod helpers;

use helpers::{api_config, free_port, hash_pass, start_api};

// ---------------------------------------------------------------------------
// Test 1: GET /api/users (no details param) omits current_connections
// ---------------------------------------------------------------------------
#[tokio::test]
async fn users_without_details_has_no_connections_field() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "tok1", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/users", port))
        .header("Authorization", "Bearer tok1")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let users = body["data"]
        .as_array()
        .expect("response data should be an array");
    assert!(!users.is_empty(), "should have at least one user");

    for user in users {
        assert!(
            user.get("current_connections").is_none(),
            "current_connections should be absent without details param, got: {}",
            user
        );
    }
}

// ---------------------------------------------------------------------------
// Test 2: GET /api/users?details=true includes current_connections
// ---------------------------------------------------------------------------
#[tokio::test]
async fn users_with_details_true_has_connections_field() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "tok2", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/users?details=true", port))
        .header("Authorization", "Bearer tok2")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let users = body["data"]
        .as_array()
        .expect("response data should be an array");
    assert!(!users.is_empty(), "should have at least one user");

    for user in users {
        assert!(
            user.get("current_connections").is_some(),
            "current_connections should be present with details=true, got: {}",
            user
        );
        // Value should be a number (0 is fine when no active connections)
        assert!(
            user["current_connections"].is_number(),
            "current_connections should be a number"
        );
    }
}

// ---------------------------------------------------------------------------
// Test 3: GET /api/users?details=1 also includes details
// ---------------------------------------------------------------------------
#[tokio::test]
async fn users_with_details_1_also_works() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "tok3", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/users?details=1", port))
        .header("Authorization", "Bearer tok3")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let users = body["data"]
        .as_array()
        .expect("response data should be an array");
    assert!(!users.is_empty(), "should have at least one user");

    for user in users {
        assert!(
            user.get("current_connections").is_some(),
            "current_connections should be present with details=1, got: {}",
            user
        );
        assert!(
            user.get("total_bytes_transferred").is_some(),
            "total_bytes_transferred should be present with details=1, got: {}",
            user
        );
    }
}

// ---------------------------------------------------------------------------
// Test 4: GET /api/users?details=false excludes detail fields
// ---------------------------------------------------------------------------
#[tokio::test]
async fn users_with_details_false_excludes() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "tok4", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/users?details=false", port))
        .header("Authorization", "Bearer tok4")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let users = body["data"]
        .as_array()
        .expect("response data should be an array");
    assert!(!users.is_empty(), "should have at least one user");

    for user in users {
        assert!(
            user.get("current_connections").is_none(),
            "current_connections should be absent with details=false, got: {}",
            user
        );
        assert!(
            user.get("total_bytes_transferred").is_none(),
            "total_bytes_transferred should be absent with details=false, got: {}",
            user
        );
    }
}

// ---------------------------------------------------------------------------
// Test 5: GET /api/users?details=true includes total_bytes_transferred
// ---------------------------------------------------------------------------
#[tokio::test]
async fn users_details_bytes_transferred_field() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "tok5", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/users?details=true", port))
        .header("Authorization", "Bearer tok5")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let users = body["data"]
        .as_array()
        .expect("response data should be an array");
    assert!(!users.is_empty(), "should have at least one user");

    for user in users {
        assert!(
            user.get("total_bytes_transferred").is_some(),
            "total_bytes_transferred should be present with details=true, got: {}",
            user
        );
        // Value should be a number (0.0 is fine when no traffic)
        assert!(
            user["total_bytes_transferred"].is_number(),
            "total_bytes_transferred should be a number"
        );
    }
}

// ---------------------------------------------------------------------------
// Test 6: GET /api/users/{username} returns full user detail
// ---------------------------------------------------------------------------
#[tokio::test]
async fn get_user_detail_returns_full_info() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "tok6", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/users/testuser", port))
        .header("Authorization", "Bearer tok6")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], true);

    let data = &body["data"];
    assert_eq!(data["username"], "testuser");
    assert_eq!(data["role"], "user");
    assert!(data["allow_shell"].is_boolean());
    assert!(data["has_password"].is_boolean());
    assert!(data["totp_enabled"].is_boolean());
    assert!(data["current_connections"].is_number());
    assert!(data["total_bytes_transferred"].is_number());
    assert!(data.get("acl").is_some());
    assert!(data["acl"]["default_policy"].is_string());
    assert!(data.get("shell_permissions").is_some());
}

// ---------------------------------------------------------------------------
// Test 7: GET /api/users/{username} returns 404 for unknown user
// ---------------------------------------------------------------------------
#[tokio::test]
async fn get_user_detail_not_found() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "tok7", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/users/nonexistent", port))
        .header("Authorization", "Bearer tok7")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["success"], false);
    assert!(body["error"].as_str().unwrap().contains("not found"));
}

// ---------------------------------------------------------------------------
// Test 8: GET /api/users/{username} requires auth
// ---------------------------------------------------------------------------
#[tokio::test]
async fn get_user_detail_requires_auth() {
    let port = free_port().await;
    let hash = hash_pass("pass");
    let config = api_config(port, "tok8", &hash);
    let _server = start_api(config).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/users/testuser", port))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}
