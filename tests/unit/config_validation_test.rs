use sks5::config::parse_config;

const FAKE_HASH: &str = "argon2id-fakehash-for-testing";

// ---------------------------------------------------------------------------
// Test 1: Empty ssh_listen is rejected
// ---------------------------------------------------------------------------
#[test]
fn empty_ssh_listen_rejected() {
    let toml = format!(
        r##"
[server]
ssh_listen = ""

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    let err = parse_config(&toml).unwrap_err();
    assert!(
        format!("{}", err).contains("ssh_listen"),
        "error should mention ssh_listen: {}",
        err
    );
}

// ---------------------------------------------------------------------------
// Test 2: API enabled without token is rejected
// ---------------------------------------------------------------------------
#[test]
fn api_enabled_without_token_rejected() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[api]
enabled = true
token = ""

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    let err = parse_config(&toml).unwrap_err();
    assert!(
        format!("{}", err).contains("api.token"),
        "error should mention api.token: {}",
        err
    );
}

// ---------------------------------------------------------------------------
// Test 3: API disabled with empty token is OK
// ---------------------------------------------------------------------------
#[test]
fn api_disabled_empty_token_ok() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[api]
enabled = false

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    assert!(parse_config(&toml).is_ok());
}

// ---------------------------------------------------------------------------
// Test 4: User with authorized_keys only (no password_hash) is valid
// ---------------------------------------------------------------------------
#[test]
fn user_with_only_authorized_keys_valid() {
    let toml = r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "keyuser"
authorized_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTestingPurposesOnly000000000000000 test@host"]
"##;
    assert!(parse_config(toml).is_ok());
}

// ---------------------------------------------------------------------------
// Test 5: User with both password and keys is valid
// ---------------------------------------------------------------------------
#[test]
fn user_with_both_auth_methods_valid() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "bothuser"
password_hash = "{FAKE_HASH}"
authorized_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTestingPurposesOnly000000000000000 test@host"]
"##
    );
    assert!(parse_config(&toml).is_ok());
}

// ---------------------------------------------------------------------------
// Test 6: Multiple webhook configs parse correctly
// ---------------------------------------------------------------------------
#[test]
fn multiple_webhooks_valid() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[webhooks]]
url = "https://example.com/hook1"
events = ["auth_success"]

[[webhooks]]
url = "https://example.com/hook2"
secret = "mysecret"

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    let config = parse_config(&toml).unwrap();
    assert_eq!(config.webhooks.len(), 2);
    assert_eq!(config.webhooks[0].events.len(), 1);
    assert!(config.webhooks[1].secret.is_some());
}

// ---------------------------------------------------------------------------
// Test 7: GeoIP config section parses correctly
// ---------------------------------------------------------------------------
#[test]
fn geoip_config_parses() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[geoip]
enabled = true
database_path = "/tmp/GeoLite2-Country.mmdb"
allowed_countries = ["US", "CA", "FR"]
denied_countries = ["CN", "RU"]

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    let config = parse_config(&toml).unwrap();
    assert!(config.geoip.enabled);
    assert_eq!(
        config
            .geoip
            .database_path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap(),
        "/tmp/GeoLite2-Country.mmdb"
    );
    assert_eq!(config.geoip.allowed_countries.len(), 3);
    assert_eq!(config.geoip.denied_countries.len(), 2);
}

// ---------------------------------------------------------------------------
// Test 8: User with expires_at field
// ---------------------------------------------------------------------------
#[test]
fn user_with_expires_at() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "temp"
password_hash = "{FAKE_HASH}"
expires_at = "2030-12-31T23:59:59Z"
"##
    );
    let config = parse_config(&toml).unwrap();
    assert_eq!(
        config.users[0].expires_at.as_deref(),
        Some("2030-12-31T23:59:59Z")
    );
}

// ---------------------------------------------------------------------------
// Test 9: User with source_ips (CIDR ranges)
// ---------------------------------------------------------------------------
#[test]
fn user_with_source_ips() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "restricted"
password_hash = "{FAKE_HASH}"
source_ips = ["10.0.0.0/8", "172.16.0.0/12", "192.168.1.0/24"]
"##
    );
    let config = parse_config(&toml).unwrap();
    assert_eq!(config.users[0].source_ips.len(), 3);
}

// ---------------------------------------------------------------------------
// Test 10: User with ACL deny and allow rules
// ---------------------------------------------------------------------------
#[test]
fn user_acl_rules_parse() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "acluser"
password_hash = "{FAKE_HASH}"

[users.acl]
default_policy = "deny"
allow = ["*.example.com:443", "10.0.0.0/8:*", "api.test.com:80-8080"]
deny = ["169.254.169.254:*", "internal.example.com:*"]
"##
    );
    let config = parse_config(&toml).unwrap();
    assert_eq!(config.users[0].acl.allow.len(), 3);
    assert_eq!(config.users[0].acl.deny.len(), 2);
}

// ---------------------------------------------------------------------------
// Test 11: Upstream proxy config
// ---------------------------------------------------------------------------
#[test]
fn upstream_proxy_config() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[upstream_proxy]
url = "socks5://proxy.example.com:1080"

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    let config = parse_config(&toml).unwrap();
    assert!(config.upstream_proxy.is_some());
    assert_eq!(
        config.upstream_proxy.unwrap().url,
        "socks5://proxy.example.com:1080"
    );
}

// ---------------------------------------------------------------------------
// Test 12: Server config with custom server_id and banner
// ---------------------------------------------------------------------------
#[test]
fn custom_server_id_and_banner() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"
server_id = "SSH-2.0-CustomServer"
banner = "Welcome to the honeypot"

[[users]]
username = "test"
password_hash = "{FAKE_HASH}"
"##
    );
    let config = parse_config(&toml).unwrap();
    assert_eq!(config.server.server_id, "SSH-2.0-CustomServer");
    assert_eq!(config.server.banner, "Welcome to the honeypot");
}

// ---------------------------------------------------------------------------
// Test 13: User with max_bandwidth_kbps
// ---------------------------------------------------------------------------
#[test]
fn user_bandwidth_limit() {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "limited"
password_hash = "{FAKE_HASH}"
max_bandwidth_kbps = 1024
max_new_connections_per_minute = 30
"##
    );
    let config = parse_config(&toml).unwrap();
    assert_eq!(config.users[0].max_bandwidth_kbps, 1024);
    assert_eq!(config.users[0].max_new_connections_per_minute, 30);
}

// ---------------------------------------------------------------------------
// Test 14: load_config with nonexistent file returns error
// ---------------------------------------------------------------------------
#[test]
fn load_nonexistent_file_fails() {
    let result =
        sks5::config::load_config(std::path::Path::new("/tmp/nonexistent-sks5-config.toml"));
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("reading config"));
}

// ---------------------------------------------------------------------------
// Test 15: load_config with valid temp file works
// ---------------------------------------------------------------------------
#[test]
fn load_config_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test-config.toml");
    let content = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "fileuser"
password_hash = "{FAKE_HASH}"
"##
    );
    std::fs::write(&path, content).unwrap();

    let config = sks5::config::load_config(&path).unwrap();
    assert_eq!(config.users[0].username, "fileuser");
}
