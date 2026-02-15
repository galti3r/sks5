use sks5::config::types::AppConfig;

fn fake_hash() -> String {
    sks5::auth::password::hash_password("test").unwrap()
}

// ---------------------------------------------------------------------------
// Test 1: TLS config with both cert and key set
// ---------------------------------------------------------------------------
#[test]
fn tls_config_both_set() {
    let hash = fake_hash();

    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
socks5_tls_cert = "/tmp/test-cert.pem"
socks5_tls_key = "/tmp/test-key.pem"

[[users]]
username = "alice"
password_hash = "{hash}"
"##
    );
    let config: AppConfig = toml::from_str(&toml_str).unwrap();
    assert!(
        config.server.socks5_tls_cert.is_some(),
        "socks5_tls_cert should be Some"
    );
    assert!(
        config.server.socks5_tls_key.is_some(),
        "socks5_tls_key should be Some"
    );
    assert_eq!(
        config.server.socks5_tls_cert.unwrap().to_str().unwrap(),
        "/tmp/test-cert.pem"
    );
    assert_eq!(
        config.server.socks5_tls_key.unwrap().to_str().unwrap(),
        "/tmp/test-key.pem"
    );
}

// ---------------------------------------------------------------------------
// Test 2: TLS config with neither cert nor key set
// ---------------------------------------------------------------------------
#[test]
fn tls_config_neither_set() {
    let hash = fake_hash();

    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"

[[users]]
username = "alice"
password_hash = "{hash}"
"##
    );
    let config: AppConfig = toml::from_str(&toml_str).unwrap();
    assert!(
        config.server.socks5_tls_cert.is_none(),
        "socks5_tls_cert should be None"
    );
    assert!(
        config.server.socks5_tls_key.is_none(),
        "socks5_tls_key should be None"
    );
}

// ---------------------------------------------------------------------------
// Test 3: TLS config with only cert (no key) fails validation
// ---------------------------------------------------------------------------
#[test]
fn tls_config_only_cert_fails_validation() {
    let hash = fake_hash();

    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
socks5_tls_cert = "/tmp/test-cert.pem"

[[users]]
username = "alice"
password_hash = "{hash}"
"##
    );
    let config: AppConfig = toml::from_str(&toml_str).unwrap();
    let result = sks5::config::parse_config_validate(&config);
    assert!(
        result.is_err(),
        "validation should fail when only cert is set"
    );
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("socks5_tls_cert") || err_msg.contains("socks5_tls_key"),
        "error should mention TLS fields: {}",
        err_msg
    );
}

// ---------------------------------------------------------------------------
// Test 4: TLS config with only key (no cert) fails validation
// ---------------------------------------------------------------------------
#[test]
fn tls_config_only_key_fails_validation() {
    let hash = fake_hash();

    let toml_str = format!(
        r##"
[server]
ssh_listen = "127.0.0.1:0"
socks5_tls_key = "/tmp/test-key.pem"

[[users]]
username = "alice"
password_hash = "{hash}"
"##
    );
    let config: AppConfig = toml::from_str(&toml_str).unwrap();
    let result = sks5::config::parse_config_validate(&config);
    assert!(
        result.is_err(),
        "validation should fail when only key is set"
    );
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("socks5_tls_cert") || err_msg.contains("socks5_tls_key"),
        "error should mention TLS fields: {}",
        err_msg
    );
}
