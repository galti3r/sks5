use proptest::prelude::*;

const FAKE_HASH: &str = "argon2id-fakehash-for-testing";

proptest! {
    #[test]
    fn parse_config_with_random_username(username in "[a-zA-Z][a-zA-Z0-9_]{0,19}") {
        let toml = format!(
            r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "{}"
password_hash = "{}"
"##,
            username, FAKE_HASH,
        );
        let result = sks5::config::parse_config(&toml);
        prop_assert!(result.is_ok(), "valid config should parse: {:?}", result.err());
    }

    #[test]
    fn parse_config_with_random_port(port in 1u16..=65535u16) {
        let toml = format!(
            r##"
[server]
ssh_listen = "0.0.0.0:{}"

[[users]]
username = "test"
password_hash = "{}"
"##,
            port, FAKE_HASH,
        );
        // All ports 1..65535 should parse fine (validation only checks non-empty)
        let result = sks5::config::parse_config(&toml);
        prop_assert!(result.is_ok(), "config with port {} should parse: {:?}", port, result.err());
    }

    #[test]
    fn parse_config_random_toml_never_panics(s in "\\PC{0,500}") {
        // Random strings should never cause a panic in the parser
        let _ = sks5::config::parse_config(&s);
    }

    #[test]
    fn parse_config_with_random_banner(banner in "[a-zA-Z0-9 !.,_-]{0,100}") {
        let toml = format!(
            r##"
[server]
ssh_listen = "0.0.0.0:2222"
banner = "{}"

[[users]]
username = "test"
password_hash = "{}"
"##,
            banner, FAKE_HASH,
        );
        let result = sks5::config::parse_config(&toml);
        prop_assert!(result.is_ok(), "config with banner '{}' should parse: {:?}", banner, result.err());
    }

    #[test]
    fn parse_config_with_random_hostname(hostname in "[a-zA-Z][a-zA-Z0-9-]{0,19}") {
        let toml = format!(
            r##"
[server]
ssh_listen = "0.0.0.0:2222"

[shell]
hostname = "{}"

[[users]]
username = "test"
password_hash = "{}"
"##,
            hostname, FAKE_HASH,
        );
        let result = sks5::config::parse_config(&toml);
        prop_assert!(result.is_ok(), "config with hostname '{}' should parse: {:?}", hostname, result.err());
    }

    #[test]
    fn parse_config_with_random_server_id(suffix in "[a-zA-Z0-9_.-]{1,20}") {
        let server_id = format!("SSH-2.0-{}", suffix);
        let toml = format!(
            r##"
[server]
ssh_listen = "0.0.0.0:2222"
server_id = "{}"

[[users]]
username = "test"
password_hash = "{}"
"##,
            server_id, FAKE_HASH,
        );
        let result = sks5::config::parse_config(&toml);
        prop_assert!(result.is_ok(), "config with server_id '{}' should parse: {:?}", server_id, result.err());
    }

    #[test]
    fn parse_config_invalid_server_id_rejected(
        prefix in "[a-zA-Z]{1,10}",
    ) {
        // Server IDs not starting with "SSH-2.0-" should be rejected
        prop_assume!(!prefix.starts_with("SSH-2.0-"));
        let toml = format!(
            r##"
[server]
ssh_listen = "0.0.0.0:2222"
server_id = "{}"

[[users]]
username = "test"
password_hash = "{}"
"##,
            prefix, FAKE_HASH,
        );
        let result = sks5::config::parse_config(&toml);
        prop_assert!(result.is_err(), "invalid server_id '{}' should be rejected", prefix);
    }

    #[test]
    fn parse_config_with_acl_rules(
        n_allow in 0usize..5,
        n_deny in 0usize..5,
    ) {
        let allow_rules: Vec<String> = (0..n_allow)
            .map(|i| format!("\"host{}.example.com:443\"", i))
            .collect();
        let deny_rules: Vec<String> = (0..n_deny)
            .map(|i| format!("\"bad{}.example.com:*\"", i))
            .collect();
        let toml = format!(
            r##"
[server]
ssh_listen = "0.0.0.0:2222"

[acl]
default_policy = "deny"
allow = [{}]
deny = [{}]

[[users]]
username = "test"
password_hash = "{}"
"##,
            allow_rules.join(", "),
            deny_rules.join(", "),
            FAKE_HASH,
        );
        let result = sks5::config::parse_config(&toml);
        prop_assert!(result.is_ok(), "config with {} allow + {} deny ACL rules should parse: {:?}", n_allow, n_deny, result.err());
    }

    #[test]
    fn parse_config_multiple_users(n_users in 1usize..=10) {
        let mut toml = String::from(
            r##"
[server]
ssh_listen = "0.0.0.0:2222"
"##
        );
        for i in 0..n_users {
            toml.push_str(&format!(
                r##"
[[users]]
username = "user{}"
password_hash = "{}"
"##,
                i, FAKE_HASH,
            ));
        }
        let result = sks5::config::parse_config(&toml);
        prop_assert!(result.is_ok(), "config with {} users should parse: {:?}", n_users, result.err());
        let config = result.unwrap();
        prop_assert_eq!(config.users.len(), n_users);
    }

    #[test]
    fn parse_config_connection_timeout_zero_rejected(
        timeout in 0u64..=0u64,
    ) {
        let _ = timeout; // always 0
        let toml = format!(
            r##"
[server]
ssh_listen = "0.0.0.0:2222"

[limits]
connection_timeout = 0

[[users]]
username = "test"
password_hash = "{}"
"##,
            FAKE_HASH,
        );
        let result = sks5::config::parse_config(&toml);
        prop_assert!(result.is_err(), "connection_timeout=0 should be rejected");
    }

    #[test]
    fn parse_config_valid_limits(
        max_conn in 1u32..=10000u32,
        conn_timeout in 1u64..=3600u64,
        max_auth in 1u32..=100u32,
    ) {
        let toml = format!(
            r##"
[server]
ssh_listen = "0.0.0.0:2222"

[limits]
max_connections = {}
connection_timeout = {}
max_auth_attempts = {}

[[users]]
username = "test"
password_hash = "{}"
"##,
            max_conn, conn_timeout, max_auth, FAKE_HASH,
        );
        let result = sks5::config::parse_config(&toml);
        prop_assert!(result.is_ok(), "valid limits should parse: {:?}", result.err());
    }
}
