use sks5::config::types::ParsedUpstreamProxy;

#[test]
fn test_parse_valid_url_no_auth() {
    let proxy = ParsedUpstreamProxy::from_url("socks5://proxy.example.com:1080").unwrap();
    assert_eq!(proxy.host, "proxy.example.com");
    assert_eq!(proxy.port, 1080);
    assert!(proxy.username.is_none());
    assert!(proxy.password.is_none());
}

#[test]
fn test_parse_valid_url_with_auth() {
    let proxy = ParsedUpstreamProxy::from_url("socks5://user:pass@proxy.example.com:1080").unwrap();
    assert_eq!(proxy.host, "proxy.example.com");
    assert_eq!(proxy.port, 1080);
    assert_eq!(proxy.username.as_deref(), Some("user"));
    assert_eq!(proxy.password.as_deref(), Some("pass"));
}

#[test]
fn test_parse_url_with_encoded_credentials() {
    let proxy =
        ParsedUpstreamProxy::from_url("socks5://us%40er:p%40ss@proxy.example.com:1080").unwrap();
    assert_eq!(proxy.username.as_deref(), Some("us@er"));
    assert_eq!(proxy.password.as_deref(), Some("p@ss"));
}

#[test]
fn test_parse_url_with_ip_host() {
    let proxy = ParsedUpstreamProxy::from_url("socks5://127.0.0.1:1080").unwrap();
    assert_eq!(proxy.host, "127.0.0.1");
    assert_eq!(proxy.port, 1080);
}

#[test]
fn test_parse_url_with_username_only() {
    let proxy = ParsedUpstreamProxy::from_url("socks5://onlyuser@proxy:9050").unwrap();
    assert_eq!(proxy.username.as_deref(), Some("onlyuser"));
    assert!(proxy.password.is_none());
}

#[test]
fn test_parse_url_invalid_scheme_http() {
    let err = ParsedUpstreamProxy::from_url("http://proxy:1080").unwrap_err();
    assert!(
        err.to_string()
            .contains("unsupported upstream proxy scheme"),
        "got: {}",
        err
    );
}

#[test]
fn test_parse_url_invalid_scheme_socks4() {
    let err = ParsedUpstreamProxy::from_url("socks4://proxy:1080").unwrap_err();
    assert!(
        err.to_string()
            .contains("unsupported upstream proxy scheme"),
        "got: {}",
        err
    );
}

#[test]
fn test_parse_url_missing_port() {
    let err = ParsedUpstreamProxy::from_url("socks5://proxy.example.com").unwrap_err();
    assert!(err.to_string().contains("missing port"), "got: {}", err);
}

#[test]
fn test_parse_url_missing_host() {
    let err = ParsedUpstreamProxy::from_url("socks5://:1080").unwrap_err();
    // url crate treats empty host as missing
    assert!(err.to_string().contains("invalid") || err.to_string().contains("host"));
}

#[test]
fn test_parse_url_completely_invalid() {
    let err = ParsedUpstreamProxy::from_url("not-a-url").unwrap_err();
    assert!(err.to_string().contains("invalid"), "got: {}", err);
}

#[test]
fn test_display_addr() {
    let proxy =
        ParsedUpstreamProxy::from_url("socks5://user:secret@proxy.example.com:1080").unwrap();
    let display = proxy.display_addr();
    assert_eq!(display, "socks5://proxy.example.com:1080");
    assert!(!display.contains("user"));
    assert!(!display.contains("secret"));
}

// --- Priority resolution tests ---

mod resolve_priority {
    use sks5::config::types::{
        AppConfig, ConnectionPoolConfig, GlobalAclConfig, LimitsConfig, ServerConfig, ShellConfig,
        UpstreamProxyConfig,
    };

    fn make_minimal_config(upstream: Option<&str>) -> AppConfig {
        AppConfig {
            server: ServerConfig {
                ssh_listen: "127.0.0.1:2222".to_string(),
                socks5_listen: None,
                host_key_path: "host_key".into(),
                server_id: "SSH-2.0-sks5".to_string(),
                banner: "test".to_string(),
                motd_path: None,
                proxy_protocol: false,
                allowed_ciphers: Vec::new(),
                allowed_kex: Vec::new(),
                shutdown_timeout: 30,
                socks5_tls_cert: None,
                socks5_tls_key: None,
                dns_cache_ttl: -1,
                dns_cache_max_entries: 1000,
                connect_retry: 0,
                connect_retry_delay_ms: 1000,
                bookmarks_path: None,
                ssh_keepalive_interval_secs: 15,
                ssh_keepalive_max: 3,
                ssh_auth_timeout: 120,
            },
            shell: ShellConfig::default(),
            limits: LimitsConfig::default(),
            security: Default::default(),
            logging: Default::default(),
            metrics: Default::default(),
            api: Default::default(),
            geoip: Default::default(),
            upstream_proxy: upstream.map(|u| UpstreamProxyConfig { url: u.to_string() }),
            webhooks: Vec::new(),
            acl: GlobalAclConfig::default(),
            users: Vec::new(),
            groups: Vec::new(),
            motd: Default::default(),
            alerting: Default::default(),
            maintenance_windows: Vec::new(),
            connection_pool: ConnectionPoolConfig::default(),
        }
    }

    fn make_user(upstream: Option<&str>) -> sks5::auth::user::User {
        use sks5::config::acl::ParsedAcl;
        use sks5::config::types::{AclPolicyConfig, RateLimitsConfig, ShellPermissions, UserRole};
        use std::collections::HashMap;

        sks5::auth::user::User {
            username: "testuser".to_string(),
            password_hash: None,
            authorized_keys: Vec::new(),
            parsed_authorized_keys: Vec::new(),
            allow_forwarding: true,
            allow_shell: true,
            max_new_connections_per_minute: 0,
            max_bandwidth_kbps: 0,
            source_ips: Vec::new(),
            expires_at: None,
            upstream_proxy: upstream.map(|u| u.to_string()),
            acl: ParsedAcl::from_config(AclPolicyConfig::Allow, &[], &[]).unwrap(),
            totp_enabled: false,
            totp_secret: None,
            max_aggregate_bandwidth_kbps: 0,
            group: None,
            role: UserRole::User,
            shell_permissions: ShellPermissions::default(),
            motd_config: None,
            quotas: None,
            time_access: None,
            auth_methods: None,
            idle_warning_secs: 0,
            colors: true,
            connect_retry: 0,
            connect_retry_delay_ms: 1000,
            aliases: HashMap::new(),
            max_connections: 0,
            rate_limits: RateLimitsConfig::default(),
        }
    }

    #[test]
    fn test_no_upstream_proxy() {
        let config = make_minimal_config(None);
        let user = make_user(None);
        let result = sks5::proxy::ProxyEngine::resolve_upstream_proxy(&user, &config);
        assert!(result.is_none());
    }

    #[test]
    fn test_global_upstream_proxy() {
        let config = make_minimal_config(Some("socks5://global-proxy:1080"));
        let user = make_user(None);
        let result = sks5::proxy::ProxyEngine::resolve_upstream_proxy(&user, &config);
        let proxy = result.expect("should resolve global proxy");
        assert_eq!(proxy.host, "global-proxy");
        assert_eq!(proxy.port, 1080);
    }

    #[test]
    fn test_user_upstream_proxy_overrides_global() {
        let config = make_minimal_config(Some("socks5://global-proxy:1080"));
        let user = make_user(Some("socks5://user-proxy:9050"));
        let result = sks5::proxy::ProxyEngine::resolve_upstream_proxy(&user, &config);
        let proxy = result.expect("should resolve user proxy");
        assert_eq!(proxy.host, "user-proxy");
        assert_eq!(proxy.port, 9050);
    }

    #[test]
    fn test_user_upstream_proxy_no_global() {
        let config = make_minimal_config(None);
        let user = make_user(Some("socks5://user-proxy:9050"));
        let result = sks5::proxy::ProxyEngine::resolve_upstream_proxy(&user, &config);
        let proxy = result.expect("should resolve user proxy");
        assert_eq!(proxy.host, "user-proxy");
    }

    #[test]
    fn test_invalid_url_falls_back_to_none() {
        let config = make_minimal_config(None);
        let user = make_user(Some("http://invalid-scheme:1080"));
        let result = sks5::proxy::ProxyEngine::resolve_upstream_proxy(&user, &config);
        assert!(result.is_none(), "invalid URL should return None");
    }
}
