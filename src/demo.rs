use crate::audit::events::AuditEvent;
use crate::config::types::{
    AclPolicyConfig, ApiConfig, AppConfig, GlobalAclConfig, GroupConfig, LoggingConfig,
    QuotaConfig, SecurityConfig, ServerConfig, ShellConfig, UserAclConfig, UserConfig, UserRole,
};
use crate::context::AppContext;
use crate::proxy::LiveSession;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

/// Build a demo-ready `AppConfig` with 3 users, ACLs, quotas, and groups.
pub fn build_demo_config(
    ssh_port: u16,
    socks5_port: u16,
    api_port: u16,
    password_hash: &str,
) -> AppConfig {
    AppConfig {
        server: ServerConfig {
            ssh_listen: format!("127.0.0.1:{}", ssh_port),
            socks5_listen: Some(format!("127.0.0.1:{}", socks5_port)),
            host_key_path: std::path::PathBuf::from("/tmp/sks5-demo-host-key"),
            server_id: "SSH-2.0-sks5-demo".to_string(),
            banner: "Welcome to sks5 demo".to_string(),
            motd_path: None,
            proxy_protocol: false,
            allowed_ciphers: Vec::new(),
            allowed_kex: Vec::new(),
            shutdown_timeout: 5,
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
        shell: ShellConfig {
            hostname: "sks5-demo".to_string(),
            ..ShellConfig::default()
        },
        limits: Default::default(),
        security: SecurityConfig {
            ban_enabled: true,
            ip_guard_enabled: false,
            ..SecurityConfig::default()
        },
        logging: LoggingConfig::default(),
        metrics: Default::default(),
        api: ApiConfig {
            enabled: true,
            listen: format!("127.0.0.1:{}", api_port),
            token: "demo".to_string(),
        },
        geoip: Default::default(),
        upstream_proxy: None,
        webhooks: Vec::new(),
        acl: GlobalAclConfig {
            default_policy: AclPolicyConfig::Deny,
            allow: vec![
                "*.example.com:443".to_string(),
                "*.github.com:443".to_string(),
                "httpbin.org:*".to_string(),
                "example.com:*".to_string(),
            ],
            deny: vec!["*.internal:*".to_string(), "10.0.0.0/8:*".to_string()],
        },
        users: vec![
            // alice: admin with shell+fwd and generous quotas
            UserConfig {
                username: "alice".to_string(),
                password_hash: Some(password_hash.to_string()),
                authorized_keys: Vec::new(),
                allow_forwarding: true,
                allow_shell: Some(true),
                max_new_connections_per_minute: 0,
                max_bandwidth_kbps: 0,
                source_ips: Vec::new(),
                expires_at: None,
                upstream_proxy: None,
                acl: UserAclConfig::default(),
                totp_secret: None,
                totp_enabled: false,
                max_aggregate_bandwidth_kbps: 0,
                group: Some("developers".to_string()),
                role: UserRole::Admin,
                shell_permissions: None,
                motd: None,
                quotas: Some(QuotaConfig {
                    daily_bandwidth_bytes: 5_368_709_120,    // 5 GB
                    monthly_bandwidth_bytes: 53_687_091_200, // 50 GB
                    bandwidth_per_hour_bytes: 1_073_741_824, // 1 GB
                    daily_connection_limit: 100,
                    monthly_connection_limit: 1000,
                    total_bandwidth_bytes: 0,
                }),
                time_access: None,
                auth_methods: None,
                idle_warning_secs: None,
                colors: None,
                connect_retry: None,
                connect_retry_delay_ms: None,
                aliases: HashMap::new(),
                max_connections: None,
                rate_limits: None,
            },
            // bob: forwarding only, moderate quotas
            UserConfig {
                username: "bob".to_string(),
                password_hash: Some(password_hash.to_string()),
                authorized_keys: Vec::new(),
                allow_forwarding: true,
                allow_shell: Some(false),
                max_new_connections_per_minute: 0,
                max_bandwidth_kbps: 0,
                source_ips: Vec::new(),
                expires_at: None,
                upstream_proxy: None,
                acl: UserAclConfig::default(),
                totp_secret: None,
                totp_enabled: false,
                max_aggregate_bandwidth_kbps: 0,
                group: Some("developers".to_string()),
                role: UserRole::User,
                shell_permissions: None,
                motd: None,
                quotas: Some(QuotaConfig {
                    daily_bandwidth_bytes: 2_147_483_648,    // 2 GB
                    monthly_bandwidth_bytes: 21_474_836_480, // 20 GB
                    bandwidth_per_hour_bytes: 536_870_912,   // 512 MB
                    daily_connection_limit: 50,
                    monthly_connection_limit: 500,
                    total_bandwidth_bytes: 0,
                }),
                time_access: None,
                auth_methods: None,
                idle_warning_secs: None,
                colors: None,
                connect_retry: None,
                connect_retry_delay_ms: None,
                aliases: HashMap::new(),
                max_connections: None,
                rate_limits: None,
            },
            // charlie: shell+fwd, tight quotas
            UserConfig {
                username: "charlie".to_string(),
                password_hash: Some(password_hash.to_string()),
                authorized_keys: Vec::new(),
                allow_forwarding: true,
                allow_shell: Some(true),
                max_new_connections_per_minute: 0,
                max_bandwidth_kbps: 0,
                source_ips: Vec::new(),
                expires_at: None,
                upstream_proxy: None,
                acl: UserAclConfig::default(),
                totp_secret: None,
                totp_enabled: false,
                max_aggregate_bandwidth_kbps: 0,
                group: None,
                role: UserRole::User,
                shell_permissions: None,
                motd: None,
                quotas: Some(QuotaConfig {
                    daily_bandwidth_bytes: 536_870_912,     // 500 MB
                    monthly_bandwidth_bytes: 5_368_709_120, // 5 GB
                    bandwidth_per_hour_bytes: 268_435_456,  // 256 MB
                    daily_connection_limit: 20,
                    monthly_connection_limit: 200,
                    total_bandwidth_bytes: 0,
                }),
                time_access: None,
                auth_methods: None,
                idle_warning_secs: None,
                colors: None,
                connect_retry: None,
                connect_retry_delay_ms: None,
                aliases: HashMap::new(),
                max_connections: None,
                rate_limits: None,
            },
        ],
        groups: vec![GroupConfig {
            name: "developers".to_string(),
            acl: UserAclConfig::default(),
            max_connections_per_user: None,
            max_bandwidth_kbps: Some(10240),
            max_aggregate_bandwidth_kbps: None,
            max_new_connections_per_minute: None,
            allow_forwarding: Some(true),
            allow_shell: Some(true),
            shell_permissions: None,
            motd: None,
            quotas: None,
            time_access: None,
            auth_methods: None,
            idle_warning_secs: None,
            role: None,
            colors: None,
            connect_retry: None,
            connect_retry_delay_ms: None,
            rate_limits: None,
        }],
        motd: Default::default(),
        alerting: Default::default(),
        maintenance_windows: Vec::new(),
        connection_pool: Default::default(),
    }
}

/// Inject realistic demo data into a running server's `AppContext`.
///
/// Returns a `Vec<Arc<LiveSession>>` that **must be kept alive** for the
/// sessions to remain visible in the dashboard. The caller should hold
/// these until the server shuts down.
pub async fn inject_demo_data(ctx: &AppContext) -> Vec<Arc<LiveSession>> {
    let qt = &ctx.quota_tracker;
    let pe = &ctx.proxy_engine;
    let audit = &ctx.audit;

    // --- Quota data (via restore_user_usage for exact values) ---
    // alice: 1.2 GB daily, 12.4 GB monthly, 45.2 GB total, 42 daily conn, 350 monthly conn
    qt.restore_user_usage(
        "alice",
        1_288_490_189,  // ~1.2 GB daily
        42,             // daily connections
        13_314_398_618, // ~12.4 GB monthly
        350,            // monthly connections
        48_535_150_182, // ~45.2 GB total
    );

    // bob: 256 MB daily, 3.1 GB monthly, 8.5 GB total, 15 daily conn, 120 monthly conn
    qt.restore_user_usage(
        "bob",
        268_435_456,   // 256 MB daily
        15,            // daily connections
        3_328_599_654, // ~3.1 GB monthly
        120,           // monthly connections
        9_126_805_504, // ~8.5 GB total
    );

    // charlie: 50 MB daily, 500 MB monthly, 1.2 GB total, 5 daily conn, 25 monthly conn
    qt.restore_user_usage(
        "charlie",
        52_428_800,    // 50 MB daily
        5,             // daily connections
        524_288_000,   // 500 MB monthly
        25,            // monthly connections
        1_288_490_189, // ~1.2 GB total
    );

    // --- Active sessions ---
    let mut sessions = Vec::new();

    // alice → github.com:443 (ssh)
    let s1 = pe.register_session("alice", "github.com", 443, "10.0.1.42", "ssh");
    s1.bytes_up.store(15_728_640, Ordering::Relaxed); // 15 MB
    s1.bytes_down.store(148_897_792, Ordering::Relaxed); // ~142 MB
    sessions.push(s1);

    // alice → api.example.com:8080 (ssh)
    let s2 = pe.register_session("alice", "api.example.com", 8080, "10.0.1.42", "ssh");
    s2.bytes_up.store(2_097_152, Ordering::Relaxed); // 2 MB
    s2.bytes_down.store(8_388_608, Ordering::Relaxed); // 8 MB
    sessions.push(s2);

    // bob → cdn.example.com:443 (socks5)
    let s3 = pe.register_session("bob", "cdn.example.com", 443, "10.0.1.55", "socks5");
    s3.bytes_up.store(512_000, Ordering::Relaxed); // ~500 KB
    s3.bytes_down.store(89_128_960, Ordering::Relaxed); // ~85 MB
    sessions.push(s3);

    // --- Banned IP ---
    {
        let security = ctx.security.write().await;
        security
            .ban_manager()
            .ban("192.168.99.1".parse().unwrap(), Duration::from_secs(1800));
    }

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

    sessions
}
