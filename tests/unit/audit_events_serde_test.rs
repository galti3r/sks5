use std::net::{IpAddr, SocketAddr};

use sks5::audit::events::AuditEvent;

// ===========================================================================
// Serde round-trip: each variant serializes with correct event_type tag
// and all expected fields
// ===========================================================================

#[test]
fn serde_auth_success_contains_all_fields() {
    let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();
    let event = AuditEvent::auth_success("alice", &addr, "password");
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "auth.success");
    assert_eq!(json["username"], "alice");
    assert_eq!(json["source_ip"], "1.2.3.4");
    assert_eq!(json["method"], "password");
    assert!(json["timestamp"].is_string());
    // correlation_id should be absent (skip_serializing_if = None)
    assert!(
        json.get("correlation_id").is_none(),
        "correlation_id should be omitted when None"
    );
}

#[test]
fn serde_auth_failure_contains_all_fields() {
    let addr: SocketAddr = "10.0.0.1:9999".parse().unwrap();
    let event = AuditEvent::auth_failure("bob", &addr, "pubkey");
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "auth.failure");
    assert_eq!(json["username"], "bob");
    assert_eq!(json["source_ip"], "10.0.0.1");
    assert_eq!(json["method"], "pubkey");
    assert!(json["timestamp"].is_string());
    assert!(
        json.get("correlation_id").is_none(),
        "correlation_id should be omitted when None"
    );
}

#[test]
fn serde_proxy_complete_contains_all_fields() {
    let addr: SocketAddr = "203.0.113.25:9999".parse().unwrap();
    let event = AuditEvent::proxy_complete(
        "charlie",
        "example.org",
        443,
        1024,
        2048,
        500,
        &addr,
        Some("93.184.216.34".to_string()),
    );
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "proxy.complete");
    assert_eq!(json["username"], "charlie");
    assert_eq!(json["target_host"], "example.org");
    assert_eq!(json["target_port"], 443);
    assert_eq!(json["bytes_uploaded"], 1024);
    assert_eq!(json["bytes_downloaded"], 2048);
    assert_eq!(json["bytes_transferred"], 3072);
    assert_eq!(json["duration_ms"], 500);
    assert_eq!(json["source_ip"], "203.0.113.25");
    assert_eq!(json["resolved_ip"], "93.184.216.34");
    assert!(json["timestamp"].is_string());
    assert!(json.get("correlation_id").is_none());
}

#[test]
fn serde_proxy_complete_omits_resolved_ip_when_none() {
    let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();
    let event = AuditEvent::proxy_complete("user", "host.com", 80, 100, 200, 50, &addr, None);
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "proxy.complete");
    assert!(
        json.get("resolved_ip").is_none(),
        "resolved_ip should be omitted when None"
    );
}

#[test]
fn serde_acl_deny_contains_all_fields() {
    let event = AuditEvent::acl_deny(
        "eve",
        "evil.com",
        80,
        Some("6.6.6.6".to_string()),
        "10.0.0.1",
        Some("deny *.evil.com".to_string()),
        "hostname blocked",
    );
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "acl.deny");
    assert_eq!(json["username"], "eve");
    assert_eq!(json["target_host"], "evil.com");
    assert_eq!(json["target_port"], 80);
    assert_eq!(json["resolved_ip"], "6.6.6.6");
    assert_eq!(json["source_ip"], "10.0.0.1");
    assert_eq!(json["matched_rule"], "deny *.evil.com");
    assert_eq!(json["reason"], "hostname blocked");
    assert!(json["timestamp"].is_string());
    assert!(json.get("correlation_id").is_none());
}

#[test]
fn serde_acl_deny_omits_optional_fields_when_none() {
    let event = AuditEvent::acl_deny("user", "host.com", 443, None, "1.2.3.4", None, "denied");
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "acl.deny");
    assert!(
        json.get("resolved_ip").is_none(),
        "resolved_ip should be omitted when None"
    );
    assert!(
        json.get("matched_rule").is_none(),
        "matched_rule should be omitted when None"
    );
    assert!(json.get("correlation_id").is_none());
}

#[test]
fn serde_connection_new_contains_all_fields() {
    let addr: SocketAddr = "172.16.0.5:8080".parse().unwrap();
    let event = AuditEvent::connection_new(&addr, "ssh");
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "connection.new");
    assert_eq!(json["source_ip"], "172.16.0.5");
    assert_eq!(json["protocol"], "ssh");
    assert!(json["timestamp"].is_string());
    assert!(json.get("correlation_id").is_none());
}

#[test]
fn serde_connection_closed_contains_all_fields() {
    let addr: SocketAddr = "172.16.0.5:8080".parse().unwrap();
    let event = AuditEvent::connection_closed(&addr, "socks5");
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "connection.closed");
    assert_eq!(json["source_ip"], "172.16.0.5");
    assert_eq!(json["protocol"], "socks5");
    assert!(json["timestamp"].is_string());
    assert!(json.get("correlation_id").is_none());
}

#[test]
fn serde_config_reload_contains_all_fields() {
    let event = AuditEvent::config_reload(5, true, None);
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "config.reload");
    assert_eq!(json["users_count"], 5);
    assert_eq!(json["success"], true);
    assert!(json["timestamp"].is_string());
    assert!(
        json.get("error").is_none(),
        "error should be omitted when None"
    );
}

#[test]
fn serde_config_reload_includes_error_when_present() {
    let event = AuditEvent::config_reload(0, false, Some("parse error".to_string()));
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "config.reload");
    assert_eq!(json["success"], false);
    assert_eq!(json["error"], "parse error");
}

#[test]
fn serde_quota_exceeded_contains_all_fields() {
    let event = AuditEvent::quota_exceeded("alice", "bandwidth", 1_000_000, 500_000);
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "quota.exceeded");
    assert_eq!(json["username"], "alice");
    assert_eq!(json["quota_type"], "bandwidth");
    assert_eq!(json["current_usage"], 1_000_000);
    assert_eq!(json["limit"], 500_000);
    assert!(json["timestamp"].is_string());
    assert!(json.get("correlation_id").is_none());
}

#[test]
fn serde_session_authenticated_contains_all_fields() {
    let addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
    let event = AuditEvent::session_authenticated("alice", &addr, "ssh", "password+totp");
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "session.authenticated");
    assert_eq!(json["username"], "alice");
    assert_eq!(json["source_ip"], "10.0.0.1");
    assert_eq!(json["protocol"], "ssh");
    assert_eq!(json["method"], "password+totp");
    assert!(json["timestamp"].is_string());
    assert!(json.get("correlation_id").is_none());
}

#[test]
fn serde_session_ended_contains_all_fields() {
    let addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
    let event = AuditEvent::session_ended("alice", &addr, "ssh", 3600, 1_000_000);
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "session.ended");
    assert_eq!(json["username"], "alice");
    assert_eq!(json["source_ip"], "10.0.0.1");
    assert_eq!(json["protocol"], "ssh");
    assert_eq!(json["duration_secs"], 3600);
    assert_eq!(json["total_bytes"], 1_000_000);
    assert!(json["timestamp"].is_string());
    assert!(json.get("correlation_id").is_none());
}

#[test]
fn serde_rate_limit_exceeded_contains_all_fields() {
    let addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
    let event = AuditEvent::rate_limit_exceeded("alice", &addr, "per_user");
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "rate_limit.exceeded");
    assert_eq!(json["username"], "alice");
    assert_eq!(json["source_ip"], "10.0.0.1");
    assert_eq!(json["limit_type"], "per_user");
    assert!(json["timestamp"].is_string());
    assert!(json.get("correlation_id").is_none());
}

#[test]
fn serde_maintenance_toggled_contains_all_fields() {
    let event = AuditEvent::maintenance_toggled(true, "api");
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "maintenance.toggled");
    assert_eq!(json["enabled"], true);
    assert_eq!(json["source"], "api");
    assert!(json["timestamp"].is_string());
}

// ===========================================================================
// Correlation ID: all *_with_cid constructors
// ===========================================================================

#[test]
fn auth_success_with_cid_sets_correlation_id() {
    let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();
    let event = AuditEvent::auth_success_with_cid("alice", &addr, "password", "cid-auth-001");
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "auth.success");
    assert_eq!(json["correlation_id"], "cid-auth-001");
    assert_eq!(json["username"], "alice");
    assert_eq!(json["source_ip"], "1.2.3.4");
    assert_eq!(json["method"], "password");
}

#[test]
fn auth_failure_with_cid_sets_correlation_id() {
    let addr: SocketAddr = "10.0.0.1:9999".parse().unwrap();
    let event = AuditEvent::auth_failure_with_cid("bob", &addr, "pubkey", "cid-fail-002");
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "auth.failure");
    assert_eq!(json["correlation_id"], "cid-fail-002");
    assert_eq!(json["username"], "bob");
    assert_eq!(json["source_ip"], "10.0.0.1");
    assert_eq!(json["method"], "pubkey");
}

#[test]
fn proxy_complete_with_cid_sets_correlation_id() {
    let addr: SocketAddr = "203.0.113.25:9999".parse().unwrap();
    let event = AuditEvent::proxy_complete_with_cid(
        "charlie",
        "example.org",
        443,
        512,
        1024,
        250,
        &addr,
        Some("93.184.216.34".to_string()),
        "cid-proxy-003",
    );
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "proxy.complete");
    assert_eq!(json["correlation_id"], "cid-proxy-003");
    assert_eq!(json["username"], "charlie");
    assert_eq!(json["target_host"], "example.org");
    assert_eq!(json["target_port"], 443);
    assert_eq!(json["bytes_uploaded"], 512);
    assert_eq!(json["bytes_downloaded"], 1024);
    assert_eq!(json["bytes_transferred"], 1536);
    assert_eq!(json["duration_ms"], 250);
}

#[test]
fn acl_deny_with_cid_sets_correlation_id() {
    let event = AuditEvent::acl_deny_with_cid(
        "eve",
        "evil.com",
        80,
        None,
        "10.0.0.1",
        Some("deny *".to_string()),
        "policy denied",
        "cid-acl-004",
    );
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "acl.deny");
    assert_eq!(json["correlation_id"], "cid-acl-004");
    assert_eq!(json["username"], "eve");
    assert_eq!(json["target_host"], "evil.com");
    assert_eq!(json["target_port"], 80);
    assert_eq!(json["reason"], "policy denied");
}

#[test]
fn connection_new_with_cid_sets_correlation_id() {
    let addr: SocketAddr = "172.16.0.5:8080".parse().unwrap();
    let event = AuditEvent::connection_new_with_cid(&addr, "ssh", "cid-conn-005");
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "connection.new");
    assert_eq!(json["correlation_id"], "cid-conn-005");
    assert_eq!(json["source_ip"], "172.16.0.5");
    assert_eq!(json["protocol"], "ssh");
}

#[test]
fn connection_closed_with_cid_sets_correlation_id() {
    let addr: SocketAddr = "172.16.0.5:8080".parse().unwrap();
    let event = AuditEvent::connection_closed_with_cid(&addr, "socks5", "cid-conn-006");
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "connection.closed");
    assert_eq!(json["correlation_id"], "cid-conn-006");
    assert_eq!(json["source_ip"], "172.16.0.5");
    assert_eq!(json["protocol"], "socks5");
}

#[test]
fn quota_exceeded_with_cid_sets_correlation_id() {
    let event =
        AuditEvent::quota_exceeded_with_cid("alice", "connections", 100, 50, "cid-quota-007");
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "quota.exceeded");
    assert_eq!(json["correlation_id"], "cid-quota-007");
    assert_eq!(json["username"], "alice");
    assert_eq!(json["quota_type"], "connections");
    assert_eq!(json["current_usage"], 100);
    assert_eq!(json["limit"], 50);
}

#[test]
fn session_authenticated_with_cid_sets_correlation_id() {
    let addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
    let event =
        AuditEvent::session_authenticated_with_cid("alice", &addr, "ssh", "pubkey", "cid-sess-008");
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "session.authenticated");
    assert_eq!(json["correlation_id"], "cid-sess-008");
    assert_eq!(json["username"], "alice");
    assert_eq!(json["source_ip"], "10.0.0.1");
    assert_eq!(json["protocol"], "ssh");
    assert_eq!(json["method"], "pubkey");
}

#[test]
fn session_ended_with_cid_sets_correlation_id() {
    let addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
    let event =
        AuditEvent::session_ended_with_cid("alice", &addr, "ssh", 7200, 2_000_000, "cid-sess-009");
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "session.ended");
    assert_eq!(json["correlation_id"], "cid-sess-009");
    assert_eq!(json["username"], "alice");
    assert_eq!(json["source_ip"], "10.0.0.1");
    assert_eq!(json["protocol"], "ssh");
    assert_eq!(json["duration_secs"], 7200);
    assert_eq!(json["total_bytes"], 2_000_000);
}

#[test]
fn rate_limit_exceeded_with_cid_sets_correlation_id() {
    let addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
    let event = AuditEvent::rate_limit_exceeded_with_cid("alice", &addr, "global", "cid-rate-010");
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "rate_limit.exceeded");
    assert_eq!(json["correlation_id"], "cid-rate-010");
    assert_eq!(json["username"], "alice");
    assert_eq!(json["source_ip"], "10.0.0.1");
    assert_eq!(json["limit_type"], "global");
}

// ===========================================================================
// Ban events: ban_created and ban_expired
// ===========================================================================

#[test]
fn serde_ban_created_contains_all_fields() {
    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    let event = AuditEvent::ban_created(&ip, 3600);
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "ban.created");
    assert_eq!(json["ip"], "192.168.1.100");
    assert_eq!(json["duration_secs"], 3600);
    assert!(json["timestamp"].is_string());
}

#[test]
fn serde_ban_created_with_ipv6() {
    let ip: IpAddr = "2001:db8::1".parse().unwrap();
    let event = AuditEvent::ban_created(&ip, 600);
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "ban.created");
    assert_eq!(json["ip"], "2001:db8::1");
    assert_eq!(json["duration_secs"], 600);
}

#[test]
fn serde_ban_expired_contains_all_fields() {
    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    let event = AuditEvent::ban_expired(&ip);
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "ban.expired");
    assert_eq!(json["ip"], "192.168.1.100");
    assert!(json["timestamp"].is_string());
    // ban.expired should not have duration_secs
    assert!(
        json.get("duration_secs").is_none(),
        "ban.expired should not contain duration_secs"
    );
}

#[test]
fn serde_ban_expired_with_ipv6() {
    let ip: IpAddr = "::1".parse().unwrap();
    let event = AuditEvent::ban_expired(&ip);
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["event_type"], "ban.expired");
    assert_eq!(json["ip"], "::1");
}

// ===========================================================================
// bytes_transferred calculation: bytes_up + bytes_down
// ===========================================================================

#[test]
fn proxy_complete_bytes_transferred_is_sum_of_up_and_down() {
    let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();

    // Case 1: typical values
    let event = AuditEvent::proxy_complete("user", "host.com", 80, 1000, 2000, 100, &addr, None);
    let json = serde_json::to_value(&event).unwrap();
    assert_eq!(json["bytes_transferred"], 3000);
    assert_eq!(json["bytes_uploaded"], 1000);
    assert_eq!(json["bytes_downloaded"], 2000);

    // Case 2: zero upload
    let event = AuditEvent::proxy_complete("user", "host.com", 80, 0, 5000, 100, &addr, None);
    let json = serde_json::to_value(&event).unwrap();
    assert_eq!(json["bytes_transferred"], 5000);
    assert_eq!(json["bytes_uploaded"], 0);
    assert_eq!(json["bytes_downloaded"], 5000);

    // Case 3: zero download
    let event = AuditEvent::proxy_complete("user", "host.com", 80, 4096, 0, 100, &addr, None);
    let json = serde_json::to_value(&event).unwrap();
    assert_eq!(json["bytes_transferred"], 4096);
    assert_eq!(json["bytes_uploaded"], 4096);
    assert_eq!(json["bytes_downloaded"], 0);

    // Case 4: both zero
    let event = AuditEvent::proxy_complete("user", "host.com", 80, 0, 0, 100, &addr, None);
    let json = serde_json::to_value(&event).unwrap();
    assert_eq!(json["bytes_transferred"], 0);

    // Case 5: large values near u64 boundary
    let large_up: u64 = u64::MAX / 2;
    let large_down: u64 = u64::MAX / 2;
    let event = AuditEvent::proxy_complete(
        "user", "host.com", 80, large_up, large_down, 100, &addr, None,
    );
    let json = serde_json::to_value(&event).unwrap();
    assert_eq!(json["bytes_transferred"], large_up + large_down);
}

#[test]
fn proxy_complete_with_cid_bytes_transferred_is_sum() {
    let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();
    let event = AuditEvent::proxy_complete_with_cid(
        "user",
        "host.com",
        80,
        750,
        1250,
        200,
        &addr,
        None,
        "cid-bytes-011",
    );
    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(json["bytes_transferred"], 2000);
    assert_eq!(json["bytes_uploaded"], 750);
    assert_eq!(json["bytes_downloaded"], 1250);
    assert_eq!(json["correlation_id"], "cid-bytes-011");
}

// ===========================================================================
// Correlation ID: verify skip_serializing_if behavior across all variants
// ===========================================================================

#[test]
fn correlation_id_absent_in_json_when_none_for_all_variants() {
    let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();

    let events: Vec<AuditEvent> = vec![
        AuditEvent::auth_success("u", &addr, "pw"),
        AuditEvent::auth_failure("u", &addr, "pw"),
        AuditEvent::proxy_complete("u", "h", 80, 0, 0, 0, &addr, None),
        AuditEvent::acl_deny("u", "h", 80, None, "1.2.3.4", None, "r"),
        AuditEvent::connection_new(&addr, "ssh"),
        AuditEvent::connection_closed(&addr, "ssh"),
        AuditEvent::quota_exceeded("u", "bw", 0, 0),
        AuditEvent::session_authenticated("u", &addr, "ssh", "pw"),
        AuditEvent::session_ended("u", &addr, "ssh", 0, 0),
        AuditEvent::rate_limit_exceeded("u", &addr, "per_user"),
    ];

    for event in &events {
        let json = serde_json::to_value(event).unwrap();
        assert!(
            json.get("correlation_id").is_none(),
            "correlation_id should be omitted for event_type={}, got: {:?}",
            json["event_type"],
            json.get("correlation_id")
        );
    }
}

#[test]
fn correlation_id_present_in_json_when_some_for_all_with_cid_variants() {
    let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();
    let cid = "test-cid-unified";

    let events: Vec<AuditEvent> = vec![
        AuditEvent::auth_success_with_cid("u", &addr, "pw", cid),
        AuditEvent::auth_failure_with_cid("u", &addr, "pw", cid),
        AuditEvent::proxy_complete_with_cid("u", "h", 80, 0, 0, 0, &addr, None, cid),
        AuditEvent::acl_deny_with_cid("u", "h", 80, None, "1.2.3.4", None, "r", cid),
        AuditEvent::connection_new_with_cid(&addr, "ssh", cid),
        AuditEvent::connection_closed_with_cid(&addr, "ssh", cid),
        AuditEvent::quota_exceeded_with_cid("u", "bw", 0, 0, cid),
        AuditEvent::session_authenticated_with_cid("u", &addr, "ssh", "pw", cid),
        AuditEvent::session_ended_with_cid("u", &addr, "ssh", 0, 0, cid),
        AuditEvent::rate_limit_exceeded_with_cid("u", &addr, "per_user", cid),
    ];

    for event in &events {
        let json = serde_json::to_value(event).unwrap();
        assert_eq!(
            json["correlation_id"], cid,
            "correlation_id should be '{}' for event_type={}",
            cid, json["event_type"]
        );
    }
}

// ===========================================================================
// Ban events do not have correlation_id fields at all
// ===========================================================================

#[test]
fn ban_events_have_no_correlation_id_field() {
    let ip: IpAddr = "192.168.1.1".parse().unwrap();

    let ban_created = AuditEvent::ban_created(&ip, 300);
    let json = serde_json::to_value(&ban_created).unwrap();
    assert!(
        json.get("correlation_id").is_none(),
        "ban.created should not have correlation_id"
    );

    let ban_expired = AuditEvent::ban_expired(&ip);
    let json = serde_json::to_value(&ban_expired).unwrap();
    assert!(
        json.get("correlation_id").is_none(),
        "ban.expired should not have correlation_id"
    );
}

// ===========================================================================
// JSON string output is valid and parseable
// ===========================================================================

#[test]
fn serde_to_string_produces_valid_json_for_all_variants() {
    let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();
    let ip: IpAddr = "192.168.1.1".parse().unwrap();

    let events: Vec<AuditEvent> = vec![
        AuditEvent::auth_success("u", &addr, "pw"),
        AuditEvent::auth_failure("u", &addr, "pw"),
        AuditEvent::proxy_complete("u", "h", 80, 100, 200, 50, &addr, None),
        AuditEvent::acl_deny("u", "h", 80, None, "1.2.3.4", None, "r"),
        AuditEvent::ban_created(&ip, 60),
        AuditEvent::ban_expired(&ip),
        AuditEvent::connection_new(&addr, "ssh"),
        AuditEvent::connection_closed(&addr, "ssh"),
        AuditEvent::config_reload(3, true, None),
        AuditEvent::quota_exceeded("u", "bw", 100, 50),
        AuditEvent::session_authenticated("u", &addr, "ssh", "pw"),
        AuditEvent::session_ended("u", &addr, "ssh", 60, 1000),
        AuditEvent::rate_limit_exceeded("u", &addr, "per_user"),
        AuditEvent::maintenance_toggled(false, "config_reload"),
    ];

    for event in &events {
        let json_str = serde_json::to_string(event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(
            parsed["event_type"].is_string(),
            "event_type should be a string in JSON output"
        );
        assert!(
            parsed["timestamp"].is_string(),
            "timestamp should be a string in JSON output for event_type={}",
            parsed["event_type"]
        );
    }
}
