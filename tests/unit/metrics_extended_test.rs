use prometheus_client::encoding::text::encode;
use sks5::metrics::error_types;
use sks5::metrics::MetricsRegistry;

// ---------------------------------------------------------------------------
// record_typed_connection_duration: dual histogram recording
// ---------------------------------------------------------------------------

#[test]
fn typed_connection_duration_records_in_both_histograms() {
    let metrics = MetricsRegistry::new();

    metrics.record_typed_connection_duration("alice", "ssh", 12.5);

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    // The type-specific histogram should contain a bucket line with conn_type="ssh"
    assert!(
        buf.contains("sks5_connection_duration_by_type_seconds_bucket"),
        "Should contain type-specific histogram buckets, got:\n{}",
        buf
    );
    assert!(
        buf.contains(r#"conn_type="ssh""#),
        "Type-specific histogram should have conn_type=ssh label, got:\n{}",
        buf
    );
    assert!(
        buf.contains("sks5_connection_duration_by_type_seconds_sum"),
        "Should contain type-specific histogram sum"
    );
    assert!(
        buf.contains("sks5_connection_duration_by_type_seconds_count"),
        "Should contain type-specific histogram count"
    );

    // The backward-compat user-only histogram should also have an entry
    assert!(
        buf.contains("sks5_connection_duration_seconds_bucket"),
        "Should contain user-only histogram buckets (backward compat)"
    );
    assert!(
        buf.contains("sks5_connection_duration_seconds_sum"),
        "Should contain user-only histogram sum (backward compat)"
    );
    assert!(
        buf.contains("sks5_connection_duration_seconds_count"),
        "Should contain user-only histogram count (backward compat)"
    );
}

#[test]
fn typed_connection_duration_socks5_type() {
    let metrics = MetricsRegistry::new();

    metrics.record_typed_connection_duration("bob", "socks5", 3.0);

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    assert!(
        buf.contains(r#"conn_type="socks5""#),
        "Type-specific histogram should have conn_type=socks5 label, got:\n{}",
        buf
    );

    // The user label should appear in both histograms
    let by_type_user = buf
        .lines()
        .any(|l| l.contains("connection_duration_by_type_seconds") && l.contains(r#"user="bob""#));
    assert!(
        by_type_user,
        "Type-specific histogram should have user=bob label"
    );

    let compat_user = buf.lines().any(|l| {
        l.contains("sks5_connection_duration_seconds_bucket") && l.contains(r#"user="bob""#)
    });
    assert!(
        compat_user,
        "User-only histogram should also have user=bob label"
    );
}

#[test]
fn typed_connection_duration_multiple_types_same_user() {
    let metrics = MetricsRegistry::new();

    metrics.record_typed_connection_duration("alice", "ssh", 10.0);
    metrics.record_typed_connection_duration("alice", "socks5", 20.0);

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    // Both connection types should appear in the type-specific histogram
    assert!(
        buf.contains(r#"conn_type="ssh""#),
        "Should contain ssh type"
    );
    assert!(
        buf.contains(r#"conn_type="socks5""#),
        "Should contain socks5 type"
    );

    // The user-only histogram count for alice should be 2 (both observations)
    let count_line = buf.lines().find(|l| {
        l.contains("sks5_connection_duration_seconds_count")
            && l.contains(r#"user="alice""#)
            && !l.starts_with('#')
    });
    assert!(count_line.is_some(), "Should have count line for alice");
    assert!(
        count_line.unwrap().contains(" 2"),
        "User-only histogram count should be 2, got: {}",
        count_line.unwrap()
    );

    // The sum should be 30.0
    let sum_line = buf.lines().find(|l| {
        l.contains("sks5_connection_duration_seconds_sum")
            && l.contains(r#"user="alice""#)
            && !l.starts_with('#')
    });
    assert!(sum_line.is_some(), "Should have sum line for alice");
    assert!(
        sum_line.unwrap().contains("30"),
        "User-only histogram sum should be 30, got: {}",
        sum_line.unwrap()
    );
}

// ---------------------------------------------------------------------------
// record_connection_duration: histogram bucket verification
// ---------------------------------------------------------------------------

#[test]
fn connection_duration_creates_proper_histogram_buckets() {
    let metrics = MetricsRegistry::new();

    // Observe a 2.5-second duration (falls in the 5.0 bucket)
    metrics.record_connection_duration("alice", 2.5);

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    // The DurationHistogramBuilder uses buckets: 1, 5, 15, 30, 60, 300, 600, 1800, 3600
    // Verify specific bucket boundaries appear in the output
    let alice_buckets: Vec<&str> = buf
        .lines()
        .filter(|l| {
            l.contains("sks5_connection_duration_seconds_bucket") && l.contains(r#"user="alice""#)
        })
        .collect();

    assert!(
        !alice_buckets.is_empty(),
        "Should have bucket lines for alice"
    );

    // Check that the 1.0 bucket has 0 (2.5 > 1.0)
    let bucket_1 = alice_buckets
        .iter()
        .find(|l| l.contains("le=\"1\"") || l.contains("le=\"1.0\""));
    assert!(
        bucket_1.is_some(),
        "Should have a le=1 bucket, available buckets:\n{}",
        alice_buckets.join("\n")
    );
    assert!(
        bucket_1.unwrap().ends_with(" 0"),
        "le=1 bucket should have count 0 (value 2.5 > 1.0), got: {}",
        bucket_1.unwrap()
    );

    // Check that the 5.0 bucket has 1 (2.5 <= 5.0)
    let bucket_5 = alice_buckets
        .iter()
        .find(|l| l.contains("le=\"5\"") || l.contains("le=\"5.0\""));
    assert!(
        bucket_5.is_some(),
        "Should have a le=5 bucket, available buckets:\n{}",
        alice_buckets.join("\n")
    );
    assert!(
        bucket_5.unwrap().ends_with(" 1"),
        "le=5 bucket should have count 1 (value 2.5 <= 5.0), got: {}",
        bucket_5.unwrap()
    );

    // The +Inf bucket should always have count 1
    let bucket_inf = alice_buckets.iter().find(|l| l.contains("+Inf"));
    assert!(bucket_inf.is_some(), "Should have a +Inf bucket");
    assert!(
        bucket_inf.unwrap().ends_with(" 1"),
        "+Inf bucket should have count 1, got: {}",
        bucket_inf.unwrap()
    );

    // Sum should be 2.5
    let sum_line = buf.lines().find(|l| {
        l.contains("sks5_connection_duration_seconds_sum") && l.contains(r#"user="alice""#)
    });
    assert!(sum_line.is_some(), "Should have sum line for alice");
    assert!(
        sum_line.unwrap().contains("2.5"),
        "Sum should be 2.5, got: {}",
        sum_line.unwrap()
    );
}

// ---------------------------------------------------------------------------
// record_http_request: status code formatting for all pre-formatted codes
// ---------------------------------------------------------------------------

#[test]
fn http_request_preformatted_status_200() {
    let metrics = MetricsRegistry::new();
    metrics.record_http_request("GET", "/api/sessions", 200);

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    let line = buf.lines().find(|l| {
        l.contains("http_requests_total") && l.contains(r#"status="200""#) && !l.starts_with('#')
    });
    assert!(
        line.is_some(),
        "Should find status=200 in http_requests_total, got:\n{}",
        buf
    );
}

#[test]
fn http_request_preformatted_status_201() {
    let metrics = MetricsRegistry::new();
    metrics.record_http_request("POST", "/api/resource", 201);

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    let line = buf.lines().find(|l| {
        l.contains("http_requests_total") && l.contains(r#"status="201""#) && !l.starts_with('#')
    });
    assert!(
        line.is_some(),
        "Should find status=201 in http_requests_total"
    );
}

#[test]
fn http_request_preformatted_status_204() {
    let metrics = MetricsRegistry::new();
    metrics.record_http_request("DELETE", "/api/resource/1", 204);

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    let line = buf.lines().find(|l| {
        l.contains("http_requests_total") && l.contains(r#"status="204""#) && !l.starts_with('#')
    });
    assert!(
        line.is_some(),
        "Should find status=204 in http_requests_total"
    );
}

#[test]
fn http_request_preformatted_status_400() {
    let metrics = MetricsRegistry::new();
    metrics.record_http_request("POST", "/api/auth", 400);

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    let line = buf.lines().find(|l| {
        l.contains("http_requests_total") && l.contains(r#"status="400""#) && !l.starts_with('#')
    });
    assert!(
        line.is_some(),
        "Should find status=400 in http_requests_total"
    );
}

#[test]
fn http_request_preformatted_status_401() {
    let metrics = MetricsRegistry::new();
    metrics.record_http_request("GET", "/api/secret", 401);

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    let line = buf.lines().find(|l| {
        l.contains("http_requests_total") && l.contains(r#"status="401""#) && !l.starts_with('#')
    });
    assert!(
        line.is_some(),
        "Should find status=401 in http_requests_total"
    );
}

#[test]
fn http_request_preformatted_status_404() {
    let metrics = MetricsRegistry::new();
    metrics.record_http_request("GET", "/api/missing", 404);

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    let line = buf.lines().find(|l| {
        l.contains("http_requests_total") && l.contains(r#"status="404""#) && !l.starts_with('#')
    });
    assert!(
        line.is_some(),
        "Should find status=404 in http_requests_total"
    );
}

#[test]
fn http_request_preformatted_status_500() {
    let metrics = MetricsRegistry::new();
    metrics.record_http_request("GET", "/api/broken", 500);

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    let line = buf.lines().find(|l| {
        l.contains("http_requests_total") && l.contains(r#"status="500""#) && !l.starts_with('#')
    });
    assert!(
        line.is_some(),
        "Should find status=500 in http_requests_total"
    );
}

#[test]
fn http_request_preformatted_status_503() {
    let metrics = MetricsRegistry::new();
    metrics.record_http_request("GET", "/api/maintenance", 503);

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    let line = buf.lines().find(|l| {
        l.contains("http_requests_total") && l.contains(r#"status="503""#) && !l.starts_with('#')
    });
    assert!(
        line.is_some(),
        "Should find status=503 in http_requests_total"
    );
}

#[test]
fn http_request_other_status_code_429() {
    let metrics = MetricsRegistry::new();
    metrics.record_http_request("GET", "/api/throttled", 429);

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    let line = buf.lines().find(|l| {
        l.contains("http_requests_total") && l.contains(r#"status="429""#) && !l.starts_with('#')
    });
    assert!(
        line.is_some(),
        "Should find status=429 (non-preformatted) in http_requests_total, got:\n{}",
        buf
    );
}

#[test]
fn http_request_all_preformatted_codes_in_single_registry() {
    let metrics = MetricsRegistry::new();

    let codes: &[u16] = &[200, 201, 204, 400, 401, 404, 500, 503, 429];
    for &code in codes {
        metrics.record_http_request("GET", "/api/test", code);
    }

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    for &code in codes {
        let expected = format!(r#"status="{}""#, code);
        assert!(
            buf.contains(&expected),
            "Should contain {} in output, got:\n{}",
            expected,
            buf
        );
    }
}

// ---------------------------------------------------------------------------
// error_types module constants
// ---------------------------------------------------------------------------

#[test]
fn error_types_auth_failure() {
    assert_eq!(error_types::AUTH_FAILURE, "auth_failure");
}

#[test]
fn error_types_acl_denied() {
    assert_eq!(error_types::ACL_DENIED, "acl_denied");
}

#[test]
fn error_types_connection_refused() {
    assert_eq!(error_types::CONNECTION_REFUSED, "connection_refused");
}

#[test]
fn error_types_connection_timeout() {
    assert_eq!(error_types::CONNECTION_TIMEOUT, "connection_timeout");
}

#[test]
fn error_types_dns_failure() {
    assert_eq!(error_types::DNS_FAILURE, "dns_failure");
}

#[test]
fn error_types_quota_exceeded() {
    assert_eq!(error_types::QUOTA_EXCEEDED, "quota_exceeded");
}

#[test]
fn error_types_rate_limited() {
    assert_eq!(error_types::RATE_LIMITED, "rate_limited");
}

#[test]
fn error_types_protocol_error() {
    assert_eq!(error_types::PROTOCOL_ERROR, "protocol_error");
}

#[test]
fn error_types_relay_error() {
    assert_eq!(error_types::RELAY_ERROR, "relay_error");
}

#[test]
fn error_types_internal_error() {
    assert_eq!(error_types::INTERNAL_ERROR, "internal_error");
}

#[test]
fn error_types_all_constants_are_distinct() {
    let all = [
        error_types::AUTH_FAILURE,
        error_types::ACL_DENIED,
        error_types::CONNECTION_REFUSED,
        error_types::CONNECTION_TIMEOUT,
        error_types::DNS_FAILURE,
        error_types::QUOTA_EXCEEDED,
        error_types::RATE_LIMITED,
        error_types::PROTOCOL_ERROR,
        error_types::RELAY_ERROR,
        error_types::INTERNAL_ERROR,
    ];
    let set: std::collections::HashSet<&str> = all.iter().copied().collect();
    assert_eq!(
        all.len(),
        set.len(),
        "All error_types constants should be distinct"
    );
}

// ---------------------------------------------------------------------------
// update_system_metrics (Linux /proc/self)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn update_system_metrics_sets_resident_memory() {
    let metrics = MetricsRegistry::new();

    // Before calling update, the gauge should be 0
    assert_eq!(metrics.process_resident_memory_bytes.get(), 0);

    metrics.update_system_metrics();

    // After calling update on Linux, RSS should be > 0 (any running process has memory)
    let rss = metrics.process_resident_memory_bytes.get();
    assert!(
        rss > 0,
        "process_resident_memory_bytes should be > 0 after update_system_metrics, got: {}",
        rss
    );
}

#[cfg(target_os = "linux")]
#[test]
fn update_system_metrics_sets_open_fds() {
    let metrics = MetricsRegistry::new();

    // Before calling update, the gauge should be 0
    assert_eq!(metrics.process_open_fds.get(), 0);

    metrics.update_system_metrics();

    // After calling update on Linux, open FDs should be > 0 (at least stdin/stdout/stderr)
    let fds = metrics.process_open_fds.get();
    assert!(
        fds > 0,
        "process_open_fds should be > 0 after update_system_metrics, got: {}",
        fds
    );
}

#[cfg(target_os = "linux")]
#[test]
fn update_system_metrics_appears_in_prometheus_output() {
    let metrics = MetricsRegistry::new();
    metrics.update_system_metrics();

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    // Verify the gauge values appear in the prometheus text output
    let rss_line = buf
        .lines()
        .find(|l| l.contains("process_resident_memory_bytes") && !l.starts_with('#'));
    assert!(
        rss_line.is_some(),
        "Should have a process_resident_memory_bytes data line"
    );
    // The value should not be "0"
    assert!(
        !rss_line.unwrap().ends_with(" 0"),
        "process_resident_memory_bytes should not be 0, got: {}",
        rss_line.unwrap()
    );

    let fds_line = buf
        .lines()
        .find(|l| l.contains("process_open_fds") && !l.starts_with('#'));
    assert!(
        fds_line.is_some(),
        "Should have a process_open_fds data line"
    );
    assert!(
        !fds_line.unwrap().ends_with(" 0"),
        "process_open_fds should not be 0, got: {}",
        fds_line.unwrap()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn update_system_metrics_called_twice_updates_values() {
    let metrics = MetricsRegistry::new();

    metrics.update_system_metrics();
    let rss_first = metrics.process_resident_memory_bytes.get();
    let fds_first = metrics.process_open_fds.get();

    // Call again; values should still be positive (may or may not change)
    metrics.update_system_metrics();
    let rss_second = metrics.process_resident_memory_bytes.get();
    let fds_second = metrics.process_open_fds.get();

    assert!(
        rss_second > 0,
        "RSS should still be > 0 after second update"
    );
    assert!(
        fds_second > 0,
        "FDs should still be > 0 after second update"
    );

    // Values should be reasonable (not wildly different from first call)
    // RSS should be within 10x of the first value (same process)
    assert!(
        rss_second <= rss_first * 10,
        "RSS should not grow 10x between two consecutive calls: first={}, second={}",
        rss_first,
        rss_second
    );
    // FD count should be within 100 of each other
    assert!(
        (fds_second - fds_first).unsigned_abs() < 100,
        "FD count should not vary wildly: first={}, second={}",
        fds_first,
        fds_second
    );
}

// ---------------------------------------------------------------------------
// record_connection_rejected: various reasons
// ---------------------------------------------------------------------------

#[test]
fn connection_rejected_multiple_reasons() {
    let metrics = MetricsRegistry::new();

    metrics.record_connection_rejected("acl_denied");
    metrics.record_connection_rejected("rate_limited");
    metrics.record_connection_rejected("quota_exceeded");
    metrics.record_connection_rejected("maintenance_window");
    metrics.record_connection_rejected("ip_banned");

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    for reason in &[
        "acl_denied",
        "rate_limited",
        "quota_exceeded",
        "maintenance_window",
        "ip_banned",
    ] {
        let expected = format!(r#"reason="{}""#, reason);
        assert!(
            buf.contains(&expected),
            "Should contain {} in rejected output, got:\n{}",
            expected,
            buf
        );
    }
}

#[test]
fn connection_rejected_same_reason_accumulates() {
    let metrics = MetricsRegistry::new();

    metrics.record_connection_rejected("rate_limited");
    metrics.record_connection_rejected("rate_limited");
    metrics.record_connection_rejected("rate_limited");

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    let line = buf.lines().find(|l| {
        l.contains("connections_rejected_total")
            && l.contains("rate_limited")
            && !l.starts_with('#')
    });
    assert!(
        line.is_some(),
        "Should find rate_limited in connections_rejected_total"
    );
    assert!(
        line.unwrap().ends_with(" 3"),
        "rate_limited count should be 3, got: {}",
        line.unwrap()
    );
}

#[test]
fn connection_rejected_distinct_reasons_have_separate_counters() {
    let metrics = MetricsRegistry::new();

    metrics.record_connection_rejected("acl_denied");
    metrics.record_connection_rejected("acl_denied");
    metrics.record_connection_rejected("rate_limited");

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    let acl_line = buf.lines().find(|l| {
        l.contains("connections_rejected_total") && l.contains("acl_denied") && !l.starts_with('#')
    });
    assert!(acl_line.is_some(), "Should find acl_denied line");
    assert!(
        acl_line.unwrap().ends_with(" 2"),
        "acl_denied count should be 2, got: {}",
        acl_line.unwrap()
    );

    let rate_line = buf.lines().find(|l| {
        l.contains("connections_rejected_total")
            && l.contains("rate_limited")
            && !l.starts_with('#')
    });
    assert!(rate_line.is_some(), "Should find rate_limited line");
    assert!(
        rate_line.unwrap().ends_with(" 1"),
        "rate_limited count should be 1, got: {}",
        rate_line.unwrap()
    );
}

// ---------------------------------------------------------------------------
// record_http_request_duration: histogram structure
// ---------------------------------------------------------------------------

#[test]
fn http_request_duration_creates_proper_histogram() {
    let metrics = MetricsRegistry::new();

    metrics.record_http_request_duration("GET", "/api/sessions", 0.035);

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    // Verify bucket, sum, and count fields all appear
    assert!(
        buf.contains("sks5_http_request_duration_seconds_bucket"),
        "Should contain histogram bucket lines"
    );
    assert!(
        buf.contains("sks5_http_request_duration_seconds_sum"),
        "Should contain histogram sum"
    );
    assert!(
        buf.contains("sks5_http_request_duration_seconds_count"),
        "Should contain histogram count"
    );

    // The HttpDurationHistogramBuilder uses buckets:
    // 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0
    // A 0.035s observation should be in the 0.05 bucket but not 0.025
    let get_buckets: Vec<&str> = buf
        .lines()
        .filter(|l| {
            l.contains("http_request_duration_seconds_bucket") && l.contains(r#"method="GET""#)
        })
        .collect();

    assert!(
        !get_buckets.is_empty(),
        "Should have bucket lines for GET method"
    );

    // The +Inf bucket should have count 1
    let inf_bucket = get_buckets.iter().find(|l| l.contains("+Inf"));
    assert!(inf_bucket.is_some(), "Should have +Inf bucket");
    assert!(
        inf_bucket.unwrap().ends_with(" 1"),
        "+Inf bucket should have count 1, got: {}",
        inf_bucket.unwrap()
    );
}

#[test]
fn http_request_duration_sum_reflects_observed_value() {
    let metrics = MetricsRegistry::new();

    metrics.record_http_request_duration("POST", "/api/auth", 0.123);

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    let sum_line = buf.lines().find(|l| {
        l.contains("http_request_duration_seconds_sum")
            && l.contains(r#"method="POST""#)
            && !l.starts_with('#')
    });
    assert!(
        sum_line.is_some(),
        "Should have sum line for POST /api/auth"
    );
    assert!(
        sum_line.unwrap().contains("0.123"),
        "Sum should contain 0.123, got: {}",
        sum_line.unwrap()
    );
}

#[test]
fn http_request_duration_count_reflects_number_of_observations() {
    let metrics = MetricsRegistry::new();

    metrics.record_http_request_duration("GET", "/api/status", 0.01);
    metrics.record_http_request_duration("GET", "/api/status", 0.02);
    metrics.record_http_request_duration("GET", "/api/status", 0.03);

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    let count_line = buf.lines().find(|l| {
        l.contains("http_request_duration_seconds_count")
            && l.contains(r#"method="GET""#)
            && !l.starts_with('#')
    });
    assert!(count_line.is_some(), "Should have count line for GET");
    assert!(
        count_line.unwrap().ends_with(" 3"),
        "Count should be 3 after 3 observations, got: {}",
        count_line.unwrap()
    );
}

#[test]
fn http_request_duration_different_paths_are_separate() {
    let metrics = MetricsRegistry::new();

    metrics.record_http_request_duration("GET", "/api/sessions", 0.05);
    metrics.record_http_request_duration("GET", "/api/metrics", 0.10);

    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();

    let sessions_count = buf.lines().find(|l| {
        l.contains("http_request_duration_seconds_count")
            && l.contains("/api/sessions")
            && !l.starts_with('#')
    });
    assert!(
        sessions_count.is_some(),
        "Should have count for /api/sessions"
    );
    assert!(
        sessions_count.unwrap().ends_with(" 1"),
        "/api/sessions count should be 1, got: {}",
        sessions_count.unwrap()
    );

    let metrics_count = buf.lines().find(|l| {
        l.contains("http_request_duration_seconds_count")
            && l.contains("/api/metrics")
            && !l.starts_with('#')
    });
    assert!(
        metrics_count.is_some(),
        "Should have count for /api/metrics"
    );
    assert!(
        metrics_count.unwrap().ends_with(" 1"),
        "/api/metrics count should be 1, got: {}",
        metrics_count.unwrap()
    );
}
