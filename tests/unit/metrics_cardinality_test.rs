use prometheus_client::encoding::text::encode;
use sks5::metrics::MetricsRegistry;

// Test 1: new() creates a MetricsRegistry with the default max_labels of 100
#[test]
fn new_default_max_labels_100() {
    let metrics = MetricsRegistry::new();

    // With default cap of 100, recording 100 distinct users should all succeed
    // without triggering the cardinality cap.
    for i in 0..100 {
        metrics.record_auth_success(&format!("user{}", i), "password");
    }

    // The cardinality cap counter should still be zero
    assert_eq!(metrics.cardinality_capped_total.get(), 0);

    // The 101st distinct user should trigger the cap
    metrics.record_auth_success("overflow_user", "password");
    assert_eq!(metrics.cardinality_capped_total.get(), 1);
}

// Test 2: with_max_labels(5) sets the cardinality cap to 5
#[test]
fn with_max_labels_custom() {
    let metrics = MetricsRegistry::with_max_labels(5);

    // Record exactly 5 users - should all fit
    for i in 0..5 {
        metrics.record_auth_success(&format!("user{}", i), "password");
    }
    assert_eq!(metrics.cardinality_capped_total.get(), 0);

    // The 6th user should hit the cap
    metrics.record_auth_success("user5", "password");
    assert_eq!(metrics.cardinality_capped_total.get(), 1);
}

// Test 3: Under the cap, Prometheus output contains all real usernames
#[test]
fn under_cap_uses_real_username() {
    let metrics = MetricsRegistry::with_max_labels(5);

    metrics.record_auth_success("alice", "password");
    metrics.record_auth_success("bob", "password");
    metrics.record_auth_success("charlie", "password");

    let mut buffer = String::new();
    encode(&mut buffer, &metrics.registry).unwrap();

    assert!(
        buffer.contains("alice"),
        "Prometheus output should contain 'alice', got:\n{}",
        buffer
    );
    assert!(
        buffer.contains("bob"),
        "Prometheus output should contain 'bob', got:\n{}",
        buffer
    );
    assert!(
        buffer.contains("charlie"),
        "Prometheus output should contain 'charlie', got:\n{}",
        buffer
    );

    // No capping should have occurred
    assert_eq!(metrics.cardinality_capped_total.get(), 0);
}

// Test 4: At the cap boundary, first N users get real labels; N+1 becomes "_other"
#[test]
fn at_cap_boundary() {
    let metrics = MetricsRegistry::with_max_labels(3);

    // Record exactly 3 users - all should get real labels
    metrics.record_auth_success("user_a", "password");
    metrics.record_auth_success("user_b", "password");
    metrics.record_auth_success("user_c", "password");
    assert_eq!(metrics.cardinality_capped_total.get(), 0);

    // The 4th user should be bucketed into "_other"
    metrics.record_auth_success("user_d", "password");
    assert_eq!(metrics.cardinality_capped_total.get(), 1);

    let mut buffer = String::new();
    encode(&mut buffer, &metrics.registry).unwrap();

    // The first 3 users should appear with their real names
    assert!(buffer.contains("user_a"), "Expected user_a in output");
    assert!(buffer.contains("user_b"), "Expected user_b in output");
    assert!(buffer.contains("user_c"), "Expected user_c in output");

    // user_d should NOT appear; instead "_other" should
    assert!(
        !buffer.contains("user_d"),
        "user_d should NOT appear in Prometheus output"
    );
    assert!(
        buffer.contains("_other"),
        "Expected '_other' label in Prometheus output"
    );
}

// Test 5: cardinality_capped_total increments for each capped call
#[test]
fn cardinality_capped_counter_increments() {
    let metrics = MetricsRegistry::with_max_labels(2);

    // Fill the cap
    metrics.record_auth_success("user1", "password");
    metrics.record_auth_success("user2", "password");
    assert_eq!(metrics.cardinality_capped_total.get(), 0);

    // Now record a 3rd user twice - each call should increment the cap counter
    metrics.record_auth_success("user3", "password");
    metrics.record_auth_success("user3", "password");
    assert_eq!(metrics.cardinality_capped_total.get(), 2);
}

// Test 6: A known user still resolves to its real label after the cap is reached
#[test]
fn known_user_still_works_after_cap() {
    let metrics = MetricsRegistry::with_max_labels(2);

    // Register user1 and user2 (fills the cap)
    metrics.record_auth_success("user1", "password");
    metrics.record_auth_success("user2", "password");

    // user3 goes to _other (cap hit)
    metrics.record_auth_success("user3", "password");
    assert_eq!(metrics.cardinality_capped_total.get(), 1);

    // user1 should still resolve to "user1", not "_other"
    metrics.record_auth_success("user1", "password");
    // Cap counter should NOT have increased for user1
    assert_eq!(metrics.cardinality_capped_total.get(), 1);

    let mut buffer = String::new();
    encode(&mut buffer, &metrics.registry).unwrap();

    // user1 should appear in output with its real label
    assert!(
        buffer.contains("user1"),
        "user1 should still appear with real label after cap"
    );
    // Verify user1 auth_successes counter is 2 (recorded twice)
    // We check that the line with user1 exists in the auth_successes metric
    let has_user1_line = buffer
        .lines()
        .any(|line| line.contains("auth_successes_total") && line.contains("user1"));
    assert!(
        has_user1_line,
        "Expected auth_successes_total line with user1"
    );
}

// Test 7: record_bytes_transferred also respects the cardinality cap
#[test]
fn bytes_transferred_respects_cap() {
    let metrics = MetricsRegistry::with_max_labels(1);

    // user1 fits within the cap
    metrics.record_bytes_transferred("user1", 1024);
    assert_eq!(metrics.cardinality_capped_total.get(), 0);

    // user2 should be capped to "_other"
    metrics.record_bytes_transferred("user2", 2048);
    assert_eq!(metrics.cardinality_capped_total.get(), 1);

    let mut buffer = String::new();
    encode(&mut buffer, &metrics.registry).unwrap();

    // user1 should appear with real label
    let has_user1_bytes = buffer
        .lines()
        .any(|line| line.contains("bytes_transferred") && line.contains("user1"));
    assert!(
        has_user1_bytes,
        "Expected bytes_transferred line with user1"
    );

    // user2 should NOT appear; _other should
    assert!(
        !buffer.contains("user2"),
        "user2 should NOT appear in bytes_transferred output"
    );
    let has_other_bytes = buffer
        .lines()
        .any(|line| line.contains("bytes_transferred") && line.contains("_other"));
    assert!(
        has_other_bytes,
        "Expected bytes_transferred line with _other label"
    );
}

// Test 8: Prometheus output contains the "_other" label when cardinality is exceeded
#[test]
fn prometheus_output_contains_other_label() {
    let metrics = MetricsRegistry::with_max_labels(1);

    // First user fits
    metrics.record_auth_success("first_user", "password");
    // Second user exceeds cap
    metrics.record_auth_success("second_user", "password");

    let mut buffer = String::new();
    encode(&mut buffer, &metrics.registry).unwrap();

    assert!(
        buffer.contains("_other"),
        "Prometheus output should contain '_other' label when cap is exceeded, got:\n{}",
        buffer
    );
    assert!(
        buffer.contains("first_user"),
        "First user should still appear with real label"
    );
    assert!(
        !buffer.contains("second_user"),
        "Second user should NOT appear in output (should be _other)"
    );
}

// Test 9: with_max_labels(0) causes all users to immediately go to "_other"
#[test]
fn zero_cap_all_go_to_other() {
    let metrics = MetricsRegistry::with_max_labels(0);

    // Every user should immediately be capped
    metrics.record_auth_success("alice", "password");
    assert_eq!(metrics.cardinality_capped_total.get(), 1);

    metrics.record_auth_success("bob", "password");
    assert_eq!(metrics.cardinality_capped_total.get(), 2);

    metrics.record_auth_success("charlie", "password");
    assert_eq!(metrics.cardinality_capped_total.get(), 3);

    let mut buffer = String::new();
    encode(&mut buffer, &metrics.registry).unwrap();

    // None of the real usernames should appear
    assert!(
        !buffer.contains("alice"),
        "alice should NOT appear with zero cap"
    );
    assert!(
        !buffer.contains(r#"user="bob"#),
        "bob should NOT appear with zero cap"
    );
    assert!(
        !buffer.contains("charlie"),
        "charlie should NOT appear with zero cap"
    );

    // Only "_other" should appear as a user label
    assert!(
        buffer.contains("_other"),
        "Only '_other' should appear as user label with zero cap, got:\n{}",
        buffer
    );
}

// ---------------------------------------------------------------------------
// Connection duration histogram tests
// ---------------------------------------------------------------------------

// Test 10: record_connection_duration creates histogram metric in Prometheus output
#[test]
fn connection_duration_appears_in_prometheus() {
    let metrics = MetricsRegistry::new();

    metrics.record_connection_duration("alice", 42.5);

    let mut buffer = String::new();
    encode(&mut buffer, &metrics.registry).unwrap();

    assert!(
        buffer.contains("sks5_connection_duration_seconds"),
        "Prometheus output should contain sks5_connection_duration_seconds, got:\n{}",
        buffer
    );
    assert!(
        buffer.contains("alice"),
        "Duration metric should include alice label, got:\n{}",
        buffer
    );
}

// Test 11: connection_duration_seconds histogram has expected buckets
#[test]
fn connection_duration_histogram_buckets() {
    let metrics = MetricsRegistry::new();

    // Record a value that falls in the 60s bucket
    metrics.record_connection_duration("bob", 45.0);

    let mut buffer = String::new();
    encode(&mut buffer, &metrics.registry).unwrap();

    // Verify histogram buckets are present
    assert!(
        buffer.contains("sks5_connection_duration_seconds_bucket"),
        "Should contain histogram bucket lines"
    );
    assert!(
        buffer.contains("sks5_connection_duration_seconds_sum"),
        "Should contain histogram sum"
    );
    assert!(
        buffer.contains("sks5_connection_duration_seconds_count"),
        "Should contain histogram count"
    );
}

// Test 12: connection_duration respects cardinality cap
#[test]
fn connection_duration_respects_cardinality_cap() {
    let metrics = MetricsRegistry::with_max_labels(2);

    metrics.record_connection_duration("user1", 10.0);
    metrics.record_connection_duration("user2", 20.0);
    assert_eq!(metrics.cardinality_capped_total.get(), 0);

    // Third user should hit cap
    metrics.record_connection_duration("user3", 30.0);
    assert_eq!(metrics.cardinality_capped_total.get(), 1);

    let mut buffer = String::new();
    encode(&mut buffer, &metrics.registry).unwrap();

    assert!(
        buffer.contains("user1"),
        "user1 should appear with real label"
    );
    assert!(
        !buffer.contains("user3"),
        "user3 should NOT appear (should be _other)"
    );
    assert!(
        buffer.contains("_other"),
        "_other should appear for capped user"
    );
}

// Test 13: multiple durations accumulate correctly
#[test]
fn connection_duration_accumulates() {
    let metrics = MetricsRegistry::new();

    metrics.record_connection_duration("alice", 10.0);
    metrics.record_connection_duration("alice", 20.0);
    metrics.record_connection_duration("alice", 30.0);

    let mut buffer = String::new();
    encode(&mut buffer, &metrics.registry).unwrap();

    // Find the count line for alice — should be 3
    let count_line = buffer
        .lines()
        .find(|l| l.contains("connection_duration_seconds_count") && l.contains("alice"));
    assert!(
        count_line.is_some(),
        "Should have a count line for alice in duration histogram"
    );
    assert!(
        count_line.unwrap().contains(" 3"),
        "Count should be 3 for alice, got: {}",
        count_line.unwrap()
    );
}
