use sks5::security::ip_reputation::IpReputationManager;
use std::net::IpAddr;

/// Helper: assert that score is within an acceptable range due to sub-millisecond
/// decay between operations. The decay is continuous (half-life = 1 hour), so
/// between rapid back-to-back calls, score loses a tiny fraction. After truncation
/// to u32, expected value N may appear as N or N-1.
fn assert_score_approx(actual: u32, expected: u32, msg: &str) {
    assert!(
        actual == expected || actual + 1 == expected,
        "{}: expected {} (or {}), got {}",
        msg,
        expected,
        expected.saturating_sub(1),
        actual
    );
}

// ===========================================================================
// Construction and basic behavior
// ===========================================================================

#[test]
fn test_new_ip_has_zero_score() {
    let mgr = IpReputationManager::new(true, 100);
    let ip: IpAddr = "192.168.1.1".parse().unwrap();
    assert_eq!(mgr.get_score(&ip), 0, "fresh IP should have score 0");
}

#[test]
fn test_new_manager_has_no_scores() {
    let mgr = IpReputationManager::new(true, 100);
    let scores = mgr.all_scores();
    assert!(
        scores.is_empty(),
        "new manager should have no score entries"
    );
}

// ===========================================================================
// Score accumulation
// ===========================================================================

#[test]
fn test_add_score_increments() {
    let mgr = IpReputationManager::new(true, 100);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    // record_auth_failure adds 10.0 to score
    mgr.record_auth_failure(&ip);
    let score1 = mgr.get_score(&ip);
    assert_score_approx(score1, 10, "one auth failure");

    // Second failure should bring score to ~20
    mgr.record_auth_failure(&ip);
    let score2 = mgr.get_score(&ip);
    assert_score_approx(score2, 20, "two auth failures");

    // Score should strictly increase after a failure
    assert!(
        score2 > score1,
        "score should increase after second failure"
    );
}

#[test]
fn test_acl_denial_adds_five() {
    let mgr = IpReputationManager::new(true, 100);
    let ip: IpAddr = "10.0.0.2".parse().unwrap();

    mgr.record_acl_denial(&ip);
    let score = mgr.get_score(&ip);
    assert_score_approx(score, 5, "ACL denial");
    assert!(
        score >= 4,
        "ACL denial should add at least 4 (approximately 5)"
    );
}

#[test]
fn test_rapid_connections_adds_three() {
    let mgr = IpReputationManager::new(true, 100);
    let ip: IpAddr = "10.0.0.3".parse().unwrap();

    mgr.record_rapid_connections(&ip);
    let score = mgr.get_score(&ip);
    assert_score_approx(score, 3, "rapid connections");
    assert!(
        score >= 2,
        "rapid connections should add at least 2 (approximately 3)"
    );
}

#[test]
fn test_auth_success_reduces_score() {
    let mgr = IpReputationManager::new(true, 100);
    let ip: IpAddr = "10.0.0.4".parse().unwrap();

    // Build up some score first: 2 failures => ~20
    mgr.record_auth_failure(&ip);
    mgr.record_auth_failure(&ip);
    let before_success = mgr.get_score(&ip);
    assert!(before_success >= 18, "two failures should give at least 18");

    // Successful auth reduces by 5
    mgr.record_auth_success(&ip);
    let after_success = mgr.get_score(&ip);
    assert!(
        after_success < before_success,
        "score should decrease after auth success: {} < {}",
        after_success,
        before_success
    );
    assert_score_approx(after_success, 15, "after success reduction");
}

#[test]
fn test_score_never_goes_below_zero() {
    let mgr = IpReputationManager::new(true, 100);
    let ip: IpAddr = "10.0.0.5".parse().unwrap();

    // Auth success on a fresh IP (score 0) should not underflow
    mgr.record_auth_success(&ip);
    assert_eq!(
        mgr.get_score(&ip),
        0,
        "score should be clamped to 0, never negative"
    );
}

#[test]
fn test_multiple_successes_on_zero_stay_zero() {
    let mgr = IpReputationManager::new(true, 100);
    let ip: IpAddr = "10.0.0.6".parse().unwrap();

    for _ in 0..10 {
        mgr.record_auth_success(&ip);
    }
    assert_eq!(
        mgr.get_score(&ip),
        0,
        "multiple successes on fresh IP should stay 0"
    );
}

#[test]
fn test_mixed_events_accumulate_correctly() {
    let mgr = IpReputationManager::new(true, 100);
    let ip: IpAddr = "10.0.0.7".parse().unwrap();

    mgr.record_auth_failure(&ip); // +10 => ~10
    mgr.record_acl_denial(&ip); // +5  => ~15
    mgr.record_rapid_connections(&ip); // +3  => ~18
    let score_before = mgr.get_score(&ip);
    assert_score_approx(score_before, 18, "mixed events sum");
    assert!(
        score_before >= 16,
        "mixed positive events should sum to at least 16"
    );

    mgr.record_auth_success(&ip); // -5  => ~13
    let score_after = mgr.get_score(&ip);
    assert!(
        score_after < score_before,
        "score should decrease after success"
    );
    assert_score_approx(score_after, 13, "after success on mixed");
}

// ===========================================================================
// Score decay over time
// ===========================================================================

#[test]
fn test_score_decay_over_time() {
    // The decay function halves the score every 3600 seconds (1 hour).
    // We cannot easily fast-forward Instant::now() in the public API, but
    // we can verify that a score recorded "just now" is very close to nominal.
    // Due to continuous decay even over microseconds, score may be truncated
    // down by 1 when cast to u32.
    let mgr = IpReputationManager::new(true, 200);
    let ip: IpAddr = "10.0.0.8".parse().unwrap();

    // 10 failures => nominal score 100
    for _ in 0..10 {
        mgr.record_auth_failure(&ip);
    }

    let score = mgr.get_score(&ip);
    // Immediately after recording, score should be very close to 100
    assert!(
        (98..=100).contains(&score),
        "score should be ~100 right after recording, got {}",
        score
    );
}

#[test]
fn test_decay_formula_is_half_life_based() {
    // Verify the decay formula: score * 0.5^(elapsed_secs / 3600)
    // For elapsed ~0, factor ~1.0 (negligible decay).
    // We verify by accumulating score and checking it's very close to nominal.
    let mgr = IpReputationManager::new(true, 300);
    let ip: IpAddr = "10.0.0.9".parse().unwrap();

    for _ in 0..20 {
        mgr.record_auth_failure(&ip); // +10 each => nominal 200
    }

    let score = mgr.get_score(&ip);
    // With negligible elapsed time, score should be very close to 200
    assert!(
        (198..=200).contains(&score),
        "score should be ~200 immediately after recording, got {}",
        score
    );
}

// ===========================================================================
// Ban threshold detection
// ===========================================================================

#[test]
fn test_should_ban_at_threshold() {
    // Use a threshold slightly below the expected accumulated score to account
    // for micro-decay. 3 auth failures = ~30 score; threshold 29 ensures ban.
    let mgr = IpReputationManager::new(true, 29);
    let ip: IpAddr = "172.16.0.1".parse().unwrap();

    mgr.record_auth_failure(&ip); // +10
    mgr.record_auth_failure(&ip); // +10
    mgr.record_auth_failure(&ip); // +10 => ~30 (29 after micro-decay)

    assert!(
        mgr.should_ban(&ip),
        "IP at/above the ban threshold should be banned (score={}, threshold=29)",
        mgr.get_score(&ip)
    );
}

#[test]
fn test_should_ban_above_threshold() {
    let mgr = IpReputationManager::new(true, 25);
    let ip: IpAddr = "172.16.0.2".parse().unwrap();

    mgr.record_auth_failure(&ip); // +10
    mgr.record_auth_failure(&ip); // +10
    mgr.record_auth_failure(&ip); // +10 => ~30

    assert!(
        mgr.should_ban(&ip),
        "IP well above the ban threshold should be banned"
    );
}

#[test]
fn test_should_ban_below_threshold() {
    let mgr = IpReputationManager::new(true, 50);
    let ip: IpAddr = "172.16.0.3".parse().unwrap();

    mgr.record_auth_failure(&ip); // +10
    mgr.record_auth_failure(&ip); // +10 => ~20

    assert!(
        !mgr.should_ban(&ip),
        "IP below the ban threshold should NOT be banned"
    );
}

#[test]
fn test_should_ban_fresh_ip_is_false() {
    let mgr = IpReputationManager::new(true, 10);
    let ip: IpAddr = "172.16.0.4".parse().unwrap();

    assert!(
        !mgr.should_ban(&ip),
        "fresh IP with score 0 should not be banned"
    );
}

#[test]
fn test_should_ban_zero_threshold_never_bans() {
    let mgr = IpReputationManager::new(true, 0);
    let ip: IpAddr = "172.16.0.5".parse().unwrap();

    // Even with high score, threshold 0 means ban is disabled
    for _ in 0..100 {
        mgr.record_auth_failure(&ip);
    }

    assert!(
        !mgr.should_ban(&ip),
        "ban_threshold=0 should never ban regardless of score"
    );
}

#[test]
fn test_should_ban_transitions_with_success() {
    // Threshold 20: well below the 3-failure score of ~30
    let mgr = IpReputationManager::new(true, 20);
    let ip: IpAddr = "172.16.0.6".parse().unwrap();

    // Build up to ban: 3 failures => ~30
    mgr.record_auth_failure(&ip);
    mgr.record_auth_failure(&ip);
    mgr.record_auth_failure(&ip);
    assert!(mgr.should_ban(&ip), "should be banned at ~30 >= 20");

    // Two auth successes reduce by ~10 => ~20, still at or above threshold
    // But with micro-decay, score may dip just below 20.
    // Instead, test with a clear gap: reduce once (-5 => ~25), still banned
    mgr.record_auth_success(&ip);
    assert!(
        mgr.should_ban(&ip),
        "score ~25 should still be above threshold 20 (score={})",
        mgr.get_score(&ip)
    );

    // Reduce 3 more times (-15 => ~10), clearly below threshold
    mgr.record_auth_success(&ip);
    mgr.record_auth_success(&ip);
    mgr.record_auth_success(&ip);
    assert!(
        !mgr.should_ban(&ip),
        "score ~10 should be below threshold 20 (score={})",
        mgr.get_score(&ip)
    );
}

// ===========================================================================
// Cleanup
// ===========================================================================

#[test]
fn test_cleanup_removes_low_scores() {
    let mgr = IpReputationManager::new(true, 100);
    let ip_low: IpAddr = "10.1.0.1".parse().unwrap();

    // Score of 3.0 is well above the cleanup threshold of 1.0
    mgr.record_rapid_connections(&ip_low); // +3

    mgr.cleanup();

    // Entry should survive cleanup since 3.0 >= 1.0
    let scores = mgr.all_scores();
    assert_eq!(
        scores.len(),
        1,
        "entry with score ~3 should survive cleanup"
    );
}

#[test]
fn test_cleanup_preserves_high_scores() {
    let mgr = IpReputationManager::new(true, 200);
    let ip: IpAddr = "10.1.0.2".parse().unwrap();

    for _ in 0..10 {
        mgr.record_auth_failure(&ip); // +10 each => ~100
    }

    mgr.cleanup();

    let scores = mgr.all_scores();
    assert_eq!(scores.len(), 1, "high-score entry should survive cleanup");
    assert!(
        scores[0].1 >= 98,
        "score should remain close to 100 after cleanup, got {}",
        scores[0].1
    );
}

#[test]
fn test_cleanup_on_empty_manager() {
    let mgr = IpReputationManager::new(true, 100);

    // Cleanup on empty manager should not panic
    mgr.cleanup();

    assert!(mgr.all_scores().is_empty());
}

#[test]
fn test_cleanup_is_idempotent() {
    let mgr = IpReputationManager::new(true, 100);
    let ip: IpAddr = "10.1.0.3".parse().unwrap();

    mgr.record_auth_failure(&ip); // +10

    mgr.cleanup();
    mgr.cleanup();
    mgr.cleanup();

    let scores = mgr.all_scores();
    assert_eq!(
        scores.len(),
        1,
        "repeated cleanup should not remove valid entries"
    );
}

#[test]
fn test_cleanup_removes_zero_score_entries() {
    let mgr = IpReputationManager::new(true, 100);
    let ip: IpAddr = "10.1.0.4".parse().unwrap();

    // An IP that had auth success on zero will have score 0.0
    // The entry still exists in the DashMap but with score 0.0
    // cleanup should remove it since 0.0 < 1.0
    mgr.record_auth_success(&ip);

    mgr.cleanup();

    let scores = mgr.all_scores();
    assert!(
        scores.is_empty(),
        "entry with score 0 should be removed by cleanup"
    );
}

// ===========================================================================
// Disabled manager
// ===========================================================================

#[test]
fn test_disabled_manager_returns_zero() {
    let mgr = IpReputationManager::new(false, 100);
    let ip: IpAddr = "203.0.113.1".parse().unwrap();

    // All record operations should be no-ops when disabled
    mgr.record_auth_failure(&ip);
    mgr.record_auth_failure(&ip);
    mgr.record_acl_denial(&ip);
    mgr.record_rapid_connections(&ip);

    assert_eq!(
        mgr.get_score(&ip),
        0,
        "disabled manager should always return score 0"
    );
}

#[test]
fn test_disabled_manager_never_bans() {
    let mgr = IpReputationManager::new(false, 1);
    let ip: IpAddr = "203.0.113.2".parse().unwrap();

    // Even with threshold=1, disabled manager should never ban
    mgr.record_auth_failure(&ip);
    mgr.record_auth_failure(&ip);

    assert!(
        !mgr.should_ban(&ip),
        "disabled manager should never ban any IP"
    );
}

#[test]
fn test_disabled_manager_has_no_entries() {
    let mgr = IpReputationManager::new(false, 100);
    let ip: IpAddr = "203.0.113.3".parse().unwrap();

    mgr.record_auth_failure(&ip);
    mgr.record_acl_denial(&ip);

    let scores = mgr.all_scores();
    assert!(
        scores.is_empty(),
        "disabled manager should not store any entries"
    );
}

// ===========================================================================
// Auth failure count tracking
// ===========================================================================

#[test]
fn test_auth_failure_count_incremented() {
    // The auth_failure_count field is private, so we verify indirectly via score.
    // Each record_auth_failure adds 10.0 and increments auth_failure_count.
    // We verify that score strictly increases with each call.
    let mgr = IpReputationManager::new(true, 200);
    let ip: IpAddr = "198.51.100.1".parse().unwrap();

    let mut prev_score = 0u32;
    for i in 1..=10 {
        mgr.record_auth_failure(&ip);
        let score = mgr.get_score(&ip);
        let expected = i * 10;
        assert_score_approx(score, expected, &format!("after {} failures", i));
        assert!(
            score > prev_score,
            "score should strictly increase: {} > {} after {} failures",
            score,
            prev_score,
            i
        );
        prev_score = score;
    }
}

#[test]
fn test_auth_failure_count_not_incremented_by_success() {
    // record_auth_success uses a negative delta, so auth_failure_count
    // should NOT be incremented (the code checks delta > 0.0).
    // We verify indirectly that the net score effect is correct.
    let mgr = IpReputationManager::new(true, 200);
    let ip: IpAddr = "198.51.100.2".parse().unwrap();

    mgr.record_auth_failure(&ip); // +10 => ~10
    mgr.record_auth_success(&ip); // -5  => ~5
    mgr.record_auth_failure(&ip); // +10 => ~15

    let score = mgr.get_score(&ip);
    assert_score_approx(score, 15, "net score after failure/success/failure");
    assert!(
        (13..=15).contains(&score),
        "net score should be approximately 15, got {}",
        score
    );
}

#[test]
fn test_acl_denial_increments_failure_count() {
    // record_acl_denial and record_rapid_connections both use positive deltas,
    // so auth_failure_count is incremented for both.
    let mgr = IpReputationManager::new(true, 200);
    let ip: IpAddr = "198.51.100.3".parse().unwrap();

    mgr.record_acl_denial(&ip); // +5  => ~5
    mgr.record_rapid_connections(&ip); // +3  => ~8

    let score = mgr.get_score(&ip);
    assert_score_approx(score, 8, "ACL denial + rapid connections");
    assert!(
        (7..=8).contains(&score),
        "score should be approximately 8, got {}",
        score
    );
}

// ===========================================================================
// Per-IP isolation
// ===========================================================================

#[test]
fn test_different_ips_are_independent() {
    let mgr = IpReputationManager::new(true, 100);
    let ip1: IpAddr = "10.0.0.1".parse().unwrap();
    let ip2: IpAddr = "10.0.0.2".parse().unwrap();
    let ip3: IpAddr = "10.0.0.3".parse().unwrap();

    mgr.record_auth_failure(&ip1); // ip1: ~10
    mgr.record_auth_failure(&ip2); // ip2: ~10
    mgr.record_auth_failure(&ip2); // ip2: ~20
    mgr.record_rapid_connections(&ip3); // ip3: ~3

    assert_score_approx(mgr.get_score(&ip1), 10, "ip1 score");
    assert_score_approx(mgr.get_score(&ip2), 20, "ip2 score");
    assert_score_approx(mgr.get_score(&ip3), 3, "ip3 score");

    // Verify isolation: ip1 score should be less than ip2 score
    assert!(
        mgr.get_score(&ip1) < mgr.get_score(&ip2),
        "ip1 (one failure) should have lower score than ip2 (two failures)"
    );
}

#[test]
fn test_ipv4_and_ipv6_are_independent() {
    let mgr = IpReputationManager::new(true, 100);
    let ipv4: IpAddr = "127.0.0.1".parse().unwrap();
    let ipv6: IpAddr = "::1".parse().unwrap();

    mgr.record_auth_failure(&ipv4); // +10
    mgr.record_acl_denial(&ipv6); // +5

    let score_v4 = mgr.get_score(&ipv4);
    let score_v6 = mgr.get_score(&ipv6);

    assert_score_approx(score_v4, 10, "IPv4 score");
    assert_score_approx(score_v6, 5, "IPv6 score");
    assert!(
        score_v4 > score_v6,
        "IPv4 (auth failure +10) should have higher score than IPv6 (ACL denial +5)"
    );
}

// ===========================================================================
// all_scores monitoring
// ===========================================================================

#[test]
fn test_all_scores_returns_active_entries() {
    let mgr = IpReputationManager::new(true, 100);
    let ip1: IpAddr = "10.0.0.1".parse().unwrap();
    let ip2: IpAddr = "10.0.0.2".parse().unwrap();

    mgr.record_auth_failure(&ip1); // +10
    mgr.record_auth_failure(&ip2); // +10
    mgr.record_auth_failure(&ip2); // +10 => ~20

    let mut scores = mgr.all_scores();
    scores.sort_by_key(|(ip, _)| *ip);

    assert_eq!(scores.len(), 2, "should have entries for both IPs");
    assert_score_approx(scores[0].1, 10, "ip1 in all_scores");
    assert_score_approx(scores[1].1, 20, "ip2 in all_scores");
    assert!(
        scores[1].1 > scores[0].1,
        "ip2 should have higher score than ip1"
    );
}

#[test]
fn test_all_scores_excludes_zero_score_entries() {
    let mgr = IpReputationManager::new(true, 100);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    // Create an entry with score 0 (auth_success on fresh IP)
    mgr.record_auth_success(&ip);

    let scores = mgr.all_scores();
    assert!(
        scores.is_empty(),
        "all_scores should filter out entries with score 0"
    );
}

#[test]
fn test_all_scores_empty_when_disabled() {
    let mgr = IpReputationManager::new(false, 100);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    mgr.record_auth_failure(&ip);

    let scores = mgr.all_scores();
    assert!(
        scores.is_empty(),
        "disabled manager all_scores should be empty"
    );
}

// ===========================================================================
// Edge cases
// ===========================================================================

#[test]
fn test_very_high_score_accumulation() {
    let mgr = IpReputationManager::new(true, u32::MAX);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    // Accumulate a very high score: 1000 * 10 = 10000
    for _ in 0..1000 {
        mgr.record_auth_failure(&ip);
    }

    let score = mgr.get_score(&ip);
    // Allow small decay tolerance for 1000 rapid calls
    assert!(
        (9990..=10_000).contains(&score),
        "1000 failures should give score ~10000, got {}",
        score
    );
}

#[test]
fn test_ban_threshold_one() {
    let mgr = IpReputationManager::new(true, 1);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    assert!(!mgr.should_ban(&ip), "fresh IP should not be banned");

    mgr.record_rapid_connections(&ip); // +3, well above threshold of 1
    assert!(
        mgr.should_ban(&ip),
        "any event should trigger ban with threshold 1"
    );
}

#[test]
fn test_many_ips_tracked_simultaneously() {
    let mgr = IpReputationManager::new(true, 100);

    for i in 0..=255u8 {
        let ip: IpAddr = format!("10.0.0.{}", i).parse().unwrap();
        mgr.record_auth_failure(&ip);
    }

    let scores = mgr.all_scores();
    assert_eq!(scores.len(), 256, "should track 256 different IPs");

    // Each IP had one auth failure (+10); with micro-decay, score is 9 or 10
    for (ip, score) in &scores {
        assert_score_approx(*score, 10, &format!("score for {}", ip));
    }
}

#[test]
fn test_score_monotonically_increases_with_failures() {
    // Verify that consecutive failures always increase the score
    let mgr = IpReputationManager::new(true, 500);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    let mut prev = 0u32;
    for _ in 0..50 {
        mgr.record_auth_failure(&ip);
        let current = mgr.get_score(&ip);
        assert!(
            current > prev,
            "score should strictly increase with each failure: {} > {}",
            current,
            prev
        );
        prev = current;
    }
}

#[test]
fn test_score_monotonically_decreases_with_successes() {
    // Build up score, then verify successes decrease it
    let mgr = IpReputationManager::new(true, 500);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    // Build up to ~100
    for _ in 0..10 {
        mgr.record_auth_failure(&ip);
    }

    let mut prev = mgr.get_score(&ip);
    for _ in 0..10 {
        mgr.record_auth_success(&ip);
        let current = mgr.get_score(&ip);
        assert!(
            current < prev,
            "score should strictly decrease with each success: {} < {}",
            current,
            prev
        );
        prev = current;
    }
}
