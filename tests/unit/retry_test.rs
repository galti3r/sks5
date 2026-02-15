use sks5::proxy::retry::connect_with_retry;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

// -------------------------------------------------------------------------
// Test: successful connection on first attempt with zero retries
// -------------------------------------------------------------------------
#[tokio::test]
async fn connect_success_no_retries() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let result = connect_with_retry("127.0.0.1", port, 0, 100).await;
    assert!(result.is_ok(), "should connect to listening port");
    let (_stream, addr) = result.unwrap();
    assert_eq!(addr.port(), port);
}

// -------------------------------------------------------------------------
// Test: connection failure after exhausting retries with backoff
// -------------------------------------------------------------------------
#[tokio::test]
async fn connect_failure_with_retries_and_backoff() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let max_retries = 2;
    let delay_ms = 50;

    let start = Instant::now();
    let result = connect_with_retry("127.0.0.1", port, max_retries, delay_ms).await;
    let elapsed = start.elapsed();

    assert!(result.is_err(), "should fail against closed port");

    // With 2 retries and delay 50ms (exponential: 50 + 100 = 150ms minimum),
    // expect at least ~100ms of backoff time
    assert!(
        elapsed >= Duration::from_millis(100),
        "expected at least 100ms of backoff, got {:?}",
        elapsed
    );
}

// -------------------------------------------------------------------------
// Test: connection succeeds on retry when listener appears later
// -------------------------------------------------------------------------
#[tokio::test]
async fn connect_succeeds_on_retry() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let port_clone = port;
    let handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(120)).await;
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port_clone))
            .await
            .unwrap();
        let _conn = listener.accept().await.unwrap();
    });

    let result = connect_with_retry("127.0.0.1", port, 3, 80).await;
    assert!(
        result.is_ok(),
        "should succeed after listener starts: {:?}",
        result.err()
    );

    handle.await.unwrap();
}

// -------------------------------------------------------------------------
// Test: zero retries means exactly one attempt (no delay)
// -------------------------------------------------------------------------
#[tokio::test]
async fn zero_retries_single_attempt() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let start = Instant::now();
    let result = connect_with_retry("127.0.0.1", port, 0, 1000).await;
    let elapsed = start.elapsed();

    assert!(result.is_err(), "should fail with zero retries");
    assert!(
        elapsed < Duration::from_millis(500),
        "zero retries should not introduce delay, got {:?}",
        elapsed
    );
}

// -------------------------------------------------------------------------
// Test: backoff cap at 10 seconds
// -------------------------------------------------------------------------
#[tokio::test]
async fn backoff_cap() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    // Start with a high delay that would exceed the 10s cap
    let max_retries = 1;
    let delay_ms = 15_000;

    let start = Instant::now();
    let result = connect_with_retry("127.0.0.1", port, max_retries, delay_ms).await;
    let elapsed = start.elapsed();

    assert!(result.is_err());
    // Should be capped: no more than ~10.5s
    assert!(
        elapsed < Duration::from_millis(11_000),
        "backoff should be capped at 10s, got {:?}",
        elapsed
    );
    // Should be at least close to 10s due to the cap
    assert!(
        elapsed >= Duration::from_secs(9),
        "backoff should be at least ~10s with cap, got {:?}",
        elapsed
    );
}

// -------------------------------------------------------------------------
// Test: exponential backoff doubles delay between retries
// -------------------------------------------------------------------------
#[tokio::test]
async fn exponential_backoff_doubles_delay() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    // 3 retries with initial delay of 50ms
    // Expected total delay: 50 + 100 + 200 = 350ms
    let max_retries = 3;
    let delay_ms = 50;

    let start = Instant::now();
    let result = connect_with_retry("127.0.0.1", port, max_retries, delay_ms).await;
    let elapsed = start.elapsed();

    assert!(result.is_err());
    // At least 300ms (50 + 100 + 200 = 350, being conservative with 300)
    assert!(
        elapsed >= Duration::from_millis(300),
        "expected at least 300ms total backoff, got {:?}",
        elapsed
    );
}

// -------------------------------------------------------------------------
// Test: error type is io::Error
// -------------------------------------------------------------------------
#[tokio::test]
async fn error_is_io_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let result = connect_with_retry("127.0.0.1", port, 0, 100).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    // The error should be a standard io::Error (ConnectionRefused)
    assert!(
        err.kind() == std::io::ErrorKind::ConnectionRefused
            || err.kind() == std::io::ErrorKind::Other,
        "unexpected error kind: {:?}",
        err.kind()
    );
}

// =========================================================================
// NEW TESTS: covering the 6 requested scenarios
// =========================================================================

// -------------------------------------------------------------------------
// test_first_attempt_no_delay: The first (and only) attempt to a listening
// port should complete almost instantly with no backoff delay.
// -------------------------------------------------------------------------
#[tokio::test]
async fn test_first_attempt_no_delay() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    // Even with a large delay_ms configured, the first attempt should not
    // sleep at all because backoff only kicks in for attempt > 0.
    let start = Instant::now();
    let result = connect_with_retry("127.0.0.1", port, 5, 5000).await;
    let elapsed = start.elapsed();

    assert!(result.is_ok(), "first attempt should succeed immediately");
    // The first attempt should take well under 100ms (no sleep).
    assert!(
        elapsed < Duration::from_millis(100),
        "first attempt should have no backoff delay, got {:?}",
        elapsed
    );
}

// -------------------------------------------------------------------------
// test_exponential_backoff_progression: Verify that the total elapsed time
// grows geometrically as max_retries increases, confirming exponential
// (not linear) progression.
// -------------------------------------------------------------------------
#[tokio::test]
async fn test_exponential_backoff_progression() {
    // Get an unused closed port.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let delay_ms: u64 = 40;

    // 1 retry: total backoff = 40ms
    let start = Instant::now();
    let _ = connect_with_retry("127.0.0.1", port, 1, delay_ms).await;
    let elapsed_1 = start.elapsed();

    // 2 retries: total backoff = 40 + 80 = 120ms
    let start = Instant::now();
    let _ = connect_with_retry("127.0.0.1", port, 2, delay_ms).await;
    let elapsed_2 = start.elapsed();

    // 3 retries: total backoff = 40 + 80 + 160 = 280ms
    let start = Instant::now();
    let _ = connect_with_retry("127.0.0.1", port, 3, delay_ms).await;
    let elapsed_3 = start.elapsed();

    // Each step should roughly double the cumulative backoff.
    // elapsed_2 should be significantly more than elapsed_1
    assert!(
        elapsed_2 > elapsed_1,
        "2 retries ({:?}) should take longer than 1 retry ({:?})",
        elapsed_2,
        elapsed_1
    );
    // elapsed_3 should be significantly more than elapsed_2
    assert!(
        elapsed_3 > elapsed_2,
        "3 retries ({:?}) should take longer than 2 retries ({:?})",
        elapsed_3,
        elapsed_2
    );

    // The growth from 2->3 retries adds 160ms while 1->2 adds 80ms,
    // so the incremental growth should be roughly doubling.
    // elapsed_3 - elapsed_2 should be roughly 2x (elapsed_2 - elapsed_1).
    // We check that the 3-retry total is at least 2x the 1-retry total,
    // which must hold for exponential backoff (sum of geometric series).
    assert!(
        elapsed_3 >= elapsed_1 * 2,
        "exponential growth: 3-retry time ({:?}) should be >= 2x 1-retry time ({:?})",
        elapsed_3,
        elapsed_1
    );
}

// -------------------------------------------------------------------------
// test_max_delay_cap: With multiple retries starting from a high initial
// delay, verify the cap (10s) bounds each individual sleep. Use 2 retries
// with delay_ms = 20_000: without capping, total would be 20s + 40s = 60s.
// With cap, total should be 10s + 10s = 20s.
// We use tokio::time::pause() to avoid actually waiting real wall-clock
// time, and measure elapsed with tokio::time::Instant which respects the
// paused/auto-advanced clock.
// -------------------------------------------------------------------------
#[tokio::test]
async fn test_max_delay_cap() {
    tokio::time::pause();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    // 2 retries starting at 20_000ms (20s).
    // Without cap: 20_000 + 40_000 = 60_000ms total backoff
    // With 10s cap: 10_000 + 10_000 = 20_000ms total backoff
    let max_retries = 2;
    let delay_ms = 20_000;

    let start = tokio::time::Instant::now();
    let result = connect_with_retry("127.0.0.1", port, max_retries, delay_ms).await;
    let elapsed = start.elapsed();

    assert!(result.is_err());

    // With the cap at 10s and 2 retries, total backoff should be ~20s.
    // It must be well below the uncapped 60s.
    assert!(
        elapsed < Duration::from_secs(25),
        "total backoff should be capped (~20s), but got {:?}",
        elapsed
    );
    // Should be at least 19s (2 * ~10s cap)
    assert!(
        elapsed >= Duration::from_secs(19),
        "total backoff should be at least ~20s with 2 capped retries, got {:?}",
        elapsed
    );
}

// -------------------------------------------------------------------------
// test_max_retries_exceeded: Verify that after max_retries + 1 total
// attempts, the function returns Err with the last connection error.
// Also verify that different max_retries values produce different timing,
// confirming all retries are actually attempted.
// -------------------------------------------------------------------------
#[tokio::test]
async fn test_max_retries_exceeded() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    // With max_retries=0: exactly 1 attempt, no sleep
    let start = Instant::now();
    let result_0 = connect_with_retry("127.0.0.1", port, 0, 50).await;
    let elapsed_0 = start.elapsed();

    assert!(result_0.is_err(), "should fail with max_retries=0");
    assert!(
        elapsed_0 < Duration::from_millis(100),
        "max_retries=0 should be near-instant, got {:?}",
        elapsed_0
    );

    // With max_retries=1: 2 total attempts, 1 sleep of 50ms
    let start = Instant::now();
    let result_1 = connect_with_retry("127.0.0.1", port, 1, 50).await;
    let elapsed_1 = start.elapsed();

    assert!(result_1.is_err(), "should fail with max_retries=1");
    assert!(
        elapsed_1 >= Duration::from_millis(40),
        "max_retries=1 should wait ~50ms, got {:?}",
        elapsed_1
    );

    // With max_retries=2: 3 total attempts, sleeps of 50ms + 100ms = 150ms
    let start = Instant::now();
    let result_2 = connect_with_retry("127.0.0.1", port, 2, 50).await;
    let elapsed_2 = start.elapsed();

    assert!(result_2.is_err(), "should fail with max_retries=2");
    assert!(
        elapsed_2 >= Duration::from_millis(120),
        "max_retries=2 should wait ~150ms, got {:?}",
        elapsed_2
    );

    // Confirm the error is a real io::Error
    let err = result_2.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
}

// -------------------------------------------------------------------------
// test_retry_with_success: Start a listener mid-retry and verify the
// returned TcpStream is actually functional (writable).
// -------------------------------------------------------------------------
#[tokio::test]
async fn test_retry_with_success() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    // Spawn a listener that appears after a delay and echoes data back.
    let handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(80)).await;
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let (mut conn, _) = listener.accept().await.unwrap();
        // Read and echo back
        let mut buf = [0u8; 5];
        use tokio::io::AsyncReadExt;
        let n = conn.read(&mut buf).await.unwrap();
        conn.write_all(&buf[..n]).await.unwrap();
    });

    // Retry: first attempt at ~0ms fails, second at ~60ms fails,
    // third at ~180ms succeeds (listener up at ~80ms).
    let result = connect_with_retry("127.0.0.1", port, 4, 60).await;
    assert!(
        result.is_ok(),
        "should succeed on retry: {:?}",
        result.err()
    );

    let (mut stream, addr) = result.unwrap();
    assert_eq!(addr.port(), port);

    // Verify the stream is actually functional.
    use tokio::io::AsyncReadExt;
    stream.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello", "stream should be usable after retry");

    handle.await.unwrap();
}

// -------------------------------------------------------------------------
// test_jitter_applied: The current implementation uses pure exponential
// backoff with NO jitter. Verify deterministic behavior: two runs with
// identical parameters should produce very similar elapsed times.
// If jitter were added in the future, this test would catch the change.
// -------------------------------------------------------------------------
#[tokio::test]
async fn test_jitter_applied() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let max_retries = 2;
    let delay_ms: u64 = 50;
    // Expected total: 50 + 100 = 150ms

    // Run twice and measure.
    let start = Instant::now();
    let _ = connect_with_retry("127.0.0.1", port, max_retries, delay_ms).await;
    let elapsed_a = start.elapsed();

    let start = Instant::now();
    let _ = connect_with_retry("127.0.0.1", port, max_retries, delay_ms).await;
    let elapsed_b = start.elapsed();

    // Without jitter, both runs should be within a tight tolerance of each
    // other. We allow up to 50ms difference for scheduling variance.
    let diff = elapsed_a.abs_diff(elapsed_b);

    assert!(
        diff < Duration::from_millis(50),
        "no jitter: two identical runs should have similar timing, \
         but got {:?} vs {:?} (diff {:?})",
        elapsed_a,
        elapsed_b,
        diff
    );

    // Both should be close to the expected 150ms total backoff.
    assert!(
        elapsed_a >= Duration::from_millis(120),
        "run A should wait at least ~150ms, got {:?}",
        elapsed_a
    );
    assert!(
        elapsed_b >= Duration::from_millis(120),
        "run B should wait at least ~150ms, got {:?}",
        elapsed_b
    );
}

// -------------------------------------------------------------------------
// test_ipv6_address_formatting: Verify IPv6 literal addresses are handled
// correctly (wrapped in brackets).
// -------------------------------------------------------------------------
#[tokio::test]
async fn test_ipv6_address_formatting() {
    let listener = TcpListener::bind("[::1]:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let result = connect_with_retry("::1", port, 0, 100).await;
    assert!(
        result.is_ok(),
        "should connect via IPv6: {:?}",
        result.err()
    );
    let (_stream, addr) = result.unwrap();
    assert_eq!(addr.port(), port);
    assert!(addr.ip().is_loopback(), "address should be IPv6 loopback");
}

// -------------------------------------------------------------------------
// test_ipv6_failure_retries: Verify retries also work for IPv6 addresses
// on unreachable ports.
// -------------------------------------------------------------------------
#[tokio::test]
async fn test_ipv6_failure_retries() {
    let listener = TcpListener::bind("[::1]:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let start = Instant::now();
    let result = connect_with_retry("::1", port, 1, 50).await;
    let elapsed = start.elapsed();

    assert!(result.is_err(), "should fail against closed IPv6 port");
    // 1 retry with 50ms delay
    assert!(
        elapsed >= Duration::from_millis(40),
        "should have backoff delay for IPv6 retry, got {:?}",
        elapsed
    );
}
