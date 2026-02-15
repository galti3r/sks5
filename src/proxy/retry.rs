use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::{debug, warn};

/// Maximum backoff cap: 10 seconds.
const MAX_BACKOFF_MS: u64 = 10_000;

/// Attempt to connect to `host:port` with exponential-backoff retries.
///
/// - On the first attempt failure, waits `delay_ms` before retrying.
/// - Each subsequent retry doubles the delay, capped at [`MAX_BACKOFF_MS`] (10 s).
/// - After `max_retries` additional attempts (so up to `1 + max_retries` total), the
///   last [`std::io::Error`] is returned.
///
/// Returns the connected [`TcpStream`] and the resolved [`SocketAddr`] on success.
pub async fn connect_with_retry(
    host: &str,
    port: u16,
    max_retries: u32,
    delay_ms: u64,
) -> std::io::Result<(TcpStream, SocketAddr)> {
    let addr_str = if host.contains(':') {
        // IPv6 literal
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    };

    let mut current_delay = delay_ms;
    let mut last_err: Option<std::io::Error> = None;

    // Total attempts = 1 (initial) + max_retries
    for attempt in 0..=max_retries {
        if attempt > 0 {
            let capped_delay = current_delay.min(MAX_BACKOFF_MS);
            debug!(
                target_addr = %addr_str,
                attempt = attempt,
                delay_ms = capped_delay,
                "Retrying connection after backoff"
            );
            tokio::time::sleep(Duration::from_millis(capped_delay)).await;
            // Exponential backoff: double delay for next iteration
            current_delay = current_delay.saturating_mul(2);
        }

        match TcpStream::connect(&addr_str).await {
            Ok(stream) => {
                let peer_addr = stream
                    .peer_addr()
                    .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], port)));
                if attempt > 0 {
                    debug!(
                        target_addr = %addr_str,
                        attempt = attempt,
                        "Connection succeeded after retry"
                    );
                }
                return Ok((stream, peer_addr));
            }
            Err(e) => {
                if attempt < max_retries {
                    warn!(
                        target_addr = %addr_str,
                        attempt = attempt,
                        max_retries = max_retries,
                        error = %e,
                        "Connection attempt failed, will retry"
                    );
                } else {
                    warn!(
                        target_addr = %addr_str,
                        attempt = attempt,
                        error = %e,
                        "Connection attempt failed, no retries remaining"
                    );
                }
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("failed to connect to {}", addr_str),
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use tokio::net::TcpListener;

    /// Verify that connecting to a valid listener succeeds on the first attempt
    /// with zero retries configured.
    #[tokio::test]
    async fn test_connect_success_no_retries() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let result = connect_with_retry("127.0.0.1", port, 0, 100).await;
        assert!(result.is_ok(), "should connect to listening port");
        let (_stream, addr) = result.unwrap();
        assert_eq!(addr.port(), port);
    }

    /// Verify that connecting to a non-listening port fails after exhausting retries,
    /// and that exponential backoff introduces a measurable delay.
    #[tokio::test]
    async fn test_connect_failure_with_retries_and_backoff() {
        // Bind and immediately drop to get an unused port that nothing listens on.
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
        // we expect at least ~100ms of backoff time (being conservative to avoid
        // flakiness on slow CI).
        assert!(
            elapsed >= Duration::from_millis(100),
            "expected at least 100ms of backoff, got {:?}",
            elapsed
        );
    }

    /// Verify that a connection succeeds on a retry when the listener appears
    /// after the initial attempt fails.
    #[tokio::test]
    async fn test_connect_succeeds_on_retry() {
        // Get an unused port.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        // Spawn a task that starts listening after a short delay.
        let port_clone = port;
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(120)).await;
            let listener = TcpListener::bind(format!("127.0.0.1:{}", port_clone))
                .await
                .unwrap();
            // Accept one connection to keep the listener alive.
            let _conn = listener.accept().await.unwrap();
        });

        // Retry with enough delay for the listener to come up.
        // Attempt 0: immediate (fails), wait 80ms
        // Attempt 1: at ~80ms (fails), wait 160ms
        // Attempt 2: at ~240ms (succeeds, listener started at ~120ms)
        let result = connect_with_retry("127.0.0.1", port, 3, 80).await;
        assert!(
            result.is_ok(),
            "should succeed after listener starts: {:?}",
            result.err()
        );

        handle.await.unwrap();
    }

    /// Verify zero retries means exactly one attempt (no backoff).
    #[tokio::test]
    async fn test_zero_retries_single_attempt() {
        // Get an unused port that is closed.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let start = Instant::now();
        let result = connect_with_retry("127.0.0.1", port, 0, 1000).await;
        let elapsed = start.elapsed();

        assert!(result.is_err(), "should fail with zero retries");
        // Should not wait at all since there are zero retries.
        assert!(
            elapsed < Duration::from_millis(500),
            "zero retries should not introduce delay, got {:?}",
            elapsed
        );
    }

    /// Verify the backoff cap at 10 seconds works correctly.
    #[tokio::test]
    async fn test_backoff_cap() {
        // Get an unused port.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        // Start with a high delay that would exceed the cap on the first retry.
        let max_retries = 1;
        let delay_ms = 15_000; // 15s, but capped at 10s

        let start = Instant::now();
        let result = connect_with_retry("127.0.0.1", port, max_retries, delay_ms).await;
        let elapsed = start.elapsed();

        assert!(result.is_err());
        // Should be capped: no more than ~10.5s (10s cap + connection attempt time).
        assert!(
            elapsed < Duration::from_millis(11_000),
            "backoff should be capped at 10s, got {:?}",
            elapsed
        );
        // Should be at least close to 10s due to the cap.
        assert!(
            elapsed >= Duration::from_secs(9),
            "backoff should be at least ~10s with cap, got {:?}",
            elapsed
        );
    }
}
