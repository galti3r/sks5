use sks5::proxy::forwarder::{self, RelayConfig};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn test_relay_config(idle_timeout: Duration, context: &str) -> RelayConfig {
    RelayConfig {
        idle_timeout,
        context: context.to_string(),
        per_conn_bandwidth_kbps: 0,
        aggregate_bandwidth_kbps: 0,
        quota_tracker: None,
        username: None,
        quotas: None,
        audit: None,
        session: None,
    }
}

// ---------------------------------------------------------------------------
// relay_one_direction via relay() -- basic data transfer
// ---------------------------------------------------------------------------

#[tokio::test]
async fn relay_transfers_data_in_both_directions() {
    let (mut client, relay_client) = tokio::io::duplex(4096);
    let (mut server, relay_server) = tokio::io::duplex(4096);

    let handle = tokio::spawn(async move {
        forwarder::relay(
            relay_client,
            relay_server,
            test_relay_config(Duration::from_secs(5), "test@bidir:80"),
        )
        .await
        .unwrap()
    });

    // Client -> Server
    client.write_all(b"request data").await.unwrap();
    let mut buf = [0u8; 64];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"request data");

    // Server -> Client
    server.write_all(b"response data").await.unwrap();
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"response data");

    drop(client);
    drop(server);

    let (up, down) = handle.await.unwrap();
    assert_eq!(up, 12); // "request data" = 12 bytes
    assert_eq!(down, 13); // "response data" = 13 bytes
}

#[tokio::test]
async fn relay_handles_empty_transfer() {
    let (client, relay_client) = tokio::io::duplex(4096);
    let (server, relay_server) = tokio::io::duplex(4096);

    let handle = tokio::spawn(async move {
        forwarder::relay(
            relay_client,
            relay_server,
            test_relay_config(Duration::from_secs(2), "test@empty:80"),
        )
        .await
        .unwrap()
    });

    // Close both sides immediately without sending data
    drop(client);
    drop(server);

    let (up, down) = handle.await.unwrap();
    assert_eq!(up, 0);
    assert_eq!(down, 0);
}

#[tokio::test]
async fn relay_handles_large_transfer() {
    let (mut client, relay_client) = tokio::io::duplex(65536);
    let (mut server, relay_server) = tokio::io::duplex(65536);

    let handle = tokio::spawn(async move {
        forwarder::relay(
            relay_client,
            relay_server,
            test_relay_config(Duration::from_secs(5), "test@large:80"),
        )
        .await
        .unwrap()
    });

    // Send a large payload (64 KiB)
    let payload = vec![0xABu8; 65536];
    client.write_all(&payload).await.unwrap();

    // Read the full payload on the server side
    let mut received = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = server.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
        if received.len() >= 65536 {
            break;
        }
    }
    assert_eq!(received.len(), 65536);
    assert!(received.iter().all(|&b| b == 0xAB));

    drop(client);
    drop(server);

    let (up, _down) = handle.await.unwrap();
    assert_eq!(up, 65536);
}

// ---------------------------------------------------------------------------
// Idle timeout
// ---------------------------------------------------------------------------

#[tokio::test]
async fn relay_idle_timeout_fires_with_no_data() {
    let (_client, relay_client) = tokio::io::duplex(4096);
    let (_server, relay_server) = tokio::io::duplex(4096);

    let start = std::time::Instant::now();
    let handle = tokio::spawn(async move {
        forwarder::relay(
            relay_client,
            relay_server,
            test_relay_config(Duration::from_millis(100), "test@idle:80"),
        )
        .await
        .unwrap()
    });

    let (up, down) = handle.await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(up, 0);
    assert_eq!(down, 0);
    // Should complete close to the timeout, definitely under 5 seconds
    assert!(elapsed < Duration::from_secs(5));
    // Should have waited at least roughly 100ms
    assert!(elapsed >= Duration::from_millis(50));
}

#[tokio::test]
async fn relay_idle_timeout_fires_after_initial_data() {
    let (mut client, relay_client) = tokio::io::duplex(4096);
    let (mut server, relay_server) = tokio::io::duplex(4096);

    let handle = tokio::spawn(async move {
        forwarder::relay(
            relay_client,
            relay_server,
            test_relay_config(Duration::from_millis(200), "test@idle-after:80"),
        )
        .await
        .unwrap()
    });

    // Send some data first
    client.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 64];
    let _ = server.read(&mut buf).await.unwrap();

    // Then stop sending -- should timeout
    let start = std::time::Instant::now();
    let (up, down) = handle.await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(up, 5);
    assert_eq!(down, 0);
    assert!(elapsed < Duration::from_secs(5));
}

#[tokio::test]
async fn relay_zero_timeout_uses_default_large_timeout() {
    // Duration::ZERO idle_timeout gets replaced with 365 days internally.
    // We verify it does not immediately timeout by sending data and reading it.
    let (mut client, relay_client) = tokio::io::duplex(4096);
    let (mut server, relay_server) = tokio::io::duplex(4096);

    let handle = tokio::spawn(async move {
        forwarder::relay(
            relay_client,
            relay_server,
            test_relay_config(Duration::ZERO, "test@zerotimeout:80"),
        )
        .await
        .unwrap()
    });

    // Should still work normally -- no immediate timeout
    client.write_all(b"data").await.unwrap();
    let mut buf = [0u8; 64];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"data");

    drop(client);
    drop(server);

    let (up, _) = handle.await.unwrap();
    assert_eq!(up, 4);
}

// ---------------------------------------------------------------------------
// Unilateral close
// ---------------------------------------------------------------------------

#[tokio::test]
async fn relay_completes_when_client_side_closes() {
    let (client, relay_client) = tokio::io::duplex(4096);
    let (_server, relay_server) = tokio::io::duplex(4096);

    let handle = tokio::spawn(async move {
        forwarder::relay(
            relay_client,
            relay_server,
            test_relay_config(Duration::from_millis(300), "test@client-close:80"),
        )
        .await
        .unwrap()
    });

    drop(client);

    let result = tokio::time::timeout(Duration::from_secs(5), handle).await;
    assert!(result.is_ok(), "Relay should complete after client close");
}

#[tokio::test]
async fn relay_completes_when_server_side_closes() {
    let (_client, relay_client) = tokio::io::duplex(4096);
    let (server, relay_server) = tokio::io::duplex(4096);

    let handle = tokio::spawn(async move {
        forwarder::relay(
            relay_client,
            relay_server,
            test_relay_config(Duration::from_millis(300), "test@server-close:80"),
        )
        .await
        .unwrap()
    });

    drop(server);

    let result = tokio::time::timeout(Duration::from_secs(5), handle).await;
    assert!(result.is_ok(), "Relay should complete after server close");
}

// ---------------------------------------------------------------------------
// Bandwidth throttling constants
// ---------------------------------------------------------------------------

#[tokio::test]
async fn relay_with_bandwidth_limit_still_transfers_data() {
    let (mut client, relay_client) = tokio::io::duplex(4096);
    let (mut server, relay_server) = tokio::io::duplex(4096);

    let config = RelayConfig {
        idle_timeout: Duration::from_secs(5),
        context: "test@bw-limit:80".to_string(),
        per_conn_bandwidth_kbps: 1000, // 1 Mbps
        aggregate_bandwidth_kbps: 0,
        quota_tracker: None,
        username: None,
        quotas: None,
        audit: None,
        session: None,
    };

    let handle = tokio::spawn(async move {
        forwarder::relay(relay_client, relay_server, config)
            .await
            .unwrap()
    });

    client.write_all(b"throttled data").await.unwrap();
    let mut buf = [0u8; 64];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"throttled data");

    drop(client);
    drop(server);

    let (up, _) = handle.await.unwrap();
    assert_eq!(up, 14); // "throttled data" = 14 bytes
}

// ---------------------------------------------------------------------------
// Session byte counter tracking
// ---------------------------------------------------------------------------

#[tokio::test]
async fn relay_updates_session_byte_counters() {
    use sks5::proxy::LiveSession;
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;

    let (mut client, relay_client) = tokio::io::duplex(4096);
    let (mut server, relay_server) = tokio::io::duplex(4096);

    let session = Arc::new(LiveSession {
        session_id: "test-s0".to_string(),
        username: "alice".to_string(),
        target_host: "host".to_string(),
        target_port: 80,
        source_ip: "10.0.0.1".to_string(),
        started_at: chrono::Utc::now(),
        bytes_up: AtomicU64::new(0),
        bytes_down: AtomicU64::new(0),
        protocol: "ssh".to_string(),
    });

    let config = RelayConfig {
        idle_timeout: Duration::from_secs(5),
        context: "test@session-bytes:80".to_string(),
        per_conn_bandwidth_kbps: 0,
        aggregate_bandwidth_kbps: 0,
        quota_tracker: None,
        username: Some("alice".to_string()),
        quotas: None,
        audit: None,
        session: Some(session.clone()),
    };

    let handle = tokio::spawn(async move {
        forwarder::relay(relay_client, relay_server, config)
            .await
            .unwrap()
    });

    // Client sends 10 bytes
    client.write_all(b"0123456789").await.unwrap();
    let mut buf = [0u8; 64];
    let _ = server.read(&mut buf).await.unwrap();

    // Server sends 5 bytes
    server.write_all(b"abcde").await.unwrap();
    let _ = client.read(&mut buf).await.unwrap();

    drop(client);
    drop(server);

    handle.await.unwrap();

    assert_eq!(
        session.bytes_up.load(std::sync::atomic::Ordering::Relaxed),
        10
    );
    assert_eq!(
        session
            .bytes_down
            .load(std::sync::atomic::Ordering::Relaxed),
        5
    );
}

// ---------------------------------------------------------------------------
// RelayConfig construction
// ---------------------------------------------------------------------------

#[test]
fn relay_config_default_fields() {
    let config = test_relay_config(Duration::from_secs(30), "ctx");

    assert_eq!(config.idle_timeout, Duration::from_secs(30));
    assert_eq!(config.context, "ctx");
    assert_eq!(config.per_conn_bandwidth_kbps, 0);
    assert_eq!(config.aggregate_bandwidth_kbps, 0);
    assert!(config.quota_tracker.is_none());
    assert!(config.username.is_none());
    assert!(config.quotas.is_none());
    assert!(config.audit.is_none());
    assert!(config.session.is_none());
}

#[test]
fn relay_config_with_username() {
    let config = RelayConfig {
        idle_timeout: Duration::from_secs(60),
        context: "user@host:443".to_string(),
        per_conn_bandwidth_kbps: 500,
        aggregate_bandwidth_kbps: 1000,
        quota_tracker: None,
        username: Some("alice".to_string()),
        quotas: None,
        audit: None,
        session: None,
    };

    assert_eq!(config.username.as_deref(), Some("alice"));
    assert_eq!(config.per_conn_bandwidth_kbps, 500);
    assert_eq!(config.aggregate_bandwidth_kbps, 1000);
}

// ---------------------------------------------------------------------------
// Multiple sequential transfers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn relay_multiple_writes_accumulate_bytes() {
    let (mut client, relay_client) = tokio::io::duplex(4096);
    let (mut server, relay_server) = tokio::io::duplex(4096);

    let handle = tokio::spawn(async move {
        forwarder::relay(
            relay_client,
            relay_server,
            test_relay_config(Duration::from_secs(5), "test@multi:80"),
        )
        .await
        .unwrap()
    });

    let mut buf = [0u8; 64];

    // Multiple writes client -> server
    for _ in 0..5 {
        client.write_all(b"ab").await.unwrap();
        let _ = server.read(&mut buf).await.unwrap();
    }

    // Multiple writes server -> client
    for _ in 0..3 {
        server.write_all(b"xyz").await.unwrap();
        let _ = client.read(&mut buf).await.unwrap();
    }

    drop(client);
    drop(server);

    let (up, down) = handle.await.unwrap();
    assert_eq!(up, 10); // 5 * 2 bytes
    assert_eq!(down, 9); // 3 * 3 bytes
}
