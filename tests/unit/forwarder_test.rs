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

#[tokio::test]
async fn test_bidirectional_relay() {
    // Create two duplex pairs: one for "client side", one for "server side"
    let (mut client_rw, relay_client) = tokio::io::duplex(4096);
    let (mut server_rw, relay_server) = tokio::io::duplex(4096);

    let relay_handle = tokio::spawn(async move {
        forwarder::relay(
            relay_client,
            relay_server,
            test_relay_config(Duration::from_secs(5), "test@localhost:80"),
        )
        .await
        .unwrap()
    });

    // Client sends data
    client_rw.write_all(b"hello server").await.unwrap();

    // Server reads it
    let mut buf = [0u8; 64];
    let n = server_rw.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello server");

    // Server sends data back
    server_rw.write_all(b"hello client").await.unwrap();

    // Client reads it
    let n = client_rw.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello client");

    // Close both sides
    drop(client_rw);
    drop(server_rw);

    let (bytes_up, bytes_down) = relay_handle.await.unwrap();
    assert!(bytes_up + bytes_down > 0);
}

#[tokio::test]
async fn test_idle_timeout_triggers() {
    let (client_rw, relay_client) = tokio::io::duplex(4096);
    let (_server_rw, relay_server) = tokio::io::duplex(4096);

    // Use very short idle timeout
    let start = std::time::Instant::now();
    let relay_handle = tokio::spawn(async move {
        forwarder::relay(
            relay_client,
            relay_server,
            test_relay_config(Duration::from_millis(100), "test@timeout:80"),
        )
        .await
        .unwrap()
    });

    // Don't send any data — just keep both sides open
    // The relay should time out
    let (bytes_up, bytes_down) = relay_handle.await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(bytes_up + bytes_down, 0);
    // Should complete quickly due to idle timeout (not hang forever)
    assert!(elapsed < Duration::from_secs(5));

    drop(client_rw);
}

#[tokio::test]
async fn test_unilateral_close() {
    let (client_rw, relay_client) = tokio::io::duplex(4096);
    let (_server_rw, relay_server) = tokio::io::duplex(4096);

    let relay_handle = tokio::spawn(async move {
        forwarder::relay(
            relay_client,
            relay_server,
            test_relay_config(Duration::from_millis(500), "test@close:80"),
        )
        .await
        .unwrap()
    });

    // Close client side immediately
    drop(client_rw);

    // Relay should complete after idle timeout on the remaining direction
    let result = tokio::time::timeout(Duration::from_secs(5), relay_handle).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_byte_counting() {
    let (mut client_rw, relay_client) = tokio::io::duplex(4096);
    let (mut server_rw, relay_server) = tokio::io::duplex(4096);

    let relay_handle = tokio::spawn(async move {
        forwarder::relay(
            relay_client,
            relay_server,
            test_relay_config(Duration::from_secs(5), "test@bytes:80"),
        )
        .await
        .unwrap()
    });

    // Client sends 10 bytes
    client_rw.write_all(b"0123456789").await.unwrap();
    let mut buf = [0u8; 64];
    let _ = server_rw.read(&mut buf).await.unwrap();

    // Server sends 5 bytes
    server_rw.write_all(b"abcde").await.unwrap();
    let _ = client_rw.read(&mut buf).await.unwrap();

    drop(client_rw);
    drop(server_rw);

    let (bytes_up, bytes_down) = relay_handle.await.unwrap();
    assert_eq!(bytes_up, 10); // client → server
    assert_eq!(bytes_down, 5); // server → client
}
