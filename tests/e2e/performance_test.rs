#[allow(dead_code, unused_imports)]
mod helpers;

use helpers::*;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Test 1: Throughput via SSH local forward
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_throughput_ssh_forward() {
    let ssh_port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(ssh_port, &hash)).await;

    let (echo_port, _echo_task) = tcp_echo_server().await;

    let client_config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(
        client_config,
        format!("127.0.0.1:{}", ssh_port),
        TestClientHandler,
    )
    .await
    .unwrap();

    handle
        .authenticate_password("testuser", "pass")
        .await
        .unwrap();

    let channel = handle
        .channel_open_direct_tcpip("127.0.0.1", echo_port as u32, "127.0.0.1", 12345)
        .await
        .unwrap();

    let mut stream = channel.into_stream();

    // Send 1MB of data
    let data_size = 1024 * 1024;
    let data = vec![0x42u8; data_size];

    let start = Instant::now();
    stream.write_all(&data).await.unwrap();

    // Read echo back
    let mut received = 0;
    let mut buf = vec![0u8; 65536];
    while received < data_size {
        match tokio::time::timeout(Duration::from_secs(30), stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => received += n,
            Ok(Err(_)) => break,
            Err(_) => break,
        }
    }

    let elapsed = start.elapsed();
    let throughput_mbps = (received as f64 / 1024.0 / 1024.0) / elapsed.as_secs_f64();

    eprintln!(
        "[PERF] SSH forward throughput: {:.2} MB/s ({} bytes in {:.2}s)",
        throughput_mbps,
        received,
        elapsed.as_secs_f64()
    );

    assert!(received > 0, "should receive data");
    assert!(
        throughput_mbps > 0.1,
        "throughput should be at least 0.1 MB/s, got {:.2}",
        throughput_mbps
    );
}

// ---------------------------------------------------------------------------
// Test 2: Throughput via SOCKS5
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_throughput_socks5() {
    let socks_port = free_port().await;
    let hash = hash_pass("pass");
    let server = start_socks5(socks_config(socks_port, &hash)).await;

    let (echo_port, _echo_task) = tcp_echo_server().await;

    let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port))
        .await
        .unwrap();

    socks5_greeting(&mut client).await;
    socks5_auth(&mut client, "alice", "pass").await;

    let reply = socks5_connect_domain(&mut client, "127.0.0.1", echo_port).await;
    assert_eq!(reply, 0x00);

    // Send 1MB
    let data_size = 1024 * 1024;
    let data = vec![0x42u8; data_size];

    let start = Instant::now();
    client.write_all(&data).await.unwrap();

    let mut received = 0;
    let mut buf = vec![0u8; 65536];
    while received < data_size {
        match tokio::time::timeout(Duration::from_secs(30), client.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => received += n,
            Ok(Err(_)) => break,
            Err(_) => break,
        }
    }

    let elapsed = start.elapsed();
    let throughput_mbps = (received as f64 / 1024.0 / 1024.0) / elapsed.as_secs_f64();

    eprintln!(
        "[PERF] SOCKS5 throughput: {:.2} MB/s ({} bytes in {:.2}s)",
        throughput_mbps,
        received,
        elapsed.as_secs_f64()
    );

    assert!(received > 0);
    assert!(
        throughput_mbps > 0.1,
        "throughput should be at least 0.1 MB/s, got {:.2}",
        throughput_mbps
    );
}

// ---------------------------------------------------------------------------
// Test 3: Concurrent SSH connections
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_concurrent_ssh_connections() {
    let ssh_port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(ssh_port, &hash)).await;

    let start = Instant::now();
    let count = 50;
    let mut handles = vec![];

    for i in 0..count {
        let handle = tokio::spawn(async move {
            let client_config = Arc::new(russh::client::Config::default());
            let mut h = russh::client::connect(
                client_config,
                format!("127.0.0.1:{}", ssh_port),
                TestClientHandler,
            )
            .await
            .unwrap();

            let ok = h.authenticate_password("testuser", "pass").await.unwrap();
            assert!(ok.success(), "connection {} should auth", i);
        });
        handles.push(handle);
    }

    let mut successes = 0;
    for h in handles {
        if h.await.is_ok() {
            successes += 1;
        }
    }

    let elapsed = start.elapsed();
    eprintln!(
        "[PERF] {} concurrent SSH connections in {:.2}s ({} succeeded)",
        count,
        elapsed.as_secs_f64(),
        successes
    );

    assert!(
        successes >= count / 2,
        "at least half of connections should succeed"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Concurrent SOCKS5 connections
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_concurrent_socks5_connections() {
    let socks_port = free_port().await;
    let hash = hash_pass("pass");
    let server = start_socks5(socks_config(socks_port, &hash)).await;

    let start = Instant::now();
    let count = 50;
    let mut handles = vec![];

    for i in 0..count {
        let p = server.port;
        let handle = tokio::spawn(async move {
            let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", p))
                .await
                .unwrap();
            socks5_greeting(&mut client).await;
            let auth = socks5_auth(&mut client, "alice", "pass").await;
            assert_eq!(auth, 0x00, "socks5 connection {} auth", i);
        });
        handles.push(handle);
    }

    let mut successes = 0;
    for h in handles {
        if h.await.is_ok() {
            successes += 1;
        }
    }

    let elapsed = start.elapsed();
    eprintln!(
        "[PERF] {} concurrent SOCKS5 connections in {:.2}s ({} succeeded)",
        count,
        elapsed.as_secs_f64(),
        successes
    );

    assert!(successes >= count / 2);
}

// ---------------------------------------------------------------------------
// Test 5: SSH auth latency
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_ssh_auth_latency() {
    let ssh_port = free_port().await;
    let hash = hash_pass("pass");
    let _server = start_ssh(ssh_config(ssh_port, &hash)).await;

    let iterations = 20;
    let mut latencies = Vec::new();

    for _ in 0..iterations {
        let start = Instant::now();

        let client_config = Arc::new(russh::client::Config::default());
        let mut handle = russh::client::connect(
            client_config,
            format!("127.0.0.1:{}", ssh_port),
            TestClientHandler,
        )
        .await
        .unwrap();

        handle
            .authenticate_password("testuser", "pass")
            .await
            .unwrap();

        latencies.push(start.elapsed());
    }

    let avg_ms = latencies.iter().map(|d| d.as_millis()).sum::<u128>() as f64 / iterations as f64;
    let min_ms = latencies.iter().map(|d| d.as_millis()).min().unwrap();
    let max_ms = latencies.iter().map(|d| d.as_millis()).max().unwrap();

    eprintln!(
        "[PERF] SSH auth latency ({}x): avg={:.1}ms min={}ms max={}ms",
        iterations, avg_ms, min_ms, max_ms
    );

    assert!(
        avg_ms < 5000.0,
        "average auth latency should be under 5s, got {:.1}ms",
        avg_ms
    );
}
