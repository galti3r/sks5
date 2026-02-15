use sks5::config::types::ConnectionPoolConfig;
use sks5::proxy::pool::ConnectionPool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::net::TcpStream;

/// Helper: create a connected TcpStream pair via a local listener.
async fn make_tcp_stream() -> TcpStream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connect_fut = TcpStream::connect(addr);
    let accept_fut = listener.accept();
    let (client, _) = tokio::join!(connect_fut, accept_fut);
    client.unwrap()
}

fn pool_config(enabled: bool, max_idle: u32, timeout_secs: u64) -> ConnectionPoolConfig {
    ConnectionPoolConfig {
        enabled,
        max_idle_per_host: max_idle,
        idle_timeout_secs: timeout_secs,
    }
}

// -------------------------------------------------------------------------
// Test: get returns None when pool is disabled
// -------------------------------------------------------------------------
#[tokio::test]
async fn get_returns_none_when_disabled() {
    let pool = ConnectionPool::new(&pool_config(false, 10, 60));
    assert!(pool.get("example.com", 80).is_none());
}

// -------------------------------------------------------------------------
// Test: get returns None when pool is empty
// -------------------------------------------------------------------------
#[tokio::test]
async fn get_returns_none_when_empty() {
    let pool = ConnectionPool::new(&pool_config(true, 10, 60));
    assert!(pool.get("example.com", 80).is_none());
    assert_eq!(pool.misses.load(Ordering::Relaxed), 0);
}

// -------------------------------------------------------------------------
// Test: put and get lifecycle
// -------------------------------------------------------------------------
#[tokio::test]
async fn put_and_get_roundtrip() {
    let pool = ConnectionPool::new(&pool_config(true, 10, 60));
    let stream = make_tcp_stream().await;

    pool.put("example.com", 80, stream);
    assert_eq!(pool.len(), 1);
    assert_eq!(pool.host_count(), 1);

    let retrieved = pool.get("example.com", 80);
    assert!(retrieved.is_some());
    assert_eq!(pool.hits.load(Ordering::Relaxed), 1);
    assert!(pool.is_empty());
}

// -------------------------------------------------------------------------
// Test: pool respects max_idle_per_host capacity limit
// -------------------------------------------------------------------------
#[tokio::test]
async fn put_respects_max_idle_per_host() {
    let pool = ConnectionPool::new(&pool_config(true, 2, 60));

    let s1 = make_tcp_stream().await;
    let s2 = make_tcp_stream().await;
    let s3 = make_tcp_stream().await;

    pool.put("example.com", 80, s1);
    pool.put("example.com", 80, s2);
    pool.put("example.com", 80, s3); // Should be dropped (exceeds max of 2)

    assert_eq!(pool.len(), 2);
}

// -------------------------------------------------------------------------
// Test: put is noop when pool is disabled
// -------------------------------------------------------------------------
#[tokio::test]
async fn put_is_noop_when_disabled() {
    let pool = ConnectionPool::new(&pool_config(false, 10, 60));
    let stream = make_tcp_stream().await;
    pool.put("example.com", 80, stream);
    assert!(pool.is_empty());
}

// -------------------------------------------------------------------------
// Test: get discards expired connections
// -------------------------------------------------------------------------
#[tokio::test]
async fn get_discards_expired_connections() {
    // Timeout of 0 seconds means everything expires immediately
    let pool = ConnectionPool::new(&pool_config(true, 10, 0));
    let stream = make_tcp_stream().await;

    pool.put("example.com", 80, stream);
    tokio::time::sleep(Duration::from_millis(5)).await;

    let retrieved = pool.get("example.com", 80);
    assert!(retrieved.is_none());
    assert_eq!(pool.misses.load(Ordering::Relaxed), 1);
    assert!(pool.is_empty());
}

// -------------------------------------------------------------------------
// Test: cleanup removes expired entries across all hosts
// -------------------------------------------------------------------------
#[tokio::test]
async fn cleanup_removes_expired_entries() {
    let pool = ConnectionPool::new(&pool_config(true, 10, 0));
    let s1 = make_tcp_stream().await;
    let s2 = make_tcp_stream().await;

    pool.put("example.com", 80, s1);
    pool.put("other.com", 443, s2);
    assert_eq!(pool.len(), 2);

    tokio::time::sleep(Duration::from_millis(5)).await;
    pool.cleanup();

    assert!(pool.is_empty());
    assert_eq!(pool.host_count(), 0);
}

// -------------------------------------------------------------------------
// Test: cleanup retains live (non-expired) connections
// -------------------------------------------------------------------------
#[tokio::test]
async fn cleanup_retains_live_connections() {
    let pool = ConnectionPool::new(&pool_config(true, 10, 300));
    let stream = make_tcp_stream().await;

    pool.put("example.com", 80, stream);
    pool.cleanup();

    assert_eq!(pool.len(), 1);
}

// -------------------------------------------------------------------------
// Test: multiple hosts are tracked independently
// -------------------------------------------------------------------------
#[tokio::test]
async fn multiple_hosts_are_independent() {
    let pool = ConnectionPool::new(&pool_config(true, 2, 60));
    let s1 = make_tcp_stream().await;
    let s2 = make_tcp_stream().await;

    pool.put("host-a.com", 80, s1);
    pool.put("host-b.com", 443, s2);

    assert_eq!(pool.host_count(), 2);
    assert_eq!(pool.len(), 2);

    let a = pool.get("host-a.com", 80);
    assert!(a.is_some());
    assert_eq!(pool.len(), 1);

    let b = pool.get("host-b.com", 443);
    assert!(b.is_some());
    assert!(pool.is_empty());
}

// -------------------------------------------------------------------------
// Test: LIFO ordering (last put is first get)
// -------------------------------------------------------------------------
#[tokio::test]
async fn lifo_order() {
    let pool = ConnectionPool::new(&pool_config(true, 10, 60));

    let s1 = make_tcp_stream().await;
    let s2 = make_tcp_stream().await;

    let addr1 = s1.local_addr().unwrap();
    let addr2 = s2.local_addr().unwrap();

    pool.put("example.com", 80, s1);
    pool.put("example.com", 80, s2);

    // LIFO: second put should come out first
    let first_out = pool.get("example.com", 80).unwrap();
    assert_eq!(first_out.local_addr().unwrap(), addr2);

    let second_out = pool.get("example.com", 80).unwrap();
    assert_eq!(second_out.local_addr().unwrap(), addr1);
}

// -------------------------------------------------------------------------
// Test: get from wrong host returns None even when other host has connections
// -------------------------------------------------------------------------
#[tokio::test]
async fn get_wrong_host_returns_none() {
    let pool = ConnectionPool::new(&pool_config(true, 10, 60));
    let stream = make_tcp_stream().await;

    pool.put("example.com", 80, stream);

    // Different host
    assert!(pool.get("other.com", 80).is_none());
    // Different port
    assert!(pool.get("example.com", 443).is_none());
    // The original is still there
    assert_eq!(pool.len(), 1);
}

// -------------------------------------------------------------------------
// Test: hit and miss counters track correctly
// -------------------------------------------------------------------------
#[tokio::test]
async fn hit_miss_counters() {
    let pool = ConnectionPool::new(&pool_config(true, 10, 60));
    let s1 = make_tcp_stream().await;
    let s2 = make_tcp_stream().await;

    pool.put("example.com", 80, s1);
    pool.put("example.com", 80, s2);

    // Two hits
    assert!(pool.get("example.com", 80).is_some());
    assert!(pool.get("example.com", 80).is_some());
    assert_eq!(pool.hits.load(Ordering::Relaxed), 2);

    // Now pool is empty, next get should miss (if key still existed)
    // But since all connections were retrieved, the key should be removed
    assert!(pool.get("example.com", 80).is_none());
}
