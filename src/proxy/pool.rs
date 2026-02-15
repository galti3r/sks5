use crate::config::types::ConnectionPoolConfig;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tracing::{debug, trace};

/// A cached TCP connection with creation metadata.
pub struct PooledConnection {
    pub stream: TcpStream,
    created_at: Instant,
}

impl PooledConnection {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            created_at: Instant::now(),
        }
    }

    /// Check whether this connection has exceeded the idle timeout.
    fn is_expired(&self, idle_timeout: Duration) -> bool {
        self.created_at.elapsed() > idle_timeout
    }
}

/// Thread-safe connection pool backed by `DashMap`.
///
/// Connections are keyed by `"host:port"` and stored in a LIFO stack
/// (last-in-first-out) so that the most recently used connection is
/// returned first, reducing the chance of handing out a stale socket.
pub struct ConnectionPool {
    connections: DashMap<String, Vec<PooledConnection>>,
    max_idle_per_host: u32,
    idle_timeout: Duration,
    enabled: bool,
    /// Total number of successful get() hits.
    pub hits: AtomicU64,
    /// Total number of get() misses (no available connection).
    pub misses: AtomicU64,
}

impl ConnectionPool {
    /// Create a new pool from the application configuration.
    pub fn new(config: &ConnectionPoolConfig) -> Self {
        Self {
            connections: DashMap::new(),
            max_idle_per_host: config.max_idle_per_host,
            idle_timeout: Duration::from_secs(config.idle_timeout_secs),
            enabled: config.enabled,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Attempt to retrieve a cached connection for `host:port`.
    ///
    /// Expired connections are discarded during the lookup.
    /// Returns `None` when the pool is disabled or no live connection is available.
    pub fn get(&self, host: &str, port: u16) -> Option<TcpStream> {
        if !self.enabled {
            return None;
        }

        let key = format!("{}:{}", host, port);
        let mut entry = self.connections.get_mut(&key)?;
        let conns = entry.value_mut();

        // Pop from the back (LIFO) and skip expired entries.
        while let Some(pooled) = conns.pop() {
            if pooled.is_expired(self.idle_timeout) {
                trace!(key = %key, "Discarding expired pooled connection");
                continue;
            }

            // Remove the map entry entirely if the vec is now empty.
            if conns.is_empty() {
                drop(entry);
                self.connections.remove(&key);
            }

            self.hits.fetch_add(1, Ordering::Relaxed);
            debug!(key = %key, "Reusing pooled connection");
            return Some(pooled.stream);
        }

        // All connections were expired — clean up the empty entry.
        drop(entry);
        self.connections.remove(&key);

        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Return a connection to the pool for future reuse.
    ///
    /// The connection is silently dropped when:
    /// - the pool is disabled, or
    /// - the per-host idle limit has been reached.
    pub fn put(&self, host: &str, port: u16, stream: TcpStream) {
        if !self.enabled {
            return;
        }

        let key = format!("{}:{}", host, port);
        let mut entry = self.connections.entry(key.clone()).or_default();
        let conns = entry.value_mut();

        if conns.len() >= self.max_idle_per_host as usize {
            debug!(key = %key, max = self.max_idle_per_host, "Pool full for host, dropping connection");
            return;
        }

        conns.push(PooledConnection::new(stream));
        trace!(key = %key, idle = conns.len(), "Connection returned to pool");
    }

    /// Remove all expired connections across every host.
    pub fn cleanup(&self) {
        let now = Instant::now();
        let idle_timeout = self.idle_timeout;

        // Retain only hosts that still have live connections after pruning.
        self.connections.retain(|key, conns| {
            let before = conns.len();
            conns.retain(|c| now.duration_since(c.created_at) <= idle_timeout);
            let removed = before - conns.len();
            if removed > 0 {
                debug!(key = %key, removed, remaining = conns.len(), "Cleaned up expired pooled connections");
            }
            !conns.is_empty()
        });
    }

    /// Total number of idle connections currently held.
    pub fn len(&self) -> usize {
        self.connections.iter().map(|e| e.value().len()).sum()
    }

    /// Whether the pool holds zero idle connections.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of distinct hosts with pooled connections.
    pub fn host_count(&self) -> usize {
        self.connections.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

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

    #[tokio::test]
    async fn get_returns_none_when_disabled() {
        let pool = ConnectionPool::new(&pool_config(false, 10, 60));
        assert!(pool.get("example.com", 80).is_none());
    }

    #[tokio::test]
    async fn get_returns_none_when_empty() {
        let pool = ConnectionPool::new(&pool_config(true, 10, 60));
        assert!(pool.get("example.com", 80).is_none());
        // No misses counter increment when the key has never been pooled.
        assert_eq!(pool.misses.load(Ordering::Relaxed), 0);
    }

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

    #[tokio::test]
    async fn put_respects_max_idle_per_host() {
        let pool = ConnectionPool::new(&pool_config(true, 2, 60));

        let s1 = make_tcp_stream().await;
        let s2 = make_tcp_stream().await;
        let s3 = make_tcp_stream().await;

        pool.put("example.com", 80, s1);
        pool.put("example.com", 80, s2);
        pool.put("example.com", 80, s3); // Should be dropped

        assert_eq!(pool.len(), 2);
    }

    #[tokio::test]
    async fn put_is_noop_when_disabled() {
        let pool = ConnectionPool::new(&pool_config(false, 10, 60));
        let stream = make_tcp_stream().await;
        pool.put("example.com", 80, stream);
        assert!(pool.is_empty());
    }

    #[tokio::test]
    async fn get_discards_expired_connections() {
        // Timeout of 0 seconds means everything expires immediately.
        let pool = ConnectionPool::new(&pool_config(true, 10, 0));
        let stream = make_tcp_stream().await;

        pool.put("example.com", 80, stream);
        // The connection was just inserted but with a 0s timeout it is already expired.
        // Sleep a tiny amount so Instant::now() progresses.
        tokio::time::sleep(Duration::from_millis(5)).await;

        let retrieved = pool.get("example.com", 80);
        assert!(retrieved.is_none());
        assert_eq!(pool.misses.load(Ordering::Relaxed), 1);
        assert!(pool.is_empty());
    }

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

    #[tokio::test]
    async fn cleanup_retains_live_connections() {
        let pool = ConnectionPool::new(&pool_config(true, 10, 300));
        let stream = make_tcp_stream().await;

        pool.put("example.com", 80, stream);
        pool.cleanup();

        assert_eq!(pool.len(), 1);
    }

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

    #[tokio::test]
    async fn lifo_order() {
        let pool = ConnectionPool::new(&pool_config(true, 10, 60));

        let s1 = make_tcp_stream().await;
        let s2 = make_tcp_stream().await;

        // Record the local addresses to identify which stream comes back.
        let addr1 = s1.local_addr().unwrap();
        let addr2 = s2.local_addr().unwrap();

        pool.put("example.com", 80, s1);
        pool.put("example.com", 80, s2);

        // LIFO: second put should come out first.
        let first_out = pool.get("example.com", 80).unwrap();
        assert_eq!(first_out.local_addr().unwrap(), addr2);

        let second_out = pool.get("example.com", 80).unwrap();
        assert_eq!(second_out.local_addr().unwrap(), addr1);
    }
}
