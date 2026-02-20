//! Integration tests for upstream SOCKS5 proxy chaining.
//!
//! Uses a mock SOCKS5 server to test `connect_via_socks5()` without requiring
//! an external SOCKS5 proxy.

use sks5::config::types::ParsedUpstreamProxy;
use sks5::proxy::connector::connect_via_socks5;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Spawn a minimal mock SOCKS5 server that accepts connections and
/// performs the handshake. Returns the bound address.
async fn spawn_mock_socks5_server(require_auth: bool) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };

            let require_auth = require_auth;
            tokio::spawn(async move {
                // Read greeting: VER + NMETHODS + METHODS
                let mut buf = [0u8; 2];
                if stream.read_exact(&mut buf).await.is_err() {
                    return;
                }
                let _ver = buf[0];
                let nmethods = buf[1] as usize;
                let mut methods = vec![0u8; nmethods];
                if stream.read_exact(&mut methods).await.is_err() {
                    return;
                }

                if require_auth {
                    // Select AUTH_PASSWORD (0x02)
                    let _ = stream.write_all(&[0x05, 0x02]).await;

                    // Read auth: VER(1) + ULEN(1) + UNAME + PLEN(1) + PASSWD
                    let mut auth_ver = [0u8; 1];
                    if stream.read_exact(&mut auth_ver).await.is_err() {
                        return;
                    }
                    let mut ulen = [0u8; 1];
                    if stream.read_exact(&mut ulen).await.is_err() {
                        return;
                    }
                    let mut uname = vec![0u8; ulen[0] as usize];
                    if stream.read_exact(&mut uname).await.is_err() {
                        return;
                    }
                    let mut plen = [0u8; 1];
                    if stream.read_exact(&mut plen).await.is_err() {
                        return;
                    }
                    let mut passwd = vec![0u8; plen[0] as usize];
                    if stream.read_exact(&mut passwd).await.is_err() {
                        return;
                    }

                    // Check credentials
                    let username = String::from_utf8_lossy(&uname);
                    let password = String::from_utf8_lossy(&passwd);
                    if username == "proxyuser" && password == "proxypass" {
                        let _ = stream.write_all(&[0x01, 0x00]).await; // success
                    } else {
                        let _ = stream.write_all(&[0x01, 0x01]).await; // failure
                        return;
                    }
                } else {
                    // Select AUTH_NONE (0x00)
                    let _ = stream.write_all(&[0x05, 0x00]).await;
                }

                // Read CONNECT request: VER(1) + CMD(1) + RSV(1) + ATYP(1) + ADDR + PORT
                let mut header = [0u8; 4];
                if stream.read_exact(&mut header).await.is_err() {
                    return;
                }

                let atyp = header[3];
                let (_target_host, _target_port) = match atyp {
                    0x03 => {
                        // Domain
                        let mut len = [0u8; 1];
                        if stream.read_exact(&mut len).await.is_err() {
                            return;
                        }
                        let mut domain = vec![0u8; len[0] as usize];
                        if stream.read_exact(&mut domain).await.is_err() {
                            return;
                        }
                        let mut port_buf = [0u8; 2];
                        if stream.read_exact(&mut port_buf).await.is_err() {
                            return;
                        }
                        let port = u16::from_be_bytes(port_buf);
                        (String::from_utf8_lossy(&domain).to_string(), port)
                    }
                    0x01 => {
                        // IPv4
                        let mut ip = [0u8; 4];
                        if stream.read_exact(&mut ip).await.is_err() {
                            return;
                        }
                        let mut port_buf = [0u8; 2];
                        if stream.read_exact(&mut port_buf).await.is_err() {
                            return;
                        }
                        let port = u16::from_be_bytes(port_buf);
                        (format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]), port)
                    }
                    _ => return,
                };

                // Send success reply with bind address 0.0.0.0:0
                let reply = [
                    0x05, 0x00, 0x00, // VER, REP=success, RSV
                    0x01, // ATYP=IPv4
                    0x00, 0x00, 0x00, 0x00, // BND.ADDR
                    0x00, 0x00, // BND.PORT
                ];
                let _ = stream.write_all(&reply).await;

                // Echo data back (simple echo server)
                let mut buf = [0u8; 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    addr
}

/// Spawn a mock SOCKS5 server that rejects authentication
async fn spawn_mock_socks5_auth_reject() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            // Read greeting
            let mut buf = [0u8; 2];
            let _ = stream.read_exact(&mut buf).await;
            let nmethods = buf[1] as usize;
            let mut methods = vec![0u8; nmethods];
            let _ = stream.read_exact(&mut methods).await;

            // Reject all methods
            let _ = stream.write_all(&[0x05, 0xFF]).await;
        }
    });

    addr
}

/// Spawn a mock SOCKS5 server that returns a CONNECT failure
async fn spawn_mock_socks5_connect_fail() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            // Read greeting
            let mut buf = [0u8; 2];
            let _ = stream.read_exact(&mut buf).await;
            let nmethods = buf[1] as usize;
            let mut methods = vec![0u8; nmethods];
            let _ = stream.read_exact(&mut methods).await;

            // Select no auth
            let _ = stream.write_all(&[0x05, 0x00]).await;

            // Read CONNECT request (consume all of it)
            let mut header = [0u8; 4];
            let _ = stream.read_exact(&mut header).await;
            let atyp = header[3];
            match atyp {
                0x03 => {
                    let mut len = [0u8; 1];
                    let _ = stream.read_exact(&mut len).await;
                    let mut domain = vec![0u8; len[0] as usize + 2];
                    let _ = stream.read_exact(&mut domain).await;
                }
                0x01 => {
                    let mut skip = [0u8; 6];
                    let _ = stream.read_exact(&mut skip).await;
                }
                _ => {}
            }

            // Send failure reply (0x05 = connection refused)
            let reply = [0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            let _ = stream.write_all(&reply).await;
        }
    });

    addr
}

#[tokio::test]
async fn test_connect_via_socks5_no_auth() {
    let mock_addr = spawn_mock_socks5_server(false).await;

    let proxy = ParsedUpstreamProxy {
        host: "127.0.0.1".to_string(),
        port: mock_addr.port(),
        username: None,
        password: None,
    };

    let mut stream = connect_via_socks5(&proxy, "example.com", 80, Duration::from_secs(5))
        .await
        .expect("should connect via proxy");

    // Test that the tunnel works (mock echoes data back)
    stream.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");
}

#[tokio::test]
async fn test_connect_via_socks5_with_auth() {
    let mock_addr = spawn_mock_socks5_server(true).await;

    let proxy = ParsedUpstreamProxy {
        host: "127.0.0.1".to_string(),
        port: mock_addr.port(),
        username: Some("proxyuser".to_string()),
        password: Some(zeroize::Zeroizing::new("proxypass".to_string())),
    };

    let mut stream = connect_via_socks5(&proxy, "target.example.com", 443, Duration::from_secs(5))
        .await
        .expect("should connect via proxy with auth");

    // Verify tunnel works
    stream.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}

#[tokio::test]
async fn test_connect_via_socks5_auth_rejected() {
    let mock_addr = spawn_mock_socks5_auth_reject().await;

    let proxy = ParsedUpstreamProxy {
        host: "127.0.0.1".to_string(),
        port: mock_addr.port(),
        username: None,
        password: None,
    };

    let result = connect_via_socks5(&proxy, "example.com", 80, Duration::from_secs(5)).await;

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("rejected all authentication methods"),
        "expected auth rejection error, got: {}",
        err
    );
}

#[tokio::test]
async fn test_connect_via_socks5_connect_failure() {
    let mock_addr = spawn_mock_socks5_connect_fail().await;

    let proxy = ParsedUpstreamProxy {
        host: "127.0.0.1".to_string(),
        port: mock_addr.port(),
        username: None,
        password: None,
    };

    let result = connect_via_socks5(&proxy, "example.com", 80, Duration::from_secs(5)).await;

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("CONNECT failed with reply code 0x05"),
        "expected CONNECT failure, got: {}",
        err
    );
}

#[tokio::test]
async fn test_connect_via_socks5_wrong_auth_credentials() {
    let mock_addr = spawn_mock_socks5_server(true).await;

    let proxy = ParsedUpstreamProxy {
        host: "127.0.0.1".to_string(),
        port: mock_addr.port(),
        username: Some("wronguser".to_string()),
        password: Some(zeroize::Zeroizing::new("wrongpass".to_string())),
    };

    let result = connect_via_socks5(&proxy, "example.com", 80, Duration::from_secs(5)).await;

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("authentication failed"),
        "expected auth failure, got: {}",
        err
    );
}

#[tokio::test]
async fn test_connect_via_socks5_timeout() {
    // Connect to a non-existent address to trigger timeout
    let proxy = ParsedUpstreamProxy {
        host: "192.0.2.1".to_string(), // TEST-NET-1, guaranteed non-routable
        port: 1,
        username: None,
        password: None,
    };

    let result = connect_via_socks5(&proxy, "example.com", 80, Duration::from_secs(1)).await;

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("timeout") || err.contains("failed to connect"),
        "expected timeout or connect error, got: {}",
        err
    );
}
