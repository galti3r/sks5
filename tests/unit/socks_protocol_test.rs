use sks5::socks::protocol::{
    read_connect_request, read_greeting, read_request, SocksRequest, TargetAddr, UdpHeader,
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, AUTH_NONE, AUTH_PASSWORD, CMD_CONNECT, CMD_UDP_ASSOCIATE,
    REPLY_ADDRESS_TYPE_NOT_SUPPORTED, REPLY_COMMAND_NOT_SUPPORTED, SOCKS_VERSION,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ===========================================================================
// TargetAddr unit tests (existing)
// ===========================================================================

#[test]
fn test_ipv4_target() {
    let addr = TargetAddr::Ipv4([10, 0, 0, 1], 8080);
    assert_eq!(addr.host_string(), "10.0.0.1");
    assert_eq!(addr.port(), 8080);
}

#[test]
fn test_domain_target() {
    let addr = TargetAddr::Domain("example.com".to_string(), 443);
    assert_eq!(addr.host_string(), "example.com");
    assert_eq!(addr.port(), 443);
}

#[test]
fn test_ipv6_target() {
    let addr = TargetAddr::Ipv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 22);
    assert_eq!(addr.port(), 22);
    let host = addr.host_string();
    assert!(host.contains("0001"));
}

// ===========================================================================
// UdpHeader::parse edge cases
// ===========================================================================

#[test]
fn test_udp_header_empty_data() {
    assert!(UdpHeader::parse(&[]).is_err());
}

#[test]
fn test_udp_header_too_short_for_ipv4() {
    // ATYP=IPv4 but not enough bytes for full IP (4 bytes) + port (2 bytes)
    let data = [0x00, 0x00, 0x00, ATYP_IPV4, 192, 168];
    let result = UdpHeader::parse(&data);
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("too short for IPv4"),
        "unexpected error: {}",
        err_msg
    );
}

#[test]
fn test_udp_header_too_short_for_ipv6() {
    // ATYP=IPv6 but only 4 bytes after header (need 16 + 2 = 18)
    let data = [0x00, 0x00, 0x00, ATYP_IPV6, 0, 0, 0, 0];
    let result = UdpHeader::parse(&data);
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("too short for IPv6"),
        "unexpected error: {}",
        err_msg
    );
}

#[test]
fn test_udp_header_unsupported_atyp() {
    // ATYP=0x02 is not a valid SOCKS5 address type
    let data = [0x00, 0x00, 0x00, 0x02];
    let result = UdpHeader::parse(&data);
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("unsupported address type"),
        "unexpected error: {}",
        err_msg
    );
}

#[test]
fn test_udp_header_domain_truncated() {
    // ATYP=domain, domain_len=10, but only 5 bytes of domain data follow
    let data = [
        0x00,
        0x00,
        0x00,
        ATYP_DOMAIN,
        10,
        b'h',
        b'e',
        b'l',
        b'l',
        b'o',
    ];
    let result = UdpHeader::parse(&data);
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("too short for domain"),
        "unexpected error: {}",
        err_msg
    );
}

#[test]
fn test_udp_header_domain_invalid_utf8() {
    // Domain with invalid UTF-8 bytes, followed by a valid port
    let data = [
        0x00,
        0x00,
        0x00,
        ATYP_DOMAIN,
        3,
        0xFF,
        0xFE,
        0xFD,
        0x00,
        0x50,
    ];
    let result = UdpHeader::parse(&data);
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("invalid domain"),
        "unexpected error: {}",
        err_msg
    );
}

#[test]
fn test_udp_header_zero_length_domain() {
    // Domain with length=0, followed by port bytes
    let data = [0x00, 0x00, 0x00, ATYP_DOMAIN, 0, 0x00, 0x50];
    // Zero-length domain: the code reads 0 bytes then a port, so it parses
    // as an empty domain string -- just verify it does not panic
    let result = UdpHeader::parse(&data);
    if let Ok((header, consumed)) = result {
        assert_eq!(header.target.host_string(), "");
        assert_eq!(header.target.port(), 80);
        assert_eq!(consumed, 7);
    }
    // If it errors, that's also acceptable -- just no panic
}

#[test]
fn test_udp_header_ipv4_exact_size() {
    // Exactly the minimum valid IPv4 UDP header: RSV(2) + FRAG(1) + ATYP(1) + IP(4) + PORT(2)
    let data = [0x00, 0x00, 0x00, ATYP_IPV4, 10, 0, 0, 1, 0x00, 0x50];
    let (header, consumed) = UdpHeader::parse(&data).unwrap();
    assert_eq!(consumed, 10);
    assert_eq!(header.frag, 0);
    assert_eq!(header.target.host_string(), "10.0.0.1");
    assert_eq!(header.target.port(), 80);
}

#[test]
fn test_udp_header_ipv6_exact_size() {
    // Exactly the minimum valid IPv6 UDP header: RSV(2) + FRAG(1) + ATYP(1) + IP(16) + PORT(2)
    let mut data = vec![0x00, 0x00, 0x00, ATYP_IPV6];
    data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // ::1
    data.extend_from_slice(&443u16.to_be_bytes());
    let (header, consumed) = UdpHeader::parse(&data).unwrap();
    assert_eq!(consumed, 22);
    assert_eq!(header.target.port(), 443);
}

#[test]
fn test_udp_header_with_trailing_payload() {
    // Valid IPv4 header followed by extra payload bytes -- consumed should only cover the header
    let mut data = vec![0x00, 0x00, 0x00, ATYP_IPV4, 127, 0, 0, 1, 0x1F, 0x90]; // port 8080
    data.extend_from_slice(b"PAYLOAD_DATA_HERE");
    let (header, consumed) = UdpHeader::parse(&data).unwrap();
    assert_eq!(consumed, 10);
    assert_eq!(header.target.host_string(), "127.0.0.1");
    assert_eq!(header.target.port(), 8080);
    assert_eq!(&data[consumed..], b"PAYLOAD_DATA_HERE");
}

#[test]
fn test_udp_header_nonzero_frag() {
    // Non-zero fragment field should be preserved
    let data = [0x00, 0x00, 0x05, ATYP_IPV4, 192, 168, 0, 1, 0x00, 0x50];
    let (header, _) = UdpHeader::parse(&data).unwrap();
    assert_eq!(header.frag, 5);
}

#[test]
fn test_udp_header_atyp_0x00_rejected() {
    // ATYP=0x00 is not valid
    let data = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert!(UdpHeader::parse(&data).is_err());
}

#[test]
fn test_udp_header_atyp_0x05_rejected() {
    // ATYP=0x05 is not valid (only 0x01, 0x03, 0x04 are)
    let data = [0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert!(UdpHeader::parse(&data).is_err());
}

#[test]
fn test_udp_header_three_bytes_only() {
    // Only 3 bytes (need at least 4 for RSV + FRAG + ATYP)
    let data = [0x00, 0x00, 0x00];
    let result = UdpHeader::parse(&data);
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("too short"),
        "unexpected error: {}",
        err_msg
    );
}

#[test]
fn test_udp_header_domain_missing_port() {
    // Domain is complete but port bytes are missing
    let data = [0x00, 0x00, 0x00, ATYP_DOMAIN, 3, b'a', b'b', b'c'];
    let result = UdpHeader::parse(&data);
    assert!(result.is_err());
}

#[test]
fn test_udp_header_ipv4_missing_port() {
    // IPv4 address complete but port bytes are missing
    let data = [0x00, 0x00, 0x00, ATYP_IPV4, 10, 0, 0, 1];
    let result = UdpHeader::parse(&data);
    assert!(result.is_err());
}

// ===========================================================================
// read_greeting tests
// ===========================================================================

#[tokio::test]
async fn test_read_greeting_wrong_version() {
    let data: &[u8] = &[0x04, 0x01, AUTH_PASSWORD]; // SOCKS4 version
    let mut cursor = data;
    let result = read_greeting(&mut cursor).await;
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("unsupported SOCKS version"),
        "unexpected error: {}",
        err_msg
    );
}

#[tokio::test]
async fn test_read_greeting_zero_methods() {
    let data: &[u8] = &[SOCKS_VERSION, 0x00]; // nmethods=0
    let mut cursor = data;
    let result = read_greeting(&mut cursor).await;
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("no authentication methods"),
        "unexpected error: {}",
        err_msg
    );
}

#[tokio::test]
async fn test_read_greeting_valid_single_method() {
    let data: &[u8] = &[SOCKS_VERSION, 0x01, AUTH_PASSWORD];
    let mut cursor = data;
    let result = read_greeting(&mut cursor).await;
    assert!(result.is_ok());
    let methods = result.unwrap();
    assert_eq!(methods, vec![AUTH_PASSWORD]);
}

#[tokio::test]
async fn test_read_greeting_valid_two_methods() {
    let data: &[u8] = &[SOCKS_VERSION, 0x02, AUTH_NONE, AUTH_PASSWORD];
    let mut cursor = data;
    let result = read_greeting(&mut cursor).await;
    assert!(result.is_ok());
    let methods = result.unwrap();
    assert_eq!(methods, vec![AUTH_NONE, AUTH_PASSWORD]);
}

#[tokio::test]
async fn test_read_greeting_version_0x00() {
    // Version byte = 0x00 (not SOCKS5)
    let data: &[u8] = &[0x00, 0x01, AUTH_NONE];
    let mut cursor = data;
    let result = read_greeting(&mut cursor).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_read_greeting_version_0xff() {
    // Version byte = 0xFF
    let data: &[u8] = &[0xFF, 0x01, AUTH_NONE];
    let mut cursor = data;
    let result = read_greeting(&mut cursor).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_read_greeting_empty_stream() {
    // Empty data - should fail with I/O error
    let data: &[u8] = &[];
    let mut cursor = data;
    let result = read_greeting(&mut cursor).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_read_greeting_only_version_byte() {
    // Only version byte, no nmethods
    let data: &[u8] = &[SOCKS_VERSION];
    let mut cursor = data;
    let result = read_greeting(&mut cursor).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_read_greeting_truncated_methods() {
    // Claims 3 methods but only provides 2
    let data: &[u8] = &[SOCKS_VERSION, 0x03, AUTH_NONE, AUTH_PASSWORD];
    let mut cursor = data;
    let result = read_greeting(&mut cursor).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_read_greeting_max_methods() {
    // Maximum nmethods = 255
    let mut data = vec![SOCKS_VERSION, 0xFF];
    data.extend_from_slice(&vec![AUTH_NONE; 255]);
    let mut cursor = data.as_slice();
    let result = read_greeting(&mut cursor).await;
    assert!(result.is_ok());
    let methods = result.unwrap();
    assert_eq!(methods.len(), 255);
}

// ===========================================================================
// read_connect_request tests
// ===========================================================================

#[tokio::test]
async fn test_read_connect_request_wrong_version() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        // Write a SOCKS4 version in the request
        client
            .write_all(&[0x04, CMD_CONNECT, 0x00, ATYP_IPV4, 127, 0, 0, 1, 0x00, 0x50])
            .await
            .unwrap();
        client.shutdown().await.unwrap();
    });
    let result = read_connect_request(&mut server).await;
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("invalid SOCKS version"),
        "unexpected error: {}",
        err_msg
    );
}

#[tokio::test]
async fn test_read_connect_request_empty_domain() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        // CONNECT with empty domain (len=0)
        client
            .write_all(&[0x05, CMD_CONNECT, 0x00, ATYP_DOMAIN, 0x00, 0x00, 0x50])
            .await
            .unwrap();
        client.shutdown().await.unwrap();
    });
    let result = read_connect_request(&mut server).await;
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("empty domain"),
        "unexpected error: {}",
        err_msg
    );
}

#[tokio::test]
async fn test_read_connect_request_valid_ipv4() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        client
            .write_all(&[0x05, CMD_CONNECT, 0x00, ATYP_IPV4, 10, 0, 0, 1, 0x01, 0xBB])
            .await
            .unwrap();
        client.shutdown().await.unwrap();
    });
    let result = read_connect_request(&mut server).await;
    assert!(result.is_ok());
    let addr = result.unwrap();
    assert_eq!(addr.host_string(), "10.0.0.1");
    assert_eq!(addr.port(), 443);
}

#[tokio::test]
async fn test_read_connect_request_valid_domain() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        let domain = b"example.com";
        let mut packet = vec![0x05, CMD_CONNECT, 0x00, ATYP_DOMAIN, domain.len() as u8];
        packet.extend_from_slice(domain);
        packet.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&packet).await.unwrap();
        client.shutdown().await.unwrap();
    });
    let result = read_connect_request(&mut server).await;
    assert!(result.is_ok());
    let addr = result.unwrap();
    assert_eq!(addr.host_string(), "example.com");
    assert_eq!(addr.port(), 443);
}

#[tokio::test]
async fn test_read_connect_request_valid_ipv6() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        let ipv6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut packet = vec![0x05, CMD_CONNECT, 0x00, ATYP_IPV6];
        packet.extend_from_slice(&ipv6);
        packet.extend_from_slice(&8080u16.to_be_bytes());
        client.write_all(&packet).await.unwrap();
        client.shutdown().await.unwrap();
    });
    let result = read_connect_request(&mut server).await;
    assert!(result.is_ok());
    let addr = result.unwrap();
    assert_eq!(addr.port(), 8080);
    match addr {
        TargetAddr::Ipv6(ip, _) => {
            assert_eq!(ip[0], 0x20);
            assert_eq!(ip[1], 0x01);
        }
        other => panic!("expected Ipv6, got {:?}", other),
    }
}

#[tokio::test]
async fn test_read_connect_request_unsupported_atyp() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        // Version=5, CMD=CONNECT, RSV=0, ATYP=0x02 (invalid)
        client
            .write_all(&[0x05, CMD_CONNECT, 0x00, 0x02])
            .await
            .unwrap();
        // Read the error reply that the server sends back
        let mut buf = [0u8; 32];
        let _ = client.read(&mut buf).await;
    });
    let result = read_connect_request(&mut server).await;
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("unsupported address type"),
        "unexpected error: {}",
        err_msg
    );
}

#[tokio::test]
async fn test_read_connect_request_unsupported_cmd_sends_reply() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    let client_handle = tokio::spawn(async move {
        // Send a UDP ASSOCIATE command (not supported by read_connect_request)
        let mut payload = vec![0x05, CMD_UDP_ASSOCIATE, 0x00, ATYP_IPV4];
        payload.extend_from_slice(&[127, 0, 0, 1]);
        payload.extend_from_slice(&80u16.to_be_bytes());
        client.write_all(&payload).await.unwrap();
        client.shutdown().await.unwrap();
        // Read the COMMAND_NOT_SUPPORTED reply
        let mut reply = vec![0u8; 64];
        let n = client.read(&mut reply).await.unwrap();
        reply.truncate(n);
        reply
    });
    let result = read_connect_request(&mut server).await;
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("unsupported command"),
        "unexpected error: {}",
        err_msg
    );
    // Verify the COMMAND_NOT_SUPPORTED reply was sent
    let reply = client_handle.await.unwrap();
    assert!(reply.len() >= 4, "reply too short: {} bytes", reply.len());
    assert_eq!(reply[0], SOCKS_VERSION);
    assert_eq!(reply[1], REPLY_COMMAND_NOT_SUPPORTED);
}

#[tokio::test]
async fn test_read_connect_request_domain_with_long_name() {
    let (mut client, mut server) = tokio::io::duplex(2048);
    tokio::spawn(async move {
        // Create a 253-byte domain name (maximum allowed by RFC 1035)
        // Use labels of 63 chars each (max label length) separated by dots
        // 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253
        let domain = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        );
        let mut packet = vec![0x05, CMD_CONNECT, 0x00, ATYP_DOMAIN, domain.len() as u8];
        packet.extend_from_slice(domain.as_bytes());
        packet.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&packet).await.unwrap();
        client.shutdown().await.unwrap();
    });
    let result = read_connect_request(&mut server).await;
    assert!(result.is_ok());
    let addr = result.unwrap();
    assert_eq!(addr.host_string().len(), 253);
    assert_eq!(addr.port(), 443);
}

#[tokio::test]
async fn test_read_connect_request_port_zero() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        // Port 0 -- valid at the protocol level
        client
            .write_all(&[0x05, CMD_CONNECT, 0x00, ATYP_IPV4, 10, 0, 0, 1, 0x00, 0x00])
            .await
            .unwrap();
        client.shutdown().await.unwrap();
    });
    let result = read_connect_request(&mut server).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().port(), 0);
}

#[tokio::test]
async fn test_read_connect_request_port_max() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        // Port 65535 (maximum)
        client
            .write_all(&[0x05, CMD_CONNECT, 0x00, ATYP_IPV4, 10, 0, 0, 1, 0xFF, 0xFF])
            .await
            .unwrap();
        client.shutdown().await.unwrap();
    });
    let result = read_connect_request(&mut server).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().port(), 65535);
}

// ===========================================================================
// read_request tests (general version: CONNECT + UDP_ASSOCIATE)
// ===========================================================================

#[tokio::test]
async fn test_read_request_connect_ipv4() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        client
            .write_all(&[
                0x05,
                CMD_CONNECT,
                0x00,
                ATYP_IPV4,
                192,
                168,
                0,
                1,
                0x00,
                0x50,
            ])
            .await
            .unwrap();
        client.shutdown().await.unwrap();
    });
    let result = read_request(&mut server).await;
    assert!(result.is_ok());
    match result.unwrap() {
        SocksRequest::Connect(addr) => {
            assert_eq!(addr.host_string(), "192.168.0.1");
            assert_eq!(addr.port(), 80);
        }
        other => panic!("expected Connect, got {:?}", other),
    }
}

#[tokio::test]
async fn test_read_request_connect_domain() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        let domain = b"test.example.org";
        let mut packet = vec![0x05, CMD_CONNECT, 0x00, ATYP_DOMAIN, domain.len() as u8];
        packet.extend_from_slice(domain);
        packet.extend_from_slice(&8443u16.to_be_bytes());
        client.write_all(&packet).await.unwrap();
        client.shutdown().await.unwrap();
    });
    let result = read_request(&mut server).await;
    assert!(result.is_ok());
    match result.unwrap() {
        SocksRequest::Connect(addr) => {
            assert_eq!(addr.host_string(), "test.example.org");
            assert_eq!(addr.port(), 8443);
        }
        other => panic!("expected Connect, got {:?}", other),
    }
}

#[tokio::test]
async fn test_read_request_connect_ipv6() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        let ipv6: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut packet = vec![0x05, CMD_CONNECT, 0x00, ATYP_IPV6];
        packet.extend_from_slice(&ipv6);
        packet.extend_from_slice(&22u16.to_be_bytes());
        client.write_all(&packet).await.unwrap();
        client.shutdown().await.unwrap();
    });
    let result = read_request(&mut server).await;
    assert!(result.is_ok());
    match result.unwrap() {
        SocksRequest::Connect(addr) => {
            assert_eq!(addr.port(), 22);
        }
        other => panic!("expected Connect, got {:?}", other),
    }
}

#[tokio::test]
async fn test_read_request_udp_associate_ipv4() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        client
            .write_all(&[
                0x05,
                CMD_UDP_ASSOCIATE,
                0x00,
                ATYP_IPV4,
                0,
                0,
                0,
                0,
                0x00,
                0x00,
            ])
            .await
            .unwrap();
        client.shutdown().await.unwrap();
    });
    let result = read_request(&mut server).await;
    assert!(result.is_ok());
    match result.unwrap() {
        SocksRequest::UdpAssociate(addr) => {
            assert_eq!(addr.host_string(), "0.0.0.0");
            assert_eq!(addr.port(), 0);
        }
        other => panic!("expected UdpAssociate, got {:?}", other),
    }
}

#[tokio::test]
async fn test_read_request_udp_associate_domain() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        let domain = b"dns.example.com";
        let mut packet = vec![
            0x05,
            CMD_UDP_ASSOCIATE,
            0x00,
            ATYP_DOMAIN,
            domain.len() as u8,
        ];
        packet.extend_from_slice(domain);
        packet.extend_from_slice(&53u16.to_be_bytes());
        client.write_all(&packet).await.unwrap();
        client.shutdown().await.unwrap();
    });
    let result = read_request(&mut server).await;
    assert!(result.is_ok());
    match result.unwrap() {
        SocksRequest::UdpAssociate(addr) => {
            assert_eq!(addr.host_string(), "dns.example.com");
            assert_eq!(addr.port(), 53);
        }
        other => panic!("expected UdpAssociate, got {:?}", other),
    }
}

#[tokio::test]
async fn test_read_request_wrong_version() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        client
            .write_all(&[0x04, CMD_CONNECT, 0x00, ATYP_IPV4, 127, 0, 0, 1, 0x00, 0x50])
            .await
            .unwrap();
        client.shutdown().await.unwrap();
    });
    let result = read_request(&mut server).await;
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("invalid SOCKS version"),
        "unexpected error: {}",
        err_msg
    );
}

#[tokio::test]
async fn test_read_request_unsupported_command() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        // CMD=0x04 is invalid (only 0x01 CONNECT and 0x03 UDP_ASSOCIATE are supported)
        client
            .write_all(&[0x05, 0x04, 0x00, ATYP_IPV4, 127, 0, 0, 1, 0x00, 0x50])
            .await
            .unwrap();
        // Read the COMMAND_NOT_SUPPORTED reply the server sends back
        let mut buf = [0u8; 32];
        let _ = client.read(&mut buf).await;
    });
    let result = read_request(&mut server).await;
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("unsupported command"),
        "unexpected error: {}",
        err_msg
    );
}

#[tokio::test]
async fn test_read_request_unsupported_command_sends_reply() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    let client_handle = tokio::spawn(async move {
        // CMD=0x02 (BIND) is not supported
        let mut payload = vec![0x05, 0x02, 0x00, ATYP_IPV4];
        payload.extend_from_slice(&[10, 0, 0, 1]);
        payload.extend_from_slice(&80u16.to_be_bytes());
        client.write_all(&payload).await.unwrap();
        client.shutdown().await.unwrap();
        // Read the error reply
        let mut reply = vec![0u8; 64];
        let n = client.read(&mut reply).await.unwrap();
        reply.truncate(n);
        reply
    });
    let result = read_request(&mut server).await;
    assert!(result.is_err());
    let reply = client_handle.await.unwrap();
    assert!(reply.len() >= 2, "reply too short: {} bytes", reply.len());
    assert_eq!(reply[0], SOCKS_VERSION);
    assert_eq!(reply[1], REPLY_COMMAND_NOT_SUPPORTED);
}

#[tokio::test]
async fn test_read_request_unsupported_atyp() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    let client_handle = tokio::spawn(async move {
        // Version=5, CMD=CONNECT, RSV=0, ATYP=0x02 (invalid)
        client
            .write_all(&[0x05, CMD_CONNECT, 0x00, 0x02])
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        // Read the ADDRESS_TYPE_NOT_SUPPORTED reply
        let mut reply = vec![0u8; 64];
        let n = client.read(&mut reply).await.unwrap();
        reply.truncate(n);
        reply
    });
    let result = read_request(&mut server).await;
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("unsupported address type"),
        "unexpected error: {}",
        err_msg
    );
    let reply = client_handle.await.unwrap();
    assert!(reply.len() >= 2);
    assert_eq!(reply[0], SOCKS_VERSION);
    assert_eq!(reply[1], REPLY_ADDRESS_TYPE_NOT_SUPPORTED);
}

#[tokio::test]
async fn test_read_request_empty_domain() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        // CONNECT with empty domain (len=0)
        client
            .write_all(&[0x05, CMD_CONNECT, 0x00, ATYP_DOMAIN, 0x00, 0x00, 0x50])
            .await
            .unwrap();
        client.shutdown().await.unwrap();
    });
    let result = read_request(&mut server).await;
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("empty domain"),
        "unexpected error: {}",
        err_msg
    );
}

#[tokio::test]
async fn test_read_request_domain_invalid_utf8() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        // Domain with invalid UTF-8
        let mut packet = vec![0x05, CMD_CONNECT, 0x00, ATYP_DOMAIN, 3];
        packet.extend_from_slice(&[0xFF, 0xFE, 0xFD]); // invalid UTF-8
        packet.extend_from_slice(&80u16.to_be_bytes());
        client.write_all(&packet).await.unwrap();
        client.shutdown().await.unwrap();
    });
    let result = read_request(&mut server).await;
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("invalid domain"),
        "unexpected error: {}",
        err_msg
    );
}

// ===========================================================================
// UdpHeader::serialize + parse roundtrip edge cases
// ===========================================================================

#[test]
fn test_udp_header_serialize_domain_roundtrip() {
    let header = UdpHeader {
        frag: 2,
        target: TargetAddr::Domain("long.subdomain.example.org".to_string(), 9999),
    };
    let bytes = header.serialize();
    let (parsed, consumed) = UdpHeader::parse(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed.frag, 2);
    assert_eq!(parsed.target.host_string(), "long.subdomain.example.org");
    assert_eq!(parsed.target.port(), 9999);
}

#[test]
fn test_udp_header_serialize_ipv4_all_zeros() {
    let header = UdpHeader {
        frag: 0,
        target: TargetAddr::Ipv4([0, 0, 0, 0], 0),
    };
    let bytes = header.serialize();
    let (parsed, consumed) = UdpHeader::parse(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed.target.host_string(), "0.0.0.0");
    assert_eq!(parsed.target.port(), 0);
}

#[test]
fn test_udp_header_serialize_ipv4_broadcast() {
    let header = UdpHeader {
        frag: 0,
        target: TargetAddr::Ipv4([255, 255, 255, 255], 65535),
    };
    let bytes = header.serialize();
    let (parsed, consumed) = UdpHeader::parse(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(parsed.target.host_string(), "255.255.255.255");
    assert_eq!(parsed.target.port(), 65535);
}
