use sks5::socks::protocol::{
    read_connect_request, read_greeting, send_method_selection, send_reply, TargetAddr,
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, CMD_CONNECT, REPLY_COMMAND_NOT_SUPPORTED, REPLY_SUCCESS,
    SOCKS_VERSION,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---------------------------------------------------------------------------
// 1. read_greeting: valid greeting with one auth method
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_read_greeting_valid() {
    let (mut client, mut server) = tokio::io::duplex(1024);

    // Client sends: version=0x05, nmethods=1, methods=[0x02]
    client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    drop(client); // close write side so reads see EOF after payload

    let methods = read_greeting(&mut server).await.unwrap();
    assert_eq!(methods, vec![0x02]);
}

// ---------------------------------------------------------------------------
// 2. read_greeting: bad SOCKS version triggers error
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_read_greeting_bad_version() {
    let (mut client, mut server) = tokio::io::duplex(1024);

    // Version 0x04 is not SOCKS5
    client.write_all(&[0x04, 0x01, 0x00]).await.unwrap();
    drop(client);

    let result = read_greeting(&mut server).await;
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("unsupported SOCKS version"),
        "unexpected error message: {}",
        err_msg
    );
}

// ---------------------------------------------------------------------------
// 3. read_connect_request: valid IPv4 CONNECT
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_read_connect_request_ipv4() {
    let (mut client, mut server) = tokio::io::duplex(1024);

    // CONNECT request: ver=5, cmd=CONNECT(1), rsv=0, atyp=IPv4(1),
    //   ip=192.168.1.100, port=8080 (0x1F90)
    let mut payload = vec![0x05, CMD_CONNECT, 0x00, ATYP_IPV4];
    payload.extend_from_slice(&[192, 168, 1, 100]);
    payload.extend_from_slice(&8080u16.to_be_bytes());
    client.write_all(&payload).await.unwrap();
    drop(client);

    let target = read_connect_request(&mut server).await.unwrap();
    match target {
        TargetAddr::Ipv4(ip, port) => {
            assert_eq!(ip, [192, 168, 1, 100]);
            assert_eq!(port, 8080);
        }
        other => panic!("expected Ipv4, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 4. read_connect_request: valid IPv6 CONNECT
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_read_connect_request_ipv6() {
    let (mut client, mut server) = tokio::io::duplex(1024);

    // IPv6 loopback ::1
    let ipv6_addr: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mut payload = vec![0x05, CMD_CONNECT, 0x00, ATYP_IPV6];
    payload.extend_from_slice(&ipv6_addr);
    payload.extend_from_slice(&443u16.to_be_bytes());
    client.write_all(&payload).await.unwrap();
    drop(client);

    let target = read_connect_request(&mut server).await.unwrap();
    match target {
        TargetAddr::Ipv6(ip, port) => {
            assert_eq!(ip, ipv6_addr);
            assert_eq!(port, 443);
        }
        other => panic!("expected Ipv6, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 5. read_connect_request: valid domain CONNECT
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_read_connect_request_domain() {
    let (mut client, mut server) = tokio::io::duplex(1024);

    let domain = b"example.com";
    let mut payload = vec![0x05, CMD_CONNECT, 0x00, ATYP_DOMAIN];
    payload.push(domain.len() as u8);
    payload.extend_from_slice(domain);
    payload.extend_from_slice(&443u16.to_be_bytes());
    client.write_all(&payload).await.unwrap();
    drop(client);

    let target = read_connect_request(&mut server).await.unwrap();
    match target {
        TargetAddr::Domain(name, port) => {
            assert_eq!(name, "example.com");
            assert_eq!(port, 443);
        }
        other => panic!("expected Domain, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 6. read_connect_request: empty domain (len=0) triggers error
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_read_connect_request_empty_domain() {
    let (mut client, mut server) = tokio::io::duplex(1024);

    // Domain with length 0
    let mut payload = vec![0x05, CMD_CONNECT, 0x00, ATYP_DOMAIN];
    payload.push(0x00); // domain length = 0
                        // Still need port bytes so the read_u8 for length succeeds
    payload.extend_from_slice(&80u16.to_be_bytes());
    client.write_all(&payload).await.unwrap();
    drop(client);

    let result = read_connect_request(&mut server).await;
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("empty domain"),
        "unexpected error message: {}",
        err_msg
    );
}

// ---------------------------------------------------------------------------
// 7. read_connect_request: unsupported command (UDP ASSOCIATE = 0x03)
//    Should send a COMMAND_NOT_SUPPORTED reply AND return an error
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_read_connect_request_unsupported_cmd() {
    let (mut client, mut server) = tokio::io::duplex(1024);

    let cmd_udp_associate: u8 = 0x03;
    // We need enough trailing data so the function can write the error reply
    // before hitting the unsupported command bail.
    // The reply is written to the same stream, but since duplex buffers both
    // directions, the write succeeds.
    let mut payload = vec![0x05, cmd_udp_associate, 0x00, ATYP_IPV4];
    payload.extend_from_slice(&[127, 0, 0, 1]);
    payload.extend_from_slice(&80u16.to_be_bytes());
    client.write_all(&payload).await.unwrap();
    // Do NOT drop client yet -- we need to read the reply that was written back
    client.shutdown().await.unwrap();

    let result = read_connect_request(&mut server).await;
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("unsupported command"),
        "unexpected error message: {}",
        err_msg
    );

    // Verify that the COMMAND_NOT_SUPPORTED reply was written back
    let mut reply_buf = vec![0u8; 64];
    let n = client.read(&mut reply_buf).await.unwrap();
    assert!(n >= 4, "expected at least 4 bytes in reply, got {}", n);
    assert_eq!(reply_buf[0], SOCKS_VERSION);
    assert_eq!(reply_buf[1], REPLY_COMMAND_NOT_SUPPORTED);
    assert_eq!(reply_buf[2], 0x00); // reserved
}

// ---------------------------------------------------------------------------
// 8. send_method_selection: writes correct bytes [0x05, method]
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_send_method_selection_writes_correct_bytes() {
    let (mut client, mut server) = tokio::io::duplex(1024);

    let method: u8 = 0x02; // AUTH_PASSWORD
    send_method_selection(&mut server, method).await.unwrap();
    drop(server); // close write side so client sees EOF

    let mut buf = vec![0u8; 16];
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(n, 2);
    assert_eq!(buf[0], SOCKS_VERSION);
    assert_eq!(buf[1], method);
}

// ---------------------------------------------------------------------------
// 9. send_reply: IPv4 success reply
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_send_reply_ipv4_success() {
    let (mut client, mut server) = tokio::io::duplex(1024);

    let bind_addr = TargetAddr::Ipv4([10, 0, 0, 1], 1080);
    send_reply(&mut server, REPLY_SUCCESS, &bind_addr)
        .await
        .unwrap();
    drop(server);

    let mut buf = vec![0u8; 64];
    let n = client.read(&mut buf).await.unwrap();

    // Expected: [0x05, 0x00, 0x00, 0x01, 10, 0, 0, 1, 0x04, 0x38]
    //   version=5, reply=SUCCESS(0), rsv=0, atyp=IPv4(1), ip, port(1080)
    let expected: Vec<u8> = vec![
        SOCKS_VERSION,
        REPLY_SUCCESS,
        0x00,      // reserved
        ATYP_IPV4, // address type
        10,
        0,
        0,
        1, // IP
        0x04,
        0x38, // port 1080 in big-endian
    ];
    assert_eq!(n, expected.len());
    assert_eq!(&buf[..n], &expected[..]);
}

// ---------------------------------------------------------------------------
// 10. send_reply: domain reply
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_send_reply_domain() {
    let (mut client, mut server) = tokio::io::duplex(1024);

    let bind_addr = TargetAddr::Domain("test.local".to_string(), 9090);
    send_reply(&mut server, REPLY_SUCCESS, &bind_addr)
        .await
        .unwrap();
    drop(server);

    let mut buf = vec![0u8; 128];
    let n = client.read(&mut buf).await.unwrap();

    // Expected layout:
    //   [0x05, 0x00, 0x00]          -- ver, rep, rsv
    //   [0x03]                       -- atyp = DOMAIN
    //   [10]                         -- domain length
    //   [b"test.local"]             -- domain bytes
    //   [0x23, 0x82]                -- port 9090 in big-endian
    let domain_bytes = b"test.local";
    let mut expected: Vec<u8> = vec![SOCKS_VERSION, REPLY_SUCCESS, 0x00, ATYP_DOMAIN];
    expected.push(domain_bytes.len() as u8);
    expected.extend_from_slice(domain_bytes);
    expected.extend_from_slice(&9090u16.to_be_bytes());

    assert_eq!(n, expected.len());
    assert_eq!(&buf[..n], &expected[..]);
}
