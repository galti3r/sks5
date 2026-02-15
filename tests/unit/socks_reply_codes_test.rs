use sks5::socks::protocol;

#[test]
fn reply_constants_match_rfc1928() {
    assert_eq!(protocol::REPLY_SUCCESS, 0x00);
    assert_eq!(protocol::REPLY_GENERAL_FAILURE, 0x01);
    assert_eq!(protocol::REPLY_NOT_ALLOWED, 0x02);
    assert_eq!(protocol::REPLY_HOST_UNREACHABLE, 0x04);
    assert_eq!(protocol::REPLY_CONNECTION_REFUSED, 0x05);
    assert_eq!(protocol::REPLY_COMMAND_NOT_SUPPORTED, 0x07);
    assert_eq!(protocol::REPLY_ADDRESS_TYPE_NOT_SUPPORTED, 0x08);
}

#[test]
fn socks_version_constant() {
    assert_eq!(protocol::SOCKS_VERSION, 0x05);
}

#[test]
fn auth_method_constants() {
    assert_eq!(protocol::AUTH_PASSWORD, 0x02);
    assert_eq!(protocol::AUTH_NO_ACCEPTABLE, 0xFF);
}

#[tokio::test]
async fn send_reply_success_format() {
    let mut buf = Vec::new();
    let addr = protocol::TargetAddr::Ipv4([127, 0, 0, 1], 8080);
    protocol::send_reply(&mut buf, protocol::REPLY_SUCCESS, &addr)
        .await
        .unwrap();

    // VER=5, REP=0, RSV=0, ATYP=1 (IPv4), IP, PORT
    assert_eq!(buf[0], 0x05); // version
    assert_eq!(buf[1], 0x00); // success
    assert_eq!(buf[2], 0x00); // reserved
    assert_eq!(buf[3], 0x01); // IPv4
    assert_eq!(&buf[4..8], &[127, 0, 0, 1]); // IP
    assert_eq!(&buf[8..10], &8080u16.to_be_bytes()); // port
}

#[tokio::test]
async fn send_reply_not_allowed_format() {
    let mut buf = Vec::new();
    let addr = protocol::TargetAddr::Ipv4([0; 4], 0);
    protocol::send_reply(&mut buf, protocol::REPLY_NOT_ALLOWED, &addr)
        .await
        .unwrap();

    assert_eq!(buf[1], 0x02); // NOT_ALLOWED
}

#[tokio::test]
async fn send_reply_connection_refused_format() {
    let mut buf = Vec::new();
    let addr = protocol::TargetAddr::Ipv4([0; 4], 0);
    protocol::send_reply(&mut buf, protocol::REPLY_CONNECTION_REFUSED, &addr)
        .await
        .unwrap();

    assert_eq!(buf[1], 0x05); // CONNECTION_REFUSED
}

#[tokio::test]
async fn send_reply_domain_format() {
    let mut buf = Vec::new();
    let addr = protocol::TargetAddr::Domain("example.com".to_string(), 443);
    protocol::send_reply(&mut buf, protocol::REPLY_SUCCESS, &addr)
        .await
        .unwrap();

    assert_eq!(buf[3], 0x03); // domain
    assert_eq!(buf[4], 11); // "example.com".len()
    assert_eq!(&buf[5..16], b"example.com");
}

#[tokio::test]
async fn send_reply_ipv6_format() {
    let mut buf = Vec::new();
    let addr = protocol::TargetAddr::Ipv6([0; 16], 80);
    protocol::send_reply(&mut buf, protocol::REPLY_SUCCESS, &addr)
        .await
        .unwrap();

    assert_eq!(buf[3], 0x04); // IPv6
    assert_eq!(buf.len(), 4 + 16 + 2); // header + ipv6 + port
}
