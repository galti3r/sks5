use sks5::socks::auth::{
    read_credentials, send_auth_result, AUTH_FAILURE, AUTH_SUCCESS, SUBNEG_VERSION,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn read_credentials_valid() {
    let (mut client, mut server) = tokio::io::duplex(1024);

    // RFC 1929: [version=0x01, ulen=5, "alice", plen=4, "pass"]
    let payload: Vec<u8> = vec![
        SUBNEG_VERSION,
        5,
        b'a',
        b'l',
        b'i',
        b'c',
        b'e',
        4,
        b'p',
        b'a',
        b's',
        b's',
    ];

    tokio::spawn(async move {
        client.write_all(&payload).await.unwrap();
        client.shutdown().await.unwrap();
    });

    let creds = read_credentials(&mut server)
        .await
        .expect("should parse valid credentials");
    assert_eq!(creds.username, "alice");
    assert_eq!(&*creds.password, "pass");
}

#[tokio::test]
async fn read_credentials_bad_version() {
    let (mut client, mut server) = tokio::io::duplex(1024);

    // Send wrong version byte (0x02 instead of 0x01)
    let payload: Vec<u8> = vec![
        0x02, 5, b'a', b'l', b'i', b'c', b'e', 4, b'p', b'a', b's', b's',
    ];

    tokio::spawn(async move {
        client.write_all(&payload).await.unwrap();
        client.shutdown().await.unwrap();
    });

    let result = read_credentials(&mut server).await;
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("should reject unsupported subneg version"),
    };
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("unsupported subneg version"),
        "error should mention unsupported version, got: {}",
        err_msg
    );
}

#[tokio::test]
async fn send_auth_result_success() {
    let (mut client, mut server) = tokio::io::duplex(1024);

    tokio::spawn(async move {
        send_auth_result(&mut server, true).await.unwrap();
        server.shutdown().await.unwrap();
    });

    let mut buf = [0u8; 2];
    client
        .read_exact(&mut buf)
        .await
        .expect("should read 2-byte response");
    assert_eq!(
        buf[0], SUBNEG_VERSION,
        "first byte should be subneg version"
    );
    assert_eq!(
        buf[1], AUTH_SUCCESS,
        "second byte should be AUTH_SUCCESS (0x00)"
    );
}

#[tokio::test]
async fn send_auth_result_failure() {
    let (mut client, mut server) = tokio::io::duplex(1024);

    tokio::spawn(async move {
        send_auth_result(&mut server, false).await.unwrap();
        server.shutdown().await.unwrap();
    });

    let mut buf = [0u8; 2];
    client
        .read_exact(&mut buf)
        .await
        .expect("should read 2-byte response");
    assert_eq!(
        buf[0], SUBNEG_VERSION,
        "first byte should be subneg version"
    );
    assert_eq!(
        buf[1], AUTH_FAILURE,
        "second byte should be AUTH_FAILURE (0x01)"
    );
}
