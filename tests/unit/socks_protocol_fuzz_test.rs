use proptest::prelude::*;

/// Helper: build a valid SOCKS5 greeting from a list of auth methods
fn build_greeting(methods: &[u8]) -> Vec<u8> {
    let mut buf = vec![0x05, methods.len() as u8];
    buf.extend_from_slice(methods);
    buf
}

/// Helper: build a SOCKS5 CONNECT request with domain target
fn build_connect_domain(domain: &str, port: u16) -> Vec<u8> {
    let mut buf = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
    buf.extend_from_slice(domain.as_bytes());
    buf.extend_from_slice(&port.to_be_bytes());
    buf
}

/// Helper: build a SOCKS5 CONNECT request with IPv4 target
fn build_connect_ipv4(ip: [u8; 4], port: u16) -> Vec<u8> {
    let mut buf = vec![0x05, 0x01, 0x00, 0x01];
    buf.extend_from_slice(&ip);
    buf.extend_from_slice(&port.to_be_bytes());
    buf
}

/// Create a multi-threaded tokio runtime for tests that need tokio::spawn
fn make_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Create a single-threaded tokio runtime for simple async tests
fn make_rt_current() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn greeting_random_bytes_never_panics(data in proptest::collection::vec(any::<u8>(), 0..256)) {
        let rt = make_rt_current();
        rt.block_on(async {
            let mut cursor = &data[..];
            let _ = sks5::socks::protocol::read_greeting(&mut cursor).await;
        });
    }

    #[test]
    fn valid_greeting_parses_correctly(
        methods in proptest::collection::vec(0u8..=255, 1..10)
    ) {
        let rt = make_rt_current();
        rt.block_on(async {
            let data = build_greeting(&methods);
            let mut cursor = &data[..];
            let result = sks5::socks::protocol::read_greeting(&mut cursor).await;
            if let Ok(parsed) = result {
                assert_eq!(parsed, methods);
            }
        });
    }

    #[test]
    fn connect_request_random_bytes_never_panics(data in proptest::collection::vec(any::<u8>(), 4..512)) {
        let rt = make_rt();
        rt.block_on(async {
            let (mut client, mut server) = tokio::io::duplex(8192);
            use tokio::io::AsyncWriteExt;
            let data_clone = data.clone();
            tokio::spawn(async move {
                let _ = server.write_all(&data_clone).await;
                let _ = server.shutdown().await;
            });
            let _ = sks5::socks::protocol::read_connect_request(&mut client).await;
        });
    }

    #[test]
    fn valid_domain_connect_parses(
        domain in "[a-z]{1,63}(\\.[a-z]{1,63}){0,3}",
        port in 1u16..=65535
    ) {
        let rt = make_rt();
        rt.block_on(async {
            let (mut client, mut server) = tokio::io::duplex(8192);
            use tokio::io::AsyncWriteExt;
            let data = build_connect_domain(&domain, port);
            tokio::spawn(async move {
                let _ = server.write_all(&data).await;
                let _ = server.shutdown().await;
            });
            let result = sks5::socks::protocol::read_connect_request(&mut client).await;
            match result {
                Ok(target) => {
                    assert_eq!(target.host_string(), domain);
                    assert_eq!(target.port(), port);
                }
                Err(e) => panic!("valid domain should parse: {}", e),
            }
        });
    }

    #[test]
    fn valid_ipv4_connect_parses(
        ip in any::<[u8; 4]>(),
        port in 1u16..=65535
    ) {
        let rt = make_rt();
        rt.block_on(async {
            let (mut client, mut server) = tokio::io::duplex(8192);
            use tokio::io::AsyncWriteExt;
            let data = build_connect_ipv4(ip, port);
            tokio::spawn(async move {
                let _ = server.write_all(&data).await;
                let _ = server.shutdown().await;
            });
            let result = sks5::socks::protocol::read_connect_request(&mut client).await;
            match result {
                Ok(target) => {
                    assert_eq!(target.port(), port);
                }
                Err(e) => panic!("valid ipv4 should parse: {}", e),
            }
        });
    }

    #[test]
    fn wrong_socks_version_rejected(ver in 0u8..=255) {
        prop_assume!(ver != 0x05);
        let rt = make_rt_current();
        rt.block_on(async {
            let data = [ver, 0x01, 0x02];
            let mut cursor = &data[..];
            let result = sks5::socks::protocol::read_greeting(&mut cursor).await;
            assert!(result.is_err());
        });
    }
}
