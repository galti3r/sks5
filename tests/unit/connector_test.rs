use sks5::proxy::connector;

#[tokio::test]
async fn connect_invalid_port_fails() {
    // Port 1 is almost certainly not listening on localhost
    // But localhost resolves to 127.0.0.1 which is blocked by ip_guard (anti-SSRF).
    // Use a public IP with an unlikely port instead.
    let result = connector::connect("192.0.2.1", 1, 2, true).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn connect_loopback_blocked() {
    // 127.0.0.1 is a private/loopback IP — ip_guard must block it
    let result = connector::connect("127.0.0.1", 80, 5, true).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("blocked") || err.contains("private") || err.contains("reserved"),
        "expected anti-SSRF error, got: {}",
        err
    );
}

#[tokio::test]
async fn connect_private_10_blocked() {
    // 10.0.0.1 is a private IP — ip_guard must block it
    let result = connector::connect("10.0.0.1", 80, 5, true).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("blocked") || err.contains("private") || err.contains("reserved"),
        "expected anti-SSRF error, got: {}",
        err
    );
}

#[tokio::test]
async fn connect_loopback_allowed_when_guard_disabled() {
    // With ip_guard disabled, loopback should not be blocked (may still fail to connect)
    let result = connector::connect("127.0.0.1", 1, 2, false).await;
    // It should either connect or fail with connection error, NOT with anti-SSRF
    if let Err(e) = &result {
        let err = e.to_string();
        assert!(
            !err.contains("blocked") && !err.contains("private"),
            "ip_guard disabled should not block loopback, got: {}",
            err
        );
    }
}

#[tokio::test]
async fn dns_resolution_timeout() {
    // Use a non-routable address that will cause DNS/connect to time out
    // RFC 5737: 198.51.100.0/24 is "TEST-NET-2" — should not resolve or connect
    let result = connector::connect("198.51.100.1", 80, 1, true).await;
    assert!(result.is_err());
}
