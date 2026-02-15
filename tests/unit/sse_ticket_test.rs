use hmac::{Hmac, Mac};
use sha2::Sha256;

fn make_ticket(api_token: &str, timestamp: u64) -> String {
    let nonce: u128 = rand::random();
    let signing_key = format!("sks5-sse-ticket:{}", api_token);
    let mut mac = Hmac::<Sha256>::new_from_slice(signing_key.as_bytes()).unwrap();
    mac.update(format!("{}:{}", timestamp, nonce).as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    format!("{}:{}:{}", timestamp, nonce, sig)
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn valid_ticket_accepted() {
    let token = "my-secret-token";
    let ts = current_timestamp();
    let ticket = make_ticket(token, ts);
    assert!(sks5::api::verify_sse_ticket(&ticket, token));
}

#[test]
fn expired_ticket_rejected() {
    let token = "my-secret-token";
    // 60 seconds in the past exceeds the 30-second validity window
    let ts = current_timestamp() - 60;
    let ticket = make_ticket(token, ts);
    assert!(!sks5::api::verify_sse_ticket(&ticket, token));
}

#[test]
fn tampered_signature_rejected() {
    let token = "my-secret-token";
    let ts = current_timestamp();
    // Build a valid ticket then corrupt the HMAC
    let ticket = make_ticket(token, ts);
    let parts: Vec<&str> = ticket.splitn(3, ':').collect();
    let tampered = format!("{}:{}:{}", parts[0], parts[1], "00".repeat(32));
    assert!(!sks5::api::verify_sse_ticket(&tampered, token));
}

#[test]
fn wrong_api_token_rejected() {
    let ts = current_timestamp();
    let ticket = make_ticket("aaa", ts);
    assert!(!sks5::api::verify_sse_ticket(&ticket, "bbb"));
}

#[test]
fn malformed_ticket_no_colon() {
    assert!(!sks5::api::verify_sse_ticket("notavalidticket", "token"));
}

#[test]
fn malformed_ticket_bad_timestamp() {
    assert!(!sks5::api::verify_sse_ticket("abc:123:hexhex", "token"));
}

#[test]
fn empty_ticket_rejected() {
    assert!(!sks5::api::verify_sse_ticket("", "token"));
}

#[test]
fn empty_token_ticket() {
    let ts = current_timestamp();
    let ticket = make_ticket("", ts);
    assert!(sks5::api::verify_sse_ticket(&ticket, ""));
}
