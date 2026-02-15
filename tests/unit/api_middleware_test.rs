use std::time::SystemTime;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use sks5::api::{is_truthy, verify_sse_ticket, ApiResponse};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Build a ticket string from explicit parts, using the same HMAC scheme as the
/// production `create_sse_ticket` implementation.
fn make_ticket(api_token: &str, timestamp: u64) -> String {
    let nonce: u128 = rand::random();
    make_ticket_with_nonce(api_token, timestamp, nonce)
}

fn make_ticket_with_nonce(api_token: &str, timestamp: u64, nonce: u128) -> String {
    let signing_key = format!("sks5-sse-ticket:{}", api_token);
    let mut mac = Hmac::<Sha256>::new_from_slice(signing_key.as_bytes()).unwrap();
    mac.update(format!("{}:{}", timestamp, nonce).as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    format!("{}:{}:{}", timestamp, nonce, sig)
}

// ===========================================================================
// 1. verify_sse_ticket
// ===========================================================================

#[test]
fn verify_sse_ticket_valid_ticket_accepted() {
    let token = "middleware-test-valid";
    let ts = current_timestamp();
    let ticket = make_ticket(token, ts);
    assert!(
        verify_sse_ticket(&ticket, token),
        "a freshly created ticket must be accepted"
    );
}

#[test]
fn verify_sse_ticket_expired_ticket_rejected() {
    let token = "middleware-test-expired";
    // 60 seconds in the past exceeds the 30-second validity window
    let ts = current_timestamp().saturating_sub(60);
    let ticket = make_ticket(token, ts);
    assert!(
        !verify_sse_ticket(&ticket, token),
        "a ticket older than 30 seconds must be rejected"
    );
}

#[test]
fn verify_sse_ticket_invalid_signature_rejected() {
    let token = "middleware-test-badsig";
    let ts = current_timestamp();
    let ticket = make_ticket(token, ts);
    // Replace the signature portion with a bogus hex string of the same length
    let parts: Vec<&str> = ticket.splitn(3, ':').collect();
    let tampered = format!("{}:{}:{}", parts[0], parts[1], "ff".repeat(32));
    assert!(
        !verify_sse_ticket(&tampered, token),
        "a ticket with a wrong signature must be rejected"
    );
}

#[test]
fn verify_sse_ticket_malformed_one_part() {
    assert!(
        !verify_sse_ticket("onlyone", "tok"),
        "a ticket with no colons must be rejected"
    );
}

#[test]
fn verify_sse_ticket_malformed_two_parts() {
    assert!(
        !verify_sse_ticket("123:456", "tok"),
        "a ticket with only two parts must be rejected"
    );
}

#[test]
fn verify_sse_ticket_empty_ticket() {
    assert!(
        !verify_sse_ticket("", "tok"),
        "an empty ticket string must be rejected"
    );
}

#[test]
fn verify_sse_ticket_invalid_timestamp_non_numeric() {
    assert!(
        !verify_sse_ticket("notanumber:123:abcdef", "tok"),
        "a ticket with a non-numeric timestamp must be rejected"
    );
}

#[test]
fn verify_sse_ticket_invalid_nonce_non_numeric() {
    let ts = current_timestamp();
    let bad_ticket = format!("{}:not_a_nonce:abcdef1234", ts);
    assert!(
        !verify_sse_ticket(&bad_ticket, "tok"),
        "a ticket with a non-numeric nonce must be rejected"
    );
}

#[test]
fn verify_sse_ticket_replay_protection_second_use_rejected() {
    let token = "middleware-replay-check";
    let ts = current_timestamp();
    let nonce: u128 = rand::random();
    let ticket = make_ticket_with_nonce(token, ts, nonce);

    assert!(
        verify_sse_ticket(&ticket, token),
        "first use of the ticket must succeed"
    );
    assert!(
        !verify_sse_ticket(&ticket, token),
        "second use of the same ticket must fail (replay protection)"
    );
}

// ===========================================================================
// 2. is_truthy
// ===========================================================================

#[test]
fn is_truthy_some_true_returns_true() {
    assert!(is_truthy(Some("true")));
}

#[test]
fn is_truthy_some_one_returns_true() {
    assert!(is_truthy(Some("1")));
}

#[test]
fn is_truthy_some_yes_returns_true() {
    assert!(is_truthy(Some("yes")));
}

#[test]
fn is_truthy_some_false_returns_false() {
    assert!(!is_truthy(Some("false")));
}

#[test]
fn is_truthy_some_zero_returns_false() {
    assert!(!is_truthy(Some("0")));
}

#[test]
fn is_truthy_some_random_string_returns_false() {
    assert!(!is_truthy(Some("random")));
}

#[test]
fn is_truthy_none_returns_false() {
    assert!(!is_truthy(None));
}

// ===========================================================================
// 3. ApiResponse serialization
// ===========================================================================

#[test]
fn api_response_ok_serializes_correctly() {
    let (status, json) = ApiResponse::ok("hello world");
    assert_eq!(status, axum::http::StatusCode::OK);

    let value = serde_json::to_value(&json.0).unwrap();
    assert_eq!(value["success"], true);
    assert_eq!(value["data"], "hello world");
    // `error` should be absent (skip_serializing_if = "Option::is_none")
    assert!(
        value.get("error").is_none(),
        "error field must be absent on success"
    );
}

#[test]
fn api_response_err_serializes_correctly() {
    let (status, json) = ApiResponse::<()>::err(axum::http::StatusCode::FORBIDDEN, "access denied");
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);

    let value = serde_json::to_value(&json.0).unwrap();
    assert_eq!(value["success"], false);
    assert_eq!(value["error"], "access denied");
    // `data` should be absent (skip_serializing_if = "Option::is_none")
    assert!(
        value.get("data").is_none(),
        "data field must be absent on error"
    );
}
