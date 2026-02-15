use russh::keys::{Algorithm, PrivateKey, PublicKey, PublicKeyBase64};
use sks5::auth::pubkey;

/// Helper: generate a key pair and produce an authorized_keys line for it.
fn gen_authorized_keys_line() -> (PrivateKey, PublicKey, String) {
    let kp = PrivateKey::random(&mut rand::rngs::OsRng, Algorithm::Ed25519).unwrap();
    let pubkey = PublicKey::from(&kp);
    let b64 = pubkey.public_key_base64();
    let line = format!("ssh-ed25519 {b64} test@test");
    (kp, pubkey, line)
}

#[test]
fn parse_valid_ed25519_key() {
    let (_kp, expected_pubkey, line) = gen_authorized_keys_line();
    let parsed = pubkey::parse_authorized_key(&line).expect("should parse a valid ed25519 key");
    assert_eq!(
        parsed, expected_pubkey,
        "parsed key must equal the original public key"
    );
}

#[test]
fn parse_invalid_key_returns_error() {
    let result = pubkey::parse_authorized_key("not-a-valid-key-line");
    assert!(
        result.is_err(),
        "single token line should fail (missing base64 field)"
    );

    let result2 = pubkey::parse_authorized_key("ssh-ed25519 !!!invalid_base64!!! comment");
    assert!(result2.is_err(), "invalid base64 should fail to parse");
}

#[test]
fn key_matches_valid() {
    let (_kp, pubkey, line) = gen_authorized_keys_line();
    let authorized: Vec<String> = vec![line];
    assert!(
        pubkey::key_matches(&pubkey, &authorized),
        "a key should match its own authorized_keys line"
    );
}

#[test]
fn key_matches_different_key() {
    let (_kp1, pubkey1, _line1) = gen_authorized_keys_line();
    let (_kp2, _pubkey2, line2) = gen_authorized_keys_line();
    let authorized: Vec<String> = vec![line2];
    assert!(
        !pubkey::key_matches(&pubkey1, &authorized),
        "a key must not match a different key's authorized_keys entry"
    );
}

#[test]
fn parse_authorized_keys_skips_invalid() {
    let (_kp, _pubkey, valid_line) = gen_authorized_keys_line();
    let lines = vec![
        "garbage-line-without-base64".to_string(),
        valid_line,
        "ssh-ed25519 !!!bad!!! comment".to_string(),
    ];
    let parsed = pubkey::parse_authorized_keys(&lines);
    assert_eq!(
        parsed.len(),
        1,
        "only the valid key should be parsed; invalid ones are skipped"
    );
}

#[test]
fn key_matches_empty_list() {
    let (_kp, pubkey, _line) = gen_authorized_keys_line();
    let empty: Vec<String> = vec![];
    assert!(
        !pubkey::key_matches(&pubkey, &empty),
        "no key should match an empty authorized_keys list"
    );
}

#[test]
fn key_matches_parsed_with_multiple_keys() {
    let (_kp1, pubkey1, _line1) = gen_authorized_keys_line();
    let (_kp2, pubkey2, _line2) = gen_authorized_keys_line();
    let (_kp3, pubkey3, _line3) = gen_authorized_keys_line();

    let authorized = vec![pubkey1.clone(), pubkey2.clone()];

    assert!(
        pubkey::key_matches_parsed(&pubkey1, &authorized),
        "first key should match"
    );
    assert!(
        pubkey::key_matches_parsed(&pubkey2, &authorized),
        "second key should match"
    );
    assert!(
        !pubkey::key_matches_parsed(&pubkey3, &authorized),
        "third key should not match"
    );
}
