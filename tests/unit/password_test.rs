use sks5::auth::password;

#[test]
fn test_password_hash_verify_cycle() {
    let pass = "my-secure-password-123!";
    let hash = password::hash_password(pass).unwrap();
    assert!(password::verify_password(pass, &hash));
    assert!(!password::verify_password("wrong-password", &hash));
}

#[test]
fn test_empty_password() {
    // Argon2 should still work with empty strings
    let hash = password::hash_password("").unwrap();
    assert!(password::verify_password("", &hash));
    assert!(!password::verify_password("notempty", &hash));
}

#[test]
fn test_unicode_password() {
    let pass = "p@ssw0rd-avec-des-accents-\u{00e9}\u{00e8}\u{00ea}";
    let hash = password::hash_password(pass).unwrap();
    assert!(password::verify_password(pass, &hash));
}

#[test]
fn test_long_password() {
    let pass = "a".repeat(1000);
    let hash = password::hash_password(&pass).unwrap();
    assert!(password::verify_password(&pass, &hash));
}
