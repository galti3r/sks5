use sks5::socks::handler::extract_totp_from_password;

// -------------------------------------------------------------------------
// Test: delimiter format "password:123456" -> ("password", Some("123456"))
// -------------------------------------------------------------------------
#[test]
fn delimiter_format_basic() {
    let (pass, totp) = extract_totp_from_password("mypassword:123456");
    assert_eq!(pass, "mypassword");
    assert_eq!(totp, Some("123456".to_string()));
}

// -------------------------------------------------------------------------
// Test: delimiter with multiple colons "pass:word:123456"
// -> ("pass:word", Some("123456"))  (rfind splits at last colon)
// -------------------------------------------------------------------------
#[test]
fn delimiter_with_multiple_colons() {
    let (pass, totp) = extract_totp_from_password("pass:word:123456");
    assert_eq!(pass, "pass:word");
    assert_eq!(totp, Some("123456".to_string()));
}

// -------------------------------------------------------------------------
// Test: suffix format "password123456" -> ("password", Some("123456"))
// -------------------------------------------------------------------------
#[test]
fn suffix_format_basic() {
    let (pass, totp) = extract_totp_from_password("password123456");
    assert_eq!(pass, "password");
    assert_eq!(totp, Some("123456".to_string()));
}

// -------------------------------------------------------------------------
// Test: short password (3 chars, no valid TOTP possible)
// -> ("abc", None)  (password too short for suffix, no colon)
// -------------------------------------------------------------------------
#[test]
fn short_password_no_totp() {
    let (pass, totp) = extract_totp_from_password("abc");
    assert_eq!(pass, "abc");
    assert_eq!(totp, None);
}

// -------------------------------------------------------------------------
// Test: only digits "123456" -> no valid extraction possible
// When input is exactly 6 digits: no colon with 6-digit suffix,
// and len <= 6 means suffix extraction skipped => returns full string + None
// -------------------------------------------------------------------------
#[test]
fn only_six_digits() {
    let (pass, totp) = extract_totp_from_password("123456");
    assert_eq!(pass, "123456");
    assert_eq!(totp, None);
}

// -------------------------------------------------------------------------
// Test: empty string -> ("", None)
// -------------------------------------------------------------------------
#[test]
fn empty_string() {
    let (pass, totp) = extract_totp_from_password("");
    assert_eq!(pass, "");
    assert_eq!(totp, None);
}

// -------------------------------------------------------------------------
// Test: colon but TOTP part is not exactly 6 digits
// (e.g., "password:12345" -> falls through to suffix check)
// -------------------------------------------------------------------------
#[test]
fn colon_with_non_six_digit_suffix() {
    // "password:12345" has 5 digits after colon, not 6
    // => delimiter check fails => suffix check: last 6 = "12345" is only 5 chars?
    // Actually "password:12345" is 14 chars, last 6 = ":12345" which has non-digit ':'
    // => returns full string + None
    let (pass, totp) = extract_totp_from_password("password:12345");
    // The rfind(':') finds colon at pos 8, candidate = "12345" (5 chars, not 6) -> skip
    // Suffix: last 6 chars of "password:12345" = ":12345" -> has ':' -> not all digits -> skip
    // Falls through: return full string with no TOTP
    assert_eq!(pass, "password:12345");
    assert_eq!(totp, None);
}

// -------------------------------------------------------------------------
// Test: colon with empty password part ":123456" -> delimiter check
// requires non-empty password, so falls through
// -------------------------------------------------------------------------
#[test]
fn colon_with_empty_password() {
    // rfind(':') finds pos 0, password = "" (empty) -> skip
    // suffix: len=7 > 6, last 6 = "123456" all digits, password part = ":" not empty
    // -> returns (":", Some("123456"))
    let (pass, totp) = extract_totp_from_password(":123456");
    assert_eq!(pass, ":");
    assert_eq!(totp, Some("123456".to_string()));
}

// -------------------------------------------------------------------------
// Test: exactly 7 chars with last 6 digits -> suffix extraction works
// -------------------------------------------------------------------------
#[test]
fn seven_chars_with_six_digit_suffix() {
    let (pass, totp) = extract_totp_from_password("a123456");
    assert_eq!(pass, "a");
    assert_eq!(totp, Some("123456".to_string()));
}

// -------------------------------------------------------------------------
// Test: password with all digits longer than 6
// "1234567890" -> suffix: last 6 = "567890", password = "1234"
// -------------------------------------------------------------------------
#[test]
fn all_digits_longer_than_six() {
    let (pass, totp) = extract_totp_from_password("1234567890");
    assert_eq!(pass, "1234");
    assert_eq!(totp, Some("567890".to_string()));
}

// -------------------------------------------------------------------------
// Test: delimiter takes precedence over suffix
// "mypass123456:654321" -> delimiter finds colon, "654321" is 6 digits
// -> ("mypass123456", Some("654321"))
// -------------------------------------------------------------------------
#[test]
fn delimiter_takes_precedence_over_suffix() {
    let (pass, totp) = extract_totp_from_password("mypass123456:654321");
    assert_eq!(pass, "mypass123456");
    assert_eq!(totp, Some("654321".to_string()));
}

// -------------------------------------------------------------------------
// Test: colon with letters after (not digits) -> suffix fallback
// "password:abcdef" -> colon check: "abcdef" is not all digits -> skip
// suffix: last 6 = "abcdef" not all digits -> skip
// -> returns full string + None
// -------------------------------------------------------------------------
#[test]
fn colon_with_non_digit_suffix() {
    let (pass, totp) = extract_totp_from_password("password:abcdef");
    assert_eq!(pass, "password:abcdef");
    assert_eq!(totp, None);
}

// -------------------------------------------------------------------------
// Test: six digits at end with non-digit prefix
// "hello!world000000" -> suffix: last 6 = "000000" all digits, password = "hello!world"
// -------------------------------------------------------------------------
#[test]
fn special_chars_with_digit_suffix() {
    let (pass, totp) = extract_totp_from_password("hello!world000000");
    assert_eq!(pass, "hello!world");
    assert_eq!(totp, Some("000000".to_string()));
}
