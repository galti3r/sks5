use sks5::shell::parser::tokenize;

#[test]
fn test_complex_quoting() {
    assert_eq!(
        tokenize(r#"echo "hello 'world'" more"#),
        vec!["echo", "hello 'world'", "more"]
    );
}

#[test]
fn test_mixed_quotes() {
    assert_eq!(
        tokenize(r#"echo "a b" 'c d' e"#),
        vec!["echo", "a b", "c d", "e"]
    );
}

#[test]
fn test_escaped_quote() {
    assert_eq!(
        tokenize(r#"echo hello\"world"#),
        vec!["echo", r#"hello"world"#]
    );
}
