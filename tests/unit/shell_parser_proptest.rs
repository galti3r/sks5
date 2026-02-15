use proptest::prelude::*;
use sks5::shell::parser::tokenize;

proptest! {
    #[test]
    fn tokenize_never_panics(s in "\\PC{0,200}") {
        // tokenize should handle any input without panicking
        let _ = tokenize(&s);
    }

    #[test]
    fn tokenize_empty_input_produces_no_tokens(s in "[ \\t\\n]*") {
        // Pure whitespace should produce no tokens
        let tokens = tokenize(&s);
        prop_assert!(tokens.is_empty(), "whitespace-only input should produce empty tokens, got {:?}", tokens);
    }

    #[test]
    fn tokenize_simple_words(words in prop::collection::vec("[a-zA-Z0-9_-]{1,20}", 1..10)) {
        let input = words.join(" ");
        let tokens = tokenize(&input);
        // Each word should become a token when separated by single spaces
        prop_assert_eq!(
            tokens.len(),
            words.len(),
            "input '{}' produced {:?}, expected {} tokens",
            input, tokens, words.len()
        );
        for (token, word) in tokens.iter().zip(words.iter()) {
            prop_assert_eq!(token, word, "token mismatch");
        }
    }

    #[test]
    fn tokenize_preserves_quoted_whitespace(
        before in "[a-zA-Z]{1,10}",
        inner in "[a-zA-Z ]{1,20}",
        after in "[a-zA-Z]{1,10}",
    ) {
        // Double-quoted strings should preserve internal whitespace
        let input = format!("{} \"{}\" {}", before, inner, after);
        let tokens = tokenize(&input);
        prop_assert!(tokens.len() >= 2, "should have at least the before and after tokens");
        prop_assert_eq!(&tokens[0], &before);
        prop_assert_eq!(&tokens[1], &inner);
        prop_assert_eq!(&tokens[2], &after);
    }

    #[test]
    fn tokenize_single_quoted_preserves_content(
        content in "[a-zA-Z0-9 ]{1,30}",
    ) {
        let input = format!("'{}'", content);
        let tokens = tokenize(&input);
        prop_assert_eq!(tokens.len(), 1, "single quoted string should produce one token");
        prop_assert_eq!(&tokens[0], &content);
    }

    #[test]
    fn tokenize_multiple_spaces_collapsed(
        words in prop::collection::vec("[a-zA-Z]{1,10}", 2..5),
    ) {
        // Build input with variable whitespace between words (2-5 spaces)
        let mut input = String::new();
        for (i, word) in words.iter().enumerate() {
            if i > 0 {
                // Use multiple spaces between each word
                input.push_str("   ");
            }
            input.push_str(word);
        }
        let tokens = tokenize(&input);
        prop_assert_eq!(
            tokens.len(),
            words.len(),
            "multiple spaces should not create extra tokens for input '{}'",
            input
        );
    }

    #[test]
    fn tokenize_backslash_escape_space(
        a in "[a-zA-Z]{1,10}",
        b in "[a-zA-Z]{1,10}",
    ) {
        // Escaped space should join two words into one token
        let input = format!("{}\\ {}", a, b);
        let tokens = tokenize(&input);
        let expected = format!("{} {}", a, b);
        prop_assert_eq!(tokens.len(), 1, "escaped space should produce single token");
        prop_assert_eq!(&tokens[0], &expected);
    }

    #[test]
    fn tokenize_idempotent_for_simple_input(s in "[a-zA-Z0-9 ]{0,50}") {
        // For simple strings without quotes/escapes, tokenizing and re-joining
        // then tokenizing again should give the same result
        let tokens1 = tokenize(&s);
        let rejoined = tokens1.join(" ");
        let tokens2 = tokenize(&rejoined);
        prop_assert_eq!(
            tokens1, tokens2,
            "tokenize should be idempotent for simple input"
        );
    }

    #[test]
    fn tokenize_nonempty_word_produces_nonempty_token(word in "[a-zA-Z0-9]{1,20}") {
        let tokens = tokenize(&word);
        prop_assert_eq!(tokens.len(), 1);
        prop_assert!(!tokens[0].is_empty());
        prop_assert_eq!(&tokens[0], &word);
    }

    #[test]
    fn tokenize_token_count_bounded_by_spaces(
        input in "[a-zA-Z0-9 ]{1,100}",
    ) {
        let tokens = tokenize(&input);
        let space_count = input.chars().filter(|c| *c == ' ').count();
        // Number of tokens can be at most space_count + 1
        prop_assert!(
            tokens.len() <= space_count + 1,
            "tokens ({}) should be <= spaces ({}) + 1",
            tokens.len(), space_count
        );
    }
}
