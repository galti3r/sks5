/// Tokenize a command line into arguments, handling basic quoting
pub fn tokenize(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escape_next = false;

    for ch in input.chars() {
        if escape_next {
            current.push(ch);
            escape_next = false;
            continue;
        }

        if ch == '\\' && !in_single_quote {
            escape_next = true;
            continue;
        }

        if ch == '\'' && !in_double_quote {
            in_single_quote = !in_single_quote;
            continue;
        }

        if ch == '"' && !in_single_quote {
            in_double_quote = !in_double_quote;
            continue;
        }

        if ch.is_whitespace() && !in_single_quote && !in_double_quote {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            continue;
        }

        current.push(ch);
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple() {
        assert_eq!(tokenize("ls -la"), vec!["ls", "-la"]);
    }

    #[test]
    fn test_empty() {
        assert!(tokenize("").is_empty());
        assert!(tokenize("   ").is_empty());
    }

    #[test]
    fn test_single_quotes() {
        assert_eq!(tokenize("echo 'hello world'"), vec!["echo", "hello world"]);
    }

    #[test]
    fn test_double_quotes() {
        assert_eq!(
            tokenize(r#"echo "hello world""#),
            vec!["echo", "hello world"]
        );
    }

    #[test]
    fn test_escaped_space() {
        assert_eq!(tokenize("echo hello\\ world"), vec!["echo", "hello world"]);
    }

    #[test]
    fn test_multiple_spaces() {
        assert_eq!(tokenize("ls   -l   -a"), vec!["ls", "-l", "-a"]);
    }
}
