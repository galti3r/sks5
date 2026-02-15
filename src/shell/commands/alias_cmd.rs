use crate::shell::commands::CommandResult;
use crate::shell::context::ShellContext;

use super::colors::{color, CYAN, GREEN, YELLOW};

/// Manage command aliases.
///
/// Usage:
///   alias                     - list all aliases
///   alias <name>=<command>    - set an alias
///   alias remove <name>       - remove an alias
pub fn run(args: &[String], ctx: &mut ShellContext) -> CommandResult {
    if !ctx.permissions.alias_command {
        return CommandResult::output("Permission denied: alias\r\n".to_string());
    }

    // No args: list all aliases
    if args.is_empty() {
        return alias_list(ctx);
    }

    // "alias remove <name>"
    if args[0] == "remove" || args[0] == "rm" || args[0] == "del" {
        return alias_remove(&args[1..], ctx);
    }

    // "alias name=command" — check if first arg contains '='
    let first = &args[0];
    if let Some(eq_pos) = first.find('=') {
        let name = &first[..eq_pos];
        let command = &first[eq_pos + 1..];
        if name.is_empty() {
            return CommandResult::output("Usage: alias <name>=<command>\r\n".to_string());
        }
        // The command might span multiple args if the user did: alias foo=show status
        // In that case, the tokenizer already split it, so we rejoin
        let full_command = if args.len() > 1 {
            let rest = args[1..].join(" ");
            if command.is_empty() {
                rest
            } else {
                format!("{} {}", command, rest)
            }
        } else {
            command.to_string()
        };

        if full_command.is_empty() {
            return CommandResult::output("Usage: alias <name>=<command>\r\n".to_string());
        }

        return alias_set(name, &full_command, ctx);
    }

    // If arg doesn't contain '=', show usage
    CommandResult::output("Usage: alias [<name>=<command>] | alias remove <name>\r\n".to_string())
}

fn alias_list(ctx: &ShellContext) -> CommandResult {
    let colors = ctx.colors;

    if ctx.aliases.is_empty() {
        return CommandResult::output("No aliases defined\r\n".to_string());
    }

    let mut output = String::new();
    output.push_str(&format!("{}\r\n", color(CYAN, "Aliases:", colors)));

    // Sort by name for deterministic output
    let mut entries: Vec<_> = ctx.aliases.iter().collect();
    entries.sort_by_key(|(k, _)| k.as_str());

    for (name, command) in entries {
        output.push_str(&format!(
            "  {} = '{}'\r\n",
            color(YELLOW, name, colors),
            command
        ));
    }

    CommandResult::output(output)
}

fn alias_set(name: &str, command: &str, ctx: &mut ShellContext) -> CommandResult {
    let colors = ctx.colors;
    let existed = ctx
        .aliases
        .insert(name.to_string(), command.to_string())
        .is_some();
    let action = if existed { "Updated" } else { "Added" };

    CommandResult::output(format!(
        "{} alias: {} = '{}'\r\n",
        color(GREEN, action, colors),
        color(YELLOW, name, colors),
        command
    ))
}

fn alias_remove(args: &[String], ctx: &mut ShellContext) -> CommandResult {
    if args.is_empty() {
        return CommandResult::output("Usage: alias remove <name>\r\n".to_string());
    }

    let name = &args[0];
    let colors = ctx.colors;

    match ctx.aliases.remove(name.as_str()) {
        Some(_) => CommandResult::output(format!(
            "{} alias '{}'\r\n",
            color(GREEN, "Removed", colors),
            name
        )),
        None => CommandResult::output(format!("Alias '{}' not found\r\n", name)),
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_helpers::make_test_ctx;
    use super::*;

    fn make_ctx() -> ShellContext {
        make_test_ctx()
    }

    #[test]
    fn test_alias_list_empty() {
        let mut ctx = make_ctx();
        let result = run(&[], &mut ctx);
        assert!(result.output.contains("No aliases"));
    }

    #[test]
    fn test_alias_list_with_entries() {
        let mut ctx = make_ctx();
        ctx.aliases
            .insert("s".to_string(), "show status".to_string());
        ctx.aliases
            .insert("c".to_string(), "show connections".to_string());
        let result = run(&[], &mut ctx);
        assert!(result.output.contains("Aliases:"));
        assert!(result.output.contains("s"));
        assert!(result.output.contains("show status"));
        assert!(result.output.contains("c"));
    }

    #[test]
    fn test_alias_set() {
        let mut ctx = make_ctx();
        let result = run(&["s=show status".to_string()], &mut ctx);
        assert!(result.output.contains("Added"));
        assert_eq!(ctx.aliases.get("s").unwrap(), "show status");
    }

    #[test]
    fn test_alias_set_multiword() {
        let mut ctx = make_ctx();
        // Simulates: alias db=test prod-db:5432
        // After tokenization: ["db=test", "prod-db:5432"]
        let result = run(
            &["db=test".to_string(), "prod-db:5432".to_string()],
            &mut ctx,
        );
        assert!(result.output.contains("Added"));
        assert_eq!(ctx.aliases.get("db").unwrap(), "test prod-db:5432");
    }

    #[test]
    fn test_alias_update() {
        let mut ctx = make_ctx();
        ctx.aliases
            .insert("s".to_string(), "old command".to_string());
        let result = run(&["s=show bandwidth".to_string()], &mut ctx);
        assert!(result.output.contains("Updated"));
        assert_eq!(ctx.aliases.get("s").unwrap(), "show bandwidth");
    }

    #[test]
    fn test_alias_set_empty_name() {
        let mut ctx = make_ctx();
        let result = run(&["=show status".to_string()], &mut ctx);
        assert!(result.output.contains("Usage:"));
    }

    #[test]
    fn test_alias_set_empty_command() {
        let mut ctx = make_ctx();
        let result = run(&["s=".to_string()], &mut ctx);
        assert!(result.output.contains("Usage:"));
    }

    #[test]
    fn test_alias_remove() {
        let mut ctx = make_ctx();
        ctx.aliases
            .insert("s".to_string(), "show status".to_string());
        let result = run(&["remove".to_string(), "s".to_string()], &mut ctx);
        assert!(result.output.contains("Removed"));
        assert!(!ctx.aliases.contains_key("s"));
    }

    #[test]
    fn test_alias_remove_nonexistent() {
        let mut ctx = make_ctx();
        let result = run(&["remove".to_string(), "nope".to_string()], &mut ctx);
        assert!(result.output.contains("not found"));
    }

    #[test]
    fn test_alias_remove_missing_arg() {
        let mut ctx = make_ctx();
        let result = run(&["remove".to_string()], &mut ctx);
        assert!(result.output.contains("Usage:"));
    }

    #[test]
    fn test_alias_no_equals() {
        let mut ctx = make_ctx();
        let result = run(&["something".to_string()], &mut ctx);
        assert!(result.output.contains("Usage:"));
    }

    #[test]
    fn test_alias_permission_denied() {
        let mut ctx = make_ctx();
        ctx.permissions.alias_command = false;
        let result = run(&[], &mut ctx);
        assert!(result.output.contains("Permission denied"));
    }
}
