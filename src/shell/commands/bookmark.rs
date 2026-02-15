use crate::shell::commands::CommandResult;
use crate::shell::context::ShellContext;

use super::colors::{color, CYAN, GREEN, YELLOW};

/// Manage destination bookmarks (in-memory).
///
/// Usage:
///   bookmark add <name> <host:port>
///   bookmark list
///   bookmark remove <name>
pub fn run(args: &[String], ctx: &mut ShellContext) -> CommandResult {
    if !ctx.permissions.bookmark_command {
        return CommandResult::output("Permission denied: bookmark\r\n".to_string());
    }

    if args.is_empty() {
        return CommandResult::output(
            "Usage: bookmark <add|list|remove> [args...]\r\n".to_string(),
        );
    }

    match args[0].as_str() {
        "add" => bookmark_add(&args[1..], ctx),
        "list" | "ls" => bookmark_list(ctx),
        "remove" | "rm" | "del" => bookmark_remove(&args[1..], ctx),
        other => CommandResult::output(format!(
            "bookmark: unknown subcommand '{}'\r\nUsage: bookmark <add|list|remove> [args...]\r\n",
            other
        )),
    }
}

fn bookmark_add(args: &[String], ctx: &mut ShellContext) -> CommandResult {
    if args.len() < 2 {
        return CommandResult::output("Usage: bookmark add <name> <host:port>\r\n".to_string());
    }

    let name = &args[0];
    let target = &args[1];
    let colors = ctx.colors;

    // Validate the target has a port
    if !target.contains(':') {
        return CommandResult::output(format!(
            "Invalid target '{}'. Expected format: host:port\r\n",
            target
        ));
    }

    let existed = ctx.bookmarks.insert(name.clone(), target.clone()).is_some();
    let action = if existed { "Updated" } else { "Added" };

    CommandResult::output(format!(
        "{} bookmark {} -> {}\r\n",
        color(GREEN, action, colors),
        color(CYAN, name, colors),
        target
    ))
}

fn bookmark_list(ctx: &ShellContext) -> CommandResult {
    let colors = ctx.colors;

    if ctx.bookmarks.is_empty() {
        return CommandResult::output("No bookmarks defined\r\n".to_string());
    }

    let mut output = String::new();
    output.push_str(&format!("{}\r\n", color(CYAN, "Bookmarks:", colors)));

    // Sort by name for deterministic output
    let mut entries: Vec<_> = ctx.bookmarks.iter().collect();
    entries.sort_by_key(|(k, _)| k.as_str());

    for (name, target) in entries {
        output.push_str(&format!(
            "  {} -> {}\r\n",
            color(YELLOW, name, colors),
            target
        ));
    }

    CommandResult::output(output)
}

fn bookmark_remove(args: &[String], ctx: &mut ShellContext) -> CommandResult {
    if args.is_empty() {
        return CommandResult::output("Usage: bookmark remove <name>\r\n".to_string());
    }

    let name = &args[0];
    let colors = ctx.colors;

    match ctx.bookmarks.remove(name.as_str()) {
        Some(_) => CommandResult::output(format!(
            "{} bookmark '{}'\r\n",
            color(GREEN, "Removed", colors),
            name
        )),
        None => CommandResult::output(format!("Bookmark '{}' not found\r\n", name)),
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
    fn test_bookmark_add() {
        let mut ctx = make_ctx();
        let result = run(
            &[
                "add".to_string(),
                "mydb".to_string(),
                "db.example.com:5432".to_string(),
            ],
            &mut ctx,
        );
        assert!(result.output.contains("Added"));
        assert!(result.output.contains("mydb"));
        assert_eq!(ctx.bookmarks.get("mydb").unwrap(), "db.example.com:5432");
    }

    #[test]
    fn test_bookmark_add_update() {
        let mut ctx = make_ctx();
        ctx.bookmarks
            .insert("mydb".to_string(), "old:5432".to_string());
        let result = run(
            &[
                "add".to_string(),
                "mydb".to_string(),
                "new:5432".to_string(),
            ],
            &mut ctx,
        );
        assert!(result.output.contains("Updated"));
        assert_eq!(ctx.bookmarks.get("mydb").unwrap(), "new:5432");
    }

    #[test]
    fn test_bookmark_add_invalid_target() {
        let mut ctx = make_ctx();
        let result = run(
            &[
                "add".to_string(),
                "mydb".to_string(),
                "noporthere".to_string(),
            ],
            &mut ctx,
        );
        assert!(result.output.contains("Invalid target"));
    }

    #[test]
    fn test_bookmark_add_missing_args() {
        let mut ctx = make_ctx();
        let result = run(&["add".to_string()], &mut ctx);
        assert!(result.output.contains("Usage:"));
    }

    #[test]
    fn test_bookmark_list_empty() {
        let mut ctx = make_ctx();
        let result = run(&["list".to_string()], &mut ctx);
        assert!(result.output.contains("No bookmarks"));
    }

    #[test]
    fn test_bookmark_list() {
        let mut ctx = make_ctx();
        ctx.bookmarks
            .insert("alpha".to_string(), "a:80".to_string());
        ctx.bookmarks
            .insert("beta".to_string(), "b:443".to_string());
        let result = run(&["list".to_string()], &mut ctx);
        assert!(result.output.contains("alpha"));
        assert!(result.output.contains("beta"));
        assert!(result.output.contains("a:80"));
        assert!(result.output.contains("b:443"));
    }

    #[test]
    fn test_bookmark_remove() {
        let mut ctx = make_ctx();
        ctx.bookmarks
            .insert("mydb".to_string(), "db:5432".to_string());
        let result = run(&["remove".to_string(), "mydb".to_string()], &mut ctx);
        assert!(result.output.contains("Removed"));
        assert!(!ctx.bookmarks.contains_key("mydb"));
    }

    #[test]
    fn test_bookmark_remove_nonexistent() {
        let mut ctx = make_ctx();
        let result = run(&["remove".to_string(), "nonexistent".to_string()], &mut ctx);
        assert!(result.output.contains("not found"));
    }

    #[test]
    fn test_bookmark_remove_missing_arg() {
        let mut ctx = make_ctx();
        let result = run(&["remove".to_string()], &mut ctx);
        assert!(result.output.contains("Usage:"));
    }

    #[test]
    fn test_bookmark_no_subcommand() {
        let mut ctx = make_ctx();
        let result = run(&[], &mut ctx);
        assert!(result.output.contains("Usage:"));
    }

    #[test]
    fn test_bookmark_unknown_subcommand() {
        let mut ctx = make_ctx();
        let result = run(&["what".to_string()], &mut ctx);
        assert!(result.output.contains("unknown subcommand"));
    }

    #[test]
    fn test_bookmark_permission_denied() {
        let mut ctx = make_ctx();
        ctx.permissions.bookmark_command = false;
        let result = run(&["list".to_string()], &mut ctx);
        assert!(result.output.contains("Permission denied"));
    }
}
