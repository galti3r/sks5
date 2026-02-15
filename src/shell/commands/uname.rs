use crate::shell::commands::CommandResult;

pub fn run(args: &[String], hostname: &str) -> CommandResult {
    if args.is_empty() {
        return CommandResult::output("sks5\r\n".to_string());
    }

    let show_all = args.iter().any(|a| a == "-a");

    if show_all {
        return CommandResult::output(format!(
            "sks5 {} {} {} sks5/{} sks5\r\n",
            hostname,
            env!("CARGO_PKG_VERSION"),
            std::env::consts::ARCH,
            env!("CARGO_PKG_VERSION"),
        ));
    }

    let mut parts = Vec::new();
    let flags = args.join("");

    if flags.contains('s') {
        parts.push("sks5".to_string());
    }
    if flags.contains('n') {
        parts.push(hostname.to_string());
    }
    if flags.contains('r') {
        parts.push(env!("CARGO_PKG_VERSION").to_string());
    }
    if flags.contains('m') {
        parts.push(std::env::consts::ARCH.to_string());
    }
    if flags.contains('o') {
        parts.push("sks5".to_string());
    }

    if parts.is_empty() {
        parts.push("sks5".to_string());
    }

    CommandResult::output(format!("{}\r\n", parts.join(" ")))
}
