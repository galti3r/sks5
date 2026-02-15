use sks5::shell::executor::CommandExecutor;

#[test]
fn test_pwd() {
    let mut exec = CommandExecutor::new("alice".to_string(), "bastion".to_string());
    let result = exec.execute("pwd");
    assert!(result.output.contains("/home/alice"));
    assert!(!result.exit_requested);
}

#[test]
fn test_whoami() {
    let mut exec = CommandExecutor::new("alice".to_string(), "bastion".to_string());
    let result = exec.execute("whoami");
    assert!(result.output.contains("alice"));
}

#[test]
fn test_hostname() {
    let mut exec = CommandExecutor::new("alice".to_string(), "bastion".to_string());
    let result = exec.execute("hostname");
    assert!(result.output.contains("bastion"));
}

#[test]
fn test_cd_and_pwd() {
    let mut exec = CommandExecutor::new("alice".to_string(), "bastion".to_string());
    exec.execute("cd /tmp");
    let result = exec.execute("pwd");
    assert!(result.output.contains("/tmp"));
}

#[test]
fn test_ls_root() {
    let mut exec = CommandExecutor::new("alice".to_string(), "bastion".to_string());
    exec.execute("cd /");
    let result = exec.execute("ls");
    assert!(result.output.contains("etc"));
    assert!(result.output.contains("home"));
}

#[test]
fn test_cat_hostname() {
    let mut exec = CommandExecutor::new("alice".to_string(), "bastion".to_string());
    let result = exec.execute("cat /etc/hostname");
    assert!(result.output.contains("bastion"));
}

#[test]
fn test_cat_nonexistent() {
    let mut exec = CommandExecutor::new("alice".to_string(), "bastion".to_string());
    let result = exec.execute("cat /etc/shadow");
    assert!(result.output.contains("No such file"));
}

#[test]
fn test_uname() {
    let mut exec = CommandExecutor::new("alice".to_string(), "bastion".to_string());
    let result = exec.execute("uname");
    assert!(result.output.contains("sks5"));
}

#[test]
fn test_uname_a() {
    let mut exec = CommandExecutor::new("alice".to_string(), "bastion".to_string());
    let result = exec.execute("uname -a");
    assert!(result.output.contains("sks5"));
    assert!(result.output.contains("bastion"));
}

#[test]
fn test_exit() {
    let mut exec = CommandExecutor::new("alice".to_string(), "bastion".to_string());
    let result = exec.execute("exit");
    assert!(result.exit_requested);
}

#[test]
fn test_unknown_command() {
    let mut exec = CommandExecutor::new("alice".to_string(), "bastion".to_string());
    let result = exec.execute("nonexistent");
    assert!(result.output.contains("command not found"));
}

#[test]
fn test_echo() {
    let mut exec = CommandExecutor::new("alice".to_string(), "bastion".to_string());
    let result = exec.execute("echo hello world");
    assert!(result.output.contains("hello world"));
}

#[test]
fn test_id() {
    let mut exec = CommandExecutor::new("alice".to_string(), "bastion".to_string());
    let result = exec.execute("id");
    assert!(result.output.contains("uid=1000(alice)"));
}

#[test]
fn test_env() {
    let mut exec = CommandExecutor::new("alice".to_string(), "bastion".to_string());
    let result = exec.execute("env");
    assert!(result.output.contains("HOME=/home/alice"));
    assert!(result.output.contains("USER=alice"));
}

#[test]
fn test_help() {
    let mut exec = CommandExecutor::new("alice".to_string(), "bastion".to_string());
    let result = exec.execute("help");
    assert!(result.output.contains("Available commands"));
    assert!(result.output.contains("ls"));
    assert!(result.output.contains("cd"));
}

#[test]
fn test_prompt_format() {
    let exec = CommandExecutor::new("alice".to_string(), "bastion".to_string());
    let prompt = exec.prompt();
    assert_eq!(prompt, "alice@bastion:~$ ");
}

#[test]
fn test_prompt_after_cd() {
    let mut exec = CommandExecutor::new("alice".to_string(), "bastion".to_string());
    exec.execute("cd /tmp");
    let prompt = exec.prompt();
    assert_eq!(prompt, "alice@bastion:/tmp$ ");
}

#[test]
fn test_comment_is_noop() {
    let mut exec = CommandExecutor::new("alice".to_string(), "bastion".to_string());
    let result = exec.execute("# this is a comment");
    assert!(result.output.is_empty());
    assert!(!result.exit_requested);
}

#[test]
fn test_clear_screen() {
    let mut exec = CommandExecutor::new("alice".to_string(), "bastion".to_string());
    let result = exec.execute("clear");
    assert!(result.output.contains("\x1b[2J\x1b[H"));
    assert!(!result.exit_requested);
}
