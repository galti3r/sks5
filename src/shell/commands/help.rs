use crate::shell::commands::CommandResult;
use crate::shell::context::ShellContext;

/// Display help text. When a `ShellContext` is available, extended commands are
/// included in the output.
pub fn run(ctx: Option<&ShellContext>) -> CommandResult {
    let mut text = String::from(
        "Available commands:\r\n\
         \r\n\
         ls [path]          List directory contents\r\n\
         cd [path]          Change directory\r\n\
         pwd                Print working directory\r\n\
         cat <file>         Display file contents\r\n\
         whoami             Print current user\r\n\
         hostname           Print hostname\r\n\
         uname [-a]         Print system information\r\n\
         id                 Print user identity\r\n\
         echo <text>        Print text\r\n\
         env                Print environment variables\r\n\
         clear              Clear screen\r\n\
         help               Show this help\r\n\
         exit               Close connection\r\n",
    );

    if ctx.is_some() {
        text.push_str(
            "\r\n\
             Proxy commands:\r\n\
             \r\n\
             show connections   Show active proxy connections\r\n\
             show bandwidth     Show bandwidth usage and limits\r\n\
             show quota         Show quota limits and current usage\r\n\
             show acl           Show effective ACL rules\r\n\
             show status        Show session status\r\n\
             show history       Show proxy connection history\r\n\
             show fingerprint   Show SSH key fingerprint\r\n\
             test <host:port>   Test if destination is allowed by ACL\r\n\
             ping <host[:port]> DNS resolve and ACL check for host\r\n\
             resolve <domain>   DNS lookup showing all IPs\r\n\
             bookmark add|list|remove  Manage destination bookmarks\r\n\
             alias                     List all aliases\r\n\
             alias <name>=<command>    Create alias\r\n\
             alias remove <name>       Remove alias\r\n",
        );
    }

    CommandResult::output(text)
}
