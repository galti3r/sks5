use std::io::IsTerminal;

pub(crate) fn is_tty() -> bool {
    std::io::stdin().is_terminal()
}
