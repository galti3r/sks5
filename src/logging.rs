use std::fmt;
use std::io::IsTerminal;

use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::format::{FormatEvent, FormatFields, Writer};
use tracing_subscriber::fmt::FmtContext;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::EnvFilter;

use crate::config::types::LogFormat;

/// Custom tracing formatter that prepends colored [ALLOW]/[DENY] prefixes
/// to log events based on message content.
pub struct PrefixedFormatter<E> {
    inner: E,
    ansi: bool,
}

impl<E> PrefixedFormatter<E> {
    pub fn new(inner: E, ansi: bool) -> Self {
        Self { inner, ansi }
    }
}

impl<S, N, E> FormatEvent<S, N> for PrefixedFormatter<E>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
    E: FormatEvent<S, N>,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut visitor = MessageVisitor {
            message: String::new(),
        };
        event.record(&mut visitor);
        let msg_lower = visitor.message.to_lowercase();

        if is_deny_pattern(&msg_lower) {
            if self.ansi {
                write!(writer, "\x1b[31m[DENY]\x1b[0m ")?;
            } else {
                write!(writer, "[DENY] ")?;
            }
        } else if is_allow_pattern(&msg_lower) {
            if self.ansi {
                write!(writer, "\x1b[34m[ALLOW]\x1b[0m ")?;
            } else {
                write!(writer, "[ALLOW] ")?;
            }
        }

        self.inner.format_event(ctx, writer, event)
    }
}

/// Visitor that extracts the message field from a tracing event.
struct MessageVisitor {
    message: String,
}

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{:?}", value);
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        }
    }
}

fn is_deny_pattern(msg: &str) -> bool {
    msg.contains("denied")
        || msg.contains("rejected")
        || msg.contains("auth failed")
        || msg.contains("banned")
        || msg.contains("rate limit exceeded")
        || msg.contains("quota exceeded")
        || msg.contains("quota already exhausted")
        || msg.contains("not in user")
        || msg.contains("auth timeout")
        || msg.contains("connect failed")
}

fn is_allow_pattern(msg: &str) -> bool {
    msg.contains("relay completed")
        || msg.contains("auth success")
        || msg.contains("forwarding completed")
}

/// Initialize the global tracing subscriber.
///
/// In Pretty mode, wraps the default formatter with `PrefixedFormatter`
/// to prepend colored [ALLOW]/[DENY] tags. JSON mode is unchanged.
pub fn setup_logging(level: &str, format: LogFormat) {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));

    match format {
        LogFormat::Json => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(filter)
                .init();
        }
        LogFormat::Pretty => {
            let ansi = std::io::stdout().is_terminal();
            let default_format = tracing_subscriber::fmt::format::Format::default();
            tracing_subscriber::fmt()
                .event_format(PrefixedFormatter::new(default_format, ansi))
                .with_env_filter(filter)
                .init();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deny_patterns() {
        assert!(is_deny_pattern("forwarding denied by acl"));
        assert!(is_deny_pattern("socks5 connection rejected"));
        assert!(is_deny_pattern("auth failed"));
        assert!(is_deny_pattern("ip banned"));
        assert!(is_deny_pattern(
            "ssh direct-tcpip rate limit exceeded (legacy)"
        ));
        assert!(is_deny_pattern("socks5 quota rate limit exceeded"));
        assert!(is_deny_pattern(
            "ssh direct-tcpip connection quota exceeded"
        ));
        assert!(is_deny_pattern(
            "ssh direct-tcpip bandwidth quota already exhausted"
        ));
        assert!(is_deny_pattern(
            "socks5 connection from ip not in user's allowed source_ips"
        ));
        assert!(is_deny_pattern("ssh auth timeout exceeded"));
        assert!(is_deny_pattern("socks5 connect failed"));
    }

    #[test]
    fn test_allow_patterns() {
        assert!(is_allow_pattern("socks5 relay completed"));
        assert!(is_allow_pattern("password auth success"));
        assert!(is_allow_pattern("public key auth success"));
        assert!(is_allow_pattern("forwarding completed"));
    }

    #[test]
    fn test_no_match() {
        assert!(!is_deny_pattern("starting sks5 proxy server"));
        assert!(!is_allow_pattern("starting sks5 proxy server"));
        assert!(!is_deny_pattern("server shutting down"));
        assert!(!is_allow_pattern("server shutting down"));
    }
}
