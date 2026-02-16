use crate::config::types::WebhookFormat;
use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct WebhookPayload {
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub data: serde_json::Value,
}

impl WebhookPayload {
    /// Generate the HTTP body for this payload in the given format.
    pub fn to_formatted_body(&self, format: WebhookFormat, template: Option<&str>) -> String {
        match format {
            WebhookFormat::Generic => serde_json::to_string(self).unwrap_or_default(),
            WebhookFormat::Slack => self.to_slack_body(),
            WebhookFormat::Discord => self.to_discord_body(),
            WebhookFormat::Custom => self.to_custom_body(template.unwrap_or("{data_json}")),
        }
    }

    /// One-line summary of the event, extracted from data fields.
    pub fn summary(&self) -> String {
        let username = self.data_str("username").unwrap_or("unknown");
        let source_ip = self.data_str("source_ip").unwrap_or("?");

        match self.event_type.as_str() {
            "auth.success" => {
                let method = self.data_str("method").unwrap_or("?");
                format!(
                    "{} authenticated via {} from {}",
                    username, method, source_ip
                )
            }
            "auth.failure" => {
                let method = self.data_str("method").unwrap_or("?");
                format!("{} auth failed ({}) from {}", username, method, source_ip)
            }
            "proxy.complete" => {
                let host = self.data_str("host").unwrap_or("?");
                let port = self.data.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
                let bytes_up = self
                    .data
                    .get("bytes_up")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let bytes_down = self
                    .data
                    .get("bytes_down")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                format!(
                    "{} → {}:{} (↑{}B ↓{}B)",
                    username, host, port, bytes_up, bytes_down
                )
            }
            "connection.new" => {
                let protocol = self.data_str("protocol").unwrap_or("?");
                format!(
                    "{} new {} connection from {}",
                    username, protocol, source_ip
                )
            }
            "connection.closed" => {
                format!("Connection closed from {}", source_ip)
            }
            "rate_limit.exceeded" => {
                let window = self.data_str("window").unwrap_or("?");
                format!("{} rate limited ({}) from {}", username, window, source_ip)
            }
            "quota.exceeded" => {
                let reason = self.data_str("reason").unwrap_or("quota");
                format!("{} {} from {}", username, reason, source_ip)
            }
            "ban.created" | "ban.auto" => {
                let ip = self.data_str("ip").unwrap_or(source_ip);
                format!("IP {} banned", ip)
            }
            "ban.removed" => {
                let ip = self.data_str("ip").unwrap_or("?");
                format!("IP {} unbanned", ip)
            }
            "config.reload" => {
                let success = self
                    .data
                    .get("success")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if success {
                    "Configuration reloaded successfully".to_string()
                } else {
                    "Configuration reload failed".to_string()
                }
            }
            "maintenance.toggled" => {
                let enabled = self
                    .data
                    .get("enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if enabled {
                    "Maintenance mode enabled".to_string()
                } else {
                    "Maintenance mode disabled".to_string()
                }
            }
            "session.authenticated" => {
                let method = self.data_str("method").unwrap_or("?");
                let protocol = self.data_str("protocol").unwrap_or("?");
                format!(
                    "{} session ({}/{}) from {}",
                    username, protocol, method, source_ip
                )
            }
            _ => format!("{} from {}@{}", self.event_type, username, source_ip),
        }
    }

    /// Format as Slack Block Kit message.
    fn to_slack_body(&self) -> String {
        let emoji = match self.event_type.as_str() {
            "auth.failure" => ":warning:",
            "auth.success" => ":white_check_mark:",
            "proxy.complete" => ":globe_with_meridians:",
            "ban.created" | "ban.auto" => ":no_entry:",
            "ban.removed" => ":unlock:",
            "rate_limit.exceeded" | "quota.exceeded" => ":hourglass:",
            "config.reload" => ":gear:",
            "maintenance.toggled" => ":wrench:",
            "connection.new" => ":electric_plug:",
            "connection.closed" => ":x:",
            _ => ":bell:",
        };

        let summary = self.summary();
        let text = format!("{} [sks5] {}: {}", emoji, self.event_type, summary);

        // Build Block Kit payload
        let blocks = serde_json::json!([
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": format!("{} {}", emoji, self.event_type),
                    "emoji": true
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": summary
                }
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": format!("sks5 | {}", self.timestamp.to_rfc3339())
                    }
                ]
            }
        ]);

        serde_json::json!({
            "text": text,
            "blocks": blocks
        })
        .to_string()
    }

    /// Format as Discord embed.
    fn to_discord_body(&self) -> String {
        let color = match self.event_type.as_str() {
            "auth.failure" | "ban.created" | "ban.auto" => 0xED4245, // red
            "auth.success" | "proxy.complete" => 0x57F287,           // green
            "rate_limit.exceeded" | "quota.exceeded" => 0xFEE75C,    // yellow
            _ => 0x5865F2,                                           // blurple (info)
        };

        let summary = self.summary();

        let mut fields = Vec::new();
        if let Some(username) = self.data_str("username") {
            fields.push(serde_json::json!({"name": "User", "value": username, "inline": true}));
        }
        if let Some(ip) = self.data_str("source_ip").or_else(|| self.data_str("ip")) {
            fields.push(serde_json::json!({"name": "IP", "value": ip, "inline": true}));
        }
        if let Some(host) = self.data_str("host") {
            let port = self.data.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
            fields.push(serde_json::json!({"name": "Target", "value": format!("{}:{}", host, port), "inline": true}));
        }

        serde_json::json!({
            "embeds": [{
                "title": self.event_type,
                "description": summary,
                "color": color,
                "fields": fields,
                "timestamp": self.timestamp.to_rfc3339(),
                "footer": {"text": "sks5"}
            }]
        })
        .to_string()
    }

    /// Format using custom template with placeholder replacement.
    fn to_custom_body(&self, template: &str) -> String {
        let username = self.data_str("username").unwrap_or("");
        let source_ip = self.data_str("source_ip").unwrap_or("");
        let target_host = self.data_str("host").unwrap_or("");
        let data_json = serde_json::to_string(&self.data).unwrap_or_default();

        template
            .replace("{event_type}", &json_escape(&self.event_type))
            .replace("{timestamp}", &json_escape(&self.timestamp.to_rfc3339()))
            .replace("{username}", &json_escape(username))
            .replace("{source_ip}", &json_escape(source_ip))
            .replace("{target_host}", &json_escape(target_host))
            .replace("{data_json}", &data_json)
            .replace("{summary}", &json_escape(&self.summary()))
    }

    /// Helper to extract a string field from `self.data`.
    fn data_str(&self, key: &str) -> Option<&str> {
        self.data.get(key).and_then(|v| v.as_str())
    }
}

/// Escape a string for safe embedding in JSON string values.
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn test_payload(event_type: &str) -> WebhookPayload {
        WebhookPayload {
            event_type: event_type.to_string(),
            timestamp: Utc.with_ymd_and_hms(2025, 1, 15, 10, 30, 0).unwrap(),
            data: serde_json::json!({
                "username": "alice",
                "source_ip": "1.2.3.4",
                "host": "example.com",
                "port": 443,
                "method": "password",
                "bytes_up": 1024,
                "bytes_down": 2048
            }),
        }
    }

    #[test]
    fn test_generic_format() {
        let p = test_payload("auth.success");
        let body = p.to_formatted_body(WebhookFormat::Generic, None);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["event_type"], "auth.success");
        assert_eq!(parsed["data"]["username"], "alice");
    }

    #[test]
    fn test_slack_format() {
        let p = test_payload("auth.success");
        let body = p.to_formatted_body(WebhookFormat::Slack, None);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(parsed["text"].as_str().unwrap().contains("[sks5]"));
        assert!(parsed["blocks"].is_array());
    }

    #[test]
    fn test_discord_format() {
        let p = test_payload("proxy.complete");
        let body = p.to_formatted_body(WebhookFormat::Discord, None);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(parsed["embeds"].is_array());
        let embed = &parsed["embeds"][0];
        assert_eq!(embed["title"], "proxy.complete");
        assert_eq!(embed["color"], 0x57F287);
        assert!(embed["footer"]["text"].as_str().unwrap().contains("sks5"));
    }

    #[test]
    fn test_custom_format() {
        let p = test_payload("auth.failure");
        let template = r#"{"msg": "Event: {event_type} by {username} from {source_ip}"}"#;
        let body = p.to_formatted_body(WebhookFormat::Custom, Some(template));
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(parsed["msg"].as_str().unwrap().contains("auth.failure"));
        assert!(parsed["msg"].as_str().unwrap().contains("alice"));
    }

    #[test]
    fn test_summary_auth_success() {
        let p = test_payload("auth.success");
        assert!(p.summary().contains("alice"));
        assert!(p.summary().contains("password"));
    }

    #[test]
    fn test_summary_proxy_complete() {
        let p = test_payload("proxy.complete");
        let s = p.summary();
        assert!(s.contains("example.com:443"));
        assert!(s.contains("1024"));
    }

    #[test]
    fn test_summary_unknown_event() {
        let p = test_payload("custom.event");
        let s = p.summary();
        assert!(s.contains("custom.event"));
        assert!(s.contains("alice"));
    }

    #[test]
    fn test_json_escape() {
        assert_eq!(json_escape(r#"hello "world""#), r#"hello \"world\""#);
        assert_eq!(json_escape("line1\nline2"), "line1\\nline2");
    }

    #[test]
    fn test_slack_deny_emoji() {
        let p = test_payload("auth.failure");
        let body = p.to_formatted_body(WebhookFormat::Slack, None);
        assert!(body.contains(":warning:"));
    }

    #[test]
    fn test_discord_deny_color() {
        let p = test_payload("auth.failure");
        let body = p.to_formatted_body(WebhookFormat::Discord, None);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        // Red color for auth failure
        assert_eq!(parsed["embeds"][0]["color"], 0xED4245);
    }

    #[test]
    fn test_backward_compat_no_format_field() {
        // Simulates old config without format field — should deserialize as Generic
        let json = r#"{"url":"https://example.com","events":[]}"#;
        let config: crate::config::types::WebhookConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.format, WebhookFormat::Generic);
        assert!(config.template.is_none());
    }
}
