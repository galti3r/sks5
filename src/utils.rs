/// Generate a compact correlation ID (8 hex characters) from the first 4 bytes of a UUID v4.
///
/// This provides a short, human-readable identifier suitable for log messages
/// while still offering ~4 billion unique values to avoid collisions in practice.
pub fn generate_correlation_id() -> String {
    let uuid = uuid::Uuid::new_v4();
    let bytes = uuid.as_bytes();
    format!(
        "{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3]
    )
}

/// Format a byte count as a human-readable string (B, KB, MB, GB, TB).
///
/// A value of 0 is interpreted as "unlimited" (used for bandwidth limits).
pub fn format_bytes(bytes: u64) -> String {
    if bytes == 0 {
        return "unlimited".to_string();
    }

    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    const TB: u64 = 1024 * GB;

    if bytes >= TB {
        format!("{:.1} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format a byte count for usage display (0 = "0 B" instead of "unlimited").
///
/// This is appropriate for displaying actual byte counts where 0 means zero,
/// not unlimited. For all non-zero values, behaves identically to [`format_bytes`].
pub fn format_bytes_used(bytes: u64) -> String {
    if bytes == 0 {
        return "0 B".to_string();
    }
    format_bytes(bytes)
}

/// Parse "HH:MM" into minutes from midnight.
///
/// Returns `None` for invalid formats (wrong number of parts, out-of-range hours/minutes).
pub fn parse_hhmm(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.trim().split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let h: u32 = parts[0].parse().ok()?;
    let m: u32 = parts[1].parse().ok()?;
    if h > 23 || m > 59 {
        return None;
    }
    Some(h * 60 + m)
}

/// Format a duration in seconds as a human-readable string.
///
/// - `< 60s`: shows seconds (e.g., "30s")
/// - `< 1h`: shows minutes + seconds (e.g., "1m 30s"), omits trailing zero
/// - `< 1d`: shows hours + minutes (e.g., "1h 1m"), omits trailing zero
/// - `>= 1d`: shows days + hours (e.g., "1d 1h"), omits trailing zero
pub fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        let m = secs / 60;
        let s = secs % 60;
        if s > 0 {
            format!("{}m {}s", m, s)
        } else {
            format!("{}m", m)
        }
    } else if secs < 86400 {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        if m > 0 {
            format!("{}h {}m", h, m)
        } else {
            format!("{}h", h)
        }
    } else {
        let d = secs / 86400;
        let h = (secs % 86400) / 3600;
        if h > 0 {
            format!("{}d {}h", d, h)
        } else {
            format!("{}d", d)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes_zero_is_unlimited() {
        assert_eq!(format_bytes(0), "unlimited");
    }

    #[test]
    fn test_format_bytes_small() {
        assert_eq!(format_bytes(500), "500 B");
    }

    #[test]
    fn test_format_bytes_kb() {
        assert_eq!(format_bytes(2048), "2.0 KB");
    }

    #[test]
    fn test_format_bytes_mb() {
        assert_eq!(format_bytes(5_242_880), "5.0 MB");
    }

    #[test]
    fn test_format_bytes_gb() {
        assert_eq!(format_bytes(1_073_741_824), "1.0 GB");
    }

    #[test]
    fn test_format_bytes_tb() {
        assert_eq!(format_bytes(1_099_511_627_776), "1.0 TB");
    }

    #[test]
    fn test_format_bytes_used_zero() {
        assert_eq!(format_bytes_used(0), "0 B");
    }

    #[test]
    fn test_format_bytes_used_nonzero() {
        assert_eq!(format_bytes_used(1024), "1.0 KB");
    }

    #[test]
    fn test_correlation_id_format() {
        let cid = generate_correlation_id();
        // Must be exactly 8 hex characters
        assert_eq!(cid.len(), 8);
        assert!(cid.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_correlation_id_uniqueness() {
        let ids: Vec<String> = (0..100).map(|_| generate_correlation_id()).collect();
        let unique: std::collections::HashSet<&String> = ids.iter().collect();
        // With 8 hex chars (~4 billion values), 100 IDs should all be unique
        assert_eq!(unique.len(), 100);
    }

    #[test]
    fn test_format_duration_seconds() {
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(30), "30s");
        assert_eq!(format_duration(59), "59s");
    }

    #[test]
    fn test_format_duration_minutes() {
        assert_eq!(format_duration(60), "1m");
        assert_eq!(format_duration(90), "1m 30s");
        assert_eq!(format_duration(300), "5m");
        assert_eq!(format_duration(3599), "59m 59s");
    }

    #[test]
    fn test_format_duration_hours() {
        assert_eq!(format_duration(3600), "1h");
        assert_eq!(format_duration(3660), "1h 1m");
        assert_eq!(format_duration(3661), "1h 1m");
        assert_eq!(format_duration(7200), "2h");
    }

    #[test]
    fn test_format_duration_days() {
        assert_eq!(format_duration(86400), "1d");
        assert_eq!(format_duration(90000), "1d 1h");
        assert_eq!(format_duration(172800), "2d");
    }

    #[test]
    fn test_parse_hhmm_valid() {
        assert_eq!(parse_hhmm("00:00"), Some(0));
        assert_eq!(parse_hhmm("09:30"), Some(570));
        assert_eq!(parse_hhmm("23:59"), Some(1439));
        assert_eq!(parse_hhmm(" 08:00 "), Some(480));
    }

    #[test]
    fn test_parse_hhmm_invalid() {
        assert_eq!(parse_hhmm("24:00"), None);
        assert_eq!(parse_hhmm("12:60"), None);
        assert_eq!(parse_hhmm("abc"), None);
        assert_eq!(parse_hhmm("12"), None);
        assert_eq!(parse_hhmm(""), None);
    }
}
