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
}
