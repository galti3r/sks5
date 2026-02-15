use std::time::Duration;

/// Compute the throttle delay needed to respect all bandwidth limits.
///
/// Returns the max delay across all constraints. All rates in bytes/sec.
/// A limit of 0 means unlimited for that constraint.
pub fn compute_throttle(
    bytes_just_written: u64,
    per_conn_limit_kbps: u64,
    aggregate_rate_bps: u64,
    aggregate_limit_bps: u64,
    server_rate_bps: u64,
    server_limit_bps: u64,
) -> Duration {
    let mut max_delay = Duration::ZERO;

    // Per-connection throttle
    if per_conn_limit_kbps > 0 {
        let bytes_per_sec = per_conn_limit_kbps as f64 * 1000.0 / 8.0;
        let delay_secs = bytes_just_written as f64 / bytes_per_sec;
        if delay_secs > 0.001 {
            max_delay = max_delay.max(Duration::from_secs_f64(delay_secs));
        }
    }

    // Per-user aggregate throttle
    if aggregate_limit_bps > 0 && aggregate_rate_bps > aggregate_limit_bps {
        let overshoot_ratio = aggregate_rate_bps as f64 / aggregate_limit_bps as f64;
        let delay_secs = (overshoot_ratio - 1.0) * 0.1; // gentle backoff
        if delay_secs > 0.001 {
            max_delay = max_delay.max(Duration::from_secs_f64(delay_secs.min(1.0)));
        }
    }

    // Server-level aggregate throttle
    if server_limit_bps > 0 && server_rate_bps > server_limit_bps {
        let overshoot_ratio = server_rate_bps as f64 / server_limit_bps as f64;
        let delay_secs = (overshoot_ratio - 1.0) * 0.1;
        if delay_secs > 0.001 {
            max_delay = max_delay.max(Duration::from_secs_f64(delay_secs.min(1.0)));
        }
    }

    max_delay
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_limits_zero_delay() {
        let d = compute_throttle(1024, 0, 0, 0, 0, 0);
        assert_eq!(d, Duration::ZERO);
    }

    #[test]
    fn test_per_conn_throttle() {
        // 100 kbps = 12500 bytes/sec, writing 12500 bytes should delay ~1s
        let d = compute_throttle(12500, 100, 0, 0, 0, 0);
        assert!(d.as_secs_f64() > 0.9 && d.as_secs_f64() < 1.1);
    }

    #[test]
    fn test_aggregate_throttle_when_over() {
        // aggregate rate 2x limit => some delay
        let d = compute_throttle(1024, 0, 2000, 1000, 0, 0);
        assert!(d > Duration::ZERO);
    }

    #[test]
    fn test_aggregate_throttle_when_under() {
        // aggregate rate under limit => no delay
        let d = compute_throttle(1024, 0, 500, 1000, 0, 0);
        assert_eq!(d, Duration::ZERO);
    }
}
