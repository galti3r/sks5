use std::sync::atomic::{AtomicU64, Ordering};

/// Lock-free rolling window counter using a circular buffer of atomic buckets.
/// Each bucket covers one sub-interval; `advance()` zeroes stale buckets as time progresses.
pub struct RollingWindow {
    buckets: Box<[AtomicU64]>,
    /// Total window duration in seconds (kept for debugging/introspection).
    #[allow(dead_code)]
    window_secs: u32,
    /// Seconds per bucket.
    bucket_secs: u32,
    /// Unix timestamp of the last advance (seconds).
    last_advance: AtomicU64,
    /// Cached sum recomputed on each `advance()` call. Avoids scanning all
    /// buckets on every `sum()` invocation (60 atomic loads for a 1-hour window).
    cached_sum: AtomicU64,
}

impl RollingWindow {
    /// Create a new rolling window.
    /// `window_secs`: total window duration.
    /// `num_buckets`: number of sub-intervals (higher = finer resolution, more memory).
    pub fn new(window_secs: u32, num_buckets: u32) -> Self {
        assert!(num_buckets > 0 && window_secs > 0);
        let bucket_secs = window_secs.div_ceil(num_buckets);
        let buckets: Vec<AtomicU64> = (0..num_buckets).map(|_| AtomicU64::new(0)).collect();
        let now = unix_secs();
        Self {
            buckets: buckets.into_boxed_slice(),
            window_secs,
            bucket_secs,
            last_advance: AtomicU64::new(now),
            cached_sum: AtomicU64::new(0),
        }
    }

    /// Record `count` units in the current bucket, advancing stale buckets if needed.
    pub fn record(&self, count: u64) {
        self.advance();
        let idx = self.current_index();
        self.buckets[idx].fetch_add(count, Ordering::Relaxed);
        self.cached_sum.fetch_add(count, Ordering::Relaxed);
    }

    /// Sum all buckets (total usage within the window).
    /// Returns the cached sum which is kept in sync by `record()` additions
    /// and `advance()` expirations. Falls back to a full scan to correct any
    /// drift from concurrent access.
    pub fn sum(&self) -> u64 {
        self.advance();
        self.cached_sum.load(Ordering::Relaxed)
    }

    /// Advance the window: zero out any buckets that have become stale since last advance.
    /// Uses CAS on `last_advance` to ensure only one thread advances at a time.
    /// After clearing stale buckets, recomputes `cached_sum` from all buckets to
    /// correct any drift from concurrent access.
    fn advance(&self) {
        let now = unix_secs();
        let last = self.last_advance.load(Ordering::Acquire);
        let elapsed_secs = now.saturating_sub(last);

        if elapsed_secs < self.bucket_secs as u64 {
            return; // Still within the same bucket interval
        }

        // Try to claim the advance
        if self
            .last_advance
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return; // Another thread advanced
        }

        let buckets_to_clear =
            (elapsed_secs / self.bucket_secs as u64).min(self.buckets.len() as u64) as usize;

        if buckets_to_clear >= self.buckets.len() {
            // Entire window has passed, zero everything
            for b in self.buckets.iter() {
                b.store(0, Ordering::Relaxed);
            }
            self.cached_sum.store(0, Ordering::Relaxed);
        } else {
            // Zero only the stale buckets
            let start_idx = self.bucket_index(last) + 1;
            for i in 0..buckets_to_clear {
                let idx = (start_idx + i) % self.buckets.len();
                self.buckets[idx].store(0, Ordering::Relaxed);
            }
            // Recompute cached_sum from all buckets to correct any drift
            let recomputed: u64 = self.buckets.iter().map(|b| b.load(Ordering::Relaxed)).sum();
            self.cached_sum.store(recomputed, Ordering::Relaxed);
        }
    }

    fn current_index(&self) -> usize {
        let now = unix_secs();
        self.bucket_index(now)
    }

    fn bucket_index(&self, timestamp: u64) -> usize {
        ((timestamp / self.bucket_secs as u64) % self.buckets.len() as u64) as usize
    }
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rolling_window_basic() {
        let w = RollingWindow::new(60, 60); // 60s window, 1s buckets
        w.record(100);
        w.record(200);
        assert_eq!(w.sum(), 300);
    }

    #[test]
    fn test_rolling_window_zero_initially() {
        let w = RollingWindow::new(10, 10);
        assert_eq!(w.sum(), 0);
    }
}
