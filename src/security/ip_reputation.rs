use dashmap::DashMap;
use std::net::IpAddr;
use std::time::Instant;

/// Score entry for an IP address
struct IpScore {
    score: f64,
    last_updated: Instant,
    last_auth_failure: Option<Instant>,
    auth_failure_count: u32,
}

/// IP Reputation scoring system
pub struct IpReputationManager {
    scores: DashMap<IpAddr, IpScore>,
    ban_threshold: u32,
    enabled: bool,
}

impl IpReputationManager {
    pub fn new(enabled: bool, ban_threshold: u32) -> Self {
        Self {
            scores: DashMap::new(),
            ban_threshold,
            enabled,
        }
    }

    /// Record an auth failure for an IP
    pub fn record_auth_failure(&self, ip: &IpAddr) {
        if !self.enabled {
            return;
        }
        self.add_score(ip, 10.0);
    }

    /// Record an ACL denial for an IP
    pub fn record_acl_denial(&self, ip: &IpAddr) {
        if !self.enabled {
            return;
        }
        self.add_score(ip, 5.0);
    }

    /// Record rapid connection attempts
    pub fn record_rapid_connections(&self, ip: &IpAddr) {
        if !self.enabled {
            return;
        }
        self.add_score(ip, 3.0);
    }

    /// Record successful auth (reduces score)
    pub fn record_auth_success(&self, ip: &IpAddr) {
        if !self.enabled {
            return;
        }
        self.add_score(ip, -5.0);
    }

    /// Get current score for an IP (with decay applied)
    pub fn get_score(&self, ip: &IpAddr) -> u32 {
        if !self.enabled {
            return 0;
        }
        match self.scores.get(ip) {
            Some(entry) => {
                let decayed = Self::apply_decay(entry.score, entry.last_updated);
                decayed.max(0.0) as u32
            }
            None => 0,
        }
    }

    /// Check if an IP should be banned based on reputation
    pub fn should_ban(&self, ip: &IpAddr) -> bool {
        if !self.enabled || self.ban_threshold == 0 {
            return false;
        }
        self.get_score(ip) >= self.ban_threshold
    }

    fn add_score(&self, ip: &IpAddr, delta: f64) {
        let mut entry = self.scores.entry(*ip).or_insert_with(|| IpScore {
            score: 0.0,
            last_updated: Instant::now(),
            last_auth_failure: None,
            auth_failure_count: 0,
        });
        // Apply decay before adding new score
        entry.score = Self::apply_decay(entry.score, entry.last_updated);
        entry.score = (entry.score + delta).max(0.0);
        entry.last_updated = Instant::now();
        if delta > 0.0 {
            entry.last_auth_failure = Some(Instant::now());
            entry.auth_failure_count += 1;
        }
    }

    /// Decay: halve score every hour
    fn apply_decay(score: f64, last_updated: Instant) -> f64 {
        let elapsed_secs = last_updated.elapsed().as_secs_f64();
        let half_lives = elapsed_secs / 3600.0;
        score * (0.5_f64).powf(half_lives)
    }

    /// Clean up entries with negligible scores
    pub fn cleanup(&self) {
        self.scores.retain(|_, entry| {
            let decayed = Self::apply_decay(entry.score, entry.last_updated);
            decayed >= 1.0
        });
    }

    /// Get all scores for monitoring
    pub fn all_scores(&self) -> Vec<(IpAddr, u32)> {
        self.scores
            .iter()
            .map(|entry| {
                let score = Self::apply_decay(entry.score, entry.last_updated).max(0.0) as u32;
                (*entry.key(), score)
            })
            .filter(|(_, s)| *s > 0)
            .collect()
    }
}
