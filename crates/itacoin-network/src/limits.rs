//! Rate limits and the discouragement list (section 7 of
//! `docs/NETWORK_PROPOSAL.md`).

use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

/// A token bucket: `rate` tokens per second, at most `burst` stored.
#[derive(Clone, Copy, Debug)]
pub struct TokenBucket {
    tokens: f64,
    rate: f64,
    burst: f64,
    last: Instant,
}

impl TokenBucket {
    /// A full bucket.
    #[must_use]
    pub fn new(rate: f64, burst: f64, now: Instant) -> Self {
        Self {
            tokens: burst,
            rate,
            burst,
            last: now,
        }
    }

    /// Takes `count` tokens if available. Returns how many were granted,
    /// which is less than `count` when the bucket runs dry.
    pub fn take(&mut self, count: usize, now: Instant) -> usize {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        self.last = now;
        let granted = (count as f64).min(self.tokens.floor()).max(0.0);
        self.tokens -= granted;
        granted as usize
    }
}

/// How long a misbehaving address stays discouraged.
pub const DISCOURAGE_DURATION: Duration = Duration::from_secs(24 * 3600);

/// Addresses that broke the protocol recently.
///
/// Discouraged addresses are not chosen for outbound connections, and their
/// inbound connections are the first evicted. There are no ban scores: any
/// violation discourages at once.
#[derive(Clone, Debug, Default)]
pub struct Discouraged {
    until: HashMap<IpAddr, Instant>,
}

impl Discouraged {
    /// Discourages `ip` for [`DISCOURAGE_DURATION`].
    pub fn add(&mut self, ip: IpAddr, now: Instant) {
        self.until.insert(ip, now + DISCOURAGE_DURATION);
    }

    /// Whether `ip` is currently discouraged.
    #[must_use]
    pub fn contains(&self, ip: &IpAddr, now: Instant) -> bool {
        self.until.get(ip).is_some_and(|until| *until > now)
    }

    /// Currently discouraged IPs and the time left for each.
    #[must_use]
    pub fn list(&self, now: Instant) -> Vec<(IpAddr, Duration)> {
        let mut list: Vec<(IpAddr, Duration)> = self
            .until
            .iter()
            .filter(|(_, until)| **until > now)
            .map(|(ip, until)| (*ip, until.duration_since(now)))
            .collect();
        list.sort();
        list
    }

    /// Forgets expired entries.
    pub fn expire(&mut self, now: Instant) {
        self.until.retain(|_, until| *until > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_refills_at_its_rate_up_to_the_burst() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(0.1, 1_000.0, start);
        assert_eq!(bucket.take(1_500, start), 1_000);
        assert_eq!(bucket.take(1, start), 0);
        assert_eq!(bucket.take(5, start + Duration::from_secs(20)), 2);
        assert_eq!(
            bucket.take(5_000, start + Duration::from_secs(1_000_000)),
            1_000
        );
    }

    #[test]
    fn discouragement_expires() {
        let now = Instant::now();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let mut list = Discouraged::default();
        list.add(ip, now);
        assert!(list.contains(&ip, now + Duration::from_secs(3600)));
        assert!(!list.contains(&ip, now + DISCOURAGE_DURATION));
        list.expire(now + DISCOURAGE_DURATION);
        assert!(!list.contains(&ip, now));
    }
}
