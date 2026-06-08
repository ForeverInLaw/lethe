//! Per-account rate scheduling. Seeded at a conservative fraction of the
//! adapter's documented max (bulk-delete at full throttle is the flag trigger).
//! Honor explicit `Retry-After` / `FLOOD_WAIT` exactly; back off + shrink on
//! repeated 429s. State is ephemeral — resume cold-starts conservative.

use std::collections::HashMap;

use lethe_adapter::RatePolicy;
use tokio::time::{Duration, Instant};

/// Run buckets at this fraction of the documented maximum.
pub const SAFETY_FRACTION: f64 = 0.75;

pub struct TokenBucket {
    rate_per_sec: f64,
    capacity: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn from_policy(policy: &RatePolicy) -> Self {
        let rate = policy.max_per_sec * SAFETY_FRACTION;
        let capacity = policy.burst.max(1) as f64;
        Self { rate_per_sec: rate.max(0.1), capacity, tokens: capacity, last: Instant::now() }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate_per_sec).min(self.capacity);
        self.last = now;
    }

    /// Block until one token is available, then consume it.
    pub async fn acquire(&mut self) {
        loop {
            self.refill();
            if self.tokens >= 1.0 {
                self.tokens -= 1.0;
                return;
            }
            let deficit = 1.0 - self.tokens;
            let wait = Duration::from_secs_f64(deficit / self.rate_per_sec);
            tokio::time::sleep(wait).await;
        }
    }

    /// React to a rate-limit: wait the platform's value, then shrink the rate.
    pub async fn penalize(&mut self, retry_after: Duration) {
        tokio::time::sleep(retry_after).await;
        self.rate_per_sec = (self.rate_per_sec * 0.5).max(0.1);
        self.tokens = 0.0;
        self.last = Instant::now();
    }

    pub fn rate_per_sec(&self) -> f64 {
        self.rate_per_sec
    }
}

#[derive(Default)]
pub struct Scheduler {
    buckets: HashMap<String, TokenBucket>,
}

impl Scheduler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bucket(&mut self, account_id: &str, policy: &RatePolicy) -> &mut TokenBucket {
        self.buckets
            .entry(account_id.to_owned())
            .or_insert_with(|| TokenBucket::from_policy(policy))
    }
}
