use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
    sync::Mutex,
    time::{Duration, Instant},
};

const MAX_TRACKED_ADDRESSES: usize = 65_536;
const PRUNE_INTERVAL: Duration = Duration::from_secs(1);

struct TokenBucket {
    tokens: f64,
    last_update: Instant,
}

impl TokenBucket {
    fn new(burst: f64) -> Self {
        Self {
            tokens: burst,
            last_update: Instant::now(),
        }
    }

    fn try_consume(&mut self, rate_per_sec: f64, burst: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.last_update = now;

        self.tokens = (self.tokens + elapsed * rate_per_sec).min(burst);

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct ConnectionRateLimiter {
    enabled: bool,
    rate_per_sec: f64,
    burst: f64,
    buckets: Mutex<Buckets>,
}

struct Buckets {
    map: HashMap<IpAddr, TokenBucket>,
    last_prune: Instant,
}

impl ConnectionRateLimiter {
    pub fn new(enabled: bool, rate_per_sec: u32, burst: u32) -> Self {
        Self {
            enabled,
            rate_per_sec: rate_per_sec as f64,
            burst: burst as f64,
            buckets: Mutex::new(Buckets {
                map: HashMap::new(),
                last_prune: Instant::now(),
            }),
        }
    }

    /// Returns true if connection is allowed, false if rate limited
    pub fn check_connection(&self, ip: &IpAddr) -> bool {
        if !self.enabled {
            return true;
        }

        let Ok(mut buckets) = self.buckets.lock() else {
            return true;
        };
        let buckets = &mut *buckets;
        let key = bucket_key(ip);

        if !buckets.map.contains_key(&key) && buckets.map.len() >= MAX_TRACKED_ADDRESSES / 2 {
            let now = Instant::now();
            if now.duration_since(buckets.last_prune) >= PRUNE_INTERVAL {
                buckets.last_prune = now;
                let idle = self.refill_time();
                buckets
                    .map
                    .retain(|_, b| now.duration_since(b.last_update) < idle);
            }
            if buckets.map.len() >= MAX_TRACKED_ADDRESSES {
                return false;
            }
        }

        buckets
            .map
            .entry(key)
            .or_insert_with(|| TokenBucket::new(self.burst))
            .try_consume(self.rate_per_sec, self.burst)
    }

    fn refill_time(&self) -> Duration {
        let max = Duration::from_secs(60);
        if self.rate_per_sec > 0.0 {
            Duration::from_secs_f64(self.burst / self.rate_per_sec)
                .clamp(Duration::from_secs(1), max)
        } else {
            max
        }
    }
}

fn bucket_key(ip: &IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !0u128 << 64)),
        v4 => v4,
    }
}

/// Per-connection packet rate limiter to detect and prevent packet flood attacks
pub struct PacketRateLimiter {
    max_packets_per_sec: u32,
    packet_count: u32,
    window_start: Instant,
}

impl PacketRateLimiter {
    pub fn new(max_packets_per_sec: u32) -> Self {
        Self {
            max_packets_per_sec,
            packet_count: 0,
            window_start: Instant::now(),
        }
    }

    /// Record a packet and return false if limit exceeded (flood detected)
    pub fn record_packet(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.packet_count = 1;
            return true;
        }

        self.packet_count += 1;
        self.packet_count <= self.max_packets_per_sec
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_rate_limiter() {
        let mut limiter = PacketRateLimiter::new(3);
        assert!(limiter.record_packet());
        assert!(limiter.record_packet());
        assert!(limiter.record_packet());
        assert!(!limiter.record_packet());
    }

    #[test]
    fn test_connection_rate_limiter() {
        let limiter = ConnectionRateLimiter::new(true, 2, 2);
        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        assert!(limiter.check_connection(&ip));
        assert!(limiter.check_connection(&ip));
        assert!(!limiter.check_connection(&ip));
    }

    #[test]
    fn test_ipv6_addresses_share_their_64_prefix() {
        let limiter = ConnectionRateLimiter::new(true, 1, 2);
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();

        assert!(limiter.check_connection(&a));
        assert!(limiter.check_connection(&b));
        assert!(!limiter.check_connection(&a));
        assert!(limiter.check_connection(&other));
    }

    #[test]
    fn test_tracked_addresses_are_bounded() {
        let limiter = ConnectionRateLimiter::new(true, 1, 5);
        for i in 0..MAX_TRACKED_ADDRESSES as u32 + 100 {
            limiter.check_connection(&IpAddr::from(i.to_be_bytes()));
        }
        assert_eq!(
            limiter.buckets.lock().unwrap().map.len(),
            MAX_TRACKED_ADDRESSES
        );
    }
}
