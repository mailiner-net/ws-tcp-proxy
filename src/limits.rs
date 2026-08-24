//! In-process concurrency, connect-rate, destination-diversity, and byte caps.
//!
//! There is no per-token identity on the public proxy; these limits are keyed
//! by client IP and destination. A [`ConnectionLease`] is held for the life of
//! an accepted session and released on drop.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitError {
    GlobalFull,
    PerIpFull,
    PerDestFull,
    ConnectRate,
    GlobalConnectRate,
    DistinctDests,
    ByteCap,
}



/// `0` on a cap means unlimited.
#[derive(Debug, Clone)]
pub struct LimitsConfig {
    pub max_global_connections: usize,
    pub max_conns_per_ip: usize,
    pub max_conns_per_dest: usize,
    pub connects_per_ip: usize,
    pub connects_per_ip_window: Duration,
    pub distinct_dests_per_ip: usize,
    pub distinct_dests_window: Duration,
    pub global_connects: usize,
    pub global_connects_window: Duration,
    /// Combined up+down bytes per source IP over [`Self::bytes_window`].
    pub max_bytes_per_ip: u64,
    pub bytes_window: Duration,
    /// IPv4 prefix length used as the limit key (`32` = one address).
    pub ipv4_prefix: u8,
    /// IPv6 prefix length used as the limit key (`64` so a /64 cannot
    /// mint a fresh budget per address).
    pub ipv6_prefix: u8,
    /// Drop idle per-IP rows after this many tracked prefixes (`0` = no cap).
    pub max_tracked_ips: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_global_connections: 5000,
            max_conns_per_ip: 16,
            max_conns_per_dest: 200,
            connects_per_ip: 10,
            connects_per_ip_window: Duration::from_secs(60),
            distinct_dests_per_ip: 10,
            distinct_dests_window: Duration::from_secs(60),
            global_connects: 20,
            global_connects_window: Duration::from_secs(1),
            max_bytes_per_ip: 1024 * 1024 * 1024,
            bytes_window: Duration::from_secs(3600),
            ipv4_prefix: 32,
            ipv6_prefix: 64,
            max_tracked_ips: 50_000,
        }
    }
}

impl LimitsConfig {
    /// High enough that tests exercising other behavior do not collide.
    pub fn unlimited() -> Self {
        Self {
            max_global_connections: 0,
            max_conns_per_ip: 0,
            max_conns_per_dest: 0,
            connects_per_ip: 0,
            connects_per_ip_window: Duration::from_secs(60),
            distinct_dests_per_ip: 0,
            distinct_dests_window: Duration::from_secs(60),
            global_connects: 0,
            global_connects_window: Duration::from_secs(1),
            max_bytes_per_ip: 0,
            bytes_window: Duration::from_secs(3600),
            ipv4_prefix: 32,
            ipv6_prefix: 64,
            max_tracked_ips: 0,
        }
    }
}

/// Mask `ip` to the configured prefix so many addresses in one network
/// share a single budget. IPv4-mapped IPv6 is treated as IPv4.
pub fn limit_key(ip: IpAddr, v4_bits: u8, v6_bits: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let bits = v4_bits.min(32);
            if bits == 32 {
                return ip;
            }
            let mask = if bits == 0 {
                0
            } else {
                !0u32 << (32 - bits)
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return limit_key(IpAddr::V4(v4), v4_bits, v6_bits);
            }
            let bits = v6_bits.min(128);
            if bits == 128 {
                return ip;
            }
            let mask = if bits == 0 {
                0
            } else {
                !0u128 << (128 - bits)
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
        }
    }
}

fn capped(limit: usize, used: usize) -> bool {
    limit != 0 && used >= limit
}

fn prune_instants(q: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    while q.front().is_some_and(|t| now.duration_since(*t) > window) {
        q.pop_front();
    }
}

#[derive(Default)]
struct IpState {
    connections: usize,
    connects: VecDeque<Instant>,
    dests: VecDeque<(Instant, String)>,
    bytes: VecDeque<(Instant, u64)>,
    bytes_sum: u64,
}

impl IpState {
    fn prune(&mut self, now: Instant, cfg: &LimitsConfig) {
        prune_instants(&mut self.connects, now, cfg.connects_per_ip_window);
        while self
            .dests
            .front()
            .is_some_and(|(t, _)| now.duration_since(*t) > cfg.distinct_dests_window)
        {
            self.dests.pop_front();
        }
        while self
            .bytes
            .front()
            .is_some_and(|(t, _)| now.duration_since(*t) > cfg.bytes_window)
        {
            if let Some((_, n)) = self.bytes.pop_front() {
                self.bytes_sum = self.bytes_sum.saturating_sub(n);
            }
        }
    }

    fn is_idle(&self) -> bool {
        self.connections == 0
            && self.connects.is_empty()
            && self.dests.is_empty()
            && self.bytes.is_empty()
    }
}

struct Inner {
    cfg: LimitsConfig,
    global_connections: usize,
    global_connects: VecDeque<Instant>,
    per_ip: HashMap<IpAddr, IpState>,
    per_dest: HashMap<String, usize>,
    last_gc: Instant,
}

impl Inner {
    fn prune_global(&mut self, now: Instant) {
        prune_instants(
            &mut self.global_connects,
            now,
            self.cfg.global_connects_window,
        );
    }

    /// Drop per-IP rows whose windows have expired and that hold no lease.
    fn gc_idle(&mut self, now: Instant) {
        self.prune_global(now);
        let cfg = self.cfg.clone();
        self.per_ip.retain(|_, st| {
            st.prune(now, &cfg);
            !st.is_idle()
        });
        self.last_gc = now;
    }

    fn maybe_gc(&mut self, now: Instant) {
        let overdue = now.duration_since(self.last_gc) >= Duration::from_secs(30);
        let large = self.per_ip.len() >= 10_000;
        if overdue || large {
            self.gc_idle(now);
        }
    }
}

pub struct LimitState {
    inner: Mutex<Inner>,
}

impl LimitState {
    pub fn new(cfg: LimitsConfig) -> Self {
        Self {
            inner: Mutex::new(Inner {
                cfg,
                global_connections: 0,
                global_connects: VecDeque::new(),
                per_ip: HashMap::new(),
                per_dest: HashMap::new(),
                last_gc: Instant::now(),
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Count a connect *attempt* (after dest policy) toward rate / diversity.
    pub fn record_attempt(&self, ip: IpAddr, dest: &str) -> Result<(), LimitError> {
        let mut g = self.lock();
        let ip = limit_key(ip, g.cfg.ipv4_prefix, g.cfg.ipv6_prefix);
        let now = Instant::now();
        g.maybe_gc(now);
        g.prune_global(now);

        if capped(g.cfg.max_tracked_ips, g.per_ip.len()) && !g.per_ip.contains_key(&ip) {
            g.gc_idle(now);
            if capped(g.cfg.max_tracked_ips, g.per_ip.len()) && !g.per_ip.contains_key(&ip) {
                return Err(LimitError::GlobalConnectRate);
            }
        }

        if capped(g.cfg.global_connects, g.global_connects.len()) {
            return Err(LimitError::GlobalConnectRate);
        }

        {
            let cfg = g.cfg.clone();
            let st = g.per_ip.entry(ip).or_default();
            st.prune(now, &cfg);
            if capped(cfg.connects_per_ip, st.connects.len()) {
                return Err(LimitError::ConnectRate);
            }
            if cfg.distinct_dests_per_ip != 0 {
                let unique: HashSet<&str> = st.dests.iter().map(|(_, d)| d.as_str()).collect();
                if !unique.contains(dest) && unique.len() >= cfg.distinct_dests_per_ip {
                    return Err(LimitError::DistinctDests);
                }
            }
            st.connects.push_back(now);
            st.dests.push_back((now, dest.to_string()));
        }

        g.global_connects.push_back(now);
        Ok(())
    }

    /// Reserve a live connection slot. Pair with [`ConnectionLease`].
    pub fn acquire(self: &Arc<Self>, ip: IpAddr, dest: &str) -> Result<ConnectionLease, LimitError> {
        let mut g = self.lock();
        let ip = limit_key(ip, g.cfg.ipv4_prefix, g.cfg.ipv6_prefix);
        g.maybe_gc(Instant::now());
        if capped(g.cfg.max_global_connections, g.global_connections) {
            return Err(LimitError::GlobalFull);
        }
        let max_per_ip = g.cfg.max_conns_per_ip;
        {
            let st = g.per_ip.entry(ip).or_default();
            if capped(max_per_ip, st.connections) {
                return Err(LimitError::PerIpFull);
            }
        }
        let dest_count = g.per_dest.get(dest).copied().unwrap_or(0);
        if capped(g.cfg.max_conns_per_dest, dest_count) {
            return Err(LimitError::PerDestFull);
        }

        g.global_connections += 1;
        g.per_ip.entry(ip).or_default().connections += 1;
        *g.per_dest.entry(dest.to_string()).or_insert(0) += 1;

        Ok(ConnectionLease {
            state: Arc::clone(self),
            ip,
            dest: dest.to_string(),
        })
    }

    fn release(&self, ip: IpAddr, dest: &str) {
        let mut g = self.lock();
        g.global_connections = g.global_connections.saturating_sub(1);
        let cfg = g.cfg.clone();
        let now = Instant::now();
        if let Some(st) = g.per_ip.get_mut(&ip) {
            st.connections = st.connections.saturating_sub(1);
            st.prune(now, &cfg);
            if st.is_idle() {
                g.per_ip.remove(&ip);
            }
        }
        if let Some(c) = g.per_dest.get_mut(dest) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                g.per_dest.remove(dest);
            }
        }
    }

    pub fn add_bytes(&self, ip: IpAddr, n: u64) -> Result<(), LimitError> {
        if n == 0 {
            return Ok(());
        }
        let mut g = self.lock();
        let ip = limit_key(ip, g.cfg.ipv4_prefix, g.cfg.ipv6_prefix);
        g.maybe_gc(Instant::now());
        if g.cfg.max_bytes_per_ip == 0 {
            return Ok(());
        }
        let now = Instant::now();
        let cfg = g.cfg.clone();
        let st = g.per_ip.entry(ip).or_default();
        st.prune(now, &cfg);
        if st.bytes_sum.saturating_add(n) > cfg.max_bytes_per_ip {
            return Err(LimitError::ByteCap);
        }
        st.bytes.push_back((now, n));
        st.bytes_sum = st.bytes_sum.saturating_add(n);
        Ok(())
    }

    #[cfg(test)]
    fn tracked_ip_count(&self) -> usize {
        self.lock().per_ip.len()
    }
}

pub struct ConnectionLease {
    state: Arc<LimitState>,
    ip: IpAddr,
    dest: String,
}

impl std::fmt::Debug for ConnectionLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionLease")
            .field("ip", &self.ip)
            .field("dest", &self.dest)
            .finish()
    }
}

impl Drop for ConnectionLease {
    fn drop(&mut self) {
        self.state.release(self.ip, &self.dest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, n))
    }

    fn v6(host: u16) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, host))
    }

    #[test]
    fn per_ip_concurrent_cap() {
        let state = Arc::new(LimitState::new(LimitsConfig {
            max_conns_per_ip: 2,
            ..LimitsConfig::unlimited()
        }));
        let a = state.acquire(ip(1), "imap.example:993").unwrap();
        let b = state.acquire(ip(1), "imap.example:993").unwrap();
        assert_eq!(
            state.acquire(ip(1), "imap.example:993").unwrap_err(),
            LimitError::PerIpFull
        );
        assert!(state.acquire(ip(2), "imap.example:993").is_ok());
        drop(a);
        drop(b);
        assert!(state.acquire(ip(1), "imap.example:993").is_ok());
    }

    #[test]
    fn global_and_per_dest_caps() {
        let state = Arc::new(LimitState::new(LimitsConfig {
            max_global_connections: 2,
            max_conns_per_dest: 1,
            ..LimitsConfig::unlimited()
        }));
        let _a = state.acquire(ip(1), "a:993").unwrap();
        assert_eq!(
            state.acquire(ip(2), "a:993").unwrap_err(),
            LimitError::PerDestFull
        );
        let _b = state.acquire(ip(2), "b:993").unwrap();
        assert_eq!(
            state.acquire(ip(3), "c:993").unwrap_err(),
            LimitError::GlobalFull
        );
    }

    #[test]
    fn connect_rate_per_ip() {
        let state = Arc::new(LimitState::new(LimitsConfig {
            connects_per_ip: 2,
            connects_per_ip_window: Duration::from_secs(60),
            ..LimitsConfig::unlimited()
        }));
        state.record_attempt(ip(1), "a:993").unwrap();
        state.record_attempt(ip(1), "a:993").unwrap();
        assert_eq!(
            state.record_attempt(ip(1), "a:993").unwrap_err(),
            LimitError::ConnectRate
        );
        assert!(state.record_attempt(ip(2), "a:993").is_ok());
    }

    #[test]
    fn distinct_dests_per_ip() {
        let state = Arc::new(LimitState::new(LimitsConfig {
            distinct_dests_per_ip: 2,
            distinct_dests_window: Duration::from_secs(60),
            ..LimitsConfig::unlimited()
        }));
        state.record_attempt(ip(1), "a:993").unwrap();
        state.record_attempt(ip(1), "b:993").unwrap();
        // same dest again is fine
        state.record_attempt(ip(1), "a:993").unwrap();
        assert_eq!(
            state.record_attempt(ip(1), "c:993").unwrap_err(),
            LimitError::DistinctDests
        );
    }

    #[test]
    fn global_connect_rate() {
        let state = Arc::new(LimitState::new(LimitsConfig {
            global_connects: 2,
            global_connects_window: Duration::from_secs(60),
            ..LimitsConfig::unlimited()
        }));
        state.record_attempt(ip(1), "a:993").unwrap();
        state.record_attempt(ip(2), "b:993").unwrap();
        assert_eq!(
            state.record_attempt(ip(3), "c:993").unwrap_err(),
            LimitError::GlobalConnectRate
        );
    }

    #[test]
    fn byte_cap_per_ip() {
        let state = Arc::new(LimitState::new(LimitsConfig {
            max_bytes_per_ip: 10,
            bytes_window: Duration::from_secs(3600),
            ..LimitsConfig::unlimited()
        }));
        state.add_bytes(ip(1), 7).unwrap();
        state.add_bytes(ip(1), 3).unwrap();
        assert_eq!(state.add_bytes(ip(1), 1).unwrap_err(), LimitError::ByteCap);
        assert!(state.add_bytes(ip(2), 10).is_ok());
    }

    #[test]
    fn ipv6_same_slash64_shares_budget() {
        let state = Arc::new(LimitState::new(LimitsConfig {
            max_conns_per_ip: 1,
            ipv6_prefix: 64,
            ..LimitsConfig::unlimited()
        }));
        let _a = state.acquire(v6(1), "imap.example:993").unwrap();
        assert_eq!(
            state.acquire(v6(2), "imap.example:993").unwrap_err(),
            LimitError::PerIpFull
        );
        // A different /64 is independent.
        assert!(state.acquire(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 1)), "imap.example:993").is_ok());
    }

    #[test]
    fn ipv4_prefix_can_aggregate_slash24() {
        let state = Arc::new(LimitState::new(LimitsConfig {
            connects_per_ip: 1,
            ipv4_prefix: 24,
            ..LimitsConfig::unlimited()
        }));
        state.record_attempt(ip(1), "a:993").unwrap();
        assert_eq!(
            state.record_attempt(ip(99), "a:993").unwrap_err(),
            LimitError::ConnectRate
        );
        assert!(state
            .record_attempt(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), "a:993")
            .is_ok());
    }

    #[test]
    fn idle_attempt_rows_are_garbage_collected() {
        let state = Arc::new(LimitState::new(LimitsConfig {
            connects_per_ip: 8,
            connects_per_ip_window: Duration::from_millis(40),
            distinct_dests_window: Duration::from_millis(40),
            ..LimitsConfig::unlimited()
        }));
        state.record_attempt(ip(1), "a:993").unwrap();
        assert_eq!(state.tracked_ip_count(), 1);
        std::thread::sleep(Duration::from_millis(50));
        // Force GC regardless of the 30s interval.
        {
            let mut g = state.lock();
            g.gc_idle(Instant::now());
        }
        assert_eq!(state.tracked_ip_count(), 0);
    }

    #[test]
    fn tracked_ip_cap_rejects_new_prefixes() {
        let state = Arc::new(LimitState::new(LimitsConfig {
            max_tracked_ips: 2,
            ..LimitsConfig::unlimited()
        }));
        state.record_attempt(ip(1), "a:993").unwrap();
        state
            .record_attempt(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), "a:993")
            .unwrap();
        assert_eq!(
            state
                .record_attempt(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), "a:993")
                .unwrap_err(),
            LimitError::GlobalConnectRate
        );
    }

    #[test]
    fn rate_window_expires() {
        let state = Arc::new(LimitState::new(LimitsConfig {
            connects_per_ip: 1,
            connects_per_ip_window: Duration::from_millis(40),
            ..LimitsConfig::unlimited()
        }));
        state.record_attempt(ip(1), "a:993").unwrap();
        assert_eq!(
            state.record_attempt(ip(1), "a:993").unwrap_err(),
            LimitError::ConnectRate
        );
        std::thread::sleep(Duration::from_millis(50));
        state.record_attempt(ip(1), "a:993").unwrap();
    }
}
