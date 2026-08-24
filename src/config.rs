use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

use rusty_paseto::core::{Local, PasetoSymmetricKey, V4};

use crate::dest::{DestPolicy, DEFAULT_ALLOWED_PORTS};
use crate::limits::LimitsConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// Require a Paseto v4.local token bound to `remote` with a non-empty `exp`.
    Paseto,
    /// Public reflector: dest policy + rate limits are the gate. Token ignored.
    Public,
}

pub struct Config {
    pub bind_addr: String,
    pub listen_port: u16,
    #[allow(dead_code)]
    pub log_level: slog::Level,

    pub secret_key: Option<PasetoSymmetricKey<V4, Local>>,
    pub metrics_auth_key: Option<String>,
    pub auth_mode: AuthMode,

    /// How long the WebSocket may be idle before we send a keepalive ping.
    /// Idle alone never closes the connection (IMAP clients are often quiet).
    pub ws_idle_timeout: Duration,
    pub ws_write_timeout: Duration,
    pub tcp_write_timeout: Duration,
    pub tcp_connect_timeout: Duration,
    pub dns_timeout: Duration,

    pub dest: DestPolicy,
    pub limits: LimitsConfig,
    /// Combined up+down bytes on a single session. `0` = unlimited.
    pub max_bytes_per_connection: u64,
    /// Hard session lifetime. `Duration::ZERO` = unlimited.
    pub max_lifetime: Duration,
    /// Honour `CF-Connecting-IP` (and `X-Real-IP`) instead of the TCP peer.
    /// Headers are used only when the TCP peer is in [`Self::trusted_proxies`].
    pub trust_forwarded_client_ip: bool,
    /// CIDRs of reverse proxies allowed to set the forwarded-client header.
    /// Empty ⇒ forwarded headers are ignored even if trust is enabled.
    pub trusted_proxies: Vec<Cidr>,
    /// Run TLS-SNI / IMAP / SMTP greeting probes on well-known mail ports.
    pub require_protocol_probe: bool,
    /// If non-empty, a browser `Origin` must be in this set. Requests with
    /// no Origin (native clients) are still accepted. `*` allows any Origin.
    pub allowed_origins: HashSet<String>,
    /// If non-empty, the HTTP `Host` header must match one of these
    /// values (case-insensitive, optional `:port`).
    pub allowed_hosts: HashSet<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bind_addr: String::from("0.0.0.0"),
            listen_port: 9400,
            log_level: slog::Level::Info,
            secret_key: None,
            metrics_auth_key: None,
            auth_mode: AuthMode::Paseto,
            // 30s is a reasonable keepalive interval; idle IMAP is expected
            // and no longer kills the connection on its own.
            ws_idle_timeout: Duration::from_secs(30),
            ws_write_timeout: Duration::from_secs(30),
            tcp_write_timeout: Duration::from_secs(30),
            tcp_connect_timeout: Duration::from_secs(30),
            dns_timeout: Duration::from_secs(5),
            dest: DestPolicy::default(),
            limits: LimitsConfig::default(),
            max_bytes_per_connection: 250 * 1024 * 1024,
            max_lifetime: Duration::from_secs(24 * 3600),
            trust_forwarded_client_ip: false,
            trusted_proxies: Vec::new(),
            require_protocol_probe: true,
            allowed_origins: HashSet::new(),
            allowed_hosts: HashSet::new(),
        }
    }
}

impl Config {
    /// Loopback echo tests: no dest/rate/proto restrictions.
    pub fn for_tests() -> Self {
        Self {
            dest: DestPolicy::unrestricted(),
            limits: LimitsConfig::unlimited(),
            max_bytes_per_connection: 0,
            max_lifetime: Duration::ZERO,
            require_protocol_probe: false,
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub bits: u8,
}

impl Cidr {
    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        let (addr_s, bits) = if let Some((a, b)) = raw.split_once('/') {
            let addr: IpAddr = a.parse().ok()?;
            let bits: u8 = b.parse().ok()?;
            let max = if addr.is_ipv4() { 32 } else { 128 };
            if bits > max {
                return None;
            }
            (addr, bits)
        } else {
            let addr: IpAddr = raw.parse().ok()?;
            let bits = if addr.is_ipv4() { 32 } else { 128 };
            (addr, bits)
        };
        Some(Cidr { addr: addr_s, bits })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(prefix), IpAddr::V4(x)) => {
                let mask = if self.bits == 0 {
                    0
                } else {
                    !0u32 << (32 - self.bits)
                };
                (u32::from(x) & mask) == (u32::from(prefix) & mask)
            }
            (IpAddr::V6(prefix), IpAddr::V6(x)) => {
                if let (Some(p4), Some(x4)) = (prefix.to_ipv4_mapped(), x.to_ipv4_mapped()) {
                    return Cidr {
                        addr: IpAddr::V4(p4),
                        bits: self.bits.min(32),
                    }
                    .contains(IpAddr::V4(x4));
                }
                let mask = if self.bits == 0 {
                    0
                } else {
                    !0u128 << (128 - self.bits)
                };
                (u128::from(x) & mask) == (u128::from(prefix) & mask)
            }
            (IpAddr::V4(prefix), IpAddr::V6(x)) => x
                .to_ipv4_mapped()
                .map(|v4| {
                    Cidr {
                        addr: IpAddr::V4(prefix),
                        bits: self.bits,
                    }
                    .contains(IpAddr::V4(v4))
                })
                .unwrap_or(false),
            _ => false,
        }
    }
}

pub fn parse_cidrs(raw: &str) -> Vec<Cidr> {
    raw.split(',')
        .filter_map(|p| Cidr::parse(p))
        .collect()
}

pub fn parse_allowed_ports(raw: &str) -> Option<HashSet<u16>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Some(HashSet::from(DEFAULT_ALLOWED_PORTS));
    }
    if raw.eq_ignore_ascii_case("any") || raw == "*" {
        return None;
    }
    let mut set = HashSet::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Ok(p) = part.parse::<u16>() {
            if p != 0 {
                set.insert(p);
            }
        }
    }
    Some(set)
}

/// Comma-separated list. Empty / unset → empty set (check disabled).
pub fn parse_csv_set(raw: &str) -> HashSet<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Normalize a Host header or allowlist entry for comparison.
pub fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Normalize an Origin (`scheme://host[:port]`) for comparison.
pub fn normalize_origin(origin: &str) -> String {
    let origin = origin.trim();
    if origin == "*" {
        return "*".to_string();
    }
    if let Some((scheme, rest)) = origin.split_once("://") {
        format!("{}://{}", scheme.to_ascii_lowercase(), normalize_host(rest))
    } else {
        origin.to_ascii_lowercase()
    }
}

pub fn env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}

pub fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

pub fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

pub fn env_secs(key: &str, default: Duration) -> Duration {
    match std::env::var(key) {
        Ok(v) => Duration::from_secs(v.parse().unwrap_or(default.as_secs())),
        Err(_) => default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ports_default_and_any() {
        assert_eq!(
            parse_allowed_ports(""),
            Some(HashSet::from(DEFAULT_ALLOWED_PORTS))
        );
        assert_eq!(parse_allowed_ports("any"), None);
        assert_eq!(parse_allowed_ports("*"), None);
        assert_eq!(
            parse_allowed_ports("993, 587"),
            Some(HashSet::from([993, 587]))
        );
    }

    #[test]
    fn csv_set_and_origin_host_normalize() {
        let set = parse_csv_set(" https://App.Example.com , * ");
        assert!(set.contains("https://App.Example.com"));
        assert!(set.contains("*"));
        assert_eq!(
            normalize_origin("HTTPS://APP.EXAMPLE.COM"),
            "https://app.example.com"
        );
        assert_eq!(normalize_host("Proxy.Example.COM:443"), "proxy.example.com:443");
    }

    #[test]
    fn cidr_parse_and_contains() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains("10.1.2.3".parse().unwrap()));
        assert!(!c.contains("11.0.0.1".parse().unwrap()));
        let one = Cidr::parse("127.0.0.1").unwrap();
        assert!(one.contains("127.0.0.1".parse().unwrap()));
        assert!(!one.contains("127.0.0.2".parse().unwrap()));
        let v6 = Cidr::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8::1".parse().unwrap()));
        assert!(!v6.contains("2001:db9::1".parse().unwrap()));
    }
}
