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
    /// If set, `/metrics` is served only on this bind address (e.g. `127.0.0.1:9401`).
    pub metrics_bind: Option<String>,
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
    /// Honour `CF-Connecting-IP`, `X-Real-IP`, then `X-Forwarded-For`
    /// (Scaleway Serverless) instead of the TCP peer. Headers are used only
    /// when the TCP peer is in [`Self::trusted_proxies`].
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
    /// Max WebSocket message size (tungstenite default is 64 MiB).
    pub ws_max_message_bytes: usize,
    /// Max WebSocket frame size (tungstenite default is 16 MiB).
    pub ws_max_frame_bytes: usize,
    /// Reject Paseto tokens whose `exp` is further ahead than this.
    /// `Duration::ZERO` disables the cap.
    pub paseto_max_ttl: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bind_addr: String::from("0.0.0.0"),
            listen_port: 9400,
            log_level: slog::Level::Info,
            secret_key: None,
            metrics_auth_key: None,
            metrics_bind: None,
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
            ws_max_message_bytes: 1024 * 1024,
            ws_max_frame_bytes: 256 * 1024,
            paseto_max_ttl: Duration::from_secs(3600),
        }
    }
}

impl Config {
    /// Misconfigurations that make a public deployment unsafe.
    /// An empty list means the process may listen on the internet.
    pub fn public_safety_errors(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.dest.allowed_ports.is_none() {
            errors.push("MAILINER_ALLOWED_PORTS=any/* opens every TCP port".to_string());
        }
        if self.dest.allow_private_destinations {
            errors.push(
                "MAILINER_ALLOW_PRIVATE_DESTS=1 enables SSRF to RFC1918/loopback".to_string(),
            );
        }
        if self.dest.allow_ip_literals {
            errors.push("MAILINER_ALLOW_IP_LITERALS=1 allows raw IP destinations".to_string());
        }
        if !self.require_protocol_probe {
            errors.push(
                "MAILINER_REQUIRE_PROTOCOL_PROBE=0 disables the mail-protocol probes".to_string(),
            );
        }
        if self.trust_forwarded_client_ip && self.trusted_proxies.is_empty() {
            errors.push(
                "MAILINER_TRUST_FORWARDED_CLIENT_IP=1 requires MAILINER_TRUSTED_PROXIES"
                    .to_string(),
            );
        }
        if self.auth_mode == AuthMode::Public
            && (self.allowed_origins.is_empty() || self.allowed_origins.contains("*"))
        {
            errors
                .push("MAILINER_AUTH=public requires MAILINER_ALLOWED_ORIGINS (not *)".to_string());
        }
        let caps = [
            (
                "MAILINER_MAX_GLOBAL_CONNECTIONS",
                self.limits.max_global_connections == 0,
            ),
            (
                "MAILINER_MAX_CONNS_PER_IP",
                self.limits.max_conns_per_ip == 0,
            ),
            (
                "MAILINER_CONNECTS_PER_IP_PER_MIN",
                self.limits.connects_per_ip == 0,
            ),
            (
                "MAILINER_MAX_BYTES_PER_CONNECTION",
                self.max_bytes_per_connection == 0,
            ),
            (
                "MAILINER_MAX_BYTES_PER_IP_PER_HOUR",
                self.limits.max_bytes_per_ip == 0,
            ),
            ("MAILINER_MAX_LIFETIME_SECS", self.max_lifetime.is_zero()),
        ];
        for (name, unlimited) in caps {
            if unlimited {
                errors.push(format!("{name}=0 disables that cap"));
            }
        }
        errors
    }

    /// Loopback echo tests: no dest/rate/proto restrictions.
    #[cfg(test)]
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
    raw.split(',').filter_map(Cidr::parse).collect()
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
        assert_eq!(
            normalize_host("Proxy.Example.COM:443"),
            "proxy.example.com:443"
        );
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

    #[test]
    fn default_config_is_public_safe() {
        assert!(Config::default().public_safety_errors().is_empty());
    }

    #[test]
    fn test_config_is_not_public_safe() {
        assert!(!Config::for_tests().public_safety_errors().is_empty());
    }

    #[test]
    fn public_auth_requires_origin_allowlist() {
        let mut c = Config {
            auth_mode: AuthMode::Public,
            ..Config::default()
        };
        assert!(c
            .public_safety_errors()
            .iter()
            .any(|e| e.contains("ALLOWED_ORIGINS")));
        c.allowed_origins.insert("https://app.example".into());
        assert!(c.public_safety_errors().is_empty());
    }
}
