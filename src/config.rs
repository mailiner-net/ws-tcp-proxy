use std::collections::HashSet;
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

    pub dest: DestPolicy,
    pub limits: LimitsConfig,
    /// Combined up+down bytes on a single session. `0` = unlimited.
    pub max_bytes_per_connection: u64,
    /// Hard session lifetime. `Duration::ZERO` = unlimited.
    pub max_lifetime: Duration,
    /// Honour `CF-Connecting-IP` (and `X-Real-IP`) instead of the TCP peer.
    /// Only enable when the process is behind a trusted reverse proxy.
    pub trust_forwarded_client_ip: bool,
    /// Run TLS-SNI / IMAP / SMTP greeting probes on well-known mail ports.
    pub require_protocol_probe: bool,
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
            dest: DestPolicy::default(),
            limits: LimitsConfig::default(),
            max_bytes_per_connection: 250 * 1024 * 1024,
            max_lifetime: Duration::from_secs(24 * 3600),
            trust_forwarded_client_ip: false,
            require_protocol_probe: true,
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
}
