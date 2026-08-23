//! Destination policy: parse `remote=host:port`, allowlist ports, reject
//! non-global IPs (SSRF), and resolve then connect to the filtered sockaddr
//! so a later DNS answer cannot rebind us onto a private address.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

/// IMAP / IMAPS / SMTP submission / SMTPS. Not 25 (open-relay spam).
pub const DEFAULT_ALLOWED_PORTS: [u16; 4] = [143, 993, 465, 587];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestError {
    InvalidRemote,
    BadPort,
    IpLiteral,
    PrivateIp,
    Dns,
    Connect,
}



#[derive(Debug, Clone)]
pub struct DestPolicy {
    /// `None` = any port (tests / emergency). Production sets the mail ports.
    pub allowed_ports: Option<HashSet<u16>>,
    pub allow_private_destinations: bool,
    pub allow_ip_literals: bool,
}

impl Default for DestPolicy {
    fn default() -> Self {
        Self {
            allowed_ports: Some(HashSet::from(DEFAULT_ALLOWED_PORTS)),
            allow_private_destinations: false,
            allow_ip_literals: false,
        }
    }
}

impl DestPolicy {
    pub fn unrestricted() -> Self {
        Self {
            allowed_ports: None,
            allow_private_destinations: true,
            allow_ip_literals: true,
        }
    }

    pub fn port_allowed(&self, port: u16) -> bool {
        match &self.allowed_ports {
            None => true,
            Some(set) => set.contains(&port),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    /// Normalized hostname (lowercase, no trailing dots) or canonical IP text.
    pub host: String,
    pub port: u16,
    pub ip_literal: Option<IpAddr>,
}

impl Remote {
    pub fn dest_key(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Parse `host:port` or `[ipv6]:port`.
pub fn parse_remote(raw: &str) -> Result<Remote, DestError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(DestError::InvalidRemote);
    }

    let (host_raw, port_str) = if let Some(rest) = raw.strip_prefix('[') {
        let close = rest.find(']').ok_or(DestError::InvalidRemote)?;
        let host = &rest[..close];
        let after = &rest[close + 1..];
        let port = after.strip_prefix(':').ok_or(DestError::InvalidRemote)?;
        (host, port)
    } else {
        let (host, port) = raw.rsplit_once(':').ok_or(DestError::InvalidRemote)?;
        if host.is_empty() || host.contains(':') {
            // Unbracketed IPv6 is ambiguous with :port.
            return Err(DestError::InvalidRemote);
        }
        (host, port)
    };

    if host_raw.is_empty() {
        return Err(DestError::InvalidRemote);
    }
    let port: u16 = port_str.parse().map_err(|_| DestError::InvalidRemote)?;
    if port == 0 {
        return Err(DestError::InvalidRemote);
    }

    if let Ok(ip) = host_raw.parse::<IpAddr>() {
        return Ok(Remote {
            host: ip_canonical(ip),
            port,
            ip_literal: Some(ip),
        });
    }

    let host = normalize_hostname(host_raw);
    if host.is_empty() {
        return Err(DestError::InvalidRemote);
    }

    Ok(Remote {
        host,
        port,
        ip_literal: None,
    })
}

pub fn normalize_hostname(host: &str) -> String {
    host.trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn ip_canonical(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.to_string();
            }
            v6.to_string()
        }
        IpAddr::V4(v4) => v4.to_string(),
    }
}

pub fn check_policy(remote: &Remote, policy: &DestPolicy) -> Result<(), DestError> {
    if !policy.port_allowed(remote.port) {
        return Err(DestError::BadPort);
    }
    if remote.ip_literal.is_some() && !policy.allow_ip_literals {
        return Err(DestError::IpLiteral);
    }
    if let Some(ip) = remote.ip_literal {
        if !policy.allow_private_destinations && !is_global_unicast(ip) {
            return Err(DestError::PrivateIp);
        }
    }
    Ok(())
}

/// Resolve `remote` and keep only policy-allowed addresses. The caller must
/// connect to one of these sockaddrs (not re-resolve) to prevent DNS rebinding.
pub async fn resolve_filtered(
    remote: &Remote,
    policy: &DestPolicy,
) -> Result<Vec<SocketAddr>, DestError> {
    if let Some(ip) = remote.ip_literal {
        // Already checked in check_policy; still filter defensively.
        if !policy.allow_private_destinations && !is_global_unicast(ip) {
            return Err(DestError::PrivateIp);
        }
        return Ok(vec![SocketAddr::new(ip, remote.port)]);
    }

    let looked_up = tokio::net::lookup_host((remote.host.as_str(), remote.port))
        .await
        .map_err(|_| DestError::Dns)?;

    let addrs: Vec<SocketAddr> = looked_up
        .filter(|a| policy.allow_private_destinations || is_global_unicast(a.ip()))
        .collect();

    if addrs.is_empty() {
        return Err(DestError::PrivateIp);
    }
    Ok(addrs)
}

pub async fn connect_addrs(
    addrs: &[SocketAddr],
    connect_timeout: Duration,
) -> Result<TcpStream, DestError> {
    let mut last_err = DestError::Connect;
    for addr in addrs {
        match timeout(connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(_)) => last_err = DestError::Connect,
            Err(_) => last_err = DestError::Connect,
        }
    }
    Err(last_err)
}

/// True if `ip` is a globally routable unicast address we are willing to dial.
pub fn is_global_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_global_v4(v4),
        IpAddr::V6(v6) => is_global_v6(v6),
    }
}

fn is_global_v4(ip: Ipv4Addr) -> bool {
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
    {
        return false;
    }
    // 0.0.0.0/8 ("this network") — `is_unspecified` is only 0.0.0.0.
    if ipv4_in(ip, Ipv4Addr::new(0, 0, 0, 0), 8) {
        return false;
    }
    // CGNAT 100.64.0.0/10
    if ipv4_in(ip, Ipv4Addr::new(100, 64, 0, 0), 10) {
        return false;
    }
    // IETF protocol assignments 192.0.0.0/24 (TEST-NET-1 is 192.0.2.0/24 via is_documentation).
    if ipv4_in(ip, Ipv4Addr::new(192, 0, 0, 0), 24) {
        return false;
    }
    // Benchmarking 198.18.0.0/15
    if ipv4_in(ip, Ipv4Addr::new(198, 18, 0, 0), 15) {
        return false;
    }
    // Reserved 240.0.0.0/4
    if ipv4_in(ip, Ipv4Addr::new(240, 0, 0, 0), 4) {
        return false;
    }
    true
}

fn is_global_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_global_v4(v4);
    }
    // Deprecated IPv4-compatible ::x.x.x.x (not mapped).
    if let Some(v4) = ip.to_ipv4() {
        if ip.segments()[0] == 0
            && ip.segments()[1] == 0
            && ip.segments()[2] == 0
            && ip.segments()[3] == 0
            && ip.segments()[4] == 0
            && ip.segments()[5] == 0
        {
            return is_global_v4(v4);
        }
    }
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || ip.is_unicast_link_local()
        || ip.is_unique_local()
    {
        return false;
    }
    // Documentation 2001:db8::/32
    if ipv6_in(ip, Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32) {
        return false;
    }
    // Discard-Only Prefix 100::/64
    if ipv6_in(ip, Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0), 64) {
        return false;
    }
    true
}

fn ipv4_in(ip: Ipv4Addr, prefix: Ipv4Addr, bits: u8) -> bool {
    if bits == 0 {
        return true;
    }
    let mask = !0u32 << (32 - bits);
    (u32::from(ip) & mask) == (u32::from(prefix) & mask)
}

fn ipv6_in(ip: Ipv6Addr, prefix: Ipv6Addr, bits: u8) -> bool {
    if bits == 0 {
        return true;
    }
    let ip_b = u128::from(ip);
    let p_b = u128::from(prefix);
    let mask = !0u128 << (128 - bits);
    (ip_b & mask) == (p_b & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hostname_port() {
        let r = parse_remote("imap.gmail.com:993").unwrap();
        assert_eq!(r.host, "imap.gmail.com");
        assert_eq!(r.port, 993);
        assert!(r.ip_literal.is_none());
    }

    #[test]
    fn parse_normalizes_hostname() {
        let r = parse_remote("IMAP.Gmail.COM.:993").unwrap();
        assert_eq!(r.host, "imap.gmail.com");
    }

    #[test]
    fn parse_ipv4() {
        let r = parse_remote("8.8.8.8:993").unwrap();
        assert_eq!(r.ip_literal, Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert_eq!(r.port, 993);
    }

    #[test]
    fn parse_ipv6() {
        let r = parse_remote("[2001:db8::1]:993").unwrap();
        assert!(r.ip_literal.unwrap().is_ipv6());
        assert_eq!(r.port, 993);
    }

    #[test]
    fn parse_rejects_unbracketed_ipv6() {
        assert_eq!(parse_remote("::1:993"), Err(DestError::InvalidRemote));
    }

    #[test]
    fn parse_rejects_missing_port() {
        assert_eq!(
            parse_remote("imap.gmail.com"),
            Err(DestError::InvalidRemote)
        );
    }

    #[test]
    fn parse_rejects_port_zero() {
        assert_eq!(
            parse_remote("imap.gmail.com:0"),
            Err(DestError::InvalidRemote)
        );
    }

    #[test]
    fn default_policy_allows_mail_ports_only() {
        let p = DestPolicy::default();
        for port in DEFAULT_ALLOWED_PORTS {
            let r = parse_remote(&format!("imap.example.com:{port}")).unwrap();
            assert!(check_policy(&r, &p).is_ok(), "port {port}");
        }
        let r = parse_remote("imap.example.com:25").unwrap();
        assert_eq!(check_policy(&r, &p), Err(DestError::BadPort));
        let r = parse_remote("imap.example.com:22").unwrap();
        assert_eq!(check_policy(&r, &p), Err(DestError::BadPort));
        let r = parse_remote("imap.example.com:443").unwrap();
        assert_eq!(check_policy(&r, &p), Err(DestError::BadPort));
    }

    #[test]
    fn default_policy_rejects_ip_literals() {
        let p = DestPolicy::default();
        let r = parse_remote("8.8.8.8:993").unwrap();
        assert_eq!(check_policy(&r, &p), Err(DestError::IpLiteral));
    }

    #[test]
    fn private_literal_rejected_even_when_literals_allowed() {
        let p = DestPolicy {
            allow_ip_literals: true,
            allow_private_destinations: false,
            ..DestPolicy::default()
        };
        for raw in [
            "127.0.0.1:993",
            "10.0.0.1:993",
            "192.168.1.1:993",
            "172.16.0.1:993",
            "169.254.169.254:993",
            "100.64.0.1:993",
            "[::1]:993",
            "[fc00::1]:993",
            "[fe80::1]:993",
            "[::ffff:127.0.0.1]:993",
        ] {
            let r = parse_remote(raw).unwrap();
            assert_eq!(check_policy(&r, &p), Err(DestError::PrivateIp), "{raw}");
        }
    }

    #[test]
    fn public_literal_allowed_when_literals_on() {
        let p = DestPolicy {
            allow_ip_literals: true,
            allow_private_destinations: false,
            ..DestPolicy::default()
        };
        let r = parse_remote("8.8.8.8:993").unwrap();
        assert!(check_policy(&r, &p).is_ok());
    }

    #[test]
    fn global_unicast_classification() {
        assert!(!is_global_unicast("0.0.0.1".parse().unwrap()));
        assert!(!is_global_unicast("127.0.0.1".parse().unwrap()));
        assert!(!is_global_unicast("10.1.2.3".parse().unwrap()));
        assert!(!is_global_unicast("192.168.0.1".parse().unwrap()));
        assert!(!is_global_unicast("172.31.255.255".parse().unwrap()));
        assert!(!is_global_unicast("169.254.169.254".parse().unwrap()));
        assert!(!is_global_unicast("100.64.0.1".parse().unwrap()));
        assert!(!is_global_unicast("224.0.0.1".parse().unwrap()));
        assert!(!is_global_unicast("255.255.255.255".parse().unwrap()));
        assert!(!is_global_unicast("192.0.2.1".parse().unwrap()));
        assert!(!is_global_unicast("198.18.0.1".parse().unwrap()));
        assert!(!is_global_unicast("240.0.0.1".parse().unwrap()));
        assert!(is_global_unicast("8.8.8.8".parse().unwrap()));
        assert!(is_global_unicast("1.1.1.1".parse().unwrap()));

        assert!(!is_global_unicast("::1".parse().unwrap()));
        assert!(!is_global_unicast("fc00::1".parse().unwrap()));
        assert!(!is_global_unicast("fe80::1".parse().unwrap()));
        assert!(!is_global_unicast("2001:db8::1".parse().unwrap()));
        assert!(!is_global_unicast("::ffff:10.0.0.1".parse().unwrap()));
        assert!(is_global_unicast("2001:4860:4860::8888".parse().unwrap()));
    }

    #[tokio::test]
    async fn resolve_localhost_private_denied() {
        let r = parse_remote("localhost:993").unwrap();
        let p = DestPolicy::default();
        // hostname, not a literal — policy check passes; resolve filters loopback.
        assert!(check_policy(&r, &p).is_ok());
        assert_eq!(
            resolve_filtered(&r, &p).await.unwrap_err(),
            DestError::PrivateIp
        );
    }

    #[tokio::test]
    async fn resolve_localhost_private_allowed() {
        let r = parse_remote("localhost:993").unwrap();
        let p = DestPolicy::unrestricted();
        let addrs = resolve_filtered(&r, &p).await.unwrap();
        assert!(addrs.iter().any(|a| a.ip().is_loopback()));
        assert!(addrs.iter().all(|a| a.port() == 993));
    }
}
