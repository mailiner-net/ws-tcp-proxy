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

    // glibc getaddrinfo accepts dword / octal / hex / short IPv4 forms that
    // Rust's IpAddr parser rejects. Treat them as literals so the IP-literal
    // and private-IP policies still apply (otherwise `134744072:993` is a
    // "hostname" that resolves to 8.8.8.8).
    if let Some(v4) = parse_loose_ipv4(host_raw) {
        let ip = IpAddr::V4(v4);
        return Ok(Remote {
            host: ip_canonical(ip),
            port,
            ip_literal: Some(ip),
        });
    }

    let host = normalize_hostname(host_raw);
    if !is_valid_dns_hostname(&host) {
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

/// DNS hostname max length (RFC 1035), excluding a trailing root dot.
const MAX_HOSTNAME_LEN: usize = 253;
const MAX_DNS_LABEL_LEN: usize = 63;

/// True if `host` is a plausible DNS name (LDH labels). Used to reject
/// spaces, slashes, NULs, and arbitrarily long attacker-controlled strings
/// before they are stored in limit maps or sent to the resolver.
pub fn is_valid_dns_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > MAX_HOSTNAME_LEN {
        return false;
    }
    if host.starts_with('.') || host.contains("..") {
        return false;
    }
    host.split('.').all(is_valid_dns_label)
}

fn is_valid_dns_label(label: &str) -> bool {
    let len = label.len();
    if len == 0 || len > MAX_DNS_LABEL_LEN {
        return false;
    }
    let bytes = label.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() || !bytes[len - 1].is_ascii_alphanumeric() {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}

/// inet_aton-style IPv4: 1–4 dotted parts, each decimal, `0`-octal, or `0x`-hex.
/// Matches the forms glibc `getaddrinfo` will turn into an A record without DNS.
fn parse_loose_ipv4(s: &str) -> Option<Ipv4Addr> {
    if s.is_empty() || s.len() > 32 {
        return None;
    }
    let parts: Vec<&str> = s.split('.').collect();
    if !(1..=4).contains(&parts.len()) || parts.iter().any(|p| p.is_empty()) {
        return None;
    }
    let mut nums = [0u32; 4];
    for (i, part) in parts.iter().enumerate() {
        nums[i] = parse_ipv4_component(part)?;
    }
    let addr = match parts.len() {
        1 => nums[0],
        2 => {
            if nums[0] > 0xff || nums[1] > 0x00ff_ffff {
                return None;
            }
            (nums[0] << 24) | nums[1]
        }
        3 => {
            if nums[0] > 0xff || nums[1] > 0xff || nums[2] > 0xffff {
                return None;
            }
            (nums[0] << 24) | (nums[1] << 16) | nums[2]
        }
        4 => {
            if nums.iter().any(|n| *n > 0xff) {
                return None;
            }
            (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]
        }
        _ => return None,
    };
    Some(Ipv4Addr::from(addr))
}

fn parse_ipv4_component(s: &str) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    if let Some(hex) = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
    {
        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        return u32::from_str_radix(hex, 16).ok();
    }
    if s.len() > 1 && s.starts_with('0') {
        if !s.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
            return None;
        }
        return u32::from_str_radix(s, 8).ok();
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
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
    dns_timeout: Duration,
) -> Result<Vec<SocketAddr>, DestError> {
    if let Some(ip) = remote.ip_literal {
        // Already checked in check_policy; still filter defensively.
        if !policy.allow_private_destinations && !is_global_unicast(ip) {
            return Err(DestError::PrivateIp);
        }
        return Ok(vec![SocketAddr::new(ip, remote.port)]);
    }

    let looked_up = timeout(dns_timeout, tokio::net::lookup_host((remote.host.as_str(), remote.port)))
        .await
        .map_err(|_| DestError::Dns)?
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
    if let Some(v4) = embedded_ipv4(ip) {
        return is_global_v4(v4);
    }
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || ip.is_unicast_link_local()
        || ip.is_unique_local()
    {
        return false;
    }
    // IETF protocol assignments 2001::/23 (Teredo 2001::/32, ORCHID, …).
    if ipv6_in(ip, Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23) {
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
    // NAT64 local-use 64:ff9b:1::/48 (well-known /96 is handled via embedded_ipv4).
    if ipv6_in(ip, Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0, 0), 48) {
        return false;
    }
    true
}

/// IPv4 embedded in IPv6: mapped (`::ffff:x.x.x.x`), compatible (`::x.x.x.x`),
/// SIIT translated (`64:ff9b::x.x.x.x`), 6to4 (`2002:xxyy:xxzz::`), or
/// NAT64 well-known / local-use prefixes.
fn embedded_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return Some(v4);
    }
    let s = ip.segments();
    // Deprecated IPv4-compatible ::x.x.x.x (not mapped).
    if s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
        return ip.to_ipv4();
    }
    // NAT64 well-known 64:ff9b::/96
    if s[0] == 0x64 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
        return Some(Ipv4Addr::new(
            (s[6] >> 8) as u8,
            s[6] as u8,
            (s[7] >> 8) as u8,
            s[7] as u8,
        ));
    }
    // 6to4 2002:V4ADDR::/48
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::new(
            (s[1] >> 8) as u8,
            s[1] as u8,
            (s[2] >> 8) as u8,
            s[2] as u8,
        ));
    }
    None
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
    fn parse_loose_ipv4_forms_as_literals() {
        let cases = [
            ("134744072:993", "8.8.8.8"),
            ("0x08080808:993", "8.8.8.8"),
            ("0X8.8.8.8:993", "8.8.8.8"),
            ("8.8.8:993", "8.8.0.8"),
            ("1.2:993", "1.0.0.2"),
            ("127.1:993", "127.0.0.1"),
            ("0177.0.0.1:993", "127.0.0.1"),
            ("0x7f.0.0.1:993", "127.0.0.1"),
            ("0:993", "0.0.0.0"),
            ("123:993", "0.0.0.123"),
        ];
        for (raw, canon) in cases {
            let r = parse_remote(raw).expect(raw);
            assert_eq!(r.host, canon, "{raw}");
            assert_eq!(r.ip_literal.unwrap().to_string(), canon, "{raw}");
        }
    }

    #[test]
    fn default_policy_rejects_loose_ipv4_literals() {
        let p = DestPolicy::default();
        for raw in ["134744072:993", "127.1:993", "0x08080808:993", "8.8.8:993"] {
            let r = parse_remote(raw).unwrap();
            assert_eq!(check_policy(&r, &p), Err(DestError::IpLiteral), "{raw}");
        }
    }

    #[test]
    fn parse_rejects_invalid_hostnames() {
        for raw in [
            "has space.com:993",
            "has/slash.com:993",
            "has@at.com:993",
            "-leading-hyphen.com:993",
            "trailing-hyphen-.com:993",
            "a..b.com:993",
            &format!("{}.com:993", "a".repeat(64)),
            &format!("{}:993", format!("{}.", "a".repeat(50)).repeat(6)),
        ] {
            assert_eq!(parse_remote(raw), Err(DestError::InvalidRemote), "{raw}");
        }
    }

    #[test]
    fn parse_accepts_punycode_and_localhost() {
        let r = parse_remote("xn--mnchen-3ya.de:993").unwrap();
        assert_eq!(r.host, "xn--mnchen-3ya.de");
        assert!(r.ip_literal.is_none());
        let r = parse_remote("localhost:993").unwrap();
        assert_eq!(r.host, "localhost");
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

        // Teredo / ORCHID (2001::/23)
        assert!(!is_global_unicast("2001::1".parse().unwrap()));
        // NAT64 well-known prefix embedding RFC1918 / public IPv4
        assert!(!is_global_unicast("64:ff9b::a00:1".parse().unwrap())); // 10.0.0.1
        assert!(!is_global_unicast("64:ff9b::7f00:1".parse().unwrap())); // 127.0.0.1
        assert!(is_global_unicast("64:ff9b::808:808".parse().unwrap())); // 8.8.8.8
        assert!(!is_global_unicast("64:ff9b:1::1".parse().unwrap()));
        // 6to4 embedding RFC1918 / public IPv4
        assert!(!is_global_unicast("2002:0a00:0001::1".parse().unwrap())); // 10.0.0.1
        assert!(is_global_unicast("2002:0808:0808::1".parse().unwrap())); // 8.8.8.8
    }

    #[tokio::test]
    async fn resolve_localhost_private_denied() {
        let r = parse_remote("localhost:993").unwrap();
        let p = DestPolicy::default();
        // hostname, not a literal — policy check passes; resolve filters loopback.
        assert!(check_policy(&r, &p).is_ok());
        assert_eq!(
            resolve_filtered(&r, &p, Duration::from_secs(2))
                .await
                .unwrap_err(),
            DestError::PrivateIp
        );
    }

    #[tokio::test]
    async fn resolve_localhost_private_allowed() {
        let r = parse_remote("localhost:993").unwrap();
        let p = DestPolicy::unrestricted();
        let addrs = resolve_filtered(&r, &p, Duration::from_secs(2))
            .await
            .unwrap();
        assert!(addrs.iter().any(|a| a.ip().is_loopback()));
        assert!(addrs.iter().all(|a| a.port() == 993));
    }
}
