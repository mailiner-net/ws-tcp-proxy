//! Cheap first-hop protocol checks that do not require decrypting mail TLS.
//!
//! * 993 / 465 (implicit TLS): first client bytes must be a TLS ClientHello;
//!   if SNI is present and the destination is a hostname, it must match.
//! * 143 (IMAP STARTTLS): server greeting must look like IMAP (`* …`).
//! * 587 (SMTP submission): server greeting must start with `220`.

use crate::dest::normalize_hostname;

const MAX_TLS_RECORD: usize = 16 * 1024;
const MAX_GREETING: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeKind {
    TlsSni,
    ImapGreeting,
    SmtpGreeting,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    NotTls,
    Malformed,
    SniMismatch,
    MissingSni,
    BadGreeting,
}

impl ProtoError {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProtoError::NotTls => "not_tls",
            ProtoError::Malformed => "malformed",
            ProtoError::SniMismatch => "sni_mismatch",
            ProtoError::MissingSni => "missing_sni",
            ProtoError::BadGreeting => "bad_greeting",
        }
    }
}

pub fn probe_for_port(port: u16) -> Option<ProbeKind> {
    match port {
        993 | 465 => Some(ProbeKind::TlsSni),
        143 => Some(ProbeKind::ImapGreeting),
        587 => Some(ProbeKind::SmtpGreeting),
        _ => None,
    }
}

/// How many more bytes we need before the TLS record is complete, or `None`
/// if the prefix is already invalid.
pub fn tls_record_needed(buf: &[u8]) -> Result<usize, ProtoError> {
    if buf.is_empty() {
        return Ok(5);
    }
    if buf[0] != 0x16 {
        return Err(ProtoError::NotTls);
    }
    if buf.len() < 5 {
        return Ok(5 - buf.len());
    }
    // SSLv3 / TLS 1.x (0x03 0x00..0x04). Reject obvious garbage.
    if buf[1] != 0x03 {
        return Err(ProtoError::NotTls);
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if record_len == 0 || record_len > MAX_TLS_RECORD {
        return Err(ProtoError::Malformed);
    }
    let total = 5 + record_len;
    if buf.len() >= total {
        Ok(0)
    } else {
        Ok(total - buf.len())
    }
}

pub fn validate_tls_client_hello(
    buf: &[u8],
    expected_host: &str,
    dest_is_ip_literal: bool,
) -> Result<(), ProtoError> {
    if tls_record_needed(buf)? != 0 {
        return Err(ProtoError::Malformed);
    }
    let sni = parse_sni(buf)?;
    if dest_is_ip_literal {
        return Ok(());
    }
    match sni {
        None => Err(ProtoError::MissingSni),
        Some(name) => {
            let got = normalize_hostname(&name);
            let want = normalize_hostname(expected_host);
            if got == want {
                Ok(())
            } else {
                Err(ProtoError::SniMismatch)
            }
        }
    }
}

/// Parse SNI hostname from a complete TLS handshake record containing a ClientHello.
pub fn parse_sni(record: &[u8]) -> Result<Option<String>, ProtoError> {
    if record.len() < 5 || record[0] != 0x16 {
        return Err(ProtoError::NotTls);
    }
    let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    let body = record.get(5..5 + record_len).ok_or(ProtoError::Malformed)?;

    // Handshake: type (1) + length (3) + ClientHello
    if body.len() < 4 || body[0] != 0x01 {
        return Err(ProtoError::NotTls);
    }
    let hs_len = u24(&body[1..4])?;
    let hello = body.get(4..4 + hs_len).ok_or(ProtoError::Malformed)?;

    // client_version (2) + random (32) + session_id
    let mut i = 2 + 32;
    let sid_len = *hello.get(i).ok_or(ProtoError::Malformed)? as usize;
    i += 1 + sid_len;
    let cs_len = u16_at(hello, i)? as usize;
    i += 2 + cs_len;
    let comp_len = *hello.get(i).ok_or(ProtoError::Malformed)? as usize;
    i += 1 + comp_len;

    if i == hello.len() {
        return Ok(None); // no extensions
    }
    let ext_len = u16_at(hello, i)? as usize;
    i += 2;
    let exts = hello.get(i..i + ext_len).ok_or(ProtoError::Malformed)?;

    let mut j = 0;
    while j + 4 <= exts.len() {
        let typ = u16::from_be_bytes([exts[j], exts[j + 1]]);
        let len = u16::from_be_bytes([exts[j + 2], exts[j + 3]]) as usize;
        j += 4;
        let data = exts.get(j..j + len).ok_or(ProtoError::Malformed)?;
        j += len;
        if typ == 0 {
            return parse_sni_extension(data);
        }
    }
    Ok(None)
}

fn parse_sni_extension(data: &[u8]) -> Result<Option<String>, ProtoError> {
    if data.len() < 2 {
        return Err(ProtoError::Malformed);
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let list = data.get(2..2 + list_len).ok_or(ProtoError::Malformed)?;
    let mut i = 0;
    while i + 3 <= list.len() {
        let name_type = list[i];
        let name_len = u16::from_be_bytes([list[i + 1], list[i + 2]]) as usize;
        i += 3;
        let name = list.get(i..i + name_len).ok_or(ProtoError::Malformed)?;
        i += name_len;
        if name_type == 0 {
            let s = std::str::from_utf8(name).map_err(|_| ProtoError::Malformed)?;
            if s.is_empty() {
                return Err(ProtoError::Malformed);
            }
            return Ok(Some(s.to_string()));
        }
    }
    Ok(None)
}

pub fn validate_greeting(buf: &[u8], kind: ProbeKind) -> Result<(), ProtoError> {
    // Skip leading CR/LF/whitespace so we look at the first real line.
    let start = buf
        .iter()
        .position(|b| !matches!(b, b'\r' | b'\n' | b' ' | b'\t'))
        .unwrap_or(buf.len());
    let line = &buf[start..];
    if line.is_empty() {
        return Err(ProtoError::BadGreeting);
    }
    match kind {
        ProbeKind::ImapGreeting => {
            // RFC 3501: greeting is untagged OK / PREAUTH / BYE.
            if line.starts_with(b"* ") {
                Ok(())
            } else {
                Err(ProtoError::BadGreeting)
            }
        }
        ProbeKind::SmtpGreeting => {
            if line.starts_with(b"220 ") || line.starts_with(b"220-") {
                Ok(())
            } else {
                Err(ProtoError::BadGreeting)
            }
        }
        ProbeKind::TlsSni => Err(ProtoError::BadGreeting),
    }
}

pub fn greeting_complete(buf: &[u8]) -> bool {
    buf.contains(&b'\n') || buf.len() >= MAX_GREETING
}

pub fn max_greeting_bytes() -> usize {
    MAX_GREETING
}

fn u24(b: &[u8]) -> Result<usize, ProtoError> {
    if b.len() < 3 {
        return Err(ProtoError::Malformed);
    }
    Ok(((b[0] as usize) << 16) | ((b[1] as usize) << 8) | (b[2] as usize))
}

fn u16_at(buf: &[u8], i: usize) -> Result<u16, ProtoError> {
    let s = buf.get(i..i + 2).ok_or(ProtoError::Malformed)?;
    Ok(u16::from_be_bytes([s[0], s[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn client_hello_with_sni(name: &str) -> Vec<u8> {
        let name_b = name.as_bytes();
        // SNI extension body: list_len + name_type + name_len + name
        let mut sni_body = Vec::new();
        let list_len = 1 + 2 + name_b.len();
        sni_body.extend_from_slice(&(list_len as u16).to_be_bytes());
        sni_body.push(0x00);
        sni_body.extend_from_slice(&(name_b.len() as u16).to_be_bytes());
        sni_body.extend_from_slice(name_b);

        let mut ext = Vec::new();
        ext.extend_from_slice(&0u16.to_be_bytes()); // type SNI
        ext.extend_from_slice(&(sni_body.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_body);

        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]); // client version TLS 1.2
        hello.extend_from_slice(&[0u8; 32]); // random
        hello.push(0); // session_id
        hello.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
        hello.extend_from_slice(&[0x00, 0x2f]);
        hello.push(1); // compression len
        hello.push(0);
        hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hello.extend_from_slice(&ext);

        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let hs_len = hello.len();
        hs.push(((hs_len >> 16) & 0xff) as u8);
        hs.push(((hs_len >> 8) & 0xff) as u8);
        hs.push((hs_len & 0xff) as u8);
        hs.extend_from_slice(&hello);

        let mut rec = Vec::new();
        rec.push(0x16);
        rec.extend_from_slice(&[0x03, 0x01]);
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn sni_roundtrip() {
        let rec = client_hello_with_sni("imap.gmail.com");
        assert_eq!(tls_record_needed(&rec).unwrap(), 0);
        assert_eq!(parse_sni(&rec).unwrap().as_deref(), Some("imap.gmail.com"));
        assert!(validate_tls_client_hello(&rec, "imap.gmail.com", false).is_ok());
        assert!(validate_tls_client_hello(&rec, "IMAP.GMAIL.COM.", false).is_ok());
        assert_eq!(
            validate_tls_client_hello(&rec, "evil.example", false),
            Err(ProtoError::SniMismatch)
        );
    }

    #[test]
    fn sni_skipped_for_ip_literal() {
        let rec = client_hello_with_sni("whatever");
        assert!(validate_tls_client_hello(&rec, "8.8.8.8", true).is_ok());
    }

    #[test]
    fn rejects_non_tls() {
        assert_eq!(tls_record_needed(b"GET /"), Err(ProtoError::NotTls));
        assert_eq!(tls_record_needed(b"SSH-2.0"), Err(ProtoError::NotTls));
    }

    #[test]
    fn needed_grows_with_prefix() {
        let rec = client_hello_with_sni("localhost");
        assert_eq!(tls_record_needed(&[]).unwrap(), 5);
        assert!(tls_record_needed(&rec[..3]).unwrap() > 0);
        assert_eq!(tls_record_needed(&rec).unwrap(), 0);
    }

    #[test]
    fn imap_greeting() {
        assert!(validate_greeting(b"* OK IMAP4rev1 ready\r\n", ProbeKind::ImapGreeting).is_ok());
        assert!(validate_greeting(
            b"* OK [CAPABILITY IMAP4rev1] Dovecot ready\r\n",
            ProbeKind::ImapGreeting
        )
        .is_ok());
        assert_eq!(
            validate_greeting(b"220 smtp.example.com\r\n", ProbeKind::ImapGreeting),
            Err(ProtoError::BadGreeting)
        );
        assert_eq!(
            validate_greeting(b"SSH-2.0-OpenSSH\r\n", ProbeKind::ImapGreeting),
            Err(ProtoError::BadGreeting)
        );
    }

    #[test]
    fn smtp_greeting() {
        assert!(
            validate_greeting(b"220 mail.example.com ESMTP\r\n", ProbeKind::SmtpGreeting).is_ok()
        );
        assert!(validate_greeting(b"220-mail.example.com\r\n", ProbeKind::SmtpGreeting).is_ok());
        assert_eq!(
            validate_greeting(b"* OK IMAP\r\n", ProbeKind::SmtpGreeting),
            Err(ProtoError::BadGreeting)
        );
    }

    #[test]
    fn greeting_complete_on_newline() {
        assert!(!greeting_complete(b"220 mail"));
        assert!(greeting_complete(b"220 mail\n"));
        assert!(greeting_complete(&vec![b'x'; 512]));
    }

    #[test]
    fn probe_ports() {
        assert_eq!(probe_for_port(993), Some(ProbeKind::TlsSni));
        assert_eq!(probe_for_port(465), Some(ProbeKind::TlsSni));
        assert_eq!(probe_for_port(143), Some(ProbeKind::ImapGreeting));
        assert_eq!(probe_for_port(587), Some(ProbeKind::SmtpGreeting));
        assert_eq!(probe_for_port(25), None);
        assert_eq!(probe_for_port(9400), None);
    }
}
