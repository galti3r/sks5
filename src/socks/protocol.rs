use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// SOCKS5 constants (RFC 1928)
pub const SOCKS_VERSION: u8 = 0x05;
#[allow(dead_code)]
pub const AUTH_NONE: u8 = 0x00;
pub const AUTH_PASSWORD: u8 = 0x02;
pub const AUTH_NO_ACCEPTABLE: u8 = 0xFF;
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;
pub const REPLY_SUCCESS: u8 = 0x00;
pub const REPLY_GENERAL_FAILURE: u8 = 0x01;
pub const REPLY_NOT_ALLOWED: u8 = 0x02;
#[allow(dead_code)]
pub const REPLY_NETWORK_UNREACHABLE: u8 = 0x03;
pub const REPLY_HOST_UNREACHABLE: u8 = 0x04;
pub const REPLY_CONNECTION_REFUSED: u8 = 0x05;
pub const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// Maximum domain name length per RFC 1035
const MAX_DOMAIN_LENGTH: usize = 253;

/// Maximum label length per RFC 1035
const MAX_LABEL_LENGTH: usize = 63;

/// S-3: Validate a domain name for SOCKS5 CONNECT requests.
///
/// Rejects domains that are empty, exceed length limits, contain invalid
/// characters, have malformed labels, or appear to be IP address injection
/// attempts (purely numeric).
///
/// Returns `Ok(())` if valid, or `Err(reason)` describing why the domain
/// is invalid.
pub fn validate_domain(domain: &str) -> Result<(), String> {
    // Empty check (also covered by read_connect_request, but defense-in-depth)
    if domain.is_empty() {
        return Err("empty domain name".to_string());
    }

    // Total length check (RFC 1035: max 253 characters)
    if domain.len() > MAX_DOMAIN_LENGTH {
        return Err(format!(
            "domain name too long: {} characters (max {})",
            domain.len(),
            MAX_DOMAIN_LENGTH
        ));
    }

    // Strip optional trailing dot (FQDN notation)
    let normalized = domain.strip_suffix('.').unwrap_or(domain);

    if normalized.is_empty() {
        // Domain was just "."
        return Err("domain name is root-only dot".to_string());
    }

    let labels: Vec<&str> = normalized.split('.').collect();

    // Reject purely numeric domains that are NOT valid IP addresses.
    // SOCKS5 clients legitimately send IP addresses as domain strings (e.g. "127.0.0.1"),
    // so we allow those but reject nonsensical purely numeric labels like "1234567890".
    let all_numeric = labels
        .iter()
        .all(|label| !label.is_empty() && label.chars().all(|c| c.is_ascii_digit()));
    if all_numeric {
        // Allow if it parses as a valid IP address
        if domain.parse::<std::net::IpAddr>().is_err() {
            return Err("purely numeric domain name (not a valid IP address)".to_string());
        }
        // Valid IP address sent as domain string — allow it
        return Ok(());
    }

    for label in &labels {
        // Empty label means consecutive dots like "foo..bar"
        if label.is_empty() {
            return Err("empty label (consecutive dots) in domain name".to_string());
        }

        // Label length check (RFC 1035: max 63 characters)
        if label.len() > MAX_LABEL_LENGTH {
            return Err(format!(
                "label too long: {} characters (max {})",
                label.len(),
                MAX_LABEL_LENGTH
            ));
        }

        // Labels cannot start or end with a hyphen (RFC 952 / RFC 1123)
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!("label '{}' starts or ends with a hyphen", label));
        }

        // Only allow alphanumeric characters and hyphens (RFC 1123)
        // Dots are already handled by splitting.
        for ch in label.chars() {
            if !ch.is_ascii_alphanumeric() && ch != '-' {
                return Err(format!(
                    "invalid character '{}' (U+{:04X}) in domain label",
                    ch, ch as u32
                ));
            }
        }
    }

    Ok(())
}

/// SOCKS5 target address
#[derive(Debug, Clone)]
pub enum TargetAddr {
    Ipv4([u8; 4], u16),
    Ipv6([u8; 16], u16),
    Domain(String, u16),
}

impl TargetAddr {
    pub fn host_string(&self) -> String {
        match self {
            TargetAddr::Ipv4(ip, _) => format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
            TargetAddr::Ipv6(ip, _) => {
                let parts: Vec<String> = ip
                    .chunks(2)
                    .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                    .collect();
                parts.join(":")
            }
            TargetAddr::Domain(domain, _) => domain.clone(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Ipv4(_, p) | TargetAddr::Ipv6(_, p) | TargetAddr::Domain(_, p) => *p,
        }
    }
}

/// SOCKS5 request type (Connect or UDP Associate)
#[derive(Debug)]
pub enum SocksRequest {
    Connect(TargetAddr),
    UdpAssociate(TargetAddr),
}

/// Read a SOCKS5 request (CONNECT or UDP ASSOCIATE), returns SocksRequest.
/// This is a more general version of read_connect_request.
pub async fn read_request(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
) -> Result<SocksRequest> {
    let ver = stream.read_u8().await?;
    if ver != SOCKS_VERSION {
        anyhow::bail!("invalid SOCKS version in request: {}", ver);
    }

    let cmd = stream.read_u8().await?;
    let _rsv = stream.read_u8().await?; // reserved byte

    let atyp = stream.read_u8().await?;
    let target = match atyp {
        ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            let port = stream.read_u16().await?;
            TargetAddr::Ipv4(ip, port)
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            if len == 0 {
                anyhow::bail!("empty domain name in SOCKS5 request");
            }
            if len > MAX_DOMAIN_LENGTH {
                anyhow::bail!(
                    "domain name too long: {} bytes (max {})",
                    len,
                    MAX_DOMAIN_LENGTH
                );
            }
            let mut domain_bytes = vec![0u8; len];
            stream.read_exact(&mut domain_bytes).await?;
            let domain = String::from_utf8(domain_bytes).context("invalid domain name encoding")?;
            // S-3: Validate domain name before DNS resolution
            if let Err(reason) = validate_domain(&domain) {
                tracing::warn!(domain = %domain, reason = %reason, "SOCKS5 request rejected: invalid domain");
                send_reply(stream, REPLY_HOST_UNREACHABLE, &TargetAddr::Ipv4([0; 4], 0)).await?;
                anyhow::bail!("invalid domain name in SOCKS5 request: {}", reason);
            }
            let port = stream.read_u16().await?;
            TargetAddr::Domain(domain, port)
        }
        ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            let port = stream.read_u16().await?;
            TargetAddr::Ipv6(ip, port)
        }
        _ => {
            send_reply(
                stream,
                REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
                &TargetAddr::Ipv4([0; 4], 0),
            )
            .await?;
            anyhow::bail!("unsupported address type: {}", atyp);
        }
    };

    match cmd {
        CMD_CONNECT => Ok(SocksRequest::Connect(target)),
        CMD_UDP_ASSOCIATE => Ok(SocksRequest::UdpAssociate(target)),
        _ => {
            send_reply(
                stream,
                REPLY_COMMAND_NOT_SUPPORTED,
                &TargetAddr::Ipv4([0; 4], 0),
            )
            .await?;
            anyhow::bail!("unsupported command: {}", cmd);
        }
    }
}

/// SOCKS5 UDP request header (RFC 1928 section 7)
/// Format: RSV(2 bytes) + FRAG(1 byte) + ATYP + DST.ADDR + DST.PORT
#[derive(Debug, Clone)]
pub struct UdpHeader {
    pub frag: u8,
    pub target: TargetAddr,
}

impl UdpHeader {
    /// Parse a UDP header from raw datagram bytes.
    /// Returns (header, consumed_bytes) so the caller can extract the payload.
    pub fn parse(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 4 {
            anyhow::bail!("UDP header too short");
        }
        // RSV must be 0x0000
        // We tolerate non-zero RSV per robustness principle
        let frag = data[2];
        let atyp = data[3];
        let mut offset = 4;

        let target = match atyp {
            ATYP_IPV4 => {
                if data.len() < offset + 6 {
                    anyhow::bail!("UDP header too short for IPv4 address");
                }
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&data[offset..offset + 4]);
                offset += 4;
                let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
                offset += 2;
                TargetAddr::Ipv4(ip, port)
            }
            ATYP_DOMAIN => {
                if data.len() < offset + 1 {
                    anyhow::bail!("UDP header too short for domain length");
                }
                let len = data[offset] as usize;
                offset += 1;
                if data.len() < offset + len + 2 {
                    anyhow::bail!("UDP header too short for domain + port");
                }
                let domain = String::from_utf8(data[offset..offset + len].to_vec())
                    .context("invalid domain in UDP header")?;
                offset += len;
                let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
                offset += 2;
                TargetAddr::Domain(domain, port)
            }
            ATYP_IPV6 => {
                if data.len() < offset + 18 {
                    anyhow::bail!("UDP header too short for IPv6 address");
                }
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&data[offset..offset + 16]);
                offset += 16;
                let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
                offset += 2;
                TargetAddr::Ipv6(ip, port)
            }
            _ => anyhow::bail!("unsupported address type in UDP header: {}", atyp),
        };

        Ok((UdpHeader { frag, target }, offset))
    }

    /// Serialize this header into bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = vec![0x00, 0x00, self.frag]; // RSV + FRAG
        match &self.target {
            TargetAddr::Ipv4(ip, port) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(ip);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            TargetAddr::Ipv6(ip, port) => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(ip);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            TargetAddr::Domain(domain, port) => {
                buf.push(ATYP_DOMAIN);
                let len = domain.len();
                assert!(len <= 255, "domain name too long for SOCKS5: {} bytes", len);
                buf.push(len as u8);
                buf.extend_from_slice(domain.as_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }
        buf
    }
}

/// Read the SOCKS5 client greeting (version + auth methods)
pub async fn read_greeting(stream: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>> {
    let ver = stream.read_u8().await.context("reading SOCKS version")?;
    if ver != SOCKS_VERSION {
        anyhow::bail!("unsupported SOCKS version: {}", ver);
    }

    let nmethods = stream.read_u8().await.context("reading nmethods")?;
    if nmethods == 0 {
        anyhow::bail!("client offered no authentication methods (RFC 1928)");
    }
    let mut methods = vec![0u8; nmethods as usize];
    stream
        .read_exact(&mut methods)
        .await
        .context("reading auth methods")?;

    Ok(methods)
}

/// Send method selection response
pub async fn send_method_selection(
    stream: &mut (impl AsyncWrite + Unpin),
    method: u8,
) -> Result<()> {
    stream
        .write_all(&[SOCKS_VERSION, method])
        .await
        .context("sending method selection")?;
    Ok(())
}

/// Read the SOCKS5 CONNECT request, returns the target address
pub async fn read_connect_request(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
) -> Result<TargetAddr> {
    let ver = stream.read_u8().await?;
    if ver != SOCKS_VERSION {
        anyhow::bail!("invalid SOCKS version in request: {}", ver);
    }

    let cmd = stream.read_u8().await?;
    if cmd != CMD_CONNECT {
        send_reply(
            stream,
            REPLY_COMMAND_NOT_SUPPORTED,
            &TargetAddr::Ipv4([0; 4], 0),
        )
        .await?;
        anyhow::bail!("unsupported command: {}", cmd);
    }

    let _rsv = stream.read_u8().await?; // reserved byte

    let atyp = stream.read_u8().await?;
    let target = match atyp {
        ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            let port = stream.read_u16().await?;
            TargetAddr::Ipv4(ip, port)
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            if len == 0 {
                anyhow::bail!("empty domain name in SOCKS5 request");
            }
            if len > MAX_DOMAIN_LENGTH {
                anyhow::bail!(
                    "domain name too long: {} bytes (max {})",
                    len,
                    MAX_DOMAIN_LENGTH
                );
            }
            let mut domain_bytes = vec![0u8; len];
            stream.read_exact(&mut domain_bytes).await?;
            let domain = String::from_utf8(domain_bytes).context("invalid domain name encoding")?;
            // S-3: Validate domain name before DNS resolution
            if let Err(reason) = validate_domain(&domain) {
                tracing::warn!(domain = %domain, reason = %reason, "SOCKS5 CONNECT rejected: invalid domain");
                send_reply(stream, REPLY_HOST_UNREACHABLE, &TargetAddr::Ipv4([0; 4], 0)).await?;
                anyhow::bail!("invalid domain name in SOCKS5 CONNECT: {}", reason);
            }
            let port = stream.read_u16().await?;
            TargetAddr::Domain(domain, port)
        }
        ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            let port = stream.read_u16().await?;
            TargetAddr::Ipv6(ip, port)
        }
        _ => {
            send_reply(
                stream,
                REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
                &TargetAddr::Ipv4([0; 4], 0),
            )
            .await?;
            anyhow::bail!("unsupported address type: {}", atyp);
        }
    };

    Ok(target)
}

/// Send a SOCKS5 reply
pub async fn send_reply(
    stream: &mut (impl AsyncWrite + Unpin),
    reply: u8,
    bind_addr: &TargetAddr,
) -> Result<()> {
    let mut buf = vec![SOCKS_VERSION, reply, 0x00]; // ver, rep, rsv

    match bind_addr {
        TargetAddr::Ipv4(ip, port) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(ip);
            buf.extend_from_slice(&port.to_be_bytes());
        }
        TargetAddr::Ipv6(ip, port) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(ip);
            buf.extend_from_slice(&port.to_be_bytes());
        }
        TargetAddr::Domain(domain, port) => {
            buf.push(ATYP_DOMAIN);
            let len = domain.len();
            assert!(len <= 255, "domain name too long for SOCKS5: {} bytes", len);
            buf.push(len as u8);
            buf.extend_from_slice(domain.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }

    stream.write_all(&buf).await.context("sending reply")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_addr_host_string() {
        let ipv4 = TargetAddr::Ipv4([192, 168, 1, 1], 80);
        assert_eq!(ipv4.host_string(), "192.168.1.1");
        assert_eq!(ipv4.port(), 80);

        let domain = TargetAddr::Domain("example.com".to_string(), 443);
        assert_eq!(domain.host_string(), "example.com");
        assert_eq!(domain.port(), 443);
    }

    #[test]
    fn test_udp_header_ipv4_roundtrip() {
        let header = UdpHeader {
            frag: 0,
            target: TargetAddr::Ipv4([192, 168, 1, 1], 8080),
        };
        let bytes = header.serialize();
        let (parsed, consumed) = UdpHeader::parse(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.frag, 0);
        assert_eq!(parsed.target.host_string(), "192.168.1.1");
        assert_eq!(parsed.target.port(), 8080);
    }

    #[test]
    fn test_udp_header_domain_roundtrip() {
        let header = UdpHeader {
            frag: 0,
            target: TargetAddr::Domain("example.com".to_string(), 443),
        };
        let bytes = header.serialize();
        let (parsed, consumed) = UdpHeader::parse(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.target.host_string(), "example.com");
        assert_eq!(parsed.target.port(), 443);
    }

    #[test]
    fn test_udp_header_ipv6_roundtrip() {
        let header = UdpHeader {
            frag: 0,
            target: TargetAddr::Ipv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 53),
        };
        let bytes = header.serialize();
        let (parsed, consumed) = UdpHeader::parse(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.target.port(), 53);
    }

    #[test]
    fn test_udp_header_too_short() {
        assert!(UdpHeader::parse(&[0, 0]).is_err());
    }

    #[test]
    fn test_udp_header_frag_preserved() {
        let header = UdpHeader {
            frag: 3,
            target: TargetAddr::Ipv4([10, 0, 0, 1], 80),
        };
        let bytes = header.serialize();
        let (parsed, _) = UdpHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.frag, 3);
    }

    // --- S-3: Domain validation tests ---

    #[test]
    fn test_validate_domain_valid() {
        assert!(validate_domain("example.com").is_ok());
        assert!(validate_domain("sub.example.com").is_ok());
        assert!(validate_domain("my-host.example.org").is_ok());
        assert!(validate_domain("a.b.c.d.example.com").is_ok());
        assert!(validate_domain("x.co").is_ok());
        assert!(validate_domain("example.com.").is_ok()); // trailing dot (FQDN)
        assert!(validate_domain("a").is_ok()); // single-char label
        assert!(validate_domain("localhost").is_ok());
    }

    #[test]
    fn test_validate_domain_empty() {
        assert!(validate_domain("").is_err());
    }

    #[test]
    fn test_validate_domain_too_long() {
        // 254 characters total (over 253 limit)
        let long = format!("{}.example.com", "a".repeat(242));
        assert!(long.len() > 253);
        assert!(validate_domain(&long).is_err());
    }

    #[test]
    fn test_validate_domain_label_too_long() {
        let long_label = format!("{}.example.com", "a".repeat(64));
        assert!(validate_domain(&long_label).is_err());

        // Exactly 63 should be fine
        let ok_label = format!("{}.example.com", "a".repeat(63));
        assert!(validate_domain(&ok_label).is_ok());
    }

    #[test]
    fn test_validate_domain_invalid_characters() {
        assert!(validate_domain("exam ple.com").is_err()); // space
        assert!(validate_domain("exam_ple.com").is_err()); // underscore
        assert!(validate_domain("exam@ple.com").is_err()); // at sign
        assert!(validate_domain("example.com/path").is_err()); // slash
        assert!(validate_domain("example.com:8080").is_err()); // colon
        assert!(validate_domain("ex\x00mple.com").is_err()); // null byte
    }

    #[test]
    fn test_validate_domain_hyphen_rules() {
        assert!(validate_domain("-example.com").is_err()); // leading hyphen
        assert!(validate_domain("example-.com").is_err()); // trailing hyphen
        assert!(validate_domain("ex-ample.com").is_ok()); // hyphen in middle is fine
    }

    #[test]
    fn test_validate_domain_purely_numeric() {
        assert!(validate_domain("12345").is_err()); // not a valid IP
        assert!(validate_domain("999.999.999.999").is_err()); // not a valid IP
        assert!(validate_domain("0.0.0.0.0").is_err()); // too many octets
                                                        // Valid IPs sent as domain strings are allowed (common SOCKS5 client behavior)
        assert!(validate_domain("127.0.0.1").is_ok());
        assert!(validate_domain("192.168.1.1").is_ok());
        assert!(validate_domain("1.2.3.4").is_ok());
    }

    #[test]
    fn test_validate_domain_not_purely_numeric() {
        // At least one label has a non-digit character
        assert!(validate_domain("1a.2.3.4").is_ok());
        assert!(validate_domain("host1.example.com").is_ok());
        assert!(validate_domain("123.example.com").is_ok());
    }

    #[test]
    fn test_validate_domain_consecutive_dots() {
        assert!(validate_domain("example..com").is_err());
        assert!(validate_domain("..example.com").is_err());
    }

    #[test]
    fn test_validate_domain_root_only_dot() {
        assert!(validate_domain(".").is_err());
    }
}
