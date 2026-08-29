use crate::common::stream::BoxStream;
use crate::crypto::digest::Digest;
use crate::crypto::encoding::hex_encode;
use crate::crypto::hash::Sha224;
use crate::engine::config::OutboundConfig;
use crate::engine::connection_tracker::TrackedConnection;
use crate::engine::error::{Error, Result};
use crate::engine::outbound::{OutboundProxy, TargetAddr};
use crate::engine::tls::{ClientConfig, TlsConnector};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

const CRLF: &[u8] = b"\r\n";

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrojanCommand {
    Connect = 0x01,
    UdpAssociate = 0x03,
}

impl TrojanCommand {
    #[allow(dead_code)]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(TrojanCommand::Connect),
            0x03 => Some(TrojanCommand::UdpAssociate),
            _ => None,
        }
    }
}

pub struct TrojanOutbound {
    config: OutboundConfig,
    server: String,
    port: u16,
    #[allow(dead_code)]
    password: String,
    password_hash: [u8; 56],
    sni: String,
    skip_cert_verify: bool,
    alpn: Vec<String>,
    udp_enabled: bool,
}

impl TrojanOutbound {
    pub fn new(config: OutboundConfig) -> Result<Self> {
        let server = config
            .server
            .clone()
            .ok_or_else(|| Error::config("Missing server address for Trojan"))?;

        let port = config
            .port
            .ok_or_else(|| Error::config("Missing port for Trojan"))?;

        let password = config
            .options
            .get("password")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_default();

        if password.is_empty() {
            return Err(Error::config("Missing password for Trojan"));
        }

        let sni = config
            .options
            .get("sni")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| server.clone());

        let skip_cert_verify = config
            .options
            .get("skip-cert-verify")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let alpn = config
            .options
            .get("alpn")
            .and_then(|v| v.as_array())
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_else(|| vec!["h2".to_string(), "http/1.1".to_string()]);

        // Default UDP to true to support QUIC and other UDP protocols
        let udp_enabled = config
            .options
            .get("udp")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let password_hash = compute_password_hash(&password);

        Ok(Self {
            config,
            server,
            port,
            password,
            password_hash,
            sni,
            skip_cert_verify,
            alpn,
            udp_enabled,
        })
    }

    fn create_tls_connector(&self) -> Result<TlsConnector> {
        let config = ClientConfig {
            server_name: Some(self.sni.clone()),
            alpn: self.alpn.clone(),
            skip_cert_verify: self.skip_cert_verify,
            enable_sni: true,
        };
        TlsConnector::new(config).map_err(|e| Error::Tls {
            message: format!("Failed to create Trojan TLS connector: {e}"),
            source: None,
        })
    }

    fn connect_tls(&self) -> Result<BoxStream> {
        let addr = format!("{}:{}", self.server, self.port);
        let stream =
            crate::common::socket::connect_host(&self.server, self.port, Duration::from_secs(30))
                .map_err(|e| {
                Error::network(format!(
                    "Failed to connect to Trojan server {}: {}",
                    addr, e
                ))
            })?;

        let connector = self.create_tls_connector()?;
        let tls_stream = connector
            .connect(stream, &self.sni)
            .map_err(|e| Error::network(format!("TLS handshake failed: {}", e)))?;

        tracing::debug!(
            "Trojan TLS connection established to {} (SNI: {})",
            addr,
            self.sni
        );

        Ok(tls_stream)
    }

    fn handshake<S: Read + Write + ?Sized>(
        &self,
        stream: &mut S,
        target: &TargetAddr,
        cmd: TrojanCommand,
    ) -> Result<()> {
        let mut buf = Vec::with_capacity(128);

        buf.extend_from_slice(&self.password_hash);
        buf.extend_from_slice(CRLF);
        buf.push(cmd as u8);

        write_address_to_buf(&mut buf, target)?;

        buf.extend_from_slice(CRLF);

        stream
            .write_all(&buf)
            .map_err(|e| Error::network(format!("Failed to send Trojan handshake: {}", e)))?;

        stream
            .flush()
            .map_err(|e| Error::network(format!("Failed to flush Trojan handshake: {}", e)))?;

        tracing::debug!("Trojan handshake sent for target: {}", target);

        Ok(())
    }

    pub fn is_udp_enabled(&self) -> bool {
        self.udp_enabled
    }

    pub fn relay_udp(&self, target: &TargetAddr, data: &[u8]) -> Result<Vec<u8>> {
        if !self.udp_enabled {
            return Err(Error::config(
                "UDP relay is not enabled for this Trojan proxy",
            ));
        }

        let mut tls_stream = self.connect_tls()?;

        self.handshake(&mut tls_stream, target, TrojanCommand::UdpAssociate)?;

        let udp_packet = build_udp_packet(target, data)?;
        tls_stream
            .write_all(&udp_packet)
            .map_err(|e| Error::network(format!("Failed to send UDP packet: {}", e)))?;
        tls_stream.flush().ok();

        tracing::debug!(
            "Trojan UDP: sent {} bytes to {} via {}:{}",
            data.len(),
            target,
            self.server,
            self.port
        );

        // Bounded response read: the TLS layer reads with a short socket
        // timeout, so retry until the 30s deadline. The courierust record
        // layer resumes from the exact byte across a transient read timeout,
        // so retrying a partially-read packet is safe.
        let deadline = Instant::now() + Duration::from_secs(30);
        let response = read_udp_packet(&mut tls_stream, deadline)
            .map_err(|e| Error::network(format!("Failed to receive UDP response: {}", e)))?;

        tracing::debug!("Trojan UDP: received {} bytes response", response.len());

        Ok(response)
    }
}

impl OutboundProxy for TrojanOutbound {
    fn connect(&self) -> Result<()> {
        let _tls_stream = self.connect_tls()?;
        tracing::info!(
            "Trojan outbound '{}' can reach {}:{}",
            self.config.tag,
            self.server,
            self.port
        );
        Ok(())
    }

    fn disconnect(&self) -> Result<()> {
        Ok(())
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn server_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }

    fn supports_udp(&self) -> bool {
        self.udp_enabled
    }

    fn relay_udp_packet(&self, target: &TargetAddr, data: &[u8]) -> Result<Vec<u8>> {
        if !self.udp_enabled {
            return Err(Error::config(
                "UDP relay is not enabled for this Trojan proxy",
            ));
        }
        self.relay_udp(target, data)
    }

    fn test_http_latency(
        &self,
        test_url: &str,
        timeout: std::time::Duration,
    ) -> Result<std::time::Duration> {
        use std::time::Instant;

        let url = crate::common::url::Url::parse(test_url)
            .map_err(|e| Error::config(format!("Invalid test URL: {}", e)))?;

        let host = url
            .host_str()
            .ok_or_else(|| Error::config("Test URL has no host"))?
            .to_string();
        let url_port = url
            .port()
            .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        let path = if url.path().is_empty() {
            "/"
        } else {
            url.path()
        };

        let start = Instant::now();

        let mut tls_stream = self.connect_tls()?;

        let target = TargetAddr::Domain(host.clone(), url_port);
        self.handshake(&mut tls_stream, &target, TrojanCommand::Connect)?;

        let http_request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: Corduit/1.0\r\n\r\n",
            path, host
        );

        tls_stream
            .write_all(http_request.as_bytes())
            .map_err(|e| Error::network(format!("Failed to send HTTP request: {}", e)))?;

        // Bounded response read: retry transient timeouts up to the deadline.
        let deadline = Instant::now() + timeout;
        let response = read_http_response(&mut tls_stream, deadline)
            .map_err(|e| Error::network(format!("Failed to read response: {}", e)))?;

        if response.starts_with("HTTP/") {
            let elapsed = start.elapsed();
            tracing::info!("Trojan latency test success: {}ms", elapsed.as_millis());
            Ok(elapsed)
        } else {
            Err(Error::network("Invalid HTTP response"))
        }
    }

    fn relay_tcp(&self, inbound: BoxStream, target: TargetAddr) -> Result<()> {
        self.relay_tcp_with_connection(inbound, target, None)
    }

    fn relay_tcp_with_connection(
        &self,
        inbound: BoxStream,
        target: TargetAddr,
        connection: Option<Arc<TrackedConnection>>,
    ) -> Result<()> {
        let tls_stream = self.connect_tls()?;

        let mut tls_stream = tls_stream;
        self.handshake(&mut tls_stream, &target, TrojanCommand::Connect)?;

        tracing::debug!(
            "Trojan: relaying TCP to {} via {}:{}",
            target,
            self.server,
            self.port
        );

        relay_streams!(inbound, tls_stream, connection)
    }
}

fn compute_password_hash(password: &str) -> [u8; 56] {
    let mut hasher = Sha224::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let hex_str = hex_encode(&result);
    let mut hash = [0u8; 56];
    hash.copy_from_slice(hex_str.as_bytes());
    hash
}

fn write_address_to_buf(buf: &mut Vec<u8>, target: &TargetAddr) -> Result<()> {
    match target {
        TargetAddr::Domain(domain, port) => {
            buf.push(0x03);
            if domain.len() > 255 {
                return Err(Error::protocol("Domain name too long"));
            }
            buf.push(domain.len() as u8);
            buf.extend_from_slice(domain.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
        TargetAddr::Ip(addr) => match addr {
            std::net::SocketAddr::V4(v4) => {
                buf.push(0x01);
                buf.extend_from_slice(&v4.ip().octets());
                buf.extend_from_slice(&v4.port().to_be_bytes());
            }
            std::net::SocketAddr::V6(v6) => {
                buf.push(0x04);
                buf.extend_from_slice(&v6.ip().octets());
                buf.extend_from_slice(&v6.port().to_be_bytes());
            }
        },
    }
    Ok(())
}

fn build_udp_packet(target: &TargetAddr, data: &[u8]) -> Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(data.len() + 64);

    write_address_to_buf(&mut packet, target)?;

    let length = data.len() as u16;
    packet.extend_from_slice(&length.to_be_bytes());

    packet.extend_from_slice(CRLF);

    packet.extend_from_slice(data);

    Ok(packet)
}

fn read_udp_packet<S: Read>(stream: &mut S, deadline: Instant) -> std::io::Result<Vec<u8>> {
    let read_u8 = |stream: &mut S| -> std::io::Result<u8> {
        let mut b = [0u8; 1];
        read_exact_deadline(stream, &mut b, deadline)?;
        Ok(b[0])
    };
    let read_u16 = |stream: &mut S| -> std::io::Result<u16> {
        let mut b = [0u8; 2];
        read_exact_deadline(stream, &mut b, deadline)?;
        Ok(u16::from_be_bytes(b))
    };

    let atype = read_u8(stream)?;

    match atype {
        0x01 => {
            let mut addr = [0u8; 4];
            read_exact_deadline(stream, &mut addr, deadline)?;
            let _port = read_u16(stream)?;
        }
        0x03 => {
            let len = read_u8(stream)? as usize;
            let mut domain = vec![0u8; len];
            read_exact_deadline(stream, &mut domain, deadline)?;
            let _port = read_u16(stream)?;
        }
        0x04 => {
            let mut addr = [0u8; 16];
            read_exact_deadline(stream, &mut addr, deadline)?;
            let _port = read_u16(stream)?;
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Unknown address type: {}", atype),
            ));
        }
    }

    let length = read_u16(stream)? as usize;

    let mut crlf = [0u8; 2];
    read_exact_deadline(stream, &mut crlf, deadline)?;

    if crlf != CRLF {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid CRLF in UDP packet",
        ));
    }

    let mut data = vec![0u8; length];
    read_exact_deadline(stream, &mut data, deadline)?;

    Ok(data)
}

/// Read exactly `buf.len()` bytes, retrying transient read timeouts until
/// `deadline`. Safe to retry: a `read` that returns `WouldBlock`/`TimedOut`
/// consumes no bytes, and the courierust TLS record layer resumes from the
/// exact byte across a mid-record timeout.
fn read_exact_deadline(
    stream: &mut dyn Read,
    buf: &mut [u8],
    deadline: Instant,
) -> std::io::Result<()> {
    let mut pos = 0usize;
    while pos < buf.len() {
        match stream.read(&mut buf[pos..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected EOF",
                ))
            }
            Ok(n) => pos += n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "read timed out",
                    ));
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Read the first HTTP response chunk within `deadline`, returning it as
/// UTF-8 lossy text (used by the latency test).
fn read_http_response(stream: &mut dyn Read, deadline: Instant) -> std::io::Result<String> {
    let mut response = vec![0u8; 1024];
    let mut pos = 0usize;
    while pos < response.len() {
        match stream.read(&mut response[pos..]) {
            Ok(0) => break,
            Ok(n) => pos += n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if pos > 0 {
                    // Already have data; treat a stall as end-of-chunk.
                    break;
                }
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "read timed out",
                    ));
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(String::from_utf8_lossy(&response[..pos]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hash() {
        let password = "test_password";
        let hash = compute_password_hash(password);

        assert_eq!(hash.len(), 56);

        let hash_str = std::str::from_utf8(&hash).unwrap();
        assert!(hash_str.chars().all(|c| c.is_ascii_hexdigit()));

        let hash2 = compute_password_hash(password);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_password_hash_known_value() {
        let password = "password123";
        let hash = compute_password_hash(password);
        let hash_str = std::str::from_utf8(&hash).unwrap();

        let mut hasher = Sha224::new();
        hasher.update(password.as_bytes());
        let expected = hex_encode(&hasher.finalize());

        assert_eq!(hash_str, expected);
    }

    #[test]
    fn test_trojan_command_from_u8() {
        assert_eq!(TrojanCommand::from_u8(0x01), Some(TrojanCommand::Connect));
        assert_eq!(
            TrojanCommand::from_u8(0x03),
            Some(TrojanCommand::UdpAssociate)
        );
        assert_eq!(TrojanCommand::from_u8(0x00), None);
        assert_eq!(TrojanCommand::from_u8(0x02), None);
        assert_eq!(TrojanCommand::from_u8(0xFF), None);
    }

    #[test]
    fn test_write_address_domain() {
        let target = TargetAddr::Domain("example.com".to_string(), 443);
        let mut buf = Vec::new();
        write_address_to_buf(&mut buf, &target).unwrap();

        assert_eq!(buf[0], 0x03);
        assert_eq!(buf[1], 11);
        assert_eq!(&buf[2..13], b"example.com");
        assert_eq!(&buf[13..15], &[0x01, 0xBB]);
    }

    #[test]
    fn test_write_address_ipv4() {
        let addr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::new(192, 168, 1, 1),
            8080,
        ));
        let target = TargetAddr::Ip(addr);
        let mut buf = Vec::new();
        write_address_to_buf(&mut buf, &target).unwrap();

        assert_eq!(buf[0], 0x01);
        assert_eq!(&buf[1..5], &[192, 168, 1, 1]);
        assert_eq!(&buf[5..7], &[0x1F, 0x90]);
    }

    #[test]
    fn test_write_address_ipv6() {
        let addr = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::LOCALHOST,
            443,
            0,
            0,
        ));
        let target = TargetAddr::Ip(addr);
        let mut buf = Vec::new();
        write_address_to_buf(&mut buf, &target).unwrap();

        assert_eq!(buf[0], 0x04);
        assert_eq!(buf.len(), 1 + 16 + 2);
    }

    #[test]
    fn test_build_udp_packet() {
        let target = TargetAddr::Domain("test.com".to_string(), 53);
        let data = b"hello";
        let packet = build_udp_packet(&target, data).unwrap();

        assert_eq!(packet[0], 0x03);
        assert_eq!(packet[1], 8);
        assert_eq!(&packet[2..10], b"test.com");
        assert_eq!(&packet[10..12], &53u16.to_be_bytes());

        let length = u16::from_be_bytes([packet[12], packet[13]]);
        assert_eq!(length, 5);

        assert_eq!(&packet[14..16], CRLF);

        assert_eq!(&packet[16..], b"hello");
    }

    #[test]
    fn test_trojan_outbound_new() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "password".to_string(),
            nextjson::Value::String("test_pass".to_string()),
        );
        options.insert(
            "sni".to_string(),
            nextjson::Value::String("custom.sni.com".to_string()),
        );
        options.insert("skip-cert-verify".to_string(), nextjson::Value::Bool(true));
        options.insert("udp".to_string(), nextjson::Value::Bool(true));

        let config = OutboundConfig {
            tag: "trojan-test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Trojan,
            server: Some("trojan.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = TrojanOutbound::new(config).unwrap();

        assert_eq!(outbound.tag(), "trojan-test");
        assert_eq!(outbound.server, "trojan.example.com");
        assert_eq!(outbound.port, 443);
        assert_eq!(outbound.sni, "custom.sni.com");
        assert!(outbound.skip_cert_verify);
        assert!(outbound.is_udp_enabled());
    }

    #[test]
    fn test_trojan_outbound_missing_password() {
        let config = OutboundConfig {
            tag: "trojan-test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Trojan,
            server: Some("trojan.example.com".to_string()),
            port: Some(443),
            options: std::collections::HashMap::new(),
        };

        let result = TrojanOutbound::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_trojan_outbound_missing_server() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "password".to_string(),
            nextjson::Value::String("test".to_string()),
        );

        let config = OutboundConfig {
            tag: "trojan-test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Trojan,
            server: None,
            port: Some(443),
            options,
        };

        let result = TrojanOutbound::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_trojan_outbound_default_sni() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "password".to_string(),
            nextjson::Value::String("test".to_string()),
        );

        let config = OutboundConfig {
            tag: "trojan-test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Trojan,
            server: Some("server.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = TrojanOutbound::new(config).unwrap();
        assert_eq!(outbound.sni, "server.example.com");
    }

    #[test]
    fn test_trojan_outbound_server_addr() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "password".to_string(),
            nextjson::Value::String("test".to_string()),
        );

        let config = OutboundConfig {
            tag: "trojan-test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Trojan,
            server: Some("server.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = TrojanOutbound::new(config).unwrap();
        let (server, port) = outbound.server_addr().unwrap();
        assert_eq!(server, "server.example.com");
        assert_eq!(port, 443);
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_domain() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9]{0,62}(\\.[a-z][a-z0-9]{0,62}){0,3}"
            .prop_filter("domain must be <= 255 bytes", |s| s.len() <= 255)
    }

    fn arb_port() -> impl Strategy<Value = u16> {
        1u16..=65535u16
    }

    fn arb_ipv4() -> impl Strategy<Value = std::net::Ipv4Addr> {
        (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>())
            .prop_map(|(a, b, c, d)| std::net::Ipv4Addr::new(a, b, c, d))
    }

    fn arb_ipv6() -> impl Strategy<Value = std::net::Ipv6Addr> {
        (
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
            any::<u16>(),
        )
            .prop_map(|(a, b, c, d, e, f, g, h)| std::net::Ipv6Addr::new(a, b, c, d, e, f, g, h))
    }

    fn arb_target_addr() -> impl Strategy<Value = TargetAddr> {
        prop_oneof![
            (arb_domain(), arb_port()).prop_map(|(d, p)| TargetAddr::Domain(d, p)),
            (arb_ipv4(), arb_port()).prop_map(|(ip, p)| TargetAddr::Ip(std::net::SocketAddr::V4(
                std::net::SocketAddrV4::new(ip, p)
            ))),
            (arb_ipv6(), arb_port()).prop_map(|(ip, p)| TargetAddr::Ip(std::net::SocketAddr::V6(
                std::net::SocketAddrV6::new(ip, p, 0, 0)
            ))),
        ]
    }

    fn arb_password() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9!@#$%^&*]{1,64}"
    }

    fn arb_udp_data() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 1..1024)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_password_hash_deterministic(password in arb_password()) {
            let hash1 = compute_password_hash(&password);
            let hash2 = compute_password_hash(&password);
            prop_assert_eq!(hash1, hash2);
        }

        #[test]
        fn prop_password_hash_length(password in arb_password()) {
            let hash = compute_password_hash(&password);
            prop_assert_eq!(hash.len(), 56);
        }

        #[test]
        fn prop_password_hash_hex_chars(password in arb_password()) {
            let hash = compute_password_hash(&password);
            let hash_str = std::str::from_utf8(&hash).unwrap();
            prop_assert!(hash_str.chars().all(|c| c.is_ascii_hexdigit()));
        }

        #[test]
        fn prop_address_encoding_domain(domain in arb_domain(), port in arb_port()) {
            let target = TargetAddr::Domain(domain.clone(), port);
            let mut buf = Vec::new();
            write_address_to_buf(&mut buf, &target).unwrap();

            prop_assert_eq!(buf[0], 0x03);
            prop_assert_eq!(buf[1] as usize, domain.len());
            prop_assert_eq!(&buf[2..2 + domain.len()], domain.as_bytes());

            let port_bytes = &buf[2 + domain.len()..];
            let decoded_port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
            prop_assert_eq!(decoded_port, port);
        }

        #[test]
        fn prop_address_encoding_ipv4(ip in arb_ipv4(), port in arb_port()) {
            let addr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip, port));
            let target = TargetAddr::Ip(addr);
            let mut buf = Vec::new();
            write_address_to_buf(&mut buf, &target).unwrap();

            prop_assert_eq!(buf[0], 0x01);
            prop_assert_eq!(&buf[1..5], &ip.octets());

            let decoded_port = u16::from_be_bytes([buf[5], buf[6]]);
            prop_assert_eq!(decoded_port, port);
        }

        #[test]
        fn prop_address_encoding_ipv6(ip in arb_ipv6(), port in arb_port()) {
            let addr = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, 0));
            let target = TargetAddr::Ip(addr);
            let mut buf = Vec::new();
            write_address_to_buf(&mut buf, &target).unwrap();

            prop_assert_eq!(buf[0], 0x04);
            prop_assert_eq!(&buf[1..17], &ip.octets());

            let decoded_port = u16::from_be_bytes([buf[17], buf[18]]);
            prop_assert_eq!(decoded_port, port);
        }

        #[test]
        fn prop_udp_packet_structure(target in arb_target_addr(), data in arb_udp_data()) {
            let packet = build_udp_packet(&target, &data).unwrap();

            let addr_len = match &target {
                TargetAddr::Domain(d, _) => 1 + 1 + d.len() + 2,
                TargetAddr::Ip(std::net::SocketAddr::V4(_)) => 1 + 4 + 2,
                TargetAddr::Ip(std::net::SocketAddr::V6(_)) => 1 + 16 + 2,
            };

            let expected_len = addr_len + 2 + 2 + data.len();
            prop_assert_eq!(packet.len(), expected_len);

            let length_offset = addr_len;
            let length = u16::from_be_bytes([packet[length_offset], packet[length_offset + 1]]);
            prop_assert_eq!(length as usize, data.len());

            let crlf_offset = length_offset + 2;
            prop_assert_eq!(&packet[crlf_offset..crlf_offset + 2], CRLF);

            let data_offset = crlf_offset + 2;
            prop_assert_eq!(&packet[data_offset..], &data[..]);
        }

        #[test]
        fn prop_different_passwords_different_hashes(
            password1 in arb_password(),
            password2 in arb_password()
        ) {
            prop_assume!(password1 != password2);
            let hash1 = compute_password_hash(&password1);
            let hash2 = compute_password_hash(&password2);
            prop_assert_ne!(hash1, hash2);
        }
    }
}
