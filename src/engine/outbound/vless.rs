use crate::common::stream::BoxStream;
use crate::crypto::uuid::Uuid;
use crate::engine::config::OutboundConfig;
use crate::engine::connection_tracker::TrackedConnection;
use crate::engine::error::{Error, Result};
use crate::engine::outbound::{OutboundProxy, TargetAddr};
use crate::engine::tls::{ClientConfig, TlsConnector};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

const VLESS_VERSION: u8 = 0x00;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessCommand {
    Tcp = 0x01,
    Udp = 0x02,
    #[allow(dead_code)]
    Mux = 0x03,
}

impl VlessCommand {
    #[allow(dead_code)]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(VlessCommand::Tcp),
            0x02 => Some(VlessCommand::Udp),
            0x03 => Some(VlessCommand::Mux),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessFlow {
    None,
    XtlsRprxVision,
    XtlsRprxVisionUdp443,
}

impl VlessFlow {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "xtls-rprx-vision" | "vision" => VlessFlow::XtlsRprxVision,
            "xtls-rprx-vision-udp443" => VlessFlow::XtlsRprxVisionUdp443,
            _ => VlessFlow::None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            VlessFlow::None => "",
            VlessFlow::XtlsRprxVision => "xtls-rprx-vision",
            VlessFlow::XtlsRprxVisionUdp443 => "xtls-rprx-vision-udp443",
        }
    }

    pub fn is_vision(&self) -> bool {
        matches!(
            self,
            VlessFlow::XtlsRprxVision | VlessFlow::XtlsRprxVisionUdp443
        )
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum VlessAddressType {
    Ipv4 = 0x01,
    Domain = 0x02,
    Ipv6 = 0x03,
}

#[allow(dead_code)]
pub struct VlessRequest {
    pub version: u8,
    pub uuid: [u8; 16],
    pub addons_len: u8,
    pub addons: Vec<u8>,
    pub command: VlessCommand,
    pub port: u16,
    pub address_type: VlessAddressType,
    pub address: Vec<u8>,
}

#[allow(dead_code)]
pub struct VlessResponse {
    pub version: u8,
    pub addons_len: u8,
    pub addons: Vec<u8>,
}

pub struct VlessOutbound {
    config: OutboundConfig,
    server: String,
    port: u16,
    #[allow(dead_code)]
    uuid: Uuid,
    uuid_bytes: [u8; 16],
    flow: VlessFlow,
    sni: String,
    skip_cert_verify: bool,
    alpn: Vec<String>,
    udp_enabled: bool,
}

impl VlessOutbound {
    pub fn new(config: OutboundConfig) -> Result<Self> {
        let server = config
            .server
            .clone()
            .ok_or_else(|| Error::config("Missing server address for VLess"))?;

        let port = config
            .port
            .ok_or_else(|| Error::config("Missing port for VLess"))?;

        let uuid_str = config
            .options
            .get("uuid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::config("Missing UUID for VLess"))?;

        let uuid =
            Uuid::parse_str(uuid_str).map_err(|e| Error::config(format!("Invalid UUID: {}", e)))?;

        let uuid_bytes = *uuid.as_bytes();

        let flow_str = config
            .options
            .get("flow")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let flow = VlessFlow::from_str(flow_str);

        let sni = config
            .options
            .get("sni")
            .or_else(|| config.options.get("servername"))
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

        Ok(Self {
            config,
            server,
            port,
            uuid,
            uuid_bytes,
            flow,
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
            message: format!("Failed to create VLess TLS connector: {e}"),
            source: None,
        })
    }

    fn connect_tls(&self) -> Result<BoxStream> {
        let addr = format!("{}:{}", self.server, self.port);
        let stream =
            crate::common::socket::connect_host(&self.server, self.port, Duration::from_secs(30))
                .map_err(|e| {
                Error::network(format!("Failed to connect to VLess server {}: {}", addr, e))
            })?;

        let connector = self.create_tls_connector()?;
        let tls_stream = connector
            .connect(stream, &self.sni)
            .map_err(|e| Error::network(format!("TLS handshake failed: {}", e)))?;

        tracing::debug!(
            "VLess TLS connection established to {} (SNI: {})",
            addr,
            self.sni
        );

        Ok(tls_stream)
    }

    fn handshake<S: Read + Write + ?Sized>(
        &self,
        stream: &mut S,
        target: &TargetAddr,
        cmd: VlessCommand,
    ) -> Result<()> {
        let mut buf = Vec::with_capacity(128);

        buf.push(VLESS_VERSION);
        buf.extend_from_slice(&self.uuid_bytes);

        if self.flow.is_vision() {
            let flow_str = self.flow.as_str();
            let flow_addon = build_flow_addon(flow_str);
            buf.push(flow_addon.len() as u8);
            buf.extend_from_slice(&flow_addon);
        } else {
            buf.push(0x00);
        }

        buf.push(cmd as u8);
        buf.extend_from_slice(&target.port().to_be_bytes());
        write_address_to_buf(&mut buf, target)?;

        stream
            .write_all(&buf)
            .map_err(|e| Error::network(format!("Failed to send VLess handshake: {}", e)))?;

        stream
            .flush()
            .map_err(|e| Error::network(format!("Failed to flush VLess handshake: {}", e)))?;

        let mut response = [0u8; 2];
        stream
            .read_exact(&mut response)
            .map_err(|e| Error::network(format!("Failed to read VLess response: {}", e)))?;

        if response[0] != VLESS_VERSION {
            return Err(Error::protocol(format!(
                "Invalid VLess response version: expected {}, got {}",
                VLESS_VERSION, response[0]
            )));
        }

        let addons_len = response[1] as usize;
        if addons_len > 0 {
            let mut addons = vec![0u8; addons_len];
            stream
                .read_exact(&mut addons)
                .map_err(|e| Error::network(format!("Failed to read VLess addons: {}", e)))?;
        }

        tracing::debug!("VLess handshake completed for target: {}", target);

        Ok(())
    }

    pub fn is_udp_enabled(&self) -> bool {
        self.udp_enabled
    }

    pub fn flow(&self) -> VlessFlow {
        self.flow
    }

    pub fn relay_udp(&self, target: &TargetAddr, data: &[u8]) -> Result<Vec<u8>> {
        if !self.udp_enabled {
            return Err(Error::config(
                "UDP relay is not enabled for this VLess proxy",
            ));
        }

        let mut tls_stream = self.connect_tls()?;

        self.handshake(&mut tls_stream, target, VlessCommand::Udp)?;

        let udp_packet = build_udp_packet(target, data)?;
        tls_stream
            .write_all(&udp_packet)
            .map_err(|e| Error::network(format!("Failed to send UDP packet: {}", e)))?;
        tls_stream.flush().ok();

        tracing::debug!(
            "VLess UDP: sent {} bytes to {} via {}:{}",
            data.len(),
            target,
            self.server,
            self.port
        );

        // Bounded response read: the TLS layer reads with a short socket
        // timeout, so retry until the 30s deadline (safe: the TLS record
        // layer resumes from the exact byte across a transient timeout).
        let deadline = Instant::now() + Duration::from_secs(30);
        let response = read_udp_packet(&mut tls_stream, deadline)
            .map_err(|e| Error::network(format!("Failed to receive UDP response: {}", e)))?;

        tracing::debug!("VLess UDP: received {} bytes response", response.len());

        Ok(response)
    }
}

impl OutboundProxy for VlessOutbound {
    fn connect(&self) -> Result<()> {
        let _tls_stream = self.connect_tls()?;
        tracing::info!(
            "VLess outbound '{}' can reach {}:{}",
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
                "UDP relay is not enabled for this VLESS proxy",
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
        self.handshake(&mut tls_stream, &target, VlessCommand::Tcp)?;

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
            tracing::info!("VLess latency test success: {}ms", elapsed.as_millis());
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
        self.handshake(&mut tls_stream, &target, VlessCommand::Tcp)?;

        tracing::debug!(
            "VLess: relaying TCP to {} via {}:{}",
            target,
            self.server,
            self.port
        );

        relay_streams!(inbound, tls_stream, connection)
    }
}

fn write_address_to_buf(buf: &mut Vec<u8>, target: &TargetAddr) -> Result<()> {
    match target {
        TargetAddr::Domain(domain, _) => {
            buf.push(VlessAddressType::Domain as u8);
            if domain.len() > 255 {
                return Err(Error::protocol("Domain name too long"));
            }
            buf.push(domain.len() as u8);
            buf.extend_from_slice(domain.as_bytes());
        }
        TargetAddr::Ip(addr) => match addr {
            std::net::SocketAddr::V4(v4) => {
                buf.push(VlessAddressType::Ipv4 as u8);
                buf.extend_from_slice(&v4.ip().octets());
            }
            std::net::SocketAddr::V6(v6) => {
                buf.push(VlessAddressType::Ipv6 as u8);
                buf.extend_from_slice(&v6.ip().octets());
            }
        },
    }
    Ok(())
}

fn build_flow_addon(flow: &str) -> Vec<u8> {
    if flow.is_empty() {
        return Vec::new();
    }

    let mut addon = Vec::new();
    addon.push(0x0a);
    addon.push(flow.len() as u8);
    addon.extend_from_slice(flow.as_bytes());
    addon
}

fn build_udp_packet(target: &TargetAddr, data: &[u8]) -> Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(data.len() + 64);

    write_address_to_buf(&mut packet, target)?;
    packet.extend_from_slice(&target.port().to_be_bytes());

    let length = data.len() as u16;
    packet.extend_from_slice(&length.to_be_bytes());

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
        }
        0x02 => {
            let len = read_u8(stream)? as usize;
            let mut domain = vec![0u8; len];
            read_exact_deadline(stream, &mut domain, deadline)?;
        }
        0x03 => {
            let mut addr = [0u8; 16];
            read_exact_deadline(stream, &mut addr, deadline)?;
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Unknown address type: {}", atype),
            ));
        }
    }

    let _port = read_u16(stream)?;

    let length = read_u16(stream)? as usize;

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
    fn test_vless_command_from_u8() {
        assert_eq!(VlessCommand::from_u8(0x01), Some(VlessCommand::Tcp));
        assert_eq!(VlessCommand::from_u8(0x02), Some(VlessCommand::Udp));
        assert_eq!(VlessCommand::from_u8(0x03), Some(VlessCommand::Mux));
        assert_eq!(VlessCommand::from_u8(0x00), None);
        assert_eq!(VlessCommand::from_u8(0xFF), None);
    }

    #[test]
    fn test_vless_flow_from_str() {
        assert_eq!(
            VlessFlow::from_str("xtls-rprx-vision"),
            VlessFlow::XtlsRprxVision
        );
        assert_eq!(VlessFlow::from_str("vision"), VlessFlow::XtlsRprxVision);
        assert_eq!(
            VlessFlow::from_str("XTLS-RPRX-VISION"),
            VlessFlow::XtlsRprxVision
        );
        assert_eq!(
            VlessFlow::from_str("xtls-rprx-vision-udp443"),
            VlessFlow::XtlsRprxVisionUdp443
        );
        assert_eq!(VlessFlow::from_str(""), VlessFlow::None);
        assert_eq!(VlessFlow::from_str("unknown"), VlessFlow::None);
    }

    #[test]
    fn test_vless_flow_is_vision() {
        assert!(!VlessFlow::None.is_vision());
        assert!(VlessFlow::XtlsRprxVision.is_vision());
        assert!(VlessFlow::XtlsRprxVisionUdp443.is_vision());
    }

    #[test]
    fn test_write_address_domain() {
        let target = TargetAddr::Domain("example.com".to_string(), 443);
        let mut buf = Vec::new();
        write_address_to_buf(&mut buf, &target).unwrap();

        assert_eq!(buf[0], VlessAddressType::Domain as u8);
        assert_eq!(buf[1], 11);
        assert_eq!(&buf[2..13], b"example.com");
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

        assert_eq!(buf[0], VlessAddressType::Ipv4 as u8);
        assert_eq!(&buf[1..5], &[192, 168, 1, 1]);
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

        assert_eq!(buf[0], VlessAddressType::Ipv6 as u8);
        assert_eq!(buf.len(), 1 + 16);
    }

    #[test]
    fn test_build_flow_addon() {
        let addon = build_flow_addon("xtls-rprx-vision");
        assert_eq!(addon[0], 0x0a);
        assert_eq!(addon[1], 16);
        assert_eq!(&addon[2..], b"xtls-rprx-vision");

        let empty_addon = build_flow_addon("");
        assert!(empty_addon.is_empty());
    }

    #[test]
    fn test_build_udp_packet() {
        let target = TargetAddr::Domain("test.com".to_string(), 53);
        let data = b"hello";
        let packet = build_udp_packet(&target, data).unwrap();

        assert_eq!(packet[0], VlessAddressType::Domain as u8);
        assert_eq!(packet[1], 8);
        assert_eq!(&packet[2..10], b"test.com");

        let port_offset = 10;
        let port = u16::from_be_bytes([packet[port_offset], packet[port_offset + 1]]);
        assert_eq!(port, 53);

        let length_offset = port_offset + 2;
        let length = u16::from_be_bytes([packet[length_offset], packet[length_offset + 1]]);
        assert_eq!(length, 5);

        let data_offset = length_offset + 2;
        assert_eq!(&packet[data_offset..], b"hello");
    }

    #[test]
    fn test_vless_outbound_new() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            nextjson::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );
        options.insert(
            "flow".to_string(),
            nextjson::Value::String("xtls-rprx-vision".to_string()),
        );
        options.insert(
            "sni".to_string(),
            nextjson::Value::String("custom.sni.com".to_string()),
        );
        options.insert("skip-cert-verify".to_string(), nextjson::Value::Bool(true));
        options.insert("udp".to_string(), nextjson::Value::Bool(true));

        let config = OutboundConfig {
            tag: "vless-test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Vless,
            server: Some("vless.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = VlessOutbound::new(config).unwrap();

        assert_eq!(outbound.tag(), "vless-test");
        assert_eq!(outbound.server, "vless.example.com");
        assert_eq!(outbound.port, 443);
        assert_eq!(outbound.sni, "custom.sni.com");
        assert!(outbound.skip_cert_verify);
        assert!(outbound.is_udp_enabled());
        assert_eq!(outbound.flow(), VlessFlow::XtlsRprxVision);
    }

    #[test]
    fn test_vless_outbound_missing_uuid() {
        let config = OutboundConfig {
            tag: "vless-test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Vless,
            server: Some("vless.example.com".to_string()),
            port: Some(443),
            options: std::collections::HashMap::new(),
        };

        let result = VlessOutbound::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_vless_outbound_missing_server() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            nextjson::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );

        let config = OutboundConfig {
            tag: "vless-test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Vless,
            server: None,
            port: Some(443),
            options,
        };

        let result = VlessOutbound::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_vless_outbound_default_sni() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            nextjson::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );

        let config = OutboundConfig {
            tag: "vless-test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Vless,
            server: Some("server.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = VlessOutbound::new(config).unwrap();
        assert_eq!(outbound.sni, "server.example.com");
    }

    #[test]
    fn test_vless_outbound_server_addr() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            nextjson::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );

        let config = OutboundConfig {
            tag: "vless-test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Vless,
            server: Some("server.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = VlessOutbound::new(config).unwrap();
        let (server, port) = outbound.server_addr().unwrap();
        assert_eq!(server, "server.example.com");
        assert_eq!(port, 443);
    }
}
