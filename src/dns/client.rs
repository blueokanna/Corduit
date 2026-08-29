//! DNS client for upstream queries

use crate::common::socket;
use crate::dns::config::{UpstreamConfig, UpstreamProtocol};
use crate::dns::error::{DnsError, Result};

use crate::dns::wire::{
    BinDecodable, BinEncodable, Message, MessageType, Name, OpCode, Query, RecordType,
};
use courierust::courierust_io::{Read as CRead, Write as CWrite};
use courierust::courierust_tls::{
    ClientConfig as CourierTlsConfig, TlsConnector as CourierTlsConnector, TlsVersion,
};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

/// DNS protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsProtocol {
    Udp,
    Tcp,
    DoT,
    DoH,
    DoQ,
}

/// DNS client for querying upstream servers
pub struct DnsClient {
    /// Upstream configuration
    config: UpstreamConfig,
    /// Query timeout
    timeout: Duration,
    /// TLS connector for DoT (courierust, shared resumption store)
    tls_connector: Option<Arc<CourierTlsConnector>>,
}

impl DnsClient {
    /// Create a new DNS client
    pub fn new(config: UpstreamConfig, timeout: Duration) -> Result<Self> {
        let tls_connector = if matches!(
            config.protocol,
            UpstreamProtocol::DoT | UpstreamProtocol::DoH
        ) {
            Some(Arc::new(Self::create_tls_connector()?))
        } else {
            None
        };

        Ok(Self {
            config,
            timeout,
            tls_connector,
        })
    }

    /// Create TLS connector (courierust, system roots)
    fn create_tls_connector() -> Result<CourierTlsConnector> {
        Ok(CourierTlsConnector::new(CourierTlsConfig {
            roots: crate::common::roots::system_root_store().clone(),
            verify: true,
            alpn: Vec::new(),
            now: unix_now(),
            min_version: TlsVersion::Tls12,
            max_version: TlsVersion::Tls13,
        }))
    }

    /// Query DNS
    pub fn query(&self, name: &str, record_type: RecordType) -> Result<Message> {
        let message = self.build_query(name, record_type)?;

        match self.config.protocol {
            UpstreamProtocol::Udp => self.query_udp(&message),
            UpstreamProtocol::Tcp => self.query_tcp(&message),
            UpstreamProtocol::DoT => self.query_dot(&message),
            UpstreamProtocol::DoH => self.query_doh(&message),
            UpstreamProtocol::DoQ => {
                // DoQ not implemented yet
                Err(DnsError::NotImplemented)
            }
        }
    }

    /// Build DNS query message
    fn build_query(&self, name: &str, record_type: RecordType) -> Result<Message> {
        let name = Name::from_ascii(name)
            .map_err(|e| DnsError::NameError(format!("Invalid domain name: {}", e)))?;

        let mut message = Message::new(
            crate::dns::util::random_id(),
            MessageType::Query,
            OpCode::Query,
        );
        message.metadata.recursion_desired = true;

        let query = Query::query(name, record_type);
        message.add_query(query);

        Ok(message)
    }

    /// Query via UDP
    fn query_udp(&self, message: &Message) -> Result<Message> {
        let addr = self.resolve_address()?;

        let data = message
            .to_bytes()
            .map_err(|e| DnsError::Protocol(e.to_string()))?;

        // One-shot UDP exchange on a fresh socket (immune to Windows ICMP
        // poisoning), bounded by the query timeout.
        let response_data =
            socket::udp_exchange(&addr, &data, self.timeout, None).map_err(map_io)?;

        let response =
            Message::from_bytes(&response_data).map_err(|e| DnsError::Protocol(e.to_string()))?;
        Ok(response)
    }

    /// Query via TCP
    fn query_tcp(&self, message: &Message) -> Result<Message> {
        let addr = self.resolve_address()?;
        let mut stream = socket::connect(&addr, self.timeout).map_err(map_io)?;
        socket::configure(&stream, Some(self.timeout), Some(self.timeout)).map_err(DnsError::Io)?;

        let data = message
            .to_bytes()
            .map_err(|e| DnsError::Protocol(e.to_string()))?;

        // TCP DNS uses 2-byte length prefix
        let len = (data.len() as u16).to_be_bytes();
        stream.write_all(&len).map_err(map_io)?;
        stream.write_all(&data).map_err(map_io)?;

        // Read response length
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).map_err(map_io)?;
        let len = u16::from_be_bytes(len_buf) as usize;

        // Read response
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).map_err(map_io)?;

        let response = Message::from_bytes(&buf).map_err(|e| DnsError::Protocol(e.to_string()))?;
        Ok(response)
    }

    /// Query via DNS over TLS (DoT) — courierust TLS, synchronous.
    fn query_dot(&self, message: &Message) -> Result<Message> {
        let addr = self.resolve_address()?;
        let connector = self
            .tls_connector
            .as_ref()
            .ok_or(DnsError::Tls("TLS connector not initialized".to_string()))?
            .clone();
        let server_name = self
            .config
            .server_name
            .clone()
            .or_else(|| Some(self.config.address.clone()))
            .ok_or(DnsError::Config("Server name required for DoT".to_string()))?;

        let tcp = socket::connect(&addr, self.timeout).map_err(map_io)?;
        let _ = tcp.set_read_timeout(Some(self.timeout));
        let _ = tcp.set_write_timeout(Some(self.timeout));

        // TLS handshake over the socket.
        let mut tls_stream = connector
            .connect(&server_name, &tcp, &tcp)
            .map_err(|e| DnsError::Tls(format!("TLS handshake failed: {e}")))?;

        let data = message
            .to_bytes()
            .map_err(|e| DnsError::Protocol(e.to_string()))?;

        // TCP DNS uses 2-byte length prefix (RFC 7858).
        let mut request = Vec::with_capacity(2 + data.len());
        request.extend_from_slice(&(data.len() as u16).to_be_bytes());
        request.extend_from_slice(&data);
        write_all(&mut tls_stream, &request)
            .map_err(|e| DnsError::Io(std::io::Error::other(e.to_string())))?;

        // Read response length.
        let mut len_buf = [0u8; 2];
        read_exact(&mut tls_stream, &mut len_buf)
            .map_err(|e| DnsError::Io(std::io::Error::other(e.to_string())))?;
        let len = u16::from_be_bytes(len_buf) as usize;
        if len > 65535 {
            return Err(DnsError::Protocol("Response too large".to_string()));
        }

        // Read response.
        let mut buf = vec![0u8; len];
        read_exact(&mut tls_stream, &mut buf)
            .map_err(|e| DnsError::Io(std::io::Error::other(e.to_string())))?;

        Message::from_bytes(&buf).map_err(|e| DnsError::Protocol(e.to_string()))
    }

    /// Query via DNS over HTTPS (DoH) — courierust HTTP client.
    fn query_doh(&self, message: &Message) -> Result<Message> {
        let data = message
            .to_bytes()
            .map_err(|e| DnsError::Protocol(e.to_string()))?;

        // Build the DoH URL.
        let host = self.config.address.clone();
        let path = self
            .config
            .path
            .clone()
            .unwrap_or_else(|| "/dns-query".to_string());
        let port = self.config.port.unwrap_or(443);
        let url = format!("https://{host}:{port}{path}");

        debug!("DoH query to {}", url);

        // courierust client (blocking engine, system roots, HTTP/2).
        let client = build_doh_client(self.timeout);

        let mut req =
            courierust::courierust_http::Request::<courierust::courierust_body::Body>::new(
                courierust::courierust_http::Method::POST,
                "/",
            );
        req.headers.insert(
            courierust::courierust_http::HeaderName::from_static("content-type"),
            courierust::courierust_http::HeaderValue::from_static("application/dns-message"),
        );
        req.headers.insert(
            courierust::courierust_http::HeaderName::from_static("accept"),
            courierust::courierust_http::HeaderValue::from_static("application/dns-message"),
        );
        req.body = courierust::courierust_body::Body::from(data);
        let resp = client
            .execute(&url, req)
            .map_err(|e| DnsError::Http(format!("DoH request failed: {e}")))?;
        let status = resp.status.as_u16();
        if status != 200 {
            return Err(DnsError::Http(format!(
                "DoH server returned status {status}"
            )));
        }
        let body = resp
            .body
            .collect_limited(128 * 1024)
            .map_err(|e| DnsError::Http(format!("DoH response too large: {e}")))?;

        Message::from_bytes(&body).map_err(|e| DnsError::Protocol(e.to_string()))
    }

    /// Resolve upstream server address
    fn resolve_address(&self) -> Result<SocketAddr> {
        // If we have a direct socket address, use it
        if let Some(addr) = self.config.socket_addr() {
            return Ok(addr);
        }

        // Otherwise, we need to resolve the hostname
        // This is a bootstrap problem - we use system DNS for this
        let port = self.config.port.unwrap_or(match self.config.protocol {
            UpstreamProtocol::Udp | UpstreamProtocol::Tcp => 53,
            UpstreamProtocol::DoT | UpstreamProtocol::DoQ => 853,
            UpstreamProtocol::DoH => 443,
        });

        // Use the system resolver on a dedicated thread (bounded).
        let addrs = socket::resolve_host(&self.config.address, port, self.timeout)?;

        addrs.into_iter().next().ok_or(DnsError::QueryFailed(
            "Failed to resolve upstream DNS server".to_string(),
        ))
    }

    /// Get protocol type
    pub fn protocol(&self) -> DnsProtocol {
        match self.config.protocol {
            UpstreamProtocol::Udp => DnsProtocol::Udp,
            UpstreamProtocol::Tcp => DnsProtocol::Tcp,
            UpstreamProtocol::DoT => DnsProtocol::DoT,
            UpstreamProtocol::DoH => DnsProtocol::DoH,
            UpstreamProtocol::DoQ => DnsProtocol::DoQ,
        }
    }

    /// Get server address
    pub fn address(&self) -> &str {
        &self.config.address
    }
}

/// Create DNS clients from configuration strings
pub fn create_clients(servers: &[String], timeout: Duration) -> Vec<DnsClient> {
    servers
        .iter()
        .filter_map(|s| {
            UpstreamConfig::parse(s).and_then(|config| DnsClient::new(config, timeout).ok())
        })
        .collect()
}

/// Build a courierust HTTP client for DoH queries (system roots, HTTP/2,
/// bounded bodies).
fn build_doh_client(timeout: Duration) -> courierust::courierust_client::Client {
    use courierust::courierust_client::{ClientConfig, TlsSettings};

    let tls = TlsSettings {
        roots: crate::common::roots::system_root_store().clone(),
        verify: true,
        alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        now: unix_now(),
        min_version: TlsVersion::Tls12,
        max_version: TlsVersion::Tls13,
    };
    courierust::courierust_client::Client::with_config(ClientConfig {
        http2: true,
        max_redirects: 3,
        max_body: 128 * 1024,
        max_header_list: 16 * 1024,
        connect_timeout: Some(timeout),
        read_timeout: Some(timeout),
        handshake_timeout: Some(timeout),
        tls: Some(tls),
        ..Default::default()
    })
}

/// Current Unix time in seconds (for certificate validity checks).
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Map an I/O error to a `DnsError`, preserving timeouts as
/// `DnsError::Timeout`.
fn map_io(e: std::io::Error) -> DnsError {
    if matches!(
        e.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        DnsError::Timeout
    } else {
        DnsError::Io(e)
    }
}

/// Write a buffer in full over a courierust writer.
fn write_all<W: CWrite>(writer: &mut W, mut data: &[u8]) -> Result<()> {
    while !data.is_empty() {
        match CWrite::write(writer, data) {
            Ok(0) => return Err(DnsError::Protocol("write returned 0 bytes".into())),
            Ok(n) => data = &data[n..],
            Err(e) if matches!(e.kind, courierust::courierust_error::ErrorKind::WouldBlock) => {
                std::thread::yield_now();
            }
            Err(e) => return Err(DnsError::Tls(e.to_string())),
        }
    }
    Ok(())
}

/// Read exactly `out.len()` bytes over a courierust reader.
fn read_exact<R: CRead>(reader: &mut R, out: &mut [u8]) -> Result<()> {
    let mut filled = 0;
    while filled < out.len() {
        match CRead::read(reader, &mut out[filled..]) {
            Ok(0) => return Err(DnsError::Protocol("connection closed mid-response".into())),
            Ok(n) => filled += n,
            Err(e) if matches!(e.kind, courierust::courierust_error::ErrorKind::WouldBlock) => {
                std::thread::yield_now();
            }
            Err(e) if matches!(e.kind, courierust::courierust_error::ErrorKind::Timeout) => {
                return Err(DnsError::Timeout);
            }
            Err(e) => return Err(DnsError::Tls(e.to_string())),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires outbound UDP access to a public DNS resolver"]
    fn test_udp_query() {
        let config = UpstreamConfig::parse("8.8.8.8").unwrap();
        let client = DnsClient::new(config, Duration::from_secs(5)).unwrap();

        let result = client.query("google.com", RecordType::A);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(!response.answers.is_empty());
    }
}
