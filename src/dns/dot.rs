//! DNS over TLS (DoT) client — RFC 7858, on courierust's TLS.
//!
//! Each query is a short request/response exchange: connect a TCP socket,
//! perform a TLS 1.2/1.3 handshake with courierust (system roots from
//! [`crate::common::roots`]), write the 2-byte length-prefixed DNS message,
//! read the length-prefixed reply. The whole exchange is synchronous.

use crate::common::roots::system_root_store;
use crate::dns::error::{DnsError, Result};
use crate::dns::wire::{
    BinDecodable, BinEncodable, Message, MessageType, Name, OpCode, Query, RData,
};
use crate::dns::RecordType;
use courierust::courierust_io::{Read as CRead, Write as CWrite};
use courierust::courierust_tls::{ClientConfig, TlsConnector, TlsVersion};
use parking_lot::RwLock;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, trace, warn};

/// DNS over TLS uses a 2-byte big-endian length prefix (RFC 7858 §3.3).
const LEN_PREFIX: usize = 2;

/// DoT client configuration.
#[derive(Debug, Clone)]
pub struct DotClientConfig {
    /// Server address (IP or hostname).
    pub server: String,
    /// Server port (default: 853).
    pub port: u16,
    /// TLS server name (SNI).
    pub tls_name: Option<String>,
    /// Connection timeout.
    pub timeout: Duration,
    /// Enable session resumption (courierust keeps a per-connector ticket
    /// store, so a `TlsConnector` shared across queries resumes 1-RTT).
    pub session_resumption: bool,
}

impl Default for DotClientConfig {
    fn default() -> Self {
        Self {
            server: "dns.google".to_string(),
            port: 853,
            tls_name: None,
            timeout: Duration::from_secs(5),
            session_resumption: true,
        }
    }
}

/// DoT client for DNS resolution.
pub struct DotClient {
    /// Server address.
    server: String,
    /// Server port.
    port: u16,
    /// TLS server name.
    tls_name: String,
    /// TLS connector (shares the resumption-session store across queries).
    tls_connector: TlsConnector,
    /// Connection timeout.
    timeout: Duration,
}

impl DotClient {
    /// Create a new DoT client.
    pub fn new(server: &str, port: u16, tls_name: Option<&str>) -> Result<Self> {
        let tls_connector = Self::create_tls_connector()?;

        Ok(Self {
            server: server.to_string(),
            port,
            tls_name: tls_name.unwrap_or(server).to_string(),
            tls_connector,
            timeout: Duration::from_secs(5),
        })
    }

    /// Create with configuration.
    pub fn with_config(config: DotClientConfig) -> Result<Self> {
        let tls_connector = Self::create_tls_connector()?;

        Ok(Self {
            server: config.server.clone(),
            port: config.port,
            tls_name: config.tls_name.unwrap_or(config.server),
            tls_connector,
            timeout: config.timeout,
        })
    }

    /// Create the courierust TLS connector with system root certificates.
    fn create_tls_connector() -> Result<TlsConnector> {
        Ok(TlsConnector::new(ClientConfig {
            roots: system_root_store().clone(),
            verify: true,
            alpn: Vec::new(),
            now: unix_now(),
            min_version: TlsVersion::Tls12,
            max_version: TlsVersion::Tls13,
        }))
    }

    /// Resolve a domain name to IP addresses.
    pub fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>> {
        // Try A records first.
        let mut ips = self.query(domain, RecordType::A).unwrap_or_default();

        // Also try AAAA records.
        if let Ok(ipv6) = self.query(domain, RecordType::AAAA) {
            ips.extend(ipv6);
        }

        if ips.is_empty() {
            return Err(DnsError::QueryFailed(format!(
                "No addresses found for {}",
                domain
            )));
        }

        Ok(ips)
    }

    /// Query DNS records.
    pub fn query(&self, domain: &str, record_type: RecordType) -> Result<Vec<IpAddr>> {
        let query_bytes = self.build_query(domain, record_type.into())?;
        let response_bytes = self.send_query(&query_bytes)?;
        self.parse_response(&response_bytes)
    }

    /// Build DNS query message.
    fn build_query(
        &self,
        domain: &str,
        record_type: crate::dns::wire::RecordType,
    ) -> Result<Vec<u8>> {
        let name = Name::from_str(domain)
            .map_err(|e| DnsError::NameError(format!("Invalid domain name: {}", e)))?;

        let mut message = Message::new(
            crate::dns::util::random_id(),
            MessageType::Query,
            OpCode::Query,
        );
        message.metadata.recursion_desired = true;

        let query = Query::query(name, record_type);
        message.add_query(query);

        message
            .to_vec()
            .map_err(|e| DnsError::Protocol(format!("Failed to serialize query: {}", e)))
    }

    /// Send a DNS query over TLS via courierust (blocking exchange).
    fn send_query(&self, query: &[u8]) -> Result<Vec<u8>> {
        // Resolve the host (courierust's transport is synchronous).
        let addrs: Vec<SocketAddr> = (self.server.as_str(), self.port)
            .to_socket_addrs()
            .map_err(DnsError::Io)?
            .collect();
        let addr = addrs.first().copied().ok_or_else(|| {
            DnsError::Config(format!("no address for {}:{}", self.server, self.port))
        })?;

        let tcp = TcpStream::connect_timeout(&addr, self.timeout).map_err(DnsError::Io)?;
        let _ = tcp.set_read_timeout(Some(self.timeout));
        let _ = tcp.set_write_timeout(Some(self.timeout));

        // TLS handshake over the socket.
        let mut tls = self
            .tls_connector
            .connect(&self.tls_name, &tcp, &tcp)
            .map_err(|e| DnsError::Tls(format!("TLS handshake failed: {e}")))?;

        // Write the 2-byte length prefix + query.
        let mut request = Vec::with_capacity(LEN_PREFIX + query.len());
        request.extend_from_slice(&(query.len() as u16).to_be_bytes());
        request.extend_from_slice(query);
        write_all(&mut tls, &request)
            .map_err(|e| DnsError::Io(std::io::Error::other(e.to_string())))?;

        // Read the response length prefix.
        let mut len_buf = [0u8; 2];
        read_exact(&mut tls, &mut len_buf)
            .map_err(|e| DnsError::Io(std::io::Error::other(e.to_string())))?;
        let response_len = u16::from_be_bytes(len_buf) as usize;
        if response_len > 65535 {
            return Err(DnsError::Protocol("Response too large".to_string()));
        }

        // Read the response body.
        let mut response = vec![0u8; response_len];
        read_exact(&mut tls, &mut response)
            .map_err(|e| DnsError::Io(std::io::Error::other(e.to_string())))?;

        trace!("DoT received {} bytes response", response.len());
        Ok(response)
    }

    /// Parse DNS response.
    fn parse_response(&self, response: &[u8]) -> Result<Vec<IpAddr>> {
        let message = Message::from_bytes(response)
            .map_err(|e| DnsError::Protocol(format!("Failed to parse DNS response: {}", e)))?;

        let mut ips = Vec::new();

        for answer in &message.answers {
            match &answer.data {
                RData::A(a) => ips.push(IpAddr::V4(a.0)),
                RData::AAAA(aaaa) => ips.push(IpAddr::V6(aaaa.0)),
                _ => {}
            }
        }

        Ok(ips)
    }

    /// Get server address.
    pub fn server(&self) -> &str {
        &self.server
    }

    /// Get server port.
    pub fn port(&self) -> u16 {
        self.port
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

/// Read exactly `len` bytes over a courierust reader.
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

/// Current Unix time in seconds (for TLS certificate validity checks).
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// DoT resolver with multiple upstream servers and load balancing.
pub struct DotResolver {
    /// DoT clients.
    clients: Vec<DotClient>,
    /// Current client index (round-robin).
    current: Arc<RwLock<usize>>,
    /// Prefer IPv4 over IPv6.
    prefer_ipv4: bool,
}

impl DotResolver {
    /// Create a new DoT resolver with multiple upstream servers.
    ///
    /// # Arguments
    /// * `servers` - List of (server, port, tls_name) tuples.
    pub fn new(servers: &[(String, u16, Option<String>)]) -> Result<Self> {
        if servers.is_empty() {
            return Err(DnsError::Config("No DoT servers configured".to_string()));
        }

        let mut clients = Vec::new();
        for (server, port, tls_name) in servers {
            match DotClient::new(server, *port, tls_name.as_deref()) {
                Ok(client) => {
                    debug!("DoT client created for {}:{}", server, port);
                    clients.push(client);
                }
                Err(e) => {
                    warn!("Failed to create DoT client for {}:{}: {}", server, port, e);
                }
            }
        }

        if clients.is_empty() {
            return Err(DnsError::Config(
                "No valid DoT servers configured".to_string(),
            ));
        }

        Ok(Self {
            clients,
            current: Arc::new(RwLock::new(0)),
            prefer_ipv4: true,
        })
    }

    /// Create from URL strings (e.g., "tls://dns.google:853").
    pub fn from_urls(urls: &[String]) -> Result<Self> {
        let mut servers = Vec::new();

        for url in urls {
            if let Some(rest) = url.strip_prefix("tls://") {
                let (host, port) = if let Some((h, p)) = rest.rsplit_once(':') {
                    (h.to_string(), p.parse().unwrap_or(853))
                } else {
                    (rest.to_string(), 853)
                };
                servers.push((host.clone(), port, Some(host)));
            }
        }

        Self::new(&servers)
    }

    /// Set IPv4 preference.
    pub fn set_prefer_ipv4(&mut self, prefer: bool) {
        self.prefer_ipv4 = prefer;
    }

    /// Resolve a domain name using round-robin load balancing.
    pub fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let mut last_error = None;

        for _ in 0..self.clients.len() {
            let idx = {
                let mut current = self.current.write();
                let idx = *current;
                *current = (*current + 1) % self.clients.len();
                idx
            };

            let client = &self.clients[idx];

            match client.resolve(domain) {
                Ok(mut ips) if !ips.is_empty() => {
                    if self.prefer_ipv4 {
                        ips.sort_by_key(|ip| match ip {
                            IpAddr::V4(_) => 0,
                            IpAddr::V6(_) => 1,
                        });
                    }
                    debug!(
                        "DoT resolved {} to {:?} via {}",
                        domain,
                        ips,
                        client.server()
                    );
                    return Ok(ips);
                }
                Ok(_) => {
                    debug!(
                        "DoT returned empty result for {} via {}",
                        domain,
                        client.server()
                    );
                }
                Err(e) => {
                    debug!(
                        "DoT resolution failed for {} via {}: {}",
                        domain,
                        client.server(),
                        e
                    );
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            DnsError::QueryFailed(format!("All DoT servers failed for {}", domain))
        }))
    }

    /// Query a specific record type.
    pub fn query(&self, domain: &str, record_type: RecordType) -> Result<Vec<IpAddr>> {
        let mut last_error = None;

        for _ in 0..self.clients.len() {
            let idx = {
                let mut current = self.current.write();
                let idx = *current;
                *current = (*current + 1) % self.clients.len();
                idx
            };

            let client = &self.clients[idx];

            match client.query(domain, record_type) {
                Ok(ips) if !ips.is_empty() => return Ok(ips),
                Ok(_) => continue,
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            DnsError::QueryFailed(format!(
                "All DoT servers failed for {} {:?}",
                domain, record_type
            ))
        }))
    }
}
