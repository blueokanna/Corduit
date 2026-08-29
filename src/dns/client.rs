//! DNS client for upstream queries

use crate::dns::config::{UpstreamConfig, UpstreamProtocol};
use crate::dns::error::{DnsError, Result};

use crate::dns::wire::{
    BinDecodable, BinEncodable, Message, MessageType, Name, OpCode, Query, RecordType,
};
use crate::protocol::tls::{ClientConfig as TlsClientConfig, TlsConnector};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
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
    /// TLS connector for DoT/DoH
    tls_connector: Option<Arc<TlsConnector>>,
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
    fn create_tls_connector() -> Result<TlsConnector> {
        TlsConnector::new(TlsClientConfig {
            server_name: None,
            alpn: Vec::new(),
            skip_cert_verify: false,
            enable_sni: true,
        })
        .map_err(|e| DnsError::Tls(format!("Failed to create TLS connector: {e}")))
    }

    /// Query DNS
    pub async fn query(&self, name: &str, record_type: RecordType) -> Result<Message> {
        let message = self.build_query(name, record_type)?;

        match self.config.protocol {
            UpstreamProtocol::Udp => self.query_udp(&message).await,
            UpstreamProtocol::Tcp => self.query_tcp(&message).await,
            UpstreamProtocol::DoT => self.query_dot(&message).await,
            UpstreamProtocol::DoH => self.query_doh(&message).await,
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
    async fn query_udp(&self, message: &Message) -> Result<Message> {
        let addr = self.resolve_address().await?;
        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        let data = message
            .to_bytes()
            .map_err(|e| DnsError::Protocol(e.to_string()))?;

        socket.send_to(&data, addr).await?;

        let mut buf = vec![0u8; 4096];
        let result = timeout(self.timeout, socket.recv_from(&mut buf)).await;

        match result {
            Ok(Ok((len, _))) => {
                let response = Message::from_bytes(&buf[..len])
                    .map_err(|e| DnsError::Protocol(e.to_string()))?;
                Ok(response)
            }
            Ok(Err(e)) => Err(DnsError::Io(e)),
            Err(_) => Err(DnsError::Timeout),
        }
    }

    /// Query via TCP
    async fn query_tcp(&self, message: &Message) -> Result<Message> {
        let addr = self.resolve_address().await?;
        let mut stream = timeout(self.timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| DnsError::Timeout)??;

        let data = message
            .to_bytes()
            .map_err(|e| DnsError::Protocol(e.to_string()))?;

        // TCP DNS uses 2-byte length prefix
        let len = (data.len() as u16).to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(&data).await?;

        // Read response length
        let mut len_buf = [0u8; 2];
        timeout(self.timeout, stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| DnsError::Timeout)??;
        let len = u16::from_be_bytes(len_buf) as usize;

        // Read response
        let mut buf = vec![0u8; len];
        timeout(self.timeout, stream.read_exact(&mut buf))
            .await
            .map_err(|_| DnsError::Timeout)??;

        let response = Message::from_bytes(&buf).map_err(|e| DnsError::Protocol(e.to_string()))?;
        Ok(response)
    }

    /// Query via DNS over TLS (DoT) — courierust TLS bridged to tokio.
    async fn query_dot(&self, message: &Message) -> Result<Message> {
        let addr = self.resolve_address().await?;
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

        let tcp_stream = timeout(self.timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| DnsError::Timeout)??;

        let mut tls_stream = timeout(self.timeout, connector.connect(tcp_stream, &server_name))
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(|e| DnsError::Tls(e.to_string()))?;

        let data = message
            .to_bytes()
            .map_err(|e| DnsError::Protocol(e.to_string()))?;

        // TCP DNS uses 2-byte length prefix (RFC 7858).
        let len = (data.len() as u16).to_be_bytes();
        tls_stream.write_all(&len).await?;
        tls_stream.write_all(&data).await?;

        // Read response length.
        let mut len_buf = [0u8; 2];
        timeout(self.timeout, tls_stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| DnsError::Timeout)??;
        let len = u16::from_be_bytes(len_buf) as usize;

        // Read response.
        let mut buf = vec![0u8; len];
        timeout(self.timeout, tls_stream.read_exact(&mut buf))
            .await
            .map_err(|_| DnsError::Timeout)??;

        Message::from_bytes(&buf).map_err(|e| DnsError::Protocol(e.to_string()))
    }

    /// Query via DNS over HTTPS (DoH) — courierust HTTP client.
    async fn query_doh(&self, message: &Message) -> Result<Message> {
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

        // courierust client (blocking engine bridged to tokio).
        let client = build_doh_client(self.timeout);
        let url = url.clone();
        let data = data.clone();
        let body = tokio::task::spawn_blocking(move || {
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
            Ok::<Vec<u8>, DnsError>(body.to_vec())
        })
        .await
        .map_err(|e| DnsError::Http(format!("DoH worker panicked: {e}")))?;

        let body = body?;
        Message::from_bytes(&body).map_err(|e| DnsError::Protocol(e.to_string()))
    }

    /// Resolve upstream server address
    async fn resolve_address(&self) -> Result<SocketAddr> {
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

        // Use tokio's built-in DNS resolution (system resolver)
        let addrs: Vec<SocketAddr> =
            tokio::net::lookup_host(format!("{}:{}", self.config.address, port))
                .await?
                .collect();

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
    use courierust::courierust_tls::TlsVersion;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires outbound UDP access to a public DNS resolver"]
    async fn test_udp_query() {
        let config = UpstreamConfig::parse("8.8.8.8").unwrap();
        let client = DnsClient::new(config, Duration::from_secs(5)).unwrap();

        let result = client.query("google.com", RecordType::A).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(!response.answers.is_empty());
    }
}
