//! DNS over TLS (DoT) server — RFC 7858, on courierust's TLS.
//!
//! Each accepted connection is handled on a dedicated thread: a courierust
//! TLS handshake, then the RFC 7858 2-byte length-prefixed DNS exchange
//! against the engine's synchronous DNS resolver.
//!
//! The acceptor is built **once** for the listener's lifetime: it holds the
//! session-ticket key, so a client that asks for TLS resumption actually gets
//! it (a per-connection acceptor could never resume).

use crate::common::cancel::CancellationToken;
use crate::common::listener::ConnectionListener;
use crate::dns::error::{DnsError, Result};
use crate::dns::resolver::DnsResolver;
use crate::dns::wire::{BinDecodable, BinEncodable, Message};
use courierust::courierust_io::{Read as CRead, Write as CWrite};
use courierust::courierust_tls::{Identity, ServerConfig, TlsAcceptor, TlsVersion};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, trace, warn};

/// Upper bound on concurrently served DoT connections (one thread each).
const MAX_CONNECTIONS: usize = 512;

/// DoT server configuration.
#[derive(Debug, Clone)]
pub struct DotServerConfig {
    /// Listen address (default: 127.0.0.1:853).
    pub listen: SocketAddr,
    /// TLS certificate path.
    pub cert_path: String,
    /// TLS private key path.
    pub key_path: String,
    /// Connection timeout in seconds.
    pub timeout_secs: u64,
}

impl Default for DotServerConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:853".parse().unwrap(),
            cert_path: String::new(),
            key_path: String::new(),
            timeout_secs: 30,
        }
    }
}

/// DNS over TLS server.
pub struct DotServer {
    /// Configuration.
    config: DotServerConfig,
    /// DNS resolver.
    resolver: Arc<DnsResolver>,
    /// TLS acceptor (identity validated at construction, ticket key stable
    /// for the listener's lifetime).
    acceptor: Arc<TlsAcceptor>,
    /// Shutdown signal.
    shutdown: CancellationToken,
}

impl DotServer {
    /// Create a new DoT server.
    pub fn new(config: DotServerConfig, resolver: Arc<DnsResolver>) -> Result<Self> {
        if config.cert_path.is_empty() || config.key_path.is_empty() {
            return Err(DnsError::Config(
                "DoT server requires TLS certificate and key".to_string(),
            ));
        }

        let identity = Identity::from_pem_file(&config.cert_path, &config.key_path)
            .map_err(|e| DnsError::Config(format!("Failed to load DoT TLS identity: {e}")))?;
        let acceptor = Arc::new(TlsAcceptor::new(ServerConfig {
            identity,
            min_version: TlsVersion::Tls12,
            max_version: TlsVersion::Tls13,
            ..ServerConfig::default()
        }));

        Ok(Self {
            config,
            resolver,
            acceptor,
            shutdown: CancellationToken::new(),
        })
    }

    /// Start the DoT server. Returns after the listener is bound; blocks
    /// until [`Self::stop`] is called.
    pub fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(self.config.listen).map_err(DnsError::Io)?;
        listener.set_nonblocking(true).map_err(DnsError::Io)?;

        let resolver = Arc::clone(&self.resolver);
        let acceptor = Arc::clone(&self.acceptor);
        let timeout = Duration::from_secs(self.config.timeout_secs);

        let mut server = ConnectionListener::new(listener, self.config.listen, MAX_CONNECTIONS);
        server
            .start("corduit-dot-conn", move |stream, addr| {
                if let Err(e) = handle_connection(stream, addr, &resolver, &acceptor, timeout) {
                    debug!("DoT connection error from {}: {}", addr, e);
                }
            })
            .map_err(DnsError::Io)?;
        info!("DoT server listening on {}", self.config.listen);
        self.shutdown.wait(Duration::from_secs(u64::MAX));
        server.stop();
        info!("DoT server stopped");
        Ok(())
    }

    /// Stop the DoT server.
    pub fn stop(&self) {
        self.shutdown.cancel();
    }

    /// Get the listen address.
    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen
    }
}

/// Handle a single TLS connection: handshake, then length-prefixed DNS
/// request/response until the peer closes or times out.
fn handle_connection(
    stream: TcpStream,
    addr: SocketAddr,
    resolver: &DnsResolver,
    acceptor: &Arc<TlsAcceptor>,
    timeout: Duration,
) -> Result<()> {
    trace!("DoT connection from {}", addr);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let stream = Arc::new(stream);
    let mut tls = acceptor
        .accept(stream.clone(), stream.clone())
        .map_err(|e| DnsError::Tls(format!("TLS handshake failed: {e}")))?;

    loop {
        let mut len_buf = [0u8; 2];
        match read_exact(&mut tls, &mut len_buf) {
            Ok(()) => {}
            Err(DnsError::Timeout) | Err(DnsError::Io(_)) | Err(_) => break,
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 || len > 65535 {
            break;
        }

        let mut query = vec![0u8; len];
        if read_exact(&mut tls, &mut query).is_err() {
            break;
        }

        let request = match Message::from_bytes(&query) {
            Ok(m) => m,
            Err(e) => {
                debug!("DoT malformed query from {}: {}", addr, e);
                break;
            }
        };
        let response = match crate::dns::server::process_query(resolver, &request) {
            Ok(r) => r,
            Err(e) => {
                warn!("DoT resolution failed for {}: {}", addr, e);
                break;
            }
        };
        let response_data = response
            .to_bytes()
            .map_err(|e| DnsError::Protocol(format!("Failed to serialize response: {e}")))?;

        let mut out = Vec::with_capacity(2 + response_data.len());
        out.extend_from_slice(&(response_data.len() as u16).to_be_bytes());
        out.extend_from_slice(&response_data);
        if write_all(&mut tls, &out).is_err() {
            break;
        }
    }

    Ok(())
}

/// Read exactly `out.len()` bytes over a courierust reader.
fn read_exact<R: CRead>(reader: &mut R, out: &mut [u8]) -> Result<()> {
    let mut filled = 0;
    while filled < out.len() {
        match CRead::read(reader, &mut out[filled..]) {
            Ok(0) => return Err(DnsError::Protocol("connection closed".into())),
            Ok(n) => filled += n,
            Err(e) if matches!(e.kind, courierust::courierust_error::ErrorKind::WouldBlock) => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(e) if matches!(e.kind, courierust::courierust_error::ErrorKind::Timeout) => {
                return Err(DnsError::Timeout);
            }
            Err(e) => return Err(DnsError::Tls(e.to_string())),
        }
    }
    Ok(())
}

/// Write a buffer in full over a courierust writer.
fn write_all<W: CWrite>(writer: &mut W, mut data: &[u8]) -> Result<()> {
    while !data.is_empty() {
        match CWrite::write(writer, data) {
            Ok(0) => return Err(DnsError::Protocol("write returned 0 bytes".into())),
            Ok(n) => data = &data[n..],
            Err(e) if matches!(e.kind, courierust::courierust_error::ErrorKind::WouldBlock) => {
                std::thread::sleep(std::time::Duration::from_millis(1));
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
    fn test_dot_server_config_default() {
        let config = DotServerConfig::default();
        assert_eq!(config.timeout_secs, 30);
        assert_eq!(config.listen.port(), 853);
    }

    #[test]
    fn test_dot_server_requires_tls() {
        let config = DotServerConfig::default();
        let resolver = Arc::new(
            crate::dns::resolver::DnsResolver::new(crate::dns::config::DnsConfig {
                nameservers: vec!["8.8.8.8".to_string()],
                ..Default::default()
            })
            .unwrap(),
        );
        assert!(DotServer::new(config, resolver).is_err());
    }
}
