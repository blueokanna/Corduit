//! DNS over TLS (DoT) server — RFC 7858, on courierust's TLS.
//!
//! Each accepted connection is handled on a dedicated thread: a courierust
//! TLS handshake, then the RFC 7858 2-byte length-prefixed DNS exchange.
//! Queries are resolved through the async engine by blocking on a captured
//! `tokio::runtime::Handle` (the same seam the DoH server uses).

use crate::common::http_server::TlsIdentity;
use crate::dns::error::{DnsError, Result};
use crate::dns::resolver::DnsResolver;
use crate::dns::wire::{BinDecodable, BinEncodable, Message};
use courierust::courierust_io::{Read as CRead, Write as CWrite};
use courierust::courierust_tls::{ServerConfig, TlsAcceptor, TlsVersion};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{debug, info, trace, warn};

/// Poll interval of the accept loop while idle.
const ACCEPT_POLL: Duration = Duration::from_millis(5);

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
    /// TLS identity (cert chain + key).
    identity: TlsIdentity,
    /// Shutdown signal sender.
    shutdown_tx: broadcast::Sender<()>,
}

impl DotServer {
    /// Create a new DoT server.
    pub fn new(config: DotServerConfig, resolver: Arc<DnsResolver>) -> Result<Self> {
        if config.cert_path.is_empty() || config.key_path.is_empty() {
            return Err(DnsError::Config(
                "DoT server requires TLS certificate and key".to_string(),
            ));
        }

        let identity = TlsIdentity::from_pem_files(&config.cert_path, &config.key_path)
            .map_err(|e| DnsError::Config(format!("Failed to load TLS identity: {e}")))?;
        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Self {
            config,
            resolver,
            identity,
            shutdown_tx,
        })
    }

    /// Start the DoT server. Returns after the listener is bound; blocks (as
    /// an async task) until [`Self::stop`] is called.
    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(self.config.listen).map_err(DnsError::Io)?;
        listener.set_nonblocking(true).map_err(DnsError::Io)?;
        info!("DoT server listening on {}", self.config.listen);

        let resolver = self.resolver.clone();
        let identity = self.identity.clone();
        let timeout = Duration::from_secs(self.config.timeout_secs);
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        // Accept loop on a dedicated thread (non-blocking poll + flag).
        let loop_shutdown = shutdown.clone();
        let accept_thread = std::thread::Builder::new()
            .name("corduit-dot-accept".into())
            .spawn(move || {
                let runtime = tokio::runtime::Handle::current();
                while !loop_shutdown.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, addr)) => {
                            let resolver = resolver.clone();
                            let identity = identity.clone();
                            let runtime = runtime.clone();
                            std::thread::Builder::new()
                                .name("corduit-dot-conn".into())
                                .spawn(move || {
                                    if let Err(e) = handle_connection(
                                        stream, addr, &resolver, &identity, &runtime, timeout,
                                    ) {
                                        debug!("DoT connection error from {}: {}", addr, e);
                                    }
                                })
                                .ok();
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(ACCEPT_POLL);
                        }
                        Err(_) => break,
                    }
                }
            })
            .map_err(|e| DnsError::Io(e))?;

        let _ = shutdown_rx.recv().await;
        shutdown.store(true, Ordering::SeqCst);
        let _ = accept_thread.join();
        info!("DoT server stopped");
        Ok(())
    }

    /// Stop the DoT server.
    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(());
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
    identity: &TlsIdentity,
    runtime: &tokio::runtime::Handle,
    timeout: Duration,
) -> Result<()> {
    trace!("DoT connection from {}", addr);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let stream = Arc::new(stream);
    let acceptor = TlsAcceptor::new(ServerConfig {
        identity: courierust::courierust_tls::Identity {
            cert_chain: identity.cert_chain.clone(),
            private_key: identity.private_key.clone(),
            is_rsa: identity.is_rsa,
        },
        alpn: Vec::new(),
        min_version: TlsVersion::Tls12,
        max_version: TlsVersion::Tls13,
        session_ticket_key: None,
    });
    let mut tls = acceptor
        .accept(stream.clone(), stream.clone())
        .map_err(|e| DnsError::Tls(format!("TLS handshake failed: {e}")))?;

    loop {
        // Read the 2-byte big-endian length prefix.
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
        let response = match runtime.block_on(crate::dns::server::process_query(resolver, &request))
        {
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
