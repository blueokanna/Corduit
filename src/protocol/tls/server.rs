//! TLS server acceptor on courierust's TLS 1.2/1.3 (replacing `rustls` +
//! `tokio-rustls`).
//!
//! Same model as the client: the handshake runs on a `spawn_blocking`
//! worker over a `std::net::TcpStream`, and the resulting blocking TLS
//! stream is bridged back to tokio.

use super::config::ServerConfig;
use super::error::{Result, TlsError};
use super::{BoxStream, TlsStream};
use crate::common::http_server::TlsIdentity;
use std::sync::Arc;
use std::time::Duration;

/// Timeout for the TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// Socket write timeout.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Read timeout used for the relay loop after the handshake.
const RELAY_READ_TIMEOUT: Duration = Duration::from_millis(20);

/// TLS server acceptor (courierust).
#[derive(Clone)]
pub struct TlsAcceptor {
    inner: Arc<courierust::courierust_tls::TlsAcceptor>,
    config: ServerConfig,
}

impl TlsAcceptor {
    /// Build an acceptor from PEM certificate + key content.
    pub fn new(config: ServerConfig) -> Result<Self> {
        let identity = TlsIdentity::from_pem(&config.certificate, &config.private_key)
            .map_err(|e| TlsError::Certificate(format!("Invalid TLS identity: {e}")))?;
        let inner = Arc::new(courierust::courierust_tls::TlsAcceptor::new(
            courierust::courierust_tls::ServerConfig {
                identity: courierust::courierust_tls::Identity {
                    cert_chain: identity.cert_chain,
                    private_key: identity.private_key,
                    is_rsa: identity.is_rsa,
                },
                alpn: config.alpn.iter().map(|s| s.as_bytes().to_vec()).collect(),
                min_version: courierust::courierust_tls::TlsVersion::Tls12,
                max_version: courierust::courierust_tls::TlsVersion::Tls13,
                session_ticket_key: None,
            },
        ));
        Ok(Self { inner, config })
    }

    /// Accept a TLS handshake on `stream`. Returns a boxed async stream.
    pub async fn accept(&self, stream: tokio::net::TcpStream) -> Result<BoxStream> {
        let acceptor = self.inner.clone();

        tokio::task::spawn_blocking(move || {
            let std_stream = stream.into_std().map_err(TlsError::Io)?;
            let _ = std_stream.set_nodelay(true);
            let _ = std_stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
            let _ = std_stream.set_write_timeout(Some(WRITE_TIMEOUT));

            let arc = Arc::new(std_stream);
            let tls = acceptor
                .accept(arc.clone(), arc.clone())
                .map_err(|e| TlsError::Handshake(e.to_string()))?;

            let _ = arc.set_read_timeout(Some(RELAY_READ_TIMEOUT));

            type Stream = courierust::courierust_tls::TlsStream<
                Arc<std::net::TcpStream>,
                Arc<std::net::TcpStream>,
            >;
            let hook: crate::common::ShutdownHook<Stream> = Box::new(|s| {
                let _ = s.close_notify();
            });

            Ok(Box::new(TlsStream::new(tls, 64, Some(hook))) as BoxStream)
        })
        .await
        .map_err(|e| TlsError::Io(std::io::Error::other(format!("TLS worker panicked: {e}"))))?
    }

    /// The underlying configuration.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }
}
