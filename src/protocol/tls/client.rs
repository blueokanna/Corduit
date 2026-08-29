//! TLS client on courierust's TLS 1.2/1.3 (replacing `rustls` +
//! `tokio-rustls`).
//!
//! The connector is synchronous: [`TlsConnector::connect`] performs the
//! handshake over a `std::net::TcpStream` and returns a boxed
//! [`SyncStream`](crate::common::stream::SyncStream). The socket read
//! timeout is shortened after the handshake to the relay cadence.

use super::config::ClientConfig;
use super::error::{Result, TlsError};
use super::{BoxStream, TlsStream};
use crate::common::roots::system_root_store;
use courierust::courierust_tls::RootStore;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

/// Timeout for the TLS handshake (generous — a slow server may stall here).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// Socket write timeout.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Read timeout used for the relay loop after the handshake (bounds how
/// long a write waits while a relay thread is blocked in a read).
const RELAY_READ_TIMEOUT: Duration = Duration::from_millis(1000);

/// TLS client connector (courierust).
#[derive(Clone)]
pub struct TlsConnector {
    inner: courierust::courierust_tls::TlsConnector,
    config: ClientConfig,
}

impl TlsConnector {
    /// Build a connector from a configuration.
    pub fn new(config: ClientConfig) -> Result<Self> {
        let roots = if config.skip_cert_verify {
            RootStore::new()
        } else {
            system_root_store().clone()
        };
        let inner = courierust::courierust_tls::TlsConnector::new(
            courierust::courierust_tls::ClientConfig {
                roots,
                verify: !config.skip_cert_verify,
                alpn: config.alpn.iter().map(|s| s.as_bytes().to_vec()).collect(),
                now: unix_now(),
                min_version: courierust::courierust_tls::TlsVersion::Tls12,
                max_version: courierust::courierust_tls::TlsVersion::Tls13,
            },
        );
        Ok(Self { inner, config })
    }

    /// Perform a TLS handshake over `stream`, authenticating `server_name`
    /// (or the configured SNI override). Returns a boxed synchronous stream.
    pub fn connect(&self, stream: TcpStream, server_name: &str) -> Result<BoxStream> {
        let name = self
            .config
            .server_name
            .clone()
            .unwrap_or_else(|| server_name.to_string());
        let connector = self.inner.clone();

        let _ = stream.set_nodelay(true);
        let _ = stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
        let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));

        let arc = Arc::new(stream);
        let tls = connector
            .connect(&name, arc.clone(), arc.clone())
            .map_err(|e| TlsError::Handshake(e.to_string()))?;

        // The relay needs a bounded read timeout so the writer thread is
        // never starved by a blocked reader.
        let _ = arc.set_read_timeout(Some(RELAY_READ_TIMEOUT));

        Ok(Box::new(TlsStream::new(tls, arc)) as BoxStream)
    }

    /// The underlying configuration.
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }
}

/// Current Unix time in seconds (for certificate validity checks).
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
