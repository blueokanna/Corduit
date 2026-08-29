//! TLS transport on courierust's TLS 1.2/1.3 (replacing `rustls` +
//! `tokio-rustls`).
//!
//! The transport is a thin configuration adapter over
//! [`crate::protocol::tls::TlsConnector`]: `TlsConfig` (SNI, ALPN, verify
//! skip, SNI toggle) maps to courierust's [`ClientConfig`] and the connector
//! returns a boxed async stream whose handshake runs on a worker thread.
//!
//! `TlsFingerprint` is retained as a configuration-compatibility enum: the
//! legacy mapping only ever rewrote the ALPN list, which courierust exposes
//! directly, so the fingerprint variants no longer change wire behavior
//! (courierust does not emulate browser TLS/JA3 fingerprints).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use nextjson::{NsonDeserialize, NsonSerialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{Result, TransportError};
use crate::protocol::tls::{ClientConfig as TlsClientConfig, TlsConnector as CourierConnector};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsFingerprint {
    #[default]
    None,
    Chrome,
    Firefox,
    Safari,
    Ios,
    Android,
    Edge,
    Random,
}

crate::impl_protocol_enum!(TlsFingerprint {
    None => "none",
    Chrome => "chrome",
    Firefox => "firefox",
    Safari => "safari",
    Ios => "ios",
    Android => "android",
    Edge => "edge",
    Random => "random",
});

#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub alpn: Vec<String>,
    #[serde(default)]
    pub skip_cert_verify: bool,
    #[serde(default = "default_enable_sni")]
    pub enable_sni: bool,
    #[serde(default)]
    pub fingerprint: TlsFingerprint,
    #[serde(default)]
    pub min_version: Option<String>,
    #[serde(default)]
    pub max_version: Option<String>,
}

fn default_enable_sni() -> bool {
    true
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            sni: None,
            alpn: vec!["h2".into(), "http/1.1".into()],
            skip_cert_verify: false,
            enable_sni: true,
            fingerprint: TlsFingerprint::None,
            min_version: None,
            max_version: None,
        }
    }
}

pub struct TlsTransport {
    config: TlsConfig,
    connector: CourierConnector,
    server_name: String,
}

impl TlsTransport {
    pub fn new(config: TlsConfig, server_name: &str) -> Result<Self> {
        let connector = Self::build_connector(&config)?;
        let sni = config
            .sni
            .clone()
            .unwrap_or_else(|| server_name.to_string());

        Ok(Self {
            config,
            connector,
            server_name: sni,
        })
    }

    fn build_connector(config: &TlsConfig) -> Result<CourierConnector> {
        // A legacy `TlsFingerprint` that isn't `None` pins the ALPN to the
        // browser-friendly h2/http1.1 pair (the same effect the old
        // implementation had).
        let mut alpn = config.alpn.clone();
        if config.fingerprint != TlsFingerprint::None && alpn.is_empty() {
            alpn = vec!["h2".into(), "http/1.1".into()];
        }
        let tls_cfg = TlsClientConfig {
            server_name: config.sni.clone(),
            alpn,
            skip_cert_verify: config.skip_cert_verify,
            enable_sni: config.enable_sni,
        };
        CourierConnector::new(tls_cfg)
            .map_err(|e| TransportError::InvalidConfig(format!("Failed to build TLS config: {e}")))
    }

    pub async fn connect(
        &self,
        stream: tokio::net::TcpStream,
    ) -> Result<TlsStream<crate::protocol::tls::BoxStream>> {
        let tls_stream = self
            .connector
            .connect(stream, &self.server_name)
            .await
            .map_err(|e| TransportError::Handshake(format!("TLS handshake failed: {e}")))?;
        Ok(TlsStream::new(tls_stream))
    }

    pub fn config(&self) -> &TlsConfig {
        &self.config
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }
}

pub struct TlsStream<S> {
    inner: S,
}

impl<S> TlsStream<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_config_default() {
        let config = TlsConfig::default();
        assert!(config.sni.is_none());
        assert_eq!(config.alpn, vec!["h2", "http/1.1"]);
        assert!(!config.skip_cert_verify);
        assert!(config.enable_sni);
        assert_eq!(config.fingerprint, TlsFingerprint::None);
    }

    #[test]
    fn test_tls_transport_new() {
        let config = TlsConfig::default();
        let transport = TlsTransport::new(config, "example.com").unwrap();
        assert_eq!(transport.server_name(), "example.com");
    }

    #[test]
    fn test_tls_transport_with_custom_sni() {
        let config = TlsConfig {
            sni: Some("custom.sni.com".to_string()),
            ..Default::default()
        };
        let transport = TlsTransport::new(config, "example.com").unwrap();
        assert_eq!(transport.server_name(), "custom.sni.com");
    }

    #[test]
    fn test_tls_config_serialization() {
        let config = TlsConfig {
            sni: Some("test.com".to_string()),
            alpn: vec!["h2".to_string()],
            skip_cert_verify: true,
            enable_sni: true,
            fingerprint: TlsFingerprint::Chrome,
            min_version: None,
            max_version: None,
        };

        let json = nextjson::to_string(&config).unwrap();
        let deserialized: TlsConfig = nextjson::from_str(&json).unwrap();

        assert_eq!(deserialized.sni, config.sni);
        assert_eq!(deserialized.alpn, config.alpn);
        assert_eq!(deserialized.skip_cert_verify, config.skip_cert_verify);
        assert_eq!(deserialized.fingerprint, config.fingerprint);
    }
}
