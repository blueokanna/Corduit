use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pki_types::pem::PemObject;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor as TokioTlsAcceptor;

use super::config::ServerConfig;
use super::error::{Result, TlsError};
use super::stream::TlsStream;

pub struct TlsAcceptor {
    inner: TokioTlsAcceptor,
}

impl TlsAcceptor {
    pub fn new(config: ServerConfig) -> Result<Self> {
        let cert_pem = config.certificate.as_bytes();
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| TlsError::Certificate(format!("Invalid certificate: {}", e)))?;

        if certs.is_empty() {
            return Err(TlsError::Certificate("No certificates found".to_string()));
        }

        let key_pem = config.private_key.as_bytes();
        let key = PrivateKeyDer::from_pem_slice(key_pem)
            .map_err(|e| TlsError::Certificate(format!("Invalid private key: {}", e)))?;

        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| TlsError::Tls(e.to_string()))?;

        tls_config.alpn_protocols = config.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();

        let acceptor = TokioTlsAcceptor::from(Arc::new(tls_config));

        Ok(Self { inner: acceptor })
    }

    pub async fn accept<S>(
        &self,
        stream: S,
    ) -> Result<TlsStream<tokio_rustls::server::TlsStream<S>>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let tls_stream = self
            .inner
            .accept(stream)
            .await
            .map_err(|e| TlsError::Handshake(e.to_string()))?;

        Ok(TlsStream::new(tls_stream))
    }
}
