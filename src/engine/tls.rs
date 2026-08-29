use crate::engine::error::{Error, Result};

pub use crate::protocol::tls::{
    ClientConfig, ServerConfig, SkipServerVerification, TlsAcceptor, TlsConnector, TlsStream,
};

pub fn yaml_value_to_string(value: &nextjson::Value) -> String {
    match value {
        nextjson::Value::String(s) => s.clone(),
        nextjson::Value::Number(n) => n.to_string(),
        nextjson::Value::Bool(b) => b.to_string(),
        _ => value.as_str().map(|s| s.to_string()).unwrap_or_default(),
    }
}

/// No-op kept for API compatibility.
///
/// The old implementation installed the `ring` crypto provider for rustls.
/// TLS is now provided by courierust (self-contained, zero dependencies),
/// so there is no global provider to install. The function remains so entry
/// points (`Corduit::new`, FFI `init_app`, …) don't need to change.
pub fn install_crypto_provider() {
    // Intentionally empty: courierust carries its own crypto primitives.
}

#[derive(Clone)]
pub struct Certificate(pub Vec<u8>);

impl Certificate {
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        Ok(Self(pem.to_vec()))
    }
}

/// Private key wrapper for compatibility
#[derive(Clone)]
pub struct PrivateKey(pub Vec<u8>);

impl PrivateKey {
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        Ok(Self(pem.to_vec()))
    }
}

/// Create a TLS connector with default settings
pub fn create_tls_connector() -> Result<TlsConnector> {
    let config = ClientConfig::default();
    TlsConnector::new(config).map_err(|e| Error::Tls {
        message: format!("Failed to create TLS connector: {}", e),
        source: None,
    })
}

pub fn create_insecure_tls_connector() -> Result<TlsConnector> {
    let config = ClientConfig {
        skip_cert_verify: true,
        ..Default::default()
    };
    TlsConnector::new(config).map_err(|e| Error::Tls {
        message: format!("Failed to create insecure TLS connector: {}", e),
        source: None,
    })
}

/// Create a TLS acceptor with certificate and key
pub fn create_tls_acceptor(cert_pem: &str, key_pem: &str) -> Result<TlsAcceptor> {
    let config = ServerConfig {
        certificate: cert_pem.to_string(),
        private_key: key_pem.to_string(),
        ..Default::default()
    };
    TlsAcceptor::new(config).map_err(|e| Error::Tls {
        message: format!("Failed to create TLS acceptor: {}", e),
        source: None,
    })
}

/// Shadow TLS implementation
/// Enhanced TLS with additional obfuscation features
pub mod shadow_tls {
    use super::*;

    pub struct ShadowTlsConnector {
        inner: TlsConnector,
        obfuscation_enabled: bool,
    }

    impl ShadowTlsConnector {
        pub fn new() -> Result<Self> {
            let inner = create_tls_connector()?;
            Ok(Self {
                inner,
                obfuscation_enabled: true,
            })
        }

        /// Enable/disable TLS fingerprint obfuscation
        pub fn set_obfuscation(&mut self, enabled: bool) {
            self.obfuscation_enabled = enabled;
        }

        pub fn connect(
            &self,
            stream: std::net::TcpStream,
            server_name: &str,
        ) -> Result<ShadowTlsStream> {
            let tls_stream = self
                .inner
                .connect(stream, server_name)
                .map_err(|e| Error::Tls {
                    message: format!("Shadow TLS connection failed: {}", e),
                    source: None,
                })?;
            Ok(ShadowTlsStream {
                inner: tls_stream,
                obfuscation_enabled: self.obfuscation_enabled,
            })
        }
    }

    impl Default for ShadowTlsConnector {
        fn default() -> Self {
            Self::new().expect("Failed to create default Shadow TLS connector")
        }
    }

    pub struct ShadowTlsStream {
        inner: crate::protocol::tls::BoxStream,
        #[allow(dead_code)]
        obfuscation_enabled: bool,
    }

    impl ShadowTlsStream {
        pub fn into_inner(self) -> crate::protocol::tls::BoxStream {
            self.inner
        }
    }
}
