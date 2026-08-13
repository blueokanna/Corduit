use quinn::{
    ClientConfig as QuinnClientConfig, Connection, Endpoint, ServerConfig as QuinnServerConfig,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum TuicError {
    #[error("QUIC error: {0}")]
    Quic(#[from] quinn::ConnectionError),
    #[error("QUIC connect error: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("QUIC write error: {0}")]
    Write(#[from] quinn::WriteError),
    #[error("QUIC read error: {0}")]
    Read(#[from] quinn::ReadToEndError),
    #[error("QUIC closed stream: {0}")]
    ClosedStream(#[from] quinn::ClosedStream),
    #[error("Rustls error: {0}")]
    Rustls(#[from] quinn::rustls::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid configuration")]
    InvalidConfig,
    #[error("Authentication failed")]
    AuthFailed,
    #[error("Protocol error: {0}")]
    Protocol(String),
}

const TUIC_PROTOCOL_VERSION: u8 = 5;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum Command {
    Connect = 0,
    Bind = 1,
    Dns = 2,
    Associate = 3,
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub server_addr: SocketAddr,
    pub uuid: Uuid,
    pub password: Vec<String>,
    pub certificate: Option<String>,
    pub alpn: Option<Vec<String>>,
    pub udp_relay_mode: UdpRelayMode,
    pub congestion_control: CongestionControl,
    pub max_packet_size: usize,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen_addr: SocketAddr,
    pub uuid: Uuid,
    pub password: Vec<String>,
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
    pub max_packet_size: usize,
}

#[derive(Debug, Clone, Copy)]
pub enum UdpRelayMode {
    Native,
    Quic,
}

#[derive(Debug, Clone, Copy)]
pub enum CongestionControl {
    Cubic,
    NewReno,
    Bbr,
}

/// TUIC authentication request.
///
/// Wire format (stable protocol contract, never change):
/// ```text
/// [version: u8]
/// [uuid_len: u64 LE][uuid: utf8 hyphenated string]
/// [password_len: u64 LE][password: utf8 string]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthRequest {
    version: u8,
    uuid: Uuid,
    password: String,
}

impl AuthRequest {
    /// Serialize into the stable TLV wire format.
    fn encode(&self) -> Vec<u8> {
        let uuid_str = self.uuid.hyphenated().to_string();
        let password = self.password.as_bytes();
        let mut buf = Vec::with_capacity(1 + 8 + uuid_str.len() + 8 + password.len());
        buf.push(self.version);
        buf.extend_from_slice(&(uuid_str.len() as u64).to_le_bytes());
        buf.extend_from_slice(uuid_str.as_bytes());
        buf.extend_from_slice(&(password.len() as u64).to_le_bytes());
        buf.extend_from_slice(password);
        buf
    }

    /// Deserialize from the stable TLV wire format, rejecting malformed input.
    fn decode(input: &[u8]) -> Result<Self, TuicError> {
        /// Copy a fixed-size chunk, failing on truncation instead of panicking.
        fn take_u64(input: &[u8], offset: &mut usize) -> Result<u64, TuicError> {
            let end = offset
                .checked_add(8)
                .ok_or_else(|| TuicError::Protocol("length field overflow".into()))?;
            if end > input.len() {
                return Err(TuicError::Protocol("length field truncated".into()));
            }
            let bytes: [u8; 8] = input[*offset..end]
                .try_into()
                .map_err(|_| TuicError::Protocol("length field truncated".into()))?;
            *offset = end;
            Ok(u64::from_le_bytes(bytes))
        }

        const MIN_LEN: usize = 1 + 8 + 8;
        if input.len() < MIN_LEN {
            return Err(TuicError::Protocol("auth request too short".into()));
        }

        let version = input[0];
        let mut offset = 1usize;

        let uuid_len = take_u64(input, &mut offset)? as usize;

        let uuid_end = offset
            .checked_add(uuid_len)
            .ok_or_else(|| TuicError::Protocol("uuid length overflow".into()))?;
        if uuid_end > input.len() {
            return Err(TuicError::Protocol("uuid payload truncated".into()));
        }
        let uuid_str = std::str::from_utf8(&input[offset..uuid_end])
            .map_err(|_| TuicError::Protocol("uuid is not valid utf-8".into()))?;
        let uuid = Uuid::parse_str(uuid_str)
            .map_err(|_| TuicError::Protocol("uuid is malformed".into()))?;
        offset = uuid_end;

        let pw_len = take_u64(input, &mut offset)? as usize;

        let pw_end = offset
            .checked_add(pw_len)
            .ok_or_else(|| TuicError::Protocol("password length overflow".into()))?;
        if pw_end > input.len() {
            return Err(TuicError::Protocol("password payload truncated".into()));
        }
        let password = std::str::from_utf8(&input[offset..pw_end])
            .map_err(|_| TuicError::Protocol("password is not valid utf-8".into()))?
            .to_string();

        Ok(Self {
            version,
            uuid,
            password,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
struct AuthResponse {
    success: bool,
    message: Option<String>,
}

pub struct TuicClient {
    config: ClientConfig,
}

impl TuicClient {
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    pub async fn connect(&self) -> Result<TuicConnection, TuicError> {
        let mut root_store = rustls::RootCertStore::empty();
        let native_certs = rustls_native_certs::load_native_certs();
        for cert in native_certs.certs {
            root_store.add(cert).map_err(TuicError::Rustls)?;
        }
        if root_store.is_empty() {
            return Err(TuicError::Protocol(
                "no trusted platform certificates are available".to_string(),
            ));
        }

        let mut crypto = quinn::rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        crypto.alpn_protocols = self
            .config
            .alpn
            .clone()
            .unwrap_or_else(|| vec!["h3".to_string()])
            .into_iter()
            .map(String::into_bytes)
            .collect();

        let client_config = QuinnClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| TuicError::Protocol(e.to_string()))?,
        ));

        let bind_addr = if self.config.server_addr.is_ipv6() {
            "[::]:0".parse().expect("valid IPv6 wildcard address")
        } else {
            "0.0.0.0:0".parse().expect("valid IPv4 wildcard address")
        };
        let mut endpoint = Endpoint::client(bind_addr)?;
        endpoint.set_default_client_config(client_config);

        let default_server_name = self.config.server_addr.ip().to_string();
        let server_name = self
            .config
            .certificate
            .as_deref()
            .unwrap_or(&default_server_name);
        let connection = endpoint
            .connect(self.config.server_addr, server_name)?
            .await?;

        self.authenticate(&connection).await?;

        Ok(TuicConnection {
            connection,
            _endpoint: endpoint,
            _config: self.config.clone(),
        })
    }

    async fn authenticate(&self, connection: &Connection) -> Result<(), TuicError> {
        let mut auth_stream = connection.open_uni().await?;
        let password = self
            .config
            .password
            .first()
            .ok_or(TuicError::InvalidConfig)?;

        let auth_request = AuthRequest {
            version: TUIC_PROTOCOL_VERSION,
            uuid: self.config.uuid,
            password: password.clone(),
        };

        let auth_data = auth_request.encode();
        auth_stream.write_all(&auth_data).await?;
        auth_stream.finish()?;

        Ok(())
    }
}

pub struct TuicServer {
    config: ServerConfig,
}

impl TuicServer {
    pub fn new(config: ServerConfig) -> Self {
        Self { config }
    }

    pub async fn serve(&self) -> Result<(), TuicError> {
        let cert_der = CertificateDer::from(self.config.certificate.clone());
        let key_der = PrivateKeyDer::try_from(self.config.private_key.clone())
            .map_err(|_| TuicError::InvalidConfig)?;
        let server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(TuicError::Rustls)?;
        let server_config = QuinnServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .map_err(|e| TuicError::Protocol(e.to_string()))?,
        ));

        let endpoint = Endpoint::server(server_config, self.config.listen_addr)?;

        loop {
            let incoming = endpoint.accept().await.ok_or(TuicError::InvalidConfig)?;
            let connection = incoming.await?;
            self.authenticate(&connection).await?;
            // TODO(protocol): route accepted connection into the session table.
        }
    }

    /// Read and validate the client's authentication request.
    async fn authenticate(&self, connection: &Connection) -> Result<(), TuicError> {
        let mut auth_stream = connection.accept_uni().await?;
        let auth_data = auth_stream.read_to_end(64 * 1024).await?;

        let request = AuthRequest::decode(&auth_data)?;
        if request.version != TUIC_PROTOCOL_VERSION {
            return Err(TuicError::Protocol(format!(
                "unsupported TUIC version {}",
                request.version
            )));
        }
        if request.uuid != self.config.uuid {
            return Err(TuicError::AuthFailed);
        }
        if !self
            .config
            .password
            .iter()
            .any(|password| password == &request.password)
        {
            return Err(TuicError::AuthFailed);
        }
        Ok(())
    }
}

pub struct TuicConnection {
    connection: Connection,
    _endpoint: Endpoint,
    _config: ClientConfig,
}

impl TuicConnection {
    pub async fn send(&mut self, data: &[u8]) -> Result<(), TuicError> {
        let mut stream = self.connection.open_uni().await?;
        stream.write_all(data).await?;
        stream.finish()?;
        Ok(())
    }

    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TuicError> {
        let mut stream = self.connection.accept_uni().await?;
        let temp_buf = stream.read_to_end(1024 * 1024).await?;

        let len = std::cmp::min(temp_buf.len(), buf.len());
        buf[..len].copy_from_slice(&temp_buf[..len]);
        Ok(len)
    }

    pub async fn send_command(&self, command: Command, payload: &[u8]) -> Result<(), TuicError> {
        let mut command_data = vec![command as u8];
        command_data.extend_from_slice(payload);

        let mut stream = self.connection.open_uni().await?;
        stream.write_all(&command_data).await?;
        stream.finish()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_auth_wire_format_is_stable() {
        let request = AuthRequest {
            version: TUIC_PROTOCOL_VERSION,
            uuid: Uuid::from_bytes([0x11; 16]),
            password: "secret".to_string(),
        };

        let encoded = request.encode();
        let decoded = AuthRequest::decode(&encoded).expect("legacy TUIC auth request must decode");

        assert_eq!(decoded, request);

        let mut expected = vec![TUIC_PROTOCOL_VERSION];
        expected.extend_from_slice(&36u64.to_le_bytes());
        expected.extend_from_slice(b"11111111-1111-1111-1111-111111111111");
        expected.extend_from_slice(&6u64.to_le_bytes());
        expected.extend_from_slice(b"secret");
        assert_eq!(encoded, expected);
    }

    #[test]
    fn auth_decode_rejects_truncated_payload() {
        let request = AuthRequest {
            version: TUIC_PROTOCOL_VERSION,
            uuid: Uuid::from_bytes([0x22; 16]),
            password: "hunter2".to_string(),
        };
        let encoded = request.encode();

        for cut in 0..encoded.len() {
            assert!(
                AuthRequest::decode(&encoded[..cut]).is_err(),
                "truncated input at {cut} bytes must be rejected"
            );
        }
    }
}
