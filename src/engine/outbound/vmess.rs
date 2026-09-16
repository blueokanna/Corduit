use crate::common::stream::BoxStream;
use crate::crypto::aead::{Aead, Aes128Gcm, ChaCha20Poly1305};
use crate::crypto::digest::Digest;
use crate::crypto::hash::{Md5, Sha256};
use crate::crypto::stream::Aes;
use crate::crypto::uuid::Uuid;
use crate::engine::config::OutboundConfig;
use crate::engine::connection_tracker::TrackedConnection;
use crate::engine::error::{Error, Result};
use crate::engine::outbound::{OutboundProxy, TargetAddr};
use dashmap::DashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const VMESS_VERSION: u8 = 1;
const VMESS_AEAD_AUTH_LEN: usize = 16;

const AUTH_ID_ENCRYPTION_SALT: &[u8] = b"AES Auth ID Encryption";
const HEADER_KEY_SALT: &[u8] = b"VMess Header AEAD Key";
const HEADER_NONCE_SALT: &[u8] = b"VMess Header AEAD Nonce";
const HEADER_LENGTH_KEY_SALT: &[u8] = b"VMess Header AEAD Key_Length";
const HEADER_LENGTH_NONCE_SALT: &[u8] = b"VMess Header AEAD Nonce_Length";
const RESPONSE_LENGTH_KEY_SALT: &[u8] = b"AEAD Resp Header Len Key";
const RESPONSE_LENGTH_IV_SALT: &[u8] = b"AEAD Resp Header Len IV";
const RESPONSE_HEADER_KEY_SALT: &[u8] = b"AEAD Resp Header Key";
const RESPONSE_HEADER_IV_SALT: &[u8] = b"AEAD Resp Header IV";
const KDF_BASE_SALT: &[u8] = b"VMess AEAD KDF";
const VMESS_READ_POLL: Duration = Duration::from_millis(500);

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessCommand {
    Tcp = 0x01,
    Udp = 0x02,
}

impl VmessCommand {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(VmessCommand::Tcp),
            0x02 => Some(VmessCommand::Udp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessCipher {
    Auto,
    Aes128Gcm,
    Chacha20Poly1305,
    None,
    Zero,
}

impl VmessCipher {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "aes-128-gcm" | "aes128gcm" => VmessCipher::Aes128Gcm,
            "chacha20-poly1305" | "chacha20poly1305" => VmessCipher::Chacha20Poly1305,
            "none" => VmessCipher::None,
            "zero" => VmessCipher::Zero,
            _ => VmessCipher::Auto,
        }
    }

    /// The `SecurityType` byte of the request header, using the v2ray/xray
    /// enum: `AUTO=2`, `AES128_GCM=3`, `CHACHA20_POLY1305=4`, `NONE=5`,
    /// `ZERO=6`. `Auto` must be resolved to a concrete cipher before it goes
    /// on the wire; AES-128-GCM is chosen because every current server
    /// implements it.
    pub fn as_byte(self) -> u8 {
        match self {
            VmessCipher::Aes128Gcm | VmessCipher::Auto => 0x03,
            VmessCipher::Chacha20Poly1305 => 0x04,
            VmessCipher::None => 0x05,
            VmessCipher::Zero => 0x06,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum VmessAddressType {
    Ipv4 = 0x01,
    Domain = 0x02,
    Ipv6 = 0x03,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct VmessOption: u8 {
        const CHUNK_STREAM = 0x01;
        const CONNECTION_REUSE = 0x02;
        const CHUNK_MASKING = 0x04;
        const GLOBAL_PADDING = 0x08;
        const AUTHENTICATED_LENGTH = 0x10;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessTransport {
    Tcp,
    Ws,
    H2,
    Grpc,
}

impl VmessTransport {
    /// Parse the configured transport name. `None` means the name is not a
    /// transport this engine knows — the caller must reject the config
    /// instead of guessing (a wrong guess speaks the wrong protocol on the
    /// wire and surfaces as an inscrutable EOF later).
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "" | "tcp" | "raw" => Some(VmessTransport::Tcp),
            "ws" | "websocket" => Some(VmessTransport::Ws),
            "h2" | "http2" => Some(VmessTransport::H2),
            "grpc" => Some(VmessTransport::Grpc),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VmessWsOptions {
    pub path: String,
    pub host: Option<String>,
    pub headers: std::collections::HashMap<String, String>,
}

impl Default for VmessWsOptions {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            host: None,
            headers: std::collections::HashMap::new(),
        }
    }
}

/// UDP session state for VMess
struct VmessUdpSession {
    stream: parking_lot::Mutex<BoxStream>,
    request_key: [u8; 16],
    request_iv: [u8; 16],
    response_key: [u8; 16],
    response_iv: [u8; 16],
    chunk_count: AtomicU64,
    response_chunk_count: AtomicU64,
    expected_response_header: u8,
    header_consumed: AtomicBool,
    last_used: std::sync::RwLock<Instant>,
}

impl VmessUdpSession {
    fn new(
        stream: BoxStream,
        request_key: [u8; 16],
        request_iv: [u8; 16],
        response_key: [u8; 16],
        response_iv: [u8; 16],
        expected_response_header: u8,
    ) -> Self {
        Self {
            stream: parking_lot::Mutex::new(stream),
            request_key,
            request_iv,
            response_key,
            response_iv,
            chunk_count: AtomicU64::new(0),
            response_chunk_count: AtomicU64::new(0),
            expected_response_header,
            header_consumed: AtomicBool::new(false),
            last_used: std::sync::RwLock::new(Instant::now()),
        }
    }

    fn next_chunk_count(&self) -> u16 {
        (self.chunk_count.fetch_add(1, Ordering::SeqCst) % 65536) as u16
    }

    /// Response chunks carry an independent nonce counter (zero-based for a
    /// fresh session). Reusing the request counter — or any fixed value —
    /// makes every chunk after the first fail its GCM open, because the
    /// nonce is part of the ciphertext's authentication.
    fn next_response_chunk_count(&self) -> u16 {
        (self.response_chunk_count.fetch_add(1, Ordering::SeqCst) % 65536) as u16
    }

    fn touch(&self) {
        if let Ok(mut guard) = self.last_used.write() {
            *guard = Instant::now();
        }
    }

    fn is_expired(&self, timeout: Duration) -> bool {
        if let Ok(guard) = self.last_used.read() {
            guard.elapsed() > timeout
        } else {
            true
        }
    }
}

pub struct VmessOutbound {
    config: OutboundConfig,
    server: String,
    port: u16,
    cipher: VmessCipher,
    udp_enabled: bool,
    cmd_key: [u8; 16],
    transport: VmessTransport,
    tls_enabled: bool,
    skip_cert_verify: bool,
    sni: Option<String>,
    ws_opts: Option<VmessWsOptions>,
    // ALPN override for the TLS layer (was `quic-opts.alpn` before the QUIC
    // transport was removed; kept as the TLS ALPN source).
    alpn: Vec<String>,
    /// `fingerprint` / `security: reality`: handshake options courierust's
    /// connector cannot express (parsed at construction, fail-closed).
    advanced: crate::engine::tls::AdvancedTlsOptions,
    // UDP session management
    udp_sessions: DashMap<String, Arc<VmessUdpSession>>,
}

pub struct VmessHeader {
    pub version: u8,
    pub request_body_iv: [u8; 16],
    pub request_body_key: [u8; 16],
    pub response_header: u8,
    pub option: VmessOption,
    pub padding_length: u8,
    pub security: VmessCipher,
    pub command: VmessCommand,
    pub port: u16,
    pub address_type: VmessAddressType,
    pub address: Vec<u8>,
}

impl VmessOutbound {
    pub fn new(config: OutboundConfig) -> Result<Self> {
        let server = config
            .server
            .clone()
            .ok_or_else(|| Error::config("Missing server address for VMess"))?;

        let port = config
            .port
            .ok_or_else(|| Error::config("Missing port for VMess"))?;

        let uuid_str = config
            .options
            .get("uuid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::config("Missing UUID for VMess"))?;

        let uuid =
            Uuid::parse_str(uuid_str).map_err(|e| Error::config(format!("Invalid UUID: {}", e)))?;

        let uuid_bytes = *uuid.as_bytes();
        let alter_id = config
            .options
            .get("alterId")
            .or_else(|| config.options.get("alter-id"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        if alter_id != 0 {
            tracing::info!(
                "VMess '{}' declares alterId={alter_id}; the AEAD handshake does not use it",
                config.tag
            );
        }

        let cipher_str = config
            .options
            .get("cipher")
            .and_then(|v| v.as_str())
            .unwrap_or("auto");
        let cipher = VmessCipher::from_str(cipher_str);

        let udp_enabled = config
            .options
            .get("udp")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        // Parse transport type
        let transport_str = config
            .options
            .get("network")
            .and_then(|v| v.as_str())
            .unwrap_or("tcp");
        let transport = match VmessTransport::from_str(transport_str) {
            Some(transport) => transport,
            None => {
                return Err(Error::config(format!(
                    "unsupported VMess transport '{transport_str}'; supported transports: tcp, ws"
                )));
            }
        };
        // Parsed-but-unimplemented transports must fail loudly: falling back
        // to raw TCP would speak the wrong protocol on the wire and surface
        // as an inscrutable EOF later.
        if matches!(transport, VmessTransport::H2 | VmessTransport::Grpc) {
            return Err(Error::config(format!(
                "VMess transport '{transport_str}' is not implemented yet; supported transports: tcp, ws"
            )));
        }

        // Parse TLS settings
        let tls_enabled = config
            .options
            .get("tls")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let skip_cert_verify = config
            .options
            .get("skip-cert-verify")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let sni = config
            .options
            .get("sni")
            .or_else(|| config.options.get("servername"))
            .and_then(|v| v.as_str())
            .map(String::from);

        // Parse WebSocket options
        let ws_opts = if transport == VmessTransport::Ws {
            let ws_opts_value = config.options.get("ws-opts");
            let path = ws_opts_value
                .and_then(|v| v.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("/")
                .to_string();

            let host = ws_opts_value
                .and_then(|v| v.get("headers"))
                .and_then(|v| v.get("Host"))
                .and_then(|v| v.as_str())
                .map(String::from);

            let mut headers = std::collections::HashMap::new();
            if let Some(headers_value) = ws_opts_value.and_then(|v| v.get("headers")) {
                if let Some(map) = headers_value.as_object() {
                    for (k, v) in map.iter() {
                        if let Some(value) = v.as_str() {
                            headers.insert(k.to_string(), value.to_string());
                        }
                    }
                }
            }

            Some(VmessWsOptions {
                path,
                host,
                headers,
            })
        } else {
            None
        };

        let alpn = config
            .options
            .get("alpn")
            .or_else(|| config.options.get("quic-opts").and_then(|v| v.get("alpn")))
            .and_then(|v| v.as_array())
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let cmd_key = generate_cmd_key(&uuid_bytes);

        let advanced = crate::engine::tls::AdvancedTlsOptions::from_options(
            &config.options,
            sni.as_deref().unwrap_or(&server),
        )?;

        tracing::info!(
            "VMess outbound '{}' created: server={}:{}, transport={:?}, tls={}, udp={}",
            config.tag,
            server,
            port,
            transport,
            tls_enabled,
            udp_enabled
        );

        Ok(Self {
            config,
            server,
            port,
            cipher,
            udp_enabled,
            cmd_key,
            transport,
            tls_enabled,
            skip_cert_verify,
            sni,
            ws_opts,
            alpn,
            advanced,
            udp_sessions: DashMap::new(),
        })
    }

    /// The AEAD AuthID of v2ray/xray (`proxy/vmess/aead/authid.go`): one
    /// AES-128-ECB block over `timestamp ‖ 4 random bytes ‖ CRC-32 of those
    /// twelve bytes`, keyed by `KDF16(cmdKey, "AES Auth ID Encryption")`.
    ///
    /// The older `MD5(uuid ‖ timestamp × 4)` construction belongs to the
    /// pre-AEAD protocol: every AEAD server rejects it and closes the
    /// connection, which is exactly what a client must not send here.
    pub fn generate_auth_id(&self, timestamp: i64) -> [u8; 16] {
        let mut block = [0u8; 16];
        block[..8].copy_from_slice(&timestamp.to_be_bytes());
        getrandom::fill(&mut block[8..12]).expect("Failed to generate AuthID randomness");

        let checksum = crc32_ieee(&block[..12]).to_be_bytes();
        block[12..].copy_from_slice(&checksum);

        let key = kdf16(&self.cmd_key, &[AUTH_ID_ENCRYPTION_SALT]);
        let cipher = Aes::new(&key).expect("a 16-byte key always selects AES-128");
        cipher.encrypt_block(&mut block);
        block
    }

    pub fn generate_request_key(&self) -> [u8; 16] {
        let mut key = [0u8; 16];
        getrandom::fill(&mut key).expect("Failed to generate random key");
        key
    }

    pub fn generate_request_iv(&self) -> [u8; 16] {
        let mut iv = [0u8; 16];
        getrandom::fill(&mut iv).expect("Failed to generate random IV");
        iv
    }

    fn generate_response_key(&self, request_key: &[u8; 16]) -> [u8; 16] {
        let mut hasher = Sha256::new();
        hasher.update(request_key);
        let result = hasher.finalize();
        let mut key = [0u8; 16];
        key.copy_from_slice(&result[..16]);
        key
    }

    fn generate_response_iv(&self, request_iv: &[u8; 16]) -> [u8; 16] {
        let mut hasher = Sha256::new();
        hasher.update(request_iv);
        let result = hasher.finalize();
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&result[..16]);
        iv
    }

    pub fn seal_header(&self, header: &VmessHeader, timestamp: i64) -> Result<Vec<u8>> {
        let mut header_buf = Vec::with_capacity(128);

        header_buf.push(header.version);
        header_buf.extend_from_slice(&header.request_body_iv);
        header_buf.extend_from_slice(&header.request_body_key);
        header_buf.push(header.response_header);
        header_buf.push(header.option.bits());

        let padding_and_security = (header.padding_length << 4) | header.security.as_byte();
        header_buf.push(padding_and_security);
        header_buf.push(0x00);
        header_buf.push(header.command as u8);

        header_buf.extend_from_slice(&header.port.to_be_bytes());

        header_buf.push(header.address_type as u8);
        header_buf.extend_from_slice(&header.address);

        if header.padding_length > 0 {
            let mut padding = vec![0u8; header.padding_length as usize];
            getrandom::fill(&mut padding).ok();
            header_buf.extend_from_slice(&padding);
        }

        let fnv_hash = fnv1a_hash(&header_buf);
        header_buf.extend_from_slice(&fnv_hash.to_be_bytes());

        let auth_id = self.generate_auth_id(timestamp);
        let connection_nonce = generate_connection_nonce();
        let header_key = kdf16(
            &self.cmd_key,
            &[HEADER_KEY_SALT, &auth_id, &connection_nonce],
        );
        let header_nonce = kdf12(
            &self.cmd_key,
            &[HEADER_NONCE_SALT, &auth_id, &connection_nonce],
        );

        let cipher = Aes128Gcm::new_from_slice(&header_key)
            .map_err(|e| Error::protocol(format!("Failed to create AES-GCM cipher: {e}")))?;

        let encrypted_header = cipher
            .encrypt(&header_nonce, header_buf.as_ref(), &auth_id)
            .map_err(|e| Error::protocol(format!("Failed to encrypt header: {e:?}")))?;

        let header_length_key = kdf16(
            &self.cmd_key,
            &[HEADER_LENGTH_KEY_SALT, &auth_id, &connection_nonce],
        );
        let header_length_nonce = kdf12(
            &self.cmd_key,
            &[HEADER_LENGTH_NONCE_SALT, &auth_id, &connection_nonce],
        );

        let length_cipher = Aes128Gcm::new_from_slice(&header_length_key)
            .map_err(|e| Error::protocol(format!("Failed to create length cipher: {e}")))?;

        let length_bytes = (header_buf.len() as u16).to_be_bytes();
        let encrypted_length = length_cipher
            .encrypt(&header_length_nonce, length_bytes.as_ref(), &auth_id)
            .map_err(|e| Error::protocol(format!("Failed to encrypt length: {e:?}")))?;

        let mut result =
            Vec::with_capacity(16 + 8 + encrypted_length.len() + encrypted_header.len());
        result.extend_from_slice(&auth_id);
        result.extend_from_slice(&encrypted_length);
        result.extend_from_slice(&connection_nonce);
        result.extend_from_slice(&encrypted_header);

        Ok(result)
    }

    /// Consume the AEAD response header, the way v2ray's AEAD client does
    /// (`proxy/vmess/encoding/client.go`): an 18-byte encrypted length
    /// followed by that many bytes plus the AEAD tag, keyed by
    /// `KDF(responseBodyKey, "AEAD Resp Header Len Key")` and
    /// `KDF(responseBodyKey, "AEAD Resp Header Key")` with the matching IV
    /// salts. The first decrypted byte has to echo what this session put into
    /// its request header.
    ///
    /// This runs before the first body chunk: the header is not part of the
    /// chunk stream, so a reader that starts with a chunk parses ciphertext
    /// as a length and fails on the first byte.
    fn read_response_header<S: Read + ?Sized>(
        &self,
        stream: &mut S,
        response_key: &[u8; 16],
        response_iv: &[u8; 16],
        expected_response_header: u8,
        deadline: Option<Instant>,
    ) -> Result<()> {
        let mut encrypted_length = [0u8; 2 + VMESS_AEAD_AUTH_LEN];
        read_exact_with_deadline(stream, &mut encrypted_length, deadline)?;
        let length = open_response_header_length(response_key, response_iv, &encrypted_length)
            .map_err(|e| Error::protocol(e.to_string()))?;
        if length > VMESS_RESPONSE_HEADER_MAX {
            return Err(Error::protocol(format!(
                "Response header length {length} is out of range"
            )));
        }

        let mut encrypted_payload = vec![0u8; length + VMESS_AEAD_AUTH_LEN];
        read_exact_with_deadline(stream, &mut encrypted_payload, deadline)?;
        let decrypted = open_response_header_payload(response_key, response_iv, &encrypted_payload)
            .map_err(|e| Error::protocol(e.to_string()))?;

        if decrypted.len() < 4 {
            return Err(Error::protocol("Decrypted response header is too short"));
        }
        if decrypted[0] != expected_response_header {
            return Err(Error::protocol(format!(
                "Unexpected response header byte: expected {expected_response_header}, got {}",
                decrypted[0]
            )));
        }

        Ok(())
    }

    fn connect_tcp(&self) -> Result<std::net::TcpStream> {
        let addr = format!("{}:{}", self.server, self.port);
        let stream =
            crate::common::socket::connect_host(&self.server, self.port, Duration::from_secs(30))
                .map_err(|e| {
                Error::network(format!("Failed to connect to VMess server {}: {}", addr, e))
            })?;
        stream.set_nodelay(true).ok();
        Ok(stream)
    }

    /// Connect with TLS if enabled (courierust TLS, boxed sync stream).
    fn connect_tls(&self) -> Result<BoxStream> {
        let tcp_stream = self.connect_tcp()?;

        let sni = self.sni.as_deref().unwrap_or(&self.server).to_string();
        if !self.advanced.is_empty() {
            return crate::engine::tls::connect_advanced_tls(
                tcp_stream,
                &sni,
                &self.effective_alpn(),
                self.skip_cert_verify,
                &self.advanced,
            );
        }
        let connector = self.create_tls_connector()?;
        connector
            .connect(tcp_stream, &sni)
            .map_err(|e| Error::network(format!("TLS handshake failed: {}", e)))
    }

    /// The ALPN offer for the TLS layer: an explicit `alpn` option wins,
    /// otherwise the transport shape decides. WebSocket upgrades are
    /// HTTP/1.1-only — advertising `h2` makes the server negotiate HTTP/2
    /// and the HTTP/1.1 upgrade bytes become a protocol error (observed
    /// with a reference Xray server: an h2 SETTINGS frame, then close).
    fn effective_alpn(&self) -> Vec<String> {
        crate::engine::tls::effective_alpn(&self.alpn, self.transport == VmessTransport::Ws)
    }

    /// Build the courierust TLS connector from the VMess options.
    fn create_tls_connector(&self) -> Result<crate::engine::tls::TlsConnector> {
        let config = crate::engine::tls::ClientConfig {
            server_name: self.sni.clone(),
            alpn: self.effective_alpn(),
            skip_cert_verify: self.skip_cert_verify,
            enable_sni: true,
        };
        crate::engine::tls::TlsConnector::new(config).map_err(|e| Error::Tls {
            message: format!("Failed to create VMess TLS connector: {e}"),
            source: None,
        })
    }

    /// Connect and return a boxed stream (TCP, TLS, or WebSocket)
    fn connect_stream(&self) -> Result<BoxStream> {
        match self.transport {
            VmessTransport::Ws => {
                let default_ws_opts = VmessWsOptions::default();
                let ws_opts = self.ws_opts.as_ref().unwrap_or(&default_ws_opts);
                let host = ws_opts.host.as_deref().unwrap_or(&self.server);
                let stream: BoxStream = if self.tls_enabled {
                    self.connect_tls()?
                } else {
                    Box::new(self.connect_tcp()?)
                };
                let ws = crate::protocol::ws::WebSocket::connect(
                    stream,
                    host,
                    &ws_opts.path,
                    &ws_opts.headers,
                )
                .map_err(|e| Error::network(format!("WebSocket handshake failed: {e}")))?;
                Ok(Box::new(ws) as BoxStream)
            }
            _ => {
                if self.tls_enabled {
                    let tls_stream = self.connect_tls()?;
                    Ok(Box::new(tls_stream) as BoxStream)
                } else {
                    let tcp_stream = self.connect_tcp()?;
                    Ok(Box::new(tcp_stream) as BoxStream)
                }
            }
        }
    }

    fn handshake<S: Read + Write + ?Sized>(
        &self,
        stream: &mut S,
        target: &TargetAddr,
        cmd: VmessCommand,
    ) -> Result<([u8; 16], [u8; 16], u8)> {
        let request_key = self.generate_request_key();
        let request_iv = self.generate_request_iv();
        let response_header_byte: u8 = crate::engine::random::u8();

        let (address_type, address_bytes) = match target {
            TargetAddr::Domain(domain, _) => {
                let mut bytes = Vec::with_capacity(domain.len() + 1);
                bytes.push(domain.len() as u8);
                bytes.extend_from_slice(domain.as_bytes());
                (VmessAddressType::Domain, bytes)
            }
            TargetAddr::Ip(addr) => match addr {
                std::net::SocketAddr::V4(v4) => (VmessAddressType::Ipv4, v4.ip().octets().to_vec()),
                std::net::SocketAddr::V6(v6) => (VmessAddressType::Ipv6, v6.ip().octets().to_vec()),
            },
        };

        let header = VmessHeader {
            version: VMESS_VERSION,
            request_body_iv: request_iv,
            request_body_key: request_key,
            response_header: response_header_byte,
            option: VmessOption::CHUNK_STREAM,
            padding_length: crate::engine::random::u8() % 16,
            security: self.cipher,
            command: cmd,
            port: target.port(),
            address_type,
            address: address_bytes,
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let sealed_header = self.seal_header(&header, timestamp)?;

        stream
            .write_all(&sealed_header)
            .map_err(|e| Error::network(format!("Failed to send VMess header: {}", e)))?;
        stream.flush().ok();

        tracing::debug!("VMess handshake sent for target: {}", target);

        Ok((request_key, request_iv, response_header_byte))
    }

    pub fn is_udp_enabled(&self) -> bool {
        self.udp_enabled
    }

    /// Get or create a UDP session for the given target
    fn get_or_create_udp_session(&self, target: &TargetAddr) -> Result<Arc<VmessUdpSession>> {
        let session_key = target.to_string();

        if let Some(session) = self.udp_sessions.get(&session_key) {
            let session = session.clone();
            if !session.is_expired(Duration::from_secs(60)) {
                session.touch();
                return Ok(session);
            }
            // Session expired, remove it
            self.udp_sessions.remove(&session_key);
        }

        self.cleanup_udp_sessions();

        let mut stream = self.connect_stream()?;
        let _ = stream.set_read_timeout(Some(VMESS_READ_POLL));
        let (request_key, request_iv, response_header) =
            self.handshake(&mut *stream, target, VmessCommand::Udp)?;

        let response_key = self.generate_response_key(&request_key);
        let response_iv = self.generate_response_iv(&request_iv);

        let session = Arc::new(VmessUdpSession::new(
            stream,
            request_key,
            request_iv,
            response_key,
            response_iv,
            response_header,
        ));

        self.udp_sessions.insert(session_key, session.clone());

        tracing::debug!("Created new VMess UDP session for {}", target);
        Ok(session)
    }

    /// Clean up expired UDP sessions
    pub fn cleanup_udp_sessions(&self) {
        let mut expired_keys = Vec::new();

        for entry in self.udp_sessions.iter() {
            if entry.value().is_expired(Duration::from_secs(120)) {
                expired_keys.push(entry.key().clone());
            }
        }

        for key in expired_keys {
            self.udp_sessions.remove(&key);
            tracing::debug!("Removed expired VMess UDP session: {}", key);
        }
    }

    pub fn relay_udp(&self, target: &TargetAddr, data: &[u8]) -> Result<Vec<u8>> {
        if !self.udp_enabled {
            return Err(Error::config(
                "UDP relay is not enabled for this VMess proxy",
            ));
        }

        let session = self.get_or_create_udp_session(target)?;

        let chunk_count = session.next_chunk_count();
        let request_key = session.request_key;
        let request_iv = session.request_iv;
        let response_key = session.response_key;
        let response_iv = session.response_iv;
        let target_str = target.to_string();

        let mut stream_guard = session.stream.lock();

        let encrypted_data = self.encrypt_chunk(data, &request_key, &request_iv, chunk_count)?;
        if let Err(e) = stream_guard.write_all(&encrypted_data) {
            // Session might be broken, remove it
            drop(stream_guard);
            self.udp_sessions.remove(&target_str);
            return Err(Error::network(format!("Failed to send UDP data: {}", e)));
        }
        stream_guard.flush().ok();
        session.touch();

        let deadline = Instant::now() + Duration::from_secs(10);
        if !session.header_consumed.swap(true, Ordering::SeqCst) {
            if let Err(e) = self.read_response_header(
                &mut **stream_guard,
                &response_key,
                &response_iv,
                session.expected_response_header,
                Some(deadline),
            ) {
                drop(stream_guard);
                self.udp_sessions.remove(&target_str);
                return Err(Error::network(format!(
                    "Failed to read the UDP response header: {e}"
                )));
            }
        }

        let response_count = session.next_response_chunk_count();
        let read_result = self.read_response_chunk(
            &mut **stream_guard,
            &response_key,
            &response_iv,
            response_count,
            deadline,
        );
        drop(stream_guard);

        match read_result {
            Ok(response) => Ok(response),
            Err(e) => {
                self.udp_sessions.remove(&target_str);
                Err(Error::network(format!(
                    "Failed to receive UDP response: {e}"
                )))
            }
        }
    }

    /// Relay UDP packet without waiting for response (fire and forget for some protocols)
    pub fn send_udp_packet(&self, target: &TargetAddr, data: &[u8]) -> Result<()> {
        if !self.udp_enabled {
            return Err(Error::config(
                "UDP relay is not enabled for this VMess proxy",
            ));
        }

        let session = self.get_or_create_udp_session(target)?;

        let chunk_count = session.next_chunk_count();
        let request_key = session.request_key;
        let request_iv = session.request_iv;

        let encrypted_data = self.encrypt_chunk(data, &request_key, &request_iv, chunk_count)?;

        let mut stream_guard = session.stream.lock();
        stream_guard
            .write_all(&encrypted_data)
            .map_err(|e| Error::network(format!("Failed to send UDP data: {}", e)))?;
        stream_guard.flush().ok();
        session.touch();

        Ok(())
    }

    fn encrypt_chunk(
        &self,
        data: &[u8],
        key: &[u8; 16],
        iv: &[u8; 16],
        count: u16,
    ) -> Result<Vec<u8>> {
        match self.cipher {
            VmessCipher::Aes128Gcm | VmessCipher::Auto => {
                self.encrypt_aes_gcm(data, key, iv, count)
            }
            VmessCipher::Chacha20Poly1305 => self.encrypt_chacha20(data, key, iv, count),
            VmessCipher::None | VmessCipher::Zero => {
                let mut result = Vec::with_capacity(2 + data.len());
                result.extend_from_slice(&(data.len() as u16).to_be_bytes());
                result.extend_from_slice(data);
                Ok(result)
            }
        }
    }

    fn encrypt_aes_gcm(
        &self,
        data: &[u8],
        key: &[u8; 16],
        iv: &[u8; 16],
        count: u16,
    ) -> Result<Vec<u8>> {
        let cipher = Aes128Gcm::new_from_slice(key)
            .map_err(|e| Error::protocol(format!("Failed to create AES-GCM cipher: {}", e)))?;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..2].copy_from_slice(&count.to_be_bytes());
        nonce_bytes[2..].copy_from_slice(&iv[2..12]);

        let encrypted = cipher
            .encrypt(&nonce_bytes, data, &[])
            .map_err(|e| Error::protocol(format!("Failed to encrypt data: {:?}", e)))?;

        let length = (encrypted.len() as u16).to_be_bytes();
        let mut result = Vec::with_capacity(2 + encrypted.len());
        result.extend_from_slice(&length);
        result.extend_from_slice(&encrypted);
        Ok(result)
    }

    fn encrypt_chacha20(
        &self,
        data: &[u8],
        key: &[u8; 16],
        iv: &[u8; 16],
        count: u16,
    ) -> Result<Vec<u8>> {
        let full_key = chacha20_poly1305_key(key);

        let cipher = ChaCha20Poly1305::new_from_slice(&full_key)
            .map_err(|e| Error::protocol(format!("Failed to create ChaCha20 cipher: {}", e)))?;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..2].copy_from_slice(&count.to_be_bytes());
        nonce_bytes[2..].copy_from_slice(&iv[2..12]);

        let encrypted = cipher
            .encrypt(&nonce_bytes, data, &[])
            .map_err(|e| Error::protocol(format!("Failed to encrypt data: {:?}", e)))?;

        let length = (encrypted.len() as u16).to_be_bytes();
        let mut result = Vec::with_capacity(2 + encrypted.len());
        result.extend_from_slice(&length);
        result.extend_from_slice(&encrypted);
        Ok(result)
    }

    fn decrypt_chunk(
        &self,
        data: &[u8],
        key: &[u8; 16],
        iv: &[u8; 16],
        count: u16,
    ) -> Result<Vec<u8>> {
        match self.cipher {
            VmessCipher::Aes128Gcm | VmessCipher::Auto => {
                self.decrypt_aes_gcm(data, key, iv, count)
            }
            VmessCipher::Chacha20Poly1305 => self.decrypt_chacha20(data, key, iv, count),
            VmessCipher::None | VmessCipher::Zero => Ok(data.to_vec()),
        }
    }

    fn decrypt_aes_gcm(
        &self,
        data: &[u8],
        key: &[u8; 16],
        iv: &[u8; 16],
        count: u16,
    ) -> Result<Vec<u8>> {
        let cipher = Aes128Gcm::new_from_slice(key)
            .map_err(|e| Error::protocol(format!("Failed to create AES-GCM cipher: {}", e)))?;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..2].copy_from_slice(&count.to_be_bytes());
        nonce_bytes[2..].copy_from_slice(&iv[2..12]);

        let decrypted = cipher
            .decrypt(&nonce_bytes, data, &[])
            .map_err(|e| Error::protocol(format!("Failed to decrypt data: {:?}", e)))?;

        Ok(decrypted)
    }

    fn decrypt_chacha20(
        &self,
        data: &[u8],
        key: &[u8; 16],
        iv: &[u8; 16],
        count: u16,
    ) -> Result<Vec<u8>> {
        let full_key = chacha20_poly1305_key(key);

        let cipher = ChaCha20Poly1305::new_from_slice(&full_key)
            .map_err(|e| Error::protocol(format!("Failed to create ChaCha20 cipher: {}", e)))?;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..2].copy_from_slice(&count.to_be_bytes());
        nonce_bytes[2..].copy_from_slice(&iv[2..12]);

        let decrypted = cipher
            .decrypt(&nonce_bytes, data, &[])
            .map_err(|e| Error::protocol(format!("Failed to decrypt data: {:?}", e)))?;

        Ok(decrypted)
    }

    /// Read one length-prefixed response chunk and open it with the `count`-th
    /// nonce of the direction. The caller owns the counter: chunk `n` is only
    /// decryptable with nonce `n`, so both the value and its increment have to
    /// track every read (a fresh session starts at zero).
    fn read_response_chunk<S: Read + ?Sized>(
        &self,
        stream: &mut S,
        key: &[u8; 16],
        iv: &[u8; 16],
        count: u16,
        deadline: Instant,
    ) -> std::io::Result<Vec<u8>> {
        let mut length_buf = [0u8; 2];
        read_exact_deadline(stream, &mut length_buf, deadline)?;

        let length = u16::from_be_bytes(length_buf) as usize;
        if length == 0 {
            return Ok(Vec::new());
        }

        let mut data = vec![0u8; length];
        read_exact_deadline(stream, &mut data, deadline)?;

        self.decrypt_chunk(&data, key, iv, count)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

/// Upper bound on the decrypted response header. The reference server sends
/// four bytes (`responseHeader | option | command`, the last two zero when no
/// command follows) plus a small command payload at most; a larger value
/// means the stream is desynchronised and there is no point assembling it.
const VMESS_RESPONSE_HEADER_MAX: usize = 4096;

/// Open the 18-byte encrypted length block of the AEAD response header,
/// returning the payload length the server announced.
fn open_response_header_length(
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
    block: &[u8],
) -> std::io::Result<usize> {
    let key = kdf16(response_key, &[RESPONSE_LENGTH_KEY_SALT]);
    let iv = kdf12(response_iv, &[RESPONSE_LENGTH_IV_SALT]);
    let cipher = Aes128Gcm::new_from_slice(&key)
        .map_err(|e| std::io::Error::other(format!("vmess: response length cipher: {e}")))?;
    let plain = cipher
        .decrypt(&iv, block, &[])
        .map_err(|e| std::io::Error::other(format!("vmess: response header length: {e}")))?;
    if plain.len() != 2 {
        return Err(std::io::Error::other(
            "vmess: response header length is not two bytes",
        ));
    }
    Ok(u16::from_be_bytes([plain[0], plain[1]]) as usize)
}

/// Open the response header payload (ciphertext plus its 16-byte tag).
fn open_response_header_payload(
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
    block: &[u8],
) -> std::io::Result<Vec<u8>> {
    let key = kdf16(response_key, &[RESPONSE_HEADER_KEY_SALT]);
    let iv = kdf12(response_iv, &[RESPONSE_HEADER_IV_SALT]);
    let cipher = Aes128Gcm::new_from_slice(&key)
        .map_err(|e| std::io::Error::other(format!("vmess: response header cipher: {e}")))?;
    cipher
        .decrypt(&iv, block, &[])
        .map_err(|e| std::io::Error::other(format!("vmess: response header: {e}")))
}

/// Read exactly `buf.len()` bytes, retrying transient read timeouts until
/// `deadline`. Safe to retry: a `read` that returns `WouldBlock`/`TimedOut`
/// consumes no bytes, and the courierust TLS record layer resumes from the
/// exact byte across a mid-record timeout.
fn read_exact_deadline<R: Read + ?Sized>(
    stream: &mut R,
    buf: &mut [u8],
    deadline: Instant,
) -> std::io::Result<()> {
    let mut pos = 0usize;
    while pos < buf.len() {
        match stream.read(&mut buf[pos..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected EOF",
                ))
            }
            Ok(n) => pos += n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "read timed out",
                    ));
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// `read_exact` that honours an optional deadline, which is how the response
/// header reads fit both the blocking relay path and the bounded latency path.
fn read_exact_with_deadline<R: Read + ?Sized>(
    stream: &mut R,
    buf: &mut [u8],
    deadline: Option<Instant>,
) -> Result<()> {
    match deadline {
        Some(deadline) => {
            read_exact_deadline(stream, buf, deadline).map_err(|e| Error::network(e.to_string()))
        }
        None => stream
            .read_exact(buf)
            .map_err(|e| Error::network(format!("Failed to read the response header: {e}"))),
    }
}

impl OutboundProxy for VmessOutbound {
    fn connect(&self) -> Result<()> {
        let _stream = self.connect_tcp()?;
        tracing::info!(
            "VMess outbound '{}' can reach {}:{}",
            self.config.tag,
            self.server,
            self.port
        );
        Ok(())
    }

    fn disconnect(&self) -> Result<()> {
        Ok(())
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn server_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }

    fn supports_udp(&self) -> bool {
        self.udp_enabled
    }

    fn relay_udp_packet(&self, target: &TargetAddr, data: &[u8]) -> Result<Vec<u8>> {
        if !self.udp_enabled {
            return Err(Error::config(
                "UDP relay is not enabled for this VMess proxy",
            ));
        }
        self.relay_udp(target, data)
    }

    fn test_http_latency(
        &self,
        test_url: &str,
        timeout: std::time::Duration,
    ) -> Result<std::time::Duration> {
        use std::time::Instant;

        let url = crate::common::url::Url::parse(test_url)
            .map_err(|e| Error::config(format!("Invalid test URL: {}", e)))?;

        let host = url
            .host_str()
            .ok_or_else(|| Error::config("Test URL has no host"))?
            .to_string();
        let url_port = url
            .port()
            .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        let path = if url.path().is_empty() {
            "/"
        } else {
            url.path()
        };

        let start = Instant::now();

        // Use connect_stream to support TLS
        let mut stream = self.connect_stream()?;

        let target = TargetAddr::Domain(host.clone(), url_port);
        let (request_key, request_iv, response_header) =
            self.handshake(&mut *stream, &target, VmessCommand::Tcp)?;

        let http_request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: Corduit/1.0\r\n\r\n",
            path, host
        );

        let encrypted_request =
            self.encrypt_chunk(http_request.as_bytes(), &request_key, &request_iv, 0)?;
        stream
            .write_all(&encrypted_request)
            .map_err(|e| Error::network(format!("Failed to send HTTP request: {}", e)))?;

        let response_key = self.generate_response_key(&request_key);
        let response_iv = self.generate_response_iv(&request_iv);

        // Bounded response read: retry transient timeouts up to the deadline.
        let deadline = Instant::now() + timeout;
        self.read_response_header(
            &mut *stream,
            &response_key,
            &response_iv,
            response_header,
            Some(deadline),
        )?;
        let response = self
            .read_response_chunk(&mut *stream, &response_key, &response_iv, 0, deadline)
            .map_err(|e| Error::network(format!("Failed to read response: {}", e)))?;

        let response_str = String::from_utf8_lossy(&response);
        if response_str.starts_with("HTTP/") {
            let elapsed = start.elapsed();
            tracing::info!("VMess latency test success: {}ms", elapsed.as_millis());
            Ok(elapsed)
        } else {
            Err(Error::network("Invalid HTTP response"))
        }
    }

    fn relay_tcp(&self, inbound: BoxStream, target: TargetAddr) -> Result<()> {
        self.relay_tcp_with_connection(inbound, target, None)
    }

    fn relay_tcp_with_connection(
        &self,
        inbound: BoxStream,
        target: TargetAddr,
        connection: Option<Arc<TrackedConnection>>,
    ) -> Result<()> {
        // Use connect_stream to support TLS / WebSocket
        let mut stream = self.connect_stream()?;
        let (request_key, request_iv, response_header) =
            self.handshake(&mut *stream, &target, VmessCommand::Tcp)?;

        let response_key = self.generate_response_key(&request_key);
        let response_iv = self.generate_response_iv(&request_iv);

        // The response header is *not* read here. The reference server
        // buffers it and only flushes it together with the first target
        // payload (v2ray `transferResponse`), so waiting for it before the
        // request body has been forwarded deadlocks the connection: the
        // target never answers a request that is still parked in this
        // thread. The downlink reader consumes it lazily instead, once the
        // relay has pushed the request out.
        let vmess_stream = VmessStream::new(
            stream,
            self.cipher,
            request_key,
            request_iv,
            response_key,
            response_iv,
            response_header,
        );

        tracing::debug!(
            "VMess: relaying TCP to {} via {}:{} (tls={})",
            target,
            self.server,
            self.port,
            self.tls_enabled
        );

        // Wrap the stream with the VMess chunked-encryption codec and let the
        // bidirectional relay drive both directions concurrently.
        relay_streams!(inbound, vmess_stream, connection)
    }
}

/// Where the downlink reader is in the framing of the bytes it still needs.
///
/// The stages exist because the relay arms a short socket read timeout
/// (`RELAY_READ_POLL`): a read that comes back `WouldBlock` in the middle of
/// a frame must not lose the bytes already consumed. A plain `read_exact`
/// would — it forgets partial progress — and the next poll would then treat
/// the second half of a frame as a new length, desynchronising the stream
/// into garbage. Every stage therefore keeps its scratch buffer and fill
/// count across calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DownlinkStage {
    /// Assembling the 18-byte encrypted length block of the response header.
    HeaderLength,
    /// Assembling the response header payload (`length + 16` bytes).
    HeaderPayload,
    /// Reading the two-byte length of the next body chunk.
    ChunkLength,
    /// Reading that chunk's ciphertext and tag.
    ChunkPayload,
}

/// A `std::io::Read + Write + SyncStream` adapter over the VMess
/// chunked-encryption codec, so the bidirectional relay can drive the
/// upstream stream: writes encrypt each chunk (incrementing the request
/// count), reads decrypt each chunk (incrementing the response count).
///
/// The downlink consumes the AEAD response header lazily, on its first read,
/// exactly like the reference client: the server only flushes the header
/// together with the first response payload, so the uplink has to be able to
/// forward the request before those bytes are anywhere near the wire.
///
/// On write-shutdown the encrypted end-of-stream chunk is emitted once before
/// the underlying transport is half-closed, matching the reference writer.
struct VmessStream {
    inner: parking_lot::Mutex<BoxStream>,
    cipher: VmessCipher,
    enc_key: [u8; 16],
    enc_iv: [u8; 16],
    dec_key: [u8; 16],
    dec_iv: [u8; 16],
    /// Request-side nonce counter. Atomic because [`SyncStream::shutdown`]
    /// takes `&self` and still has to emit the final chunk with the next
    /// counter value.
    enc_count: AtomicU16,
    dec_count: u16,
    /// Downlink framing state plus the scratch buffer it is filling (see
    /// [`DownlinkStage`]).
    stage: DownlinkStage,
    fill: Vec<u8>,
    filled: usize,
    /// The byte the response header has to echo back; `None` once consumed.
    expected_response_header: Option<u8>,
    read_buffer: Vec<u8>,
    read_pos: usize,
    eof: bool,
    end_chunk_sent: AtomicBool,
}

/// Maximum plaintext bytes per VMess chunk (u16 length field on the wire;
/// ciphertext adds a 16-byte tag, so 16 KiB always fits).
const VMESS_CHUNK_MAX: usize = 16 * 1024;

impl VmessStream {
    #[allow(clippy::too_many_arguments)]
    fn new(
        inner: BoxStream,
        cipher: VmessCipher,
        enc_key: [u8; 16],
        enc_iv: [u8; 16],
        dec_key: [u8; 16],
        dec_iv: [u8; 16],
        expected_response_header: u8,
    ) -> Self {
        Self {
            inner: parking_lot::Mutex::new(inner),
            cipher,
            enc_key,
            enc_iv,
            dec_key,
            dec_iv,
            enc_count: AtomicU16::new(0),
            dec_count: 0,
            stage: DownlinkStage::HeaderLength,
            fill: vec![0u8; 2 + VMESS_AEAD_AUTH_LEN],
            filled: 0,
            expected_response_header: Some(expected_response_header),
            read_buffer: Vec::new(),
            read_pos: 0,
            eof: false,
            end_chunk_sent: AtomicBool::new(false),
        }
    }

    /// Fill the current stage's scratch buffer, preserving partial progress
    /// across idle polls. `Ok(false)` means a poll expired without completing
    /// the buffer (no frame byte is lost); `Err` is fatal for the stream.
    ///
    /// The transport lock is taken here (rather than by the caller) so the
    /// borrow of `self.inner` stays disjoint from the `&mut` access to the
    /// framing fields.
    fn fill_stage(&mut self) -> std::io::Result<bool> {
        let mut inner = self.inner.lock();
        while self.filled < self.fill.len() {
            match inner.read(&mut self.fill[self.filled..]) {
                Ok(0) => {
                    if self.stage == DownlinkStage::ChunkLength && self.filled == 0 {
                        self.eof = true;
                        return Ok(true);
                    }
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "unexpected EOF",
                    ));
                }
                Ok(n) => self.filled += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(false);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(true)
    }

    /// Consume the stage that just completed and switch to the next one.
    /// Never blocks and never reads.
    fn advance_stage(&mut self) -> std::io::Result<()> {
        match self.stage {
            DownlinkStage::HeaderLength => {
                let length = open_response_header_length(&self.dec_key, &self.dec_iv, &self.fill)?;
                if length > VMESS_RESPONSE_HEADER_MAX {
                    return Err(std::io::Error::other(format!(
                        "vmess: response header length {length} is out of range"
                    )));
                }
                self.fill = vec![0u8; length + VMESS_AEAD_AUTH_LEN];
                self.filled = 0;
                self.stage = DownlinkStage::HeaderPayload;
            }
            DownlinkStage::HeaderPayload => {
                let plain = open_response_header_payload(&self.dec_key, &self.dec_iv, &self.fill)?;
                if plain.len() < 4 {
                    return Err(std::io::Error::other(
                        "vmess: response header payload is too short",
                    ));
                }
                if let Some(expected) = self.expected_response_header.take() {
                    if plain[0] != expected {
                        return Err(std::io::Error::other(format!(
                            "vmess: response header byte mismatch (expected {expected}, got {})",
                            plain[0]
                        )));
                    }
                }
                self.begin_chunk_length();
            }
            DownlinkStage::ChunkLength => {
                let length = u16::from_be_bytes([self.fill[0], self.fill[1]]) as usize;
                if length == 0 {
                    self.eof = true;
                    return Ok(());
                }
                self.fill = vec![0u8; length];
                self.filled = 0;
                self.stage = DownlinkStage::ChunkPayload;
            }
            DownlinkStage::ChunkPayload => {
                let decrypted = decrypt_chunk_static(
                    self.cipher,
                    &self.fill,
                    &self.dec_key,
                    &self.dec_iv,
                    self.dec_count,
                )
                .map_err(|e| std::io::Error::other(e.to_string()))?;
                self.dec_count = self.dec_count.wrapping_add(1);
                if decrypted.is_empty() {
                    self.eof = true;
                    return Ok(());
                }
                self.read_buffer = decrypted;
                self.read_pos = 0;
                self.begin_chunk_length();
            }
        }
        Ok(())
    }

    fn begin_chunk_length(&mut self) {
        self.stage = DownlinkStage::ChunkLength;
        self.fill.clear();
        self.fill.resize(2, 0);
        self.filled = 0;
    }
}

impl Read for VmessStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            // Serve buffered plaintext first.
            if self.read_pos < self.read_buffer.len() {
                let n = (self.read_buffer.len() - self.read_pos).min(buf.len());
                buf[..n].copy_from_slice(&self.read_buffer[self.read_pos..self.read_pos + n]);
                self.read_pos += n;
                if self.read_pos >= self.read_buffer.len() {
                    self.read_buffer.clear();
                    self.read_pos = 0;
                }
                return Ok(n);
            }
            if self.eof {
                return Ok(0);
            }

            let completed = self.fill_stage()?;
            if self.eof {
                return Ok(0);
            }
            if !completed {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "vmess: idle poll",
                ));
            }
            self.advance_stage()?;
        }
    }
}

impl Write for VmessStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut inner = self.inner.lock();
        let mut count = self.enc_count.load(Ordering::Relaxed);
        for chunk in buf.chunks(VMESS_CHUNK_MAX) {
            let encrypted =
                encrypt_chunk_static(self.cipher, chunk, &self.enc_key, &self.enc_iv, count)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
            inner.write_all(&encrypted)?;
            count = count.wrapping_add(1);
        }
        self.enc_count.store(count, Ordering::Relaxed);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.lock().flush()
    }
}

impl crate::common::stream::SyncStream for VmessStream {
    fn shutdown(&self, how: std::net::Shutdown) -> std::io::Result<()> {
        let mut inner = self.inner.lock();
        // Emit the end-of-stream chunk exactly once, and only when the write
        // half is actually closing. The wire form is an *encrypted* empty
        // chunk: the reference reader only treats a chunk whose length equals
        // the authentication overhead as end-of-stream, and hands anything
        // else to its AEAD open — where a bare `[0x00,0x00]` fails
        // authentication and turns a clean close into a protocol error.
        // Sealing zero bytes produces exactly that form: `[0x00,0x10]` plus a
        // 16-byte tag (or `[0x00,0x00]` under a plaintext cipher).
        if matches!(how, std::net::Shutdown::Write | std::net::Shutdown::Both)
            && !self.end_chunk_sent.swap(true, Ordering::SeqCst)
        {
            let count = self.enc_count.fetch_add(1, Ordering::SeqCst);
            match encrypt_chunk_static(self.cipher, &[], &self.enc_key, &self.enc_iv, count) {
                Ok(end_chunk) => {
                    let _ = inner.write_all(&end_chunk);
                    let _ = inner.flush();
                }
                Err(e) => {
                    tracing::debug!("VMess: failed to seal the end-of-stream chunk: {e}");
                }
            }
        }
        inner.shutdown(how)
    }

    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.lock().peer_addr()
    }

    fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        self.inner.lock().set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        self.inner.lock().set_write_timeout(timeout)
    }
}

fn generate_cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(uuid);
    hasher.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    hasher.finalize()
}

/// The 32-byte ChaCha20-Poly1305 key of the reference implementation
/// (`vmess/encoding/auth.go`, `GenerateChacha20Poly1305Key`):
/// `MD5(bodyKey) ‖ MD5(MD5(bodyKey))`.
///
/// It is emphatically *not* the 16-byte body key doubled: a doubled key is
/// self-consistent between our writer and reader and still fails every real
/// server with `chacha20poly1305: message authentication failed`.
fn chacha20_poly1305_key(body_key: &[u8; 16]) -> [u8; 32] {
    let mut hasher = Md5::new();
    hasher.update(body_key);
    let first = hasher.finalize();

    let mut hasher = Md5::new();
    hasher.update(&first);
    let second = hasher.finalize();

    let mut key = [0u8; 32];
    key[..16].copy_from_slice(&first);
    key[16..].copy_from_slice(&second);
    key
}

/// CRC-32 (IEEE 802.3): the checksum the AuthID carries so a server can tell
/// a corrupted timestamp from a wrong key.
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn generate_connection_nonce() -> [u8; 8] {
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).expect("Failed to generate nonce");
    nonce
}

/// The AEAD KDF of v2ray/xray (`proxy/vmess/aead/kdf.go`): a chain of nested
/// HMAC-SHA-256 constructions. Level zero is plain SHA-256; every following
/// level is an HMAC whose key is one path element and whose underlying hash is
/// the previous level, so the outermost level — keyed by the last path element
/// — is the one that finally absorbs `key`. The constant salt keys the
/// innermost level.
///
/// Interoperability depends on this shape, not on a flat
/// `SHA256(key ‖ path…)`: a server derives the same keys with the chain, and a
/// client that concatenates instead produces a header it cannot decrypt.
fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut keys: [&[u8]; 6] = [b"".as_slice(); 6];
    keys[0] = KDF_BASE_SALT;
    let mut count = 1;
    for element in path {
        keys[count] = element;
        count += 1;
    }
    kdf_chain(&keys[..count], key)
}

/// Applies the chain described on [`kdf`] to `message`; `keys` runs from the
/// innermost salt to the outermost one.
fn kdf_chain(keys: &[&[u8]], message: &[u8]) -> [u8; 32] {
    let Some((salt, inner_levels)) = keys.split_last() else {
        let mut out = [0u8; 32];
        Sha256::digest_into(message, &mut out);
        return out;
    };

    let mut key_block = [0u8; 64];
    if salt.len() > key_block.len() {
        let mut hashed = [0u8; 32];
        Sha256::digest_into(salt, &mut hashed);
        key_block.copy_from_slice(&hashed);
    } else {
        key_block[..salt.len()].copy_from_slice(salt);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..key_block.len() {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner_input = Vec::with_capacity(64 + message.len());
    inner_input.extend_from_slice(&ipad);
    inner_input.extend_from_slice(message);
    let inner_digest = kdf_chain(inner_levels, &inner_input);

    let mut outer_input = Vec::with_capacity(64 + inner_digest.len());
    outer_input.extend_from_slice(&opad);
    outer_input.extend_from_slice(&inner_digest);
    kdf_chain(inner_levels, &outer_input)
}

fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let full = kdf(key, path);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

fn kdf12(key: &[u8], path: &[&[u8]]) -> [u8; 12] {
    let full = kdf(key, path);
    let mut out = [0u8; 12];
    out.copy_from_slice(&full[..12]);
    out
}

fn fnv1a_hash(data: &[u8]) -> u32 {
    const FNV_OFFSET_BASIS: u32 = 0x811c9dc5;
    const FNV_PRIME: u32 = 0x01000193;

    let mut hash = FNV_OFFSET_BASIS;
    for byte in data {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn encrypt_chunk_static(
    cipher: VmessCipher,
    data: &[u8],
    key: &[u8; 16],
    iv: &[u8; 16],
    count: u16,
) -> Result<Vec<u8>> {
    match cipher {
        VmessCipher::Aes128Gcm | VmessCipher::Auto => {
            let aes_cipher = Aes128Gcm::new_from_slice(key)
                .map_err(|e| Error::protocol(format!("Failed to create AES-GCM cipher: {}", e)))?;

            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[..2].copy_from_slice(&count.to_be_bytes());
            nonce_bytes[2..].copy_from_slice(&iv[2..12]);

            let encrypted = aes_cipher
                .encrypt(&nonce_bytes, data, &[])
                .map_err(|e| Error::protocol(format!("Failed to encrypt data: {:?}", e)))?;

            let length = (encrypted.len() as u16).to_be_bytes();
            let mut result = Vec::with_capacity(2 + encrypted.len());
            result.extend_from_slice(&length);
            result.extend_from_slice(&encrypted);
            Ok(result)
        }
        VmessCipher::Chacha20Poly1305 => {
            let full_key = chacha20_poly1305_key(key);

            let chacha_cipher = ChaCha20Poly1305::new_from_slice(&full_key)
                .map_err(|e| Error::protocol(format!("Failed to create ChaCha20 cipher: {}", e)))?;

            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[..2].copy_from_slice(&count.to_be_bytes());
            nonce_bytes[2..].copy_from_slice(&iv[2..12]);

            let encrypted = chacha_cipher
                .encrypt(&nonce_bytes, data, &[])
                .map_err(|e| Error::protocol(format!("Failed to encrypt data: {:?}", e)))?;

            let length = (encrypted.len() as u16).to_be_bytes();
            let mut result = Vec::with_capacity(2 + encrypted.len());
            result.extend_from_slice(&length);
            result.extend_from_slice(&encrypted);
            Ok(result)
        }
        VmessCipher::None | VmessCipher::Zero => {
            let mut result = Vec::with_capacity(2 + data.len());
            result.extend_from_slice(&(data.len() as u16).to_be_bytes());
            result.extend_from_slice(data);
            Ok(result)
        }
    }
}

fn decrypt_chunk_static(
    cipher: VmessCipher,
    data: &[u8],
    key: &[u8; 16],
    iv: &[u8; 16],
    count: u16,
) -> Result<Vec<u8>> {
    match cipher {
        VmessCipher::Aes128Gcm | VmessCipher::Auto => {
            let aes_cipher = Aes128Gcm::new_from_slice(key)
                .map_err(|e| Error::protocol(format!("Failed to create AES-GCM cipher: {}", e)))?;

            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[..2].copy_from_slice(&count.to_be_bytes());
            nonce_bytes[2..].copy_from_slice(&iv[2..12]);

            let decrypted = aes_cipher
                .decrypt(&nonce_bytes, data, &[])
                .map_err(|e| Error::protocol(format!("Failed to decrypt data: {:?}", e)))?;

            Ok(decrypted)
        }
        VmessCipher::Chacha20Poly1305 => {
            let full_key = chacha20_poly1305_key(key);

            let chacha_cipher = ChaCha20Poly1305::new_from_slice(&full_key)
                .map_err(|e| Error::protocol(format!("Failed to create ChaCha20 cipher: {}", e)))?;

            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[..2].copy_from_slice(&count.to_be_bytes());
            nonce_bytes[2..].copy_from_slice(&iv[2..12]);

            let decrypted = chacha_cipher
                .decrypt(&nonce_bytes, data, &[])
                .map_err(|e| Error::protocol(format!("Failed to decrypt data: {:?}", e)))?;

            Ok(decrypted)
        }
        VmessCipher::None | VmessCipher::Zero => Ok(data.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vmess_cipher_from_str() {
        assert_eq!(VmessCipher::from_str("aes-128-gcm"), VmessCipher::Aes128Gcm);
        assert_eq!(VmessCipher::from_str("aes128gcm"), VmessCipher::Aes128Gcm);
        assert_eq!(
            VmessCipher::from_str("chacha20-poly1305"),
            VmessCipher::Chacha20Poly1305
        );
        assert_eq!(VmessCipher::from_str("none"), VmessCipher::None);
        assert_eq!(VmessCipher::from_str("zero"), VmessCipher::Zero);
        assert_eq!(VmessCipher::from_str("auto"), VmessCipher::Auto);
        assert_eq!(VmessCipher::from_str("unknown"), VmessCipher::Auto);
    }

    #[test]
    fn test_vmess_cipher_as_byte() {
        assert_eq!(VmessCipher::Aes128Gcm.as_byte(), 0x03);
        assert_eq!(VmessCipher::Chacha20Poly1305.as_byte(), 0x04);
        assert_eq!(VmessCipher::None.as_byte(), 0x05);
        assert_eq!(VmessCipher::Zero.as_byte(), 0x06);
        assert_eq!(VmessCipher::Auto.as_byte(), 0x03);
    }

    #[test]
    fn test_vmess_command_from_u8() {
        assert_eq!(VmessCommand::from_u8(0x01), Some(VmessCommand::Tcp));
        assert_eq!(VmessCommand::from_u8(0x02), Some(VmessCommand::Udp));
        assert_eq!(VmessCommand::from_u8(0x00), None);
        assert_eq!(VmessCommand::from_u8(0xFF), None);
    }

    #[test]
    fn test_generate_cmd_key() {
        let uuid = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let key = generate_cmd_key(&uuid);
        assert_eq!(key.len(), 16);

        let key2 = generate_cmd_key(&uuid);
        assert_eq!(key, key2);
    }

    #[test]
    fn test_fnv1a_hash() {
        let data = b"hello world";
        let hash = fnv1a_hash(data);
        assert_ne!(hash, 0);

        let hash2 = fnv1a_hash(data);
        assert_eq!(hash, hash2);

        let hash3 = fnv1a_hash(b"different data");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_kdf16() {
        let key = b"test_key";
        let path = [b"path1".as_slice(), b"path2".as_slice()];
        let result = kdf16(key, &path);
        assert_eq!(result.len(), 16);

        let result2 = kdf16(key, &path);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_kdf12() {
        let key = b"test_key";
        let path = [b"path1".as_slice(), b"path2".as_slice()];
        let result = kdf12(key, &path);
        assert_eq!(result.len(), 12);

        let result2 = kdf12(key, &path);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_vmess_outbound_new() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            nextjson::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );
        options.insert(
            "alterId".to_string(),
            nextjson::Value::Number(nextjson::Number::from(0)),
        );
        options.insert(
            "cipher".to_string(),
            nextjson::Value::String("aes-128-gcm".to_string()),
        );
        options.insert("udp".to_string(), nextjson::Value::Bool(true));

        let config = OutboundConfig {
            tag: "vmess-test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Vmess,
            server: Some("vmess.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = VmessOutbound::new(config).unwrap();

        assert_eq!(outbound.tag(), "vmess-test");
        assert_eq!(outbound.server, "vmess.example.com");
        assert_eq!(outbound.port, 443);
        assert_eq!(outbound.cipher, VmessCipher::Aes128Gcm);
        assert!(outbound.is_udp_enabled());
    }

    #[test]
    fn test_vmess_outbound_missing_uuid() {
        let config = OutboundConfig {
            tag: "vmess-test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Vmess,
            server: Some("vmess.example.com".to_string()),
            port: Some(443),
            options: std::collections::HashMap::new(),
        };

        let result = VmessOutbound::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_vmess_outbound_invalid_uuid() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            nextjson::Value::String("invalid-uuid".to_string()),
        );

        let config = OutboundConfig {
            tag: "vmess-test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Vmess,
            server: Some("vmess.example.com".to_string()),
            port: Some(443),
            options,
        };

        let result = VmessOutbound::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_vmess_outbound_server_addr() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            nextjson::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );

        let config = OutboundConfig {
            tag: "vmess-test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Vmess,
            server: Some("server.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = VmessOutbound::new(config).unwrap();
        let (server, port) = outbound.server_addr().unwrap();
        assert_eq!(server, "server.example.com");
        assert_eq!(port, 443);
    }

    fn options_with_uuid() -> std::collections::HashMap<String, nextjson::Value> {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            nextjson::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );
        options
    }

    fn outbound_with(
        options: std::collections::HashMap<String, nextjson::Value>,
    ) -> Result<VmessOutbound> {
        VmessOutbound::new(OutboundConfig {
            tag: "vmess-test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Vmess,
            server: Some("vmess.example.com".to_string()),
            port: Some(443),
            options,
        })
    }

    #[test]
    fn test_vmess_ws_tls_defaults_to_http11_alpn() {
        let mut options = options_with_uuid();
        options.insert(
            "network".to_string(),
            nextjson::Value::String("ws".to_string()),
        );
        options.insert("tls".to_string(), nextjson::Value::Bool(true));
        let outbound = outbound_with(options).unwrap();
        assert_eq!(outbound.effective_alpn(), vec!["http/1.1".to_string()]);
    }

    #[test]
    fn test_vmess_explicit_alpn_wins_over_the_default() {
        let mut options = options_with_uuid();
        options.insert(
            "network".to_string(),
            nextjson::Value::String("ws".to_string()),
        );
        options.insert(
            "alpn".to_string(),
            nextjson::Value::Array(vec![nextjson::Value::String("h2".to_string())]),
        );
        let outbound = outbound_with(options).unwrap();
        assert_eq!(outbound.effective_alpn(), vec!["h2".to_string()]);
    }

    #[test]
    fn test_vmess_tcp_tls_keeps_the_browser_alpn_default() {
        let mut options = options_with_uuid();
        options.insert("tls".to_string(), nextjson::Value::Bool(true));
        let outbound = outbound_with(options).unwrap();
        assert_eq!(
            outbound.effective_alpn(),
            vec!["h2".to_string(), "http/1.1".to_string()]
        );
    }

    #[test]
    fn test_vmess_unimplemented_or_unknown_transports_are_rejected() {
        for name in ["grpc", "h2", "http2", "quic", "kcp", "domainsocket"] {
            let mut options = options_with_uuid();
            options.insert(
                "network".to_string(),
                nextjson::Value::String(name.to_string()),
            );
            assert!(
                outbound_with(options).is_err(),
                "transport '{name}' must be rejected"
            );
        }
    }

    #[test]
    fn test_vmess_tcp_and_ws_transports_are_accepted() {
        for name in ["tcp", "ws", ""] {
            let mut options = options_with_uuid();
            options.insert(
                "network".to_string(),
                nextjson::Value::String(name.to_string()),
            );
            assert!(
                outbound_with(options).is_ok(),
                "transport '{name}' must be accepted"
            );
        }
    }

    #[test]
    fn test_generate_auth_id() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            nextjson::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );

        let config = OutboundConfig {
            tag: "vmess-test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Vmess,
            server: Some("server.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = VmessOutbound::new(config).unwrap();
        let timestamp = 1234567890i64;
        let auth_id = outbound.generate_auth_id(timestamp);
        assert_eq!(auth_id.len(), 16);

        let key = kdf16(&outbound.cmd_key, &[AUTH_ID_ENCRYPTION_SALT]);
        let cipher = Aes::new(&key).unwrap();
        let mut block = auth_id;
        cipher.decrypt_block(&mut block);
        assert_eq!(
            i64::from_be_bytes(block[..8].try_into().unwrap()),
            timestamp
        );
        assert_eq!(
            u32::from_be_bytes(block[12..].try_into().unwrap()),
            crc32_ieee(&block[..12])
        );
    }

    #[test]
    fn test_generate_request_key_iv() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            nextjson::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );

        let config = OutboundConfig {
            tag: "vmess-test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Vmess,
            server: Some("server.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = VmessOutbound::new(config).unwrap();

        let key1 = outbound.generate_request_key();
        let key2 = outbound.generate_request_key();
        assert_eq!(key1.len(), 16);
        assert_eq!(key2.len(), 16);
        assert_ne!(key1, key2);

        let iv1 = outbound.generate_request_iv();
        let iv2 = outbound.generate_request_iv();
        assert_eq!(iv1.len(), 16);
        assert_eq!(iv2.len(), 16);
        assert_ne!(iv1, iv2);
    }

    #[test]
    fn test_generate_response_key_iv() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            nextjson::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );

        let config = OutboundConfig {
            tag: "vmess-test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Vmess,
            server: Some("server.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = VmessOutbound::new(config).unwrap();

        let request_key = [0x01u8; 16];
        let request_iv = [0x02u8; 16];

        let response_key = outbound.generate_response_key(&request_key);
        let response_iv = outbound.generate_response_iv(&request_iv);

        assert_eq!(response_key.len(), 16);
        assert_eq!(response_iv.len(), 16);

        let response_key2 = outbound.generate_response_key(&request_key);
        let response_iv2 = outbound.generate_response_iv(&request_iv);
        assert_eq!(response_key, response_key2);
        assert_eq!(response_iv, response_iv2);
    }

    #[test]
    fn test_encrypt_decrypt_aes_gcm_roundtrip() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            nextjson::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );
        options.insert(
            "cipher".to_string(),
            nextjson::Value::String("aes-128-gcm".to_string()),
        );

        let config = OutboundConfig {
            tag: "vmess-test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Vmess,
            server: Some("server.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = VmessOutbound::new(config).unwrap();

        let key = [0x01u8; 16];
        let iv = [0x02u8; 16];
        let data = b"Hello, VMess!";

        let encrypted = outbound.encrypt_aes_gcm(data, &key, &iv, 0).unwrap();
        assert!(encrypted.len() > data.len());

        let length = u16::from_be_bytes([encrypted[0], encrypted[1]]) as usize;
        let decrypted = outbound
            .decrypt_aes_gcm(&encrypted[2..2 + length], &key, &iv, 0)
            .unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_encrypt_decrypt_chacha20_roundtrip() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            nextjson::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );
        options.insert(
            "cipher".to_string(),
            nextjson::Value::String("chacha20-poly1305".to_string()),
        );

        let config = OutboundConfig {
            tag: "vmess-test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Vmess,
            server: Some("server.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = VmessOutbound::new(config).unwrap();

        let key = [0x01u8; 16];
        let iv = [0x02u8; 16];
        let data = b"Hello, VMess!";

        let encrypted = outbound.encrypt_chacha20(data, &key, &iv, 0).unwrap();
        assert!(encrypted.len() > data.len());

        let length = u16::from_be_bytes([encrypted[0], encrypted[1]]) as usize;
        let decrypted = outbound
            .decrypt_chacha20(&encrypted[2..2 + length], &key, &iv, 0)
            .unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_encrypt_decrypt_none_roundtrip() {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            nextjson::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );
        options.insert(
            "cipher".to_string(),
            nextjson::Value::String("none".to_string()),
        );

        let config = OutboundConfig {
            tag: "vmess-test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Vmess,
            server: Some("server.example.com".to_string()),
            port: Some(443),
            options,
        };

        let outbound = VmessOutbound::new(config).unwrap();

        let key = [0x01u8; 16];
        let iv = [0x02u8; 16];
        let data = b"Hello, VMess!";

        let encrypted = outbound.encrypt_chunk(data, &key, &iv, 0).unwrap();
        let length = u16::from_be_bytes([encrypted[0], encrypted[1]]) as usize;
        assert_eq!(length, data.len());

        let decrypted = outbound
            .decrypt_chunk(&encrypted[2..], &key, &iv, 0)
            .unwrap();
        assert_eq!(decrypted, data);
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_key() -> impl Strategy<Value = [u8; 16]> {
        prop::array::uniform16(any::<u8>())
    }

    fn arb_iv() -> impl Strategy<Value = [u8; 16]> {
        prop::array::uniform16(any::<u8>())
    }

    fn arb_data() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 1..1024)
    }

    fn arb_count() -> impl Strategy<Value = u16> {
        0u16..1000u16
    }

    fn arb_timestamp() -> impl Strategy<Value = i64> {
        1000000000i64..2000000000i64
    }

    fn create_test_outbound(cipher_str: &str) -> VmessOutbound {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "uuid".to_string(),
            nextjson::Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
        );
        options.insert(
            "cipher".to_string(),
            nextjson::Value::String(cipher_str.to_string()),
        );

        let config = OutboundConfig {
            tag: "vmess-test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Vmess,
            server: Some("server.example.com".to_string()),
            port: Some(443),
            options,
        };

        VmessOutbound::new(config).unwrap()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_aes_gcm_encrypt_decrypt_roundtrip(
            key in arb_key(),
            iv in arb_iv(),
            data in arb_data(),
            count in arb_count()
        ) {
            let outbound = create_test_outbound("aes-128-gcm");

            let encrypted = outbound.encrypt_aes_gcm(&data, &key, &iv, count).unwrap();
            let length = u16::from_be_bytes([encrypted[0], encrypted[1]]) as usize;
            let decrypted = outbound.decrypt_aes_gcm(&encrypted[2..2+length], &key, &iv, count).unwrap();

            prop_assert_eq!(decrypted, data);
        }

        #[test]
        fn prop_chacha20_encrypt_decrypt_roundtrip(
            key in arb_key(),
            iv in arb_iv(),
            data in arb_data(),
            count in arb_count()
        ) {
            let outbound = create_test_outbound("chacha20-poly1305");

            let encrypted = outbound.encrypt_chacha20(&data, &key, &iv, count).unwrap();
            let length = u16::from_be_bytes([encrypted[0], encrypted[1]]) as usize;
            let decrypted = outbound.decrypt_chacha20(&encrypted[2..2+length], &key, &iv, count).unwrap();

            prop_assert_eq!(decrypted, data);
        }

        #[test]
        fn prop_none_cipher_roundtrip(
            key in arb_key(),
            iv in arb_iv(),
            data in arb_data(),
            count in arb_count()
        ) {
            let outbound = create_test_outbound("none");

            let encrypted = outbound.encrypt_chunk(&data, &key, &iv, count).unwrap();
            let length = u16::from_be_bytes([encrypted[0], encrypted[1]]) as usize;
            prop_assert_eq!(length, data.len());

            let decrypted = outbound.decrypt_chunk(&encrypted[2..], &key, &iv, count).unwrap();
            prop_assert_eq!(decrypted, data);
        }

        #[test]
        fn prop_auth_id_carries_a_valid_crc(timestamp in arb_timestamp()) {
            let outbound = create_test_outbound("auto");

            let auth_id = outbound.generate_auth_id(timestamp);
            prop_assert_eq!(auth_id.len(), 16);

            let key = kdf16(&outbound.cmd_key, &[AUTH_ID_ENCRYPTION_SALT]);
            let cipher = Aes::new(&key).unwrap();
            let mut block = auth_id;
            cipher.decrypt_block(&mut block);

            prop_assert_eq!(
                i64::from_be_bytes(block[..8].try_into().unwrap()),
                timestamp
            );
            prop_assert_eq!(
                u32::from_be_bytes(block[12..].try_into().unwrap()),
                crc32_ieee(&block[..12])
            );
        }

        #[test]
        fn prop_auth_id_different_timestamps(
            timestamp1 in arb_timestamp(),
            timestamp2 in arb_timestamp()
        ) {
            prop_assume!(timestamp1 != timestamp2);
            let outbound = create_test_outbound("auto");

            let auth_id1 = outbound.generate_auth_id(timestamp1);
            let auth_id2 = outbound.generate_auth_id(timestamp2);

            prop_assert_ne!(auth_id1, auth_id2);
        }

        #[test]
        fn prop_response_key_iv_deterministic(
            request_key in arb_key(),
            request_iv in arb_iv()
        ) {
            let outbound = create_test_outbound("auto");

            let response_key1 = outbound.generate_response_key(&request_key);
            let response_key2 = outbound.generate_response_key(&request_key);
            prop_assert_eq!(response_key1, response_key2);

            let response_iv1 = outbound.generate_response_iv(&request_iv);
            let response_iv2 = outbound.generate_response_iv(&request_iv);
            prop_assert_eq!(response_iv1, response_iv2);
        }

        #[test]
        fn prop_fnv1a_deterministic(data in arb_data()) {
            let hash1 = fnv1a_hash(&data);
            let hash2 = fnv1a_hash(&data);
            prop_assert_eq!(hash1, hash2);
        }

        #[test]
        fn prop_kdf_deterministic(
            key in prop::collection::vec(any::<u8>(), 1..64),
            path1 in prop::collection::vec(any::<u8>(), 1..32),
            path2 in prop::collection::vec(any::<u8>(), 1..32)
        ) {
            let path = [path1.as_slice(), path2.as_slice()];

            let result1 = kdf16(&key, &path);
            let result2 = kdf16(&key, &path);
            prop_assert_eq!(result1, result2);

            let result3 = kdf12(&key, &path);
            let result4 = kdf12(&key, &path);
            prop_assert_eq!(result3, result4);
        }

        #[test]
        fn prop_cmd_key_deterministic(uuid in prop::array::uniform16(any::<u8>())) {
            let key1 = generate_cmd_key(&uuid);
            let key2 = generate_cmd_key(&uuid);
            prop_assert_eq!(key1, key2);
            prop_assert_eq!(key1.len(), 16);
        }
    }

    /// The official KDF vector from v2ray-core (`proxy/vmess/aead/kdf_test.go`).
    /// Every AEAD key in the protocol is derived by this function, so a
    /// mismatch here is a mismatch with every server.
    #[test]
    fn kdf_matches_the_v2ray_test_vector() {
        let derived = kdf(
            b"Demo Key for KDF Value Test",
            &[
                b"Demo Path for KDF Value Test",
                b"Demo Path for KDF Value Test2",
                b"Demo Path for KDF Value Test3",
            ],
        );

        let mut hex = String::with_capacity(64);
        for byte in derived {
            hex.push_str(&format!("{byte:02x}"));
        }
        assert_eq!(
            hex,
            "53e9d7e1bd7bd25022b71ead07d8a596efc8a845c7888652fd684b4903dc8892"
        );
    }

    /// A sealed request header has to reproduce v2ray's wire layout: the
    /// AuthID, the encrypted length, the connection nonce and the encrypted
    /// header, with both seals bound to the AuthID as additional data.
    #[test]
    fn sealed_request_header_follows_the_reference_layout() {
        let outbound = create_test_outbound("aes-128-gcm");
        let target = TargetAddr::Domain("example.com".to_string(), 443);

        let mut wire = std::io::Cursor::new(Vec::new());
        let (_, _, response_header_byte) = outbound
            .handshake(&mut wire, &target, VmessCommand::Tcp)
            .expect("the header seals");
        let sealed = wire.into_inner();

        assert!(sealed.len() > 16 + 18 + 8, "authID, length, nonce, header");

        let auth_id: [u8; 16] = sealed[..16].try_into().unwrap();
        let connection_nonce: [u8; 8] = sealed[34..42].try_into().unwrap();

        let length_key = kdf16(
            &outbound.cmd_key,
            &[HEADER_LENGTH_KEY_SALT, &auth_id, &connection_nonce],
        );
        let length_nonce = kdf12(
            &outbound.cmd_key,
            &[HEADER_LENGTH_NONCE_SALT, &auth_id, &connection_nonce],
        );
        let length_cipher = Aes128Gcm::new_from_slice(&length_key).unwrap();
        let length_plain = length_cipher
            .decrypt(&length_nonce, &sealed[16..34], &auth_id)
            .expect("the length decrypts with the AuthID as additional data");
        let length = u16::from_be_bytes([length_plain[0], length_plain[1]]) as usize;
        // The length field is the PLAINTEXT header size; the ciphertext that
        // follows it is `length + 16` bytes (v2ray `OpenVMessAEADHeader` reads
        // exactly that).
        assert_eq!(length, sealed.len() - 42 - 16);

        // The same ciphertext without the AuthID as additional data must fail.
        assert!(length_cipher
            .decrypt(&length_nonce, &sealed[16..34], &[])
            .is_err());

        let header_key = kdf16(
            &outbound.cmd_key,
            &[HEADER_KEY_SALT, &auth_id, &connection_nonce],
        );
        let header_nonce = kdf12(
            &outbound.cmd_key,
            &[HEADER_NONCE_SALT, &auth_id, &connection_nonce],
        );
        let header_cipher = Aes128Gcm::new_from_slice(&header_key).unwrap();
        let plain = header_cipher
            .decrypt(&header_nonce, &sealed[42..], &auth_id)
            .expect("the header decrypts");

        assert_eq!(plain[0], VMESS_VERSION);
        assert_eq!(plain[33], response_header_byte);
        assert_eq!(plain[34], VmessOption::CHUNK_STREAM.bits());
        assert_eq!(plain[35] & 0x0f, VmessCipher::Aes128Gcm.as_byte());
        assert_eq!(plain[37], VmessCommand::Tcp as u8);
        assert_eq!(u16::from_be_bytes([plain[38], plain[39]]), 443);
        assert_eq!(plain[40], VmessAddressType::Domain as u8);
        assert_eq!(plain[41] as usize, "example.com".len());
        assert_eq!(&plain[42..53], b"example.com");

        let expected_fnv = fnv1a_hash(&plain[..plain.len() - 4]).to_be_bytes();
        assert_eq!(&plain[plain.len() - 4..], &expected_fnv);
    }

    /// The client has to consume the response header before the first body
    /// chunk; the reader stops exactly at its end and reports the echoed byte.
    #[test]
    fn response_header_round_trips_through_the_client_reader() {
        let outbound = create_test_outbound("aes-128-gcm");
        let request_key = [0x11u8; 16];
        let request_iv = [0x22u8; 16];
        let response_key = outbound.generate_response_key(&request_key);
        let response_iv = outbound.generate_response_iv(&request_iv);

        let echoed = 0x5au8;
        let payload = [echoed, 0x01, 0x00, 0x00];

        let length_key = kdf16(&response_key, &[RESPONSE_LENGTH_KEY_SALT]);
        let length_iv = kdf12(&response_iv, &[RESPONSE_LENGTH_IV_SALT]);
        let length_cipher = Aes128Gcm::new_from_slice(&length_key).unwrap();

        let payload_key = kdf16(&response_key, &[RESPONSE_HEADER_KEY_SALT]);
        let payload_iv = kdf12(&response_iv, &[RESPONSE_HEADER_IV_SALT]);
        let payload_cipher = Aes128Gcm::new_from_slice(&payload_key).unwrap();

        let mut wire = Vec::new();
        wire.extend_from_slice(
            &length_cipher
                .encrypt(&length_iv, &(payload.len() as u16).to_be_bytes(), &[])
                .unwrap(),
        );
        wire.extend_from_slice(&payload_cipher.encrypt(&payload_iv, &payload, &[]).unwrap());
        wire.extend_from_slice(&[0x00, 0x0b]);

        let mut reader = std::io::Cursor::new(wire.clone());
        outbound
            .read_response_header(&mut reader, &response_key, &response_iv, echoed, None)
            .expect("the header parses");
        assert_eq!(reader.position() as usize, 18 + payload.len() + 16);

        let mut mismatched = std::io::Cursor::new(wire);
        assert!(outbound
            .read_response_header(
                &mut mismatched,
                &response_key,
                &response_iv,
                echoed ^ 0xff,
                None
            )
            .is_err());
    }

    /// The full server-side open of a sealed request: decode the AuthID (AES
    /// block decrypt, then the CRC-32 and timestamp checks the reference
    /// AuthID holder performs), open the length block and the header, and walk
    /// the decoded fields down to the FNV-1a trailer. Passing this is what
    /// makes the request byte-compatible with a live v2ray/xray server.
    #[test]
    fn a_reference_server_decodes_the_sealed_request() {
        let outbound = create_test_outbound("aes-128-gcm");
        let target = TargetAddr::Domain("www.youtube.com".to_string(), 443);

        let mut wire = std::io::Cursor::new(Vec::new());
        let (request_key, request_iv, response_header_byte) = outbound
            .handshake(&mut wire, &target, VmessCommand::Tcp)
            .expect("the header seals");
        let sealed = wire.into_inner();

        // AuthID: one AES block decrypt with the command key.
        let auth_id: [u8; 16] = sealed[..16].try_into().unwrap();
        let auth_block = Aes::new(&kdf16(&outbound.cmd_key, &[AUTH_ID_ENCRYPTION_SALT])).unwrap();
        let mut decoded = auth_id;
        auth_block.decrypt_block(&mut decoded);
        let timestamp = i64::from_be_bytes(decoded[..8].try_into().unwrap());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(
            (now - timestamp).abs() <= 120,
            "the AuthID timestamp must be inside the two-minute window"
        );
        assert_eq!(
            u32::from_be_bytes(decoded[12..].try_into().unwrap()),
            crc32_ieee(&decoded[..12]),
            "the AuthID CRC-32 has to cover timestamp and random bytes"
        );

        // The connection nonce sits between the length block and the payload.
        let nonce: [u8; 8] = sealed[34..42].try_into().unwrap();

        let length_key = kdf16(
            &outbound.cmd_key,
            &[HEADER_LENGTH_KEY_SALT, &auth_id, &nonce],
        );
        let length_nonce = kdf12(
            &outbound.cmd_key,
            &[HEADER_LENGTH_NONCE_SALT, &auth_id, &nonce],
        );
        let length_cipher = Aes128Gcm::new_from_slice(&length_key).unwrap();
        let length_plain = length_cipher
            .decrypt(&length_nonce, &sealed[16..34], &auth_id)
            .expect("the length opens with the AuthID as AAD");
        let length = u16::from_be_bytes([length_plain[0], length_plain[1]]) as usize;

        let header_key = kdf16(&outbound.cmd_key, &[HEADER_KEY_SALT, &auth_id, &nonce]);
        let header_nonce = kdf12(&outbound.cmd_key, &[HEADER_NONCE_SALT, &auth_id, &nonce]);
        let header_cipher = Aes128Gcm::new_from_slice(&header_key).unwrap();
        let payload = &sealed[42..42 + length + VMESS_AEAD_AUTH_LEN];
        assert_eq!(sealed.len(), 42 + length + VMESS_AEAD_AUTH_LEN);
        let plain = header_cipher
            .decrypt(&header_nonce, payload, &auth_id)
            .expect("the header opens");

        // Field walk: version | IV | key | response byte | option |
        // padding<<4|security | reserved | command | port | atyp | address.
        assert_eq!(plain[0], VMESS_VERSION);
        assert_eq!(&plain[1..17], &request_iv);
        assert_eq!(&plain[17..33], &request_key);
        assert_eq!(plain[33], response_header_byte);
        assert_eq!(plain[34] & VmessOption::CHUNK_STREAM.bits(), 0x01);
        assert_eq!(plain[35] & 0x0f, VmessCipher::Aes128Gcm.as_byte());
        assert_eq!(plain[36], 0x00);
        assert_eq!(plain[37], VmessCommand::Tcp as u8);
        assert_eq!(u16::from_be_bytes([plain[38], plain[39]]), 443);
        assert_eq!(plain[40], VmessAddressType::Domain as u8);
        let domain_len = plain[41] as usize;
        assert_eq!(&plain[42..42 + domain_len], b"www.youtube.com");

        // Padding is random but counted in the high nibble; the FNV-1a
        // trailer covers everything before it.
        let padding = (plain[35] >> 4) as usize;
        assert_eq!(plain.len(), 42 + domain_len + padding + 4);
        let trailer = fnv1a_hash(&plain[..plain.len() - 4]).to_be_bytes();
        assert_eq!(&plain[plain.len() - 4..], &trailer);
    }

    /// Every response chunk consumes one nonce slot, and a fresh session
    /// starts at zero. This is the multi-chunk framing of a UDP or TCP
    /// response; reading a later chunk with an earlier nonce fails the GCM
    /// open, which is why the counter has to advance per read.
    #[test]
    fn response_chunks_consume_incrementing_nonces() {
        let outbound = create_test_outbound("aes-128-gcm");
        let key = [0x33u8; 16];
        let iv = [0x44u8; 16];

        let mut wire = Vec::new();
        wire.extend_from_slice(
            &encrypt_chunk_static(VmessCipher::Aes128Gcm, b"first", &key, &iv, 0).unwrap(),
        );
        wire.extend_from_slice(
            &encrypt_chunk_static(VmessCipher::Aes128Gcm, b"second", &key, &iv, 1).unwrap(),
        );

        let deadline = Instant::now() + Duration::from_secs(1);
        let mut cursor = std::io::Cursor::new(wire);
        let first = outbound
            .read_response_chunk(&mut cursor, &key, &iv, 0, deadline)
            .expect("the first chunk opens with nonce zero");
        assert_eq!(first, b"first");
        let second = outbound
            .read_response_chunk(&mut cursor, &key, &iv, 1, deadline)
            .expect("the second chunk opens with the next nonce");
        assert_eq!(second, b"second");
    }

    /// `shutdown(Write)` must emit the AEAD end-of-stream chunk and not a bare
    /// `[0x00,0x00]`: the reference reader forwards the latter to its AEAD
    /// open, where authentication fails and a clean close turns into a
    /// protocol error.
    #[test]
    fn write_shutdown_emits_the_aead_end_chunk() {
        use crate::common::stream::SyncStream;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(addr).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let enc_key = [0x11u8; 16];
        let enc_iv = [0x22u8; 16];
        let dec_key = [0x33u8; 16];
        let dec_iv = [0x44u8; 16];

        let mut stream = VmessStream::new(
            Box::new(client) as BoxStream,
            VmessCipher::Aes128Gcm,
            enc_key,
            enc_iv,
            dec_key,
            dec_iv,
            0x00,
        );

        stream.write_all(b"hello").unwrap();
        stream
            .shutdown(std::net::Shutdown::Write)
            .expect("shutdown forwards to the transport");
        // A second shutdown must not emit another end chunk.
        stream.shutdown(std::net::Shutdown::Write).unwrap();

        let mut received = Vec::new();
        let mut buf = [0u8; 256];
        while let Ok(n) = server.read(&mut buf) {
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }

        let data_chunk =
            encrypt_chunk_static(VmessCipher::Aes128Gcm, b"hello", &enc_key, &enc_iv, 0).unwrap();
        assert_eq!(&received[..data_chunk.len()], &data_chunk[..]);

        let end_chunk = &received[data_chunk.len()..];
        assert_eq!(end_chunk.len(), 2 + 16, "end chunk is [length][tag]");
        assert_eq!(&end_chunk[..2], &[0x00, 0x10]);
        let opened = decrypt_chunk_static(
            VmessCipher::Aes128Gcm,
            &end_chunk[2..],
            &enc_key,
            &enc_iv,
            1,
        )
        .expect("the end chunk opens with the next nonce");
        assert!(opened.is_empty());
    }

    /// The downlink has to consume the response header itself, on its first
    /// read: the reference server only flushes the header together with the
    /// first target payload, so a client that waits for it before forwarding
    /// the request deadlocks — the target never answers a request that is
    /// still parked in the client. And because the relay arms a 25 ms socket
    /// timeout, the framing reader must resume cleanly when a poll expires in
    /// the middle of a frame instead of dropping what it already consumed.
    #[test]
    fn downlink_reads_lazily_and_resumes_split_frames() {
        use crate::common::stream::SyncStream;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(addr).unwrap();
        let (mut server, _) = listener.accept().unwrap();

        let enc_key = [0x51u8; 16];
        let enc_iv = [0x62u8; 16];
        let dec_key = [0x73u8; 16];
        let dec_iv = [0x84u8; 16];
        let echoed = 0x5au8;

        let header_plain = [echoed, 0x01, 0x00, 0x00];
        let length_key = kdf16(&dec_key, &[RESPONSE_LENGTH_KEY_SALT]);
        let length_iv = kdf12(&dec_iv, &[RESPONSE_LENGTH_IV_SALT]);
        let header_key = kdf16(&dec_key, &[RESPONSE_HEADER_KEY_SALT]);
        let header_iv = kdf12(&dec_iv, &[RESPONSE_HEADER_IV_SALT]);
        let length_cipher = Aes128Gcm::new_from_slice(&length_key).unwrap();
        let header_cipher = Aes128Gcm::new_from_slice(&header_key).unwrap();

        let mut wire = Vec::new();
        wire.extend_from_slice(
            &length_cipher
                .encrypt(&length_iv, &(header_plain.len() as u16).to_be_bytes(), &[])
                .unwrap(),
        );
        wire.extend_from_slice(
            &header_cipher
                .encrypt(&header_iv, &header_plain, &[])
                .unwrap(),
        );
        let data_chunk =
            encrypt_chunk_static(VmessCipher::Aes128Gcm, b"hello", &dec_key, &dec_iv, 0).unwrap();
        let end_chunk =
            encrypt_chunk_static(VmessCipher::Aes128Gcm, &[], &dec_key, &dec_iv, 1).unwrap();

        let writer = std::thread::spawn(move || {
            // Split the header block itself so at least one read poll expires
            // with a half-filled frame in flight.
            let (first, second) = wire.split_at(9);
            server.write_all(first).unwrap();
            server.flush().unwrap();
            std::thread::sleep(Duration::from_millis(60));
            server.write_all(second).unwrap();
            server.flush().unwrap();
            std::thread::sleep(Duration::from_millis(60));
            server.write_all(&data_chunk).unwrap();
            server.flush().unwrap();
            std::thread::sleep(Duration::from_millis(60));
            server.write_all(&end_chunk).unwrap();
            server.flush().unwrap();
            // Hold the socket open until the client has drained everything.
            std::thread::sleep(Duration::from_millis(200));
        });

        let mut stream = VmessStream::new(
            Box::new(client) as BoxStream,
            VmessCipher::Aes128Gcm,
            enc_key,
            enc_iv,
            dec_key,
            dec_iv,
            echoed,
        );
        stream
            .set_read_timeout(Some(Duration::from_millis(25)))
            .unwrap();

        let mut collected = Vec::new();
        let mut eof = false;
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let mut buf = [0u8; 5];
            match stream.read(&mut buf) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(n) => collected.extend_from_slice(&buf[..n]),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(e) => panic!("downlink read failed: {e}"),
            }
        }
        assert_eq!(collected, b"hello");
        assert!(eof, "the encrypted end-of-stream chunk must surface as EOF");
        writer.join().unwrap();
    }

    /// The reference key schedule for ChaCha20-Poly1305 body chunks:
    /// `MD5(b) ‖ MD5(MD5(b))`, pinned against an independent MD5
    /// implementation (Windows CNG) for `b = 0x00..0x0f`.
    #[test]
    fn chacha20_key_matches_the_reference_derivation() {
        let body = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let key = chacha20_poly1305_key(&body);
        let hex = |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
        assert_eq!(hex(&key[..16]), "1ac1ef01e96caf1be0d329331a4fc2a8");
        assert_eq!(hex(&key[16..]), "e0542db5418c43d256a6a643afa553fe");
    }
}
