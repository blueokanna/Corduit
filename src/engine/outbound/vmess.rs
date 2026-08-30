use crate::common::stream::BoxStream;
use crate::crypto::aead::{Aead, Aes128Gcm, ChaCha20Poly1305};
use crate::crypto::digest::Digest;
use crate::crypto::encoding::{encode as b64_encode, Config as B64Config};
use crate::crypto::hash::{Md5, Sha1, Sha256};
use crate::crypto::uuid::Uuid;
use crate::engine::config::OutboundConfig;
use crate::engine::connection_tracker::TrackedConnection;
use crate::engine::error::{Error, Result};
use crate::engine::outbound::{OutboundProxy, TargetAddr};
use dashmap::DashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const VMESS_VERSION: u8 = 1;
const VMESS_AEAD_AUTH_LEN: usize = 16;
const VMESS_AEAD_NONCE_LEN: usize = 12;

#[allow(dead_code)]
const VMESS_AEAD_KEY_LEN: usize = 16;

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

    pub fn as_byte(self) -> u8 {
        match self {
            VmessCipher::Aes128Gcm => 0x03,
            VmessCipher::Chacha20Poly1305 => 0x04,
            VmessCipher::None => 0x02,
            VmessCipher::Zero => 0x05,
            VmessCipher::Auto => 0x03,
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
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "ws" | "websocket" => VmessTransport::Ws,
            "h2" | "http2" => VmessTransport::H2,
            "grpc" => VmessTransport::Grpc,
            "quic" => VmessTransport::Tcp,
            _ => VmessTransport::Tcp,
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
    last_used: std::sync::RwLock<Instant>,
}

impl VmessUdpSession {
    fn new(
        stream: BoxStream,
        request_key: [u8; 16],
        request_iv: [u8; 16],
        response_key: [u8; 16],
        response_iv: [u8; 16],
    ) -> Self {
        Self {
            stream: parking_lot::Mutex::new(stream),
            request_key,
            request_iv,
            response_key,
            response_iv,
            chunk_count: AtomicU64::new(0),
            last_used: std::sync::RwLock::new(Instant::now()),
        }
    }

    fn next_chunk_count(&self) -> u16 {
        (self.chunk_count.fetch_add(1, Ordering::SeqCst) % 65536) as u16
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

pub struct WebSocketStream<S: crate::common::stream::SyncStream> {
    inner: parking_lot::Mutex<S>,
    read_buffer: Vec<u8>,
    read_pos: usize,
}

/// Largest WebSocket payload `read_frame` will accept. The length field is a
/// 64-bit integer straight from the wire, so without a cap a malicious peer
/// could request a multi-gigabyte allocation and abort the process.
const MAX_WS_FRAME_SIZE: u64 = 16 * 1024 * 1024; // 16 MiB

impl<S: crate::common::stream::SyncStream> WebSocketStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner: parking_lot::Mutex::new(inner),
            read_buffer: Vec::new(),
            read_pos: 0,
        }
    }
}

impl<S: crate::common::stream::SyncStream> WebSocketStream<S> {
    /// Perform WebSocket handshake
    pub fn handshake(
        stream: S,
        host: &str,
        path: &str,
        extra_headers: &std::collections::HashMap<String, String>,
    ) -> Result<Self> {
        let ws = Self::new(stream);

        let mut key_bytes = [0u8; 16];
        getrandom::fill(&mut key_bytes)
            .map_err(|e| Error::protocol(format!("Failed to generate WebSocket key: {}", e)))?;
        let ws_key = b64_encode(&key_bytes, B64Config::STANDARD);
        let mut request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n",
            path, host, ws_key
        );

        // Add extra headers
        for (key, value) in extra_headers {
            if key.to_lowercase() != "host" {
                request.push_str(&format!("{}: {}\r\n", key, value));
            }
        }
        request.push_str("\r\n");
        ws.inner
            .lock()
            .write_all(request.as_bytes())
            .map_err(|e| Error::network(format!("Failed to send WebSocket handshake: {}", e)))?;
        ws.inner.lock().flush().ok();

        let mut response = Vec::with_capacity(1024);
        let mut buf = [0u8; 1];
        let mut found_end = false;

        while response.len() < 4096 {
            ws.inner
                .lock()
                .read_exact(&mut buf)
                .map_err(|e| Error::network(format!("Failed to read WebSocket response: {}", e)))?;
            response.push(buf[0]);

            // Check for \r\n\r\n
            if response.len() >= 4 && &response[response.len() - 4..] == b"\r\n\r\n" {
                found_end = true;
                break;
            }
        }

        if !found_end {
            return Err(Error::protocol(
                "WebSocket handshake response too long or incomplete",
            ));
        }

        let response_str = String::from_utf8_lossy(&response);

        // Verify response status
        if !response_str.starts_with("HTTP/1.1 101") {
            return Err(Error::protocol(format!(
                "WebSocket handshake failed: {}",
                response_str.lines().next().unwrap_or("unknown")
            )));
        }

        // Verify Sec-WebSocket-Accept
        let expected_accept = compute_websocket_accept(&ws_key);
        let accept_found = response_str.lines().any(|line| {
            let lower = line.to_lowercase();
            if lower.starts_with("sec-websocket-accept:") {
                let value = line.split(':').nth(1).map(|s| s.trim()).unwrap_or("");
                value == expected_accept
            } else {
                false
            }
        });

        if !accept_found {
            tracing::warn!(
                "WebSocket Sec-WebSocket-Accept header mismatch or missing, continuing anyway"
            );
        }

        tracing::debug!("WebSocket handshake completed successfully");
        Ok(ws)
    }

    #[allow(dead_code)]
    pub fn write_frame(&self, data: &[u8]) -> std::io::Result<()> {
        let mut frame = Vec::with_capacity(14 + data.len());

        frame.push(0x82);
        let len = data.len();
        if len < 126 {
            frame.push(0x80 | len as u8);
        } else if len < 65536 {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }

        let mut mask = [0u8; 4];
        getrandom::fill(&mut mask)
            .map_err(|e| std::io::Error::other(format!("Failed to generate mask: {}", e)))?;
        frame.extend_from_slice(&mask);

        // Masked payload
        for (i, byte) in data.iter().enumerate() {
            frame.push(byte ^ mask[i % 4]);
        }

        self.inner
            .lock()
            .write_all(&frame)
            .map_err(|e| Error::network(format!("Failed to write WebSocket frame: {}", e)))
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    /// Read a WebSocket frame, returns the payload data
    #[allow(dead_code)]
    pub fn read_frame(&self) -> std::io::Result<Vec<u8>> {
        let mut inner = self.inner.lock();

        // Read first 2 bytes
        let mut header = [0u8; 2];
        inner.read_exact(&mut header)?;

        let _fin = (header[0] & 0x80) != 0;
        let opcode = header[0] & 0x0F;
        let masked = (header[1] & 0x80) != 0;
        let mut payload_len = (header[1] & 0x7F) as u64;

        if opcode == 0x08 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "WebSocket connection closed by server",
            ));
        }

        // Handle ping frame - read payload and continue (non-recursive)
        if opcode == 0x09 {
            if payload_len > MAX_WS_FRAME_SIZE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "WebSocket ping frame too large",
                ));
            }
            if payload_len > 0 {
                let mut ping_data = vec![0u8; payload_len as usize];
                inner.read_exact(&mut ping_data).ok();
            }
            // Return empty to signal caller should retry
            return Ok(Vec::new());
        }

        // Extended payload length
        if payload_len == 126 {
            let mut ext = [0u8; 2];
            inner.read_exact(&mut ext)?;
            payload_len = u16::from_be_bytes(ext) as u64;
        } else if payload_len == 127 {
            let mut ext = [0u8; 8];
            inner.read_exact(&mut ext)?;
            payload_len = u64::from_be_bytes(ext);
        }

        // Reject oversized frames before allocating any buffer.
        if payload_len > MAX_WS_FRAME_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("WebSocket frame too large: {} bytes", payload_len),
            ));
        }

        let mask = if masked {
            let mut m = [0u8; 4];
            inner.read_exact(&mut m)?;
            Some(m)
        } else {
            None
        };

        // Read payload
        let mut payload = vec![0u8; payload_len as usize];
        inner.read_exact(&mut payload)?;

        // Unmask if needed
        if let Some(m) = mask {
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= m[i % 4];
            }
        }

        Ok(payload)
    }

    /// Read frame with retry for control frames
    #[allow(dead_code)]
    pub fn read_frame_data(&self) -> std::io::Result<Vec<u8>> {
        loop {
            let data = self.read_frame()?;
            if !data.is_empty() {
                return Ok(data);
            }
        }
    }
}

fn compute_websocket_accept(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let result = hasher.finalize();
    b64_encode(&result, B64Config::STANDARD)
}

impl<S: crate::common::stream::SyncStream> Read for WebSocketStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            // Serve buffered frame payload first.
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
            // Pull the next non-empty frame (pings yield empty payloads and
            // are skipped). Errors (including read timeouts) propagate with
            // their io kind so the relay treats idle as "nothing happened".
            let data = self.read_frame()?;
            if !data.is_empty() {
                self.read_buffer = data;
                self.read_pos = 0;
            }
        }
    }
}

impl<S: crate::common::stream::SyncStream> Write for WebSocketStream<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Build and send one masked binary frame.
        let mut frame = Vec::with_capacity(14 + buf.len());
        frame.push(0x82);

        let len = buf.len();
        if len < 126 {
            frame.push(0x80 | len as u8);
        } else if len < 65536 {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }

        let mask: [u8; 4] = crate::engine::random::bytes();
        frame.extend_from_slice(&mask);

        for (i, byte) in buf.iter().enumerate() {
            frame.push(byte ^ mask[i % 4]);
        }

        self.inner.lock().write_all(&frame)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.lock().flush()
    }
}

impl<S: crate::common::stream::SyncStream> crate::common::stream::SyncStream
    for WebSocketStream<S>
{
    fn shutdown(&self, how: std::net::Shutdown) -> std::io::Result<()> {
        self.inner.lock().shutdown(how)
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

pub struct VmessOutbound {
    config: OutboundConfig,
    server: String,
    port: u16,
    #[allow(dead_code)]
    uuid: Uuid,
    uuid_bytes: [u8; 16],
    #[allow(dead_code)]
    alter_id: u16,
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

pub struct VmessResponseHeader {
    pub response_header: u8,
    pub option: u8,
    pub command: u8,
    pub command_length: u8,
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
            .unwrap_or(0) as u16;

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
        let transport = VmessTransport::from_str(transport_str);

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
            .get("quic-opts")
            .and_then(|v| v.get("alpn"))
            .and_then(|v| v.as_array())
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let cmd_key = generate_cmd_key(&uuid_bytes);

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
            uuid,
            uuid_bytes,
            alter_id,
            cipher,
            udp_enabled,
            cmd_key,
            transport,
            tls_enabled,
            skip_cert_verify,
            sni,
            ws_opts,
            alpn,
            udp_sessions: DashMap::new(),
        })
    }

    pub fn generate_auth_id(&self, timestamp: i64) -> [u8; 16] {
        let mut hasher = Md5::new();
        hasher.update(&self.uuid_bytes);
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.finalize()
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
            &[b"VMess Header AEAD Key", &auth_id, &connection_nonce],
        );
        let header_nonce = kdf12(
            &self.cmd_key,
            &[b"VMess Header AEAD Nonce", &auth_id, &connection_nonce],
        );

        let cipher = Aes128Gcm::new_from_slice(&header_key)
            .map_err(|e| Error::protocol(format!("Failed to create AES-GCM cipher: {}", e)))?;

        let encrypted_header = cipher
            .encrypt(&header_nonce, header_buf.as_ref(), &[])
            .map_err(|e| Error::protocol(format!("Failed to encrypt header: {:?}", e)))?;

        let header_length_key = kdf16(
            &self.cmd_key,
            &[b"VMess Header AEAD Key Length", &auth_id, &connection_nonce],
        );
        let header_length_nonce = kdf12(
            &self.cmd_key,
            &[
                b"VMess Header AEAD Nonce Length",
                &auth_id,
                &connection_nonce,
            ],
        );

        let length_cipher = Aes128Gcm::new_from_slice(&header_length_key)
            .map_err(|e| Error::protocol(format!("Failed to create length cipher: {}", e)))?;

        let length_bytes = (encrypted_header.len() as u16).to_be_bytes();
        let encrypted_length = length_cipher
            .encrypt(&header_length_nonce, length_bytes.as_ref(), &[])
            .map_err(|e| Error::protocol(format!("Failed to encrypt length: {:?}", e)))?;

        let mut result =
            Vec::with_capacity(16 + 8 + encrypted_length.len() + encrypted_header.len());
        result.extend_from_slice(&auth_id);
        result.extend_from_slice(&encrypted_length);
        result.extend_from_slice(&connection_nonce);
        result.extend_from_slice(&encrypted_header);

        Ok(result)
    }

    pub fn open_response_header(
        &self,
        data: &[u8],
        response_key: &[u8; 16],
        response_iv: &[u8; 16],
    ) -> Result<VmessResponseHeader> {
        if data.len() < 4 + VMESS_AEAD_AUTH_LEN {
            return Err(Error::protocol("Response header too short"));
        }

        let cipher = Aes128Gcm::new_from_slice(response_key)
            .map_err(|e| Error::protocol(format!("Failed to create response cipher: {}", e)))?;

        let decrypted = cipher
            .decrypt(&response_iv[..VMESS_AEAD_NONCE_LEN], data, &[])
            .map_err(|e| Error::protocol(format!("Failed to decrypt response header: {:?}", e)))?;

        if decrypted.len() < 4 {
            return Err(Error::protocol("Decrypted response header too short"));
        }

        Ok(VmessResponseHeader {
            response_header: decrypted[0],
            option: decrypted[1],
            command: decrypted[2],
            command_length: decrypted[3],
        })
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
        let connector = self.create_tls_connector()?;
        connector
            .connect(tcp_stream, &sni)
            .map_err(|e| Error::network(format!("TLS handshake failed: {}", e)))
    }

    /// Build the courierust TLS connector from the VMess options.
    fn create_tls_connector(&self) -> Result<crate::engine::tls::TlsConnector> {
        let mut alpn = self.alpn.clone();
        if alpn.is_empty() {
            // VMess-over-TLS/WS speaks h2 / http1.1 by default.
            alpn = vec!["h2".into(), "http/1.1".into()];
        }
        let config = crate::engine::tls::ClientConfig {
            server_name: self.sni.clone(),
            alpn,
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
                let path = &ws_opts.path;

                if self.tls_enabled {
                    let tls_stream = self.connect_tls()?;
                    let ws_stream =
                        WebSocketStream::handshake(tls_stream, host, path, &ws_opts.headers)?;
                    Ok(Box::new(ws_stream) as BoxStream)
                } else {
                    let tcp_stream = self.connect_tcp()?;
                    let ws_stream =
                        WebSocketStream::handshake(tcp_stream, host, path, &ws_opts.headers)?;
                    Ok(Box::new(ws_stream) as BoxStream)
                }
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
            option: VmessOption::CHUNK_STREAM
                | VmessOption::CHUNK_MASKING
                | VmessOption::GLOBAL_PADDING
                | VmessOption::AUTHENTICATED_LENGTH,
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

        // Check for existing session
        if let Some(session) = self.udp_sessions.get(&session_key) {
            let session = session.clone();
            if !session.is_expired(Duration::from_secs(60)) {
                session.touch();
                return Ok(session);
            }
            // Session expired, remove it
            self.udp_sessions.remove(&session_key);
        }

        // Create new session
        let mut stream = self.connect_stream()?;
        let (request_key, request_iv, _response_header) =
            self.handshake(&mut *stream, target, VmessCommand::Udp)?;

        let response_key = self.generate_response_key(&request_key);
        let response_iv = self.generate_response_iv(&request_iv);

        let session = Arc::new(VmessUdpSession::new(
            stream,
            request_key,
            request_iv,
            response_key,
            response_iv,
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

        // Get or create a session for this target
        let session = self.get_or_create_udp_session(target)?;

        // Get chunk count and keys
        let chunk_count = session.next_chunk_count();
        let request_key = session.request_key;
        let request_iv = session.request_iv;
        let response_key = session.response_key;
        let response_iv = session.response_iv;
        let target_str = target.to_string();

        // Lock stream for write
        let mut stream_guard = session.stream.lock();

        // Encrypt and send data
        let encrypted_data = self.encrypt_chunk(data, &request_key, &request_iv, chunk_count)?;
        if let Err(e) = stream_guard.write_all(&encrypted_data) {
            // Session might be broken, remove it
            drop(stream_guard);
            self.udp_sessions.remove(&target_str);
            return Err(Error::network(format!("Failed to send UDP data: {}", e)));
        }
        stream_guard.flush().ok();
        session.touch();

        // Read response with deadline. The stream read timeout may fire
        // while no data has arrived; retry until the 10s deadline.
        let deadline = Instant::now() + Duration::from_secs(10);
        let response = self
            .read_response_chunk(&mut **stream_guard, &response_key, &response_iv, deadline)
            .map_err(|e| {
                // Read error, remove session
                Error::network(format!("Failed to receive UDP response: {}", e))
            })?;

        Ok(response)
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
        let mut full_key = [0u8; 32];
        full_key[..16].copy_from_slice(key);
        full_key[16..].copy_from_slice(key);

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
        let mut full_key = [0u8; 32];
        full_key[..16].copy_from_slice(key);
        full_key[16..].copy_from_slice(key);

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

    fn read_response_chunk<S: Read + ?Sized>(
        &self,
        stream: &mut S,
        key: &[u8; 16],
        iv: &[u8; 16],
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

        self.decrypt_chunk(&data, key, iv, 0)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
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
        let (request_key, request_iv, _) =
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
        let response = self
            .read_response_chunk(&mut *stream, &response_key, &response_iv, deadline)
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
        let (request_key, request_iv, _response_header) =
            self.handshake(&mut *stream, &target, VmessCommand::Tcp)?;

        let response_key = self.generate_response_key(&request_key);
        let response_iv = self.generate_response_iv(&request_iv);

        tracing::debug!(
            "VMess: relaying TCP to {} via {}:{} (tls={})",
            target,
            self.server,
            self.port,
            self.tls_enabled
        );

        // Wrap the stream with the VMess chunked-encryption codec and let the
        // bidirectional relay drive both directions concurrently.
        let vmess_stream = VmessStream::new(
            stream,
            self.cipher,
            request_key,
            request_iv,
            response_key,
            response_iv,
        );

        relay_streams!(inbound, vmess_stream, connection)
    }
}

/// A `std::io::Read + Write + SyncStream` adapter over the VMess
/// chunked-encryption codec, so the bidirectional relay can drive the
/// upstream stream: writes encrypt each chunk (incrementing the request
/// count), reads decrypt each chunk (incrementing the response count). On
/// write-shutdown the `[0,0]` end-of-stream chunk is emitted once before
/// the underlying transport is half-closed, matching the VMess wire format.
struct VmessStream {
    inner: parking_lot::Mutex<BoxStream>,
    cipher: VmessCipher,
    enc_key: [u8; 16],
    enc_iv: [u8; 16],
    dec_key: [u8; 16],
    dec_iv: [u8; 16],
    enc_count: u16,
    dec_count: u16,
    read_buffer: Vec<u8>,
    read_pos: usize,
    eof: bool,
    end_chunk_sent: AtomicBool,
}

/// Maximum plaintext bytes per VMess chunk (u16 length field on the wire;
/// ciphertext adds a 16-byte tag, so 16 KiB always fits).
const VMESS_CHUNK_MAX: usize = 16 * 1024;

impl VmessStream {
    fn new(
        inner: BoxStream,
        cipher: VmessCipher,
        enc_key: [u8; 16],
        enc_iv: [u8; 16],
        dec_key: [u8; 16],
        dec_iv: [u8; 16],
    ) -> Self {
        Self {
            inner: parking_lot::Mutex::new(inner),
            cipher,
            enc_key,
            enc_iv,
            dec_key,
            dec_iv,
            enc_count: 0,
            dec_count: 0,
            read_buffer: Vec::new(),
            read_pos: 0,
            eof: false,
            end_chunk_sent: AtomicBool::new(false),
        }
    }
}

impl Read for VmessStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            // Serve buffered decrypted data first.
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
            // Read the next chunk: [2-byte length][payload].
            let mut inner = self.inner.lock();
            let mut length_buf = [0u8; 2];
            match inner.read_exact(&mut length_buf) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    self.eof = true;
                    return Ok(0);
                }
                Err(e) => return Err(e),
            }
            let length = u16::from_be_bytes(length_buf) as usize;
            if length == 0 {
                self.eof = true;
                return Ok(0);
            }
            let mut data = vec![0u8; length];
            inner.read_exact(&mut data)?;
            drop(inner);

            let count = self.dec_count;
            let decrypted =
                decrypt_chunk_static(self.cipher, &data, &self.dec_key, &self.dec_iv, count)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
            self.dec_count = self.dec_count.wrapping_add(1);

            self.read_buffer = decrypted;
            self.read_pos = 0;
        }
    }
}

impl Write for VmessStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut inner = self.inner.lock();
        let mut count = self.enc_count;
        for chunk in buf.chunks(VMESS_CHUNK_MAX) {
            let encrypted =
                encrypt_chunk_static(self.cipher, chunk, &self.enc_key, &self.enc_iv, count)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
            inner.write_all(&encrypted)?;
            count = count.wrapping_add(1);
        }
        self.enc_count = count;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.lock().flush()
    }
}

impl crate::common::stream::SyncStream for VmessStream {
    fn shutdown(&self, how: std::net::Shutdown) -> std::io::Result<()> {
        let mut inner = self.inner.lock();
        if matches!(how, std::net::Shutdown::Write | std::net::Shutdown::Both) {
            // Emit the [0,0] end-of-stream chunk exactly once, then FIN.
            if !self.end_chunk_sent.swap(true, Ordering::SeqCst) {
                let end_chunk = [0u8; 2];
                let _ = inner.write_all(&end_chunk);
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

fn generate_connection_nonce() -> [u8; 8] {
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).expect("Failed to generate nonce");
    nonce
}

fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let mut result = [0u8; 16];
    let mut hasher = Sha256::new();
    hasher.update(key);
    for p in path {
        hasher.update(p);
    }
    let hash = hasher.finalize();
    result.copy_from_slice(&hash[..16]);
    result
}

fn kdf12(key: &[u8], path: &[&[u8]]) -> [u8; 12] {
    let mut result = [0u8; 12];
    let mut hasher = Sha256::new();
    hasher.update(key);
    for p in path {
        hasher.update(p);
    }
    let hash = hasher.finalize();
    result.copy_from_slice(&hash[..12]);
    result
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
            let mut full_key = [0u8; 32];
            full_key[..16].copy_from_slice(key);
            full_key[16..].copy_from_slice(key);

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
            let mut full_key = [0u8; 32];
            full_key[..16].copy_from_slice(key);
            full_key[16..].copy_from_slice(key);

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
        assert_eq!(VmessCipher::None.as_byte(), 0x02);
        assert_eq!(VmessCipher::Zero.as_byte(), 0x05);
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

        let auth_id2 = outbound.generate_auth_id(timestamp);
        assert_eq!(auth_id, auth_id2);

        let auth_id3 = outbound.generate_auth_id(timestamp + 1);
        assert_ne!(auth_id, auth_id3);
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
        fn prop_auth_id_deterministic(timestamp in arb_timestamp()) {
            let outbound = create_test_outbound("auto");

            let auth_id1 = outbound.generate_auth_id(timestamp);
            let auth_id2 = outbound.generate_auth_id(timestamp);

            prop_assert_eq!(auth_id1, auth_id2);
            prop_assert_eq!(auth_id1.len(), 16);
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
}
