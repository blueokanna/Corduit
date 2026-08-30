use crate::common::stream::BoxStream;
use crate::crypto::aead::{Aead, Aes128Gcm, Aes256Gcm, ChaCha20Poly1305};
use crate::crypto::digest::Digest;
use crate::crypto::encoding::{decode as b64_decode, Config as B64Config};
use crate::crypto::hash::{Blake3, Md5, Sha1};
use crate::crypto::kdf::Hkdf;
use crate::engine::config::OutboundConfig;
use crate::engine::error::{Error, Result};
use crate::engine::outbound::{OutboundProxy, TargetAddr};
use crate::engine::tls::yaml_value_to_string;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// Shadowsocks outbound proxy
pub struct ShadowsocksOutbound {
    config: OutboundConfig,
    server: String,
    port: u16,
    password: String,
    cipher: String,
    udp_enabled: bool,
}

impl OutboundProxy for ShadowsocksOutbound {
    fn connect(&self) -> Result<()> {
        // Test connection to Shadowsocks server (DNS resolution happens here)
        let _stream =
            crate::common::socket::connect_host(&self.server, self.port, Duration::from_secs(30))
                .map_err(|e| {
                Error::network(format!(
                    "Failed to connect to Shadowsocks server {}:{}: {}",
                    self.server, self.port, e
                ))
            })?;
        tracing::info!(
            "Shadowsocks outbound '{}' connected to {}:{}",
            self.config.tag,
            self.server,
            self.port
        );
        Ok(())
    }

    fn disconnect(&self) -> Result<()> {
        // Shadowsocks doesn't maintain persistent connections in this impl
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
                "UDP relay is not enabled for this Shadowsocks proxy",
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

        // Parse the test URL to get host and port
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

        let cipher_spec = CipherSpec::new(&self.cipher)?;

        let server_addr = format!("{}:{}", self.server, self.port);
        tracing::debug!("SS latency test: resolving {}", server_addr);

        // Connect to the Shadowsocks server
        let mut stream = crate::common::socket::connect_host(&self.server, self.port, timeout)
            .map_err(|e| Error::network(format!("Failed to connect: {}", e)))?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| Error::network(format!("set read timeout: {}", e)))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|e| Error::network(format!("set write timeout: {}", e)))?;

        // Disable Nagle's algorithm for lower latency
        stream.set_nodelay(true).ok();

        tracing::debug!(
            "SS latency test: connected, setting up cipher {}",
            self.cipher
        );

        // Generate client salt for sending
        let mut client_salt = vec![0u8; cipher_spec.salt_len];
        getrandom::fill(&mut client_salt)
            .map_err(|e| Error::network(format!("Failed to generate salt: {}", e)))?;

        // Derive encryption key from client salt
        let enc_subkey = derive_subkey_for_cipher(&self.password, &client_salt, &cipher_spec)?;
        let mut enc = AeadCipher::new(cipher_spec, enc_subkey);

        // Build address header
        let target = crate::engine::outbound::TargetAddr::Domain(host.clone(), url_port);
        let addr_header = self.build_address_header(&target)?;

        // Build HTTP request
        let http_request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: Corduit/1.0\r\n\r\n",
            path, host
        );

        // Combine address header and HTTP request into one payload
        let mut first_payload = addr_header;
        first_payload.extend_from_slice(http_request.as_bytes());

        // Encrypt the combined payload
        let len = first_payload.len();
        let len_bytes = (len as u16).to_be_bytes();
        let enc_len = enc.encrypt(&len_bytes)?;
        let enc_data = enc.encrypt(&first_payload)?;

        // Send client_salt + encrypted length + encrypted data in one write
        let mut send_buf = Vec::with_capacity(client_salt.len() + enc_len.len() + enc_data.len());
        send_buf.extend_from_slice(&client_salt);
        send_buf.extend_from_slice(&enc_len);
        send_buf.extend_from_slice(&enc_data);

        tracing::debug!("SS latency test: sending {} bytes", send_buf.len());

        stream
            .write_all(&send_buf)
            .map_err(|e| Error::network(format!("Failed to send request: {}", e)))?;
        stream
            .flush()
            .map_err(|e| Error::network(format!("Flush failed: {}", e)))?;

        tracing::debug!("SS latency test: waiting for response");

        // Read the server's salt (server uses its own salt for responses)
        let mut server_salt = vec![0u8; cipher_spec.salt_len];
        let salt_result = stream.read_exact(&mut server_salt);
        match salt_result {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(Error::network(
                    "Server closed connection (check password/cipher)",
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                return Err(Error::network("Response timeout"));
            }
            Err(e) => {
                return Err(Error::network(format!("Failed to read server salt: {}", e)));
            }
        }

        tracing::debug!("SS latency test: received server salt");

        // Derive decryption key from server's salt
        let dec_subkey = derive_subkey_for_cipher(&self.password, &server_salt, &cipher_spec)?;
        let mut dec = AeadCipher::new(cipher_spec, dec_subkey);

        // Now read and decrypt the response
        match recv_decrypted_chunk(&mut stream, &mut dec)? {
            Some(chunk) => {
                let response = String::from_utf8_lossy(&chunk);
                tracing::debug!(
                    "SS latency test: got response: {}",
                    &response[..response.len().min(100)]
                );
                if response.starts_with("HTTP/") {
                    let elapsed = start.elapsed();
                    tracing::info!("SS latency test success: {}ms", elapsed.as_millis());
                    Ok(elapsed)
                } else {
                    Err(Error::network(format!(
                        "Invalid HTTP response: {}",
                        &response[..response.len().min(50)]
                    )))
                }
            }
            None => Err(Error::network("No response received")),
        }
    }

    fn relay_tcp(&self, inbound: BoxStream, target: TargetAddr) -> Result<()> {
        self.relay_tcp_with_connection(inbound, target, None)
    }

    fn relay_tcp_with_connection(
        &self,
        inbound: BoxStream,
        target: TargetAddr,
        connection: Option<std::sync::Arc<crate::engine::connection_tracker::TrackedConnection>>,
    ) -> Result<()> {
        let cipher_spec = CipherSpec::new(&self.cipher)?;

        let mut outbound =
            crate::common::socket::connect_host(&self.server, self.port, Duration::from_secs(30))
                .map_err(|e| {
                Error::network(format!(
                    "Failed to connect to SS server {}:{}: {}",
                    self.server, self.port, e
                ))
            })?;
        outbound
            .set_read_timeout(Some(Duration::from_secs(60)))
            .map_err(|e| Error::network(format!("set read timeout: {}", e)))?;
        outbound
            .set_write_timeout(Some(Duration::from_secs(60)))
            .map_err(|e| Error::network(format!("set write timeout: {}", e)))?;

        // Disable Nagle's algorithm for lower latency
        outbound.set_nodelay(true).ok();

        tracing::debug!(
            "Shadowsocks: connected to {}:{} for target {}",
            self.server,
            self.port,
            target
        );

        // Generate client salt for sending
        let mut client_salt = vec![0u8; cipher_spec.salt_len];
        getrandom::fill(&mut client_salt)
            .map_err(|e| Error::network(format!("Failed to generate salt: {}", e)))?;

        // Derive encryption key from client salt
        let enc_subkey = derive_subkey_for_cipher(&self.password, &client_salt, &cipher_spec)?;
        let mut enc = AeadCipher::new(cipher_spec, enc_subkey);

        // Send client salt first
        outbound
            .write_all(&client_salt)
            .map_err(|e| Error::network(format!("Failed to send SS salt: {}", e)))?;

        let addr_header = self.build_address_header(&target)?;
        send_encrypted_chunk(&mut outbound, &mut enc, &addr_header)?;

        // Wrap the socket with the Shadowsocks chunked-encryption codec and
        // let the bidirectional relay drive both directions concurrently.
        let ss_stream = ShadowsocksStream::new(outbound, enc, cipher_spec, self.password.clone());

        relay_streams!(inbound, ss_stream, connection)
    }
}

impl ShadowsocksOutbound {
    pub fn new(config: OutboundConfig) -> Result<Self> {
        let server = config
            .server
            .as_ref()
            .ok_or_else(|| Error::config("Missing server address for Shadowsocks"))?
            .clone();

        let port = config
            .port
            .ok_or_else(|| Error::config("Missing port for Shadowsocks"))?;

        // Get password from options - handle different YAML value types
        let password = config
            .options
            .get("password")
            .map(yaml_value_to_string)
            .unwrap_or_default();

        // Get cipher/method from options - Clash configs use both "cipher" and "method"
        let cipher = config
            .options
            .get("cipher")
            .or_else(|| config.options.get("method"))
            .map(yaml_value_to_string)
            .unwrap_or_else(|| "aes-256-gcm".to_string());

        // Get UDP option - default to true to support QUIC and other UDP protocols
        let udp_enabled = config
            .options
            .get("udp")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        tracing::debug!(
            "Creating SS outbound: server={}, port={}, cipher={}, password_len={}, udp={}",
            server,
            port,
            cipher,
            password.len(),
            udp_enabled
        );

        if password.is_empty() {
            return Err(Error::config("Missing password for Shadowsocks"));
        }

        Ok(Self {
            config,
            server,
            port,
            password,
            cipher,
            udp_enabled,
        })
    }

    /// Build SOCKS5-style address header for Shadowsocks
    fn build_address_header(&self, target: &TargetAddr) -> Result<Vec<u8>> {
        let mut header = Vec::new();

        match target {
            TargetAddr::Domain(domain, port) => {
                // 0x03 = domain name
                header.push(0x03);
                // Domain length (1 byte)
                if domain.len() > 255 {
                    return Err(Error::protocol("Domain name too long"));
                }
                header.push(domain.len() as u8);
                // Domain bytes
                header.extend_from_slice(domain.as_bytes());
                // Port (big endian)
                header.extend_from_slice(&port.to_be_bytes());
            }
            TargetAddr::Ip(addr) => {
                match addr {
                    std::net::SocketAddr::V4(v4) => {
                        // 0x01 = IPv4
                        header.push(0x01);
                        header.extend_from_slice(&v4.ip().octets());
                        header.extend_from_slice(&v4.port().to_be_bytes());
                    }
                    std::net::SocketAddr::V6(v6) => {
                        // 0x04 = IPv6
                        header.push(0x04);
                        header.extend_from_slice(&v6.ip().octets());
                        header.extend_from_slice(&v6.port().to_be_bytes());
                    }
                }
            }
        }

        Ok(header)
    }

    /// Check if UDP relay is enabled
    pub fn is_udp_enabled(&self) -> bool {
        self.udp_enabled
    }

    /// Relay UDP packets through Shadowsocks
    ///
    /// Encrypts the outgoing packet (with address header) and decrypts the
    /// reply, using a fresh one-shot UDP socket (immune to Windows ICMP
    /// poisoning).
    pub fn relay_udp(&self, target: &TargetAddr, data: &[u8]) -> Result<Vec<u8>> {
        if !self.udp_enabled {
            return Err(Error::config(
                "UDP relay is not enabled for this Shadowsocks proxy",
            ));
        }

        let cipher_spec = CipherSpec::new(&self.cipher)?;

        let timeout = Duration::from_secs(30);

        // Resolve server address
        let resolved_addr: SocketAddr =
            crate::common::socket::resolve_host(&self.server, self.port, timeout)
                .map_err(|e| Error::network(format!("Failed to resolve SS server: {}", e)))?
                .into_iter()
                .next()
                .ok_or_else(|| Error::network("No addresses found for SS server"))?;

        // Bind a fresh UDP socket (read timeout set by udp_bind)
        let server_socket = crate::common::socket::udp_bind("0.0.0.0:0".parse().unwrap(), timeout)
            .map_err(|e| Error::network(format!("Failed to bind UDP socket: {}", e)))?;

        // Connect to server (for send/recv convenience)
        server_socket
            .connect(resolved_addr)
            .map_err(|e| Error::network(format!("Failed to connect UDP to SS server: {}", e)))?;

        // Encrypt and send UDP packet
        let encrypted = self.encrypt_udp_packet(target, data, &cipher_spec)?;
        server_socket
            .send(&encrypted)
            .map_err(|e| Error::network(format!("Failed to send UDP packet: {}", e)))?;

        tracing::debug!(
            "Shadowsocks UDP: sent {} bytes to {} via {}:{}",
            data.len(),
            target,
            self.server,
            self.port
        );

        // Receive response with timeout
        let mut recv_buf = vec![0u8; 65535];
        let recv_len =
            crate::common::socket::recv_udp_timeout(&server_socket, &mut recv_buf, timeout)
                .map_err(|e| {
                    if e.kind() == std::io::ErrorKind::TimedOut {
                        Error::network("UDP receive timeout")
                    } else {
                        Error::network(format!("Failed to receive UDP packet: {}", e))
                    }
                })?;

        // Decrypt response
        let (response_data, _response_addr) =
            self.decrypt_udp_packet(&recv_buf[..recv_len], &cipher_spec)?;

        tracing::debug!(
            "Shadowsocks UDP: received {} bytes response",
            response_data.len()
        );

        Ok(response_data)
    }

    /// Encrypt a UDP packet for Shadowsocks
    /// Format: [salt][encrypted([address][payload])]
    fn encrypt_udp_packet(
        &self,
        target: &TargetAddr,
        data: &[u8],
        cipher_spec: &CipherSpec,
    ) -> Result<Vec<u8>> {
        // Generate salt
        let mut salt = vec![0u8; cipher_spec.salt_len];
        getrandom::fill(&mut salt)
            .map_err(|e| Error::network(format!("Failed to generate salt: {}", e)))?;

        // Derive key from salt
        let key = derive_subkey_for_cipher(&self.password, &salt, cipher_spec)?;

        // Build payload: [address][data]
        let addr_header = self.build_address_header(target)?;
        let mut payload = addr_header;
        payload.extend_from_slice(data);

        // Encrypt payload (UDP uses single-shot encryption, not chunked)
        let encrypted = encrypt_udp_payload(&key, &payload, cipher_spec)?;

        // Combine: [salt][encrypted_payload]
        let mut result = salt;
        result.extend_from_slice(&encrypted);

        Ok(result)
    }

    /// Decrypt a UDP packet from Shadowsocks
    /// Format: [salt][encrypted([address][payload])]
    /// Returns: (payload, target_address)
    fn decrypt_udp_packet(
        &self,
        data: &[u8],
        cipher_spec: &CipherSpec,
    ) -> Result<(Vec<u8>, TargetAddr)> {
        if data.len() < cipher_spec.salt_len + cipher_spec.tag_len {
            return Err(Error::protocol("UDP packet too short"));
        }

        // Extract salt
        let salt = &data[..cipher_spec.salt_len];
        let encrypted = &data[cipher_spec.salt_len..];

        // Derive key from salt
        let key = derive_subkey_for_cipher(&self.password, salt, cipher_spec)?;

        // Decrypt payload
        let decrypted = decrypt_udp_payload(&key, encrypted, cipher_spec)?;

        // Parse address from decrypted payload
        let (target, addr_len) = parse_address_header(&decrypted)?;
        let payload = decrypted[addr_len..].to_vec();

        Ok((payload, target))
    }
}

/// A `std::io::Read + Write + SyncStream` adapter over the Shadowsocks
/// chunked-encryption codec, so the bidirectional relay can drive the
/// upstream socket: writes encrypt one chunk at a time, reads consume the
/// server salt once and then decrypt chunk-by-chunk. Read/write timeouts
/// surface as `WouldBlock`/`TimedOut` and are treated as idle by the relay.
struct ShadowsocksStream {
    inner: parking_lot::Mutex<TcpStream>,
    enc: AeadCipher,
    dec: Option<AeadCipher>,
    password: String,
    cipher_spec: CipherSpec,
    read_buffer: Vec<u8>,
    read_pos: usize,
    eof: bool,
}

impl ShadowsocksStream {
    fn new(inner: TcpStream, enc: AeadCipher, cipher_spec: CipherSpec, password: String) -> Self {
        Self {
            inner: parking_lot::Mutex::new(inner),
            enc,
            dec: None,
            password,
            cipher_spec,
            read_buffer: Vec::new(),
            read_pos: 0,
            eof: false,
        }
    }
}

impl std::io::Read for ShadowsocksStream {
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
            let chunk = {
                let mut inner = self.inner.lock();
                if self.dec.is_none() {
                    // First read: consume the server salt and derive the key.
                    let mut server_salt = vec![0u8; self.cipher_spec.salt_len];
                    inner.read_exact(&mut server_salt)?;
                    let dec_subkey =
                        derive_subkey_for_cipher(&self.password, &server_salt, &self.cipher_spec)
                            .map_err(|e| std::io::Error::other(e.to_string()))?;
                    self.dec = Some(AeadCipher::new(self.cipher_spec, dec_subkey));
                }
                recv_decrypted_chunk(&mut *inner, self.dec.as_mut().unwrap())?
            };
            match chunk {
                Some(c) => {
                    self.read_buffer = c;
                    self.read_pos = 0;
                }
                None => {
                    self.eof = true;
                    return Ok(0);
                }
            }
        }
    }
}

impl std::io::Write for ShadowsocksStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut inner = self.inner.lock();
        for chunk in buf.chunks(0x3fff) {
            send_encrypted_chunk(&mut *inner, &mut self.enc, chunk)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.lock().flush()
    }
}

impl crate::common::stream::SyncStream for ShadowsocksStream {
    fn shutdown(&self, how: std::net::Shutdown) -> std::io::Result<()> {
        self.inner.lock().shutdown(how)
    }

    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.lock().peer_addr().ok()
    }

    fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        self.inner.lock().set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        self.inner.lock().set_write_timeout(timeout)
    }
}

/// AEAD cipher specifications
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CipherSpec {
    pub key_len: usize,
    pub salt_len: usize,
    pub tag_len: usize,
    pub cipher_type: CipherType,
}

/// Cipher type enumeration
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CipherType {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
    Aes128Gcm2022,
    Aes256Gcm2022,
    Chacha20Poly13052022,
}

impl CipherSpec {
    pub fn new(method: &str) -> Result<Self> {
        match method.to_lowercase().as_str() {
            "aes-256-gcm" | "aead_aes_256_gcm" => Ok(Self {
                key_len: 32,
                salt_len: 32,
                tag_len: 16,
                cipher_type: CipherType::Aes256Gcm,
            }),
            "aes-128-gcm" | "aead_aes_128_gcm" => Ok(Self {
                key_len: 16,
                salt_len: 16,
                tag_len: 16,
                cipher_type: CipherType::Aes128Gcm,
            }),
            "chacha20-ietf-poly1305" | "aead_chacha20_poly1305" => Ok(Self {
                key_len: 32,
                salt_len: 32,
                tag_len: 16,
                cipher_type: CipherType::Chacha20Poly1305,
            }),
            "2022-blake3-aes-128-gcm" => Ok(Self {
                key_len: 16,
                salt_len: 16,
                tag_len: 16,
                cipher_type: CipherType::Aes128Gcm2022,
            }),
            "2022-blake3-aes-256-gcm" => Ok(Self {
                key_len: 32,
                salt_len: 32,
                tag_len: 16,
                cipher_type: CipherType::Aes256Gcm2022,
            }),
            "2022-blake3-chacha20-poly1305" | "2022-blake3-chacha8-poly1305" => Ok(Self {
                key_len: 32,
                salt_len: 32,
                tag_len: 16,
                cipher_type: CipherType::Chacha20Poly13052022,
            }),
            _ => Err(Error::config(format!(
                "Unsupported shadowsocks cipher: {}",
                method
            ))),
        }
    }

    /// Check if this is a 2022 cipher
    pub fn is_2022(&self) -> bool {
        matches!(
            self.cipher_type,
            CipherType::Aes128Gcm2022
                | CipherType::Aes256Gcm2022
                | CipherType::Chacha20Poly13052022
        )
    }
}

/// Derive key from password using EVP_BytesToKey (OpenSSL-style MD5)
fn evp_bytes_to_key(password: &str, key_len: usize) -> Vec<u8> {
    let mut key = Vec::new();
    let mut prev: Vec<u8> = Vec::new();
    while key.len() < key_len {
        let mut hasher = Md5::new();
        hasher.update(&prev);
        hasher.update(password.as_bytes());
        prev = hasher.finalize().to_vec();
        key.extend_from_slice(&prev);
    }
    key.truncate(key_len);
    key
}

/// HKDF-SHA1 derive subkey (from master key + salt)
fn derive_subkey(password: &str, salt: &[u8], key_len: usize) -> Result<Vec<u8>> {
    // First derive master key from password using EVP_BytesToKey
    let master_key = evp_bytes_to_key(password, key_len);

    // Then derive session subkey using HKDF-SHA1
    let hk = Hkdf::<Sha1>::new(Some(salt), &master_key);
    let mut okm = vec![0u8; key_len];
    hk.expand(b"ss-subkey", &mut okm)
        .map_err(|e| Error::protocol(format!("HKDF expand failed: {}", e)))?;
    Ok(okm)
}

/// Derive subkey for 2022 ciphers using BLAKE3
/// The 2022 protocol uses the password directly as the key (base64-encoded)
/// and derives session keys using BLAKE3
fn derive_subkey_2022(password: &str, salt: &[u8], key_len: usize) -> Result<Vec<u8>> {
    // For 2022 ciphers, the password is a base64-encoded key
    let master_key = b64_decode(password.as_bytes(), B64Config::STANDARD)
        .map_err(|e| Error::config(format!("Invalid 2022 cipher key (must be base64): {:?}", e)))?;

    if master_key.len() != key_len {
        return Err(Error::config(format!(
            "Invalid 2022 cipher key length: expected {}, got {}",
            key_len,
            master_key.len()
        )));
    }

    // Derive session key using BLAKE3 with salt
    let mut hasher = Blake3::new_derive_key("shadowsocks 2022 session subkey".as_bytes());
    hasher.update(&master_key);
    hasher.update(salt);
    let mut output = vec![0u8; key_len];
    hasher.finalize_xof_into(&mut output);

    Ok(output)
}

/// Derive subkey based on cipher type
fn derive_subkey_for_cipher(
    password: &str,
    salt: &[u8],
    cipher_spec: &CipherSpec,
) -> Result<Vec<u8>> {
    if cipher_spec.is_2022() {
        derive_subkey_2022(password, salt, cipher_spec.key_len)
    } else {
        derive_subkey(password, salt, cipher_spec.key_len)
    }
}

/// AEAD cipher with incrementing nonce
/// Supports AES-256-GCM, AES-128-GCM, and ChaCha20-Poly1305
#[allow(clippy::large_enum_variant)]
enum AeadCipherInner {
    Aes256Gcm(Aes256Gcm),
    Aes128Gcm(Aes128Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

struct AeadCipher {
    inner: AeadCipherInner,
    counter: u64,
    tag_len: usize,
}

impl AeadCipher {
    fn new(spec: CipherSpec, key: Vec<u8>) -> Self {
        let inner = match spec.cipher_type {
            CipherType::Aes256Gcm | CipherType::Aes256Gcm2022 => AeadCipherInner::Aes256Gcm(
                Aes256Gcm::new_from_slice(&key).expect("validated key length"),
            ),
            CipherType::Aes128Gcm | CipherType::Aes128Gcm2022 => AeadCipherInner::Aes128Gcm(
                Aes128Gcm::new_from_slice(&key).expect("validated key length"),
            ),
            CipherType::Chacha20Poly1305 | CipherType::Chacha20Poly13052022 => {
                AeadCipherInner::ChaCha20Poly1305(
                    ChaCha20Poly1305::new_from_slice(&key).expect("validated key length"),
                )
            }
        };
        Self {
            inner,
            counter: 0,
            tag_len: spec.tag_len,
        }
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        // Shadowsocks AEAD uses little-endian nonce counter
        // The nonce is simply the counter value in little-endian format
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.counter.to_le_bytes());
        self.counter = self.counter.wrapping_add(1);
        nonce
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.next_nonce();
        match &self.inner {
            AeadCipherInner::Aes256Gcm(cipher) => cipher
                .encrypt(&nonce, plaintext, &[])
                .map_err(|e| Error::protocol(format!("AEAD encrypt failed: {:?}", e))),
            AeadCipherInner::Aes128Gcm(cipher) => cipher
                .encrypt(&nonce, plaintext, &[])
                .map_err(|e| Error::protocol(format!("AEAD encrypt failed: {:?}", e))),
            AeadCipherInner::ChaCha20Poly1305(cipher) => cipher
                .encrypt(&nonce, plaintext, &[])
                .map_err(|e| Error::protocol(format!("AEAD encrypt failed: {:?}", e))),
        }
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.next_nonce();
        match &self.inner {
            AeadCipherInner::Aes256Gcm(cipher) => cipher
                .decrypt(&nonce, ciphertext, &[])
                .map_err(|e| Error::protocol(format!("AEAD decrypt failed: {:?}", e))),
            AeadCipherInner::Aes128Gcm(cipher) => cipher
                .decrypt(&nonce, ciphertext, &[])
                .map_err(|e| Error::protocol(format!("AEAD decrypt failed: {:?}", e))),
            AeadCipherInner::ChaCha20Poly1305(cipher) => cipher
                .decrypt(&nonce, ciphertext, &[])
                .map_err(|e| Error::protocol(format!("AEAD decrypt failed: {:?}", e))),
        }
    }
}

/// 发送一个加密块：加密(2-byte length) + 加密(payload)
fn send_encrypted_chunk<W: Write>(writer: &mut W, enc: &mut AeadCipher, data: &[u8]) -> Result<()> {
    let len = data.len();
    if len > 0x3fff {
        return Err(Error::protocol("Shadowsocks chunk too large (>16KB)"));
    }

    let len_bytes = (len as u16).to_be_bytes();
    let enc_len = enc.encrypt(&len_bytes)?;
    writer
        .write_all(&enc_len)
        .map_err(|e| Error::network(format!("Failed to send SS length: {}", e)))?;

    if len > 0 {
        let enc_data = enc.encrypt(data)?;
        writer
            .write_all(&enc_data)
            .map_err(|e| Error::network(format!("Failed to send SS data: {}", e)))?;
    }

    Ok(())
}

/// 接收并解密一个数据块；返回 `None` 表示 EOF。
///
/// 以 `io::Result` 返回，保留底层 socket 的错误 kind（`WouldBlock`/
/// `TimedOut` 表示空闲，relay 循环据此重试）。
fn recv_decrypted_chunk<R: Read>(
    reader: &mut R,
    dec: &mut AeadCipher,
) -> std::io::Result<Option<Vec<u8>>> {
    let tag = dec.tag_len;

    // 读取并解密长度
    let mut enc_len_buf = vec![0u8; 2 + tag];
    match reader.read_exact(&mut enc_len_buf) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let len_plain = dec
        .decrypt(&enc_len_buf)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    if len_plain.len() != 2 {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "Invalid SS length field",
        ));
    }
    let data_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;

    if data_len == 0 {
        return Ok(None);
    }

    // 读取并解密数据块
    let mut enc_data = vec![0u8; data_len + tag];
    reader.read_exact(&mut enc_data)?;

    let data = dec
        .decrypt(&enc_data)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(Some(data))
}

/// Encrypt UDP payload (single-shot, not chunked like TCP)
fn encrypt_udp_payload(key: &[u8], plaintext: &[u8], cipher_spec: &CipherSpec) -> Result<Vec<u8>> {
    // UDP uses nonce = 0 for single-shot encryption
    let nonce = [0u8; 12];

    match cipher_spec.cipher_type {
        CipherType::Aes256Gcm | CipherType::Aes256Gcm2022 => {
            let cipher = Aes256Gcm::new_from_slice(key).expect("validated key length");
            cipher
                .encrypt(&nonce, plaintext, &[])
                .map_err(|e| Error::protocol(format!("UDP AEAD encrypt failed: {:?}", e)))
        }
        CipherType::Aes128Gcm | CipherType::Aes128Gcm2022 => {
            let cipher = Aes128Gcm::new_from_slice(key).expect("validated key length");
            cipher
                .encrypt(&nonce, plaintext, &[])
                .map_err(|e| Error::protocol(format!("UDP AEAD encrypt failed: {:?}", e)))
        }
        CipherType::Chacha20Poly1305 | CipherType::Chacha20Poly13052022 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key).expect("validated key length");
            cipher
                .encrypt(&nonce, plaintext, &[])
                .map_err(|e| Error::protocol(format!("UDP AEAD encrypt failed: {:?}", e)))
        }
    }
}

/// Decrypt UDP payload (single-shot, not chunked like TCP)
fn decrypt_udp_payload(key: &[u8], ciphertext: &[u8], cipher_spec: &CipherSpec) -> Result<Vec<u8>> {
    // UDP uses nonce = 0 for single-shot decryption
    let nonce = [0u8; 12];

    match cipher_spec.cipher_type {
        CipherType::Aes256Gcm | CipherType::Aes256Gcm2022 => {
            let cipher = Aes256Gcm::new_from_slice(key).expect("validated key length");
            cipher
                .decrypt(&nonce, ciphertext, &[])
                .map_err(|e| Error::protocol(format!("UDP AEAD decrypt failed: {:?}", e)))
        }
        CipherType::Aes128Gcm | CipherType::Aes128Gcm2022 => {
            let cipher = Aes128Gcm::new_from_slice(key).expect("validated key length");
            cipher
                .decrypt(&nonce, ciphertext, &[])
                .map_err(|e| Error::protocol(format!("UDP AEAD decrypt failed: {:?}", e)))
        }
        CipherType::Chacha20Poly1305 | CipherType::Chacha20Poly13052022 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key).expect("validated key length");
            cipher
                .decrypt(&nonce, ciphertext, &[])
                .map_err(|e| Error::protocol(format!("UDP AEAD decrypt failed: {:?}", e)))
        }
    }
}

/// Parse SOCKS5-style address header from buffer
/// Returns (TargetAddr, bytes_consumed)
fn parse_address_header(data: &[u8]) -> Result<(TargetAddr, usize)> {
    if data.is_empty() {
        return Err(Error::protocol("Empty address header"));
    }

    let atype = data[0];
    match atype {
        0x01 => {
            // IPv4: 1 + 4 + 2 = 7 bytes
            if data.len() < 7 {
                return Err(Error::protocol("IPv4 address too short"));
            }
            let ip = std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok((
                TargetAddr::Ip(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                    ip, port,
                ))),
                7,
            ))
        }
        0x03 => {
            // Domain: 1 + 1 + domain_len + 2
            if data.len() < 2 {
                return Err(Error::protocol("Domain address too short"));
            }
            let domain_len = data[1] as usize;
            let total_len = 2 + domain_len + 2;
            if data.len() < total_len {
                return Err(Error::protocol("Domain address incomplete"));
            }
            let domain = String::from_utf8(data[2..2 + domain_len].to_vec())
                .map_err(|_| Error::protocol("Invalid domain encoding"))?;
            let port = u16::from_be_bytes([data[2 + domain_len], data[3 + domain_len]]);
            Ok((TargetAddr::Domain(domain, port), total_len))
        }
        0x04 => {
            // IPv6: 1 + 16 + 2 = 19 bytes
            if data.len() < 19 {
                return Err(Error::protocol("IPv6 address too short"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[1..17]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok((
                TargetAddr::Ip(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                    ip, port, 0, 0,
                ))),
                19,
            ))
        }
        _ => Err(Error::protocol(format!("Unknown address type: {}", atype))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_spec_aes_256_gcm() {
        let spec = CipherSpec::new("aes-256-gcm").unwrap();
        assert_eq!(spec.key_len, 32);
        assert_eq!(spec.salt_len, 32);
        assert_eq!(spec.tag_len, 16);
        assert_eq!(spec.cipher_type, CipherType::Aes256Gcm);
        assert!(!spec.is_2022());
    }

    #[test]
    fn test_cipher_spec_aes_128_gcm() {
        let spec = CipherSpec::new("aes-128-gcm").unwrap();
        assert_eq!(spec.key_len, 16);
        assert_eq!(spec.salt_len, 16);
        assert_eq!(spec.tag_len, 16);
        assert_eq!(spec.cipher_type, CipherType::Aes128Gcm);
        assert!(!spec.is_2022());
    }

    #[test]
    fn test_cipher_spec_chacha20() {
        let spec = CipherSpec::new("chacha20-ietf-poly1305").unwrap();
        assert_eq!(spec.key_len, 32);
        assert_eq!(spec.salt_len, 32);
        assert_eq!(spec.tag_len, 16);
        assert_eq!(spec.cipher_type, CipherType::Chacha20Poly1305);
        assert!(!spec.is_2022());
    }

    #[test]
    fn test_cipher_spec_2022_aes_256() {
        let spec = CipherSpec::new("2022-blake3-aes-256-gcm").unwrap();
        assert_eq!(spec.key_len, 32);
        assert_eq!(spec.salt_len, 32);
        assert_eq!(spec.tag_len, 16);
        assert_eq!(spec.cipher_type, CipherType::Aes256Gcm2022);
        assert!(spec.is_2022());
    }

    #[test]
    fn test_cipher_spec_2022_aes_128() {
        let spec = CipherSpec::new("2022-blake3-aes-128-gcm").unwrap();
        assert_eq!(spec.key_len, 16);
        assert_eq!(spec.salt_len, 16);
        assert_eq!(spec.tag_len, 16);
        assert_eq!(spec.cipher_type, CipherType::Aes128Gcm2022);
        assert!(spec.is_2022());
    }

    #[test]
    fn test_cipher_spec_2022_chacha20() {
        let spec = CipherSpec::new("2022-blake3-chacha20-poly1305").unwrap();
        assert_eq!(spec.key_len, 32);
        assert_eq!(spec.salt_len, 32);
        assert_eq!(spec.tag_len, 16);
        assert_eq!(spec.cipher_type, CipherType::Chacha20Poly13052022);
        assert!(spec.is_2022());
    }

    #[test]
    fn test_aead_cipher_encrypt_decrypt_roundtrip() {
        let spec = CipherSpec::new("aes-256-gcm").unwrap();
        let key = vec![0u8; 32];
        let mut enc = AeadCipher::new(spec, key.clone());
        let mut dec = AeadCipher::new(spec, key);

        let plaintext = b"Hello, Shadowsocks!";
        let ciphertext = enc.encrypt(plaintext).unwrap();
        let decrypted = dec.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_aead_cipher_chacha20_roundtrip() {
        let spec = CipherSpec::new("chacha20-ietf-poly1305").unwrap();
        let key = vec![0u8; 32];
        let mut enc = AeadCipher::new(spec, key.clone());
        let mut dec = AeadCipher::new(spec, key);

        let plaintext = b"Hello, ChaCha20!";
        let ciphertext = enc.encrypt(plaintext).unwrap();
        let decrypted = dec.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_address_header_ipv4() {
        let config = OutboundConfig {
            tag: "test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Shadowsocks,
            server: Some("127.0.0.1".to_string()),
            port: Some(8388),
            options: {
                let mut opts = std::collections::HashMap::new();
                opts.insert(
                    "password".to_string(),
                    nextjson::Value::String("test".to_string()),
                );
                opts.insert(
                    "cipher".to_string(),
                    nextjson::Value::String("aes-256-gcm".to_string()),
                );
                opts
            },
        };
        let outbound = ShadowsocksOutbound::new(config).unwrap();

        let target = TargetAddr::Ip(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::new(192, 168, 1, 1),
            443,
        )));
        let header = outbound.build_address_header(&target).unwrap();

        assert_eq!(header[0], 0x01); // IPv4 type
        assert_eq!(&header[1..5], &[192, 168, 1, 1]); // IP address
        assert_eq!(&header[5..7], &[0x01, 0xBB]); // Port 443 in big-endian
    }

    #[test]
    fn test_address_header_domain() {
        let config = OutboundConfig {
            tag: "test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Shadowsocks,
            server: Some("127.0.0.1".to_string()),
            port: Some(8388),
            options: {
                let mut opts = std::collections::HashMap::new();
                opts.insert(
                    "password".to_string(),
                    nextjson::Value::String("test".to_string()),
                );
                opts.insert(
                    "cipher".to_string(),
                    nextjson::Value::String("aes-256-gcm".to_string()),
                );
                opts
            },
        };
        let outbound = ShadowsocksOutbound::new(config).unwrap();

        let target = TargetAddr::Domain("example.com".to_string(), 80);
        let header = outbound.build_address_header(&target).unwrap();

        assert_eq!(header[0], 0x03); // Domain type
        assert_eq!(header[1], 11); // Domain length
        assert_eq!(&header[2..13], b"example.com");
        assert_eq!(&header[13..15], &[0x00, 0x50]); // Port 80 in big-endian
    }

    #[test]
    fn test_parse_address_header_ipv4() {
        let data = [0x01, 192, 168, 1, 1, 0x01, 0xBB]; // IPv4 192.168.1.1:443
        let (target, len) = parse_address_header(&data).unwrap();

        assert_eq!(len, 7);
        match target {
            TargetAddr::Ip(addr) => {
                assert_eq!(addr.ip().to_string(), "192.168.1.1");
                assert_eq!(addr.port(), 443);
            }
            _ => panic!("Expected IP address"),
        }
    }

    #[test]
    fn test_parse_address_header_domain() {
        let mut data = vec![0x03, 11]; // Domain type, length 11
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&[0x00, 0x50]); // Port 80

        let (target, len) = parse_address_header(&data).unwrap();

        assert_eq!(len, 15);
        match target {
            TargetAddr::Domain(domain, port) => {
                assert_eq!(domain, "example.com");
                assert_eq!(port, 80);
            }
            _ => panic!("Expected domain address"),
        }
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_cipher_type() -> impl Strategy<Value = &'static str> {
        prop_oneof![
            Just("aes-256-gcm"),
            Just("aes-128-gcm"),
            Just("chacha20-ietf-poly1305"),
        ]
    }

    fn arb_plaintext() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 1..1024)
    }

    fn arb_key_for_cipher(cipher: &str) -> Vec<u8> {
        let spec = CipherSpec::new(cipher).unwrap();
        vec![0x42u8; spec.key_len]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// **Feature: rust-codebase-optimization, Property: 加密解密往返**
        /// **Validates: Requirements 5.1**
        /// *For any* plaintext and supported cipher, encrypting then decrypting
        /// should produce the original plaintext.
        #[test]
        fn prop_aead_encrypt_decrypt_roundtrip(
            plaintext in arb_plaintext(),
            cipher in arb_cipher_type(),
        ) {
            let spec = CipherSpec::new(cipher).unwrap();
            let key = arb_key_for_cipher(cipher);

            let mut enc = AeadCipher::new(spec, key.clone());
            let mut dec = AeadCipher::new(spec, key);

            let ciphertext = enc.encrypt(&plaintext).unwrap();
            let decrypted = dec.decrypt(&ciphertext).unwrap();

            prop_assert_eq!(plaintext, decrypted);
        }

        /// **Feature: rust-codebase-optimization, Property: 加密解密往返**
        /// **Validates: Requirements 5.1**
        /// *For any* plaintext, the ciphertext should be longer than plaintext
        /// by exactly the tag length.
        #[test]
        fn prop_ciphertext_length(
            plaintext in arb_plaintext(),
            cipher in arb_cipher_type(),
        ) {
            let spec = CipherSpec::new(cipher).unwrap();
            let key = arb_key_for_cipher(cipher);

            let mut enc = AeadCipher::new(spec, key);
            let ciphertext = enc.encrypt(&plaintext).unwrap();

            prop_assert_eq!(ciphertext.len(), plaintext.len() + spec.tag_len);
        }

        /// **Feature: rust-codebase-optimization, Property: 加密解密往返**
        /// **Validates: Requirements 5.1**
        /// *For any* two different plaintexts with the same key, the ciphertexts
        /// should be different (due to incrementing nonce).
        #[test]
        fn prop_different_plaintexts_different_ciphertexts(
            plaintext1 in arb_plaintext(),
            plaintext2 in arb_plaintext(),
            cipher in arb_cipher_type(),
        ) {
            prop_assume!(plaintext1 != plaintext2);

            let spec = CipherSpec::new(cipher).unwrap();
            let key = arb_key_for_cipher(cipher);

            let mut enc = AeadCipher::new(spec, key);
            let ciphertext1 = enc.encrypt(&plaintext1).unwrap();
            let ciphertext2 = enc.encrypt(&plaintext2).unwrap();

            prop_assert_ne!(ciphertext1, ciphertext2);
        }

        /// **Feature: rust-codebase-optimization, Property: 加密解密往返**
        /// **Validates: Requirements 5.1**
        /// *For any* plaintext encrypted twice with the same key, the ciphertexts
        /// should be different (due to incrementing nonce).
        #[test]
        fn prop_same_plaintext_different_ciphertexts(
            plaintext in arb_plaintext(),
            cipher in arb_cipher_type(),
        ) {
            let spec = CipherSpec::new(cipher).unwrap();
            let key = arb_key_for_cipher(cipher);

            let mut enc = AeadCipher::new(spec, key);
            let ciphertext1 = enc.encrypt(&plaintext).unwrap();
            let ciphertext2 = enc.encrypt(&plaintext).unwrap();

            // Same plaintext encrypted twice should produce different ciphertexts
            // because the nonce increments
            prop_assert_ne!(ciphertext1, ciphertext2);
        }

        /// **Feature: rust-codebase-optimization, Property: UDP加密解密往返**
        /// **Validates: Requirements 5.1, 5.10**
        /// *For any* plaintext and supported cipher, UDP encrypt then decrypt
        /// should produce the original plaintext.
        #[test]
        fn prop_udp_encrypt_decrypt_roundtrip(
            plaintext in arb_plaintext(),
            cipher in arb_cipher_type(),
        ) {
            let spec = CipherSpec::new(cipher).unwrap();
            let key = arb_key_for_cipher(cipher);

            let encrypted = encrypt_udp_payload(&key, &plaintext, &spec).unwrap();
            let decrypted = decrypt_udp_payload(&key, &encrypted, &spec).unwrap();

            prop_assert_eq!(plaintext, decrypted);
        }
    }
}
