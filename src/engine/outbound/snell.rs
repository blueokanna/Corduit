//! Snell v4/v5 outbound.
//!
//! Snell is Surge's own protocol; there is no RFC. This implementation follows
//! the byte layout of `SagerNet/sing-snell`, the interop-tested reimplementation
//! sing-box delegates to. Every constant and every field order below is from
//! that source (`snell.go`, `snellv4/record.go`, `snellv5/record.go`,
//! `request.go`, `address.go`, `crypto.go`), not from a specification — which
//! is why the codecs are written by hand and pinned by byte-exact tests.
//!
//! # Record framing
//!
//! ```text
//! first record of a direction
//!   [16B salt][23B sealed header][padding][sealed payload]
//! later records of the same direction
//!   [23B sealed header][padding][sealed payload]
//!
//! header plaintext (7B)   [0x04][0x00][0x00][padding len u16 BE][payload len u16 BE]
//! key                     Argon2id(psk, salt, t=3, m=8 KiB, p=1, 32 bytes)[..16]
//! cipher                  AES-128-GCM, AAD empty for both the header and the payload
//! nonce                   12 bytes, starts at zero, increments by one per AEAD
//!                         operation (so twice per record) for the life of the
//!                         direction
//! ```
//!
//! The salt travels in the clear at the head of the first record, so each
//! direction derives its own key from its own salt: the client's write key and
//! its read key are unrelated, and a record replayed into the wrong direction
//! fails its tag rather than decrypting.
//!
//! # The padding is a mask, not a filler
//!
//! The padding bytes are not merely appended: the writer and the reader both
//! exchange the even-indexed bytes of the padding area with the even-indexed
//! bytes of the sealed payload. Applied twice the operation is the identity, so
//! the wire ends up carrying a payload whose even bytes sit in the padding area
//! and vice versa. The effect is that the first bytes of every record are
//! random-looking regardless of what the ciphertext would have started with —
//! and the length field that describes it is inside the sealed header, so a
//! passive observer cannot even tell how much of the record is padding.
//!
//! # Honest scope
//!
//! * **v4 and v5 only.** They share a wire format (v5 differs in the server's
//!   QUIC-relay capability, not in the framing). `version: 6` is refused: v6
//!   adds a salt-block/record-prefix shaping mode whose parameters are chosen
//!   by a `Profile` the reference selects with per-mode rules, and getting those
//!   wrong would look like an auth failure rather than an unsupported version.
//!   Versions below 4 are refused for a different reason — their key derivation
//!   is not Argon2id.
//! * **`obfs: http` is implemented** from the reference's request shape.
//!   **`obfs: tls` is refused**: it prepends a fabricated `ClientHello` whose
//!   extension sequence is what makes it look like a browser, and that sequence
//!   could not be verified byte-for-byte from source. A wrong guess there is a
//!   silent failure against a real server, which is worse than a config error.
//! * The adaptive padding-length algorithm of the reference is **not**
//!   reproduced (only its initial range is): the length is self-describing, so
//!   any policy that the writer applies consistently is protocol-correct. What
//!   is lost is the traffic-shaping heuristic, and reproducing a heuristic
//!   without its exact recurrence would be inventing a fingerprint rather than
//!   matching one.
//! * `reuse` (v5's connection reuse) is not implemented; each connection is its
//!   own TCP session, which is what `reuse: false` means.

use crate::common::stream::{BoxStream, SyncStream};
use crate::crypto::aead::{Aead, Aes128Gcm};
use crate::crypto::kdf::{argon2id, Argon2idParams};
use crate::engine::config::OutboundConfig;
use crate::engine::connection_tracker::TrackedConnection;
use crate::engine::error::{Error, Result};
use crate::engine::outbound::{OutboundProxy, TargetAddr};
use crate::engine::tls::yaml_value_to_string;
use courierust::courierust_tls::crypto::rng::fill_random;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};

/// Version byte of the sealed header.
const HEADER_VERSION: u8 = 0x04;
/// Plaintext header length.
const HEADER_PLAIN_LEN: usize = 7;
/// AEAD tag length.
const AEAD_TAG_LEN: usize = 16;
/// Sealed header length.
const HEADER_CIPHER_LEN: usize = HEADER_PLAIN_LEN + AEAD_TAG_LEN;
/// Salt length prepended to the first record of each direction.
const SALT_LEN: usize = 16;
/// Nonce length for AES-GCM.
const NONCE_LEN: usize = 12;
/// Largest payload one record can describe (`u16`, and the reference caps it at
/// 0x3fff).
const MAX_PAYLOAD_LEN: usize = 0x3fff;
/// First byte of the request body.
const REQUEST_VERSION: u8 = 0x01;
/// `ConnectV2` — the command the reference client sends for TCP, even with
/// reuse off.
const COMMAND_CONNECT_V2: u8 = 0x05;
/// `Ping`, used by health checks.
const COMMAND_PING: u8 = 0x00;
/// First byte of a successful reply.
const REPLY_TUNNEL: u8 = 0x00;
/// First byte of a failed reply, followed by a code and a message.
const REPLY_ERROR: u8 = 0x02;

/// Plaintext length of an error reply's fixed part, after the status byte:
/// the code and the message length.
const REPLY_ERROR_HEAD_LEN: usize = 2;

/// Initial-record padding range from the reference (`0x100..0x200`).
const INITIAL_PADDING_MIN: usize = 0x100;
const INITIAL_PADDING_SPAN: usize = 0x100;
/// Padding range for later records. Non-zero, so the mask is always applied.
const LATER_PADDING_MAX: usize = 64;

/// TCP connect budget.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Bound for the fake-HTTP obfs header we skip on the first read.
const MAX_OBFS_HEADER: usize = 16 * 1024;
/// User agents the http obfs draws from, matching the reference's list of
/// period browsers rather than one fixed string: a constant UA across a whole
/// deployment is itself a fingerprint.
const OBFS_USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:42.0) Gecko/20100101 Firefox/42.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 9_1 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13B143 Safari/601.1",
];

/// How the first packets are dressed up.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SnellObfs {
    /// Raw Snell records.
    #[default]
    None,
    /// A fabricated `GET` (WebSocket upgrade) precedes the first record, and the
    /// server's fabricated `101` response is skipped before the first read.
    Http { host: String, uri: String },
}

/// Snell outbound settings (kept for introspection and tests).
#[derive(Debug, Clone)]
pub struct SnellConfig {
    pub server: String,
    pub port: u16,
    pub psk: String,
    pub version: u8,
    pub obfs: SnellObfs,
    /// Sent in the request's client-id field. Empty by default: an empty field
    /// is valid on the wire, and inventing an identifier the server never
    /// issued would be worse than sending nothing.
    pub client_id: Vec<u8>,
}

impl Default for SnellConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 443,
            psk: String::new(),
            version: 4,
            obfs: SnellObfs::None,
            client_id: Vec::new(),
        }
    }
}

pub struct SnellOutbound {
    config: OutboundConfig,
    settings: SnellConfig,
}

impl SnellOutbound {
    pub fn new(config: OutboundConfig) -> Result<Self> {
        let server = config
            .server
            .clone()
            .ok_or_else(|| Error::config("Missing server address for Snell"))?;
        let port = config
            .port
            .ok_or_else(|| Error::config("Missing port for Snell"))?;

        let psk = config
            .options
            .get("psk")
            .or_else(|| config.options.get("password"))
            .map(yaml_value_to_string)
            .unwrap_or_default();
        if psk.is_empty() {
            return Err(Error::config("Snell requires a `psk`"));
        }

        let version = config
            .options
            .get("version")
            .and_then(|v| v.as_u64())
            .unwrap_or(4);
        match version {
            4 | 5 => {}
            6 => {
                return Err(Error::config(
                    "Snell version 6 adds shaped records whose parameters this build does not \
                     reproduce; use version 5 against a v5/v6 server, or add the shaped mode",
                ))
            }
            other => {
                return Err(Error::config(format!(
                    "Snell version {other} is not supported: versions before 4 derive their key \
                     differently (no Argon2id), and this build implements 4 and 5"
                )))
            }
        }
        let version = version as u8;

        let obfs = match config
            .options
            .get("obfs")
            .map(yaml_value_to_string)
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
        {
            None => SnellObfs::None,
            Some(mode) if mode == "http" => SnellObfs::Http {
                host: config
                    .options
                    .get("obfs-host")
                    .map(yaml_value_to_string)
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "bing.com".to_string()),
                uri: config
                    .options
                    .get("obfs-uri")
                    .map(yaml_value_to_string)
                    .map(|s| s.trim().to_string())
                    .filter(|s| s.starts_with('/'))
                    .unwrap_or_else(|| "/".to_string()),
            },
            Some(mode) if mode == "tls" => {
                return Err(Error::config(
                    "Snell `obfs: tls` fabricates a ClientHello whose extension sequence this \
                     build does not reproduce; `obfs: http` or no obfs are available",
                ))
            }
            Some(other) => {
                return Err(Error::config(format!(
                    "Unknown Snell obfs mode `{other}`; the reference defines `http` and `tls`"
                )))
            }
        };

        if config
            .options
            .get("reuse")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            warn!(
                "Snell outbound '{}': `reuse: true` is not implemented — one TCP session per \
                 connection is used, which is what `reuse: false` means",
                config.tag
            );
        }

        let settings = SnellConfig {
            server,
            port,
            psk,
            version,
            obfs,
            client_id: config
                .options
                .get("client-id")
                .or_else(|| config.options.get("client_id"))
                .or_else(|| config.options.get("user-id"))
                .map(yaml_value_to_string)
                .unwrap_or_default()
                .into_bytes(),
        };

        debug!(
            "Creating Snell outbound: server={}:{}, version={}, obfs={:?}",
            settings.server, settings.port, settings.version, settings.obfs
        );

        Ok(Self { config, settings })
    }

    /// The parsed settings, for introspection and tests.
    pub fn snell_config(&self) -> &SnellConfig {
        &self.settings
    }

    fn dial(&self, timeout: Duration) -> Result<BoxStream> {
        let stream =
            crate::common::socket::connect_host(&self.settings.server, self.settings.port, timeout)
                .map_err(|e| {
                    Error::network(format!(
                        "Failed to connect to Snell server {}:{}: {e}",
                        self.settings.server, self.settings.port
                    ))
                })?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| Error::network(format!("set read timeout: {e}")))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|e| Error::network(format!("set write timeout: {e}")))?;

        let inner: BoxStream = match &self.settings.obfs {
            SnellObfs::None => Box::new(stream),
            SnellObfs::Http { host, uri } => Box::new(ObfsHttpStream::new(
                Box::new(stream),
                host.clone(),
                uri.clone(),
            )),
        };
        Ok(inner)
    }

    /// Open a session and consume the server's reply header.
    fn open(&self, target: &TargetAddr, timeout: Duration) -> Result<SnellStream> {
        let mut stream = SnellStream::new(self.dial(timeout)?, self.settings.psk.as_bytes());
        let request = encode_request(COMMAND_CONNECT_V2, &self.settings.client_id, target);
        stream
            .write_all(&request)
            .map_err(|e| Error::network(format!("Failed to send the Snell request: {e}")))?;

        let mut status = [0u8; 1];
        stream
            .read_exact(&mut status)
            .map_err(|e| Error::network(format!("Failed to read the Snell reply: {e}")))?;
        match status[0] {
            REPLY_TUNNEL => Ok(stream),
            REPLY_ERROR => {
                let mut head = [0u8; REPLY_ERROR_HEAD_LEN];
                stream
                    .read_exact(&mut head)
                    .map_err(|e| Error::network(format!("Failed to read the Snell error: {e}")))?;
                let mut message = vec![0u8; usize::from(head[1])];
                if !message.is_empty() {
                    stream.read_exact(&mut message).map_err(|e| {
                        Error::network(format!("Failed to read the Snell error text: {e}"))
                    })?;
                }
                Err(Error::network(format!(
                    "Snell server refused the request (code {}): {}",
                    head[0],
                    String::from_utf8_lossy(&message)
                )))
            }
            other => Err(Error::protocol(format!(
                "Snell reply starts with unknown status 0x{other:02x}"
            ))),
        }
    }
}

impl OutboundProxy for SnellOutbound {
    fn connect(&self) -> Result<()> {
        let mut stream =
            SnellStream::new(self.dial(CONNECT_TIMEOUT)?, self.settings.psk.as_bytes());
        let request = encode_request(
            COMMAND_PING,
            &self.settings.client_id,
            &TargetAddr::Domain(String::new(), 0),
        );
        stream
            .write_all(&request)
            .map_err(|e| Error::network(format!("Failed to send the Snell ping: {e}")))?;
        let mut status = [0u8; 1];
        stream
            .read_exact(&mut status)
            .map_err(|e| Error::network(format!("Failed to read the Snell pong: {e}")))?;
        if status[0] != REPLY_TUNNEL && status[0] != 0x01 {
            return Err(Error::protocol(format!(
                "Snell ping answered with status 0x{:02x}",
                status[0]
            )));
        }
        Ok(())
    }

    fn disconnect(&self) -> Result<()> {
        Ok(())
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn server_addr(&self) -> Option<(String, u16)> {
        Some((self.settings.server.clone(), self.settings.port))
    }

    fn test_http_latency(&self, test_url: &str, timeout: Duration) -> Result<Duration> {
        let url = crate::common::url::Url::parse(test_url)
            .map_err(|e| Error::config(format!("Invalid test URL: {e}")))?;
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

        let start = std::time::Instant::now();
        let mut stream = self.open(
            &TargetAddr::Domain(host.clone(), url_port),
            timeout.min(CONNECT_TIMEOUT),
        )?;
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: Corduit/1.0\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| Error::network(format!("Failed to send probe request: {e}")))?;

        let mut first = [0u8; 5];
        stream
            .read_exact(&mut first)
            .map_err(|e| Error::network(format!("Failed to read probe response: {e}")))?;
        if &first != b"HTTP/" {
            return Err(Error::protocol(
                "Snell latency probe did not get an HTTP status line",
            ));
        }
        Ok(start.elapsed())
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
        let stream = self.open(&target, CONNECT_TIMEOUT)?;
        debug!(
            "Snell: relaying TCP to {target} via {}:{}",
            self.settings.server, self.settings.port
        );
        relay_streams!(inbound, stream, connection)
    }
}

// ---------------------------------------------------------------------------
// Codecs
// ---------------------------------------------------------------------------

/// The AEAD state of one direction: a key, a nonce, and the rule for advancing
/// it.
///
/// The nonce advances once per AEAD operation, so one record consumes two
/// values — the header's and the payload's. That is the detail an
/// implementation is most likely to get wrong, and the reason this is a type
/// with the advance inside `seal`/`open` rather than three free functions.
struct Direction {
    cipher: Aes128Gcm,
    nonce: [u8; NONCE_LEN],
}

impl Direction {
    fn new(key: [u8; 16]) -> Self {
        Self {
            cipher: Aes128Gcm::new(&key),
            nonce: [0u8; NONCE_LEN],
        }
    }

    /// Little-endian byte-wise increment, exactly as the reference does it: the
    /// first byte is incremented, and only a wrap carries onward.
    fn advance(&mut self) {
        for byte in self.nonce.iter_mut() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }

    /// Seal with the current nonce and advance.
    fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let sealed = self
            .cipher
            .encrypt(&self.nonce, plaintext, &[])
            .map_err(|e| Error::protocol(format!("Snell seal failed: {e}")))?;
        self.advance();
        Ok(sealed)
    }

    /// Open with the current nonce and advance.
    ///
    /// The nonce is advanced only after the tag has verified: a record that
    /// fails authentication must not desynchronise the two sides' counters,
    /// because the connection is torn down either way and a half-advanced
    /// counter would make the diagnosis harder.
    fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let plaintext = self
            .cipher
            .decrypt(&self.nonce, ciphertext, &[])
            .map_err(|_| Error::protocol("Snell record failed authentication"))?;
        self.advance();
        Ok(plaintext)
    }
}

/// `EVP`-free key derivation: Argon2id over the psk and the record salt.
fn derive_key(psk: &[u8], salt: &[u8]) -> Result<[u8; 16]> {
    let tag = argon2id(
        psk,
        salt,
        &[],
        &[],
        Argon2idParams {
            memory_kib: 8,
            iterations: 3,
            lanes: 1,
            tag_len: 32,
        },
    )
    .map_err(|e| Error::protocol(format!("Snell key derivation: {e}")))?;

    let mut key = [0u8; 16];
    key.copy_from_slice(&tag[..16]);
    Ok(key)
}

/// Exchange the even-indexed bytes of `padding` and `cipher`.
///
/// The operation is its own inverse, which is the whole trick: the writer
/// randomises the low bytes of the record's opening while the payload it masks
/// is still recoverable by the reader, and neither side needs to know the
/// other's padding bytes.
fn swap_even(padding: &mut [u8], cipher: &mut [u8]) {
    let limit = padding.len().min(cipher.len());
    let mut index = 0;
    while index < limit {
        std::mem::swap(&mut padding[index], &mut cipher[index]);
        index += 2;
    }
}

/// The 7-byte plaintext header.
fn encode_header(padding_len: usize, payload_len: usize) -> [u8; HEADER_PLAIN_LEN] {
    let mut header = [0u8; HEADER_PLAIN_LEN];
    header[0] = HEADER_VERSION;
    header[3..5].copy_from_slice(&(padding_len as u16).to_be_bytes());
    header[5..7].copy_from_slice(&(payload_len as u16).to_be_bytes());
    header
}

/// The parsed 7-byte header.
fn decode_header(plain: &[u8]) -> Result<(usize, usize)> {
    if plain.len() != HEADER_PLAIN_LEN {
        return Err(Error::protocol(format!(
            "Snell header is {} bytes, expected {HEADER_PLAIN_LEN}",
            plain.len()
        )));
    }
    if plain[0] != HEADER_VERSION {
        return Err(Error::protocol(format!(
            "Snell record header version is 0x{:02x}, expected 0x{HEADER_VERSION:02x}",
            plain[0]
        )));
    }
    // The reference leaves these two bytes zero; anything else means the record
    // is not the shape this implementation understands.
    if plain[1] != 0 || plain[2] != 0 {
        return Err(Error::protocol(format!(
            "Snell header reserved bytes are {:02x} {:02x}, expected zero",
            plain[1], plain[2]
        )));
    }
    let padding_len = usize::from(u16::from_be_bytes([plain[3], plain[4]]));
    let payload_len = usize::from(u16::from_be_bytes([plain[5], plain[6]]));
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(Error::protocol(format!(
            "Snell record declares {payload_len} payload bytes, above the {MAX_PAYLOAD_LEN} cap"
        )));
    }
    Ok((padding_len, payload_len))
}

/// The request body: `[0x01][command][u8 cid len][cid][u8 host len][host][u16 port]`
///
/// The host is a SOCKS-style length-prefixed string even when it is an address
/// literal, which is what the reference's `WriteConnectAddress` does.
fn encode_request(command: u8, client_id: &[u8], target: &TargetAddr) -> Vec<u8> {
    let host = target.host();
    let host = host.as_bytes();
    let host_len = u8::try_from(host.len()).unwrap_or(u8::MAX);
    let client_id = &client_id[..client_id.len().min(usize::from(u8::MAX))];

    let mut out = Vec::with_capacity(4 + client_id.len() + 1 + host.len() + 2);
    out.push(REQUEST_VERSION);
    out.push(command);
    out.push(client_id.len() as u8);
    out.extend_from_slice(client_id);
    out.push(host_len);
    out.extend_from_slice(&host[..host_len as usize]);
    out.extend_from_slice(&target.port().to_be_bytes());
    out
}

/// Where a record's padding length comes from.
fn padding_len(first: bool) -> usize {
    let mut byte = [0u8; 2];
    fill_random(&mut byte);
    let draw = usize::from(u16::from_be_bytes(byte));
    if first {
        INITIAL_PADDING_MIN + draw % INITIAL_PADDING_SPAN
    } else {
        1 + draw % LATER_PADDING_MAX
    }
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    fill_random(&mut out);
    out
}

/// Fill `buf` completely, reporting `false` only when the stream ended before
/// its first byte.
///
/// `Read::read` is allowed to return a short count, so a single call cannot
/// distinguish "nothing yet" from "nothing ever".
fn read_or_eof(inner: &mut BoxStream, buf: &mut [u8]) -> std::io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match inner.read(&mut buf[filled..])? {
            0 if filled == 0 => return Ok(false),
            0 => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "stream ended inside a Snell record",
                ))
            }
            n => filled += n,
        }
    }
    Ok(true)
}

/// A Snell session as a duplex stream: records in, records out.
///
/// `read` decodes whole records into a buffer and serves bytes from it;
/// `write` seals each call into one record (splitting at the payload ceiling).
struct SnellStream {
    inner: BoxStream,
    /// Key for the server→client direction, established when the server's salt
    /// is read.
    read: Option<Direction>,
    /// Key and salt state for the client→server direction.
    write: Option<Direction>,
    psk: Vec<u8>,
    decode: Vec<u8>,
    decode_pos: usize,
}

impl SnellStream {
    fn new(inner: BoxStream, psk: &[u8]) -> Self {
        Self {
            inner,
            read: None,
            write: None,
            psk: psk.to_vec(),
            decode: Vec::new(),
            decode_pos: 0,
        }
    }

    fn buffered(&self) -> usize {
        self.decode.len() - self.decode_pos
    }

    /// Decode one record into the buffer.
    ///
    /// `Ok(false)` means the peer closed the connection cleanly between
    /// records. That distinction cannot be recovered from an `UnexpectedEof`
    /// later, which is why the salt read probes for EOF first: a truncated
    /// record and a finished stream look identical otherwise, and one is an
    /// error while the other is how every connection ends.
    fn read_record(&mut self) -> Result<bool> {
        if self.read.is_none() {
            let mut salt = [0u8; SALT_LEN];
            if !read_or_eof(&mut self.inner, &mut salt)
                .map_err(|e| Error::network(format!("Failed to read the Snell salt: {e}")))?
            {
                return Ok(false);
            }
            self.read = Some(Direction::new(derive_key(&self.psk, &salt)?));
        }
        let direction = self.read.as_mut().expect("just initialised");

        let mut header = [0u8; HEADER_CIPHER_LEN];
        self.inner
            .read_exact(&mut header)
            .map_err(|e| Error::network(format!("Failed to read a Snell header: {e}")))?;
        let plain = direction.open(&header)?;
        let (padding_len, payload_len) = decode_header(&plain)?;

        let mut padding = vec![0u8; padding_len];
        if padding_len > 0 {
            self.inner
                .read_exact(&mut padding)
                .map_err(|e| Error::network(format!("Failed to read Snell padding: {e}")))?;
        }
        let mut payload = vec![0u8; payload_len + AEAD_TAG_LEN];
        self.inner
            .read_exact(&mut payload)
            .map_err(|e| Error::network(format!("Failed to read a Snell payload: {e}")))?;

        swap_even(&mut padding, &mut payload);
        let plain = direction.open(&payload)?;
        if plain.len() != payload_len {
            return Err(Error::protocol(format!(
                "Snell record decoded to {} bytes, header declared {payload_len}",
                plain.len()
            )));
        }
        self.decode.clear();
        self.decode_pos = 0;
        self.decode.extend_from_slice(&plain);
        Ok(true)
    }

    /// Seal `buf` into one record and write it.
    fn write_record(&mut self, buf: &[u8]) -> Result<usize> {
        let take = buf.len().min(MAX_PAYLOAD_LEN);
        let first = self.write.is_none();

        let mut out =
            Vec::with_capacity(SALT_LEN + HEADER_CIPHER_LEN + 0x200 + take + AEAD_TAG_LEN);
        if first {
            let mut salt = [0u8; SALT_LEN];
            fill_random(&mut salt);
            self.write = Some(Direction::new(derive_key(&self.psk, &salt)?));
            out.extend_from_slice(&salt);
        }
        let direction = self.write.as_mut().expect("just initialised");

        let padding_len = padding_len(first);
        let sealed_header = direction.seal(&encode_header(padding_len, take))?;
        let mut padding = random_bytes(padding_len);
        let mut payload = direction.seal(&buf[..take])?;
        swap_even(&mut padding, &mut payload);

        out.extend_from_slice(&sealed_header);
        out.extend_from_slice(&padding);
        out.extend_from_slice(&payload);

        self.inner
            .write_all(&out)
            .map_err(|e| Error::network(format!("Failed to write a Snell record: {e}")))?;
        Ok(take)
    }
}

impl Read for SnellStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.buffered() == 0 {
            match self.read_record() {
                Ok(true) => {}
                // A clean close between records is the end of the stream.
                Ok(false) => return Ok(0),
                Err(e) => return Err(std::io::Error::other(e.to_string())),
            }
        }
        let take = self.buffered().min(buf.len());
        buf[..take].copy_from_slice(&self.decode[self.decode_pos..self.decode_pos + take]);
        self.decode_pos += take;
        Ok(take)
    }
}

impl Write for SnellStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.write_record(buf)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl SyncStream for SnellStream {
    fn shutdown(&self, how: Shutdown) -> std::io::Result<()> {
        if how == Shutdown::Both {
            self.inner.shutdown(how)
        } else {
            Ok(())
        }
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.inner.peer_addr()
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.inner.set_write_timeout(timeout)
    }
}

/// The `obfs: http` dressing: a WebSocket-upgrade `GET` before the first write,
/// and a skipped `101` response before the first read.
///
/// The `Content-Length` is the length of the record that follows, so the two
/// are one HTTP body as far as anything reading the connection is concerned.
struct ObfsHttpStream {
    inner: BoxStream,
    host: String,
    uri: String,
    header_sent: bool,
    response_skipped: bool,
}

impl ObfsHttpStream {
    fn new(inner: BoxStream, host: String, uri: String) -> Self {
        Self {
            inner,
            host,
            uri,
            header_sent: false,
            response_skipped: false,
        }
    }

    /// The fabricated request head, with a per-process user agent and key.
    fn request_head(&self, body_len: usize) -> Vec<u8> {
        use std::sync::OnceLock;
        static FINGERPRINT: OnceLock<(String, String)> = OnceLock::new();
        let (agent, key) = FINGERPRINT.get_or_init(|| {
            let mut pick = [0u8; 1];
            fill_random(&mut pick);
            let agent = OBFS_USER_AGENTS[usize::from(pick[0]) % OBFS_USER_AGENTS.len()].to_string();
            let mut key_bytes = [0u8; 16];
            fill_random(&mut key_bytes);
            let key = courierust::courierust_crypto::base64::encode(&key_bytes);
            (agent, key)
        });

        format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nContent-Length: {}\r\nSec-WebSocket-Key: {}\r\n\r\n",
            self.uri, self.host, agent, body_len, key
        )
        .into_bytes()
    }
}

impl Read for ObfsHttpStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.response_skipped {
            self.response_skipped = true;
            let mut seen = Vec::new();
            let mut byte = [0u8; 1];
            while !seen.ends_with(b"\r\n\r\n") {
                if seen.len() >= MAX_OBFS_HEADER {
                    return Err(std::io::Error::other(
                        "Snell http obfs: server response head exceeded the cap",
                    ));
                }
                match self.inner.read(&mut byte)? {
                    0 => break,
                    _ => seen.push(byte[0]),
                }
            }
        }
        self.inner.read(buf)
    }
}

impl Write for ObfsHttpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.header_sent {
            self.header_sent = true;
            let head = self.request_head(buf.len());
            self.inner.write_all(&head)?;
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl SyncStream for ObfsHttpStream {
    fn shutdown(&self, how: Shutdown) -> std::io::Result<()> {
        self.inner.shutdown(how)
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.inner.peer_addr()
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.inner.set_write_timeout(timeout)
    }

    /// `None` on purpose: the obfs header has to be written before anything
    /// else, and a shared-handle relay would write around it.
    fn shared_handle(&self) -> Option<crate::common::stream::SharedStream> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(options: &[(&str, nextjson::Value)]) -> OutboundConfig {
        let mut map = HashMap::new();
        for (k, v) in options {
            map.insert((*k).to_string(), v.clone());
        }
        OutboundConfig {
            tag: "snell-test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Snell,
            server: Some("snell.example".to_string()),
            port: Some(443),
            options: map,
        }
    }

    fn string(value: &str) -> nextjson::Value {
        nextjson::Value::String(value.to_string())
    }

    fn build(options: &[(&str, nextjson::Value)]) -> Result<SnellConfig> {
        SnellOutbound::new(config(options)).map(|o| o.snell_config().clone())
    }

    fn psk() -> Vec<(&'static str, nextjson::Value)> {
        vec![("psk", string("test-psk"))]
    }

    #[test]
    fn the_request_is_the_documented_byte_layout() {
        let target = TargetAddr::Domain("example.com".to_string(), 443);
        let request = encode_request(COMMAND_CONNECT_V2, b"cid", &target);
        assert_eq!(request[0], REQUEST_VERSION);
        assert_eq!(request[1], COMMAND_CONNECT_V2);
        assert_eq!(request[2], 3, "client id length");
        assert_eq!(&request[3..6], b"cid");
        assert_eq!(request[6], 11, "host length");
        assert_eq!(&request[7..18], b"example.com");
        assert_eq!(&request[18..20], &443u16.to_be_bytes());
        assert_eq!(request.len(), 20);
    }

    #[test]
    fn an_address_literal_goes_out_as_text_in_the_same_field() {
        let target = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        let request = encode_request(COMMAND_CONNECT_V2, b"", &target);
        assert_eq!(request[2], 0, "empty client id");
        assert_eq!(request[3], 7, "host length");
        assert_eq!(&request[4..11], b"1.2.3.4");
        assert_eq!(&request[11..13], &53u16.to_be_bytes());
    }

    #[test]
    fn the_header_carries_the_lengths_big_endian_in_the_documented_offsets() {
        let header = encode_header(0x0102, 0x0304);
        assert_eq!(header, [0x04, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(decode_header(&header).unwrap(), (0x0102, 0x0304));
    }

    #[test]
    fn a_header_that_is_not_this_shape_is_refused() {
        let mut wrong_version = encode_header(0, 10);
        wrong_version[0] = 0x03;
        assert!(decode_header(&wrong_version).is_err());

        let mut reserved = encode_header(0, 10);
        reserved[1] = 1;
        assert!(decode_header(&reserved).is_err());
        assert_eq!(
            decode_header(&encode_header(0, MAX_PAYLOAD_LEN)).unwrap().1,
            MAX_PAYLOAD_LEN
        );
        assert!(
            decode_header(&[0x04, 0, 0, 0, 0, 0]).is_err(),
            "short header"
        );
    }

    #[test]
    fn the_padding_swap_is_its_own_inverse_and_only_touches_even_indices() {
        let mut padding = vec![1u8, 2, 3, 4, 5, 6];
        let mut cipher = vec![9u8, 8, 7, 6, 5];
        let (original_padding, original_cipher) = (padding.clone(), cipher.clone());

        swap_even(&mut padding, &mut cipher);
        assert_eq!(padding[..4], [9, 2, 7, 4], "even indices exchanged");
        assert_eq!(cipher[..4], [1, 8, 3, 6]);
        assert_eq!(padding[4], 5, "beyond the shorter slice stays put");
        assert_eq!(padding[5], 6);

        swap_even(&mut padding, &mut cipher);
        assert_eq!(padding, original_padding, "applying it twice restores");
        assert_eq!(cipher, original_cipher);
    }

    #[test]
    fn the_nonce_advances_once_per_aead_operation() {
        let mut direction = Direction::new([0u8; 16]);
        assert_eq!(direction.nonce, [0u8; NONCE_LEN]);
        let _ = direction.seal(b"header").unwrap();
        assert_eq!(direction.nonce[0], 1);
        let _ = direction.seal(b"payload").unwrap();
        assert_eq!(direction.nonce[0], 2);
        direction.nonce[0] = 0xff;
        direction.advance();
        assert_eq!(direction.nonce[0], 0);
        assert_eq!(direction.nonce[1], 1);
    }

    #[test]
    fn a_record_sealed_with_one_key_does_not_open_with_another() {
        let mut a = Direction::new([1u8; 16]);
        let mut b = Direction::new([2u8; 16]);
        let sealed = a.seal(b"secret").unwrap();
        assert!(
            b.open(&sealed).is_err(),
            "a different key must fail the tag"
        );
    }

    #[test]
    fn a_failed_open_does_not_advance_the_counter() {
        let mut direction = Direction::new([3u8; 16]);
        assert!(direction.open(&[0u8; 32]).is_err());
        assert_eq!(direction.nonce, [0u8; NONCE_LEN]);
    }

    #[test]
    fn key_derivation_is_deterministic_and_salt_dependent() {
        let a = derive_key(b"psk", b"0123456789abcdef").unwrap();
        let b = derive_key(b"psk", b"0123456789abcdef").unwrap();
        assert_eq!(a, b);
        let c = derive_key(b"psk", b"fedcba9876543210").unwrap();
        assert_ne!(a, c);
        let d = derive_key(b"psK", b"0123456789abcdef").unwrap();
        assert_ne!(a, d);
    }

    #[test]
    fn the_psk_is_required() {
        let err = build(&[]).unwrap_err().to_string();
        assert!(err.contains("psk"), "{err}");
        assert!(build(&[("psk", string(""))]).is_err());
        assert!(
            build(&[("password", string("x"))]).is_ok(),
            "alias accepted"
        );
    }

    #[test]
    fn versions_4_and_5_share_the_wire_and_others_are_refused_with_a_reason() {
        assert_eq!(build(&psk()).unwrap().version, 4, "default");
        assert_eq!(
            build(&[
                ("psk", string("x")),
                (
                    "version",
                    nextjson::Value::Number(nextjson::Number::from(5))
                )
            ])
            .unwrap()
            .version,
            5
        );

        let six = build(&[
            ("psk", string("x")),
            (
                "version",
                nextjson::Value::Number(nextjson::Number::from(6)),
            ),
        ])
        .unwrap_err()
        .to_string();
        assert!(six.contains("shaped"), "{six}");

        let three = build(&[
            ("psk", string("x")),
            (
                "version",
                nextjson::Value::Number(nextjson::Number::from(3)),
            ),
        ])
        .unwrap_err()
        .to_string();
        assert!(three.contains("Argon2id"), "{three}");
    }

    #[test]
    fn http_obfs_is_accepted_with_its_defaults_and_tls_obfs_is_refused() {
        let cfg = build(&[("psk", string("x")), ("obfs", string("HTTP"))]).unwrap();
        assert_eq!(
            cfg.obfs,
            SnellObfs::Http {
                host: "bing.com".to_string(),
                uri: "/".to_string()
            }
        );

        let cfg = build(&[
            ("psk", string("x")),
            ("obfs", string("http")),
            ("obfs-host", string("cdn.example")),
            ("obfs-uri", string("/ws")),
        ])
        .unwrap();
        assert_eq!(
            cfg.obfs,
            SnellObfs::Http {
                host: "cdn.example".to_string(),
                uri: "/ws".to_string()
            }
        );

        let tls = build(&[("psk", string("x")), ("obfs", string("tls"))])
            .unwrap_err()
            .to_string();
        assert!(tls.contains("ClientHello"), "{tls}");

        let other = build(&[("psk", string("x")), ("obfs", string("plain"))])
            .unwrap_err()
            .to_string();
        assert!(other.contains("Unknown Snell obfs"), "{other}");
    }

    #[test]
    fn a_relative_obfs_uri_falls_back_to_the_root() {
        let cfg = build(&[
            ("psk", string("x")),
            ("obfs", string("http")),
            ("obfs-uri", string("ws")),
        ])
        .unwrap();
        assert_eq!(
            cfg.obfs,
            SnellObfs::Http {
                host: "bing.com".to_string(),
                uri: "/".to_string()
            }
        );
    }

    #[test]
    fn the_client_id_is_configurable_and_empty_by_default() {
        assert!(build(&psk()).unwrap().client_id.is_empty());
        let cfg = build(&[("psk", string("x")), ("client-id", string("user1"))]).unwrap();
        assert_eq!(cfg.client_id, b"user1");
    }

    /// A full round trip against a server written from the same layout: the
    /// request bytes on the wire, both directions' salts, the record framing,
    /// the padding swap and the nonce accounting all have to agree.
    ///
    /// This does not prove interop with a real Snell server — only the
    /// byte-exact tests above can pin the layout, and only a real server can
    /// confirm it. It does prove the two halves of *this* implementation are
    /// consistent, which is where the framing bugs live.
    #[test]
    fn a_full_session_round_trips_against_a_mirror_server() {
        use std::io::Read as _;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let mut conn = SnellStream::new(Box::new(tcp), b"test-psk");
            let mut head = [0u8; 3];
            conn.read_exact(&mut head).unwrap();
            assert_eq!(head[0], REQUEST_VERSION);
            assert_eq!(head[1], COMMAND_CONNECT_V2);
            let mut client_id = vec![0u8; usize::from(head[2])];
            conn.read_exact(&mut client_id).unwrap();
            let mut host_len = [0u8; 1];
            conn.read_exact(&mut host_len).unwrap();
            let mut tail = vec![0u8; usize::from(host_len[0]) + 2];
            conn.read_exact(&mut tail).unwrap();
            assert_eq!(&tail[..tail.len() - 2], b"target.example");
            assert_eq!(&tail[tail.len() - 2..], &80u16.to_be_bytes());

            conn.write_all(b"\x00HELLO").unwrap();
            conn.flush().unwrap();

            let mut buf = [0u8; 32];
            let n = conn.read(&mut buf).unwrap();
            conn.write_all(&buf[..n]).unwrap();
            conn.flush().unwrap();
        });

        let out = SnellOutbound::new(OutboundConfig {
            tag: "snell".to_string(),
            outbound_type: crate::engine::config::OutboundType::Snell,
            server: Some("127.0.0.1".to_string()),
            port: Some(port),
            options: HashMap::from([("psk".to_string(), string("test-psk"))]),
        })
        .unwrap();

        let mut stream = out
            .open(
                &TargetAddr::Domain("target.example".to_string(), 80),
                Duration::from_secs(5),
            )
            .expect("session opens");

        let mut greeting = [0u8; 5];
        stream.read_exact(&mut greeting).unwrap();
        assert_eq!(&greeting, b"HELLO");

        stream.write_all(b"ping").unwrap();
        let mut echoed = [0u8; 4];
        stream.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"ping");

        server.join().unwrap();
    }

    #[test]
    fn a_refused_request_surfaces_the_server_message() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let mut conn = SnellStream::new(Box::new(tcp), b"test-psk");
            let mut discard = [0u8; 32];
            let _ = conn.read(&mut discard);
            conn.write_all(b"\x02\x05\x04nope").unwrap();
            conn.flush().unwrap();
        });

        let out = SnellOutbound::new(OutboundConfig {
            tag: "snell".to_string(),
            outbound_type: crate::engine::config::OutboundType::Snell,
            server: Some("127.0.0.1".to_string()),
            port: Some(port),
            options: HashMap::from([("psk".to_string(), string("test-psk"))]),
        })
        .unwrap();

        let err = out
            .open(
                &TargetAddr::Domain("target.example".to_string(), 80),
                Duration::from_secs(5),
            )
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(err.contains("code 5"), "{err}");
        assert!(err.contains("nope"), "{err}");
    }
}
