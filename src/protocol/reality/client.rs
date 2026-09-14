//! REALITY handshake glue: config parsing, the `ClientHello` hook that seals
//! the session id, and the server authentication that replaces the CA chain.

use super::wire::{
    client_shared_secret, derive_auth_key, seal_session_id, verify_ephemeral_certificate,
    SessionMeta, MAX_SHORT_ID_LEN,
};
use super::{client_version, RealityError, Result as RealityResult};
use crate::common::stream::BoxStream;
use crate::protocol::tls13::client::{
    connect as tls13_connect, ClientHelloDraft, ClientHelloHook, ServerAuth, Tls13ClientConfig,
};
use crate::protocol::tls13::fingerprint::Fingerprint;
use crate::protocol::tls13::{Result as Tls13Result, Tls13Error};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use courierust::courierust_tls::x509::Certificate;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Timeout for the TLS handshake (a REALITY server answers quickly, but a
/// decoy site may be slower).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// Read timeout used by the relay after the handshake (mirrors the engine's
/// TLS connector so a blocked reader cannot starve the writer).
const RELAY_READ_TIMEOUT: Duration = Duration::from_millis(1000);
/// Write timeout for the handshake and the relay.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// REALITY client settings, parsed and validated from an outbound's options.
#[derive(Debug, Clone)]
pub struct RealityClientOptions {
    /// The server's static X25519 public key (`public-key`, also spelled
    /// `password` in the reference config).
    pub public_key: [u8; 32],
    /// Short id (`short-id`), hex decoded, at most 8 bytes.
    pub short_id: Vec<u8>,
    /// Decoy SNI (`server-name` / `sni`); must be one of the server's
    /// configured `serverNames`.
    pub server_name: String,
    /// `ClientHello` shape (`fingerprint`), `chrome` by default.
    pub fingerprint: Fingerprint,
    /// `spider-x`: accepted for config compatibility; crawling is not
    /// implemented (a fallback is reported as an error instead).
    pub spider_x: Option<String>,
}

impl RealityClientOptions {
    /// Parse the REALITY fields out of an outbound's `options` map.
    ///
    /// Every missing or malformed field is an error naming the field; no
    /// default silently weakens authentication. `default_server_name` is used
    /// when the options do not carry a decoy name (the outbound's `sni`).
    pub fn from_options(
        options: &HashMap<String, nextjson::Value>,
        default_server_name: &str,
    ) -> RealityResult<Self> {
        let public_key_str = options
            .get("public-key")
            .or_else(|| options.get("public_key"))
            .or_else(|| options.get("password"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                RealityError::Config("missing 'public-key' (the server's X25519 public key)".into())
            })?;
        let public_key = decode_public_key(public_key_str)?;

        let short_id = match options.get("short-id").or_else(|| options.get("short_id")) {
            Some(v) => {
                let hex = v
                    .as_str()
                    .ok_or_else(|| RealityError::Config("'short-id' must be a string".into()))?;
                let bytes = crate::crypto::codec::hex_decode(hex.as_bytes()).map_err(|e| {
                    RealityError::Config(alloc::format!("'short-id' is not valid hex: {e:?}"))
                })?;
                if bytes.len() > MAX_SHORT_ID_LEN {
                    return Err(RealityError::Config(alloc::format!(
                        "'short-id' decodes to {} bytes; the limit is {MAX_SHORT_ID_LEN}",
                        bytes.len()
                    )));
                }
                bytes
            }
            None => Vec::new(),
        };

        let server_name = options
            .get("server-name")
            .or_else(|| options.get("server_name"))
            .or_else(|| options.get("sni"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                let fallback = default_server_name.trim();
                (!fallback.is_empty()).then(|| fallback.to_string())
            })
            .ok_or_else(|| {
                RealityError::Config(
                    "missing 'server-name' (the decoy SNI the server offers)".into(),
                )
            })?;

        let fingerprint = match options.get("fingerprint").and_then(|v| v.as_str()) {
            Some(name) if !name.trim().is_empty() => {
                Fingerprint::parse(name).map_err(|e| RealityError::Config(e.to_string()))?
            }
            _ => Fingerprint::Chrome,
        };

        // Configured but not implemented: fail closed instead of ignoring.
        if let Some(mldsa) = options
            .get("mldsa65-verify")
            .or_else(|| options.get("mldsa65_verify"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
        {
            return Err(RealityError::Unsupported(alloc::format!(
                "'mldsa65-verify' is set ({} bytes) but ML-DSA-65 verification is not implemented",
                mldsa.len()
            )));
        }

        let spider_x = options
            .get("spider-x")
            .or_else(|| options.get("spider_x"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(Self {
            public_key,
            short_id,
            server_name,
            fingerprint,
            spider_x,
        })
    }
}

fn decode_public_key(text: &str) -> RealityResult<[u8; 32]> {
    let trimmed = text.trim();
    // A 64-character hex string is accepted as well; the reference prints
    // X25519 keys in base64.
    let bytes = if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        crate::crypto::codec::hex_decode(trimmed.as_bytes())
            .map_err(|e| RealityError::Config(alloc::format!("'public-key' hex: {e:?}")))?
    } else {
        crate::crypto::codec::base64_decode(trimmed)
            .ok_or_else(|| RealityError::Config("'public-key' is not valid base64".into()))?
    };
    if bytes.len() != 32 {
        return Err(RealityError::Config(alloc::format!(
            "'public-key' must decode to 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Shared slot between the `ClientHello` hook (which computes the auth key)
/// and the server authentication (which checks the proof).
type AuthKeySlot = Arc<Mutex<Option<[u8; 32]>>>;

struct RealityHook {
    server_public: [u8; 32],
    short_id: Vec<u8>,
    auth_key: AuthKeySlot,
}

impl ClientHelloHook for RealityHook {
    fn on_client_hello(&mut self, draft: &mut ClientHelloDraft<'_>) -> Tls13Result<()> {
        let shared = client_shared_secret(draft.key_share_private, &self.server_public);
        let auth_key = derive_auth_key(&shared, draft.random);
        let meta = SessionMeta {
            version: client_version(),
            timestamp: unix_now(),
            short_id_len: self.short_id.len() as u8,
        };
        seal_session_id(&auth_key, draft.random, draft.raw, &meta, &self.short_id)
            .map_err(Tls13Error::from)?;
        *self.auth_key.lock() = Some(auth_key);
        Ok(())
    }
}

struct RealityAuth {
    auth_key: AuthKeySlot,
}

impl ServerAuth for RealityAuth {
    fn verify_certificate(
        &mut self,
        _leaf_der: &[u8],
        leaf: &Certificate,
        _chain: &[Vec<u8>],
    ) -> Tls13Result<()> {
        let auth_key = (*self.auth_key.lock()).ok_or_else(|| {
            Tls13Error::Certificate(
                "REALITY: certificate received before the session id was sealed".into(),
            )
        })?;
        if verify_ephemeral_certificate(&auth_key, &leaf.spki.key, &leaf.signature) {
            return Ok(());
        }
        Err(Tls13Error::Certificate(
            "REALITY fallback: the server presented a real certificate, so this session was not \
             authenticated by the configured public key (rejection, redirection, or a man in the \
             middle)"
                .into(),
        ))
    }
}

/// Perform a REALITY handshake over `stream` and return the relay stream.
///
/// `alpn` is what the tunnel negotiates with the server (the decoy site's
/// protocols are what the reference offers, so `h2` + `http/1.1` are the
/// defaults).
pub fn connect(
    stream: TcpStream,
    options: RealityClientOptions,
    alpn: Vec<String>,
) -> RealityResult<BoxStream> {
    let _ = &options.spider_x; // parsed for compatibility; see the module docs

    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));

    let auth_key: AuthKeySlot = Arc::new(Mutex::new(None));
    let hook = RealityHook {
        server_public: options.public_key,
        short_id: options.short_id.clone(),
        auth_key: auth_key.clone(),
    };
    let auth = RealityAuth {
        auth_key: auth_key.clone(),
    };

    // One socket, several shared handles: the TLS stream owns the reader and
    // writer, this module keeps one for socket-wide timeouts and half-close.
    let socket = crate::common::shared_socket::SharedTcpStream::new(stream);
    let reader = socket.clone();
    let writer = socket.clone();
    let control = socket.clone();
    let hook_socket = socket.clone();
    let shutdown_hook = Some(
        Arc::new(move |how: std::net::Shutdown| hook_socket.shutdown(how))
            as Arc<dyn Fn(std::net::Shutdown) -> std::io::Result<()> + Send + Sync>,
    );

    let config = Tls13ClientConfig {
        server_name: options.server_name.clone(),
        alpn,
        fingerprint: options.fingerprint.clone(),
        now: unix_now_i64(),
        roots: None,
        verify: false, // authentication is the REALITY proof, not a CA chain
        auth: Some(Box::new(auth)),
        hello_hook: Some(Box::new(hook)),
        compatibility_ccs: true,
        shutdown_hook,
    };

    let tls = tls13_connect(reader, writer, config).map_err(|e| match e {
        Tls13Error::Certificate(m) => RealityError::Fallback(m),
        other => RealityError::Wire(other.to_string()),
    })?;

    // The relay reads with a bounded timeout so its writer thread is never
    // starved (same cadence as `protocol::tls`). The timeout is a property of
    // the socket, so the control handle updates the stream's reads too.
    let _ = control.set_read_timeout(Some(RELAY_READ_TIMEOUT));

    Ok(Box::new(tls) as BoxStream)
}

fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

fn unix_now_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
