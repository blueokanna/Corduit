//! TLS 1.3 client handshake over QUIC (RFC 8446 §4 + RFC 9001 §4).
//!
//! courierust's own TLS layer keeps its handshake/key-schedule machinery in
//! `pub(crate)` modules, so this module reimplements the client side of the
//! handshake on top of the **public** primitives:
//!
//! * [`courierust::courierust_tls::crypto`] — SHA-256/384, HKDF, X25519,
//!   RSA-PSS / ECDSA / Ed25519 signature verification;
//! * [`courierust::courierust_tls::x509`] — certificate parsing + chain
//!   validation + hostname matching;
//! * [`courierust::courierust_quic::protection::PacketKey`] — QUIC traffic
//!   keys derived from the TLS traffic secrets.
//!
//! The transcript hashes the TLS handshake messages as a byte stream (the
//! QUIC CRYPTO stream) exactly as RFC 8446 §4.4.1 requires.

use courierust::courierust_quic::protection::PacketKey;
use courierust::courierust_tls::crypto::hash::Digest as _;
use courierust::courierust_tls::crypto::hash::{Sha256, Sha384};
use courierust::courierust_tls::crypto::{ed25519, hmac, rng, x25519};
use courierust::courierust_tls::x509::{self, Certificate, RootStore, Spki};

use super::error::{QuicError, Result};

/// TLS 1.3 cipher suite: TLS_AES_128_GCM_SHA256.
const SUITE_AES_128: u16 = 0x1301;
/// TLS 1.3 cipher suite: TLS_AES_256_GCM_SHA384.
const SUITE_AES_256: u16 = 0x1302;
/// TLS 1.3 cipher suite: TLS_CHACHA20_POLY1305_SHA256.
const SUITE_CHACHA: u16 = 0x1303;

/// Handshake message types (RFC 8446 §4).
const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;

/// Extension types (RFC 8446 §4.2).
const EXT_SERVER_NAME: u16 = 0;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_ALPN: u16 = 16;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_KEY_SHARE: u16 = 51;

/// QUIC transport parameters extension type (RFC 9001 §8.2).
const EXT_QUIC_TP: u16 = 0x39;

/// Signature schemes we offer (RFC 8446 §4.2.3); SHA-512 variants are
/// intentionally omitted (courierust's crypto layer has no public SHA-512).
const SIG_RSA_PSS_SHA256: u16 = 0x0804;
const SIG_RSA_PSS_SHA384: u16 = 0x0805;
const SIG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
const SIG_ECDSA_SECP384R1_SHA384: u16 = 0x0503;
const SIG_ED25519: u16 = 0x0807;

/// The HelloRetryRequest random (RFC 8446 §4.1.3).
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];
/// TLS 1.3 downgrade sentinel for TLS 1.2 (RFC 8446 §4.1.3).
const DOWNGRADE_TLS12: [u8; 8] = [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00];

/// The hash length of the negotiated cipher suite (32 for SHA-256, 48 for
/// SHA-384).
fn suite_hash_len(suite: u16) -> usize {
    if suite == SUITE_AES_256 {
        48
    } else {
        32
    }
}

// ---------------------------------------------------------------------------
// QUIC transport parameters (RFC 9000 §18)
// ---------------------------------------------------------------------------

/// Transport parameters negotiated during the handshake.
#[derive(Debug, Clone)]
pub(crate) struct TransportParameters {
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub max_udp_payload_size: u64,
    pub ack_delay_exponent: u64,
    pub max_ack_delay: u64,
    pub initial_source_connection_id: Vec<u8>,
    pub disable_active_migration: bool,
}

impl Default for TransportParameters {
    fn default() -> Self {
        Self {
            max_udp_payload_size: 1200,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            ..Self::empty()
        }
    }
}

impl TransportParameters {
    fn empty() -> Self {
        Self {
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            max_udp_payload_size: 0,
            ack_delay_exponent: 0,
            max_ack_delay: 0,
            initial_source_connection_id: Vec::new(),
            disable_active_migration: false,
        }
    }
}

/// Transport parameter identifiers.
const TP_INITIAL_MAX_DATA: u64 = 0x04;
const TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
const TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
const TP_INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
const TP_INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
const TP_INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
const TP_ACK_DELAY_EXPONENT: u64 = 0x0a;
const TP_MAX_ACK_DELAY: u64 = 0x0b;
const TP_DISABLE_ACTIVE_MIGRATION: u64 = 0x0c;
const TP_INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0f;
const TP_MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;

/// Encode the client's transport parameters (extension value body, without
/// the 2-byte extension type/length).
pub(crate) fn encode_client_tp(tp: &TransportParameters, scid: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    push_tp(&mut out, TP_INITIAL_MAX_DATA, &varint(tp.initial_max_data));
    push_tp(
        &mut out,
        TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
        &varint(tp.initial_max_stream_data_bidi_local),
    );
    push_tp(
        &mut out,
        TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
        &varint(tp.initial_max_stream_data_bidi_remote),
    );
    push_tp(
        &mut out,
        TP_INITIAL_MAX_STREAM_DATA_UNI,
        &varint(tp.initial_max_stream_data_uni),
    );
    push_tp(
        &mut out,
        TP_INITIAL_MAX_STREAMS_BIDI,
        &varint(tp.initial_max_streams_bidi),
    );
    push_tp(
        &mut out,
        TP_INITIAL_MAX_STREAMS_UNI,
        &varint(tp.initial_max_streams_uni),
    );
    push_tp(
        &mut out,
        TP_MAX_UDP_PAYLOAD_SIZE,
        &varint(tp.max_udp_payload_size),
    );
    push_tp(
        &mut out,
        TP_ACK_DELAY_EXPONENT,
        &varint(tp.ack_delay_exponent),
    );
    push_tp(&mut out, TP_MAX_ACK_DELAY, &varint(tp.max_ack_delay));
    push_tp(&mut out, TP_DISABLE_ACTIVE_MIGRATION, &[]);
    let mut scid_tp = varint(scid.len() as u64);
    scid_tp.extend_from_slice(scid);
    push_tp(&mut out, TP_INITIAL_SOURCE_CONNECTION_ID, &scid_tp);
    out
}

fn push_tp(out: &mut Vec<u8>, id: u64, value: &[u8]) {
    out.extend_from_slice(&varint(id));
    out.extend_from_slice(&varint(value.len() as u64));
    out.extend_from_slice(value);
}

/// Encode a QUIC varint (RFC 9000 §16).
fn varint(v: u64) -> Vec<u8> {
    if v < 64 {
        vec![v as u8]
    } else if v < 16384 {
        vec![0x40 | ((v >> 8) as u8), (v & 0xff) as u8]
    } else if v < 1 << 30 {
        vec![
            0x80 | ((v >> 24) as u8),
            ((v >> 16) as u8),
            ((v >> 8) as u8),
            (v as u8),
        ]
    } else {
        vec![
            0xc0 | ((v >> 56) as u8),
            ((v >> 48) as u8),
            ((v >> 40) as u8),
            ((v >> 32) as u8),
            ((v >> 24) as u8),
            ((v >> 16) as u8),
            ((v >> 8) as u8),
            (v as u8),
        ]
    }
}

/// Parse a QUIC varint, returning `(value, bytes_consumed)`.
fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64> {
    let b0 = *buf
        .get(*pos)
        .ok_or_else(|| QuicError::Protocol("truncated varint".into()))?;
    let len = 1usize << (b0 >> 6);
    if buf.len() - *pos < len {
        return Err(QuicError::Protocol("truncated varint".into()));
    }
    let mut v: u64 = (b0 & 0x3f) as u64;
    for i in 1..len {
        v = (v << 8) | buf[*pos + i] as u64;
    }
    *pos += len;
    Ok(v)
}

/// Parse the peer's transport parameters from an extension value body.
pub(crate) fn parse_tp(data: &[u8]) -> Result<TransportParameters> {
    let mut tp = TransportParameters::empty();
    let mut pos = 0usize;
    let mut saw_initial_scid = false;
    while pos < data.len() {
        let id = read_varint(data, &mut pos)?;
        let len = read_varint(data, &mut pos)? as usize;
        if data.len() - pos < len {
            return Err(QuicError::Protocol("truncated transport parameter".into()));
        }
        let value = &data[pos..pos + len];
        pos += len;
        match id {
            TP_INITIAL_MAX_DATA => tp.initial_max_data = parse_tp_u64(value)?,
            TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                tp.initial_max_stream_data_bidi_local = parse_tp_u64(value)?
            }
            TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                tp.initial_max_stream_data_bidi_remote = parse_tp_u64(value)?
            }
            TP_INITIAL_MAX_STREAM_DATA_UNI => tp.initial_max_stream_data_uni = parse_tp_u64(value)?,
            TP_INITIAL_MAX_STREAMS_BIDI => tp.initial_max_streams_bidi = parse_tp_u64(value)?,
            TP_INITIAL_MAX_STREAMS_UNI => tp.initial_max_streams_uni = parse_tp_u64(value)?,
            TP_MAX_UDP_PAYLOAD_SIZE => tp.max_udp_payload_size = parse_tp_u64(value)?,
            TP_ACK_DELAY_EXPONENT => tp.ack_delay_exponent = parse_tp_u64(value)?,
            TP_MAX_ACK_DELAY => tp.max_ack_delay = parse_tp_u64(value)?,
            TP_DISABLE_ACTIVE_MIGRATION => tp.disable_active_migration = true,
            TP_INITIAL_SOURCE_CONNECTION_ID => {
                tp.initial_source_connection_id = value.to_vec();
                saw_initial_scid = true;
            }
            // Unknown parameters are ignored (RFC 9000 §18.2).
            _ => {}
        }
    }
    let _ = saw_initial_scid;
    Ok(tp)
}

fn parse_tp_u64(value: &[u8]) -> Result<u64> {
    if value.len() > 8 {
        return Err(QuicError::Protocol(
            "transport parameter value too long".into(),
        ));
    }
    let mut v: u64 = 0;
    for &b in value {
        v = (v << 8) | b as u64;
    }
    Ok(v)
}

// ---------------------------------------------------------------------------
// TLS handshake message framing (RFC 8446 §4)
// ---------------------------------------------------------------------------

/// Frame a handshake message: `[type:1][length:3][body]`.
fn hs_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let len = body.len() as u32;
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(msg_type);
    out.push((len >> 16) as u8);
    out.push((len >> 8) as u8);
    out.push(len as u8);
    out.extend_from_slice(body);
    out
}

/// Try to pull one complete handshake message from the front of `buf`.
/// Returns `(msg_type, body)` and advances the cursor; `None` when the
/// buffer holds no complete message yet.
fn take_hs_message<'a>(buf: &'a [u8], pos: &mut usize) -> Option<(u8, &'a [u8])> {
    if buf.len() - *pos < 4 {
        return None;
    }
    let msg_type = buf[*pos];
    let len = ((buf[*pos + 1] as usize) << 16)
        | ((buf[*pos + 2] as usize) << 8)
        | (buf[*pos + 3] as usize);
    if buf.len() - *pos < 4 + len {
        return None;
    }
    let body = &buf[*pos + 4..*pos + 4 + len];
    *pos += 4 + len;
    Some((msg_type, body))
}

/// Encode a 2-byte-length extension `[type:2][len:2][data]`.
fn encode_extension(ext_type: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Parse extensions from a message body (after fixed fields). Returns a
/// `(type, data)` list, rejecting duplicate critical extension types.
fn parse_extensions(buf: &[u8], pos: &mut usize) -> Result<Vec<(u16, Vec<u8>)>> {
    if buf.len() - *pos < 2 {
        return Err(QuicError::Protocol("truncated extensions".into()));
    }
    let total = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]) as usize;
    *pos += 2;
    if buf.len() - *pos < total {
        return Err(QuicError::Protocol("truncated extensions".into()));
    }
    let end = *pos + total;
    let mut out = Vec::new();
    while *pos < end {
        if end - *pos < 4 {
            return Err(QuicError::Protocol("truncated extension".into()));
        }
        let ext_type = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]);
        let len = u16::from_be_bytes([buf[*pos + 2], buf[*pos + 3]]) as usize;
        *pos += 4;
        if end - *pos < len {
            return Err(QuicError::Protocol("truncated extension data".into()));
        }
        let data = buf[*pos..*pos + len].to_vec();
        *pos += len;
        if out.iter().any(|(t, _)| *t == ext_type) {
            return Err(QuicError::Protocol("duplicate TLS extension".into()));
        }
        out.push((ext_type, data));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// The client handshake state machine
// ---------------------------------------------------------------------------

/// TLS 1.3 client state over QUIC.
pub(crate) struct Tls13Client {
    server_name: String,
    skip_cert_verify: bool,
    roots: RootStore,
    now: i64,
    /// The running transcript hash over all handshake messages.
    transcript: Box<dyn courierust::courierust_tls::crypto::hash::Digest + Send>,
    /// Client key-share private key (used for the ECDHE shared secret).
    client_priv: [u8; 32],
    /// ClientHello bytes (already consumed into the transcript; re-sent by
    /// the transport on loss).
    pub(crate) client_hello: Vec<u8>,
    /// Negotiated cipher suite (set after ServerHello).
    suite: Option<u16>,
    /// Handshake traffic keys.
    pub(crate) hs_write: Option<PacketKey>,
    pub(crate) hs_read: Option<PacketKey>,
    /// 1-RTT traffic keys.
    pub(crate) app_write: Option<PacketKey>,
    pub(crate) app_read: Option<PacketKey>,
    /// Peer transport parameters (from EncryptedExtensions).
    pub(crate) peer_tp: Option<TransportParameters>,
    /// Negotiated ALPN.
    pub(crate) negotiated_alpn: Option<Vec<u8>>,
    /// Set once the server's Finished was verified.
    server_finished: bool,
    /// The client Finished message (sent once the server Finished arrives).
    client_finished_msg: Option<Vec<u8>>,
    /// Client handshake traffic secret (for the Finished key).
    client_hs_secret: Vec<u8>,
    /// Server handshake traffic secret.
    server_hs_secret: Vec<u8>,
    /// ECDHE shared secret (for the master-secret derivation).
    ecdhe_shared: Vec<u8>,
    /// Transcript hash of ClientHello..ServerHello.
    ch_sh_hash: Vec<u8>,
    /// Parsed leaf certificate (for CertificateVerify).
    leaf: Option<Certificate>,
    /// Queued crypto-stream bytes to send (the client Finished).
    pub(crate) crypto_pending: Vec<u8>,
}

impl Tls13Client {
    /// Build a fresh client handshake: generates the X25519 key share,
    /// constructs the ClientHello (already placed in `crypto_pending`),
    /// and initializes the transcript with it.
    pub fn new(
        server_name: String,
        alpn: Vec<String>,
        skip_cert_verify: bool,
        roots: RootStore,
        now: i64,
        tp: &TransportParameters,
        scid: &[u8],
    ) -> Result<Self> {
        let mut rng_bytes = [0u8; 64];
        rng::fill_random(&mut rng_bytes);
        let mut rng = rng::ChaChaRng::from_seed(&seed_from(&rng_bytes));

        let (client_priv, client_pub) = x25519::keypair(&mut |b| rng.fill(b));
        let client_random = rand32(&mut rng);

        let mut transcript = Box::new(Sha256::new())
            as Box<dyn courierust::courierust_tls::crypto::hash::Digest + Send>;

        let mut body = Vec::new();
        // legacy_version
        body.extend_from_slice(&[0x03, 0x03]);
        // random
        body.extend_from_slice(&client_random);
        // legacy_session_id (empty)
        body.push(0x00);
        // cipher_suites
        body.extend_from_slice(&[0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03]);
        // legacy_compression_methods
        body.extend_from_slice(&[0x01, 0x00]);
        // extensions
        let mut exts = Vec::new();
        // server_name
        let host = server_name.as_bytes();
        let mut sni = Vec::new();
        sni.push(0x00); // name_type
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host);
        exts.push(encode_extension(EXT_SERVER_NAME, &sni));
        // supported_groups: x25519
        exts.push(encode_extension(
            EXT_SUPPORTED_GROUPS,
            &[0x00, 0x02, 0x00, 0x1d],
        ));
        // signature_algorithms
        let schemes = [
            SIG_RSA_PSS_SHA256,
            SIG_RSA_PSS_SHA384,
            SIG_ECDSA_SECP256R1_SHA256,
            SIG_ECDSA_SECP384R1_SHA384,
            SIG_ED25519,
        ];
        let mut sigs = Vec::with_capacity(2 + schemes.len() * 2);
        sigs.extend_from_slice(&(schemes.len() as u16 * 2).to_be_bytes());
        for s in schemes {
            sigs.extend_from_slice(&s.to_be_bytes());
        }
        exts.push(encode_extension(EXT_SIGNATURE_ALGORITHMS, &sigs));
        // supported_versions: 1.3
        exts.push(encode_extension(
            EXT_SUPPORTED_VERSIONS,
            &[0x00, 0x02, 0x03, 0x04],
        ));
        // ALPN
        if !alpn.is_empty() {
            let mut alpn_body = Vec::new();
            let mut list = Vec::new();
            for p in &alpn {
                list.push(p.len() as u8);
                list.extend_from_slice(p.as_bytes());
            }
            alpn_body.extend_from_slice(&(list.len() as u16).to_be_bytes());
            alpn_body.extend_from_slice(&list);
            exts.push(encode_extension(EXT_ALPN, &alpn_body));
        }
        // QUIC transport parameters
        exts.push(encode_extension(EXT_QUIC_TP, &encode_client_tp(tp, scid)));
        // key_share: x25519
        let mut ks = Vec::new();
        ks.extend_from_slice(&[0x00, 0x1d]); // group
        ks.extend_from_slice(&(32u16).to_be_bytes());
        ks.extend_from_slice(&client_pub);
        exts.push(encode_extension(EXT_KEY_SHARE, &ks));
        // append extensions
        let mut exts_wire = Vec::new();
        exts_wire
            .extend_from_slice(&(exts.iter().map(|e| e.len()).sum::<usize>() as u16).to_be_bytes());
        for e in &exts {
            exts_wire.extend_from_slice(e);
        }
        body.extend_from_slice(&exts_wire);

        let client_hello = hs_message(HS_CLIENT_HELLO, &body);
        transcript.update(&client_hello);

        Ok(Self {
            server_name,
            skip_cert_verify,
            roots,
            now,
            transcript,
            client_priv,
            client_hello: client_hello.clone(),
            suite: None,
            hs_write: None,
            hs_read: None,
            app_write: None,
            app_read: None,
            peer_tp: None,
            negotiated_alpn: None,
            server_finished: false,
            client_finished_msg: None,
            client_hs_secret: Vec::new(),
            server_hs_secret: Vec::new(),
            ecdhe_shared: Vec::new(),
            ch_sh_hash: Vec::new(),
            leaf: None,
            crypto_pending: client_hello,
        })
    }

    /// Whether the handshake has fully completed (server Finished verified
    /// and the client Finished produced).
    pub(crate) fn is_complete(&self) -> bool {
        self.server_finished && self.app_write.is_some()
    }

    /// The current transcript hash (snapshot).
    fn transcript_hash(&self) -> Vec<u8> {
        let mut fork = self.transcript.fork();
        fork.finalize()
    }

    /// A fresh hasher for the negotiated suite (SHA-256 for AES-128/ChaCha,
    /// SHA-384 for AES-256).
    fn suite_digest(&self) -> Box<dyn courierust::courierust_tls::crypto::hash::Digest + Send> {
        if self.suite == Some(SUITE_AES_256) {
            Box::new(Sha384::new())
        } else {
            Box::new(Sha256::new())
        }
    }

    /// Consume bytes from the QUIC CRYPTO stream. Processes every complete
    /// handshake message at the front of `buf` and returns the number of
    /// bytes consumed (all complete messages; a partial trailing message is
    /// left for the caller to buffer). The transcript is updated with each
    /// complete message as it is consumed.
    pub(crate) fn consume_crypto(&mut self, buf: &[u8]) -> Result<usize> {
        let mut pos = 0usize;
        while pos < buf.len() {
            let start = pos;
            let Some((msg_type, body)) = take_hs_message(buf, &mut pos) else {
                break;
            };
            let msg_bytes = &buf[start..pos];
            if msg_type == HS_FINISHED {
                // The server's Finished verify_data covers the transcript up
                // to (but not including) the Finished itself; the application
                // traffic secrets cover it *including* the Finished.
                let before = self.transcript_hash();
                self.transcript.update(msg_bytes);
                self.on_server_finished(body, &before)?;
                return Ok(pos); // handshake complete; no further messages
            }
            self.transcript.update(msg_bytes);
            match msg_type {
                HS_SERVER_HELLO => self.on_server_hello(body)?,
                HS_ENCRYPTED_EXTENSIONS => self.on_encrypted_extensions(body)?,
                HS_CERTIFICATE => self.on_certificate(body)?,
                HS_CERTIFICATE_VERIFY => self.on_certificate_verify(body)?,
                HS_CLIENT_HELLO => {
                    return Err(QuicError::Protocol(
                        "unexpected ClientHello from server".into(),
                    ))
                }
                other => {
                    return Err(QuicError::Protocol(format!(
                        "unexpected handshake message type {other}"
                    )))
                }
            }
        }
        Ok(pos)
    }

    /// Reset the transcript after a QUIC Retry: the ClientHello is re-sent
    /// with the same key share, so the transcript restarts from it.
    pub(crate) fn reset_after_retry(&mut self) {
        self.suite = None;
        self.hs_write = None;
        self.hs_read = None;
        self.app_write = None;
        self.app_read = None;
        self.peer_tp = None;
        self.negotiated_alpn = None;
        self.server_finished = false;
        self.client_finished_msg = None;
        self.client_hs_secret.clear();
        self.server_hs_secret.clear();
        self.ecdhe_shared.clear();
        self.ch_sh_hash.clear();
        self.leaf = None;
        self.crypto_pending.clear();
        self.transcript = Box::new(Sha256::new());
        self.transcript.update(&self.client_hello);
    }

    /// Take (and clear) any CRYPTO bytes queued to send (the client
    /// Finished, produced once the server Finished arrives).
    pub(crate) fn take_crypto_pending(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.crypto_pending)
    }

    fn on_server_hello(&mut self, body: &[u8]) -> Result<()> {
        if self.suite.is_some() {
            return Err(QuicError::Protocol("duplicate ServerHello".into()));
        }
        if body.len() < 35 {
            return Err(QuicError::Protocol("truncated ServerHello".into()));
        }
        // legacy_version (2)
        // random (32)
        let random = &body[2..34];
        // HelloRetryRequest?
        if random == HRR_RANDOM {
            return Err(QuicError::Protocol(
                "HelloRetryRequest unsupported (only X25519 offered)".into(),
            ));
        }
        // Downgrade sentinel check.
        if random[24..] == DOWNGRADE_TLS12 {
            return Err(QuicError::Protocol(
                "server signals TLS 1.2 downgrade; rejecting".into(),
            ));
        }
        // session_id (1 + data)
        let sid_len = body[34] as usize;
        if body.len() < 35 + sid_len + 3 {
            return Err(QuicError::Protocol("truncated ServerHello".into()));
        }
        let mut pos = 35 + sid_len;
        // cipher_suite (2)
        let suite = u16::from_be_bytes([body[pos], body[pos + 1]]);
        pos += 2;
        if !matches!(suite, SUITE_AES_128 | SUITE_AES_256 | SUITE_CHACHA) {
            return Err(QuicError::Protocol(format!(
                "server selected unsupported cipher suite 0x{suite:04x}"
            )));
        }
        // compression (1)
        if body[pos] != 0x00 {
            return Err(QuicError::Protocol(
                "server selected a compression method".into(),
            ));
        }
        pos += 1;
        let exts = parse_extensions(body, &mut pos)?;
        let key_share = exts
            .iter()
            .find(|(t, _)| *t == EXT_KEY_SHARE)
            .map(|(_, d)| d.clone())
            .ok_or_else(|| QuicError::Protocol("ServerHello missing key_share".into()))?;
        if key_share.len() < 34 || key_share[0..2] != [0x00, 0x1d] {
            return Err(QuicError::Protocol(
                "ServerHello key_share is not X25519".into(),
            ));
        }
        let key_len = u16::from_be_bytes([key_share[2], key_share[3]]) as usize;
        if key_share.len() < 4 + key_len || key_len != 32 {
            return Err(QuicError::Protocol("invalid ServerHello key_share".into()));
        }
        let mut server_pub = [0u8; 32];
        server_pub.copy_from_slice(&key_share[4..4 + key_len]);

        self.suite = Some(suite);

        // ECDHE shared secret.
        let shared = x25519::x25519(&self.client_priv, &server_pub);

        // Key schedule (RFC 8446 §7.1).
        let hash_len = suite_hash_len(suite);
        let mut digest = self.suite_digest();
        // early_secret = Extract(0, 0)
        let zeros = vec![0u8; hash_len];
        let early = hmac::extract(digest.as_mut(), &zeros, &zeros);
        // derived = Derive-Secret(early, "derived", Hash(""))
        let empty_hash = {
            let mut d = self.suite_digest();
            d.finalize()
        };
        let derived = self.derive_secret_from(&early, b"derived", &empty_hash, hash_len);
        // handshake_secret = Extract(derived, ecdhe)
        let hs_secret = hmac::extract(digest.as_mut(), &derived, &shared);
        // c/s hs traffic
        let ch_sh_hash = self.transcript_hash();
        let client_hs = self.derive_secret_from(&hs_secret, b"c hs traffic", &ch_sh_hash, hash_len);
        let server_hs = self.derive_secret_from(&hs_secret, b"s hs traffic", &ch_sh_hash, hash_len);

        self.client_hs_secret = client_hs.clone();
        self.server_hs_secret = server_hs.clone();
        self.ecdhe_shared = shared.to_vec();
        self.ch_sh_hash = ch_sh_hash;
        self.hs_write = Some(PacketKey::from_secret(suite, &client_hs)?);
        self.hs_read = Some(PacketKey::from_secret(suite, &server_hs)?);

        Ok(())
    }

    fn derive_secret_from(
        &self,
        secret: &[u8],
        label: &[u8],
        messages_hash: &[u8],
        hash_len: usize,
    ) -> Vec<u8> {
        let mut digest = self.suite_digest();
        hmac::expand_label(digest.as_mut(), secret, label, messages_hash, hash_len)
    }

    fn on_encrypted_extensions(&mut self, body: &[u8]) -> Result<()> {
        if self.peer_tp.is_some() {
            return Err(QuicError::Protocol("duplicate EncryptedExtensions".into()));
        }
        let mut pos = 0usize;
        let exts = parse_extensions(body, &mut pos)?;
        for (t, data) in &exts {
            match *t {
                EXT_ALPN => {
                    // protocol_name_list: [len:2][[len:1][proto]...]
                    if data.len() < 2 {
                        return Err(QuicError::Protocol("truncated ALPN".into()));
                    }
                    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
                    if data.len() < 2 + list_len {
                        return Err(QuicError::Protocol("truncated ALPN".into()));
                    }
                    let mut p = 2usize;
                    let mut chosen = None;
                    while p < data.len() {
                        let plen = data[p] as usize;
                        p += 1;
                        if p + plen > data.len() {
                            return Err(QuicError::Protocol("truncated ALPN entry".into()));
                        }
                        chosen = Some(data[p..p + plen].to_vec());
                        p += plen;
                    }
                    self.negotiated_alpn = chosen;
                }
                EXT_QUIC_TP => {
                    self.peer_tp = Some(parse_tp(data)?);
                }
                _ => {}
            }
        }
        if self.peer_tp.is_none() {
            return Err(QuicError::Protocol(
                "EncryptedExtensions missing quic_transport_parameters".into(),
            ));
        }
        Ok(())
    }

    fn on_certificate(&mut self, body: &[u8]) -> Result<()> {
        if self.leaf.is_some() {
            return Err(QuicError::Protocol("duplicate Certificate".into()));
        }
        let mut pos = 0usize;
        // certificate_request_context
        let ctx_len = body
            .get(pos)
            .copied()
            .ok_or_else(|| QuicError::Protocol("truncated Certificate".into()))?
            as usize;
        pos += 1;
        if body.len() < pos + ctx_len {
            return Err(QuicError::Protocol("truncated Certificate".into()));
        }
        pos += ctx_len;
        // certificate_list
        if body.len() - pos < 3 {
            return Err(QuicError::Protocol("truncated Certificate".into()));
        }
        let list_len =
            ((body[pos] as usize) << 16) | ((body[pos + 1] as usize) << 8) | body[pos + 2] as usize;
        pos += 3;
        if body.len() - pos < list_len {
            return Err(QuicError::Protocol("truncated Certificate".into()));
        }
        let list_end = pos + list_len;
        let mut chain: Vec<Vec<u8>> = Vec::new();
        while pos < list_end {
            if list_end - pos < 3 {
                return Err(QuicError::Protocol("truncated certificate entry".into()));
            }
            let cert_len = ((body[pos] as usize) << 16)
                | ((body[pos + 1] as usize) << 8)
                | body[pos + 2] as usize;
            pos += 3;
            if list_end - pos < cert_len {
                return Err(QuicError::Protocol("truncated certificate data".into()));
            }
            chain.push(body[pos..pos + cert_len].to_vec());
            pos += cert_len;
            // certificate extensions (2-byte length)
            if list_end - pos < 2 {
                return Err(QuicError::Protocol(
                    "truncated certificate extensions".into(),
                ));
            }
            let ext_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
            pos += 2;
            if list_end - pos < ext_len {
                return Err(QuicError::Protocol(
                    "truncated certificate extensions".into(),
                ));
            }
            pos += ext_len;
        }
        if chain.is_empty() {
            return Err(QuicError::Protocol("empty certificate chain".into()));
        }

        let leaf_der = chain[0].clone();
        let leaf = x509::parse_certificate(&leaf_der)
            .map_err(|e| QuicError::Certificate(e.to_string()))?;

        if !self.skip_cert_verify {
            x509::validate_chain(&self.roots, &chain, self.now)
                .map_err(|e| QuicError::Certificate(e.to_string()))?;
            if !x509::hostname_matches(&self.server_name, &leaf.dns_names, &leaf.ip_names) {
                return Err(QuicError::Certificate(format!(
                    "server name '{}' does not match the certificate",
                    self.server_name
                )));
            }
        }

        self.leaf = Some(leaf);
        Ok(())
    }

    fn on_certificate_verify(&mut self, body: &[u8]) -> Result<()> {
        let leaf = self
            .leaf
            .as_ref()
            .ok_or_else(|| QuicError::Protocol("CertificateVerify before Certificate".into()))?;
        if body.len() < 4 {
            return Err(QuicError::Protocol("truncated CertificateVerify".into()));
        }
        let scheme = u16::from_be_bytes([body[0], body[1]]);
        let sig_len = u16::from_be_bytes([body[2], body[3]]) as usize;
        if body.len() < 4 + sig_len {
            return Err(QuicError::Protocol(
                "truncated CertificateVerify signature".into(),
            ));
        }
        let signature = &body[4..4 + sig_len];

        // Content to be signed: Transcript-Hash(..., Certificate).
        let content = self.transcript_hash();

        // Signers must have the digitalSignature key usage (checked in
        // validate_chain for non-skip mode; here we verify the signature).
        let ok = verify_signature(&leaf.spki, scheme, &content, signature);
        if !ok {
            return Err(QuicError::Certificate(
                "CertificateVerify signature verification failed".into(),
            ));
        }
        Ok(())
    }

    fn on_server_finished(&mut self, body: &[u8], before_finished: &[u8]) -> Result<()> {
        if self.server_finished {
            return Err(QuicError::Protocol("duplicate Finished".into()));
        }
        let hash_len = self.suite.map(suite_hash_len).unwrap_or(32);
        if body.len() != hash_len {
            return Err(QuicError::Protocol("invalid Finished length".into()));
        }

        // finished_key = HKDF-Expand-Label(server_hs_secret, "finished", "")
        let server_finished_key = {
            let mut digest = self.suite_digest();
            hmac::expand_label(
                digest.as_mut(),
                &self.server_hs_secret,
                b"finished",
                &[],
                hash_len,
            )
        };
        let expected = hmac::hmac(
            self.suite_digest().as_mut(),
            &server_finished_key,
            before_finished,
        );
        if expected.len() != body.len() || !constant_time_eq(&expected, body) {
            return Err(QuicError::Protocol(
                "server Finished verification failed".into(),
            ));
        }
        self.server_finished = true;

        // Master secret + application traffic secrets.
        let hash_len = self.suite.map(suite_hash_len).unwrap_or(32);
        let empty_hash = {
            let mut d = self.suite_digest();
            d.finalize()
        };
        let derived =
            self.derive_secret_from(&self.server_hs_secret, b"derived", &empty_hash, hash_len);
        let master = hmac::extract(self.suite_digest().as_mut(), &derived, &vec![0u8; hash_len]);

        // Transcript up to and including the server Finished.
        let up_to_fin = self.transcript_hash();
        let client_app = self.derive_secret_from(&master, b"c ap traffic", &up_to_fin, hash_len);
        let server_app = self.derive_secret_from(&master, b"s ap traffic", &up_to_fin, hash_len);
        if let Some(suite) = self.suite {
            self.app_write = Some(PacketKey::from_secret(suite, &client_app)?);
            self.app_read = Some(PacketKey::from_secret(suite, &server_app)?);
        }

        // Client Finished.
        let client_finished_key = {
            let mut digest = self.suite_digest();
            hmac::expand_label(
                digest.as_mut(),
                &self.client_hs_secret,
                b"finished",
                &[],
                hash_len,
            )
        };
        let verify_data = hmac::hmac(
            self.suite_digest().as_mut(),
            &client_finished_key,
            &self.transcript_hash(),
        );
        let msg = hs_message(HS_FINISHED, &verify_data);
        self.client_finished_msg = Some(msg.clone());
        self.crypto_pending.extend_from_slice(&msg);
        Ok(())
    }
}

/// Constant-time comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Seed a ChaChaRng from 32 random bytes (first 32 used; 12-byte nonce in
/// bytes 32..44).
fn seed_from(bytes: &[u8]) -> [u8; 44] {
    let mut seed = [0u8; 44];
    seed[..32].copy_from_slice(&bytes[..32]);
    // nonce: bytes 32..44
    seed[32..].copy_from_slice(&bytes[32..44]);
    seed
}

fn rand32(rng: &mut rng::ChaChaRng) -> [u8; 32] {
    let mut out = [0u8; 32];
    rng.fill(&mut out);
    out
}

/// Verify a TLS 1.3 CertificateVerify signature over `content` with the
/// certificate's public key.
fn verify_signature(spki: &Spki, scheme: u16, content: &[u8], signature: &[u8]) -> bool {
    match scheme {
        SIG_RSA_PSS_SHA256 => {
            let Some((n, e)) = parse_rsa_spki(&spki.key) else {
                return false;
            };
            let key = courierust::courierust_tls::crypto::rsa::RsaPublicKey { n, e };
            let mut d = Sha256::new();
            key.verify_pss(&mut d, content, 32, signature)
        }
        SIG_RSA_PSS_SHA384 => {
            let Some((n, e)) = parse_rsa_spki(&spki.key) else {
                return false;
            };
            let key = courierust::courierust_tls::crypto::rsa::RsaPublicKey { n, e };
            let mut d = Sha384::new();
            key.verify_pss(&mut d, content, 48, signature)
        }
        SIG_ECDSA_SECP256R1_SHA256 => {
            let Some((qx, qy)) = parse_ec_point(&spki.key, 32) else {
                return false;
            };
            courierust::courierust_tls::crypto::ecdsa::verify_der(
                courierust::courierust_tls::crypto::ecdsa::Curve::P256,
                qx,
                qy,
                content,
                signature,
            )
        }
        SIG_ECDSA_SECP384R1_SHA384 => {
            let Some((qx, qy)) = parse_ec_point(&spki.key, 48) else {
                return false;
            };
            courierust::courierust_tls::crypto::ecdsa::verify_der(
                courierust::courierust_tls::crypto::ecdsa::Curve::P384,
                qx,
                qy,
                content,
                signature,
            )
        }
        SIG_ED25519 => {
            let Some(key): Option<[u8; 32]> = spki.key[..32].try_into().ok() else {
                return false;
            };
            let Some(sig): Option<[u8; 64]> = signature.try_into().ok() else {
                return false;
            };
            ed25519::verify(&key, content, &sig)
        }
        _ => false,
    }
}

/// Parse an RSA SPKI key (DER `RSAPublicKey` = SEQUENCE { INTEGER n, INTEGER e }).
fn parse_rsa_spki(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    // Minimal DER: 0x30 <len> 0x02 <len> <n> 0x02 <len> <e>
    if der.len() < 8 || der[0] != 0x30 {
        return None;
    }
    let mut pos = 1usize;
    // Sequence length (skip; we validate bounds below).
    let (seq_len, _) = der_len(der, &mut pos)?;
    let _ = seq_len;
    if pos >= der.len() || der[pos] != 0x02 {
        return None;
    }
    pos += 1;
    let (n_len, _) = der_len(der, &mut pos)?;
    if der.len() - pos < n_len {
        return None;
    }
    let n = der[pos..pos + n_len].to_vec();
    pos += n_len;
    if pos >= der.len() || der[pos] != 0x02 {
        return None;
    }
    pos += 1;
    let (e_len, _) = der_len(der, &mut pos)?;
    if der.len() - pos < e_len {
        return None;
    }
    let e = der[pos..pos + e_len].to_vec();
    Some((n, e))
}

/// Parse a DER length field; returns `(length, consumed)`.
fn der_len(der: &[u8], pos: &mut usize) -> Option<(usize, usize)> {
    let b0 = *der.get(*pos)?;
    if b0 & 0x80 == 0 {
        let len = b0 as usize;
        *pos += 1;
        return Some((len, 1));
    }
    let n = (b0 & 0x7f) as usize;
    if n == 0 || n > 4 || der.len() - *pos < 1 + n {
        return None;
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | der[*pos + 1 + i] as usize;
    }
    *pos += 1 + n;
    Some((len, 1 + n))
}

/// Parse an uncompressed EC point `0x04 || x || y` into (x, y).
fn parse_ec_point(key: &[u8], coord: usize) -> Option<(&[u8], &[u8])> {
    if key.len() != 1 + 2 * coord || key[0] != 0x04 {
        return None;
    }
    Some((&key[1..1 + coord], &key[1 + coord..]))
}
