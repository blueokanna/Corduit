//! The synchronous TLS 1.3 client driver (RFC 8446).
//!
//! [`connect`] builds a profile-shaped `ClientHello` (see
//! [`fingerprint`](super::fingerprint)), runs the handshake over any
//! `Read + Write` pair, authenticates the server through a [`ServerAuth`]
//! hook, and returns a [`Tls13Stream`] that frames application data with the
//! TLS record layer.
//!
//! Two hooks make this client reusable for REALITY:
//!
//! * [`ClientHelloHook`] runs after the `ClientHello` is assembled and may
//!   rewrite bytes in place (REALITY seals its session id there), and
//! * [`ServerAuth`] replaces the default x509 chain check with REALITY's
//!   ephemeral-certificate proof.
//!
//! Everything else — record layer, key schedule, `Finished` verification,
//! `KeyUpdate`, `close_notify` — is the standard handshake and is identical
//! for every caller.
//!
//! # Behaviour worth knowing
//!
//! * TLS 1.3 only: a server that selects TLS 1.2 (or sends a
//!   HelloRetryRequest) aborts the handshake with an explicit error.
//! * The transcript hashes exactly the bytes sent and received, including a
//!   `ClientHello` rewritten by a hook.
//! * `WouldBlock` / `TimedOut` from the underlying socket are propagated so
//!   the engine's relay can treat them as "nothing yet"; partial records are
//!   buffered across calls.

use super::codec::{
    self, read_hs_message, take_hs_message, HS_CERTIFICATE, HS_CERTIFICATE_VERIFY, HS_KEY_UPDATE,
    HS_NEW_SESSION_TICKET, HS_SERVER_HELLO,
};
use super::fingerprint::{self, ClientHelloSpec, Fingerprint};
use super::key_schedule::{HandshakeSecrets, SuiteHash, TrafficKey};
use super::record::{
    parse_record_header, plaintext_record, RecordProtector, ALERT_FATAL, ALERT_WARNING,
    CONTENT_ALERT, CONTENT_APPLICATION_DATA, CONTENT_CHANGE_CIPHER_SPEC, CONTENT_HANDSHAKE,
    MAX_PLAINTEXT,
};
use super::{Result, Tls13Error};
use crate::crypto::dh::{public_key as x25519_public_key, x25519};
use crate::crypto::util::ct_eq;
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use courierust::courierust_tls::x509::{self, Certificate, RootStore};
use std::io::{Read, Write};
use std::sync::Arc;

/// How the server is authenticated.
pub trait ServerAuth: Send {
    /// Check the server certificate before `CertificateVerify` is validated.
    ///
    /// `leaf_der` is the leaf certificate as sent, `leaf` its parsed form,
    /// and `chain` the whole chain in wire order. An `Err` aborts the
    /// handshake.
    fn verify_certificate(
        &mut self,
        leaf_der: &[u8],
        leaf: &Certificate,
        chain: &[Vec<u8>],
    ) -> Result<()>;
}

/// The default authentication: x509 chain validation against a root store
/// plus hostname matching (RFC 8446 §4.4.2.4).
pub struct X509ServerAuth {
    roots: RootStore,
    server_name: String,
    now: i64,
    verify: bool,
}

impl X509ServerAuth {
    /// Authenticate `server_name` against `roots` at `now`.
    pub fn new(roots: RootStore, server_name: String, now: i64, verify: bool) -> Self {
        Self {
            roots,
            server_name,
            now,
            verify,
        }
    }
}

impl ServerAuth for X509ServerAuth {
    fn verify_certificate(
        &mut self,
        _leaf_der: &[u8],
        leaf: &Certificate,
        chain: &[Vec<u8>],
    ) -> Result<()> {
        if !self.verify {
            return Ok(());
        }
        x509::validate_chain(&self.roots, chain, self.now)
            .map_err(|e| Tls13Error::Certificate(e.to_string()))?;
        if !x509::hostname_matches(&self.server_name, &leaf.dns_names, &leaf.ip_names) {
            return Err(Tls13Error::Certificate(format!(
                "server name '{}' does not match the certificate",
                self.server_name
            )));
        }
        Ok(())
    }
}

/// The assembled `ClientHello`, handed to a [`ClientHelloHook`] before it is
/// sent.
pub struct ClientHelloDraft<'a> {
    /// The full handshake message. Rewrite bytes in place to change what goes
    /// on the wire; the transcript hashes what is sent, not what was drafted.
    pub raw: &'a mut Vec<u8>,
    /// The `ClientHello.random` embedded in `raw`.
    pub random: &'a [u8; 32],
    /// The client's ephemeral X25519 private key (secret — never log it).
    pub key_share_private: &'a [u8; 32],
    /// The client's ephemeral X25519 public key (the key share in `raw`).
    pub key_share_public: &'a [u8; 32],
    /// Byte offset of the 32-byte `legacy_session_id` inside `raw`.
    pub session_id_offset: usize,
}

/// A post-build rewrite of the `ClientHello` (REALITY's session-id sealing).
pub trait ClientHelloHook: Send {
    /// Rewrite `draft` in place. An `Err` aborts the connection.
    fn on_client_hello(&mut self, draft: &mut ClientHelloDraft<'_>) -> Result<()>;
}

/// Client configuration.
pub struct Tls13ClientConfig {
    /// SNI / certificate hostname.
    pub server_name: String,
    /// ALPN protocols; empty uses the fingerprint profile's list.
    pub alpn: Vec<String>,
    /// `ClientHello` shape.
    pub fingerprint: Fingerprint,
    /// Current time (Unix seconds) for certificate validity checks.
    pub now: i64,
    /// Root store for the default x509 authentication.
    pub roots: Option<RootStore>,
    /// Whether the default x509 authentication validates the chain.
    pub verify: bool,
    /// Custom server authentication (replaces the default x509 path).
    pub auth: Option<Box<dyn ServerAuth>>,
    /// `ClientHello` rewrite hook.
    pub hello_hook: Option<Box<dyn ClientHelloHook>>,
    /// Send a compatibility `change_cipher_spec` after the `ClientHello`
    /// (RFC 8446 appendix D.4), as browsers do.
    pub compatibility_ccs: bool,
    /// Half-close hook: the engine's relay calls `SyncStream::shutdown`, and
    /// only the caller knows how to shut the underlying socket down.
    pub shutdown_hook: Option<Arc<dyn Fn(std::net::Shutdown) -> std::io::Result<()> + Send + Sync>>,
}

impl Default for Tls13ClientConfig {
    fn default() -> Self {
        Self {
            server_name: String::new(),
            alpn: Vec::new(),
            fingerprint: Fingerprint::Off,
            now: 0,
            roots: None,
            verify: true,
            auth: None,
            hello_hook: None,
            compatibility_ccs: true,
            shutdown_hook: None,
        }
    }
}

/// Perform a TLS 1.3 handshake over `reader`/`writer` (normally the two
/// handles of one socket).
pub fn connect<R: Read, W: Write>(
    reader: R,
    writer: W,
    mut config: Tls13ClientConfig,
) -> Result<Tls13Stream<R, W>> {
    if config.server_name.is_empty() {
        return Err(Tls13Error::InvalidConfig("server_name is empty".into()));
    }

    // Entropy: client random + ephemeral X25519 key.
    let mut random = [0u8; 32];
    let mut private = [0u8; 32];
    getrandom::fill(&mut random).map_err(|e| Tls13Error::Io(format!("entropy failure: {e}")))?;
    getrandom::fill(&mut private).map_err(|e| Tls13Error::Io(format!("entropy failure: {e}")))?;
    let public = x25519_public_key(&private);

    // Build the ClientHello in the requested shape, then let the hook rewrite
    // it (REALITY seals its session id here).
    let spec = ClientHelloSpec {
        server_name: &config.server_name,
        alpn: &config.alpn,
        fingerprint: config.fingerprint.clone(),
        random: &random,
        session_id: [0u8; 32],
        key_share: &public,
    };
    let hello = fingerprint::build_client_hello(&spec)?;
    let session_id_offset = hello.session_id_offset;
    let mut client_hello = hello.raw;
    let sent_session_id = client_hello[session_id_offset..session_id_offset + 32].to_vec();
    if let Some(mut hook) = config.hello_hook {
        let mut draft = ClientHelloDraft {
            raw: &mut client_hello,
            random: &random,
            key_share_private: &private,
            key_share_public: &public,
            session_id_offset,
        };
        hook.on_client_hello(&mut draft)?;
    }

    let offered_alpn: Vec<Vec<u8>> = if config.alpn.is_empty() {
        // The browser-shaped profiles offer h2 + http/1.1; `Off` offers none.
        match config.fingerprint {
            Fingerprint::Off => Vec::new(),
            _ => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        }
    } else {
        config.alpn.iter().map(|s| s.as_bytes().to_vec()).collect()
    };
    let mut offered_schemes = config.fingerprint.signature_algorithms();
    if offered_schemes.is_empty() {
        offered_schemes = vec![
            codec::SIG_RSA_PSS_SHA256,
            codec::SIG_ECDSA_SECP256R1_SHA256,
            codec::SIG_ED25519,
        ];
    }

    let mut reader = reader;
    let mut writer = writer;

    write_all(
        &mut writer,
        &plaintext_record(CONTENT_HANDSHAKE, &client_hello),
    )?;
    if config.compatibility_ccs && !matches!(config.fingerprint, Fingerprint::Off) {
        write_all(
            &mut writer,
            &plaintext_record(CONTENT_CHANGE_CIPHER_SPEC, &[0x01]),
        )?;
    }

    // Transcript: every handshake message in order, verbatim, because the
    // hash is not known until the ServerHello picks the suite.
    let mut transcript: Vec<u8> = client_hello.clone();

    // --- ServerHello -----------------------------------------------------
    let server_hello_msg = loop {
        let (outer, payload) = read_record(&mut reader)?;
        match outer {
            CONTENT_CHANGE_CIPHER_SPEC => continue,
            CONTENT_ALERT => return Err(alert_error(&payload)),
            CONTENT_HANDSHAKE => {
                let Some((ty, _body, used)) = read_hs_message(&payload) else {
                    return Err(Tls13Error::Protocol(
                        "ServerHello record does not hold a complete handshake message".into(),
                    ));
                };
                if ty != HS_SERVER_HELLO {
                    return Err(Tls13Error::Protocol(format!(
                        "expected ServerHello (2), got handshake type {ty}"
                    )));
                }
                break payload[..used].to_vec();
            }
            other => {
                return Err(Tls13Error::Protocol(format!(
                    "unexpected record type {other} before ServerHello"
                )))
            }
        }
    };
    let sh = codec::parse_server_hello(&server_hello_msg[4..])?;
    if sh.legacy_session_id_echo != sent_session_id {
        return Err(Tls13Error::Protocol(
            "ServerHello legacy_session_id_echo does not match the ClientHello".into(),
        ));
    }
    transcript.extend_from_slice(&server_hello_msg);

    // Key schedule → handshake traffic keys.
    let ecdhe = x25519(&private, &sh.key_share);
    let hash = SuiteHash::for_suite(sh.suite);
    let transcript_ch_sh = hash.hash(&transcript);
    let hs = HandshakeSecrets::new(sh.suite, &ecdhe, &transcript_ch_sh);
    let (client_hs_key, client_hs_iv) = TrafficKey::derive(sh.suite, hash, &hs.client_hs_traffic)?;
    let (server_hs_key, server_hs_iv) = TrafficKey::derive(sh.suite, hash, &hs.server_hs_traffic)?;
    let mut read_protector = RecordProtector::new(server_hs_key, server_hs_iv);
    let mut write_protector = RecordProtector::new(client_hs_key, client_hs_iv);

    // --- Server flight: EE, Certificate, CertificateVerify, Finished ------
    let mut default_auth = X509ServerAuth::new(
        config.roots.clone().unwrap_or_default(),
        config.server_name.clone(),
        config.now,
        config.verify,
    );
    let auth: &mut dyn ServerAuth = match config.auth.as_mut() {
        Some(custom) => custom.as_mut(),
        None => &mut default_auth,
    };

    let mut negotiated_alpn: Option<Vec<u8>> = None;
    let mut saw_ee = false;
    let mut leaf_der: Option<Vec<u8>> = None;
    let mut leaf: Option<Certificate> = None;
    let mut server_finished_msg: Option<Vec<u8>> = None;
    let mut pending: Vec<u8> = Vec::new();

    while server_finished_msg.is_none() {
        let (outer, payload) = read_record(&mut reader)?;
        let plaintext = match outer {
            CONTENT_CHANGE_CIPHER_SPEC => continue,
            CONTENT_ALERT => return Err(alert_error(&payload)),
            CONTENT_HANDSHAKE => {
                return Err(Tls13Error::Protocol(
                    "unprotected handshake record after ServerHello".into(),
                ))
            }
            CONTENT_APPLICATION_DATA => {
                let (inner, data) = read_protector.open(&payload)?;
                match inner {
                    CONTENT_HANDSHAKE => data,
                    CONTENT_ALERT => return Err(alert_error(&data)),
                    other => {
                        return Err(Tls13Error::Protocol(format!(
                            "unexpected inner content type {other} during handshake"
                        )))
                    }
                }
            }
            other => {
                return Err(Tls13Error::Protocol(format!(
                    "unexpected record type {other} during handshake"
                )))
            }
        };
        pending.extend_from_slice(&plaintext);

        while let Some((ty, _body, used)) = read_hs_message(&pending) {
            let msg = pending[..used].to_vec();
            let body = &msg[4..];
            match ty {
                codec::HS_ENCRYPTED_EXTENSIONS => {
                    if saw_ee {
                        return Err(Tls13Error::Protocol("duplicate EncryptedExtensions".into()));
                    }
                    saw_ee = true;
                    let selected = parse_alpn_extension(body)?;
                    if let Some(proto) = &selected {
                        if !offered_alpn.iter().any(|p| p == proto) {
                            return Err(Tls13Error::Protocol(format!(
                                "server selected ALPN '{}' which was not offered",
                                String::from_utf8_lossy(proto)
                            )));
                        }
                    }
                    negotiated_alpn = selected;
                    transcript.extend_from_slice(&msg);
                }
                HS_CERTIFICATE => {
                    if leaf.is_some() {
                        return Err(Tls13Error::Protocol("duplicate Certificate".into()));
                    }
                    let chain = parse_certificate_message(body)?;
                    let der = chain
                        .first()
                        .ok_or_else(|| Tls13Error::Protocol("empty certificate chain".into()))?
                        .clone();
                    let parsed = x509::parse_certificate(&der)
                        .map_err(|e| Tls13Error::Certificate(e.to_string()))?;
                    auth.verify_certificate(&der, &parsed, &chain)?;
                    leaf_der = Some(der);
                    leaf = Some(parsed);
                    transcript.extend_from_slice(&msg);
                }
                HS_CERTIFICATE_VERIFY => {
                    let cert = leaf.as_ref().ok_or_else(|| {
                        Tls13Error::Protocol("CertificateVerify before Certificate".into())
                    })?;
                    if body.len() < 4 {
                        return Err(Tls13Error::Protocol("truncated CertificateVerify".into()));
                    }
                    let scheme = u16::from_be_bytes([body[0], body[1]]);
                    let sig_len = u16::from_be_bytes([body[2], body[3]]) as usize;
                    if body.len() < 4 + sig_len {
                        return Err(Tls13Error::Protocol(
                            "truncated CertificateVerify signature".into(),
                        ));
                    }
                    if !offered_schemes.contains(&scheme) {
                        return Err(Tls13Error::Protocol(format!(
                            "server used signature scheme 0x{scheme:04x} which was not offered"
                        )));
                    }
                    let content = codec::cert_verify_content(&hash.hash(&transcript), false);
                    if !codec::verify_signature(&cert.spki, scheme, &content, &body[4..4 + sig_len])
                    {
                        return Err(Tls13Error::Certificate(format!(
                            "CertificateVerify signature verification failed \
                             (scheme 0x{scheme:04x}, suite 0x{:04x})",
                            sh.suite
                        )));
                    }
                    transcript.extend_from_slice(&msg);
                }
                codec::HS_FINISHED => {
                    if body.len() != hash.len() {
                        return Err(Tls13Error::Protocol("invalid Finished length".into()));
                    }
                    let finished_key = hash.finished_key(&hs.server_hs_traffic);
                    let expected = hash.hmac(&finished_key, &hash.hash(&transcript));
                    if !ct_eq(&expected, body) {
                        return Err(Tls13Error::Protocol(
                            "server Finished verification failed".into(),
                        ));
                    }
                    server_finished_msg = Some(msg.clone());
                }
                HS_NEW_SESSION_TICKET => {
                    // Post-handshake and not part of the transcript. No PSK
                    // resumption is offered, so the ticket is discarded.
                }
                HS_KEY_UPDATE => {
                    return Err(Tls13Error::Protocol(
                        "KeyUpdate before the handshake completed".into(),
                    ))
                }
                other => {
                    return Err(Tls13Error::Protocol(format!(
                        "unexpected handshake message type {other} during handshake"
                    )))
                }
            }
            pending.drain(..used);
        }
    }

    if leaf.is_none() {
        return Err(Tls13Error::Certificate(
            "server did not send a Certificate message".into(),
        ));
    }
    let server_finished_msg = server_finished_msg.expect("loop exits only on Finished");

    // Transcript through the server Finished → application secrets and the
    // client Finished (RFC 8446 §4.4.4, §7.1).
    transcript.extend_from_slice(&server_finished_msg);
    let transcript_fin = hash.hash(&transcript);
    let app = hs.application(&transcript_fin);
    let client_finished_key = hash.finished_key(&hs.client_hs_traffic);
    let verify_data = hash.hmac(&client_finished_key, &transcript_fin);
    let client_finished = codec::hs_message(codec::HS_FINISHED, &verify_data);
    let record = write_protector.seal(CONTENT_HANDSHAKE, &client_finished)?;
    write_all(&mut writer, &record)?;
    writer.flush().map_err(Tls13Error::from)?;

    // Switch both directions to the application keys.
    let (client_app_key, client_app_iv) =
        TrafficKey::derive(sh.suite, hash, &app.client_app_traffic)?;
    let (server_app_key, server_app_iv) =
        TrafficKey::derive(sh.suite, hash, &app.server_app_traffic)?;
    write_protector.rekey(client_app_key, client_app_iv);
    read_protector.rekey(server_app_key, server_app_iv);

    Ok(Tls13Stream {
        reader,
        writer,
        read: read_protector,
        write: write_protector,
        read_secret: app.server_app_traffic,
        write_secret: app.client_app_traffic,
        hash,
        suite: sh.suite,
        server_name: config.server_name,
        negotiated_alpn,
        peer_certificate: leaf_der,
        plaintext: Vec::new(),
        read_buf: Vec::new(),
        closed: false,
        peer_closed: false,
        key_update_response: false,
        shutdown_hook: config.shutdown_hook,
    })
}

/// A TLS 1.3 record stream over an established connection.
pub struct Tls13Stream<R, W> {
    reader: R,
    writer: W,
    read: RecordProtector,
    write: RecordProtector,
    read_secret: Vec<u8>,
    write_secret: Vec<u8>,
    hash: SuiteHash,
    suite: u16,
    server_name: String,
    negotiated_alpn: Option<Vec<u8>>,
    peer_certificate: Option<Vec<u8>>,
    /// Decrypted application data not yet handed to the caller.
    plaintext: Vec<u8>,
    /// Raw socket bytes of an incomplete record.
    read_buf: Vec<u8>,
    closed: bool,
    peer_closed: bool,
    key_update_response: bool,
    /// Half-close hook supplied by the caller (see `Tls13ClientConfig`).
    shutdown_hook: Option<Arc<dyn Fn(std::net::Shutdown) -> std::io::Result<()> + Send + Sync>>,
}

impl<R: Read, W: Write> Tls13Stream<R, W> {
    /// The negotiated cipher suite.
    pub fn suite(&self) -> u16 {
        self.suite
    }

    /// The negotiated ALPN protocol, if any.
    pub fn negotiated_alpn(&self) -> Option<&[u8]> {
        self.negotiated_alpn.as_deref()
    }

    /// The server name this connection was authenticated for.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// The leaf certificate as sent by the server.
    pub fn peer_certificate_der(&self) -> Option<&[u8]> {
        self.peer_certificate.as_deref()
    }

    /// Send `close_notify` and close the write side (RFC 8446 §6.1).
    pub fn close_notify(&mut self) -> std::io::Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let alert = [ALERT_WARNING, 0 /* close_notify */];
        let record = self
            .write
            .seal(CONTENT_ALERT, &alert)
            .map_err(to_io_error)?;
        self.writer.write_all(&record)?;
        self.writer.flush()
    }

    /// Send a `KeyUpdate` and roll the write key (RFC 8446 §4.6.3).
    fn key_update(&mut self, request_peer_update: bool) -> Result<()> {
        let msg = codec::hs_message(HS_KEY_UPDATE, &[request_peer_update as u8]);
        let record = self.write.seal(CONTENT_HANDSHAKE, &msg)?;
        write_all(&mut self.writer, &record)?;
        self.write_secret = self.hash.next_traffic_secret(&self.write_secret);
        let (key, iv) = TrafficKey::derive(self.suite, self.hash, &self.write_secret)?;
        self.write.rekey(key, iv);
        Ok(())
    }

    fn on_post_handshake(&mut self, body: &[u8], msg_type: u8) -> Result<()> {
        match msg_type {
            HS_NEW_SESSION_TICKET => Ok(()),
            HS_KEY_UPDATE => {
                if body.len() != 1 || body[0] > 1 {
                    return Err(Tls13Error::Protocol("invalid KeyUpdate message".into()));
                }
                self.read_secret = self.hash.next_traffic_secret(&self.read_secret);
                let (key, iv) = TrafficKey::derive(self.suite, self.hash, &self.read_secret)?;
                self.read.rekey(key, iv);
                if body[0] == 1 {
                    self.key_update_response = true;
                }
                Ok(())
            }
            other => Err(Tls13Error::Protocol(format!(
                "unexpected post-handshake message type {other}"
            ))),
        }
    }

    /// Decrypt the next application-data run into `self.plaintext`.
    ///
    /// `Ok(false)` means the peer closed cleanly (`close_notify`).
    fn fill_plaintext(&mut self) -> Result<bool> {
        loop {
            if self.read_buf.len() >= 5 {
                let (outer, len) = parse_record_header(&self.read_buf)?;
                if self.read_buf.len() >= 5 + len {
                    let body = self.read_buf[5..5 + len].to_vec();
                    self.read_buf.drain(..5 + len);
                    match outer {
                        CONTENT_CHANGE_CIPHER_SPEC => continue,
                        CONTENT_HANDSHAKE => {
                            return Err(Tls13Error::Protocol(
                                "unprotected handshake record after the handshake".into(),
                            ))
                        }
                        CONTENT_ALERT => {
                            let (level, desc) = alert_parts(&body);
                            if desc == 0 {
                                self.peer_closed = true;
                                return Ok(false);
                            }
                            if level == ALERT_FATAL {
                                return Err(Tls13Error::Alert {
                                    level,
                                    description: desc,
                                });
                            }
                            continue;
                        }
                        CONTENT_APPLICATION_DATA => {
                            let (inner, data) = self.read.open(&body)?;
                            match inner {
                                CONTENT_APPLICATION_DATA => {
                                    if !data.is_empty() {
                                        self.plaintext.extend_from_slice(&data);
                                        return Ok(true);
                                    }
                                    continue;
                                }
                                CONTENT_HANDSHAKE => {
                                    let mut pos = 0usize;
                                    while let Some((ty, msg_body)) =
                                        take_hs_message(&data, &mut pos)
                                    {
                                        self.on_post_handshake(msg_body, ty)?;
                                    }
                                    continue;
                                }
                                CONTENT_ALERT => {
                                    let (level, desc) = alert_parts(&data);
                                    if desc == 0 {
                                        self.peer_closed = true;
                                        return Ok(false);
                                    }
                                    if level == ALERT_FATAL {
                                        return Err(Tls13Error::Alert {
                                            level,
                                            description: desc,
                                        });
                                    }
                                    continue;
                                }
                                other => {
                                    return Err(Tls13Error::Protocol(format!(
                                        "invalid inner content type {other}"
                                    )))
                                }
                            }
                        }
                        other => {
                            return Err(Tls13Error::Protocol(format!(
                                "unexpected record type {other}"
                            )))
                        }
                    }
                }
            }

            let mut chunk = [0u8; 4096];
            match self.reader.read(&mut chunk) {
                Ok(0) => {
                    if self.read_buf.is_empty() {
                        self.peer_closed = true;
                        return Ok(false);
                    }
                    return Err(Tls13Error::Protocol(
                        "connection closed in the middle of a record".into(),
                    ));
                }
                Ok(n) => self.read_buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Tls13Error::Io(e.to_string())),
            }
        }
    }
}

impl<R: Read, W: Write> Read for Tls13Stream<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.plaintext.is_empty() {
            if self.peer_closed {
                return Ok(0);
            }
            if !self.fill_plaintext().map_err(to_io_error)? {
                return Ok(0);
            }
        }
        let n = core::cmp::min(buf.len(), self.plaintext.len());
        buf[..n].copy_from_slice(&self.plaintext[..n]);
        self.plaintext.drain(..n);
        Ok(n)
    }
}

impl<R: Read, W: Write> Write for Tls13Stream<R, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.closed {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "TLS connection write side is closed",
            ));
        }
        if self.key_update_response {
            self.key_update_response = false;
            self.key_update(false).map_err(to_io_error)?;
        }
        for chunk in buf.chunks(MAX_PLAINTEXT) {
            let record = self
                .write
                .seal(CONTENT_APPLICATION_DATA, chunk)
                .map_err(to_io_error)?;
            self.writer.write_all(&record)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

/// The engine's relay stream contract (`Read + Write + Send`), satisfied for
/// any socket handles the caller can move into a relay thread. Half-close goes
/// through the caller-supplied hook.
impl<R: Read + Send, W: Write + Send> crate::common::stream::SyncStream for Tls13Stream<R, W> {
    fn shutdown(&self, how: std::net::Shutdown) -> std::io::Result<()> {
        match &self.shutdown_hook {
            Some(hook) => hook(how),
            None => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn to_io_error(e: Tls13Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
}

fn write_all<W: Write>(writer: &mut W, bytes: &[u8]) -> Result<()> {
    writer.write_all(bytes).map_err(Tls13Error::from)
}

/// Read one complete record (header + body).
///
/// `WouldBlock`/`TimedOut` are propagated as-is: the engine's relay treats
/// them as "nothing happened yet" and retries.
fn read_record<R: Read>(reader: &mut R) -> Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 5];
    read_exact(reader, &mut header)?;
    let (content_type, len) = parse_record_header(&header)?;
    let mut body = vec![0u8; len];
    read_exact(reader, &mut body)?;
    Ok((content_type, body))
}

fn read_exact<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<()> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(Tls13Error::Io(
                    "connection closed during a record read".into(),
                ))
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Tls13Error::Io(e.to_string())),
        }
    }
    Ok(())
}

fn alert_error(payload: &[u8]) -> Tls13Error {
    let (level, description) = alert_parts(payload);
    Tls13Error::Alert { level, description }
}

fn alert_parts(payload: &[u8]) -> (u8, u8) {
    if payload.len() >= 2 {
        (payload[0], payload[1])
    } else {
        (
            ALERT_FATAL,
            80, // internal_error
        )
    }
}

/// Parse the server-selected ALPN from an `EncryptedExtensions` body.
fn parse_alpn_extension(body: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut pos = 0usize;
    let exts = codec::parse_extensions(body, &mut pos)?;
    for (t, d) in exts {
        if t == codec::EXT_ALPN {
            if d.len() < 3 {
                return Err(Tls13Error::Protocol("truncated ALPN extension".into()));
            }
            let list_len = u16::from_be_bytes([d[0], d[1]]) as usize;
            if list_len == 0 || d.len() < 2 + list_len {
                return Err(Tls13Error::Protocol("truncated ALPN extension".into()));
            }
            let plen = d[2] as usize;
            if 3 + plen > d.len() {
                return Err(Tls13Error::Protocol("truncated ALPN protocol".into()));
            }
            return Ok(Some(d[3..3 + plen].to_vec()));
        }
    }
    Ok(None)
}

/// Parse a `Certificate` message body into the DER chain.
fn parse_certificate_message(body: &[u8]) -> Result<Vec<Vec<u8>>> {
    let ctx_len = *body
        .first()
        .ok_or_else(|| Tls13Error::Protocol("truncated Certificate".into()))?
        as usize;
    let mut pos = 1usize;
    if body.len() < pos + ctx_len {
        return Err(Tls13Error::Protocol("truncated Certificate".into()));
    }
    if ctx_len != 0 {
        return Err(Tls13Error::Protocol(
            "server CertificateRequest context must be empty".into(),
        ));
    }
    pos += ctx_len;
    if body.len() - pos < 3 {
        return Err(Tls13Error::Protocol("truncated Certificate".into()));
    }
    let list_len =
        ((body[pos] as usize) << 16) | ((body[pos + 1] as usize) << 8) | body[pos + 2] as usize;
    pos += 3;
    if body.len() - pos < list_len {
        return Err(Tls13Error::Protocol("truncated Certificate".into()));
    }
    let list_end = pos + list_len;
    let mut chain = Vec::new();
    while pos < list_end {
        if list_end - pos < 3 {
            return Err(Tls13Error::Protocol("truncated certificate entry".into()));
        }
        let cert_len =
            ((body[pos] as usize) << 16) | ((body[pos + 1] as usize) << 8) | body[pos + 2] as usize;
        pos += 3;
        if list_end - pos < cert_len {
            return Err(Tls13Error::Protocol("truncated certificate data".into()));
        }
        chain.push(body[pos..pos + cert_len].to_vec());
        pos += cert_len;
        if list_end - pos < 2 {
            return Err(Tls13Error::Protocol(
                "truncated certificate extensions".into(),
            ));
        }
        let ext_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2;
        if list_end - pos < ext_len {
            return Err(Tls13Error::Protocol(
                "truncated certificate extensions".into(),
            ));
        }
        // We never advertise `compress_certificate`, so an entry carrying it
        // is a protocol violation, not something to ignore.
        let entry_exts = &body[pos..pos + ext_len];
        let mut epos = 0usize;
        while epos + 4 <= entry_exts.len() {
            let t = u16::from_be_bytes([entry_exts[epos], entry_exts[epos + 1]]);
            let l = u16::from_be_bytes([entry_exts[epos + 2], entry_exts[epos + 3]]) as usize;
            if epos + 4 + l > entry_exts.len() {
                return Err(Tls13Error::Protocol(
                    "truncated certificate entry extension".into(),
                ));
            }
            if t == codec::CERT_EXT_COMPRESSED_CERTIFICATE {
                return Err(Tls13Error::Protocol(
                    "server compressed a certificate although compress_certificate was not offered"
                        .into(),
                ));
            }
            epos += 4 + l;
        }
        pos += ext_len;
    }
    if chain.is_empty() {
        return Err(Tls13Error::Protocol("empty certificate chain".into()));
    }
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use courierust::courierust_io::{Read as CRead, Write as CWrite};
    use courierust::courierust_tls::{Identity, ServerConfig, TlsAcceptor, TlsVersion};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    const RSA_CERT: &[u8] = include_bytes!("testdata/rsa_cert.der");
    const RSA_KEY: &[u8] = include_bytes!("testdata/rsa_key.der");
    const EC_CERT: &[u8] = include_bytes!("testdata/ec_cert.der");
    const EC_KEY: &[u8] = include_bytes!("testdata/ec_key.der");

    fn unix_now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs() as i64
    }

    fn root_with(cert: &[u8]) -> RootStore {
        let mut roots = RootStore::new();
        roots.add_der(cert.to_vec());
        roots
    }

    /// Spawn a courierust TLS 1.3 server on loopback that echoes one message.
    fn spawn_server(
        cert: &'static [u8],
        key: &'static [u8],
        is_rsa: bool,
    ) -> (u16, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let acceptor = TlsAcceptor::new(ServerConfig {
            identity: Identity {
                cert_chain: vec![cert.to_vec()],
                private_key: key.to_vec(),
                is_rsa,
            },
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            min_version: TlsVersion::Tls13,
            max_version: TlsVersion::Tls13,
            session_ticket_key: None,
        });
        let handle = thread::spawn(move || {
            let (sock, _) = listener.accept().expect("accept");
            sock.set_read_timeout(Some(Duration::from_secs(10)))
                .expect("timeout");
            sock.set_write_timeout(Some(Duration::from_secs(10)))
                .expect("timeout");
            let mut stream = acceptor.accept(&sock, &sock).expect("server handshake");
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).expect("server read");
            stream.write_all(&buf[..n]).expect("server write");
            stream.flush().ok();
        });
        (port, handle)
    }

    fn run_roundtrip(
        cert: &'static [u8],
        key: &'static [u8],
        is_rsa: bool,
        fingerprint: Fingerprint,
        label: &str,
    ) {
        let (port, server) = spawn_server(cert, key, is_rsa);
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");

        let mut client = connect(
            &stream,
            &stream,
            Tls13ClientConfig {
                server_name: "localhost".into(),
                alpn: vec!["h2".into(), "http/1.1".into()],
                fingerprint,
                now: unix_now(),
                roots: Some(root_with(cert)),
                verify: true,
                auth: None,
                hello_hook: None,
                compatibility_ccs: true,
                shutdown_hook: None,
            },
        )
        .unwrap_or_else(|e| panic!("[{label}] client handshake failed: {e}"));

        assert!(
            matches!(client.suite(), 0x1301..=0x1303),
            "[{label}] negotiated a TLS 1.3 suite"
        );
        assert_eq!(client.negotiated_alpn(), Some(&b"h2"[..]), "[{label}] ALPN");
        assert!(
            client.peer_certificate_der().is_some(),
            "[{label}] leaf cert"
        );

        client.write_all(b"ping").expect("client write");
        client.flush().expect("flush");
        let mut echo = [0u8; 4];
        client.read_exact(&mut echo).expect("client read");
        assert_eq!(&echo, b"ping", "[{label}] echo");

        client.close_notify().expect("close_notify");
        server.join().expect("server thread");
    }

    /// Full handshake against a real TLS 1.3 peer (courierust's server) in
    /// every certificate × fingerprint combination this client supports:
    /// chain validation on, RSA and ECDSA identities, Chrome-shaped and
    /// minimal `ClientHello`s.
    #[test]
    fn handshake_roundtrips_all_combinations() {
        run_roundtrip(RSA_CERT, RSA_KEY, true, Fingerprint::Chrome, "rsa/chrome");
        run_roundtrip(RSA_CERT, RSA_KEY, true, Fingerprint::Off, "rsa/off");
        run_roundtrip(EC_CERT, EC_KEY, false, Fingerprint::Chrome, "ec/chrome");
        run_roundtrip(EC_CERT, EC_KEY, false, Fingerprint::Off, "ec/off");
    }

    /// A server certificate that does not match the requested name is
    /// rejected by the default authentication.
    #[test]
    fn wrong_server_name_is_rejected() {
        let (port, server) = spawn_server(RSA_CERT, RSA_KEY, true);
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let result = connect(
            &stream,
            &stream,
            Tls13ClientConfig {
                server_name: "not-in-the-cert.test".into(),
                alpn: vec!["h2".into()],
                fingerprint: Fingerprint::Off,
                now: unix_now(),
                roots: Some(root_with(RSA_CERT)),
                verify: true,
                auth: None,
                hello_hook: None,
                compatibility_ccs: false,
                shutdown_hook: None,
            },
        );
        match result {
            Err(Tls13Error::Certificate(m)) => assert!(
                m.contains("does not match"),
                "unexpected certificate error: {m}"
            ),
            Ok(_) => panic!("expected a hostname mismatch, got a completed handshake"),
            Err(e) => panic!("expected a hostname mismatch, got {e}"),
        }
        // The server side fails its handshake too; joining keeps the test
        // from leaking the thread.
        let _ = server.join();
    }

    /// A custom `ServerAuth` replaces the x509 path, and the transcript still
    /// verifies (this is the hook REALITY builds on).
    #[test]
    fn custom_server_auth_is_used() {
        struct AcceptAny(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl ServerAuth for AcceptAny {
            fn verify_certificate(
                &mut self,
                leaf_der: &[u8],
                _leaf: &Certificate,
                _chain: &[Vec<u8>],
            ) -> Result<()> {
                assert!(!leaf_der.is_empty());
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            }
        }

        let called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (port, server) = spawn_server(RSA_CERT, RSA_KEY, true);
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let mut client = connect(
            &stream,
            &stream,
            Tls13ClientConfig {
                server_name: "localhost".into(),
                alpn: vec!["h2".into()],
                fingerprint: Fingerprint::Chrome,
                now: unix_now(),
                roots: None, // no roots at all: the custom auth is the only check
                verify: true,
                auth: Some(Box::new(AcceptAny(called.clone()))),
                hello_hook: None,
                compatibility_ccs: true,
                shutdown_hook: None,
            },
        )
        .expect("handshake with custom auth");
        assert!(called.load(std::sync::atomic::Ordering::SeqCst));

        // The connection is fully usable, not just handshaken.
        client.write_all(b"ping").expect("write");
        client.flush().expect("flush");
        let mut echo = [0u8; 4];
        client.read_exact(&mut echo).expect("read");
        assert_eq!(&echo, b"ping");

        client.close_notify().ok();
        server.join().expect("server thread");
    }
}
