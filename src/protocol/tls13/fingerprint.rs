//! Profile-shaped `ClientHello` construction.
//!
//! A TLS `ClientHello` is public data; what a middlebox observes is its
//! *shape* — the cipher suite list, the extension set and order, the
//! supported groups, the signature algorithms, the padding. This module
//! builds a standards-valid `ClientHello` whose shape is taken from a
//! declared [`Fingerprint`], and it reports exactly what it emitted and what
//! it deliberately left out, so nothing about the resulting shape is
//! implicit.
//!
//! # Profiles shipped
//!
//! | [`Fingerprint`] | source of the shape |
//! |---|---|
//! | [`Fingerprint::Off`] | the minimal modern client: TLS 1.3, X25519, SNI, ALPN |
//! | [`Fingerprint::Chrome`] | `courierust_fingerprint::chrome_tls_profile()` — the parameter set documented in the JA4 specification |
//! | [`Fingerprint::Randomized`] | the Chrome set with per-connection randomized extension order, GREASE values and padding |
//! | [`Fingerprint::Custom`] | caller-supplied [`TlsProfile`], for shapes verified against a real capture |
//!
//! Named profiles for other browsers (`firefox`, `safari`, `ios`, …) are
//! **not** shipped: their parameter sets change per release and this crate
//! has no verified capture to derive them from. [`Fingerprint::parse`]
//! rejects those names with an explicit error instead of silently sending
//! something that is not the requested browser.
//!
//! # Known omissions
//!
//! Two extensions that Chromium sends are never emitted, because emitting
//! them without implementing their semantics would break real connections or
//! misrepresent the client:
//!
//! * `compress_certificate` (0x001b, RFC 8879) — a server that sees it may
//!   compress its certificate chain (brotli/zlib), which this client does not
//!   decompress, so the extension is not advertised.
//! * `application_settings` (0x4469, ALPS) — it carries protocol settings
//!   (HTTP/2 frame payloads) this client does not present.
//!
//! [`KNOWN_OMISSIONS`] lists them, and [`ClientHello::omitted_extensions`]
//! reports the omissions for the profile actually used, so a caller can see
//! the difference between "what the profile says" and "what went on the
//! wire". GREASE (RFC 8701) values are per-connection and are filtered out of
//! JA3/JA4 by construction.

use super::{Result, Tls13Error};
use crate::crypto::hash::Sha256;
use crate::crypto::Digest;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use courierust::courierust_fingerprint::{chrome_tls_profile, TlsProfile};

/// Extensions a Chromium-shaped profile lists but this client never emits,
/// with the reason. See the module docs.
pub const KNOWN_OMISSIONS: &[(u16, &str)] = &[
    (
        super::codec::EXT_COMPRESS_CERTIFICATE,
        "compress_certificate (RFC 8879) is not advertised: certificate decompression is not implemented",
    ),
    (
        super::codec::EXT_APPLICATION_SETTINGS,
        "application_settings (ALPS) is not advertised: the client presents no protocol settings payload",
    ),
];

/// Which client shape the `ClientHello` should present.
#[derive(Debug, Clone, Default)]
pub enum Fingerprint {
    /// Minimal modern client: TLS 1.3 only, X25519, SNI + ALPN, no padding,
    /// no GREASE, no legacy extensions.
    #[default]
    Off,
    /// The Chrome parameter set from `courierust_fingerprint`.
    Chrome,
    /// The Chrome parameter set with randomized extension order, GREASE
    /// placement and padding — the shape varies per connection, so no stable
    /// JA3/JA4 is presented.
    Randomized,
    /// A caller-supplied profile (e.g. one verified against a real capture).
    Custom(TlsProfile),
}

impl Fingerprint {
    /// Parse a configuration spelling.
    ///
    /// Only the shipped profiles are accepted; `firefox` / `safari` / `ios` /
    /// `edge` and friends are rejected with a message that says why, rather
    /// than being silently mapped to a different shape.
    pub fn parse(name: &str) -> Result<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "" | "off" | "none" => Ok(Fingerprint::Off),
            "chrome" | "chromium" => Ok(Fingerprint::Chrome),
            "randomized" | "random" => Ok(Fingerprint::Randomized),
            other => Err(Tls13Error::InvalidConfig(format!(
                "unsupported fingerprint '{other}': shipped profiles are 'chrome', 'randomized' and \
                 'off'; other browsers are not shipped because their parameter sets are not \
                 verified against a capture (use Fingerprint::Custom in the API)"
            ))),
        }
    }

    /// The canonical configuration name.
    pub fn canonical_name(&self) -> &'static str {
        match self {
            Fingerprint::Off => "off",
            Fingerprint::Chrome => "chrome",
            Fingerprint::Randomized => "randomized",
            Fingerprint::Custom(_) => "custom",
        }
    }

    /// The base parameter set this fingerprint shapes itself from.
    fn base_profile(&self) -> Option<TlsProfile> {
        match self {
            Fingerprint::Off => None,
            Fingerprint::Chrome | Fingerprint::Randomized => Some(chrome_tls_profile()),
            Fingerprint::Custom(p) => Some(p.clone()),
        }
    }

    /// The signature schemes this fingerprint offers, used to check that the
    /// server's `CertificateVerify` scheme was actually offered (RFC 8446
    /// §4.4.2.2). Empty means "the caller decides".
    pub fn signature_algorithms(&self) -> Vec<u16> {
        self.base_profile()
            .map(|p| p.signature_algorithms)
            .unwrap_or_default()
    }
}

/// Inputs for one `ClientHello`.
pub struct ClientHelloSpec<'a> {
    /// SNI value; an empty string omits the `server_name` extension.
    pub server_name: &'a str,
    /// ALPN protocols to offer (wire bytes). Empty falls back to the
    /// profile's list (or omits the extension for [`Fingerprint::Off`]).
    pub alpn: &'a [String],
    /// Shape to present.
    pub fingerprint: Fingerprint,
    /// The 32-byte `ClientHello.random` (caller-provided entropy).
    pub random: &'a [u8; 32],
    /// The legacy session id. Always 32 bytes: the offset is fixed (39) and
    /// REALITY rewrites this field after the message is built.
    pub session_id: [u8; 32],
    /// The client's X25519 key share.
    pub key_share: &'a [u8; 32],
}

/// A completed `ClientHello` handshake message.
#[derive(Debug, Clone)]
pub struct ClientHello {
    /// The full handshake message: 1-byte type + 3-byte length + body.
    pub raw: Vec<u8>,
    /// Byte offset of the 32-byte `legacy_session_id` inside [`Self::raw`]
    /// (always 39).
    pub session_id_offset: usize,
    /// The random embedded in the message.
    pub random: [u8; 32],
    /// Extensions the profile listed but this client does not emit.
    pub omitted_extensions: Vec<(u16, &'static str)>,
}

/// Byte offset of `legacy_session_id` in a handshake message
/// (4-byte handshake header + 2-byte version + 32-byte random + 1-byte
/// length). REALITY depends on this being fixed.
pub const SESSION_ID_OFFSET: usize = 39;

/// Build a `Some Third-Partyies` shaped by `spec`.
pub fn build_client_hello(spec: &ClientHelloSpec<'_>) -> Result<ClientHello> {
    let mut omitted: Vec<(u16, &'static str)> = Vec::new();
    let profile = spec.fingerprint.base_profile();
    let mut stream = Stream::new(spec.random);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    body.extend_from_slice(spec.random);
    body.push(spec.session_id.len() as u8);
    body.extend_from_slice(&spec.session_id);

    let ciphers: Vec<u16> = match &profile {
        Some(p) => p.ciphers.clone(),
        None => alloc::vec![0x1301u16, 0x1302, 0x1303],
    };
    if ciphers.is_empty() {
        return Err(Tls13Error::InvalidConfig(
            "profile has no cipher suites".into(),
        ));
    }
    let mut cipher_bytes = Vec::with_capacity(2 + (ciphers.len() + 1) * 2);
    let grease_cipher = !matches!(spec.fingerprint, Fingerprint::Off);
    if grease_cipher {
        cipher_bytes.extend_from_slice(&stream.grease().to_be_bytes());
    }
    for c in &ciphers {
        cipher_bytes.extend_from_slice(&c.to_be_bytes());
    }
    body.extend_from_slice(&(cipher_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&cipher_bytes);
    body.extend_from_slice(&[0x01, 0x00]);

    let mut exts: Vec<(u16, Vec<u8>)> = Vec::new();
    let push_sni = |exts: &mut Vec<(u16, Vec<u8>)>| {
        if !spec.server_name.is_empty() {
            let host = spec.server_name.as_bytes();
            let mut sni = Vec::with_capacity(3 + host.len());
            sni.push(0x00); // host_name
            sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
            sni.extend_from_slice(host);
            exts.push((super::codec::EXT_SERVER_NAME, sni));
        }
    };

    match &profile {
        None => {
            push_sni(&mut exts);
            let alpn = alpn_list(spec.alpn, &[]);
            if !alpn.is_empty() {
                exts.push((super::codec::EXT_ALPN, alpn));
            }
            exts.push((
                super::codec::EXT_SUPPORTED_GROUPS,
                groups_body(&[super::codec::GROUP_X25519], false, &mut stream),
            ));
            exts.push((
                super::codec::EXT_SIGNATURE_ALGORITHMS,
                sig_algs_body(&[
                    super::codec::SIG_RSA_PSS_SHA256,
                    super::codec::SIG_ECDSA_SECP256R1_SHA256,
                    super::codec::SIG_ED25519,
                ]),
            ));
            exts.push((
                super::codec::EXT_SUPPORTED_VERSIONS,
                supported_versions_body(&[0x0304], None),
            ));
            exts.push((
                super::codec::EXT_KEY_SHARE,
                key_share_body(spec.key_share, false, &mut stream),
            ));
        }
        Some(p) => {
            for ext_type in &p.extensions {
                match *ext_type {
                    super::codec::EXT_SERVER_NAME => {
                        if spec.server_name.is_empty() {
                            continue;
                        }
                        let host = spec.server_name.as_bytes();
                        let mut sni = Vec::with_capacity(3 + host.len());
                        sni.push(0x00);
                        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
                        sni.extend_from_slice(host);
                        exts.push((super::codec::EXT_SERVER_NAME, sni));
                    }
                    super::codec::EXT_SUPPORTED_GROUPS => exts.push((
                        super::codec::EXT_SUPPORTED_GROUPS,
                        groups_body(&p.groups, true, &mut stream),
                    )),
                    super::codec::EXT_EC_POINT_FORMATS => exts.push((
                        super::codec::EXT_EC_POINT_FORMATS,
                        point_formats_body(&p.point_formats),
                    )),
                    super::codec::EXT_SIGNATURE_ALGORITHMS => exts.push((
                        super::codec::EXT_SIGNATURE_ALGORITHMS,
                        sig_algs_body(&p.signature_algorithms),
                    )),
                    super::codec::EXT_ALPN => {
                        let alpn = alpn_list(spec.alpn, &p.alpn);
                        if !alpn.is_empty() {
                            exts.push((super::codec::EXT_ALPN, alpn));
                        }
                    }
                    super::codec::EXT_SUPPORTED_VERSIONS => {
                        let grease = grease_cipher.then(|| stream.grease());
                        exts.push((
                            super::codec::EXT_SUPPORTED_VERSIONS,
                            supported_versions_body(&p.supported_versions, grease),
                        ))
                    }
                    super::codec::EXT_KEY_SHARE => exts.push((
                        super::codec::EXT_KEY_SHARE,
                        key_share_body(spec.key_share, true, &mut stream),
                    )),
                    super::codec::EXT_PSK_KEY_EXCHANGE_MODES => exts.push((
                        super::codec::EXT_PSK_KEY_EXCHANGE_MODES,
                        alloc::vec![0x01, 0x01], // psk_dhe_ke
                    )),
                    super::codec::EXT_SESSION_TICKET => {
                        exts.push((super::codec::EXT_SESSION_TICKET, Vec::new()))
                    }
                    super::codec::EXT_EXTENDED_MASTER_SECRET => {
                        exts.push((super::codec::EXT_EXTENDED_MASTER_SECRET, Vec::new()))
                    }
                    super::codec::EXT_RENEGOTIATION_INFO => {
                        exts.push((super::codec::EXT_RENEGOTIATION_INFO, alloc::vec![0x00]))
                    }
                    super::codec::EXT_STATUS_REQUEST => exts.push((
                        super::codec::EXT_STATUS_REQUEST,
                        alloc::vec![0x01, 0x00, 0x00, 0x01, 0x00],
                    )),
                    super::codec::EXT_SIGNED_CERTIFICATE_TIMESTAMP => {
                        exts.push((super::codec::EXT_SIGNED_CERTIFICATE_TIMESTAMP, Vec::new()))
                    }
                    super::codec::EXT_PADDING => {}
                    other => {
                        let reason = KNOWN_OMISSIONS
                            .iter()
                            .find(|(t, _)| *t == other)
                            .map(|(_, r)| *r)
                            .unwrap_or(
                                "the profile lists an extension this client cannot construct",
                            );
                        omitted.push((other, reason));
                    }
                }
            }
            if exts.is_empty() {
                return Err(Tls13Error::InvalidConfig(
                    "profile has no constructible extensions".into(),
                ));
            }
        }
    }

    if grease_cipher {
        exts.insert(0, (stream.grease(), Vec::new()));
    }

    if matches!(spec.fingerprint, Fingerprint::Randomized) {
        stream.shuffle(&mut exts);
    }

    let want_padding = !matches!(spec.fingerprint, Fingerprint::Off);
    let mut ext_bytes = Vec::new();
    for (t, d) in &exts {
        ext_bytes.extend_from_slice(&super::codec::encode_extension(*t, d));
    }
    if want_padding {
        let unpadded = 4 + body.len() + 2 + ext_bytes.len();
        let padded_len = pad_len(unpadded);
        if padded_len > 0 {
            let padding = super::codec::encode_extension(
                super::codec::EXT_PADDING,
                &alloc::vec![0u8; padded_len],
            );
            ext_bytes.extend_from_slice(&padding);
        }
    }
    if ext_bytes.len() > u16::MAX as usize {
        return Err(Tls13Error::InvalidConfig(
            "ClientHello extensions exceed 65535 bytes".into(),
        ));
    }
    body.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext_bytes);

    let raw = super::codec::hs_message(super::codec::HS_CLIENT_HELLO, &body);
    debug_assert_eq!(
        raw.len(),
        SESSION_ID_OFFSET + 32 + (raw.len() - SESSION_ID_OFFSET - 32)
    );
    let mut hello = ClientHello {
        raw,
        session_id_offset: SESSION_ID_OFFSET,
        random: *spec.random,
        omitted_extensions: omitted,
    };
    debug_assert_eq!(
        hello.raw[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32],
        spec.session_id[..]
    );

    hello.omitted_extensions.sort_unstable_by_key(|(t, _)| *t);
    hello.omitted_extensions.dedup_by_key(|(t, _)| *t);
    Ok(hello)
}

/// ALPN body: caller list wins, otherwise the profile's list.
fn alpn_list(caller: &[String], profile: &[String]) -> Vec<u8> {
    let list: &[String] = if caller.is_empty() { profile } else { caller };
    if list.is_empty() {
        return Vec::new();
    }
    let mut inner = Vec::new();
    for p in list {
        let bytes = p.as_bytes();
        if bytes.len() > u8::MAX as usize {
            continue;
        }
        inner.push(bytes.len() as u8);
        inner.extend_from_slice(bytes);
    }
    let mut out = Vec::with_capacity(2 + inner.len());
    out.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    out.extend_from_slice(&inner);
    out
}

/// `supported_groups` body.
fn groups_body(groups: &[u16], grease: bool, stream: &mut Stream) -> Vec<u8> {
    let mut list = Vec::new();
    let mut count = 0usize;
    let grease_value = grease.then(|| stream.grease());
    if let Some(g) = grease_value {
        list.extend_from_slice(&g.to_be_bytes());
        count += 1;
    }
    for group in groups {
        list.extend_from_slice(&group.to_be_bytes());
        count += 1;
    }
    let _ = count;
    let mut out = Vec::with_capacity(2 + list.len());
    out.extend_from_slice(&(list.len() as u16).to_be_bytes());
    out.extend_from_slice(&list);
    out
}

/// `ec_point_formats` body.
fn point_formats_body(formats: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + formats.len());
    out.push(formats.len() as u8);
    out.extend_from_slice(formats);
    out
}

/// `signature_algorithms` body.
fn sig_algs_body(schemes: &[u16]) -> Vec<u8> {
    let mut list = Vec::with_capacity(schemes.len() * 2);
    for s in schemes {
        list.extend_from_slice(&s.to_be_bytes());
    }
    let mut out = Vec::with_capacity(2 + list.len());
    out.extend_from_slice(&(list.len() as u16).to_be_bytes());
    out.extend_from_slice(&list);
    out
}

/// `supported_versions` body (client form: 1-byte list length).
///
/// `grease` is inserted as the first version when present, which is what
/// Chromium does; the declared length always equals the bytes written.
fn supported_versions_body(versions: &[u16], grease: Option<u16>) -> Vec<u8> {
    let mut list = Vec::with_capacity(2 + versions.len() * 2);
    if let Some(g) = grease {
        list.extend_from_slice(&g.to_be_bytes());
    }
    for v in versions {
        list.extend_from_slice(&v.to_be_bytes());
    }
    let mut out = Vec::with_capacity(1 + list.len());
    out.push(list.len() as u8);
    out.extend_from_slice(&list);
    out
}

/// `key_share` body with a single X25519 share (client form: 2-byte list
/// length).
fn key_share_body(public: &[u8; 32], grease: bool, stream: &mut Stream) -> Vec<u8> {
    let mut entry = Vec::with_capacity(36);
    if grease {
        let g = stream.grease();
        entry.extend_from_slice(&g.to_be_bytes());
        entry.extend_from_slice(&0u16.to_be_bytes()); // empty GREASE share
    }
    entry.extend_from_slice(&super::codec::GROUP_X25519.to_be_bytes());
    entry.extend_from_slice(&32u16.to_be_bytes());
    entry.extend_from_slice(public);
    let mut out = Vec::with_capacity(2 + entry.len());
    out.extend_from_slice(&(entry.len() as u16).to_be_bytes());
    out.extend_from_slice(&entry);
    out
}

/// Padding length that brings the message to the next 512-byte boundary
/// (0 already means "omit the padding extension"). Capped so a padded
/// ClientHello stays within two records.
fn pad_len(unpadded: usize) -> usize {
    let target = ((unpadded / 512) + 1) * 512;
    let pad = target.saturating_sub(unpadded + 4); // 4 = padding extension header
    if pad > 512 {
        0
    } else {
        pad
    }
}

/// Deterministic byte stream derived from the ClientHello random. Used for
/// GREASE selection, shuffling and padding decisions so a message is a pure
/// function of its inputs.
struct Stream {
    seed: [u8; 32],
    block: [u8; 32],
    used: usize,
    counter: u64,
}

impl Stream {
    fn new(random: &[u8; 32]) -> Self {
        let mut s = Stream {
            seed: *random,
            block: [0u8; 32],
            used: 32,
            counter: 0,
        };
        s.refill();
        s
    }

    fn refill(&mut self) {
        let mut h = Sha256::new();
        h.update(&self.seed);
        h.update(&self.counter.to_be_bytes());
        h.finalize_into(&mut self.block);
        self.counter += 1;
        self.used = 0;
    }

    fn next_u8(&mut self) -> u8 {
        if self.used >= self.block.len() {
            self.refill();
        }
        let b = self.block[self.used];
        self.used += 1;
        b
    }

    /// A GREASE value (RFC 8701): `0x?a?a`.
    fn grease(&mut self) -> u16 {
        let n = (self.next_u8() & 0x0f) as u16;
        let octet = (n << 4) | 0x0a;
        (octet << 8) | octet
    }

    /// Fisher-Yates shuffle driven by the deterministic stream.
    fn shuffle<T>(&mut self, items: &mut [(u16, T)]) {
        let n = items.len();
        if n < 2 {
            return;
        }
        for i in (1..n).rev() {
            let j = (self.next_u8() as usize) % (i + 1);
            items.swap(i, j);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use courierust::courierust_fingerprint::{ja3_hash, ja3_string, ja4};

    fn spec<'a>(
        fingerprint: Fingerprint,
        random: &'a [u8; 32],
        alpn: &'a [String],
    ) -> ClientHelloSpec<'a> {
        ClientHelloSpec {
            server_name: "example.com",
            alpn,
            fingerprint,
            random,
            session_id: [0u8; 32],
            key_share: &[0x11; 32],
        }
    }

    /// Parse our own `ClientHello` back into a `TlsProfile` so the JA3/JA4
    /// builders can be run over what actually went on the wire.
    fn profile_from_bytes(raw: &[u8], protocol: char) -> TlsProfile {
        let (ty, body, _) = super::super::codec::read_hs_message(raw).expect("handshake frame");
        assert_eq!(ty, super::super::codec::HS_CLIENT_HELLO);
        let mut p = TlsProfile {
            protocol,
            tls_version: u16::from_be_bytes([body[0], body[1]]),
            ..Default::default()
        };
        let mut i = 34usize;
        let sid_len = body[i] as usize;
        i += 1 + sid_len;
        let cipher_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
        i += 2;
        for c in body[i..i + cipher_len].chunks(2) {
            p.ciphers.push(u16::from_be_bytes([c[0], c[1]]));
        }
        i += cipher_len;
        i += 1 + body[i] as usize; // compression methods
        let exts = super::super::codec::parse_extensions(body, &mut i).expect("extensions");
        for (t, d) in exts {
            p.extensions.push(t);
            match t {
                super::super::codec::EXT_SERVER_NAME => p.has_sni = true,
                super::super::codec::EXT_SUPPORTED_GROUPS => {
                    let mut q = 2usize;
                    while q + 2 <= d.len() {
                        p.groups.push(u16::from_be_bytes([d[q], d[q + 1]]));
                        q += 2;
                    }
                }
                super::super::codec::EXT_SIGNATURE_ALGORITHMS => {
                    let mut q = 2usize;
                    while q + 2 <= d.len() {
                        p.signature_algorithms
                            .push(u16::from_be_bytes([d[q], d[q + 1]]));
                        q += 2;
                    }
                }
                super::super::codec::EXT_EC_POINT_FORMATS => {
                    let n = d[0] as usize;
                    p.point_formats.extend_from_slice(&d[1..1 + n]);
                }
                super::super::codec::EXT_SUPPORTED_VERSIONS => {
                    let n = d[0] as usize;
                    let mut q = 1usize;
                    while q + 2 <= 1 + n {
                        p.supported_versions
                            .push(u16::from_be_bytes([d[q], d[q + 1]]));
                        q += 2;
                    }
                }
                super::super::codec::EXT_ALPN => {
                    let mut q = 2usize;
                    while q < d.len() {
                        let len = d[q] as usize;
                        q += 1;
                        p.alpn
                            .push(String::from_utf8_lossy(&d[q..q + len]).into_owned());
                        q += len;
                    }
                }
                _ => {}
            }
        }
        p
    }

    /// The Chrome profile is emitted faithfully: cipher list, extension set
    /// (minus the documented omissions), groups, signature algorithms and
    /// ALPN are exactly the profile's, so the JA3 of what we send equals the
    /// JA3 of the profile with those omissions removed.
    #[test]
    fn chrome_shape_matches_profile_minus_omissions() {
        let alpn = alloc::vec!["h2".to_string(), "http/1.1".to_string()];
        let random = [0x5au8; 32];
        let hello = build_client_hello(&spec(Fingerprint::Chrome, &random, &alpn)).expect("built");
        let emitted = profile_from_bytes(&hello.raw, 't');

        let expected_profile = chrome_tls_profile();
        // Expected: profile minus the documented omissions.
        let mut expected = expected_profile.clone();
        expected
            .extensions
            .retain(|t| !KNOWN_OMISSIONS.iter().any(|(o, _)| o == t));

        let mut emitted_sorted = emitted.clone();
        emitted_sorted.extensions = without_grease(&emitted_sorted.extensions);
        emitted_sorted.extensions.sort_unstable();
        let mut expected_sorted = expected.clone();
        expected_sorted.extensions.sort_unstable();
        assert_eq!(
            emitted_sorted.extensions, expected_sorted.extensions,
            "extension set must match the profile minus documented omissions"
        );
        assert_eq!(
            without_grease(&emitted.ciphers),
            expected.ciphers,
            "cipher suite list"
        );
        assert_eq!(
            without_grease(&emitted.groups),
            expected.groups,
            "supported groups"
        );
        assert_eq!(
            without_grease(&emitted.supported_versions),
            expected.supported_versions,
            "supported versions"
        );
        assert_eq!(
            emitted.signature_algorithms, expected.signature_algorithms,
            "signature algorithms"
        );
        assert_eq!(emitted.alpn, expected.alpn, "ALPN");
        assert_eq!(emitted.point_formats, expected.point_formats);

        // GREASE (RFC 8701) is on the wire in the cipher list, the extension
        // list and the group list, and the reported omissions are exactly the
        // documented ones.
        assert!(emitted.ciphers.iter().any(|c| is_grease_val(*c)));
        assert!(emitted.extensions.iter().any(|e| is_grease_val(*e)));
        assert!(emitted.groups.iter().any(|g| is_grease_val(*g)));
        assert_eq!(hello.omitted_extensions.len(), KNOWN_OMISSIONS.len());

        // Fingerprints: JA4 ignores GREASE, JA3 keeps it, so the emitted
        // hello is compared after filtering GREASE out (which is what a
        // capture-based JA3 would report for a browser that sends GREASE).
        let mut emitted_no_grease = emitted.clone();
        emitted_no_grease.ciphers = without_grease(&emitted_no_grease.ciphers);
        emitted_no_grease.groups = without_grease(&emitted_no_grease.groups);
        emitted_no_grease.extensions = without_grease(&emitted_no_grease.extensions);
        emitted_no_grease.supported_versions =
            without_grease(&emitted_no_grease.supported_versions);
        assert_eq!(
            ja3_string(&emitted_no_grease),
            ja3_string(&expected),
            "JA3 string (GREASE filtered)"
        );
        assert_eq!(
            ja3_hash(&emitted_no_grease),
            ja3_hash(&expected),
            "JA3 hash (GREASE filtered)"
        );
        assert_eq!(ja4(&emitted_no_grease), ja4(&expected), "JA4");
        // On the wire the GREASE values are present, exactly as a real Chrome
        // hello carries them.
        assert_ne!(ja3_string(&emitted), ja3_string(&expected));
    }

    fn is_grease_val(v: u16) -> bool {
        v & 0x000f == 0x000a && (v >> 8) == (v & 0x00ff)
    }

    /// GREASE (RFC 8701) values are per-connection and are filtered out of
    /// JA3/JA4; comparisons of the *shape* must do the same.
    fn without_grease(values: &[u16]) -> Vec<u16> {
        values
            .iter()
            .copied()
            .filter(|v| !is_grease_val(*v))
            .collect()
    }

    /// The session id sits at the fixed offset REALITY rewrites.
    #[test]
    fn session_id_offset_is_fixed() {
        let alpn = alloc::vec!["h2".to_string()];
        let mut session_id = [0u8; 32];
        session_id[0] = 0xAB;
        let mut s = spec(Fingerprint::Chrome, &[0x11; 32], &alpn);
        s.session_id = session_id;
        let hello = build_client_hello(&s).expect("built");
        assert_eq!(hello.session_id_offset, SESSION_ID_OFFSET);
        assert_eq!(
            &hello.raw[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32],
            &session_id[..]
        );
        // The handshake header advertises the true body length.
        let declared = ((hello.raw[1] as usize) << 16)
            | ((hello.raw[2] as usize) << 8)
            | hello.raw[3] as usize;
        assert_eq!(declared + 4, hello.raw.len());
    }

    /// Padding brings Chrome-shaped messages to a 512-byte boundary; the
    /// message stays within the record limit and parses end to end.
    #[test]
    fn chrome_padding_is_bounded_and_parsable() {
        for seed in 0u8..16 {
            let alpn = alloc::vec!["h2".to_string(), "http/1.1".to_string()];
            let random = [seed; 32];
            let hello =
                build_client_hello(&spec(Fingerprint::Chrome, &random, &alpn)).expect("built");
            assert!(hello.raw.len() <= 2 * 16384, "fits in two records");
            // A full parse walks every extension and rejects malformed ones.
            let emitted = profile_from_bytes(&hello.raw, 't');
            assert!(
                emitted
                    .extensions
                    .contains(&super::super::codec::EXT_PADDING),
                "browser-shaped messages carry the padding extension"
            );
            assert_eq!(
                hello.raw.len() % 512,
                0,
                "a padded message ends on a 512-byte boundary"
            );
        }
    }

    /// `Randomized` varies per connection but stays parseable and keeps the
    /// same *set* of extensions (GREASE excluded) as Chrome minus omissions.
    #[test]
    fn randomized_varies_shape_but_keeps_the_set() {
        let alpn = alloc::vec!["h2".to_string()];
        let mut reference: Option<Vec<u16>> = None;
        let mut non_sorted_orders = 0usize;
        for seed in 0u8..8 {
            let hello = build_client_hello(&spec(Fingerprint::Randomized, &[seed; 32], &alpn))
                .expect("built");
            let emitted = profile_from_bytes(&hello.raw, 't');
            let order = without_grease(&emitted.extensions);
            let mut sorted = order.clone();
            sorted.sort_unstable();
            match &reference {
                Some(prev) => assert_eq!(*prev, sorted, "the extension set stays constant"),
                None => reference = Some(sorted.clone()),
            }
            if order != sorted {
                non_sorted_orders += 1;
            }
        }
        assert!(
            non_sorted_orders > 0,
            "at least one connection presents a non-sorted extension order"
        );
    }

    /// `Off` is a valid minimal handshake: no GREASE, X25519 only, TLS 1.3.
    #[test]
    fn off_profile_is_minimal_and_valid() {
        let alpn = alloc::vec!["h2".to_string()];
        let hello = build_client_hello(&spec(Fingerprint::Off, &[0x22; 32], &alpn)).expect("built");
        let emitted = profile_from_bytes(&hello.raw, 't');
        assert!(!emitted.ciphers.iter().any(|c| is_grease_val(*c)));
        assert_eq!(
            emitted.groups,
            alloc::vec![super::super::codec::GROUP_X25519]
        );
        assert_eq!(emitted.supported_versions, alloc::vec![0x0304]);
        assert_eq!(emitted.extensions[0], super::super::codec::EXT_SERVER_NAME);
        assert!(hello.omitted_extensions.is_empty());
    }

    /// Unshipped browser names are rejected instead of being silently
    /// replaced by a different shape.
    #[test]
    fn unshipped_fingerprint_names_are_rejected() {
        for name in ["firefox", "safari", "ios", "edge", "android"] {
            let err = Fingerprint::parse(name).unwrap_err();
            assert!(err.to_string().contains(name), "error names the profile");
        }
        assert!(matches!(
            Fingerprint::parse("chrome").unwrap(),
            Fingerprint::Chrome
        ));
        assert!(matches!(Fingerprint::parse("").unwrap(), Fingerprint::Off));
    }

    /// A custom profile gets exactly its declared shape for the extensions we
    /// can construct, and unknown ones are reported, never guessed.
    #[test]
    fn custom_profile_reports_unknown_extensions() {
        let alpn = alloc::vec!["h2".to_string()];
        let mut profile = chrome_tls_profile();
        profile.extensions.push(0x1234); // not a constructible extension
        let hello = build_client_hello(&spec(Fingerprint::Custom(profile), &[0x33; 32], &alpn))
            .expect("built");
        assert!(hello.omitted_extensions.iter().any(|(t, _)| *t == 0x1234));
        let emitted = profile_from_bytes(&hello.raw, 't');
        assert!(!emitted.extensions.contains(&0x1234));
    }
}
