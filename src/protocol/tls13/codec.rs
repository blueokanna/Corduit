//! Handshake/extension codecs and signature verification shared by the TLS
//!
//! Byte-level codecs only: no I/O, no buffering policy — every function is a
//! pure transform over slices, which keeps the whole module usable from
//! `no_std + alloc` code and from tests without sockets.

use super::{Result, Tls13Error};
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Handshake message types (RFC 8446 §4)
// ---------------------------------------------------------------------------

/// `client_hello`.
pub(crate) const HS_CLIENT_HELLO: u8 = 1;
/// `server_hello`.
pub(crate) const HS_SERVER_HELLO: u8 = 2;
/// `new_session_ticket`.
pub(crate) const HS_NEW_SESSION_TICKET: u8 = 4;
/// `encrypted_extensions`.
pub(crate) const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
/// `certificate`.
pub(crate) const HS_CERTIFICATE: u8 = 11;
/// `certificate_verify`.
pub(crate) const HS_CERTIFICATE_VERIFY: u8 = 15;
/// `finished`.
pub(crate) const HS_FINISHED: u8 = 20;
/// `key_update`.
pub(crate) const HS_KEY_UPDATE: u8 = 24;

// ---------------------------------------------------------------------------
// Extension types (RFC 8446 §4.2, RFC 6066, RFC 8449, RFC 8879)
// ---------------------------------------------------------------------------

/// `server_name`.
pub(crate) const EXT_SERVER_NAME: u16 = 0x0000;
/// `status_request`.
pub(crate) const EXT_STATUS_REQUEST: u16 = 0x0005;
/// `supported_groups`.
pub(crate) const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
/// `ec_point_formats`.
pub(crate) const EXT_EC_POINT_FORMATS: u16 = 0x000b;
/// `signature_algorithms`.
pub(crate) const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
/// `application_layer_protocol_negotiation`.
pub(crate) const EXT_ALPN: u16 = 0x0010;
/// `signed_certificate_timestamp`.
pub(crate) const EXT_SIGNED_CERTIFICATE_TIMESTAMP: u16 = 0x0012;
/// `padding`.
pub(crate) const EXT_PADDING: u16 = 0x0015;
/// `extended_master_secret`.
pub(crate) const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
/// `compress_certificate`.
pub(crate) const EXT_COMPRESS_CERTIFICATE: u16 = 0x001b;
/// `session_ticket`.
pub(crate) const EXT_SESSION_TICKET: u16 = 0x0023;
/// `supported_versions`.
pub(crate) const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
/// `psk_key_exchange_modes`.
pub(crate) const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
/// `key_share`.
pub(crate) const EXT_KEY_SHARE: u16 = 0x0033;
/// `application_settings` (ALPS — Chromium).
pub(crate) const EXT_APPLICATION_SETTINGS: u16 = 0x4469;
/// `renegotiation_info` (RFC 5746).
pub(crate) const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/// The `compressed_certificate` certificate-entry extension (RFC 8879 §4).
pub(crate) const CERT_EXT_COMPRESSED_CERTIFICATE: u16 = 0x001b;

// ---------------------------------------------------------------------------
// Named groups and signature schemes
// ---------------------------------------------------------------------------

/// `x25519` (RFC 8446 §4.2.7).
pub(crate) const GROUP_X25519: u16 = 0x001d;

/// `rsa_pss_rsae_sha256`.
pub(crate) const SIG_RSA_PSS_SHA256: u16 = 0x0804;
/// `rsa_pss_rsae_sha384`.
pub(crate) const SIG_RSA_PSS_SHA384: u16 = 0x0805;
/// `ecdsa_secp256r1_sha256`.
pub(crate) const SIG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
/// `ecdsa_secp384r1_sha384`.
pub(crate) const SIG_ECDSA_SECP384R1_SHA384: u16 = 0x0503;
/// `ed25519`.
pub(crate) const SIG_ED25519: u16 = 0x0807;

/// The HelloRetryRequest random (RFC 8446 §4.1.3): SHA-256 of
/// `"HelloRetryRequest"`.
pub(crate) const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// TLS 1.2 downgrade sentinel (`DOWNGRD\x00`) in `ServerHello.random`
/// (RFC 8446 §4.1.3).
pub(crate) const DOWNGRADE_TLS12: [u8; 8] = [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00];

/// TLS 1.3 cipher suite: `TLS_AES_128_GCM_SHA256`.
pub const SUITE_AES_128: u16 = 0x1301;
/// TLS 1.3 cipher suite: `TLS_AES_256_GCM_SHA384`.
pub const SUITE_AES_256: u16 = 0x1302;
/// TLS 1.3 cipher suite: `TLS_CHACHA20_POLY1305_SHA256`.
pub const SUITE_CHACHA: u16 = 0x1303;

/// Whether `suite` is a TLS 1.3 cipher suite this client implements.
pub(crate) fn is_supported_suite(suite: u16) -> bool {
    matches!(suite, SUITE_AES_128 | SUITE_AES_256 | SUITE_CHACHA)
}

/// Hash length of a TLS 1.3 cipher suite (32 for SHA-256, 48 for SHA-384).
pub(crate) fn suite_hash_len(suite: u16) -> usize {
    if suite == SUITE_AES_256 {
        48
    } else {
        32
    }
}

/// Traffic key length of a TLS 1.3 cipher suite.
pub(crate) fn suite_key_len(suite: u16) -> usize {
    if suite == SUITE_AES_128 {
        16
    } else {
        32
    }
}

// ---------------------------------------------------------------------------
// Handshake message framing
// ---------------------------------------------------------------------------

/// Frame a handshake message: 1-byte type + 3-byte length + body.
pub(crate) fn hs_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(msg_type);
    let len = body.len();
    out.push((len >> 16) as u8);
    out.push((len >> 8) as u8);
    out.push(len as u8);
    out.extend_from_slice(body);
    out
}

/// Decode one handshake message from the front of `buf`.
///
/// Returns `(type, body, consumed)`; `None` when the buffer does not yet hold
/// a complete message.
pub(crate) fn read_hs_message(buf: &[u8]) -> Option<(u8, &[u8], usize)> {
    if buf.len() < 4 {
        return None;
    }
    let len = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | buf[3] as usize;
    if buf.len() < 4 + len {
        return None;
    }
    Some((buf[0], &buf[4..4 + len], 4 + len))
}

/// Decode the next handshake message in `buf` at `*pos`, advancing `*pos`.
pub(crate) fn take_hs_message<'a>(buf: &'a [u8], pos: &mut usize) -> Option<(u8, &'a [u8])> {
    let (msg_type, body, consumed) = read_hs_message(&buf[*pos..])?;
    *pos += consumed;
    Some((msg_type, body))
}

// ---------------------------------------------------------------------------
// Extension framing
// ---------------------------------------------------------------------------

/// Frame one extension: 2-byte type + 2-byte length + body.
pub(crate) fn encode_extension(ext_type: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Parse an extension block (the 2-byte total length is included in `buf`).
pub(crate) fn parse_extensions(buf: &[u8], pos: &mut usize) -> Result<Vec<(u16, Vec<u8>)>> {
    if buf.len() - *pos < 2 {
        return Err(Tls13Error::Protocol("truncated extension block".into()));
    }
    let total = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]) as usize;
    *pos += 2;
    if buf.len() - *pos < total {
        return Err(Tls13Error::Protocol("truncated extension block".into()));
    }
    let end = *pos + total;
    let mut out = Vec::new();
    while *pos < end {
        if end - *pos < 4 {
            return Err(Tls13Error::Protocol("truncated extension".into()));
        }
        let ext_type = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]);
        let ext_len = u16::from_be_bytes([buf[*pos + 2], buf[*pos + 3]]) as usize;
        *pos += 4;
        if end - *pos < ext_len {
            return Err(Tls13Error::Protocol("truncated extension body".into()));
        }
        out.push((ext_type, buf[*pos..*pos + ext_len].to_vec()));
        *pos += ext_len;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// ServerHello
// ---------------------------------------------------------------------------

/// The parsed parts of a `ServerHello` that the client acts on.
#[derive(Debug, Clone)]
pub(crate) struct ServerHello {
    /// The echoed legacy session id.
    pub legacy_session_id_echo: Vec<u8>,
    /// The server-selected cipher suite.
    pub suite: u16,
    /// The server's X25519 key share.
    pub key_share: [u8; 32],
}

/// Parse a `ServerHello` body (without the 4-byte handshake header).
///
/// Rejects HelloRetryRequest and downgrade sentinels with a clear error: this
/// client offers exactly one key share and TLS 1.3 only.
pub(crate) fn parse_server_hello(body: &[u8]) -> Result<ServerHello> {
    if body.len() < 35 {
        return Err(Tls13Error::Protocol("truncated ServerHello".into()));
    }
    let mut random = [0u8; 32];
    random.copy_from_slice(&body[2..34]);
    if random == HRR_RANDOM {
        return Err(Tls13Error::Unsupported(
            "server sent HelloRetryRequest (this client offers a single X25519 key share)".into(),
        ));
    }
    if random[24..] == DOWNGRADE_TLS12 {
        return Err(Tls13Error::Unsupported(
            "server signals a TLS 1.2 downgrade; refusing TLS 1.2".into(),
        ));
    }

    let sid_len = body[34] as usize;
    if body.len() < 35 + sid_len + 3 {
        return Err(Tls13Error::Protocol("truncated ServerHello".into()));
    }
    let legacy_session_id_echo = body[35..35 + sid_len].to_vec();
    let mut pos = 35 + sid_len;
    let suite = u16::from_be_bytes([body[pos], body[pos + 1]]);
    pos += 2;
    if !is_supported_suite(suite) {
        return Err(Tls13Error::Unsupported(alloc::format!(
            "server selected unsupported cipher suite 0x{suite:04x}"
        )));
    }
    if body[pos] != 0x00 {
        return Err(Tls13Error::Protocol(
            "server selected a compression method".into(),
        ));
    }
    pos += 1;

    let exts = parse_extensions(body, &mut pos)?;
    let key_share = exts
        .iter()
        .find(|(t, _)| *t == EXT_KEY_SHARE)
        .map(|(_, d)| d)
        .ok_or_else(|| Tls13Error::Protocol("ServerHello missing key_share".into()))?;
    if key_share.len() < 4 || key_share[0..2] != GROUP_X25519.to_be_bytes() {
        return Err(Tls13Error::Unsupported(
            "ServerHello key_share is not X25519".into(),
        ));
    }
    let key_len = u16::from_be_bytes([key_share[2], key_share[3]]) as usize;
    if key_share.len() < 4 + key_len || key_len != 32 {
        return Err(Tls13Error::Protocol("invalid ServerHello key_share".into()));
    }
    let mut server_pub = [0u8; 32];
    server_pub.copy_from_slice(&key_share[4..4 + 32]);

    Ok(ServerHello {
        legacy_session_id_echo,
        suite,
        key_share: server_pub,
    })
}

// ---------------------------------------------------------------------------
// CertificateVerify signature verification
// ---------------------------------------------------------------------------

use courierust::courierust_tls::crypto::hash::Digest as _;
use courierust::courierust_tls::crypto::hash::{Sha256, Sha384};
use courierust::courierust_tls::crypto::{ecdsa, ed25519, rsa};
use courierust::courierust_tls::x509::Spki;

/// The content a TLS 1.3 `CertificateVerify` signs (RFC 8446 §4.4.3):
///
/// ```text
/// 64 x 0x20 || context_string || 0x00 || Transcript-Hash(...)
/// ```
///
/// The context string (`TLS 1.3, server CertificateVerify` or the client
/// variant) already carries its NUL terminator here.
pub(crate) fn cert_verify_content(transcript_hash: &[u8], client: bool) -> Vec<u8> {
    let context: &[u8] = if client {
        b"TLS 1.3, client CertificateVerify\x00"
    } else {
        b"TLS 1.3, server CertificateVerify\x00"
    };
    let mut out = vec![0x20u8; 64];
    out.extend_from_slice(context);
    out.extend_from_slice(transcript_hash);
    out
}

/// Verify a TLS 1.3 `CertificateVerify` signature.
///
/// `content` must be [`cert_verify_content`]. The digest schemes hash this
/// content themselves; ECDSA needs the scheme hash applied here, exactly as
/// RFC 8446 §4.4.3 specifies.
pub(crate) fn verify_signature(spki: &Spki, scheme: u16, content: &[u8], signature: &[u8]) -> bool {
    match scheme {
        SIG_RSA_PSS_SHA256 => {
            let Some((n, e)) = parse_rsa_spki(&spki.key) else {
                return false;
            };
            let key = rsa::RsaPublicKey { n, e };
            let mut d = Sha256::new();
            key.verify_pss(&mut d, content, 32, signature)
        }
        SIG_RSA_PSS_SHA384 => {
            let Some((n, e)) = parse_rsa_spki(&spki.key) else {
                return false;
            };
            let key = rsa::RsaPublicKey { n, e };
            let mut d = Sha384::new();
            key.verify_pss(&mut d, content, 48, signature)
        }
        SIG_ECDSA_SECP256R1_SHA256 => {
            let Some((qx, qy)) = parse_ec_point(&spki.key, 32) else {
                return false;
            };
            let digest = {
                let mut d = Sha256::new();
                d.update(content);
                d.finalize()
            };
            ecdsa::verify_der(ecdsa::Curve::P256, qx, qy, &digest, signature)
        }
        SIG_ECDSA_SECP384R1_SHA384 => {
            let Some((qx, qy)) = parse_ec_point(&spki.key, 48) else {
                return false;
            };
            let digest = {
                let mut d = Sha384::new();
                d.update(content);
                d.finalize()
            };
            ecdsa::verify_der(ecdsa::Curve::P384, qx, qy, &digest, signature)
        }
        SIG_ED25519 => {
            let Some(key): Option<[u8; 32]> = spki.key.get(..32).and_then(|k| k.try_into().ok())
            else {
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

/// Parse an RSA SPKI subjectPublicKey (`DER RSAPublicKey`).
///
/// DER INTEGERs are signed, so a modulus whose top bit is set carries a
/// leading `0x00` pad; the pad is stripped here because the bignum
/// routines take unsigned magnitudes.
fn parse_rsa_spki(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    // SEQUENCE { INTEGER n, INTEGER e }
    if der.len() < 8 || der[0] != 0x30 {
        return None;
    }
    let mut pos = 1usize;
    let _ = der_len(der, &mut pos)?;
    if pos >= der.len() || der[pos] != 0x02 {
        return None;
    }
    pos += 1;
    let (n_len, _) = der_len(der, &mut pos)?;
    if der.len() - pos < n_len {
        return None;
    }
    let n = strip_leading_zeros(&der[pos..pos + n_len]).to_vec();
    pos += n_len;
    if pos >= der.len() || der[pos] != 0x02 {
        return None;
    }
    pos += 1;
    let (e_len, _) = der_len(der, &mut pos)?;
    if der.len() - pos < e_len {
        return None;
    }
    let e = strip_leading_zeros(&der[pos..pos + e_len]).to_vec();
    if n.is_empty() || e.is_empty() {
        return None;
    }
    Some((n, e))
}

/// Strip the signed-INTEGER leading zeros from a DER magnitude.
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let mut i = 0usize;
    while i + 1 < bytes.len() && bytes[i] == 0x00 {
        i += 1;
    }
    &bytes[i..]
}

/// Parse a DER length field; returns `(length, bytes consumed)`.
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

/// Parse an uncompressed EC point `0x04 || x || y` into `(x, y)`.
fn parse_ec_point(key: &[u8], coord: usize) -> Option<(&[u8], &[u8])> {
    if key.len() != 1 + 2 * coord || key[0] != 0x04 {
        return None;
    }
    Some((&key[1..1 + coord], &key[1 + coord..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_framing_round_trips() {
        let msg = hs_message(HS_FINISHED, &[1, 2, 3]);
        assert_eq!(msg[0], HS_FINISHED);
        let (ty, body, used) = read_hs_message(&msg).expect("complete");
        assert_eq!((ty, body, used), (HS_FINISHED, &[1u8, 2, 3][..], 7));
        // Truncated message: no decode, and the caller retries after more I/O.
        assert!(read_hs_message(&msg[..5]).is_none());
    }

    #[test]
    fn extension_block_round_trips() {
        let mut block = Vec::new();
        let mut inner = encode_extension(EXT_SERVER_NAME, b"example.com");
        inner.extend_from_slice(&encode_extension(EXT_PADDING, &[]));
        block.extend_from_slice(&(inner.len() as u16).to_be_bytes());
        block.extend_from_slice(&inner);
        let mut pos = 0usize;
        let exts = parse_extensions(&block, &mut pos).expect("valid");
        assert_eq!(pos, block.len());
        assert_eq!(exts.len(), 2);
        assert_eq!(exts[0].0, EXT_SERVER_NAME);
        assert_eq!(exts[0].1, b"example.com");
        assert_eq!(exts[1], (EXT_PADDING, Vec::new()));
    }

    #[test]
    fn server_hello_parses_x25519_key_share() {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0x11; 32]); // random
        body.push(0); // session id length
        body.extend_from_slice(&SUITE_AES_128.to_be_bytes());
        body.push(0); // compression
        let mut ks = Vec::new();
        ks.extend_from_slice(&GROUP_X25519.to_be_bytes());
        ks.extend_from_slice(&(32u16).to_be_bytes());
        ks.extend_from_slice(&[0x22; 32]);
        let exts = encode_extension(EXT_KEY_SHARE, &ks);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let hello = parse_server_hello(&body).expect("valid ServerHello");
        assert_eq!(hello.suite, SUITE_AES_128);
        assert_eq!(hello.key_share, [0x22; 32]);
    }

    #[test]
    fn server_hello_rejects_hello_retry_request() {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&HRR_RANDOM);
        body.push(0);
        body.extend_from_slice(&SUITE_AES_128.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&[0x00, 0x00]); // empty extensions
        match parse_server_hello(&body) {
            Err(Tls13Error::Unsupported(m)) => assert!(m.contains("HelloRetryRequest")),
            other => panic!("expected HelloRetryRequest rejection, got {other:?}"),
        }
    }

    #[test]
    fn server_hello_rejects_tls12_downgrade_sentinel() {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        let mut random = [0u8; 32];
        random[24..].copy_from_slice(&DOWNGRADE_TLS12);
        body.extend_from_slice(&random);
        body.push(0);
        body.extend_from_slice(&SUITE_AES_128.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&[0x00, 0x00]);
        assert!(matches!(
            parse_server_hello(&body),
            Err(Tls13Error::Unsupported(_))
        ));
    }

    #[test]
    fn server_hello_rejects_unknown_suite() {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x11; 32]);
        body.push(0);
        body.extend_from_slice(&0xc02fu16.to_be_bytes()); // TLS 1.2 suite
        body.push(0);
        body.extend_from_slice(&[0x00, 0x00]);
        assert!(matches!(
            parse_server_hello(&body),
            Err(Tls13Error::Unsupported(_))
        ));
    }

    /// RSA-PSS signatures produced by OpenSSL over fixed messages must verify
    /// with the certificate's SPKI — an independent check of the SPKI parser
    /// and the PSS dispatch (no self-signed-by-our-own-code vector).
    #[test]
    fn rsa_pss_vectors_from_openssl_verify() {
        let cert = courierust::courierust_tls::x509::parse_certificate(include_bytes!(
            "testdata/rsa_cert.der"
        ))
        .expect("parse test certificate");

        let msg = include_bytes!("testdata/pss_msg.bin");
        let sig = include_bytes!("testdata/pss_sig.bin");
        assert!(
            verify_signature(&cert.spki, SIG_RSA_PSS_SHA256, msg, sig),
            "OpenSSL SHA-256 PSS vector must verify"
        );
        assert!(
            !verify_signature(&cert.spki, SIG_RSA_PSS_SHA256, b"tampered", sig),
            "tampered content must not verify"
        );

        let msg384 = include_bytes!("testdata/pss_msg384.bin");
        let sig384 = include_bytes!("testdata/pss_sig384.bin");
        assert!(
            verify_signature(&cert.spki, SIG_RSA_PSS_SHA384, msg384, sig384),
            "OpenSSL SHA-384 PSS vector must verify"
        );
    }

    /// The CertificateVerify content is exactly RFC 8446 §4.4.3: 64 spaces,
    /// the context string incl. its NUL, then the transcript hash.
    #[test]
    fn cert_verify_content_matches_rfc8446() {
        let hash = [0xAB; 32];
        let content = cert_verify_content(&hash, false);
        assert_eq!(&content[..64], &[0x20u8; 64]);
        assert_eq!(
            &content[64..64 + 34],
            b"TLS 1.3, server CertificateVerify\x00"
        );
        assert_eq!(&content[64 + 34..], &hash[..]);
        assert_eq!(content.len(), 64 + 34 + 32);

        let client = cert_verify_content(&hash, true);
        assert_eq!(
            &client[64..64 + 34],
            b"TLS 1.3, client CertificateVerify\x00"
        );
    }
}
