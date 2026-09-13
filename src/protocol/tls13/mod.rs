//! # In-repo TLS 1.3 client (RFC 8446) with profile-shaped `ClientHello`
//!
//! TLS 1.2/1.3 for the rest of the engine is courierust's connector, whose
//! `ClientHello` is fixed. This module is the piece courierust deliberately
//! does not provide: a TLS 1.3 client whose **`ClientHello` wire shape is
//! data-driven**, so a connection can present the cipher/extensions/signature
//! set of a known client (see [`fingerprint`]), and whose **server
//! authentication is a hook** — the default x509 chain check, or REALITY's
//! ephemeral-certificate proof ([`crate::protocol::reality`]).
//!
//! ## Layout
//!
//! | part | `no_std` | contents |
//! |---|---|---|
//! | [`fingerprint`] | yes | `Fingerprint` profiles + the `ClientHello` builder |
//! | `codec` | yes | handshake/extension codecs, `ServerHello` parsing, signature verification |
//! | `key_schedule` | yes | RFC 8446 §7.1 key schedule (labeled HKDF, traffic keys) |
//! | `record` | yes | RFC 8446 §5 TLS record protection (AEAD, inner content type) |
//! | `client` | no | the synchronous handshake driver over `Read`/`Write` |
//!
//! The pure parts compile on `no_std + alloc`; only the driver needs `std`.
//!
//! ## What is deliberately not implemented
//!
//! Every omission below is reported, never papered over:
//!
//! * **0-RTT / early data** — no `early_data` extension is offered.
//! * **HelloRetryRequest** — rejected: the client offers exactly one key
//!   share (X25519), so a retry cannot help (RFC 8446 §4.1.4 allows a client
//!   to abort).
//! * **TLS 1.2 fallback** — rejected: this client is 1.3-only by design.
//! * **Certificate compression (RFC 8879)** — not advertised and not
//!   decompressed; see [`fingerprint`] for the reported deviation.
//! * **Client certificates / post-handshake auth** — not offered.
//! * **PSK resumption** — `NewSessionTicket` is parsed and ignored.

// Without `std` the handshake driver is not compiled, so the codecs and the
// key schedule it drives look unreferenced to the lint. That is expected: the
// same items are exercised by the `std` build.
#![cfg_attr(not(feature = "std"), allow(dead_code, unused_imports))]

pub mod fingerprint;

pub(crate) mod codec;
pub(crate) mod key_schedule;
pub(crate) mod record;

#[cfg(feature = "std")]
pub(crate) mod client;

use alloc::string::{String, ToString};
use core::fmt;

#[cfg(feature = "std")]
pub use client::{
    connect, ClientHelloDraft, ClientHelloHook, ServerAuth, Tls13ClientConfig, Tls13Stream,
    X509ServerAuth,
};

/// Errors produced by the TLS 1.3 client.
#[derive(Debug, Clone)]
pub enum Tls13Error {
    /// Underlying transport failure.
    Io(String),
    /// The peer violated the handshake protocol.
    Protocol(String),
    /// Server certificate/authentication failure.
    Certificate(String),
    /// The peer sent a fatal alert.
    Alert {
        /// Alert level (1 = warning, 2 = fatal).
        level: u8,
        /// Alert description code (RFC 8446 §6).
        description: u8,
    },
    /// A required feature was not offered/negotiated.
    Unsupported(String),
    /// Invalid local configuration.
    InvalidConfig(String),
    /// The connection is closed.
    Closed,
}

impl fmt::Display for Tls13Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Tls13Error::Io(m) => write!(f, "TLS I/O error: {m}"),
            Tls13Error::Protocol(m) => write!(f, "TLS protocol error: {m}"),
            Tls13Error::Certificate(m) => write!(f, "TLS certificate error: {m}"),
            Tls13Error::Alert { level, description } => {
                write!(f, "TLS alert (level {level}, description {description})")
            }
            Tls13Error::Unsupported(m) => write!(f, "TLS unsupported: {m}"),
            Tls13Error::InvalidConfig(m) => write!(f, "TLS invalid config: {m}"),
            Tls13Error::Closed => write!(f, "TLS connection closed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Tls13Error {}

#[cfg(feature = "std")]
impl From<std::io::Error> for Tls13Error {
    fn from(e: std::io::Error) -> Self {
        Tls13Error::Io(e.to_string())
    }
}

impl From<courierust::courierust_error::Error> for Tls13Error {
    fn from(e: courierust::courierust_error::Error) -> Self {
        Tls13Error::Io(e.to_string())
    }
}

/// Result alias for this module.
pub type Result<T> = core::result::Result<T, Tls13Error>;
