//! # REALITY client
//!
//! REALITY (XTLS) lets a proxy server present a *plausible* TLS handshake to
//! whoever asks: the server needs no certificate of its own, and clients that
//! know its public key get an authenticated session, while everyone else is
//! forwarded to a real decoy site.
//!
//! This module implements the **client** in-repo, on top of
//! [`crate::protocol::tls13`]:
//!
//! * [`wire`] — the authenticated `legacy_session_id` and the
//!   ephemeral-certificate proof (pure, `no_std`, unit-tested against the
//!   inverse server operations);
//! * [`RealityClientOptions`] — the config surface (`public-key`, `short-id`,
//!   `server-name`, `fingerprint`, …), validated at construction;
//! * `connect` — a TLS 1.3 handshake whose `ClientHello` carries the sealed
//!   session id and whose server authentication is the REALITY proof instead
//!   of a CA chain.
//!
//! ## What is deliberately not implemented
//!
//! * **`mldsa65Verify`** (optional ML-DSA-65 signature over the ephemeral
//!   certificate): rejected with an explicit error rather than ignored,
//!   because a client that skips the check it was configured to perform would
//!   silently claim more than it verifies.
//! * **Spider mode**: when a client receives a *real* certificate the
//!   reference implementation crawls the decoy site to look like a browser
//!   before dropping the connection. This client reports the situation as a
//!   hard error (`REALITY fallback`) and closes; `spider-x` is parsed so
//!   configs are accepted, but no crawling is performed. Treating a
//!   redirection or MITM as an error is the safe half of that behaviour.
//! * **Server side**: authenticating a concurrent *client* is provided by
//!   [`wire::unseal_session_id`] (and tested), but a REALITY *server* would
//!   need an Ed25519 private key to sign `CertificateVerify`, which this
//!   crate's crypto layer does not provide; no fake half-server is shipped.

pub mod wire;

#[cfg(feature = "std")]
mod client;

#[cfg(feature = "std")]
pub use client::{connect, RealityClientOptions};

use alloc::string::String;
use core::fmt;

/// Errors produced by the REALITY layer.
#[derive(Debug, Clone)]
pub enum RealityError {
    /// An option is missing or malformed.
    Config(String),
    /// The session-id carrier is malformed (never a valid REALITY hello).
    Wire(String),
    /// The session id did not authenticate under this key.
    Unauthenticated,
    /// The server presented a real certificate: the REALITY handshake did not
    /// happen (rejection, redirection, or a man in the middle).
    Fallback(String),
    /// A configured feature is not implemented.
    Unsupported(String),
}

impl fmt::Display for RealityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RealityError::Config(m) => write!(f, "REALITY config error: {m}"),
            RealityError::Wire(m) => write!(f, "REALITY wire error: {m}"),
            RealityError::Unauthenticated => {
                write!(f, "REALITY session id failed authentication")
            }
            RealityError::Fallback(m) => write!(f, "REALITY fallback: {m}"),
            RealityError::Unsupported(m) => write!(f, "REALITY unsupported: {m}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RealityError {}

impl From<RealityError> for crate::protocol::tls13::Tls13Error {
    fn from(e: RealityError) -> Self {
        match e {
            RealityError::Fallback(m) => crate::protocol::tls13::Tls13Error::Certificate(m),
            other => crate::protocol::tls13::Tls13Error::InvalidConfig(other.to_string()),
        }
    }
}

/// Result alias for this module.
pub type Result<T> = core::result::Result<T, RealityError>;

/// The version bytes this client claims inside the session id.
///
/// The reference stores the *client's* Xray version there, and servers may
/// enforce a window with `minClientVer` / `maxClientVer`. This crate reports
/// its own version; a server configured to require a specific Xray version
/// will reject it (that is the honest answer — claiming to be a different
/// implementation would be a lie in the handshake).
pub fn client_version() -> [u8; 3] {
    let mut out = [0u8; 3];
    let version = env!("CARGO_PKG_VERSION");
    for (slot, part) in out.iter_mut().zip(version.split('.')) {
        let numeric: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
        *slot = numeric.parse::<u8>().unwrap_or(0);
    }
    out
}
