//! Failure modes of the traversal layer.

use alloc::string::String;
use core::net::SocketAddr;
use thiserror::Error;

/// Everything NAT traversal can fail with.
///
/// The variants are deliberately specific. "Traversal failed" tells an operator
/// nothing; knowing whether the STUN server never answered, the NAT defeated
/// every probe, or the platform cannot do TCP simultaneous open is the
/// difference between a config change and a rewrite.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NatError {
    /// A STUN transaction got no usable answer within its deadline.
    #[error("no STUN answer from {server}: {detail}")]
    NoResponse {
        /// Server that was asked.
        server: SocketAddr,
        /// What went wrong, in enough detail to act on.
        detail: String,
    },

    /// A STUN message was malformed, or the server rejected the request.
    #[error("STUN protocol error: {0}")]
    Stun(crate::nat::stun::StunError),

    /// The socket layer failed.
    ///
    /// Carried as text rather than `std::io::Error` so this type stays usable
    /// from the `no_std` codec side, where there is no `io` module.
    #[error("socket error: {0}")]
    Io(String),

    /// A NAT behaviour could not be established, and the reason is not a
    /// failure so much as an absence of evidence.
    ///
    /// The usual cause is a STUN server that does not implement RFC 5780:
    /// without an alternate address to answer from, filtering behaviour is
    /// simply not observable, and reporting a guess would be worse than
    /// reporting nothing.
    #[error("NAT behaviour could not be determined: {detail}")]
    Undetermined {
        /// Why the answer is missing.
        detail: String,
    },

    /// A transport exists in principle but not here.
    #[error("{transport} traversal is unavailable: {detail}")]
    Unsupported {
        /// Transport that was asked for.
        transport: &'static str,
        /// Why, and what would have to change.
        detail: String,
    },

    /// Every probe was sent and none of them produced a peer.
    #[error("no path established after {attempts} probes: {detail}")]
    NoPath {
        /// Probes actually sent before giving up.
        attempts: u32,
        /// Summary of what was tried.
        detail: String,
    },

    /// The plan handed to the puncher cannot work.
    #[error("unusable traversal plan: {detail}")]
    InvalidPlan {
        /// What is wrong with it.
        detail: String,
    },
}

impl From<crate::nat::stun::StunError> for NatError {
    fn from(error: crate::nat::stun::StunError) -> Self {
        Self::Stun(error)
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for NatError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(alloc::string::ToString::to_string(&error))
    }
}
