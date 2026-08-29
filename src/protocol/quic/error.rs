//! QUIC client errors.

use std::fmt;

/// Errors produced by the QUIC client transport.
#[derive(Debug, Clone)]
pub enum QuicError {
    /// I/O failure on the UDP socket.
    Io(String),
    /// The peer sent a malformed or protocol-violating packet.
    Protocol(String),
    /// The TLS handshake failed.
    Tls(String),
    /// Certificate validation failed.
    Certificate(String),
    /// Handshake did not complete in time.
    Timeout,
    /// The connection was closed by the peer.
    ClosedByPeer { error_code: u64, reason: String },
    /// The connection was closed locally.
    Closed,
    /// A stream was reset by the peer.
    StreamReset { error_code: u64 },
    /// Flow-control / stream-limit violation.
    StreamLimit,
    /// The datagram exceeds the maximum size a single QUIC packet can carry
    /// (RFC 9221 §2). The sender must fragment it.
    DatagramTooLarge,
    /// Invalid configuration.
    InvalidConfig(String),
    /// Idle timeout expired.
    IdleTimeout,
}

impl fmt::Display for QuicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuicError::Io(m) => write!(f, "QUIC I/O error: {m}"),
            QuicError::Protocol(m) => write!(f, "QUIC protocol error: {m}"),
            QuicError::Tls(m) => write!(f, "QUIC TLS error: {m}"),
            QuicError::Certificate(m) => write!(f, "QUIC certificate error: {m}"),
            QuicError::Timeout => write!(f, "QUIC handshake timeout"),
            QuicError::ClosedByPeer { error_code, reason } => {
                write!(f, "QUIC closed by peer (code {error_code}): {reason}")
            }
            QuicError::Closed => write!(f, "QUIC connection closed"),
            QuicError::StreamReset { error_code } => {
                write!(f, "QUIC stream reset by peer (code {error_code})")
            }
            QuicError::StreamLimit => write!(f, "QUIC stream limit exceeded"),
            QuicError::DatagramTooLarge => write!(f, "QUIC datagram exceeds packet size"),
            QuicError::InvalidConfig(m) => write!(f, "QUIC invalid config: {m}"),
            QuicError::IdleTimeout => write!(f, "QUIC idle timeout"),
        }
    }
}

impl std::error::Error for QuicError {}

impl From<std::io::Error> for QuicError {
    fn from(e: std::io::Error) -> Self {
        QuicError::Io(e.to_string())
    }
}

impl From<courierust::courierust_error::Error> for QuicError {
    fn from(e: courierust::courierust_error::Error) -> Self {
        QuicError::Protocol(e.to_string())
    }
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, QuicError>;
