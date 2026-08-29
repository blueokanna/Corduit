use alloc::string::String;
use thiserror::Error;

/// Protocol-level error for the wire codecs. `no_std + alloc` — the `Io`
/// variant carries the message text so no `std::io` dependency leaks into
/// the no_std core.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("TLS error: {0}")]
    Tls(String),

    #[error("WireGuard error: {0}")]
    WireGuard(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Handshake error: {0}")]
    Handshake(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("IO error: {0}")]
    Io(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Authentication failed")]
    AuthFailed,

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Timeout")]
    Timeout,

    #[error("Address parse error: {0}")]
    AddressParse(String),

    #[error("Unsupported address type: {0}")]
    UnsupportedAddressType(u8),

    #[error("Buffer too small")]
    BufferTooSmall,
}

#[cfg(feature = "std")]
impl From<std::io::Error> for ProtocolError {
    fn from(err: std::io::Error) -> Self {
        ProtocolError::Io(err.to_string())
    }
}

pub type Result<T> = core::result::Result<T, ProtocolError>;
