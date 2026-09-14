use thiserror::Error;

/// Network stack specific errors
#[derive(Error, Debug)]
pub enum NetStackError {
    #[error("TUN device error: {0}")]
    TunError(String),

    #[error("TUN device not found or wintun.dll missing")]
    TunNotAvailable,

    #[error("TCP stack error: {0}")]
    TcpError(String),

    #[error("UDP stack error: {0}")]
    UdpError(String),

    #[error("Network interface error: {0}")]
    InterfaceError(String),

    #[error("Routing error: {0}")]
    RoutingError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Address parse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    #[error("Channel closed")]
    ChannelClosed,

    #[error("Stack not running")]
    NotRunning,

    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    #[error("Connection refused")]
    ConnectionRefused,

    #[error("Connection reset")]
    ConnectionReset,

    #[error("Connection timeout")]
    Timeout,

    #[error("NAT table full")]
    NatTableFull,

    #[error("Unsupported protocol: {0}")]
    UnsupportedProtocol(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

pub type Result<T> = std::result::Result<T, NetStackError>;
