use std::fmt;

#[derive(Debug, Clone)]
pub enum CorduitError {
    Config(String),
    Network(String),
    Dns(String),
    Tls(String),
    Protocol(String),
    Io(String),
    Parse(String),
    Auth(String),
    Timeout(String),
    ResourceExhausted(String),
    Internal(String),
    Routing(String),
    Proxy(String),
}

impl fmt::Display for CorduitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CorduitError::Config(msg) => write!(f, "Config error: {}", msg),
            CorduitError::Network(msg) => write!(f, "Network error: {}", msg),
            CorduitError::Dns(msg) => write!(f, "DNS error: {}", msg),
            CorduitError::Tls(msg) => write!(f, "TLS error: {}", msg),
            CorduitError::Protocol(msg) => write!(f, "Protocol error: {}", msg),
            CorduitError::Io(msg) => write!(f, "IO error: {}", msg),
            CorduitError::Parse(msg) => write!(f, "Parse error: {}", msg),
            CorduitError::Auth(msg) => write!(f, "Auth error: {}", msg),
            CorduitError::Timeout(msg) => write!(f, "Timeout error: {}", msg),
            CorduitError::ResourceExhausted(msg) => write!(f, "Resource exhausted: {}", msg),
            CorduitError::Internal(msg) => write!(f, "Internal error: {}", msg),
            CorduitError::Routing(msg) => write!(f, "Routing error: {}", msg),
            CorduitError::Proxy(msg) => write!(f, "Proxy error: {}", msg),
        }
    }
}

impl std::error::Error for CorduitError {}

impl From<corduit_core::Error> for CorduitError {
    fn from(err: corduit_core::Error) -> Self {
        match err {
            corduit_core::Error::Config { message, .. } => CorduitError::Config(message),
            corduit_core::Error::Network { message, .. } => CorduitError::Network(message),
            corduit_core::Error::Dns { message, .. } => CorduitError::Dns(message),
            corduit_core::Error::Tls { message, .. } => CorduitError::Tls(message),
            corduit_core::Error::Protocol { message, .. } => CorduitError::Protocol(message),
            corduit_core::Error::Io(err) => CorduitError::Io(err.to_string()),
            corduit_core::Error::Parse { message, .. } => CorduitError::Parse(message),
            corduit_core::Error::Auth { message, .. } => CorduitError::Auth(message),
            corduit_core::Error::Timeout { message, .. } => CorduitError::Timeout(message),
            corduit_core::Error::ResourceExhausted { message, .. } => {
                CorduitError::ResourceExhausted(message)
            }
            corduit_core::Error::Internal { message, .. } => CorduitError::Internal(message),
            corduit_core::Error::Routing { message, .. } => CorduitError::Routing(message),
            corduit_core::Error::Proxy { message, .. } => CorduitError::Proxy(message),
        }
    }
}

/// FFI result type
pub type Result<T> = std::result::Result<T, CorduitError>;
