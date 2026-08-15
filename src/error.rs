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

impl From<crate::engine::Error> for CorduitError {
    fn from(err: crate::engine::Error) -> Self {
        match err {
            crate::engine::Error::Config { message, .. } => CorduitError::Config(message),
            crate::engine::Error::Network { message, .. } => CorduitError::Network(message),
            crate::engine::Error::Dns { message, .. } => CorduitError::Dns(message),
            crate::engine::Error::Tls { message, .. } => CorduitError::Tls(message),
            crate::engine::Error::Protocol { message, .. } => CorduitError::Protocol(message),
            crate::engine::Error::Io(err) => CorduitError::Io(err.to_string()),
            crate::engine::Error::Parse { message, .. } => CorduitError::Parse(message),
            crate::engine::Error::Auth { message, .. } => CorduitError::Auth(message),
            crate::engine::Error::Timeout { message, .. } => CorduitError::Timeout(message),
            crate::engine::Error::ResourceExhausted { message, .. } => {
                CorduitError::ResourceExhausted(message)
            }
            crate::engine::Error::Internal { message, .. } => CorduitError::Internal(message),
            crate::engine::Error::Routing { message, .. } => CorduitError::Routing(message),
            crate::engine::Error::Proxy { message, .. } => CorduitError::Proxy(message),
        }
    }
}

/// FFI result type
pub type Result<T> = std::result::Result<T, CorduitError>;
