//! TLS layer for Corduit, on courierust's TLS 1.2/1.3 (replacing `rustls`
//! and `tokio-rustls`).
//!
//! * [`TlsConnector`] — client connector; [`TlsConnector::connect`] performs
//!   the handshake on a worker thread and returns a boxed async stream.
//! * [`TlsAcceptor`] — server acceptor; same model.
//! * `SkipServerVerification` — kept as a marker for API compatibility;
//!   skipping verification is configured via
//!   [`ClientConfig::skip_cert_verify`].

mod client;
mod config;
mod error;
mod server;
mod verifier;

pub use client::TlsConnector;
pub use config::{ClientConfig, ServerConfig};
pub use error::{Result, TlsError};
pub use server::TlsAcceptor;
pub use verifier::SkipServerVerification;

use std::sync::Arc;

/// The concrete blocking TLS stream type the bridge wraps.
pub type TlsStream = crate::common::BlockingStream<
    courierust::courierust_tls::TlsStream<Arc<std::net::TcpStream>, Arc<std::net::TcpStream>>,
>;

/// A boxed async duplex stream (the engine's canonical relay stream type).
pub type BoxStream = crate::common::BoxStream;
