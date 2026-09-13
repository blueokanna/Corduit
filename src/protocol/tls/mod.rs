//! TLS layer for Corduit, on courierust's TLS 1.2/1.3 (replacing `rustls`
//! and `tokio-rustls`).
//!
//! * [`TlsConnector`] — client connector; [`TlsConnector::connect`] performs
//!   the handshake synchronously over a `std::net::TcpStream` and returns a
//!   boxed [`SyncStream`](crate::common::stream::SyncStream).
//! * [`TlsAcceptor`] — server acceptor; same model.
//! * [`TlsStream`] — the synchronous TLS stream (std `Read`/`Write` +
//!   half-close).

mod client;
mod config;
mod error;
mod server;
mod stream;

pub use client::TlsConnector;
pub use config::{ClientConfig, ServerConfig};
pub use error::{Result, TlsError};
pub use server::TlsAcceptor;
pub use stream::TlsStream;

/// A boxed synchronous duplex stream (the engine's canonical relay stream
/// type).
pub type BoxStream = crate::common::BoxStream;
