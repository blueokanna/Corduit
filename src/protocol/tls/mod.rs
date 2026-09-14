//! TLS layer for Corduit, on courierust's TLS 1.2/1.3 (replacing `rustls`
//! and `tokio-rustls`).
//!
//! * [`TlsConnector`] — client connector; [`TlsConnector::connect`] performs
//!   the handshake synchronously over a `std::net::TcpStream` and returns a
//!   boxed [`SyncStream`](crate::common::stream::SyncStream).
//! * [`TlsStream`] — the synchronous TLS stream (std `Read`/`Write` +
//!   half-close).
//!
//! Server-side TLS is courierust's own acceptor
//! ([`courierust::courierust_tls::TlsAcceptor`]) plus its identity type:
//! the DoT server and the HTTP servers build on those directly, so there is
//! no second acceptor in this workspace.

mod client;
mod config;
mod error;
mod stream;

pub use client::TlsConnector;
pub use config::ClientConfig;
pub use error::{Result, TlsError};
pub use stream::TlsStream;

/// A boxed synchronous duplex stream (the engine's canonical relay stream
/// type).
pub type BoxStream = crate::common::BoxStream;
