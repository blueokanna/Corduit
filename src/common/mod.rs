//! Shared minimal utilities for Corduit.
//!
//! This crate intentionally carries a very small surface area. It exists to
//! serve the parts of the engine that several crates (`corduit-core`,
//! `corduit-dns`, `corduit-lib`, `corduit-netstack`) need in common, without
//! forcing a heavyweight dependency on any single layer:
//!
//! * [`url`] — a dependency-free, RFC 3986-subset URL parser covering
//!   `scheme://[userinfo@]host[:port][/path][?query][#fragment]`.
//! * [`http`] — an HTTP client built on `courierust` (replacing `hyper` +
//!   `rustls`): GET with timeout, redirect following, optional HTTP proxy,
//!   bounded bodies.
//! * [`http_server`] — a small blocking HTTP/1.1 server on courierust's H/1
//!   codec and TLS, with graceful stop and per-connection threads.
//! * [`roots`] — system root-certificate loading for courierust's TLS stack
//!   (Windows cert store, Linux bundle, Android cacerts).
//! * [`blocking_io`] — the seam between courierust's synchronous transports
//!   and the tokio async engine: wraps a blocking duplex stream as
//!   `AsyncRead + AsyncWrite`.
//!
//! # Safety
//!
//! The crate forbids `unsafe` everywhere except [`roots`]: reading the
//! Windows certificate store requires calling the Win32 API directly (there
//! is no safe wrapper in the `windows` crate), and the unsafe surface is a
//! single, audited function.

#![deny(unsafe_code)]

pub mod blocking_io;
pub mod http;
pub mod http_server;
pub mod roots;
pub mod url;

pub use blocking_io::BlockingStream;
pub(crate) use blocking_io::ShutdownHook;
pub use http::{HttpClient, HttpError, HttpResponse};
pub use url::{Url, UrlError};

use tokio::io::{AsyncRead, AsyncWrite};

/// A boxed async duplex stream (the canonical type the engine relays
/// through). Defined here — not in `engine` or `protocol` — so both layers
/// (and courierust's blocking bridge) agree on one trait object.
pub type BoxStream = Box<dyn AsyncReadWrite>;

/// An async duplex byte stream: `AsyncRead + AsyncWrite + Unpin + Send`.
/// Blanket-implemented for every such type, so it can be used both as a
/// bound on generics and as the object trait behind [`BoxStream`].
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}
