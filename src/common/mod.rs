//! Shared minimal utilities for Corduit.
//!
//! This crate intentionally carries a very small surface area. It exists to
//! serve the parts of the engine that several crates (`corduit-core`,
//! `corduit-dns`, `corduit-lib`, `corduit-netstack`) need in common, without
//! forcing a heavyweight dependency on any single layer:
//!
//! * [`url`] — a dependency-free, RFC 3986-subset URL parser covering
//!   `scheme://[userinfo@]host[:port][/path][?query][#fragment]`.
//! * [`http`] — a self-implemented HTTP/1.1 client built directly on `hyper`
//!   and `rustls`, replacing `reqwest` for Corduit's needs (GET with timeout,
//!   redirect following, optional HTTP proxy, bounded bodies).

#![forbid(unsafe_code)]

pub mod http;
pub mod url;

pub use http::{HttpClient, HttpError, HttpResponse};
pub use url::{Url, UrlError};
