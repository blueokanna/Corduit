//! Shared minimal utilities for Corduit.
//!
//! This module carries a deliberately small surface area. It exists to
//! serve the parts of the engine (engine, dns, netstack, rpc) that need
//! common primitives, without forcing a heavyweight dependency on any
//! single layer:
//!
//! * [`exec`] — the synchronous scheduler: a typed layer over courierust's
//!   work-stealing [`courierust::courierust_pool::ThreadPool`]
//!   plus session admission control.
//! * [`socket`] — blocking socket primitives: timeout-bounded connect,
//!   hostname resolution, one-shot UDP exchange.
//! * [`stream`] — the canonical [`SyncStream`] trait and the bidirectional
//!   [`stream::relay`] that backs every proxy connection.
//! * [`timer`] — a single-threaded timer wheel whose callbacks run on the
//!   pool (health checks, provider refresh).
//! * [`cancel`] — [`CancellationToken`], the synchronous cancellation
//!   primitive (a shared atomic + condition variable, no futures).
//! * [`url`] — a dependency-free, RFC 3986-subset URL parser covering
//!   `scheme://[userinfo@]host[:port][/path][?query][#fragment]`.
//! * [`http`] — an HTTP client built on `courierust` (replacing `hyper` +
//!   `rustls`): GET with timeout, redirect following, optional HTTP proxy,
//!   bounded bodies.
//! * [`listener`] — the accept loop and connection budget shared by the
//!   in-process servers, on top of courierust's per-connection engine.
//! * [`roots`] — system root-certificate loading for courierust's TLS stack
//!   (Windows cert store, Linux bundle, Android cacerts).
//! * [`throttle`] — [`LogThrottle`], for conditions that are expected but can
//!   repeat thousands of times per second.
//!
//! # The synchronous model
//!
//! Corduit has **no async runtime**. Concurrency is layered:
//!
//! 1. Short tasks (accept dispatch, handshakes, DNS, control plane,
//!    timers) run on courierust's work-stealing thread pool ([`exec`]).
//! 2. Long-lived relays run on dedicated threads, bounded by a
//!    [`SessionGate`](exec::SessionGate).
//! 3. One accept thread per listener hands connections to the pool.
//!
//! # Safety
//!
//! The crate forbids `unsafe` everywhere except [`roots`]: reading the
//! Windows certificate store requires calling the Win32 API directly (there
//! is no safe wrapper in the `windows` crate), and the unsafe surface is a
//! single, audited function.

#![deny(unsafe_code)]

pub mod url;

#[cfg(feature = "std")]
pub mod cancel;
#[cfg(feature = "std")]
pub mod clock;
#[cfg(feature = "std")]
pub mod exec;
#[cfg(feature = "std")]
pub mod http;
#[cfg(feature = "std")]
pub mod listener;
#[cfg(feature = "std")]
pub mod lru;
#[cfg(feature = "std")]
pub mod roots;
#[cfg(feature = "std")]
pub mod shared_socket;
#[cfg(feature = "std")]
pub mod socket;
#[cfg(feature = "std")]
pub mod stream;
#[cfg(feature = "std")]
pub mod sync;
#[cfg(feature = "std")]
pub mod throttle;
#[cfg(feature = "std")]
pub mod timer;

#[cfg(feature = "std")]
pub use cancel::CancellationToken;
#[cfg(feature = "std")]
pub use http::{HttpClient, HttpError, HttpResponse};
#[cfg(feature = "std")]
pub use socket::{connect, connect_host, udp_exchange};
#[cfg(feature = "std")]
pub use stream::{relay, BoxStream, PrefixedStream, RelayStats, SyncStream};
#[cfg(feature = "std")]
pub use throttle::LogThrottle;
pub use url::{Url, UrlError};
