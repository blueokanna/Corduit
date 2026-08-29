//! QUIC v1 client transport, implemented from scratch on courierust's public
//! codecs.
//!
//! courierust ships the RFC 9000 wire codecs ([`courierust::courierust_quic`]:
//! packet headers, frames, varints, packet protection) and the TLS 1.3 crypto
//! primitives + X.509 validation ([`courierust::courierust_tls::crypto`],
//! [`courierust::courierust_tls::x509`]), but **no** reusable QUIC connection
//! runtime — its `QuicClient` lives in a `pub(crate)` module and the HTTP/3
//! runtime is request/response oriented. This module is the missing piece:
//! a real client-side QUIC v1 connection built on those public primitives.
//!
//! # Scope
//!
//! * TLS 1.3-over-QUIC client handshake (RFC 8446 §4 + RFC 9001 §4):
//!   ClientHello with `quic_transport_parameters`, key schedule, X.509 chain
//!   validation (or `skip_cert_verify`), Finished.
//! * QUIC v1 transport (RFC 9000 + RFC 9002): packet-number spaces, ACK /
//!   loss detection (PTO + time threshold), NewReno congestion control,
//!   flow control (`MAX_DATA` / `MAX_STREAM_DATA` / `MAX_STREAMS`), stream
//!   send/recv with reassembly, and RFC 9221 datagrams.
//! * Synchronous surface for the engine: [`QuicClient`] connects over a
//!   `std::net::UdpSocket` with a dedicated driver thread per connection,
//!   and hands out [`ClientConnection`] / stream handles that implement
//!   `std::io::Read` / `std::io::Write` with blocking, backpressured IO.
//!
//! # Honest scope notes
//!
//! * 0-RTT / early data is not offered (same as courierust's own TLS layer).
//! * Connection migration and NAT rebinding are out of scope for a client
//!   connection; `disable_active_migration` is advertised.
//! * The congestion controller is a NewReno-style AIMD (RFC 5681 semantics
//!   adapted to QUIC), not full BBR/CUBIC.
//! * Interop with real servers is exercised through the TUIC / Hysteria2
//!   outbound paths; see `engine/outbound/{tuic,hysteria2}.rs`.

mod client;
mod config;
mod error;
mod obfs;
mod stream;
mod tls13;
mod transport;

pub use client::{ClientConnection, QuicClient};
pub use config::{ClientConfig, CongestionControl};
pub use error::{QuicError, Result};
pub use obfs::Salamander;
pub use stream::{QuicRecvStream, QuicSendStream};

/// QUIC version 1 (RFC 9000).
pub(crate) const QUIC_VERSION: u32 = 0x0000_0001;
/// Default initial congestion window (10 × 1200, RFC 9002 §7.2).
pub(crate) const INITIAL_CWND: u64 = 10 * 1200;
/// Minimum congestion window (2 × 1200, RFC 9002 §7.2).
pub(crate) const MIN_CWND: u64 = 2 * 1200;
/// Default maximum datagram size we send.
pub(crate) const MAX_UDP_PAYLOAD: u64 = 1200;
/// Hard cap for a single received datagram / packet (64 KiB + slack).
pub(crate) const MAX_PACKET: usize = 65_527 + 64;
