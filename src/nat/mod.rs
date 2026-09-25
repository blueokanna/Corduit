//! # NAT traversal
//!
//! Direct peer-to-peer connectivity is the hard part of every overlay network,
//! and the part where marketing and engineering diverge most. This module takes
//! the position that the boundary is knowable, so it states the boundary first
//! and then builds strictly inside it.
//!
//! ## The taxonomy that decides everything
//!
//! A NAT has two independent behaviours ([RFC 4787]): how it *maps* an internal
//! endpoint to a public one, and how it *filters* inbound packets. Difficulty
//! follows from those two, not from the router's vendor or price.
//!
//! | Mapping | Filtering | Direct path | What it takes |
//! |---|---|---|---|
//! | Endpoint-independent | Endpoint-independent | Yes | One STUN discovery, one probe |
//! | Endpoint-independent | Address-dependent | Yes | Send first, both sides |
//! | Endpoint-independent | Address-and-port-dependent | Yes | Same, plus knowing the peer's address+port |
//! | Address-dependent | any | Usually | Probing a small predicted port set |
//! | Address-and-port-dependent | any | **Sometimes** | Predicted ports, hit probabilistically |
//!
//! The last row is where products differ and where claims usually become false.
//!
//! ## What is genuinely impossible
//!
//! Two endpoints behind address-and-port-dependent mapping **cannot** be joined
//! directly. Each new destination gets a *new* external port, so neither side
//! can learn where the other will appear; there is nothing to punch toward. This
//! is not a limitation of any implementation — it is the definition of the
//! behaviour. Symmetric-NAT-to-symmetric-NAT is therefore relayed, always, by
//! every product that actually works, including the ones whose documentation
//! implies otherwise.
//!
//! What *is* achievable on that row is probability: many implementations of
//! address-and-port-dependent mapping allocate ports sequentially or with a
//! small stride. Probing a predicted window turns an impossibility into a
//! bounded chance, and [`discover`] measures the stride rather than assuming it.
//!
//! ## So what this layer's job actually is
//!
//! Not "defeat NAT". It is: **the user never has to know a NAT was involved.**
//!
//! 1. Learn the local behaviour ([`discover`]).
//! 2. Race every transport against every candidate at once ([`punch`]).
//! 3. Whatever wins, use. If nothing wins, hand off to a relay — and keep
//!    probing so a path that appears later is promoted without interrupting the
//!    session.
//!
//! Steps 1 and 2 are implemented here. Step 3 is not, and the omission is
//! deliberate: it needs a relay server and a signalling plane that exchanges
//! candidates, both of which are protocol-and-deployment decisions rather than
//! library code. A local stand-in for them would compile and be useless.
//!
//! ## Transport: what is here, and what is not
//!
//! Tunnels built solely on UDP/WireGuard degrade the moment a network drops UDP
//! — which campus and corporate networks do routinely, and which is precisely
//! the deployment this is aimed at. The design therefore calls for [`punch`] to
//! race **UDP hole punching and TCP simultaneous open concurrently**, taking
//! whichever completes first.
//!
//! Only the UDP arm is implemented. TCP simultaneous open is omitted rather
//! than sketched, because its correctness rests on `SO_REUSEADDR`/`SO_REUSEPORT`
//! co-existence and bind-before-connect semantics that differ across Linux, the
//! BSDs, macOS and Windows — and none of it can be verified without two peers
//! behind real NATs. Platform-specific socket code that has never been run
//! against a NAT is a liability dressed as a feature. The plan type and the
//! racer are shaped so the TCP arm drops in as a second concurrent attempt
//! without an API change.
//!
//! ## Security
//!
//! A punch is a window in which an off-path attacker who guesses the 4-tuple
//! can inject a packet and claim the session. Every probe therefore carries a
//! truncation-resistant tag keyed by the session secret, and a datagram that
//! fails it is dropped without being counted as progress. STUN transaction ids
//! come from a CSPRNG for the same reason: a predictable id lets an attacker
//! answer before the real server does and feed us a false mapping.
//!
//! ## Layout
//!
//! * [`stun`] — the wire format and a client. Codec is `core + alloc`; only the
//!   client needs sockets.
//! * [`discover`] — RFC 5780 behaviour measurement and port-stride inference.
//! * [`punch`] — the concurrent, authenticated punch racer.
//!
//! [RFC 4787]: https://www.rfc-editor.org/rfc/rfc4787

pub mod error;
pub mod stun;

#[cfg(feature = "std")]
pub mod discover;
#[cfg(feature = "std")]
pub mod punch;

pub use error::NatError;
pub use stun::{Attribute, Message, MessageClass, Method, TransactionId};
