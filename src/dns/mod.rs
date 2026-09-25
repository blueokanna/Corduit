//! Corduit's DNS: a profile's DNS section, on top of RecurseX.
//!
//! There is exactly **one** DNS implementation in this crate, and it is not
//! here. [RecurseX](https://github.com/blueokanna/RecurseX) owns the wire codec,
//! the name and record types, the semantic cache, every transport (UDP, TCP,
//! DoT, DoH, DoH3, DoQ), request coalescing, upstream selection and the server
//! loop. This module is the adapter that turns a Corduit profile into a
//! `ResolverConfig`, plus the one decision RecurseX cannot make for us.
//!
//! ```text
//!  profile DNS section             this module                    RecurseX
//!  ┌───────────────────┐   ┌─────────────────────────┐   ┌──────────────────────┐
//!  │ nameservers       │   │ upstream::Upstream      │   │ Forwarder            │
//!  │ default-nameserver├──▶│  parse · bootstrap      ├──▶│ ForwarderSet         │
//!  │ nameserver-policy │   │  render → IP literal    │   │ NameserverPolicy     │
//!  │ hosts             │   │                         │   │ HostsTable           │
//!  │ fallback(-filter) │   │ engine_resolver::Plan   │   │ Resolver             │
//!  │ cache-size        │   │  + SuspectPolicy        │   │  cache · transports  │
//!  └───────────────────┘   └─────────────────────────┘   └──────────────────────┘
//! ```
//!
//! # The four modules
//!
//! - [`upstream`] — the grammar of an upstream server string, and the two
//!   rewrites a profile needs before RecurseX will accept one.
//! - [`engine_resolver`] — the process-wide resolver the engine dials through,
//!   its anti-poisoning gate, and the `configure` / `resolve` entry points.
//! - [`bogon`] — which addresses a public name may answer with. Used by the
//!   gate above, and useful on its own to any caller inspecting a response.
//! - [`pattern`] — the domain-rule spellings on the string side, for the
//!   paths that hold a name as text rather than as a parsed [`Name`].
//! - [`server`] — the client-facing listener `dns.enable` and `dns.listen`
//!   start, which is RecurseX's server bound to a resolver built from the same
//!   profile.
//!
//! # What a profile cannot express
//!
//! Nothing here reads `/etc/resolv.conf` unless the profile asked for it: an
//! upstream named by a hostname is resolved through `default-nameserver`, and
//! the operating system's resolver is only the last resort when the profile
//! names no bootstrap server. That is the same rule RecurseX applies, for the
//! same reason — a resolver that depends on the resolution it is meant to
//! replace is not a resolver — relaxed by exactly the amount a proxy engine
//! needs, because the machine running the engine is already online.

pub mod bogon;
pub mod engine_resolver;
pub mod pattern;
pub mod server;
pub mod upstream;

// RecurseX *is* the DNS engine, so its vocabulary is re-exported rather than
// duplicated: a second `RecordType` enum next to `RrType` would be a second
// implementation of "which record types exist", and the two would drift.
pub use pattern::{normalize_suffix, suffix_matches};
pub use recurse_x::{HeaderFlags, Message, Name, Question, RData, Rcode, Record, RrClass, RrType};
pub use server::DnsServer;
pub use upstream::{Upstream, UpstreamProtocol};
