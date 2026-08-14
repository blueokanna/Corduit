//! Corduit DNS - High-performance DNS resolver and server
//!
//! A comprehensive DNS library for Corduit with support for:
//! - Local DNS server (UDP/TCP/DoH/DoT)
//! - Multiple upstream DNS protocols (UDP/TCP/DoH/DoT)
//! - DNS caching with TTL awareness
//! - Fake-IP mode for transparent proxying
//! - Anti-spoofing protection
//! - Domain-based routing (domestic/foreign DNS)
//! - Hosts file support
#![cfg_attr(docsrs, feature(doc_cfg))]
//!
//! # Architecture
//!
//! ```text
//! +-------------------------------------------------------------+
//! |                     DNS Manager                             |
//! | +---------+ +---------+ +---------+ +---------+             |
//! | |   DoH   | |   DoT   | |  Cache  | | Fake-IP |             |
//! | +----+----+ +----+----+ +----+----+ +----+----+             |
//! |      +----------+----------+----------+                     |
//! |                        |                                    |
//! |                   +----v----+                               |
//! |                   |Resolver | (Domain-based routing)        |
//! |                   +----+----+                               |
//! |          +-------------+-------------+                      |
//! |     +----v----+  +----v----+  +----v----+                   |
//! |     | Hosts   |  | Primary |  |Fallback |                   |
//! |     |  File   |  |   DNS   |  |   DNS   |                   |
//! |     +---------+  +---------+  +---------+                   |
//! +-------------------------------------------------------------+
//!                        |
//!                   +----v----+
//!                   |  DNS    |
//!                   | Server  |
//!                   +---------+
//! ```
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use corduit_dns::{DnsManager, DnsConfig, RecordType};
//!
//! #[tokio::main]
//! async fn main() -> corduit_dns::Result<()> {
//!     // Create DNS manager with default config
//!     let manager = DnsManager::new()?;
//!
//!     // Resolve a domain
//!     let ips = manager.resolve("google.com").await?;
//!     println!("Resolved: {:?}", ips);
//!
//!     // Start DNS server
//!     manager.start_server().await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Features
//!
//! - **Multi-protocol support**: UDP, TCP, DoH (DNS over HTTPS), DoT (DNS over TLS)
//! - **Intelligent caching**: TTL-aware caching with stale-while-revalidate support
//! - **Fake-IP mode**: Virtual IP allocation for transparent proxying
//! - **Anti-spoofing**: Fallback DNS with bogon IP detection
//! - **Load balancing**: Round-robin across multiple upstream servers
//! - **Hot reload**: Configuration can be reloaded without restart

pub mod bogon;
pub mod cache;
pub mod client;
pub mod config;
pub mod doh;
pub mod doh_server;
pub mod dot;
pub mod dot_server;
pub mod error;
pub mod fake_ip;
pub mod hosts;
pub mod manager;
pub mod resolver;
pub mod server;
pub mod util;
pub mod wire;

#[cfg(test)]
mod tests;

// Re-export main types
pub use bogon::{
    classify_bogon, contains_bogon, filter_bogons, is_bogon, is_bogon_ipv4, is_bogon_ipv6,
    is_loopback, is_private, is_reserved, BogonType,
};
pub use cache::{CacheEntry, CacheStats, DnsCache};
pub use client::{create_clients, DnsClient, DnsProtocol};
pub use config::{DnsConfig, FallbackFilter, UpstreamConfig, UpstreamProtocol};
pub use doh::{DohClient, DohClientConfig, DohMethod, DohResolver};
pub use doh_server::{DohServer, DohServerConfig};
pub use dot::{DotClient, DotClientConfig, DotResolver};
pub use dot_server::{DotServer, DotServerConfig};
pub use error::{DnsError, Result};
pub use fake_ip::{FakeIpEntry, FakeIpPool};
pub use hosts::HostsFile;
pub use manager::{CacheStatistics, DnsManager, DnsManagerState};
pub use resolver::DnsResolver;
pub use server::DnsServer;

/// DNS record types supported by this library
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    /// IPv4 address record
    A,
    /// IPv6 address record
    AAAA,
    /// Canonical name record
    CNAME,
    /// Text record
    TXT,
    /// Mail exchange record
    MX,
    /// Name server record
    NS,
    /// Start of authority record
    SOA,
    /// Pointer record (reverse DNS)
    PTR,
    /// Service record
    SRV,
    /// HTTPS service binding
    HTTPS,
    /// Service binding
    SVCB,
}

impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordType::A => write!(f, "A"),
            RecordType::AAAA => write!(f, "AAAA"),
            RecordType::CNAME => write!(f, "CNAME"),
            RecordType::TXT => write!(f, "TXT"),
            RecordType::MX => write!(f, "MX"),
            RecordType::NS => write!(f, "NS"),
            RecordType::SOA => write!(f, "SOA"),
            RecordType::PTR => write!(f, "PTR"),
            RecordType::SRV => write!(f, "SRV"),
            RecordType::HTTPS => write!(f, "HTTPS"),
            RecordType::SVCB => write!(f, "SVCB"),
        }
    }
}

impl From<crate::wire::RecordType> for RecordType {
    fn from(rt: crate::wire::RecordType) -> Self {
        match rt {
            crate::wire::RecordType::A => RecordType::A,
            crate::wire::RecordType::AAAA => RecordType::AAAA,
            crate::wire::RecordType::CNAME => RecordType::CNAME,
            crate::wire::RecordType::TXT => RecordType::TXT,
            crate::wire::RecordType::MX => RecordType::MX,
            crate::wire::RecordType::NS => RecordType::NS,
            crate::wire::RecordType::SOA => RecordType::SOA,
            crate::wire::RecordType::PTR => RecordType::PTR,
            crate::wire::RecordType::SRV => RecordType::SRV,
            crate::wire::RecordType::HTTPS => RecordType::HTTPS,
            crate::wire::RecordType::SVCB => RecordType::SVCB,
            _ => RecordType::A, // Default fallback
        }
    }
}

impl From<RecordType> for crate::wire::RecordType {
    fn from(rt: RecordType) -> Self {
        match rt {
            RecordType::A => crate::wire::RecordType::A,
            RecordType::AAAA => crate::wire::RecordType::AAAA,
            RecordType::CNAME => crate::wire::RecordType::CNAME,
            RecordType::TXT => crate::wire::RecordType::TXT,
            RecordType::MX => crate::wire::RecordType::MX,
            RecordType::NS => crate::wire::RecordType::NS,
            RecordType::SOA => crate::wire::RecordType::SOA,
            RecordType::PTR => crate::wire::RecordType::PTR,
            RecordType::SRV => crate::wire::RecordType::SRV,
            RecordType::HTTPS => crate::wire::RecordType::HTTPS,
            RecordType::SVCB => crate::wire::RecordType::SVCB,
        }
    }
}

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::config::DnsConfig;
    pub use crate::error::{DnsError, Result};
    pub use crate::manager::DnsManager;
    pub use crate::RecordType;
}
