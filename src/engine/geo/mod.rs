//! The Geo databases: `geosite.dat`, `geoip.dat` and `Country.mmdb`.
//!
//! Three files, two formats, one question each: "does this hostname belong to
//! that category" and "does this address belong to that country". A profile may
//! ship either the community `.dat` pair or a MaxMind
//! `Country.mmdb` (what sing-box and the v2fly tools use), and an engine that
//! supports only one of them silently drops half its users' rules. So both are
//! read here:
//!
//! * [`geosite`] — `geosite.dat`, decoded lazily per category;
//! * [`geoip`] — `geoip.dat`, decoded lazily per country;
//! * [`crate::engine::mmdb`] — `Country.mmdb`, which the engine's `GEOIP` path
//!   consults first when it is present.
//!
//! Everything in this module is content-sniffed, never name-sniffed: a file
//! called `geosite.dat` that actually holds a MaxMind database loads as one, and
//! a file with no name at all still loads correctly.

pub mod geoip;
pub mod geosite;
pub mod ipset;
pub mod proto;

pub use geoip::{CompiledGeoIp, GeoIpIndex};
pub use geosite::{CompiledGeoSite, GeoSiteIndex};

use crate::engine::error::{Error, Result};
use parking_lot::RwLock;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

/// Largest Geo database this engine will hold, in bytes.
///
/// The community `geosite.dat` is about 4 MiB and the largest `geoip.dat` under
/// 20 MiB, so the limit only catches a wrong file — a video, an ISO, a truncated
/// download — before it is parsed.
pub const MAX_DATABASE_BYTES: u64 = 512 * 1024 * 1024;

/// Which database a payload holds, decided by content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseKind {
    /// A `GeoSiteList` protobuf (`geosite.dat`).
    GeoSite,
    /// A `GeoIPList` protobuf (`geoip.dat`).
    GeoIp,
    /// A MaxMind DB (`Country.mmdb`).
    Mmdb,
    /// Nothing this module reads.
    Unknown,
}

impl DatabaseKind {
    /// Short name for logs and diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GeoSite => "geosite",
            Self::GeoIp => "geoip",
            Self::Mmdb => "mmdb",
            Self::Unknown => "unknown",
        }
    }
}

/// Trailer every MaxMind DB ends with.
const MMDB_TRAILER: &[u8] = b"\xab\xcd\xefMaxMind.com";

/// Identify a payload by its bytes.
pub fn identify(bytes: &[u8]) -> DatabaseKind {
    if bytes.len() >= MMDB_TRAILER.len() && bytes.ends_with(MMDB_TRAILER) {
        return DatabaseKind::Mmdb;
    }
    if GeoSiteIndex::probe(bytes) {
        return DatabaseKind::GeoSite;
    }
    if GeoIpIndex::probe(bytes) {
        return DatabaseKind::GeoIp;
    }
    DatabaseKind::Unknown
}

/// Whether `bytes` looks like either of the protobuf Geo databases.
pub fn looks_like_geodatabase(bytes: &[u8]) -> bool {
    GeoSiteIndex::probe(bytes) || GeoIpIndex::probe(bytes)
}

/// The Geo databases a router answers from.
///
/// Each half is swappable on its own: reloading `geoip.dat` must not disturb a
/// `geosite` category a connection is in the middle of matching, which is why the
/// two live in separate locks and are replaced wholesale under a write lock.
#[derive(Debug, Default)]
pub struct GeoDatabases {
    site: RwLock<Option<Arc<GeoSiteIndex>>>,
    ip: RwLock<Option<Arc<GeoIpIndex>>>,
}

impl GeoDatabases {
    /// No databases loaded: every Geo rule misses.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read and install a database file, deciding its kind from its content.
    ///
    /// A MaxMind DB is *reported* rather than installed: it belongs to the
    /// country matcher that owns `MmdbReader`, and installing it here would split
    /// one file across two owners.
    pub fn load_file(&self, path: &Path) -> Result<DatabaseKind> {
        let metadata = std::fs::metadata(path).map_err(|error| {
            Error::config(format!(
                "Cannot read Geo database '{}': {error}",
                path.display()
            ))
        })?;
        if metadata.len() > MAX_DATABASE_BYTES {
            return Err(Error::config(format!(
                "Geo database '{}' is {} bytes, past the {} MiB limit",
                path.display(),
                metadata.len(),
                MAX_DATABASE_BYTES / (1024 * 1024)
            )));
        }
        let data = std::fs::read(path).map_err(|error| {
            Error::config(format!(
                "Cannot read Geo database '{}': {error}",
                path.display()
            ))
        })?;
        self.load_bytes(data)
    }

    /// Install a database from memory, deciding its kind from its content.
    pub fn load_bytes(&self, data: Vec<u8>) -> Result<DatabaseKind> {
        match identify(&data) {
            DatabaseKind::GeoSite => {
                let index = GeoSiteIndex::open(data)?;
                tracing::info!("geosite database loaded with {} categories", index.len());
                *self.site.write() = Some(Arc::new(index));
                Ok(DatabaseKind::GeoSite)
            }
            DatabaseKind::GeoIp => {
                let index = GeoIpIndex::open(data)?;
                tracing::info!("geoip database loaded with {} countries", index.len());
                *self.ip.write() = Some(Arc::new(index));
                Ok(DatabaseKind::GeoIp)
            }
            other => Ok(other),
        }
    }

    /// Install a `geosite.dat` regardless of what it is called.
    pub fn load_geosite_file(&self, path: &Path) -> Result<()> {
        let data = std::fs::read(path).map_err(|error| {
            Error::config(format!(
                "Cannot read geosite database '{}': {error}",
                path.display()
            ))
        })?;
        let index = GeoSiteIndex::open(data)?;
        tracing::info!(
            "geosite database '{}' loaded with {} categories",
            path.display(),
            index.len()
        );
        *self.site.write() = Some(Arc::new(index));
        Ok(())
    }

    /// Install a `geoip.dat` regardless of what it is called.
    pub fn load_geoip_file(&self, path: &Path) -> Result<()> {
        let data = std::fs::read(path).map_err(|error| {
            Error::config(format!(
                "Cannot read geoip database '{}': {error}",
                path.display()
            ))
        })?;
        let index = GeoIpIndex::open(data)?;
        tracing::info!(
            "geoip database '{}' loaded with {} countries",
            path.display(),
            index.len()
        );
        *self.ip.write() = Some(Arc::new(index));
        Ok(())
    }

    /// The geosite database, when one is loaded.
    pub fn site(&self) -> Option<Arc<GeoSiteIndex>> {
        self.site.read().clone()
    }

    /// The geoip database, when one is loaded.
    pub fn ip(&self) -> Option<Arc<GeoIpIndex>> {
        self.ip.read().clone()
    }

    /// Whether any Geo database is loaded.
    pub fn is_empty(&self) -> bool {
        self.site.read().is_none() && self.ip.read().is_none()
    }

    /// Whether `domain` belongs to the geosite category `tag`.
    ///
    /// The first lookup of an unknown category logs once — a typo in a profile
    /// must be visible — and the answer is a miss, never a panic and never a
    /// silent match.
    pub fn matches_geosite(&self, tag: &str, domain: &str) -> bool {
        let Some(index) = self.site() else {
            return false;
        };
        index.matches(tag, domain)
    }

    /// Whether `address` belongs to the geoip country `code`.
    pub fn matches_geoip(&self, code: &str, address: IpAddr) -> bool {
        let Some(index) = self.ip() else {
            return false;
        };
        index.matches(code, address)
    }

    /// One line describing what is loaded, for the startup log.
    pub fn describe(&self) -> String {
        let site = self
            .site()
            .map(|index| format!("geosite {} categories", index.len()))
            .unwrap_or_else(|| "no geosite".to_string());
        let ip = self
            .ip()
            .map(|index| format!("geoip {} countries", index.len()))
            .unwrap_or_else(|| "no geoip".to_string());
        format!("{site}, {ip}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint(out: &mut Vec<u8>, mut value: u64) {
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                return;
            }
        }
    }

    fn field_varint(out: &mut Vec<u8>, number: u8, value: u64) {
        varint(out, u64::from(number) << 3);
        varint(out, value);
    }

    fn field_bytes(out: &mut Vec<u8>, number: u8, payload: &[u8]) {
        varint(out, (u64::from(number) << 3) | 2);
        varint(out, payload.len() as u64);
        out.extend_from_slice(payload);
    }

    fn geosite() -> Vec<u8> {
        let mut domain = Vec::new();
        field_varint(&mut domain, 1, 0);
        field_bytes(&mut domain, 2, b"ads.example.com");

        let mut category = Vec::new();
        field_bytes(&mut category, 1, b"ads");
        field_bytes(&mut category, 2, &domain);

        let mut out = Vec::new();
        field_bytes(&mut out, 1, &category);
        out
    }

    fn geoip() -> Vec<u8> {
        let mut cidr = Vec::new();
        field_bytes(&mut cidr, 1, &[10, 0, 0, 0]);
        field_varint(&mut cidr, 2, 8);

        let mut country = Vec::new();
        field_bytes(&mut country, 1, b"LAN");
        field_bytes(&mut country, 2, &cidr);

        let mut out = Vec::new();
        field_bytes(&mut out, 1, &country);
        out
    }

    #[test]
    fn identification_is_by_content() {
        assert_eq!(identify(&geosite()), DatabaseKind::GeoSite);
        assert_eq!(identify(&geoip()), DatabaseKind::GeoIp);
        assert_eq!(identify(b"DOMAIN,example.com"), DatabaseKind::Unknown);

        let mut mmdb = vec![0u8; 16];
        mmdb.extend_from_slice(MMDB_TRAILER);
        assert_eq!(identify(&mmdb), DatabaseKind::Mmdb);
    }

    #[test]
    fn loading_a_geosite_database_answers_category_queries() {
        let databases = GeoDatabases::new();
        assert!(databases.is_empty());
        assert_eq!(
            databases.load_bytes(geosite()).expect("load"),
            DatabaseKind::GeoSite
        );
        assert!(!databases.is_empty());
        assert!(databases.matches_geosite("ads", "tracker.ads.example.com"));
        assert!(!databases.matches_geosite("ads", "example.com"));
        // No geoip half was installed.
        assert!(!databases.matches_geoip("LAN", "10.1.2.3".parse().expect("ip")));
        assert!(databases.describe().contains("geosite"));
    }

    #[test]
    fn loading_a_geoip_database_answers_country_queries() {
        let databases = GeoDatabases::new();
        assert_eq!(
            databases.load_bytes(geoip()).expect("load"),
            DatabaseKind::GeoIp
        );
        assert!(databases.matches_geoip("lan", "10.9.9.9".parse().expect("ip")));
        assert!(!databases.matches_geoip("LAN", "11.9.9.9".parse().expect("ip")));
        // No geosite half was installed.
        assert!(!databases.matches_geosite("ads", "ads.example.com"));
    }

    #[test]
    fn the_two_halves_are_independent() {
        let databases = GeoDatabases::new();
        databases.load_bytes(geoip()).expect("geoip");
        databases.load_bytes(geosite()).expect("geosite");
        assert!(databases.matches_geoip("LAN", "10.1.2.3".parse().expect("ip")));
        assert!(databases.matches_geosite("ads", "ads.example.com"));
        assert!(
            databases.describe().contains("geosite 1 categories"),
            "{}",
            databases.describe()
        );
    }

    #[test]
    fn unroutable_files_are_reported_not_installed() {
        let databases = GeoDatabases::new();
        let mut mmdb = vec![0u8; 16];
        mmdb.extend_from_slice(MMDB_TRAILER);
        assert_eq!(
            databases.load_bytes(mmdb).expect("identified"),
            DatabaseKind::Mmdb
        );
        assert!(databases.is_empty());
        assert_eq!(
            databases.load_bytes(b"DOMAIN,x".to_vec()).expect("unknown"),
            DatabaseKind::Unknown
        );
    }
}
