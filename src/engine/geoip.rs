use crate::engine::error::{Error, Result};
use crate::engine::mmdb::MmdbReader;
use parking_lot::RwLock;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A two-letter ISO 3166-1 alpha-2 country code, stored as raw uppercase bytes.
///
/// Parsing, storage and comparison are all allocation-free: the code is always
/// exactly two ASCII letters, so a packed `[u8; 2]` is both the canonical form
/// and the fastest one.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct CountryCode([u8; 2]);

impl CountryCode {
    /// Parse a country code, uppercasing on the fly. Anything that is not
    /// exactly two ASCII letters is rejected.
    pub fn parse(code: &str) -> Option<Self> {
        let b = code.as_bytes();
        if b.len() == 2 && b[0].is_ascii_alphabetic() && b[1].is_ascii_alphabetic() {
            Some(Self([b[0].to_ascii_uppercase(), b[1].to_ascii_uppercase()]))
        } else {
            None
        }
    }

    /// The two raw uppercase bytes.
    pub const fn as_bytes(&self) -> &[u8; 2] {
        &self.0
    }

    /// Byte-exact comparison against another code.
    pub fn matches(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl core::fmt::Display for CountryCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(core::str::from_utf8(&self.0).expect("two ASCII bytes"))
    }
}

/// Number of `u64` words needed to hold all 26×26 alpha-2 combinations.
const COUNTRY_MASK_WORDS: usize = (26usize * 26).div_ceil(64);

/// A set of [`CountryCode`]s packed into a 676-bit mask.
///
/// Membership is a single index computation plus a bit test: no hashing, no
/// allocation, no collisions. Built for rule groups such as
/// `GEOIP,CN` / `GEOIP,HK`-style batches that must be evaluated per packet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CountryCodeSet([u64; COUNTRY_MASK_WORDS]);

impl Default for CountryCodeSet {
    fn default() -> Self {
        Self::new()
    }
}

impl CountryCodeSet {
    pub const fn new() -> Self {
        Self([0; COUNTRY_MASK_WORDS])
    }

    pub fn insert(&mut self, code: CountryCode) {
        let idx = Self::index(code.as_bytes());
        self.0[idx / 64] |= 1u64 << (idx % 64);
    }

    pub fn insert_str(&mut self, code: &str) -> bool {
        if let Some(code) = CountryCode::parse(code) {
            self.insert(code);
            true
        } else {
            false
        }
    }

    pub fn contains(&self, code: CountryCode) -> bool {
        let idx = Self::index(code.as_bytes());
        (self.0[idx / 64] >> (idx % 64)) & 1 == 1
    }

    pub fn len(&self) -> usize {
        self.0.iter().map(|w| w.count_ones() as usize).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|w| *w == 0)
    }

    #[inline]
    const fn index(bytes: &[u8; 2]) -> usize {
        ((bytes[0] - b'A') as usize) * 26 + ((bytes[1] - b'A') as usize)
    }
}

/// Country-level IP matching abstraction.
///
/// `Router` depends on this trait (not on `GeoIpManager` directly) so that
/// tests and alternate data sources can inject a deterministic implementation.
pub trait CountryMatcher: Send + Sync {
    fn matches_country(&self, country_code: &str, ip: IpAddr) -> bool;
    fn load_database(&self, path: &str) -> Result<()>;
    fn load_database_from_bytes(&self, data: Vec<u8>) -> Result<()>;
}

pub struct GeoIpDatabase {
    reader: Option<MmdbReader>,
}

impl GeoIpDatabase {
    pub fn new() -> Self {
        Self { reader: None }
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let data = std::fs::read(path.as_ref())
            .map_err(|e| Error::config(format!("Failed to read GeoIP database: {e}")))?;
        let reader = MmdbReader::open(data)
            .map_err(|e| Error::config(format!("Failed to parse GeoIP database: {e}")))?;
        Ok(Self {
            reader: Some(reader),
        })
    }

    pub fn load_from_bytes(data: Vec<u8>) -> Result<Self> {
        let reader = MmdbReader::open(data).map_err(|e| {
            Error::config(format!("Failed to parse GeoIP database from bytes: {e}"))
        })?;
        Ok(Self {
            reader: Some(reader),
        })
    }

    pub fn is_loaded(&self) -> bool {
        self.reader.is_some()
    }

    pub fn lookup_country(&self, ip: IpAddr) -> Option<CountryCode> {
        self.reader.as_ref()?.lookup_country(ip).map(CountryCode)
    }

    pub fn matches_country(&self, country_code: &str, ip: IpAddr) -> bool {
        if country_code.eq_ignore_ascii_case("LAN") || country_code.eq_ignore_ascii_case("PRIVATE")
        {
            return is_private_ip(ip);
        }
        let Some(code) = CountryCode::parse(country_code) else {
            return false;
        };
        match self.lookup_country(ip) {
            Some(found) => found.matches(&code),
            None => false,
        }
    }
}

impl Default for GeoIpDatabase {
    fn default() -> Self {
        Self::new()
    }
}

/// Guards the "Country.mmdb not found" warning so it is emitted at most once
/// per process (routers can be constructed repeatedly, e.g. on hot reload or
/// in tests, and the missing DB is a normal recoverable state).
static GEOIP_MISSING_WARNED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub struct GeoIpManager {
    database: Arc<RwLock<GeoIpDatabase>>,
}

impl GeoIpManager {
    pub fn new() -> Self {
        Self {
            database: Arc::new(RwLock::new(GeoIpDatabase::new())),
        }
    }

    /// Creates a manager backed by an optionally-supplied country database.
    /// A database is loaded from `Country.mmdb` next to the executable (or the
    /// path given via `CORDUIT_GEOIP_DB`). If no database is available the
    /// manager starts empty: `GEOIP` rules will simply miss and fall through,
    /// while the rest of the router keeps working. Callers can later install a
    /// database at runtime via [`GeoIpManager::load_database`].
    pub fn from_embedded_country_database() -> Self {
        let db_path = std::env::var_os("CORDUIT_GEOIP_DB")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::current_exe()
                    .ok()
                    .and_then(|exe| exe.parent().map(|dir| dir.join("Country.mmdb")))
            });

        let database = match db_path {
            Some(path) if path.is_file() => match GeoIpDatabase::load_from_file(&path) {
                Ok(db) => {
                    tracing::info!("GeoIP country database loaded from {}", path.display());
                    db
                }
                Err(error) => {
                    tracing::warn!(
                        "GeoIP database at {} is unreadable: {error}; \
                             continuing without GeoIP rules",
                        path.display()
                    );
                    GeoIpDatabase::new()
                }
            },
            Some(path) => {
                // A missing database is a normal, recoverable state (GEOIP
                // rules just miss). Warn once per process instead of on every
                // router construction so test/restart loops don't flood logs.
                if !GEOIP_MISSING_WARNED.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    tracing::warn!(
                        "GeoIP database {} not found; continuing without GeoIP rules \
                         (set CORDUIT_GEOIP_DB to enable)",
                        path.display()
                    );
                } else {
                    tracing::debug!(
                        "GeoIP database {} not found (already warned); GEOIP rules disabled",
                        path.display()
                    );
                }
                GeoIpDatabase::new()
            }
            None => GeoIpDatabase::new(),
        };

        Self {
            database: Arc::new(RwLock::new(database)),
        }
    }

    pub fn load_database<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let db = GeoIpDatabase::load_from_file(path)?;
        let mut guard = self.database.write();
        *guard = db;
        tracing::info!("GeoIP database loaded successfully");
        Ok(())
    }

    pub fn load_database_from_bytes(&self, data: Vec<u8>) -> Result<()> {
        let db = GeoIpDatabase::load_from_bytes(data)?;
        let mut guard = self.database.write();
        *guard = db;
        tracing::info!("GeoIP database loaded from bytes successfully");
        Ok(())
    }

    pub fn is_loaded(&self) -> bool {
        self.database.read().is_loaded()
    }

    pub fn lookup_country(&self, ip: IpAddr) -> Option<CountryCode> {
        self.database.read().lookup_country(ip)
    }

    pub fn matches_country(&self, country_code: &str, ip: IpAddr) -> bool {
        self.database.read().matches_country(country_code, ip)
    }
}

impl CountryMatcher for GeoIpManager {
    fn matches_country(&self, country_code: &str, ip: IpAddr) -> bool {
        self.matches_country(country_code, ip)
    }

    fn load_database(&self, path: &str) -> Result<()> {
        self.load_database(path)
    }

    fn load_database_from_bytes(&self, data: Vec<u8>) -> Result<()> {
        self.load_database_from_bytes(data)
    }
}

impl Default for GeoIpManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for GeoIpManager {
    fn clone(&self) -> Self {
        Self {
            database: Arc::clone(&self.database),
        }
    }
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private()
                || ipv4.is_loopback()
                || ipv4.is_link_local()
                || ipv4.is_broadcast()
                || ipv4.is_documentation()
                || ipv4.is_unspecified()
                || is_cgnat(ipv4)
        }
        IpAddr::V6(ipv6) => ipv6.is_loopback() || ipv6.is_unspecified() || is_ipv6_private(&ipv6),
    }
}

pub(crate) fn is_local_or_private_ip(ip: IpAddr) -> bool {
    is_private_ip(ip)
}

fn is_cgnat(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (octets[1] >= 64 && octets[1] <= 127)
}

fn is_ipv6_private(ip: &std::net::Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] & 0xfe00) == 0xfc00 || (segments[0] & 0xffc0) == 0xfe80 || ip.is_multicast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_private_ipv4() {
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn test_private_ipv6() {
        assert!(is_private_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_private_ip(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888
        ))));
    }

    #[test]
    fn test_country_code_parse_and_match() {
        assert_eq!(CountryCode::parse("cn").unwrap().as_bytes(), b"CN");
        assert_eq!(CountryCode::parse("US").unwrap().as_bytes(), b"US");
        assert!(CountryCode::parse("cn")
            .unwrap()
            .matches(&CountryCode::parse("CN").unwrap()));
        assert!(!CountryCode::parse("CN")
            .unwrap()
            .matches(&CountryCode::parse("JP").unwrap()));
        assert!(CountryCode::parse("C").is_none());
        assert!(CountryCode::parse("CHN").is_none());
        assert!(CountryCode::parse("").is_none());
        assert!(CountryCode::parse("12").is_none());
        assert_eq!(CountryCode::parse("cn").unwrap().to_string(), "CN");
    }

    #[test]
    fn test_country_code_set_bitmask() {
        let mut set = CountryCodeSet::new();
        assert!(set.is_empty());
        assert!(set.insert_str("cn"));
        assert!(set.insert_str("HK"));
        assert!(set.insert_str("tw"));
        assert!(!set.insert_str("not-a-code"));
        assert_eq!(set.len(), 3);
        assert!(set.contains(CountryCode::parse("CN").unwrap()));
        assert!(set.contains(CountryCode::parse("hk").unwrap()));
        assert!(!set.contains(CountryCode::parse("JP").unwrap()));
        // Boundary bits land in different u64 words and must all be set.
        let mut all = CountryCodeSet::new();
        for hi in b'A'..=b'Z' {
            for lo in b'A'..=b'Z' {
                let code = CountryCode::parse(core::str::from_utf8(&[hi, lo]).unwrap()).unwrap();
                all.insert(code);
            }
        }
        assert_eq!(all.len(), 26 * 26);
        assert!(all.contains(CountryCode::parse("ZZ").unwrap()));
        assert!(all.contains(CountryCode::parse("AA").unwrap()));
    }

    #[test]
    fn test_geoip_database_new() {
        let db = GeoIpDatabase::new();
        assert!(!db.is_loaded());
    }

    #[test]
    fn test_fallback_lan_match() {
        let db = GeoIpDatabase::new();
        assert!(db.matches_country("LAN", IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(db.matches_country("PRIVATE", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!db.matches_country("US", IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn test_embedded_country_database_degrades_gracefully() {
        // Without a real Country.mmdb on disk the manager must still construct,
        // start empty, and let GEOIP rules miss without panicking.
        let manager = GeoIpManager::from_embedded_country_database();

        assert!(!manager.is_loaded());
        // Empty database: every GEOIP lookup is a miss, falling through to
        // the next rule instead of aborting routing.
        assert!(!manager
            .lookup_country(IpAddr::V4(Ipv4Addr::new(114, 114, 114, 114)))
            .is_some());
        assert!(!manager.matches_country("CN", IpAddr::V4(Ipv4Addr::new(114, 114, 114, 114))));
    }
}
