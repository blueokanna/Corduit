use crate::error::{Error, Result};
use crate::mmdb::MmdbReader;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Country-level IP matching abstraction.
///
/// `Router` depends on this trait (not on `GeoIpManager` directly) so that
/// tests and alternate data sources can inject a deterministic implementation.
#[async_trait::async_trait]
pub trait CountryMatcher: Send + Sync {
    /// Returns `true` when `ip` belongs to the given ISO 3166-1 alpha-2 code.
    async fn matches_country(&self, country_code: &str, ip: IpAddr) -> bool;

    /// Replace the backing database from a file path.
    async fn load_database(&self, path: &str) -> Result<()>;

    /// Replace the backing database from an in-memory byte blob.
    async fn load_database_from_bytes(&self, data: Vec<u8>) -> Result<()>;
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

    pub fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        self.reader.as_ref()?.lookup_country(ip)
    }

    pub fn matches_country(&self, country_code: &str, ip: IpAddr) -> bool {
        if let Some(lookup_country) = self.lookup_country(ip) {
            lookup_country.eq_ignore_ascii_case(country_code)
        } else {
            self.fallback_country_match(country_code, ip)
        }
    }

    fn fallback_country_match(&self, country_code: &str, ip: IpAddr) -> bool {
        let code_upper = country_code.to_uppercase();

        if code_upper == "LAN" || code_upper == "PRIVATE" {
            return is_private_ip(ip);
        }

        false
    }
}

impl Default for GeoIpDatabase {
    fn default() -> Self {
        Self::new()
    }
}

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
    ///
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
            Some(path) if path.is_file() => {
                match GeoIpDatabase::load_from_file(&path) {
                    Ok(db) => {
                        tracing::info!(
                            "GeoIP country database loaded from {}",
                            path.display()
                        );
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
                }
            }
            Some(path) => {
                tracing::warn!(
                    "GeoIP database {} not found; continuing without GeoIP rules \
                     (set CORDUIT_GEOIP_DB to enable)",
                    path.display()
                );
                GeoIpDatabase::new()
            }
            None => GeoIpDatabase::new(),
        };

        Self {
            database: Arc::new(RwLock::new(database)),
        }
    }

    pub async fn load_database<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let db = GeoIpDatabase::load_from_file(path)?;
        let mut guard = self.database.write().await;
        *guard = db;
        tracing::info!("GeoIP database loaded successfully");
        Ok(())
    }

    pub async fn load_database_from_bytes(&self, data: Vec<u8>) -> Result<()> {
        let db = GeoIpDatabase::load_from_bytes(data)?;
        let mut guard = self.database.write().await;
        *guard = db;
        tracing::info!("GeoIP database loaded from bytes successfully");
        Ok(())
    }

    pub async fn is_loaded(&self) -> bool {
        self.database.read().await.is_loaded()
    }

    pub async fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        self.database.read().await.lookup_country(ip)
    }

    pub async fn matches_country(&self, country_code: &str, ip: IpAddr) -> bool {
        self.database.read().await.matches_country(country_code, ip)
    }
}

#[async_trait::async_trait]
impl CountryMatcher for GeoIpManager {
    async fn matches_country(&self, country_code: &str, ip: IpAddr) -> bool {
        self.matches_country(country_code, ip).await
    }

    async fn load_database(&self, path: &str) -> Result<()> {
        self.load_database(path).await
    }

    async fn load_database_from_bytes(&self, data: Vec<u8>) -> Result<()> {
        self.load_database_from_bytes(data).await
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
        let runtime = tokio::runtime::Runtime::new().unwrap();

        runtime.block_on(async {
            assert!(!manager.is_loaded().await);
            // Empty database: every GEOIP lookup is a miss, falling through to
            // the next rule instead of aborting routing.
            assert!(!manager.lookup_country(IpAddr::V4(Ipv4Addr::new(114, 114, 114, 114))).await.is_some());
            assert!(!manager
                .matches_country("CN", IpAddr::V4(Ipv4Addr::new(114, 114, 114, 114)))
                .await);
        });
    }
}
