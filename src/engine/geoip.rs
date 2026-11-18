use crate::engine::error::{Error, Result};
use crate::engine::geo::{DatabaseKind, GeoDatabases};
use crate::engine::mmdb::MmdbReader;
use parking_lot::RwLock;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

static DEFAULT_DATABASE_PATH: RwLock<Option<PathBuf>> = RwLock::new(None);
static DEFAULT_GEOSITE_PATH: RwLock<Option<PathBuf>> = RwLock::new(None);

/// Register the database used by subsequently constructed routers.
///
/// The file may be any of the three shapes this engine reads — a MaxMind
/// `Country.mmdb`, a v2ray/Mihomo `geoip.dat`, or a `geosite.dat` — because the
/// kind is decided from the content, not from the name.
///
/// Embedders must use this instead of mutating process environment variables
/// after native or Flutter worker threads have started. Existing routers keep
/// their current database until they are reconfigured.
pub fn set_default_database_path(path: impl AsRef<Path>) -> Result<()> {
    let path = path
        .as_ref()
        .canonicalize()
        .map_err(|error| Error::config(format!("Cannot resolve GeoIP database: {error}")))?;
    if !path.is_file() {
        return Err(Error::config("GeoIP database path is not a file"));
    }
    *DEFAULT_DATABASE_PATH.write() = Some(path);
    Ok(())
}

/// Register the `geosite.dat` used by subsequently constructed routers.
///
/// Separate from [`set_default_database_path`] because a profile normally ships
/// both files and wants both; passing the geosite file to the country database
/// would otherwise replace the address half instead of installing the category
/// half.
pub fn set_default_geosite_path(path: impl AsRef<Path>) -> Result<()> {
    let path = path
        .as_ref()
        .canonicalize()
        .map_err(|error| Error::config(format!("Cannot resolve geosite database: {error}")))?;
    if !path.is_file() {
        return Err(Error::config("Geosite database path is not a file"));
    }
    *DEFAULT_GEOSITE_PATH.write() = Some(path);
    Ok(())
}

/// Longest [`CountryCode`] accepted, in bytes.
///
/// A GeoLite2-family database ships two-letter ISO 3166-1 alpha-2 codes, but
/// customized builds also label provider networks with names such as
/// `GOOGLE`, `NETFLIX` or `CLOUDFRONT`. Sixteen covers those naming schemes
/// while keeping the type `Copy`, inline and allocation-free.
pub const MAX_COUNTRY_CODE_LEN: usize = 16;

/// A GeoIP code: an ISO 3166-1 alpha-2 country code, or the provider label a
/// customized database carries in the same `country.iso_code` field.
///
/// The code is stored inline and uppercased, so parsing, storage and comparison
/// stay allocation-free. Only `A-Z{2,16}` is accepted — the shapes databases and
/// rule payloads legitimately use — and anything else is rejected instead of
/// being normalized into something that could match by accident.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CountryCode {
    bytes: [u8; MAX_COUNTRY_CODE_LEN],
    len: u8,
}

impl CountryCode {
    /// Parse a rule payload such as `CN`, `LAN` or `GOOGLE`.
    pub fn parse(code: &str) -> Option<Self> {
        Self::from_bytes(code.as_bytes())
    }

    /// Canonicalize raw bytes coming from a rule payload or a database field.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 2 || bytes.len() > MAX_COUNTRY_CODE_LEN {
            return None;
        }
        let mut out = [0u8; MAX_COUNTRY_CODE_LEN];
        for (slot, byte) in out.iter_mut().zip(bytes) {
            if !byte.is_ascii_alphabetic() {
                return None;
            }
            *slot = byte.to_ascii_uppercase();
        }
        Some(Self {
            bytes: out,
            len: bytes.len() as u8,
        })
    }

    /// The raw uppercase bytes, without the unused tail of the inline buffer.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// The code as a string slice; always ASCII.
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or_default()
    }

    /// Byte-exact comparison against another code.
    pub fn matches(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl core::fmt::Display for CountryCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::fmt::Debug for CountryCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CountryCode({self})")
    }
}

/// Geo data matching for the router.
///
/// `Router` depends on this trait (not on `GeoIpManager` directly) so that tests
/// and alternate data sources can inject a deterministic implementation. It spans
/// both questions a `GEOIP` / `GEOSITE` rule can ask, because both are answered
/// from the same family of files.
pub trait CountryMatcher: Send + Sync {
    /// Whether `ip` belongs to `country_code`.
    fn matches_country(&self, country_code: &str, ip: IpAddr) -> bool;

    /// Whether `domain` belongs to the geosite category `tag`.
    fn matches_geosite(&self, tag: &str, domain: &str) -> bool;

    /// Install a Geo database file, deciding its kind from its content.
    fn load_database(&self, path: &str) -> Result<()>;

    /// Install a Geo database from memory.
    fn load_database_from_bytes(&self, data: Vec<u8>) -> Result<()>;

    /// Install a `geosite.dat`, refusing a file that is not one.
    fn load_geosite_database(&self, path: &str) -> Result<()>;
}

/// The Geo databases behind one router: an optional MaxMind DB for country
/// ownership and the community `.dat` pair for categories and address ranges.
pub struct GeoIpDatabase {
    /// `Country.mmdb`, when the profile ships one. Preferred for country lookups
    /// because it is the source that carries per-city and per-ASN detail.
    reader: Option<MmdbReader>,
    /// `geoip.dat` / `geosite.dat`, when the profile ships those.
    geo: GeoDatabases,
}

impl GeoIpDatabase {
    /// A database with nothing loaded: every Geo rule misses.
    pub fn new() -> Self {
        Self {
            reader: None,
            geo: GeoDatabases::new(),
        }
    }

    /// Load a database file of any supported kind.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let data = std::fs::read(path.as_ref())
            .map_err(|e| Error::config(format!("Failed to read GeoIP database: {e}")))?;
        Self::load_from_bytes(data)
    }

    /// Load a database payload of any supported kind.
    pub fn load_from_bytes(data: Vec<u8>) -> Result<Self> {
        let mut database = Self::new();
        database.install_bytes(data)?;
        Ok(database)
    }

    /// Install a file into this database, replacing the half it belongs to.
    ///
    /// A MaxMind DB replaces the address reader; `geoip.dat` replaces the address
    /// ranges; `geosite.dat` replaces the categories. Two address sources cannot
    /// both be installed through this call because the file decides, and a profile
    /// that ships both wants the pair, not a merge.
    pub fn install_file<P: AsRef<Path>>(&mut self, path: P) -> Result<DatabaseKind> {
        let path = path.as_ref();
        let data = std::fs::read(path).map_err(|error| {
            Error::config(format!(
                "Failed to read Geo database '{}': {error}",
                path.display()
            ))
        })?;
        self.install_bytes(data)
    }

    /// Install a payload into this database, replacing the half it belongs to.
    pub fn install_bytes(&mut self, data: Vec<u8>) -> Result<DatabaseKind> {
        let kind = crate::engine::geo::identify(&data);
        match kind {
            DatabaseKind::Mmdb => {
                let reader = MmdbReader::open(data)
                    .map_err(|e| Error::config(format!("Failed to parse Country.mmdb: {e}")))?;
                self.reader = Some(reader);
                Ok(kind)
            }
            DatabaseKind::GeoSite | DatabaseKind::GeoIp => {
                let installed = self.geo.load_bytes(data)?;
                Ok(installed)
            }
            DatabaseKind::Unknown => Err(Error::config(
                "Geo database is in a format this engine does not read: expected Country.mmdb, \
                 geosite.dat or geoip.dat",
            )),
        }
    }

    /// Whether any Geo source is available.
    pub fn is_loaded(&self) -> bool {
        self.reader.is_some() || !self.geo.is_empty()
    }

    /// Whether a MaxMind database is loaded.
    pub fn has_mmdb(&self) -> bool {
        self.reader.is_some()
    }

    /// The community databases, for callers that want to query tags directly.
    pub fn geo(&self) -> &GeoDatabases {
        &self.geo
    }

    /// Country ownership from the MaxMind database, when one is loaded.
    pub fn lookup_country(&self, ip: IpAddr) -> Option<CountryCode> {
        self.reader.as_ref()?.lookup_country(ip)
    }

    /// Whether `ip` belongs to `country_code`.
    ///
    /// Order matters and is deliberate: `LAN`/`PRIVATE` are answered from the
    /// unroutable table (no database describes them consistently), then the
    /// MaxMind database is authoritative when it has a record, and `geoip.dat`
    /// answers the rest. A profile that ships only `geoip.dat` — the common
    /// community-profile case — therefore works without a MaxMind file at all.
    pub fn matches_country(&self, country_code: &str, ip: IpAddr) -> bool {
        if country_code.eq_ignore_ascii_case("LAN") || country_code.eq_ignore_ascii_case("PRIVATE")
        {
            return is_non_routable(ip);
        }
        if let Some(found) = self.lookup_country(ip) {
            return match CountryCode::parse(country_code) {
                Some(code) => found.matches(&code),
                None => false,
            };
        }
        self.geo.matches_geoip(country_code, ip)
    }

    /// Whether `domain` belongs to the geosite category `tag`.
    pub fn matches_geosite(&self, tag: &str, domain: &str) -> bool {
        self.geo.matches_geosite(tag, domain)
    }
}

impl Default for GeoIpDatabase {
    fn default() -> Self {
        Self::new()
    }
}

/// Guards the "no Geo database found" warning so it is emitted at most once per
/// process (routers can be constructed repeatedly, e.g. on hot reload or in
/// tests, and a missing database is a normal recoverable state).
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

    /// Build a manager from the Geo databases beside the executable.
    ///
    /// Candidate files, each loaded independently so a profile may ship any
    /// combination of them:
    ///
    /// * the path registered through [`set_default_database_path`], otherwise
    ///   `CORDUIT_GEOIP_DB`, otherwise `Country.mmdb` / `geoip.dat` next to the
    ///   executable;
    /// * the path registered through [`set_default_geosite_path`], otherwise
    ///   `CORDUIT_GEOSITE_DB`, otherwise `geosite.dat` next to the executable.
    ///
    /// A database that is absent is a normal, recoverable state: `GEOIP` and
    /// `GEOSITE` rules simply miss and fall through to the next rule. A database
    /// that is present but unreadable is a warning naming the file, because that
    /// one is a mistake worth seeing.
    pub fn from_embedded_country_database() -> Self {
        let mut database = GeoIpDatabase::new();
        let mut found_any = false;

        for candidate in ip_candidates() {
            if !candidate.is_file() {
                continue;
            }
            match database.install_file(&candidate) {
                Ok(kind) => {
                    found_any = true;
                    tracing::info!(
                        "Geo database {} loaded from {}",
                        kind.as_str(),
                        candidate.display()
                    );
                }
                Err(error) => tracing::warn!(
                    "Geo database {} is unreadable: {error}; continuing without it",
                    candidate.display()
                ),
            }
        }

        for candidate in site_candidates() {
            if !candidate.is_file() {
                continue;
            }
            match database.install_file(&candidate) {
                Ok(kind) => {
                    found_any = true;
                    tracing::info!(
                        "Geo database {} loaded from {}",
                        kind.as_str(),
                        candidate.display()
                    );
                }
                Err(error) => tracing::warn!(
                    "Geo database {} is unreadable: {error}; continuing without it",
                    candidate.display()
                ),
            }
        }

        if !found_any && !GEOIP_MISSING_WARNED.swap(true, std::sync::atomic::Ordering::SeqCst) {
            tracing::warn!(
                "No Geo database found (looked for Country.mmdb, geoip.dat and geosite.dat next to \
                 the executable); GEOIP and GEOSITE rules will not match. Set CORDUIT_GEOIP_DB / \
                 CORDUIT_GEOSITE_DB or call set_default_database_path to enable them"
            );
        }

        if found_any {
            tracing::info!("Geo databases: {}", database.geo().describe());
        }

        Self {
            database: Arc::new(RwLock::new(database)),
        }
    }

    /// Install a database file, deciding its kind from its content.
    pub fn load_database<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let kind = self.database.write().install_file(path)?;
        tracing::info!("Geo database ({}) loaded successfully", kind.as_str());
        Ok(())
    }

    /// Install a database from memory, deciding its kind from its content.
    pub fn load_database_from_bytes(&self, data: Vec<u8>) -> Result<()> {
        let kind = self.database.write().install_bytes(data)?;
        tracing::info!(
            "Geo database ({}) loaded from memory successfully",
            kind.as_str()
        );
        Ok(())
    }

    /// Install a `geosite.dat`, refusing a file that is not one.
    ///
    /// The geosite half is replaced on its own: reloading categories must not
    /// disturb the address database a connection is being routed against.
    pub fn load_geosite_database<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        self.database.read().geo().load_geosite_file(path.as_ref())
    }

    /// Whether any Geo source is available.
    pub fn is_loaded(&self) -> bool {
        self.database.read().is_loaded()
    }

    /// Country ownership from the MaxMind database, when one is loaded.
    pub fn lookup_country(&self, ip: IpAddr) -> Option<CountryCode> {
        self.database.read().lookup_country(ip)
    }

    /// Whether `ip` belongs to `country_code`.
    pub fn matches_country(&self, country_code: &str, ip: IpAddr) -> bool {
        self.database.read().matches_country(country_code, ip)
    }

    /// Whether `domain` belongs to the geosite category `tag`.
    pub fn matches_geosite(&self, tag: &str, domain: &str) -> bool {
        self.database.read().matches_geosite(tag, domain)
    }

    /// One line describing the loaded sources, for diagnostics.
    pub fn describe(&self) -> String {
        let database = self.database.read();
        let mmdb = if database.has_mmdb() {
            "mmdb"
        } else {
            "no mmdb"
        };
        format!("{mmdb}, {}", database.geo().describe())
    }
}

impl CountryMatcher for GeoIpManager {
    fn matches_country(&self, country_code: &str, ip: IpAddr) -> bool {
        self.matches_country(country_code, ip)
    }

    fn matches_geosite(&self, tag: &str, domain: &str) -> bool {
        self.matches_geosite(tag, domain)
    }

    fn load_database(&self, path: &str) -> Result<()> {
        self.load_database(path)
    }

    fn load_database_from_bytes(&self, data: Vec<u8>) -> Result<()> {
        self.load_database_from_bytes(data)
    }

    fn load_geosite_database(&self, path: &str) -> Result<()> {
        self.load_geosite_database(path)
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

/// Where to look for the address half, in order.
fn ip_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = DEFAULT_DATABASE_PATH.read().clone() {
        candidates.push(path);
    }
    if let Some(path) = std::env::var_os("CORDUIT_GEOIP_DB") {
        candidates.push(PathBuf::from(path));
    }
    if let Some(directory) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
    {
        candidates.push(directory.join("Country.mmdb"));
        candidates.push(directory.join("geoip.dat"));
    }
    candidates
}

/// Where to look for the geosite half, in order.
fn site_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = DEFAULT_GEOSITE_PATH.read().clone() {
        candidates.push(path);
    }
    if let Some(path) = std::env::var_os("CORDUIT_GEOSITE_DB") {
        candidates.push(PathBuf::from(path));
    }
    if let Some(directory) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
    {
        candidates.push(directory.join("geosite.dat"));
    }
    candidates
}

/// Whether an address can be reached from the public internet.
///
/// Delegated to [`crate::dns::bogon`] rather than re-derived. There used to be
/// a second, hand-written range check here, and it had already drifted: it knew
/// about RFC 1918, loopback, link-local, CGNAT and the documentation nets, but
/// not multicast, not `0.0.0.0/8` beyond the single unspecified address, not
/// `240.0.0.0/4`, not the benchmarking range, and nothing about
/// `::ffff:0:0/96` or the v6 translation prefixes. Two tables of "addresses that
/// are not routable" is one table too many, and the failure mode is silent:
/// a rule that reads as if it protects simply stops recognising a range.
///
/// The one table lives with the answer-quality gate that reads it, because that
/// gate is where an unroutable address in an answer means "an upstream is
/// lying" rather than "do not dial this".
pub(crate) fn is_non_routable(ip: IpAddr) -> bool {
    crate::dns::bogon::is_bogon(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_private_ipv4() {
        // The ranges the old hand-written check knew about...
        assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(!is_non_routable(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));

        // ...and the ones it did not, which is why there is one table now.
        assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))));
        assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1))));
        assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(0, 1, 2, 3))));
        assert!(is_non_routable(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))));
    }

    #[test]
    fn test_private_ipv6() {
        assert!(is_non_routable(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_non_routable("fe80::1".parse().expect("ipv6")));
        assert!(is_non_routable("fd00::1".parse().expect("ipv6")));
        assert!(is_non_routable("::ffff:10.0.0.1".parse().expect("mapped")));
        assert!(!is_non_routable(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888
        ))));
    }

    #[test]
    fn test_country_code_parse_and_match() {
        assert_eq!(CountryCode::parse("cn").unwrap().as_bytes(), b"CN");
        assert_eq!(CountryCode::parse("US").unwrap().as_bytes(), b"US");
        assert!(
            CountryCode::parse("cn")
                .unwrap()
                .matches(&CountryCode::parse("CN").unwrap())
        );
        assert!(
            !CountryCode::parse("CN")
                .unwrap()
                .matches(&CountryCode::parse("JP").unwrap())
        );
        assert!(CountryCode::parse("C").is_none());
        assert!(CountryCode::parse("").is_none());
        assert!(CountryCode::parse("12").is_none());
        assert!(CountryCode::parse("C1").is_none());
        assert!(CountryCode::parse("CN-").is_none());
        assert_eq!(CountryCode::parse("cn").unwrap().to_string(), "CN");
    }

    /// Customized GeoLite2 builds label provider networks instead of countries;
    /// those labels are first-class codes, not silently dropped lookups.
    #[test]
    fn test_country_code_accepts_provider_labels() {
        let google = CountryCode::parse("google").unwrap();
        assert_eq!(google.as_str(), "GOOGLE");
        assert_eq!(CountryCode::parse("GOOGLE").unwrap(), google);
        assert!(
            CountryCode::parse("cloudfront")
                .unwrap()
                .matches(&CountryCode::parse("CLOUDFRONT").unwrap())
        );
        assert!(!google.matches(&CountryCode::parse("CLOUDFLARE").unwrap()));
        assert!(CountryCode::parse(&"A".repeat(MAX_COUNTRY_CODE_LEN)).is_some());
        assert!(CountryCode::parse(&"A".repeat(MAX_COUNTRY_CODE_LEN + 1)).is_none());
    }

    #[test]
    fn test_geoip_database_new() {
        let db = GeoIpDatabase::new();
        assert!(!db.is_loaded());
        assert!(!db.has_mmdb());
    }

    #[test]
    fn test_fallback_lan_match() {
        let db = GeoIpDatabase::new();
        assert!(db.matches_country("LAN", IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(db.matches_country("PRIVATE", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!db.matches_country("US", IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    /// The community pair is what makes this reachable without a MaxMind file:
    /// `GEOIP,CN` and `GEOSITE,netflix` both have to answer from `geoip.dat` and
    /// `geosite.dat` alone.
    #[test]
    fn the_community_dat_pair_answers_rules_without_an_mmdb() {
        let mut database = GeoIpDatabase::new();
        assert_eq!(
            database
                .install_bytes(geoip_fixture())
                .expect("geoip installs"),
            DatabaseKind::GeoIp
        );
        assert_eq!(
            database
                .install_bytes(geosite_fixture())
                .expect("geosite installs"),
            DatabaseKind::GeoSite
        );
        assert!(database.is_loaded());
        assert!(!database.has_mmdb());

        assert!(database.matches_country("CN", "36.1.2.3".parse().expect("ip")));
        assert!(!database.matches_country("CN", "8.8.8.8".parse().expect("ip")));
        assert!(database.matches_geosite("netflix", "www.netflix.com"));
        assert!(!database.matches_geosite("netflix", "example.com"));
        // LAN stays answered from the unroutable table even with a database.
        assert!(database.matches_country("LAN", "10.1.2.3".parse().expect("ip")));
    }

    #[test]
    fn an_unreadable_payload_is_refused() {
        let mut database = GeoIpDatabase::new();
        assert!(
            database
                .install_bytes(b"DOMAIN,example.com".to_vec())
                .is_err()
        );
        assert!(!database.is_loaded());
    }

    #[test]
    fn test_embedded_country_database_degrades_gracefully() {
        // Without a real database on disk the manager must still construct, start
        // empty, and let GEOIP rules miss without panicking.
        let manager = GeoIpManager::from_embedded_country_database();
        let loaded = manager.is_loaded();
        // Either a database from the environment exists (CI may ship one) or the
        // manager is empty; both are valid, neither may panic.
        if !loaded {
            assert!(
                manager
                    .lookup_country(IpAddr::V4(Ipv4Addr::new(114, 114, 114, 114)))
                    .is_none()
            );
            assert!(!manager.matches_country("CN", IpAddr::V4(Ipv4Addr::new(36, 152, 0, 1))));
            assert!(!manager.matches_geosite("netflix", "www.netflix.com"));
        }
        assert!(!manager.describe().is_empty());
    }

    // --- fixtures ------------------------------------------------------------

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

    fn geoip_fixture() -> Vec<u8> {
        let mut cidr = Vec::new();
        field_bytes(&mut cidr, 1, &[36, 0, 0, 0]);
        field_varint(&mut cidr, 2, 8);

        let mut country = Vec::new();
        field_bytes(&mut country, 1, b"CN");
        field_bytes(&mut country, 2, &cidr);

        let mut out = Vec::new();
        field_bytes(&mut out, 1, &country);
        out
    }

    fn geosite_fixture() -> Vec<u8> {
        let mut domain = Vec::new();
        field_varint(&mut domain, 1, 0);
        field_bytes(&mut domain, 2, b"netflix.com");

        let mut category = Vec::new();
        field_bytes(&mut category, 1, b"netflix");
        field_bytes(&mut category, 2, &domain);

        let mut out = Vec::new();
        field_bytes(&mut out, 1, &category);
        out
    }
}
