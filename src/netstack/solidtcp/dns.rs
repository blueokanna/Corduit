//! DNS handling with Fake-IP support

use crate::common::lru::LruCache;
use crate::dns::engine_resolver::resolve_ips;
use crate::dns::pattern::{any_suffix_matches, normalize_suffix};
use crate::netstack::solidtcp::error::{Result, SolidTcpError};
use dashmap::DashMap;
use parking_lot::Mutex;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// TTL of a fake-IP answer, in seconds.
///
/// Deliberately tiny. The mapping behind a fake address lives only in this
/// process, while the client may keep dialling the address for as long as its
/// resolver honours the TTL. After a restart — or an explicit pool reset —
/// every previously handed-out address is unmappable, so the window in which a
/// client can still hold a stale one has to stay short enough to matter less
/// than the re-resolution it costs.
pub const FAKE_IP_TTL_SECS: u32 = 10;

/// Fake-IP configuration
#[derive(Debug, Clone)]
pub struct FakeIpConfig {
    pub range_start: Ipv4Addr,
    pub pool_size: u32,
    pub ttl: Duration,
}

impl Default for FakeIpConfig {
    fn default() -> Self {
        Self {
            range_start: Ipv4Addr::new(198, 18, 0, 0),
            pool_size: 65536,
            ttl: Duration::from_secs(600),
        }
    }
}

impl FakeIpConfig {
    /// Build a pool from a CIDR such as `198.18.0.0/16`.
    pub fn from_cidr(cidr: &str) -> std::result::Result<Self, String> {
        let network = cidr
            .trim()
            .parse::<ipnet::IpNet>()
            .map_err(|error| format!("invalid fake-ip-range '{cidr}': {error}"))?;
        let ipnet::IpNet::V4(network) = network else {
            return Err(format!(
                "fake-ip-range '{cidr}' is IPv6; the client pool hands out IPv4 \
                 addresses and holds no IPv6 range"
            ));
        };
        let prefix = network.prefix_len();
        if !(16..=24).contains(&prefix) {
            return Err(format!(
                "fake-ip-range '{cidr}' uses a /{prefix}; the supported sizes are \
                 /16 through /24"
            ));
        }
        Ok(Self {
            range_start: network.network(),
            pool_size: 1u32 << (32 - u32::from(prefix)),
            ttl: Self::default().ttl,
        })
    }
}

/// Fake-IP entry
#[derive(Debug, Clone)]
pub struct FakeIpEntry {
    pub ip: Ipv4Addr,
    pub domain: String,
    pub expires: Instant,
}

/// Fake-IP pool
pub struct FakeIpPool {
    config: FakeIpConfig,
    domain_to_ip: DashMap<String, FakeIpEntry>,
    ip_to_domain: DashMap<Ipv4Addr, String>,
    next_offset: AtomicU32,
    lru: Mutex<LruCache<String, Ipv4Addr>>,
}

impl FakeIpPool {
    pub fn new() -> Self {
        Self::with_config(FakeIpConfig::default())
    }

    pub fn with_config(config: FakeIpConfig) -> Self {
        let sz =
            NonZeroUsize::new(config.pool_size as usize).unwrap_or(NonZeroUsize::new(1).unwrap());
        Self {
            config,
            domain_to_ip: DashMap::new(),
            ip_to_domain: DashMap::new(),
            next_offset: AtomicU32::new(3),
            lru: Mutex::new(LruCache::new(sz)),
        }
    }

    pub fn allocate(&self, domain: &str) -> Result<Ipv4Addr> {
        let domain = domain.to_lowercase();
        if let Some(e) = self.domain_to_ip.get(&domain) {
            if Instant::now() < e.expires {
                self.lru.lock().put(domain.clone(), e.ip);
                return Ok(e.ip);
            }
        }

        let offset = self.next_offset.fetch_add(1, Ordering::Relaxed);
        let effective_offset = if offset >= self.config.pool_size {
            self.next_offset.store(3, Ordering::Relaxed);
            self.cleanup();
            if self.domain_to_ip.len() >= self.config.pool_size as usize - 3 {
                return Err(SolidTcpError::FakeIpPoolExhausted);
            }
            3
        } else if offset < 3 {
            self.next_offset.store(3, Ordering::Relaxed);
            3
        } else {
            offset
        };

        let ip = self.offset_to_ip(effective_offset);
        if let Some((_, old)) = self.ip_to_domain.remove(&ip) {
            self.domain_to_ip.remove(&old);
        }

        let entry = FakeIpEntry {
            ip,
            domain: domain.clone(),
            expires: Instant::now() + self.config.ttl,
        };
        self.domain_to_ip.insert(domain.clone(), entry);
        self.ip_to_domain.insert(ip, domain.clone());
        self.lru.lock().put(domain.clone(), ip);
        info!("Fake-IP allocated: {} -> {}", ip, domain);
        Ok(ip)
    }

    pub fn lookup(&self, ip: Ipv4Addr) -> Option<String> {
        self.ip_to_domain.get(&ip).map(|d| d.clone())
    }

    pub fn is_fake_ip(&self, ip: Ipv4Addr) -> bool {
        let start = u32::from(self.config.range_start);
        let val = u32::from(ip);
        val >= start && val < start + self.config.pool_size
    }

    fn offset_to_ip(&self, offset: u32) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.config.range_start) + offset)
    }

    pub fn cleanup(&self) {
        let expired: Vec<_> = self
            .domain_to_ip
            .iter()
            .filter(|e| Instant::now() >= e.expires)
            .map(|e| (e.key().clone(), e.ip))
            .collect();
        for (domain, ip) in expired {
            self.domain_to_ip.remove(&domain);
            self.ip_to_domain.remove(&ip);
        }
    }

    pub fn cleanup_expired(&self) {
        self.cleanup();
    }

    pub fn size(&self) -> usize {
        self.domain_to_ip.len()
    }

    pub fn clear(&self) {
        self.domain_to_ip.clear();
        self.ip_to_domain.clear();
        self.lru.lock().clear();
        self.next_offset.store(3, Ordering::Relaxed);
        info!("Fake-IP pool cleared, next_offset reset to 3");
    }
}

impl Default for FakeIpPool {
    fn default() -> Self {
        Self::new()
    }
}

/// DNS query type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DnsQueryType {
    A = 1,
    AAAA = 28,
    CNAME = 5,
    Other = 0,
}

impl DnsQueryType {
    pub fn from_u16(v: u16) -> Self {
        match v {
            1 => Self::A,
            28 => Self::AAAA,
            5 => Self::CNAME,
            _ => Self::Other,
        }
    }
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

/// Parsed DNS query
#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub id: u16,
    pub domain: String,
    pub qtype: DnsQueryType,
    pub qclass: u16,
}

/// TTL of an answer the responder resolved for real.
///
/// The upstream TTL is not propagated: the client re-asks on this schedule, and
/// the resolver keeps its own cache behind it, so a short value costs a cheap
/// cache hit rather than a round trip when the answer is still warm.
pub const REAL_ANSWER_TTL_SECS: u32 = 60;

/// TTL of a static `hosts` answer. A literal in a profile does not expire.
pub const HOSTS_TTL_SECS: u32 = 300;

/// Suffixes that always resolve for real.
///
/// These names exist only inside the network the client is on, so a public
/// resolver cannot answer them and a fake address would route a LAN name into
/// the tunnel and fail with no explanation. Single-label names are excluded by
/// the same rule; see [`AnswerPolicy::is_filtered`].
///
/// `arpa` is here for reverse lookups: `in-addr.arpa` and `ip6.arpa` are how an
/// address is turned back into a name, and a fake address reversing to nothing
/// is worse than an empty answer.
const RESERVED_LOCAL_SUFFIXES: [&str; 5] = ["lan", "local", "localdomain", "home.arpa", "arpa"];

/// How the client-facing responder answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientDnsMode {
    /// Hand out an address from the fake pool and let the router resolve the
    /// real one by domain. The client never sees or caches the real address, and
    /// every connection stays routable by name.
    FakeIp,
    /// Resolve for real and return the address.
    Normal,
}

impl ClientDnsMode {
    /// Read the mode from a profile's `enhanced-mode`.
    ///
    /// `redir-host` maps to [`ClientDnsMode::Normal`]: this responder answers
    /// with the real address and routes on the resolved IP, which is what the
    /// client gets either way. An unrecognised value falls back to normal,
    /// because resolving for real is the mode that cannot silently lose the
    /// domain a connection was made to.
    pub fn from_profile(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "fake-ip" | "fakeip" | "fake_ip" => Self::FakeIp,
            _ => Self::Normal,
        }
    }
}

/// Client-facing DNS behaviour, taken from the profile's `dns` section.
///
/// Everything a query needs is normalized here, once, so the per-query path is
/// comparisons rather than parsing.
#[derive(Debug, Clone)]
pub struct ClientDnsSettings {
    pub mode: ClientDnsMode,
    pub fake_ip: FakeIpConfig,
    /// `fake-ip-filter`: suffixes that must always receive a real address.
    pub filter: Vec<String>,
    /// `hosts`: name to addresses, keys lower-cased.
    pub hosts: Vec<(String, Vec<IpAddr>)>,
    /// Resolve and answer `AAAA` queries. When false every `AAAA` query gets an
    /// empty answer, which makes a client fall back to `A` instead of stalling
    /// on a v6 path the tunnel may not carry; that is why it defaults to false.
    pub ipv6: bool,
    /// TTL handed to the client for a fake address.
    pub fake_ip_ttl: u32,
}

impl Default for ClientDnsSettings {
    fn default() -> Self {
        Self {
            mode: ClientDnsMode::FakeIp,
            fake_ip: FakeIpConfig::default(),
            filter: Vec::new(),
            hosts: Vec::new(),
            ipv6: false,
            fake_ip_ttl: FAKE_IP_TTL_SECS,
        }
    }
}

impl ClientDnsSettings {
    /// Build from profile values.
    pub fn from_parts(
        mode: ClientDnsMode,
        fake_ip_range: &str,
        filter: &[String],
        hosts: &[(String, Vec<IpAddr>)],
    ) -> std::result::Result<Self, String> {
        let mut normalized: Vec<String> =
            filter.iter().map(|entry| normalize_suffix(entry)).collect();
        normalized.retain(|entry| !entry.is_empty());
        normalized.sort();
        normalized.dedup();

        let mut static_hosts: Vec<(String, Vec<IpAddr>)> = hosts
            .iter()
            .map(|(name, addresses)| {
                (
                    name.trim().trim_end_matches('.').to_ascii_lowercase(),
                    addresses.clone(),
                )
            })
            .filter(|(name, addresses)| !name.is_empty() && !addresses.is_empty())
            .collect();
        static_hosts.sort_by(|left, right| left.0.cmp(&right.0));

        Ok(Self {
            mode,
            fake_ip: FakeIpConfig::from_cidr(fake_ip_range)?,
            filter: normalized,
            hosts: static_hosts,
            ipv6: false,
            fake_ip_ttl: FAKE_IP_TTL_SECS,
        })
    }

    /// Whether `AAAA` queries are answered.
    pub fn with_ipv6(mut self, ipv6: bool) -> Self {
        self.ipv6 = ipv6;
        self
    }

    /// TTL to hand out for a fake address.
    ///
    /// A zero TTL would be a client that re-resolves on every connection while
    /// gaining nothing, so it is treated as "use the default".
    pub fn with_fake_ip_ttl(mut self, ttl: u32) -> Self {
        if ttl > 0 {
            self.fake_ip_ttl = ttl;
        }
        self
    }
}

/// The part of [`ClientDnsSettings`] the responder itself needs.
///
/// The pool owns the range; this owns how a name is answered. Keeping them apart
/// means there is exactly one owner for each fact and no way for two copies to
/// disagree.
struct AnswerPolicy {
    mode: ClientDnsMode,
    filter: Vec<String>,
    hosts: Vec<(String, Vec<IpAddr>)>,
    ipv6: bool,
    fake_ip_ttl: u32,
}

impl AnswerPolicy {
    fn from_settings(settings: &ClientDnsSettings) -> Self {
        Self {
            mode: settings.mode,
            filter: settings.filter.clone(),
            hosts: settings.hosts.clone(),
            ipv6: settings.ipv6,
            fake_ip_ttl: settings.fake_ip_ttl,
        }
    }

    /// A static answer, if the profile has one.
    fn host_answer(&self, domain: &str) -> Option<&[IpAddr]> {
        let wanted = domain.trim_end_matches('.');
        self.hosts
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
            .map(|(_, addresses)| addresses.as_slice())
    }

    /// Must this name be resolved for real?
    fn is_filtered(&self, domain: &str) -> bool {
        if !domain.contains('.') {
            return true;
        }
        if any_suffix_matches(domain, RESERVED_LOCAL_SUFFIXES) {
            return true;
        }
        any_suffix_matches(domain, self.filter.iter().map(String::as_str))
    }
}

/// What the responder wants done with a query.
#[derive(Debug)]
pub enum DnsVerdict {
    /// Send these bytes back to the client. `faked_domain` is set when a fake
    /// address was allocated, for stats and for the reverse mapping.
    Answer {
        bytes: Vec<u8>,
        faked_domain: Option<String>,
    },
    /// The query is not something the pool can answer. Letting it take the
    /// normal UDP path reaches a real resolver and supports every record type,
    /// which is strictly better than inventing a wrong answer for it.
    Forward,
}

/// DNS handler
pub struct DnsHandler {
    fake_ip_pool: Arc<FakeIpPool>,
    policy: AnswerPolicy,
}

impl DnsHandler {
    pub fn new(pool: Arc<FakeIpPool>, settings: &ClientDnsSettings) -> Self {
        Self {
            fake_ip_pool: pool,
            policy: AnswerPolicy::from_settings(settings),
        }
    }

    /// The mode in effect, for diagnostics.
    pub fn mode(&self) -> ClientDnsMode {
        self.policy.mode
    }

    pub fn parse_query(&self, data: &[u8]) -> Result<DnsQuery> {
        if data.len() < 12 {
            return Err(SolidTcpError::DnsError("Too short".into()));
        }
        let id = u16::from_be_bytes([data[0], data[1]]);
        if data[2] & 0x80 != 0 {
            return Err(SolidTcpError::DnsError("Not a query".into()));
        }
        let (domain, offset) = self.parse_name(data, 12)?;
        if offset + 4 > data.len() {
            return Err(SolidTcpError::DnsError("Truncated".into()));
        }
        let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        Ok(DnsQuery {
            id,
            domain,
            qtype: DnsQueryType::from_u16(qtype),
            qclass,
        })
    }

    fn parse_name(&self, data: &[u8], start: usize) -> Result<(String, usize)> {
        let mut labels = Vec::new();
        let mut pos = start;
        let mut jumped = false;
        let mut jump_pos = 0;
        loop {
            if pos >= data.len() {
                return Err(SolidTcpError::DnsError("Name truncated".into()));
            }
            let len = data[pos] as usize;
            if len == 0 {
                if !jumped {
                    pos += 1;
                }
                break;
            }
            if len & 0xC0 == 0xC0 {
                if pos + 1 >= data.len() {
                    return Err(SolidTcpError::DnsError("Ptr truncated".into()));
                }
                let ptr = ((len & 0x3F) << 8) | data[pos + 1] as usize;
                if !jumped {
                    jump_pos = pos + 2;
                    jumped = true;
                }
                pos = ptr;
                continue;
            }
            pos += 1;
            if pos + len > data.len() {
                return Err(SolidTcpError::DnsError("Label truncated".into()));
            }
            labels.push(String::from_utf8_lossy(&data[pos..pos + len]).to_string());
            pos += len;
        }
        Ok((labels.join("."), if jumped { jump_pos } else { pos }))
    }

    pub fn build_response(&self, query: &DnsQuery, ip: Ipv4Addr) -> Vec<u8> {
        let mut r = Vec::with_capacity(512);
        r.extend_from_slice(&query.id.to_be_bytes());
        r.extend_from_slice(&0x8180u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        self.encode_name(&mut r, &query.domain);
        r.extend_from_slice(&query.qtype.to_u16().to_be_bytes());
        r.extend_from_slice(&query.qclass.to_be_bytes());
        r.extend_from_slice(&0xC00Cu16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&self.policy.fake_ip_ttl.to_be_bytes());
        r.extend_from_slice(&4u16.to_be_bytes());
        r.extend_from_slice(&ip.octets());
        r
    }

    pub fn build_nxdomain(&self, query: &DnsQuery) -> Vec<u8> {
        let mut r = Vec::with_capacity(512);
        r.extend_from_slice(&query.id.to_be_bytes());
        r.extend_from_slice(&0x8183u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        self.encode_name(&mut r, &query.domain);
        r.extend_from_slice(&query.qtype.to_u16().to_be_bytes());
        r.extend_from_slice(&query.qclass.to_be_bytes());
        r
    }

    fn encode_name(&self, buf: &mut Vec<u8>, name: &str) {
        for label in name.split('.') {
            if !label.is_empty() {
                buf.push(label.len() as u8);
                buf.extend_from_slice(label.as_bytes());
            }
        }
        buf.push(0);
    }

    /// Decide the answer for one query.
    ///
    /// The order is deliberate: a static answer first, then the mode and the
    /// filter, because `hosts` is a statement that this name has a known answer
    /// and must not be asked about, while a filtered name has to be resolved by
    /// someone who can answer it.
    pub fn handle_query(&self, data: &[u8]) -> Result<DnsVerdict> {
        let query = self.parse_query(data)?;
        info!("DNS query received: {} ({:?})", query.domain, query.qtype);

        if let Some(addresses) = self.policy.host_answer(&query.domain) {
            let wanted = select_family(addresses, query.qtype);
            if !wanted.is_empty() {
                info!(
                    "DNS {} query: {} -> {} host entries",
                    query.qtype.to_u16(),
                    query.domain,
                    wanted.len()
                );
                return Ok(DnsVerdict::Answer {
                    bytes: self.build_address_response(&query, &wanted, HOSTS_TTL_SECS),
                    faked_domain: None,
                });
            }
        }

        let resolve_for_real =
            self.policy.mode == ClientDnsMode::Normal || self.policy.is_filtered(&query.domain);

        match query.qtype {
            DnsQueryType::A => {
                if resolve_for_real {
                    return Ok(DnsVerdict::Answer {
                        bytes: self.real_answer(&query, false),
                        faked_domain: None,
                    });
                }
                let ip = self.fake_ip_pool.allocate(&query.domain)?;
                info!(
                    "DNS A query: {} -> {} (Fake-IP allocated)",
                    query.domain, ip
                );
                Ok(DnsVerdict::Answer {
                    bytes: self.build_response(&query, ip),
                    faked_domain: Some(query.domain),
                })
            }
            DnsQueryType::AAAA => {
                if !self.policy.ipv6 {
                    info!(
                        "DNS AAAA query: {} -> empty response (ipv6 disabled)",
                        query.domain
                    );
                    return Ok(DnsVerdict::Answer {
                        bytes: self.build_empty_response(&query),
                        faked_domain: None,
                    });
                }
                if resolve_for_real {
                    return Ok(DnsVerdict::Answer {
                        bytes: self.real_answer(&query, true),
                        faked_domain: None,
                    });
                }
                info!(
                    "DNS AAAA query: {} -> empty response (fake-IP pool is IPv4)",
                    query.domain
                );
                Ok(DnsVerdict::Answer {
                    bytes: self.build_empty_response(&query),
                    faked_domain: None,
                })
            }
            _ => {
                info!(
                    "DNS {:?} query for {} is not pool-answerable; forwarding",
                    query.qtype, query.domain
                );
                Ok(DnsVerdict::Forward)
            }
        }
    }

    /// Resolve for real and build the answer.
    fn real_answer(&self, query: &DnsQuery, want_v6: bool) -> Vec<u8> {
        match self.resolve_real(&query.domain, want_v6) {
            Ok(addresses) if !addresses.is_empty() => {
                info!(
                    "DNS {} query: {} -> {} resolved addresses",
                    query.qtype.to_u16(),
                    query.domain,
                    addresses.len()
                );
                self.build_address_response(query, addresses.as_slice(), REAL_ANSWER_TTL_SECS)
            }

            Ok(_) => self.build_nxdomain(query),
            Err(error) => {
                warn!(
                    "DNS: could not resolve {} for a client query: {error}",
                    query.domain
                );
                self.build_servfail(query)
            }
        }
    }

    /// Resolve through the profile's DNS, then the system resolver.
    ///
    /// The system resolver gets the last word whenever the engine lookup
    /// produced nothing — it failed, it answered NODATA or NXDOMAIN, or no
    /// engine resolver is configured at all. That mirrors the outbound path
    /// (`common::socket`), which has always retried the engine's "found no
    /// address" through the system resolver: the engine resolver is a
    /// convenience over the profile's servers, not a name filter, so a client
    /// query must not fail where a dial would have succeeded. When both fail,
    /// the error names the engine's reason first, so the log answers "why"
    /// instead of "could not resolve".
    fn resolve_real(
        &self,
        domain: &str,
        want_v6: bool,
    ) -> std::result::Result<Vec<IpAddr>, String> {
        with_system_fallback(domain, resolve_ips(domain, want_v6), || {
            system_lookup(domain, want_v6)
        })
    }

    /// Build a response carrying every address of the matching family.
    ///
    /// The record type is taken from each address rather than from the question,
    /// so a response can never claim type `A` over a 16-byte address.
    fn build_address_response(&self, query: &DnsQuery, addresses: &[IpAddr], ttl: u32) -> Vec<u8> {
        let mut records = Vec::with_capacity(addresses.len() * 20);
        for ip in addresses {
            records.extend_from_slice(&0xC00Cu16.to_be_bytes());
            match ip {
                IpAddr::V4(v4) => {
                    records.extend_from_slice(&1u16.to_be_bytes());
                    records.extend_from_slice(&1u16.to_be_bytes());
                    records.extend_from_slice(&ttl.to_be_bytes());
                    records.extend_from_slice(&4u16.to_be_bytes());
                    records.extend_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    records.extend_from_slice(&28u16.to_be_bytes());
                    records.extend_from_slice(&1u16.to_be_bytes());
                    records.extend_from_slice(&ttl.to_be_bytes());
                    records.extend_from_slice(&16u16.to_be_bytes());
                    records.extend_from_slice(&v6.octets());
                }
            }
        }

        let mut response = Vec::with_capacity(12 + query.domain.len() + 6 + records.len());
        response.extend_from_slice(&query.id.to_be_bytes());
        response.extend_from_slice(&0x8180u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&(addresses.len() as u16).to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        self.encode_name(&mut response, &query.domain);
        response.extend_from_slice(&query.qtype.to_u16().to_be_bytes());
        response.extend_from_slice(&query.qclass.to_be_bytes());
        response.extend_from_slice(&records);
        response
    }

    /// A `SERVFAIL` response.
    ///
    /// Used instead of `NXDOMAIN` when a lookup failed for a reason that is not
    /// "this name has no record": claiming a name does not exist is a statement
    /// about the name, and clients act on it by giving up.
    pub fn build_servfail(&self, query: &DnsQuery) -> Vec<u8> {
        let mut response = Vec::with_capacity(12 + query.domain.len() + 6);
        response.extend_from_slice(&query.id.to_be_bytes());
        response.extend_from_slice(&0x8182u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        self.encode_name(&mut response, &query.domain);
        response.extend_from_slice(&query.qtype.to_u16().to_be_bytes());
        response.extend_from_slice(&query.qclass.to_be_bytes());
        response
    }

    pub fn build_empty_response(&self, query: &DnsQuery) -> Vec<u8> {
        let mut r = Vec::with_capacity(512);
        r.extend_from_slice(&query.id.to_be_bytes());
        r.extend_from_slice(&0x8180u16.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        self.encode_name(&mut r, &query.domain);
        r.extend_from_slice(&query.qtype.to_u16().to_be_bytes());
        r.extend_from_slice(&query.qclass.to_be_bytes());
        r
    }

    pub fn pool(&self) -> &Arc<FakeIpPool> {
        &self.fake_ip_pool
    }
}

/// Keep the addresses a client asked for.
///
/// An answer that mixes families is rejected by strict clients and defeats
/// happy-eyeballs, so a query for `A` gets the IPv4 addresses and an `AAAA`
/// query gets the IPv6 ones.
fn select_family(addresses: &[IpAddr], qtype: DnsQueryType) -> Vec<IpAddr> {
    let want_v6 = qtype == DnsQueryType::AAAA;
    addresses
        .iter()
        .copied()
        .filter(|ip| matches!(ip, IpAddr::V6(_)) == want_v6)
        .collect()
}

/// The engine lookup's outcome, with the system resolver as the last word.
///
/// Split out as a pure decision so the policy — *when* the system resolver is
/// asked — is testable without touching a socket. `engine` is exactly what
/// [`resolve_ips`] hands back: `None` when no engine resolver is configured,
/// otherwise its result; an engine answer with no address of the wanted
/// family is already an error by the time it gets here, and is treated like
/// any other engine failure.
fn with_system_fallback(
    domain: &str,
    engine: Option<std::io::Result<Vec<IpAddr>>>,
    system: impl FnOnce() -> std::result::Result<Vec<IpAddr>, String>,
) -> std::result::Result<Vec<IpAddr>, String> {
    let reason = match engine {
        Some(Ok(addresses)) if !addresses.is_empty() => return Ok(addresses),
        Some(Ok(_)) => "the engine DNS returned no addresses".to_string(),
        Some(Err(error)) => error.to_string(),
        None => "no engine DNS resolver is configured".to_string(),
    };
    debug!(
        "DNS: the engine lookup for {domain} produced nothing ({reason}); \
         the system resolver gets the last word"
    );
    system().map_err(|system_error| {
        format!("engine DNS: {reason}; the system resolver failed too: {system_error}")
    })
}

/// One system-resolver lookup, restricted to the requested family.
fn system_lookup(domain: &str, want_v6: bool) -> std::result::Result<Vec<IpAddr>, String> {
    let resolved = (domain, 0u16)
        .to_socket_addrs()
        .map_err(|error| error.to_string())?;
    let wanted: Vec<IpAddr> = resolved
        .map(|address| address.ip())
        .filter(|ip| matches!(ip, IpAddr::V6(_)) == want_v6)
        .collect();
    if wanted.is_empty() {
        Err("no address of the requested family".to_string())
    } else {
        Ok(wanted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A query in wire form, which is what the handler is handed.
    fn query_bytes(id: u16, domain: &str, qtype: u16) -> Vec<u8> {
        let mut query = Vec::new();
        query.extend_from_slice(&id.to_be_bytes());
        query.extend_from_slice(&0x0100u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        for label in domain.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&qtype.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query
    }

    fn handler(settings: ClientDnsSettings) -> (DnsHandler, Arc<FakeIpPool>) {
        let pool = Arc::new(FakeIpPool::with_config(settings.fake_ip.clone()));
        (DnsHandler::new(pool.clone(), &settings), pool)
    }

    fn fake_ip_mode() -> ClientDnsSettings {
        ClientDnsSettings::default()
    }

    fn normal_mode() -> ClientDnsSettings {
        ClientDnsSettings {
            mode: ClientDnsMode::Normal,
            ..ClientDnsSettings::default()
        }
    }

    #[test]
    fn fake_ip_mode_allocates_for_an_ordinary_name() {
        let (handler, pool) = handler(fake_ip_mode());
        let verdict = handler
            .handle_query(&query_bytes(0x1234, "node.example.com", 1))
            .expect("query");

        let DnsVerdict::Answer {
            bytes,
            faked_domain,
        } = verdict
        else {
            panic!("fake-ip mode must answer an A query, not forward it");
        };
        assert_eq!(faked_domain.as_deref(), Some("node.example.com"));
        assert_eq!(pool.size(), 1);
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 1, "one answer");

        let first = Ipv4Addr::new(198, 18, 0, 3);
        assert_eq!(pool.lookup(first).as_deref(), Some("node.example.com"));
        assert!(
            bytes
                .windows(4)
                .any(|window| window == first.octets().as_slice()),
            "the answer must carry the allocated address"
        );
    }

    /// The bug this replaced: `normal` mode was ignored entirely and every `A`
    /// query got a fake address anyway.
    #[test]
    fn normal_mode_never_allocates_a_fake_address() {
        let (handler, pool) = handler(normal_mode());
        let verdict = handler
            .handle_query(&query_bytes(0x0001, "node.example.com", 1))
            .expect("query");

        match verdict {
            DnsVerdict::Answer {
                bytes,
                faked_domain,
            } => {
                assert!(faked_domain.is_none());
                // No allocation happened, so no answer can name a pool address.
                assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 0);
            }
            DnsVerdict::Forward => panic!("an A query must be answered, not forwarded"),
        }
        assert_eq!(pool.size(), 0);
    }

    /// Names that only exist on the local network must never be faked, in any
    /// mode: nothing public resolves them, so a fake address is a guaranteed
    /// failure with no diagnostic.
    #[test]
    fn local_names_are_never_faked() {
        let policy = AnswerPolicy::from_settings(&fake_ip_mode());
        for name in [
            "nas",
            "printer",
            "router.lan",
            "host.local",
            "thing.localdomain",
            "gateway.home.arpa",
        ] {
            assert!(policy.is_filtered(name), "{name} must resolve for real");
        }
        for name in ["example.com", "node.example.com", "a.b.c.example.org"] {
            assert!(!policy.is_filtered(name), "{name} may be faked");
        }
        // Label boundary: a public name that merely ends in the same letters.
        assert!(!policy.is_filtered("notlocal.example"));
    }

    #[test]
    fn profile_filter_suffixes_are_honoured_and_normalized() {
        let settings = ClientDnsSettings::from_parts(
            ClientDnsMode::FakeIp,
            "198.18.0.0/16",
            &[
                "+.must-be-real.example".to_string(),
                "*.also-real.example".to_string(),
                ".third.example".to_string(),
                String::new(),
            ],
            &[],
        )
        .expect("settings");
        let policy = AnswerPolicy::from_settings(&settings);

        for name in [
            "must-be-real.example",
            "a.must-be-real.example",
            "x.also-real.example",
            "y.third.example",
        ] {
            assert!(policy.is_filtered(name), "{name} should be filtered");
        }
        assert!(!policy.is_filtered("notmust-be-real.example"));
        // The empty entry is dropped rather than matching everything.
        assert!(!policy.is_filtered("example.com"));
    }

    /// A filtered name is answered for real, and the responder must not allocate
    /// for it even when the resolution is about to fail.
    #[test]
    fn filtered_name_is_not_allocated() {
        let settings = ClientDnsSettings {
            filter: vec!["must-be-real.example".to_string()],
            ..fake_ip_mode()
        };
        let (handler, pool) = handler(settings);
        let verdict = handler
            .handle_query(&query_bytes(0x0002, "a.must-be-real.example", 1))
            .expect("query");

        match verdict {
            DnsVerdict::Answer { faked_domain, .. } => assert!(faked_domain.is_none()),
            DnsVerdict::Forward => panic!("an A query must be answered, not forwarded"),
        }
        assert_eq!(pool.size(), 0);
    }

    #[test]
    fn hosts_answer_without_allocating() {
        let settings = ClientDnsSettings::from_parts(
            ClientDnsMode::FakeIp,
            "198.18.0.0/16",
            &[],
            &[(
                "static.example".to_string(),
                vec!["203.0.113.9".parse().expect("ip")],
            )],
        )
        .expect("settings");
        let (handler, pool) = handler(settings);

        let DnsVerdict::Answer {
            bytes,
            faked_domain,
        } = handler
            .handle_query(&query_bytes(0x0003, "STATIC.example", 1))
            .expect("query")
        else {
            panic!("a host entry must answer");
        };
        assert!(faked_domain.is_none());
        assert_eq!(pool.size(), 0);
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 1);
        assert!(bytes
            .windows(4)
            .any(|window| window == [203, 0, 113, 9].as_slice()));
    }

    /// An `AAAA` answer must never carry an IPv4 address, and a `hosts` entry
    /// of the wrong family must not be bent into one.
    #[test]
    fn family_selection_is_strict() {
        let v4: Vec<IpAddr> = vec!["203.0.113.9".parse().expect("ip")];
        assert_eq!(select_family(&v4, DnsQueryType::A).len(), 1);
        assert!(select_family(&v4, DnsQueryType::AAAA).is_empty());

        let v6: Vec<IpAddr> = vec!["2001:db8::1".parse().expect("ip")];
        assert_eq!(select_family(&v6, DnsQueryType::AAAA).len(), 1);
        assert!(select_family(&v6, DnsQueryType::A).is_empty());
    }

    #[test]
    fn address_response_is_well_formed() {
        let (handler, _pool) = handler(fake_ip_mode());
        let query = handler
            .parse_query(&query_bytes(0x00AB, "node.example.com", 1))
            .expect("parse");
        let addresses: Vec<IpAddr> = vec![
            "203.0.113.7".parse().expect("ip"),
            "203.0.113.8".parse().expect("ip"),
        ];

        let bytes = handler.build_address_response(&query, &addresses, 60);
        assert_eq!(
            &bytes[0..2],
            0x00ABu16.to_be_bytes().as_slice(),
            "id preserved"
        );
        assert_eq!(
            &bytes[2..4],
            0x8180u16.to_be_bytes().as_slice(),
            "response, no error"
        );
        assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), 1, "one question");
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 2, "two answers");
        let question_len = 12 + "node.example.com".len() + 2 + 4;
        let mut offset = question_len;
        for expected in [Ipv4Addr::new(203, 0, 113, 7), Ipv4Addr::new(203, 0, 113, 8)] {
            assert_eq!(
                &bytes[offset..offset + 2],
                [0xC0, 0x0C].as_slice(),
                "name pointer"
            );
            assert_eq!(
                u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]),
                1,
                "type A"
            );
            assert_eq!(
                u16::from_be_bytes([bytes[offset + 4], bytes[offset + 5]]),
                1,
                "class IN"
            );
            assert_eq!(
                &bytes[offset + 6..offset + 10],
                60u32.to_be_bytes().as_slice(),
                "ttl"
            );
            assert_eq!(
                u16::from_be_bytes([bytes[offset + 10], bytes[offset + 11]]),
                4,
                "rdlength"
            );
            assert_eq!(
                &bytes[offset + 12..offset + 16],
                expected.octets().as_slice()
            );
            offset += 16;
        }
        assert_eq!(offset, bytes.len(), "no trailing bytes");
    }

    /// NXDOMAIN for these used to make clients abandon hosts that resolve
    /// perfectly well, because `HTTPS` and `SVCB` probes are routine now.
    #[test]
    fn records_the_pool_cannot_fake_are_forwarded() {
        let (handler, pool) = handler(fake_ip_mode());
        for qtype in [28u16, 2, 6, 15, 33, 65] {
            let verdict = handler
                .handle_query(&query_bytes(0x0004, "node.example.com", qtype))
                .expect("query");
            if qtype == 28 {
                assert!(matches!(verdict, DnsVerdict::Answer { .. }));
            } else {
                assert!(
                    matches!(verdict, DnsVerdict::Forward),
                    "qtype {qtype} must be forwarded, not answered"
                );
            }
        }
        assert_eq!(pool.size(), 0, "forwarding must not allocate");
    }

    #[test]
    fn servfail_says_the_lookup_failed_not_that_the_name_is_missing() {
        let (handler, _pool) = handler(fake_ip_mode());
        let query = handler
            .parse_query(&query_bytes(0x0009, "node.example.com", 1))
            .expect("parse");
        let bytes = handler.build_servfail(&query);
        assert_eq!(
            u16::from_be_bytes([bytes[2], bytes[3]]) & 0x000F,
            2,
            "rcode must be SERVFAIL"
        );
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 0, "no answers");
    }

    #[test]
    fn pool_range_from_cidr_drives_allocation_and_membership() {
        let settings =
            ClientDnsSettings::from_parts(ClientDnsMode::FakeIp, "198.19.0.0/24", &[], &[])
                .expect("settings");
        let (handler, pool) = handler(settings);

        handler
            .handle_query(&query_bytes(0x0005, "node.example.com", 1))
            .expect("query");

        assert!(
            pool.is_fake_ip(Ipv4Addr::new(198, 19, 0, 3)),
            "allocation must land inside the configured range"
        );
        assert!(
            !pool.is_fake_ip(Ipv4Addr::new(198, 18, 0, 3)),
            "the default range must no longer be in use"
        );
    }

    #[test]
    fn pool_range_rejects_what_it_cannot_serve() {
        let make =
            |range: &str| ClientDnsSettings::from_parts(ClientDnsMode::FakeIp, range, &[], &[]);

        assert!(make("198.18.0.0/16").is_ok());
        assert!(make("198.18.0.0/24").is_ok());

        let from_host_address = make("198.18.0.1/16").expect("a host address in a CIDR");
        assert_eq!(
            from_host_address.fake_ip.range_start,
            Ipv4Addr::new(198, 18, 0, 0)
        );
        assert_eq!(from_host_address.fake_ip.pool_size, 65536);

        let error = make("nonsense").expect_err("garbage must be rejected");
        assert!(
            error.contains("nonsense"),
            "message must name the value: {error}"
        );

        let error = make("fd00::/64").expect_err("IPv6 must be rejected");
        assert!(error.contains("IPv6"), "message must say why: {error}");

        let error = make("198.18.0.0/30").expect_err("too small must be rejected");
        assert!(
            error.contains("/30"),
            "message must name the prefix: {error}"
        );
    }

    /// The `ipv6: false` default: an `AAAA` query is answered with an empty
    /// result rather than a v6 address, in every mode.
    #[test]
    fn aaaa_is_empty_while_ipv6_is_disabled() {
        let (handler, pool) = handler(fake_ip_mode());
        let DnsVerdict::Answer {
            bytes,
            faked_domain,
        } = handler
            .handle_query(&query_bytes(0x0010, "node.example.com", 28))
            .expect("query")
        else {
            panic!("an AAAA query must be answered with an empty result");
        };

        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 0, "no answers");
        assert_eq!(
            u16::from_be_bytes([bytes[2], bytes[3]]) & 0x000F,
            0,
            "NOERROR, not NXDOMAIN: the name exists, it just has no v6 answer"
        );
        assert!(faked_domain.is_none());
        assert_eq!(pool.size(), 0, "an AAAA query must not allocate");
    }

    /// With `ipv6: true` a real-mode `AAAA` query is resolved instead of being
    /// blanked — but the pool is still IPv4, so fake-ip mode stays empty.
    #[test]
    fn ipv6_enabled_changes_what_aaaa_does() {
        let (handler, _pool) = handler(fake_ip_mode().with_ipv6(true));
        let DnsVerdict::Answer { bytes, .. } = handler
            .handle_query(&query_bytes(0x0011, "node.example.com", 28))
            .expect("query")
        else {
            panic!("AAAA must be answered");
        };
        assert_eq!(
            u16::from_be_bytes([bytes[6], bytes[7]]),
            0,
            "the fake-IP pool holds no IPv6 addresses"
        );
    }

    #[test]
    fn fake_ip_ttl_is_honoured() {
        let settings = fake_ip_mode().with_fake_ip_ttl(3);
        assert_eq!(settings.fake_ip_ttl, 3);
        assert_eq!(settings.clone().with_fake_ip_ttl(0).fake_ip_ttl, 3);

        let (handler, _pool) = handler(settings);
        let DnsVerdict::Answer { bytes, .. } = handler
            .handle_query(&query_bytes(0x0012, "node.example.com", 1))
            .expect("query")
        else {
            panic!("an A query must be answered");
        };

        let answer_at = bytes
            .windows(2)
            .position(|window| window == [0xC0, 0x0C])
            .expect("answer name pointer");
        let ttl = u32::from_be_bytes([
            bytes[answer_at + 6],
            bytes[answer_at + 7],
            bytes[answer_at + 8],
            bytes[answer_at + 9],
        ]);
        assert_eq!(ttl, 3, "the configured fake-IP TTL must reach the client");
    }

    /// Reverse lookups are never faked: an address that reverses to nothing is
    /// worse than an empty answer.
    #[test]
    fn reverse_lookups_are_never_faked() {
        let policy = AnswerPolicy::from_settings(&fake_ip_mode());
        for name in ["1.0.18.198.in-addr.arpa", "a.b.ip6.arpa"] {
            assert!(policy.is_filtered(name), "{name} must resolve for real");
        }
    }

    #[test]
    fn profile_mode_spellings_all_land_somewhere_deliberate() {
        assert_eq!(
            ClientDnsMode::from_profile("fake-ip"),
            ClientDnsMode::FakeIp
        );
        assert_eq!(ClientDnsMode::from_profile("fakeip"), ClientDnsMode::FakeIp);
        assert_eq!(
            ClientDnsMode::from_profile("FAKE_IP"),
            ClientDnsMode::FakeIp
        );
        assert_eq!(ClientDnsMode::from_profile("normal"), ClientDnsMode::Normal);
        assert_eq!(
            ClientDnsMode::from_profile("redir-host"),
            ClientDnsMode::Normal
        );
        // Unknown input resolves for real, which cannot silently lose the domain
        // a connection was made to.
        assert_eq!(ClientDnsMode::from_profile(""), ClientDnsMode::Normal);
        assert_eq!(ClientDnsMode::from_profile("typo"), ClientDnsMode::Normal);
    }

    // -- the system-resolver fallback ---------------------------------------

    fn v4(text: &str) -> IpAddr {
        text.parse().expect("ipv4 literal")
    }

    /// The engine answer wins when it has one; the system resolver is not
    /// asked at all.
    #[test]
    fn a_real_engine_answer_never_reaches_the_system_resolver() {
        let mut asked = 0;
        let answer = with_system_fallback(
            "node.example.com",
            Some(Ok(vec![v4("203.0.113.7")])),
            || {
                asked += 1;
                Ok(vec![v4("198.51.100.1")])
            },
        )
        .expect("engine answer");
        assert_eq!(answer, vec![v4("203.0.113.7")]);
        assert_eq!(asked, 0, "the system resolver must stay out of the way");
    }

    /// The bug this fixes: "engine DNS found no address" used to be the end of
    /// the story for a client query, even though the outbound path retries the
    /// system resolver for exactly the same error.
    #[test]
    fn an_engine_miss_falls_back_to_the_system_resolver() {
        let engine_error = std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "engine DNS found no address for 'node.example.com'",
        );
        for engine in [
            Some(Err(engine_error)),
            None, // no engine resolver configured at all
        ] {
            let answer =
                with_system_fallback("node.example.com", engine, || Ok(vec![v4("198.51.100.1")]))
                    .expect("the system resolver answers");
            assert_eq!(answer, vec![v4("198.51.100.1")]);
        }
    }

    /// An empty engine answer should not happen — `resolve_ips` reports it as
    /// an error — but if it ever does, it is a miss, not an answer.
    #[test]
    fn an_empty_engine_answer_is_treated_like_a_miss() {
        let answer = with_system_fallback("node.example.com", Some(Ok(Vec::new())), || {
            Ok(vec![v4("198.51.100.2")])
        })
        .expect("fallback answer");
        assert_eq!(answer, vec![v4("198.51.100.2")]);
    }

    /// When both resolvers fail, the error names both reasons: the engine's
    /// first — it is the run's configured resolver — and the system's after it,
    /// so the log answers "why" instead of "could not resolve".
    #[test]
    fn both_resolvers_failing_names_both_reasons() {
        let engine = Some(Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "engine DNS found no address for 'node.example.com'",
        )));
        let error = with_system_fallback("node.example.com", engine, || {
            Err("no address of the requested family".to_string())
        })
        .expect_err("nothing resolved");
        assert!(
            error.contains("engine DNS found no address"),
            "the engine reason must survive: {error}"
        );
        assert!(
            error.contains("system resolver failed too"),
            "the system side must be named: {error}"
        );
    }
}
