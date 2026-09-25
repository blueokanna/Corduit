//! The engine's own resolver: which servers answer the names the engine dials.
//!
//! Subscription profiles routinely route their **own node domains** through a
//! private resolver (a `nameserver-policy` entry, e.g.
//! `+.v51124-6.qpon: tcp://<host>:8080`). The public DNS either has no record
//! for those names or hands back a decoy address — a system-resolver lookup
//! then fails instantly (NXDOMAIN) or dials the wrong host, which surfaces as
//! "every VMess connection dies silently in a quarter second". A profile that
//! carries the policy expects it to be honoured; the engine must as well.
//!
//! # What this module owns, and what RecurseX owns
//!
//! RecurseX owns everything that is DNS: the wire codec, name compression, the
//! semantic cache, the transports (UDP/TCP/DoT/DoH/DoH3/DoQ), request
//! coalescing, retransmission accounting and upstream selection. This module
//! owns exactly three things it cannot:
//!
//! 1. **The profile's shape.** A profile names its servers with a scheme —
//!    `https://dns.google/dns-query` — and RecurseX refuses a hostname
//!    upstream on principle, because a resolver that has to ask
//!    `/etc/resolv.conf` what its own servers are is not a resolver. Bridging
//!    that is [`crate::dns::upstream`] plus the bootstrap set built here.
//! 2. **Country-based answer filtering.** RecurseX ships no country database,
//!    so the `fallback-filter.geoip` signal has no expression inside it. Rather
//!    than let a configured security measure quietly do nothing, the decision
//!    stays here — see `SuspectPolicy` below — and the fallback servers live in
//!    their own resolver so the decision has somewhere to send the query.
//! 3. **The dial path's error type.** Callers here want an `io::Error` so they
//!    can fall back to the system resolver.
//!
//! # Why the resolver is built lazily
//!
//! A profile that names a DoH server by hostname cannot be turned into a
//! RecurseX configuration without a lookup, and the engine is routinely
//! configured before the network is up. So configuration only *validates* and
//! stores a plan; the resolver, its sockets and its maintenance thread appear
//! on the first lookup, and a failed attempt is retried on a slow timer instead
//! of being re-attempted once per dial.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use recurse_x::cache::CacheConfig;
use recurse_x::cidr::IpCidr;
use recurse_x::forward::Forwarder;
use recurse_x::hosts::HostsTable;
use recurse_x::resolver::{DnsPolicy, EngineConfig, ResolverConfig, UpstreamGroups};
use recurse_x::routing::{FallbackFilter, GroupId, NameserverPolicy};
use recurse_x::{ErrorKind, Name, Resolver, RrType};
use tracing::{debug, info, warn};

use crate::dns::bogon;
use crate::dns::pattern::{normalize_suffix, suffix_matches};
use crate::dns::upstream::Upstream;

/// Timeout for one exchange with one server.
///
/// RecurseX's own default, restated here because it is part of the contract
/// this module documents rather than something a caller may tune.
const ATTEMPT_TIMEOUT_MS: u64 = 1_500;

/// Wall-clock budget for one engine lookup, covering every attempt it spawns.
///
/// RecurseX defaults to 20 s, which is the right number for a resolver serving
/// clients and the wrong one for a dial that is already holding a connection
/// attempt open. The previous implementation bounded a query at 5 s; that is
/// the bound kept here.
const QUERY_BUDGET_MS: u64 = 5_000;

/// Budget for resolving an upstream's own hostname.
///
/// Shorter than [`QUERY_BUDGET_MS`] on purpose: this runs while the dial that
/// needed it is waiting, and a bootstrap that cannot answer in three seconds
/// will not answer usefully at all.
const BOOTSTRAP_BUDGET_MS: u64 = 3_000;

/// How long to wait after a failed build before trying again.
///
/// Without it, a profile whose upstream is a hostname would re-run a doomed
/// lookup on every single dial — the exact shaping that turns a broken
/// bootstrap into a DNS flood at the moment the network is least able to
/// absorb one.
const BUILD_RETRY: Duration = Duration::from_secs(30);

/// A country-code matcher, boxed so a resolver can live in a process static.
pub type CountryLookup = Arc<dyn Fn(&str, IpAddr) -> bool + Send + Sync>;

/// What makes a primary answer not worth using.
///
/// An answer can be wrong in ways the client has no way to notice, so the only
/// defence is to recognise the shape of a bad answer and ask someone else. All
/// four signals are cheap; none of them requires the other.
#[derive(Debug, Default, Clone)]
struct SuspectPolicy {
    /// Any private, loopback, link-local, CGNAT or otherwise bogus address
    /// makes the whole answer suspect.
    ///
    /// This is the signal that catches poisoning with no configuration at all:
    /// a poisoned answer is almost never a routable public address, because
    /// routing it would reach the real server and defeat the point.
    bogus: bool,
    /// Explicit networks that make an answer suspect.
    networks: Vec<IpCidr>,
    /// Suffixes that always go to the fallback set, normalized.
    domains: Vec<String>,
    /// Country codes that make an answer suspect.
    countries: Vec<String>,
}

impl SuspectPolicy {
    fn is_empty(&self) -> bool {
        !self.bogus
            && self.networks.is_empty()
            && self.domains.is_empty()
            && self.countries.is_empty()
    }

    /// Does this answer need re-resolving through the fallback set?
    fn suspect(&self, host: &str, ips: &[IpAddr], country: Option<&CountryLookup>) -> bool {
        if self
            .domains
            .iter()
            .any(|suffix| suffix_matches(host, suffix))
        {
            return true;
        }
        if self.bogus && bogon::contains_bogon(ips) {
            return true;
        }
        if self
            .networks
            .iter()
            .any(|net| ips.iter().any(|ip| net.contains(*ip)))
        {
            return true;
        }
        if let Some(matches) = country {
            if self
                .countries
                .iter()
                .any(|code| ips.iter().any(|ip| matches(code, *ip)))
            {
                return true;
            }
        }
        false
    }
}

/// Everything the resolver needs from a profile's DNS section.
#[derive(Debug, Clone)]
pub struct EngineDnsSettings {
    /// The profile's `nameservers`.
    pub nameservers: Vec<String>,
    /// The profile's `fallback`.
    pub fallback: Vec<String>,
    /// The profile's `default-nameserver`: resolvers used for the hostname of an
    /// upstream that is itself named by one.
    pub default_nameserver: Vec<String>,
    /// `nameserver-policy`.
    pub policy: HashMap<String, Vec<String>>,
    /// `hosts`, already parsed.
    pub hosts: HashMap<String, IpAddr>,
    /// `cache-size`.
    pub cache_size: usize,
    /// `fallback-filter.geoip`.
    pub geoip: bool,
    /// `fallback-filter.geoip-code`.
    pub geoip_code: String,
    /// `fallback-filter.ipcidr`.
    pub fallback_ipcidr: Vec<String>,
    /// `fallback-filter.domain`.
    pub fallback_domain: Vec<String>,
}

impl Default for EngineDnsSettings {
    fn default() -> Self {
        Self {
            nameservers: Vec::new(),
            fallback: Vec::new(),
            default_nameserver: Vec::new(),
            policy: HashMap::new(),
            hosts: HashMap::new(),
            cache_size: 4096,
            geoip: false,
            geoip_code: "CN".to_string(),
            fallback_ipcidr: Vec::new(),
            fallback_domain: Vec::new(),
        }
    }
}

/// The validated, network-free half of the resolver.
///
/// Split from [`EngineResolver`] so that "the profile makes sense" and "the
/// network is reachable" are different facts, reported at different times.
struct Plan {
    /// `nameservers`, in order.
    default: Vec<Upstream>,
    /// `fallback`, in order.
    fallback: Vec<Upstream>,
    /// `nameserver-policy`, each entry with the servers it selects.
    policy: Vec<(String, Vec<Upstream>)>,
    /// `default-nameserver`, restricted to IP literals.
    bootstrap: Vec<Upstream>,
    /// Static answers, in RecurseX's own table so the resolver serves them
    /// before the cache and before any server.
    hosts: HostsTable,
    /// `cache-size`.
    cache_size: usize,
    /// When a primary answer is not worth using.
    suspect: SuspectPolicy,
    /// Country matcher, `None` when unavailable or not configured.
    country: Option<CountryLookup>,
}

/// Where an upstream's own hostname is resolved.
enum Bootstrap {
    /// A RecurseX resolver over the profile's `default-nameserver` set.
    Resolver(Arc<Resolver>),
    /// The operating system's resolver.
    ///
    /// The last resort, and deliberately not the first: it makes the engine
    /// depend on `/etc/resolv.conf`, which is the dependency
    /// `default-nameserver` exists to remove. It is reachable only when the
    /// profile names no usable bootstrap server — and in a proxy engine that is
    /// defensible in a way it would not be for a standalone resolver, because
    /// the machine running the engine is, by definition, already online.
    System,
}

impl Bootstrap {
    /// One address for `host`, preferring IPv4.
    ///
    /// One is enough: a RecurseX forwarder is a single endpoint, and dialing
    /// order in the engine prefers IPv4 anyway.
    fn resolve_one(&self, host: &str) -> Option<IpAddr> {
        let mut candidates = match self {
            Bootstrap::Resolver(resolver) => {
                let name = Name::from_ascii(host).ok()?;
                let mut found = Vec::new();
                for rr_type in [RrType::A, RrType::AAAA] {
                    if let Ok(resolution) = resolver.resolve(&name, rr_type) {
                        found.extend(addresses_of(&resolution));
                    }
                }
                found
            }
            Bootstrap::System => (host, 0u16)
                .to_socket_addrs()
                .ok()
                .map(|addrs| addrs.map(|addr| addr.ip()).collect())
                .unwrap_or_default(),
        };
        candidates.sort_by_key(|ip| matches!(ip, IpAddr::V6(_)) as u8);
        candidates.into_iter().next()
    }
}

/// The live half: what a successful build produced.
struct Live {
    /// The servers that answer, and the policy that routes between them.
    primary: Option<Arc<Resolver>>,
    /// The fallback servers, in their own resolver.
    ///
    /// Separate because recurrence cannot be expressed inside one: RecurseX
    /// routes by *name*, and the decision to use the fallback set is made after
    /// the primary answer has been seen. One resolver could not be asked "now
    /// do that again, through the other group".
    fallback: Option<Arc<Resolver>>,
    /// Earliest time a retry is worth attempting.
    next_attempt: Instant,
}

impl Default for Live {
    fn default() -> Self {
        Self {
            primary: None,
            fallback: None,
            next_attempt: Instant::now(),
        }
    }
}

/// A resolver over the profile's DNS settings, used for the engine's own
/// outbound server names.
pub struct EngineResolver {
    plan: Arc<Plan>,
    live: RwLock<Live>,
}

impl EngineResolver {
    /// Build a resolver from just `nameservers` and `nameserver-policy`.
    ///
    /// The degenerate form: no fallback, no hosts, default cache. Used by
    /// tests and by callers that have no full DNS section to hand.
    pub fn new(nameservers: &[String], policy: &HashMap<String, Vec<String>>) -> Option<Self> {
        Self::from_settings(EngineDnsSettings {
            nameservers: nameservers.to_vec(),
            policy: policy.clone(),
            ..EngineDnsSettings::default()
        })
    }

    /// Validate a DNS section into a resolver plan.
    ///
    /// `None` when no list yields a usable server at all — the caller then
    /// leaves the system resolver in place. No I/O happens here; see the module
    /// documentation for why.
    pub fn from_settings(settings: EngineDnsSettings) -> Option<Self> {
        let default = parse_upstreams(&settings.nameservers, "nameservers");
        let fallback = parse_upstreams(&settings.fallback, "fallback");

        let mut policy: Vec<(String, Vec<Upstream>)> = Vec::with_capacity(settings.policy.len());
        for (suffix, servers) in &settings.policy {
            let parsed = parse_upstreams(servers, "nameserver-policy");
            if parsed.is_empty() {
                warn!("DNS policy for '{suffix}' has no usable servers; entry ignored");
                continue;
            }
            policy.push((suffix.clone(), parsed));
        }

        if default.is_empty() && policy.is_empty() {
            return None;
        }
        let bootstrap = bootstrap_candidates(&settings.default_nameserver, &default, &fallback);
        let explicit_fallback = !fallback.is_empty();

        let mut networks = Vec::with_capacity(settings.fallback_ipcidr.len());
        for network in &settings.fallback_ipcidr {
            match IpCidr::parse(network.trim()) {
                Some(parsed) => networks.push(parsed),
                None => {
                    warn!("dns.fallback-filter.ipcidr '{network}' is not a CIDR; entry ignored")
                }
            }
        }

        let countries: Vec<String> = if settings.geoip {
            vec![settings.geoip_code.trim().to_ascii_uppercase()]
        } else {
            Vec::new()
        };
        let country = country_lookup(&countries);
        let suspect = SuspectPolicy {
            bogus: explicit_fallback,
            networks,
            domains: settings
                .fallback_domain
                .iter()
                .map(|suffix| normalize_suffix(suffix))
                .collect(),
            countries,
        };
        if explicit_fallback && suspect.is_empty() {
            debug!("dns.fallback is set but nothing can mark an answer suspect");
        }

        Some(Self {
            plan: Arc::new(Plan {
                default,
                fallback,
                policy,
                bootstrap,
                hosts: hosts_table(&settings.hosts),
                cache_size: settings.cache_size.max(1),
                suspect,
                country,
            }),
            live: RwLock::new(Live::default()),
        })
    }

    /// Whether an answer from the primary servers would be re-resolved.
    pub fn has_fallback_policy(&self) -> bool {
        !self.plan.fallback.is_empty() && !self.plan.suspect.is_empty()
    }

    /// The live resolver pair, building it if this is the first call and the
    /// retry window has elapsed.
    fn live(&self) -> Option<(Arc<Resolver>, Option<Arc<Resolver>>)> {
        if let Some(pair) = current(&self.live.read()) {
            return Some(pair);
        }

        let mut live = self.live.write();
        if let Some(pair) = current(&live) {
            return Some(pair);
        }
        if Instant::now() < live.next_attempt {
            return None;
        }

        let bootstrap = Bootstrap::build(&self.plan.bootstrap);
        match self.plan.build_engine(Some(&bootstrap)) {
            Some(built) => {
                info!(
                    "Engine DNS resolver online: {} default, {} policy, {} fallback servers",
                    built.default_count, built.policy_count, built.fallback_count
                );
                live.primary = Some(built.primary);
                live.fallback = built.fallback;
                current(&live)
            }
            None => {
                warn!(
                    "Engine DNS resolver could not be built (no upstream was reachable or \
                     resolvable); outbound names use the system resolver meanwhile"
                );
                live.next_attempt = Instant::now() + BUILD_RETRY;
                None
            }
        }
    }

    /// Resolve `host` into addresses of a single family.
    ///
    /// Used by the netstack's client-facing responder, which has to answer an
    /// `A` query with `A` records: a mixed set would put `AAAA` addresses in an
    /// `A` answer, which is malformed and gets the whole response dropped by
    /// strict clients.
    pub fn resolve_ips(&self, host: &str, want_v6: bool) -> io::Result<Vec<IpAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return if matches!(ip, IpAddr::V6(_)) == want_v6 {
                Ok(vec![ip])
            } else {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("'{host}' is not an address of the requested family"),
                ))
            };
        }

        let (primary, fallback) = self.live().ok_or_else(|| self.no_resolver(host))?;
        let name = parse_name(host)?;
        let rr_type = if want_v6 { RrType::AAAA } else { RrType::A };
        let mut ips = query(&primary, &name, rr_type, host)?;
        let answer_looks_suspect = !ips.is_empty()
            && self
                .plan
                .suspect
                .suspect(host, &ips, self.plan.country.as_ref());
        if answer_looks_suspect {
            if let Some(fallback) = fallback {
                match query(&fallback, &name, rr_type, host) {
                    Ok(from_fallback) if !from_fallback.is_empty() => {
                        debug!("engine DNS: answer for '{host}' looked suspect; using the fallback set");
                        ips = from_fallback;
                    }
                    Ok(_) => warn!(
                        "engine DNS: answer for '{host}' looked suspect but the fallback set \
                         returned nothing; using the suspect answer"
                    ),
                    Err(error) => warn!(
                        "engine DNS: answer for '{host}' looked suspect and the fallback set \
                         failed ({error}); using the suspect answer"
                    ),
                }
            }
        }

        if ips.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("engine DNS found no address for '{host}'"),
            ));
        }
        // Dialing order matters for flaky IPv6 paths.
        ips.sort_by_key(|ip| matches!(ip, IpAddr::V6(_)) as u8);
        Ok(ips)
    }

    /// Resolve `host` to socket addresses.
    pub fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }

        let ips = match self.resolve_ips(host, false) {
            Ok(ips) => ips,
            Err(no_v4) => self.resolve_ips(host, true).map_err(|_| no_v4)?,
        };
        Ok(ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }

    /// The resolver a client-facing listener should serve from.
    ///
    /// `None` under the same conditions that leave the engine on the system
    /// resolver: the profile names no usable server, or none of them could be
    /// turned into an address.
    pub fn client_resolver(&self) -> Option<Arc<Resolver>> {
        let bootstrap = Bootstrap::build(&self.plan.bootstrap);
        self.plan.build_client(Some(&bootstrap))
    }

    fn no_resolver(&self, host: &str) -> io::Error {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("no engine DNS server could be reached to resolve '{host}'"),
        )
    }
}

/// A built resolver pair, plus the counts the log line needs.
struct Built {
    primary: Arc<Resolver>,
    fallback: Option<Arc<Resolver>>,
    default_count: usize,
    policy_count: usize,
    fallback_count: usize,
}

impl Plan {
    /// Turn the plan into the engine's resolvers, resolving upstream hostnames.
    ///
    /// `None` when nothing usable came out — every upstream was either
    /// unreachable in name or unusable as a string.
    fn build_engine(&self, bootstrap: Option<&Bootstrap>) -> Option<Built> {
        let groups = self.render_groups(bootstrap)?;
        let policy_count = groups.extra.len();
        let default_count = groups.default.len();
        if default_count == 0 && policy_count == 0 {
            return None;
        }

        let config = self.resolver_config(Role::Engine, groups)?;
        let primary = Arc::new(Resolver::new(config));

        let fallback_forwarders =
            parse_forwarders(&render_set(&self.fallback, bootstrap, "fallback"));
        let fallback_count = fallback_forwarders.len();
        let fallback = self.build_fallback(fallback_forwarders);
        let _ = primary.spawn_maintenance();
        if let Some(resolver) = &fallback {
            let _ = resolver.spawn_maintenance();
        }

        Some(Built {
            primary,
            fallback,
            default_count,
            policy_count,
            fallback_count,
        })
    }

    /// The resolver a client-facing listener answers from.
    ///
    /// Separate from the engine's because a listener and a dial ask different
    /// questions of the same configuration; [`Role`] is where that is written
    /// down.
    fn build_client(&self, bootstrap: Option<&Bootstrap>) -> Option<Arc<Resolver>> {
        let groups = self.render_groups(bootstrap)?;
        if groups.default.is_empty() && groups.extra.is_empty() {
            return None;
        }

        let config = self.resolver_config(Role::Client, groups)?;
        let resolver = Arc::new(Resolver::new(config));
        let _ = resolver.spawn_maintenance();
        Some(resolver)
    }

    /// Render the upstream groups, resolving every hostname-named server.
    fn render_groups(&self, bootstrap: Option<&Bootstrap>) -> Option<Groups> {
        let default = parse_forwarders(&render_set(&self.default, bootstrap, "nameservers"));
        let fallback = parse_forwarders(&render_set(&self.fallback, bootstrap, "fallback"));

        let mut extra: Vec<Vec<Forwarder>> = Vec::with_capacity(self.policy.len());
        let mut surviving: Vec<String> = Vec::with_capacity(self.policy.len());
        for (suffix, upstreams) in &self.policy {
            let rendered = render_set(upstreams, bootstrap, "nameserver-policy");
            if rendered.is_empty() {
                warn!("dns.nameserver-policy for '{suffix}' left no usable server; entry ignored");
                continue;
            }
            surviving.push(suffix.clone());
            extra.push(parse_forwarders(&rendered));
        }

        Some(Groups {
            rules: policy_rules(&surviving),
            default,
            fallback,
            extra,
        })
    }

    /// Assemble a [`ResolverConfig`].
    ///
    /// **The one place that does**, so an engine resolver and a listener
    /// resolver cannot drift in anything they share — cache sizing, timeouts,
    /// hosts, policy routing, transports — while still differing in the one
    /// thing they must. The role alone decides that difference, so there is no
    /// second parameter that could disagree with it.
    fn resolver_config(&self, role: Role, groups: Groups) -> Option<ResolverConfig> {
        let (filter, fallback_group) = match role {
            Role::Engine => (FallbackFilter::new(&[], Some(&[]), false).ok()?, Vec::new()),
            Role::Client => (self.client_filter()?, groups.fallback.clone()),
        };

        Some(ResolverConfig {
            cache: self.cache_config(),
            dns: DnsPolicy {
                hosts: self.hosts.clone(),
                fake_ip: None,
                policy: NameserverPolicy::new(&groups.rules).ok()?,
                fallback: filter,
                upstreams: UpstreamGroups {
                    default: groups.default,
                    fallback: fallback_group,
                    extra: groups.extra,
                },
            },
            engine: EngineConfig {
                timeout_ms: ATTEMPT_TIMEOUT_MS,
                query_budget_ms: QUERY_BUDGET_MS,
                ..EngineConfig::default()
            },
            ..ResolverConfig::default()
        })
    }

    /// RecurseX's answer-quality filter, armed from the profile.
    ///
    /// It carries the three signals RecurseX can express: the name rules, the
    /// operator's `fallback-filter.ipcidr`, and — when an explicit `fallback`
    /// list armed the gate — the whole [`bogon`] table, which is the signal that
    /// needs no configuration at all.
    ///
    /// The country signal is absent because RecurseX ships no country database.
    /// That is the entire reason [`SuspectPolicy`] exists, and it protects the
    /// engine's own dials: a poisoned *node* address sends traffic to whoever
    /// poisoned it, while a listener's answer is a client's problem to route.
    fn client_filter(&self) -> Option<FallbackFilter> {
        let mut ipcidr: Vec<String> = self
            .suspect
            .networks
            .iter()
            .map(|network| network.to_string())
            .collect();
        if self.suspect.bogus {
            ipcidr.extend(bogon::all_ranges().map(str::to_string));
        }

        match FallbackFilter::new(&self.suspect.domains, Some(&ipcidr), false) {
            Ok(filter) => Some(filter),
            Err(error) => {
                warn!(
                    "dns.fallback-filter could not be given to the DNS listener ({error}); the \
                     listener answers without it"
                );
                None
            }
        }
    }

    fn build_fallback(&self, forwarders: Vec<Forwarder>) -> Option<Arc<Resolver>> {
        if forwarders.is_empty() {
            return None;
        }
        let config = ResolverConfig {
            cache: self.cache_config(),
            dns: DnsPolicy {
                upstreams: UpstreamGroups {
                    default: forwarders,
                    fallback: Vec::new(),
                    extra: Vec::new(),
                },
                ..DnsPolicy::default()
            },
            engine: EngineConfig {
                timeout_ms: ATTEMPT_TIMEOUT_MS,
                query_budget_ms: QUERY_BUDGET_MS,
                ..EngineConfig::default()
            },
            ..ResolverConfig::default()
        };
        Some(Arc::new(Resolver::new(config)))
    }

    /// How `cache-size` reaches RecurseX.
    ///
    /// It bounds the warm tier, which is the tier that holds the working set;
    /// the hot tier is a small index of the most-requested names and the cold
    /// tier a spill area, and both keep RecurseX's own proportions rather than
    /// growing with the operator's number.
    fn cache_config(&self) -> CacheConfig {
        CacheConfig {
            warm_capacity: self.cache_size,
            ..CacheConfig::default()
        }
    }
}

/// Which resolver is being built, which is what says who owns the
/// answer-quality decision and where the fallback servers belong.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Role {
    /// The engine's own outbound dials, which Corduit gates.
    Engine,
    /// A client-facing listener, which RecurseX serves and therefore gates.
    Client,
}

/// The upstream groups of one resolver, before they become a `ResolverConfig`.
struct Groups {
    /// `nameservers`.
    default: Vec<Forwarder>,
    /// `fallback`.
    fallback: Vec<Forwarder>,
    /// `nameserver-policy` groups, indexed from group id `2`.
    extra: Vec<Vec<Forwarder>>,
    /// The `(pattern, group id)` rules that select `extra`.
    rules: Vec<(String, GroupId)>,
}

/// Assign RecurseX group ids to the policy groups that survived rendering.
///
/// Ids `0` and `1` are reserved by RecurseX for the default and fallback
/// groups, so policy groups start at `2`, and the rule that names a group must
/// carry the same id as the group itself — which is why this is one function
/// and not two loops that have to agree.
fn policy_rules(suffixes: &[String]) -> Vec<(String, GroupId)> {
    suffixes
        .iter()
        .enumerate()
        .map(|(index, suffix)| (suffix.clone(), 2 + index))
        .collect()
}

impl Bootstrap {
    /// Where an upstream's own hostname gets resolved.
    ///
    /// There is always an answer — the system resolver is the last resort — so
    /// this cannot fail and callers never have to invent a fallback.
    fn build(upstreams: &[Upstream]) -> Self {
        let forwarders = parse_forwarders(&render_set(upstreams, None, "default-nameserver"));
        if forwarders.is_empty() {
            return Bootstrap::System;
        }
        let config = ResolverConfig {
            dns: DnsPolicy {
                upstreams: UpstreamGroups {
                    default: forwarders,
                    fallback: Vec::new(),
                    extra: Vec::new(),
                },
                ..DnsPolicy::default()
            },
            engine: EngineConfig {
                timeout_ms: ATTEMPT_TIMEOUT_MS,
                query_budget_ms: BOOTSTRAP_BUDGET_MS,
                ..EngineConfig::default()
            },
            ..ResolverConfig::default()
        };
        Bootstrap::Resolver(Arc::new(Resolver::new(config)))
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        if let Some(resolver) = self.primary.take() {
            resolver.shutdown();
        }
        if let Some(resolver) = self.fallback.take() {
            resolver.shutdown();
        }
    }
}

/// The live pair, when a build has succeeded.
fn current(live: &Live) -> Option<(Arc<Resolver>, Option<Arc<Resolver>>)> {
    live.primary
        .as_ref()
        .map(|primary| (Arc::clone(primary), live.fallback.clone()))
}

/// Parse a list of upstream strings, warning about each one that is dropped.
fn parse_upstreams(servers: &[String], setting: &str) -> Vec<Upstream> {
    let mut parsed = Vec::with_capacity(servers.len());
    for server in servers {
        match Upstream::parse(server) {
            Ok(upstream) => parsed.push(upstream),
            Err(error) => warn!("dns.{setting} entry '{server}' is not a usable DNS address: {error}; entry ignored"),
        }
    }
    parsed
}

/// Render each upstream into a string RecurseX accepts, resolving the ones
/// named by a hostname through `bootstrap`.
fn render_set(upstreams: &[Upstream], bootstrap: Option<&Bootstrap>, setting: &str) -> Vec<String> {
    let mut rendered = Vec::with_capacity(upstreams.len());
    for upstream in upstreams {
        if !upstream.needs_bootstrap() {
            rendered.push(upstream.render(None));
            continue;
        }
        match bootstrap.and_then(|bootstrap| bootstrap.resolve_one(upstream.host())) {
            Some(address) => rendered.push(upstream.render(Some(address))),
            None => warn!(
                "dns.{setting}: {upstream} is named by a hostname that could not be resolved, \
                 and a hostname inside `/etc/resolv.conf`-style resolution is not one this build \
                 will take; entry ignored"
            ),
        }
    }
    rendered
}

/// Parse rendered upstream strings into RecurseX forwarders.
///
/// A render that RecurseX rejects is a bug in this crate, not a configuration
/// error, so it is reported at `warn` with both spellings rather than dropped.
fn parse_forwarders(rendered: &[String]) -> Vec<recurse_x::forward::Forwarder> {
    let mut forwarders = Vec::with_capacity(rendered.len());
    for upstream in rendered {
        match recurse_x::config::parse_upstream(upstream) {
            Ok(forwarder) => forwarders.push(forwarder),
            Err(error) => {
                warn!("dns: internal upstream '{upstream}' was rejected by RecurseX: {error}")
            }
        }
    }
    forwarders
}

/// The servers used to resolve an upstream's own hostname, in order of intent.
///
/// 1. `default-nameserver`, because the operator named it for exactly this.
/// 2. The IP literals in `nameservers` and `fallback`. A profile that already
///    names a server by address does not need `/etc/resolv.conf` to find its own
///    servers, and without this a profile whose only upstream is
///    `https://dns.google/dns-query` would reach the system resolver even though
///    it named `8.8.8.8` two fields away.
/// 3. Nothing, and the caller then uses the system resolver — the documented
///    last resort.
///
/// An entry in `default-nameserver` that is *not* an IP literal is refused with
/// a warning rather than passed over silently, for a reason worth stating: a
/// bootstrap resolver named by a hostname could only itself be resolved by the
/// system resolver, which is the dependency
/// this list exists to remove. Accepting it would look like it worked while
/// changing nothing.
fn bootstrap_candidates(
    default_nameserver: &[String],
    default: &[Upstream],
    fallback: &[Upstream],
) -> Vec<Upstream> {
    let mut candidates: Vec<Upstream> = Vec::new();

    for entry in default_nameserver {
        match Upstream::parse(entry) {
            Ok(upstream) if upstream.is_literal() => push_unique(&mut candidates, upstream),
            Ok(upstream) => warn!(
                "dns.default-nameserver entry '{entry}' is named by the hostname '{}'; it can \
                 only be resolved by the system resolver, so it cannot bootstrap anything and is \
                 ignored",
                upstream.host()
            ),
            Err(error) => warn!(
                "dns.default-nameserver entry '{entry}' is not a usable DNS address: {error}; \
                 entry ignored"
            ),
        }
    }

    for upstream in default.iter().chain(fallback.iter()) {
        if upstream.is_literal() {
            push_unique(&mut candidates, upstream.clone());
        }
    }

    candidates
}

/// Append `upstream` unless an identical one is already present.
///
/// Two entries that render to the same string are the same server, and a
/// bootstrap list that asks one server twice pays for it twice.
fn push_unique(into: &mut Vec<Upstream>, upstream: Upstream) {
    if !into.contains(&upstream) {
        into.push(upstream);
    }
}

/// The `hosts` table, with a name-to-name alias reported rather than dropped.
fn hosts_table(hosts: &HashMap<String, IpAddr>) -> HostsTable {
    let mut table = HostsTable::new(recurse_x::hosts::DEFAULT_HOSTS_TTL);
    let mut entries: Vec<(&String, &IpAddr)> = hosts.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    for (host, address) in entries {
        if let Err(error) = table.insert_from_config(host, &[address.to_string()]) {
            warn!("dns.hosts entry '{host}' was rejected: {error}; entry ignored");
        }
    }
    table
}

/// Build the country matcher, if the filter needs one.
///
/// Loaded lazily so a profile that does not ask for country filtering never
/// pays for a database read. When no database is present the matcher stays
/// `None` and says so once — a filter that silently passed every answer would
/// be worse than no filter, because the operator would believe the signal was
/// working.
fn country_lookup(codes: &[String]) -> Option<CountryLookup> {
    if codes.is_empty() {
        return None;
    }
    let manager = Arc::new(crate::engine::geoip::GeoIpManager::from_embedded_country_database());
    if !manager.is_loaded() {
        warn!(
            "dns.fallback-filter.geoip is configured but no GeoIP database is available; country \
             filtering is inactive (bogon, ipcidr and domain filtering still apply)"
        );
        return None;
    }
    Some(Arc::new(move |code: &str, ip: IpAddr| {
        manager.matches_country(code, ip)
    }))
}

/// A name for the resolver, with the root label tolerated.
fn parse_name(host: &str) -> io::Result<Name> {
    Name::from_ascii(host.trim_end_matches('.')).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("'{host}' is not a DNS name: {error}"),
        )
    })
}

/// The addresses in a resolution, in the order the resolver produced them.
fn addresses_of(resolution: &recurse_x::Resolution) -> Vec<IpAddr> {
    resolution
        .answers
        .iter()
        .filter_map(|record| match record.rdata {
            recurse_x::RData::A(address) => Some(IpAddr::V4(address)),
            recurse_x::RData::Aaaa(address) => Some(IpAddr::V6(address)),
            _ => None,
        })
        .collect()
}

/// Resolve `name`, flattening the two negative answers the engine treats as
/// "no address" rather than as failures.
///
/// NODATA is a *successful* answer that carries no records, and NXDOMAIN is a
/// successful answer that says the name does not exist; neither says anything
/// about the primary servers being broken, so neither is reported as an error
/// against them.
fn query(resolver: &Resolver, name: &Name, rr_type: RrType, host: &str) -> io::Result<Vec<IpAddr>> {
    match resolver.resolve(name, rr_type) {
        Ok(resolution) => Ok(addresses_of(&resolution)),
        Err(error) => match error.kind() {
            ErrorKind::NoData | ErrorKind::NxDomain => {
                debug!("engine DNS: '{host}' has no {} record", rr_type.as_str());
                Ok(Vec::new())
            }
            _ => Err(io::Error::other(error.to_string())),
        },
    }
}

// ---------------------------------------------------------------------------
// Process-wide installation
// ---------------------------------------------------------------------------

/// Process-wide resolver, configured from the engine config.
static ENGINE_RESOLVER: RwLock<Option<Arc<EngineResolver>>> = RwLock::new(None);

/// Install (or clear) the engine resolver from the profile's DNS settings.
///
/// Called on every config conversion, so both initialize and reload paths stay
/// in sync. Replacing the resolver shuts the previous one down: its maintenance
/// thread stops and its cache, estimators and alias graph are released, so a
/// reload does not leak a resolver per reload.
pub fn configure(settings: EngineDnsSettings) {
    let summary = format!(
        "{} default servers, {} policy entries, {} fallback servers, {} host entries",
        settings.nameservers.len(),
        settings.policy.len(),
        settings.fallback.len(),
        settings.hosts.len()
    );
    match EngineResolver::from_settings(settings) {
        Some(resolver) => {
            info!("Engine DNS resolver configured: {summary}");
            *ENGINE_RESOLVER.write() = Some(Arc::new(resolver));
        }
        None => {
            debug!(
                "No usable engine DNS server configured ({summary}); outbound names use the system resolver"
            );
            *ENGINE_RESOLVER.write() = None;
        }
    }
}

/// The live engine resolver, for callers that need to serve queries from it.
///
/// Building it is deferred to the first lookup, so this may return `None` even
/// with a valid configuration: that means "not yet online", not "not
/// configured". [`resolve`] and [`resolve_ips`] tell the two apart by returning
/// `None` only in the second case.
pub fn resolver() -> Option<Arc<EngineResolver>> {
    ENGINE_RESOLVER.read().clone()
}

/// Build the resolver a client-facing DNS listener should serve from.
///
/// Deliberately not the same object as [`resolver`]: the engine's resolver
/// answers dials and owns the country-aware gate, while a listener answers
/// clients through RecurseX's own server and filter. The two share the profile,
/// the upstreams and the cache sizing — `Plan::resolver_config` is what keeps
/// them from drifting — and differ only where they must.
///
/// `Err` carries the reason for the caller to log, because a listener that
/// cannot start is a warning rather than a reason to refuse to run a proxy.
pub fn client_resolver(settings: EngineDnsSettings) -> Result<Arc<Resolver>, String> {
    let resolver = EngineResolver::from_settings(settings)
        .ok_or_else(|| "no usable DNS server is configured".to_string())?;
    resolver
        .client_resolver()
        .ok_or_else(|| "no DNS server could be reached or resolved".to_string())
}

/// Resolve `host` into addresses of one family through the engine's DNS.
///
/// `None` means the engine has no DNS configuration, so the caller can fall
/// back to the system resolver.
pub fn resolve_ips(host: &str, want_v6: bool) -> Option<io::Result<Vec<IpAddr>>> {
    let resolver = resolver()?;
    Some(resolver.resolve_ips(host, want_v6))
}

/// Resolve `host` through the engine's configured DNS.
///
/// `None` means the engine has no DNS configuration — the caller falls back to
/// the system resolver, which is also the fallback when the engine lookup
/// fails.
pub fn resolve(host: &str, port: u16) -> Option<io::Result<Vec<SocketAddr>>> {
    let resolver = resolver()?;
    Some(resolver.resolve(host, port))
}

/// Fixtures shared by this module's tests and by [`crate::dns::server`]'s.
///
/// One implementation: a second fake DNS server would be a second thing to keep
/// right about a protocol this crate does not own.
#[cfg(test)]
pub(crate) mod testing {
    use recurse_x::{Message, Name, RData, Record, RrClass, RrType};
    use std::net::{Ipv4Addr, UdpSocket};
    use std::time::Duration;

    /// A loopback DNS server that answers `A` queries from `lookup`.
    ///
    /// Returns its port and its thread. The thread stops when the socket reports
    /// a timeout, so a test that finishes early simply detaches it; nothing here
    /// reaches the network beyond `127.0.0.1`.
    pub(crate) fn spawn_udp_server(
        lookup: impl Fn(&Name) -> Option<Ipv4Addr> + Send + 'static,
    ) -> (u16, std::thread::JoinHandle<()>) {
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind a loopback UDP socket");
        server
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("a read timeout, so the thread cannot outlive the test forever");
        let port = server.local_addr().expect("bound address").port();

        let handle = std::thread::spawn(move || {
            let mut buf = vec![0u8; 4096];
            while let Ok((len, peer)) = server.recv_from(&mut buf) {
                let Ok(query) = Message::parse(&buf[..len]) else {
                    continue;
                };
                let Some(question) = query.question() else {
                    continue;
                };

                let mut response = Message::new(query.id);
                response.flags.qr = true;
                response.flags.opcode = query.flags.opcode;
                response.flags.rd = query.flags.rd;
                response.flags.ra = true;
                response.questions = query.questions.clone();

                if question.qclass == RrClass::IN && question.qtype == RrType::A {
                    if let Some(address) = lookup(&question.qname) {
                        response.answers.push(Record {
                            name: question.qname.clone(),
                            rr_type: RrType::A,
                            class: RrClass::IN,
                            ttl: 60,
                            rdata: RData::A(address),
                        });
                    }
                }

                if let Ok(bytes) = response.to_bytes() {
                    let _ = server.send_to(&bytes, peer);
                }
            }
        });

        (port, handle)
    }
}

#[cfg(test)]
mod tests {
    use super::testing::spawn_udp_server;
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(address: &str) -> IpAddr {
        address.parse().expect("ipv4 literal")
    }

    // -- the anti-poisoning gate -------------------------------------------

    /// A poisoned answer is almost never a routable address, because routing it
    /// would reach the real server and defeat the point. That is why the bogus
    /// signal needs no configuration once a fallback list exists.
    #[test]
    fn bogus_addresses_are_suspect_and_public_ones_are_not() {
        let policy = SuspectPolicy {
            bogus: true,
            ..SuspectPolicy::default()
        };
        let host = "node.example.com";

        for bogus in [
            "10.0.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "192.168.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "fd00::1",
            "2001:db8::1",
        ] {
            assert!(
                policy.suspect(host, &[v4(bogus)], None),
                "{bogus} should be suspect"
            );
        }

        assert!(!policy.suspect(host, &[v4("93.184.216.34")], None));
        assert!(!policy.suspect(host, &[v4("1.1.1.1")], None));
        // One bad address is enough, even beside a good one.
        assert!(policy.suspect(host, &[v4("93.184.216.34"), v4("10.0.0.1")], None));
    }

    #[test]
    fn ipcidr_and_domain_signals_match_on_boundaries() {
        let policy = SuspectPolicy {
            networks: vec![IpCidr::parse("203.0.113.0/24").expect("cidr")],
            domains: vec!["blocked.example".to_string()],
            ..SuspectPolicy::default()
        };
        let public = v4("1.1.1.1");

        assert!(policy.suspect("blocked.example", &[public], None));
        assert!(policy.suspect("a.blocked.example", &[public], None));
        // Label boundary: a longer name that merely ends in the same letters is
        // a different name.
        assert!(!policy.suspect("notblocked.example", &[public], None));

        assert!(policy.suspect("x.example", &[v4("203.0.113.7")], None));
        assert!(!policy.suspect("x.example", &[v4("203.0.114.7")], None));
    }

    /// Country filtering must stay inactive when no database is loaded, rather
    /// than rejecting every answer: a filter that quietly rejects everything is
    /// worse than no filter, because the operator believes it is working.
    #[test]
    fn country_filter_is_inert_without_a_matcher() {
        let policy = SuspectPolicy {
            countries: vec!["CN".to_string()],
            ..SuspectPolicy::default()
        };
        let address = [v4("93.184.216.34")];

        assert!(!policy.suspect("x.example", &address, None));

        let matcher: CountryLookup = Arc::new(|_code: &str, _ip: IpAddr| true);
        assert!(policy.suspect("x.example", &address, Some(&matcher)));
    }

    /// A `fallback` list is what arms the bogus-address signal: without servers
    /// to re-resolve through there is no policy, and the resolver must not
    /// claim otherwise.
    #[test]
    fn fallback_policy_requires_both_a_list_and_a_signal() {
        let with_list = EngineResolver::from_settings(EngineDnsSettings {
            nameservers: vec!["udp://192.0.2.53:53".to_string()],
            fallback: vec!["udp://192.0.2.54:53".to_string()],
            ..EngineDnsSettings::default()
        })
        .expect("resolver");
        assert!(with_list.has_fallback_policy());

        let without_list = EngineResolver::from_settings(EngineDnsSettings {
            nameservers: vec!["udp://192.0.2.53:53".to_string()],
            ..EngineDnsSettings::default()
        })
        .expect("resolver");
        assert!(!without_list.has_fallback_policy());
    }

    // -- plan → resolver mapping -------------------------------------------

    /// `cache-size` reaches the resolver rather than being ignored, and zero is
    /// clamped: a cache that can hold nothing would turn every lookup into a
    /// round trip without saying so.
    #[test]
    fn cache_size_reaches_the_resolver() {
        let sized = EngineResolver::from_settings(EngineDnsSettings {
            nameservers: vec!["127.0.0.1:53".to_string()],
            cache_size: 2,
            ..EngineDnsSettings::default()
        })
        .expect("resolver");
        assert_eq!(sized.plan.cache_config().warm_capacity, 2);

        let clamped = EngineResolver::from_settings(EngineDnsSettings {
            nameservers: vec!["127.0.0.1:53".to_string()],
            cache_size: 0,
            ..EngineDnsSettings::default()
        })
        .expect("resolver");
        assert_eq!(clamped.plan.cache_config().warm_capacity, 1);
    }

    /// RecurseX reserves group ids 0 and 1 for its default and fallback groups,
    /// so a policy group's id and the rule that names it have to be produced by
    /// the same walk — a gap between them would route a suffix to a group that
    /// does not exist.
    #[test]
    fn policy_group_ids_start_at_two_and_are_contiguous() {
        let rules = policy_rules(&[
            "a.test".to_string(),
            "b.test".to_string(),
            "c.test".to_string(),
        ]);
        assert_eq!(
            rules,
            vec![
                ("a.test".to_string(), 2),
                ("b.test".to_string(), 3),
                ("c.test".to_string(), 4),
            ]
        );
        assert!(policy_rules(&[]).is_empty());
    }

    // -- what a profile cannot express -------------------------------------

    /// These entries have to be IPs: a hostname here could only be resolved by
    /// the system resolver, which is the dependency the list exists to remove.
    /// Accepting it would look like it worked.
    ///
    /// A profile that names no bootstrap server still does not need the system
    /// resolver if it already named a server *by address* — which is the second
    /// half of this test.
    #[test]
    fn bootstrap_refuses_hostnames_and_falls_back_to_literal_servers() {
        assert!(bootstrap_candidates(&[], &[], &[]).is_empty());

        assert!(
            bootstrap_candidates(&["https://named.test/dns-query".to_string()], &[], &[])
                .is_empty(),
            "a hostname-named bootstrap resolver cannot bootstrap anything"
        );
        assert!(
            bootstrap_candidates(&["not a dns server".to_string()], &[], &[]).is_empty(),
            "an unparseable entry must not become a resolver"
        );

        assert_eq!(
            bootstrap_candidates(&["223.5.5.5".to_string()], &[], &[]).len(),
            1,
            "an IP literal is exactly what this list is for"
        );
        assert_eq!(
            bootstrap_candidates(&["tls://223.5.5.5".to_string()], &[], &[]).len(),
            1,
            "an encrypted bootstrap resolver is still an IP literal"
        );

        // The implicit half: a literal `nameservers` entry bootstraps the
        // hostname-named one beside it, and a duplicate is not asked twice.
        let named = vec![
            Upstream::parse("8.8.8.8").expect("literal"),
            Upstream::parse("https://dns.google/dns-query").expect("named"),
        ];
        let candidates = bootstrap_candidates(&["8.8.8.8".to_string()], &named, &[]);
        assert_eq!(
            candidates.len(),
            1,
            "the explicit entry and the literal nameserver are the same server"
        );
        assert_eq!(candidates[0].host(), "8.8.8.8");

        let implicit = bootstrap_candidates(&[], &named, &[]);
        assert_eq!(implicit.len(), 1, "only the literal is usable");
        assert_eq!(implicit[0].host(), "8.8.8.8");
    }

    /// A profile that names nothing usable leaves the system resolver in place,
    /// which is a different outcome from a resolver that cannot be reached yet.
    #[test]
    fn a_profile_without_usable_servers_is_not_a_resolver() {
        assert!(EngineResolver::new(&[], &HashMap::new()).is_none());
        assert!(EngineResolver::new(&["not a dns server".to_string()], &HashMap::new()).is_none());
        assert!(EngineResolver::new(&["8.8.8.8".to_string()], &HashMap::new()).is_some());
    }

    /// Building the resolver is deferred, and a literal upstream needs no
    /// lookup to get there: `from_settings` performs no I/O at all.
    #[test]
    fn configuration_never_touches_the_network() {
        let started = Instant::now();
        let resolver = EngineResolver::from_settings(EngineDnsSettings {
            nameservers: vec!["https://dns.invalid/dns-query".to_string()],
            default_nameserver: vec!["192.0.2.53".to_string()],
            ..EngineDnsSettings::default()
        })
        .expect("a plan is validated, not built");
        assert!(!resolver.has_fallback_policy());
        assert!(
            started.elapsed() < Duration::from_millis(BOOTSTRAP_BUDGET_MS / 2),
            "configuration must not wait on a lookup"
        );
    }

    // -- runtime -----------------------------------------------------------

    #[test]
    fn ip_literals_bypass_dns_entirely() {
        let resolver =
            EngineResolver::new(&["127.0.0.1:5353".to_string()], &HashMap::new()).unwrap();
        let addrs = resolver.resolve("10.1.2.3", 443).unwrap();
        assert_eq!(addrs, vec!["10.1.2.3:443".parse().unwrap()]);

        // ...and asking for the wrong family of a literal is not a lookup.
        let error = resolver.resolve_ips("10.1.2.3", true).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    /// `hosts` wins over every server, so it must answer without a query. The
    /// configured upstream points at a documentation address and is never
    /// contacted.
    #[test]
    fn hosts_answers_without_asking_anyone() {
        let mut hosts = HashMap::new();
        hosts.insert("node.example".to_string(), v4("203.0.113.9"));

        let resolver = EngineResolver::from_settings(EngineDnsSettings {
            nameservers: vec!["udp://192.0.2.53:53".to_string()],
            hosts,
            ..EngineDnsSettings::default()
        })
        .expect("resolver with a host entry");
        let addresses = resolver
            .resolve("NODE.example.", 443)
            .expect("hosts entry should answer");
        assert_eq!(addresses, vec!["203.0.113.9:443".parse().unwrap()]);
    }

    #[test]
    fn a_configured_upstream_answers_and_is_used_for_both_families() {
        let (port, handle) = spawn_udp_server(|_| Some(Ipv4Addr::new(10, 9, 8, 7)));
        let resolver = EngineResolver::new(&[format!("udp://127.0.0.1:{port}")], &HashMap::new())
            .expect("a literal upstream needs no bootstrap");

        assert_eq!(
            resolver.resolve("entry.node.test", 8443).expect("resolved"),
            vec!["10.9.8.7:8443".parse().unwrap()]
        );
        assert_eq!(
            resolver
                .resolve_ips("entry.node.test", false)
                .expect("resolved"),
            vec![v4("10.9.8.7")]
        );
        drop(handle);
    }

    /// `default-nameserver` is what resolves an upstream that is itself named by
    /// a hostname. Nothing on this machine can resolve `named.test`, so the query
    /// only reaches a server because the bootstrap answered first — which is the
    /// difference between the setting being consumed and merely parsed.
    ///
    /// One fake server plays both roles and answers by name rather than by
    /// arrival order, so the test does not depend on how many queries a resolver
    /// chooses to send or in what order.
    #[test]
    fn default_nameserver_resolves_a_hostname_named_upstream() {
        let (port, handle) = spawn_udp_server(|name| {
            if name.to_ascii() == "named.test" {
                // Where the upstream hostname actually lives.
                Some(Ipv4Addr::LOCALHOST)
            } else {
                // The address the caller is asking for.
                Some(Ipv4Addr::new(10, 9, 8, 7))
            }
        });

        let resolver = EngineResolver::from_settings(EngineDnsSettings {
            nameservers: vec![format!("udp://named.test:{port}")],
            default_nameserver: vec![format!("127.0.0.1:{port}")],
            ..EngineDnsSettings::default()
        })
        .expect("resolver");

        let addresses = resolver.resolve("entry.example", 443).expect("resolved");
        assert_eq!(addresses, vec!["10.9.8.7:443".parse().unwrap()]);
        drop(handle);
    }

    /// Without a bootstrap server the upstream hostname cannot be turned into an
    /// address, so the build fails, the failure is remembered, and the caller is
    /// told — rather than the failure being retried on every dial.
    #[test]
    fn a_hostname_upstream_without_a_bootstrap_fails_once_and_backs_off() {
        let resolver = EngineResolver::from_settings(EngineDnsSettings {
            nameservers: vec!["udp://dns.invalid:53".to_string()],
            ..EngineDnsSettings::default()
        })
        .expect("a plan is validated, not built");

        let error = resolver
            .resolve("entry.example", 443)
            .expect_err("nothing can reach dns.invalid");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        let started = Instant::now();
        assert!(resolver.resolve("entry.example", 443).is_err());
        assert!(started.elapsed() < Duration::from_millis(50));
        assert!(resolver.live.read().next_attempt > Instant::now());
    }
}
