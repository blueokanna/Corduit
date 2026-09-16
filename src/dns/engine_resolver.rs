//! Outbound name resolution for the engine itself.
//!
//! Subscription profiles routinely route their **own node domains** through a
//! private resolver (`nameserver-policy` in Clash syntax, e.g.
//! `+.v51124-6.qpon: tcp://<host>:8080`). The public DNS either has no record
//! for those names or hands back a decoy address — a system-resolver lookup
//! then fails instantly (NXDOMAIN) or dials the wrong host, which surfaces as
//! "every VMess connection dies silently in a quarter second". Clash-family
//! clients honour the policy; the engine must as well.
//!
//! This module keeps a process-wide resolver configured from the engine
//! config: per-suffix policy servers first (longest suffix wins), then the
//! default nameservers, with a small positive cache. `connect_host` consults
//! it before touching the system resolver and falls back to the system
//! resolver only when the engine has no usable DNS configuration (or the
//! engine lookup fails outright).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tracing::{debug, info, warn};

use crate::dns::cache::DnsCache;
use crate::dns::client::{create_clients, DnsClient};
use crate::dns::wire::RData;
use crate::dns::RecordType;

/// Query timeout for each upstream attempt.
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// TTL for cached answers (node entry records are stable; mirrors the
/// runtime resolver's fixed default).
const CACHE_TTL: u32 = 300;

/// A resolver over the profile's DNS settings, used for the engine's own
/// outbound server names.
pub struct EngineResolver {
    /// Policy entries, longest suffix first.
    policy: Vec<(String, Vec<DnsClient>)>,
    /// Default servers (the profile's `nameservers`).
    defaults: Vec<DnsClient>,
    /// Positive cache.
    cache: Arc<DnsCache>,
}

impl EngineResolver {
    /// Build a resolver from the profile's nameservers and
    /// `nameserver-policy`. `None` when neither list yields a usable server.
    pub fn new(nameservers: &[String], policy: &HashMap<String, Vec<String>>) -> Option<Self> {
        let defaults = create_clients(nameservers, QUERY_TIMEOUT);

        let mut policy_clients: Vec<(String, Vec<DnsClient>)> = Vec::new();
        for (suffix, servers) in policy {
            let clients = create_clients(servers, QUERY_TIMEOUT);
            if clients.is_empty() {
                warn!("DNS policy for '{suffix}' has no usable servers; entry ignored");
                continue;
            }
            policy_clients.push((normalize_suffix(suffix), clients));
        }
        // Longest suffix first so the most specific policy wins.
        policy_clients.sort_by_key(|(suffix, _)| std::cmp::Reverse(suffix.len()));

        if defaults.is_empty() && policy_clients.is_empty() {
            return None;
        }

        Some(Self {
            policy: policy_clients,
            defaults,
            cache: Arc::new(DnsCache::new(4096, 10, CACHE_TTL)),
        })
    }

    /// The clients responsible for `host`: a matching policy entry, else the
    /// default servers.
    fn clients_for(&self, host: &str) -> Option<&[DnsClient]> {
        for (suffix, clients) in &self.policy {
            if suffix_matches(host, suffix) {
                return Some(clients);
            }
        }
        if self.defaults.is_empty() {
            None
        } else {
            Some(&self.defaults)
        }
    }

    /// Resolve `host` to socket addresses.
    pub fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }

        let name = host.trim_end_matches('.').to_ascii_lowercase();
        if let Some(entry) = self.cache.get(&name, RecordType::A) {
            if !entry.addresses.is_empty() {
                return Ok(entry
                    .addresses
                    .iter()
                    .map(|ip| SocketAddr::new(*ip, port))
                    .collect());
            }
        }

        let Some(clients) = self.clients_for(&name) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no engine DNS servers configured for '{host}'"),
            ));
        };

        let mut ips = Vec::new();
        let mut last_error: Option<String> = None;
        for record in [RecordType::A, RecordType::AAAA] {
            let wire_record = crate::dns::wire::RecordType::from(record);
            for client in clients {
                match client.query(&name, wire_record) {
                    Ok(response) => {
                        for answer in &response.answers {
                            match &answer.data {
                                RData::A(a) if record == RecordType::A => ips.push(IpAddr::V4(a.0)),
                                RData::AAAA(a) if record == RecordType::AAAA => {
                                    ips.push(IpAddr::V6(a.0))
                                }
                                _ => {}
                            }
                        }
                        if !ips.is_empty() {
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("engine DNS {} failed for '{name}': {e}", client.address());
                        last_error = Some(e.to_string());
                    }
                }
            }
            if !ips.is_empty() {
                break;
            }
        }

        if ips.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "engine DNS found no address for '{host}': {}",
                    last_error.unwrap_or_else(|| "empty answer".to_string())
                ),
            ));
        }

        // Prefer IPv4 (dialing order matters for flaky IPv6 paths).
        ips.sort_by_key(|ip| matches!(ip, IpAddr::V6(_)) as u8);
        self.cache
            .insert(&name, RecordType::A, ips.clone(), CACHE_TTL);

        Ok(ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }
}

/// Normalize a `nameserver-policy` key: Clash writes `+.example.com`,
/// `*.example.com`, `.example.com` or a bare domain — all mean "this domain
/// and its subdomains".
fn normalize_suffix(key: &str) -> String {
    let key = key.trim().trim_end_matches('.').to_ascii_lowercase();
    let key = key
        .strip_prefix("+.")
        .or_else(|| key.strip_prefix("*."))
        .unwrap_or(&key);
    key.strip_prefix('.').unwrap_or(key).to_string()
}

/// Label-boundary suffix match (`example.com` matches `example.com` and
/// `a.example.com`, never `notexample.com`).
fn suffix_matches(host: &str, suffix: &str) -> bool {
    suffix.is_empty()
        || host == suffix
        || (host.len() > suffix.len() && host.ends_with(suffix) && {
            let boundary = host.len() - suffix.len() - 1;
            host.as_bytes()[boundary] == b'.'
        })
}

/// Process-wide resolver, configured from the engine config.
static ENGINE_RESOLVER: RwLock<Option<Arc<EngineResolver>>> = RwLock::new(None);

/// Install (or clear) the engine resolver from the profile's DNS settings.
/// Called on every config conversion, so both initialize and reload paths
/// stay in sync.
pub fn configure(nameservers: &[String], policy: &HashMap<String, Vec<String>>) {
    match EngineResolver::new(nameservers, policy) {
        Some(resolver) => {
            info!(
                "Engine DNS resolver configured: {} default servers, {} policy entries",
                nameservers.len(),
                policy.len()
            );
            *ENGINE_RESOLVER.write() = Some(Arc::new(resolver));
        }
        None => {
            debug!("No engine DNS servers configured; outbound names use the system resolver");
            *ENGINE_RESOLVER.write() = None;
        }
    }
}

/// Resolve `host` through the engine's configured DNS.
///
/// `None` means the engine has no DNS configuration — the caller falls back
/// to the system resolver, which is also the fallback when the engine
/// lookup fails.
pub fn resolve(host: &str, port: u16) -> Option<io::Result<Vec<SocketAddr>>> {
    let resolver = ENGINE_RESOLVER.read().clone()?;
    Some(resolver.resolve(host, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::wire::rdata;
    use crate::dns::wire::{
        BinDecodable, BinEncodable, Message, MessageType, OpCode, Query, Record,
    };
    use std::net::{Ipv4Addr, UdpSocket};

    #[test]
    fn policy_keys_normalize_like_clash() {
        assert_eq!(normalize_suffix("+.example.com"), "example.com");
        assert_eq!(normalize_suffix("*.example.com"), "example.com");
        assert_eq!(normalize_suffix(".example.com"), "example.com");
        assert_eq!(normalize_suffix("EXAMPLE.com."), "example.com");
        assert_eq!(normalize_suffix("example.com"), "example.com");
    }

    #[test]
    fn suffix_matching_respects_label_boundaries() {
        assert!(suffix_matches("example.com", "example.com"));
        assert!(suffix_matches("a.example.com", "example.com"));
        assert!(suffix_matches("a.b.example.com", "example.com"));
        assert!(!suffix_matches("notexample.com", "example.com"));
        assert!(!suffix_matches("example.com.evil.org", "example.com"));
        assert!(suffix_matches("anything.test", ""));
    }

    #[test]
    fn the_longest_policy_suffix_wins() {
        let mut policy = HashMap::new();
        policy.insert(
            "+.example.com".to_string(),
            vec!["127.0.0.1:5353".to_string()],
        );
        policy.insert(
            "+.sub.example.com".to_string(),
            vec!["127.0.0.2:5354".to_string()],
        );
        let resolver = EngineResolver::new(&["127.0.0.9:53".to_string()], &policy).unwrap();

        let clients = resolver.clients_for("a.sub.example.com").unwrap();
        assert_eq!(clients[0].address(), "127.0.0.2");

        let clients = resolver.clients_for("a.example.com").unwrap();
        assert_eq!(clients[0].address(), "127.0.0.1");

        let clients = resolver.clients_for("other.test").unwrap();
        assert_eq!(clients[0].address(), "127.0.0.9");
    }

    #[test]
    fn ip_literals_bypass_dns_entirely() {
        let resolver =
            EngineResolver::new(&["127.0.0.1:5353".to_string()], &HashMap::new()).unwrap();
        let addrs = resolver.resolve("10.1.2.3", 443).unwrap();
        assert_eq!(addrs, vec!["10.1.2.3:443".parse().unwrap()]);
    }

    /// A loopback UDP DNS server answers one A query; the resolver must use
    /// the *policy* server (the default server points at a dead port).
    #[test]
    fn policy_servers_resolve_the_name() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (n, peer) = server.recv_from(&mut buf).unwrap();
            let request = Message::from_bytes(&buf[..n]).unwrap();
            let mut response =
                Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
            for q in &request.queries {
                response.add_query(Query::query(q.name().clone(), q.query_type()));
            }
            let name = request.queries[0].name().clone();
            response.add_answer(Record::from_rdata(
                name,
                60,
                RData::A(rdata::A(Ipv4Addr::new(10, 9, 8, 7))),
            ));
            let bytes = response.to_bytes().unwrap();
            server.send_to(&bytes, peer).unwrap();
        });

        let mut policy = HashMap::new();
        policy.insert(
            "+.node.test".to_string(),
            vec![format!("udp://127.0.0.1:{}", server_addr.port())],
        );
        // The default server is a dead port: only the policy path can answer.
        let resolver = EngineResolver::new(&["127.0.0.1:1".to_string()], &policy).unwrap();

        let addrs = resolver.resolve("entry.node.test", 8443).unwrap();
        handle.join().unwrap();

        assert_eq!(addrs, vec!["10.9.8.7:8443".parse().unwrap()]);
        // Second lookup must come from the cache (server thread already gone).
        let cached = resolver.resolve("entry.node.test", 9443).unwrap();
        assert_eq!(cached, vec!["10.9.8.7:9443".parse().unwrap()]);
    }
}
