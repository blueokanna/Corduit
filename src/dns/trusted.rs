//! The resolver the engine falls back on while its own tunnel captures DNS.
//!
//! A TUN device points the operating system's resolver at an address inside
//! the tunnel (`198.18.0.2` on Windows), because DNS is how a transparent
//! tunnel learns the names behind the connections it carries. That hijack is
//! correct for every other process on the machine and wrong for exactly one:
//! the engine itself. The engine **is** the tunnel, so a lookup that follows
//! the OS resolver comes back with a fake address that routes straight back
//! into the engine — and a profile without its own `dns` section has no other
//! resolver to fall back on. The dial then either loops into itself or fails
//! after the resolver's full retry budget, which is what "TUN mode has no
//! internet" looks like from the outside.
//!
//! The fix is not to special-case DNS interception; it is to resolve through
//! the servers that answered *before* the tunnel existed. [`set_servers`] is
//! called with the physical interface's own DNS addresses — snapshotted by the
//! platform layer at the moment the tunnel is raised — and from then on
//! [`resolve`] and [`resolve_any`] query those servers directly: one UDP
//! exchange per attempt, from a socket pinned to the physical interface, so
//! the datagram leaves the machine instead of re-entering the tunnel.
//!
//! Nothing here runs unless the platform layer armed it: with an empty server
//! list [`is_active`] is false and every caller keeps its previous behaviour
//! (the system resolver). The one module-level promise is that the fallback
//! order stays: the profile's resolver first (`engine_resolver`), this second,
//! the OS resolver last and only while no tunnel is capturing it.
//!
//! Answers are cached briefly — long enough that one page load does not turn
//! into a burst of identical queries, short enough that a server-side address
//! change is picked up on the next dial rather than at the next restart.

use parking_lot::Mutex;
use recurse_x::{Message, Name, RData, RrClass, RrType};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, info};

/// Ceiling on the captured server list: a machine with a dozen VPN adapters
/// still gets the first few, and the list stays inspectable in a log line.
const MAX_SERVERS: usize = 8;

/// How many captured servers one lookup tries before giving up.
const MAX_ATTEMPTS: usize = 4;

/// Per-attempt budget. This path exists so a dial does not stall on a resolver
/// the dial no longer trusts, so it is deliberately shorter than the OS
/// resolver's own retries.
const ATTEMPT_TIMEOUT: Duration = Duration::from_millis(1500);

/// How long an answer is reused. Short on purpose: the servers are the
/// network's own, and their answers are the only ones a tunnel-less path got.
const POSITIVE_TTL: Duration = Duration::from_secs(60);
const NEGATIVE_TTL: Duration = Duration::from_secs(5);

/// Cap on the answer cache. A dial-heavy minute covers a few hundred names;
/// beyond that the cache is cleared rather than grown.
const MAX_CACHE_ENTRIES: usize = 1024;

/// DNS servers of the physical network, snapshotted before the tunnel's own
/// DNS was installed.
static TRUSTED_SERVERS: Mutex<Vec<SocketAddr>> = Mutex::new(Vec::new());

/// Rotating first server, so a dead entry cannot be hit by every lookup.
static NEXT_SERVER: AtomicUsize = AtomicUsize::new(0);

/// Query ids. A stub resolver's transaction id is not a security boundary
/// against an on-path attacker (there is none to defend against here — this
/// socket leaves through the physical interface the server is reached
/// through), but it must not be *predictable* either, or an off-path spoofer
/// could race the answer. A seeded counter overlaps nothing in practice.
static NEXT_QUERY_ID: AtomicU16 = AtomicU16::new(0);

struct CacheEntry {
    expires: Instant,
    addresses: Vec<IpAddr>,
}

static ANSWER_CACHE: Mutex<Option<HashMap<String, CacheEntry>>> = Mutex::new(None);

/// Install the servers a lookup may fall back on, replacing any previous set.
///
/// Called by the platform layer right before it raises a TUN whose DNS will
/// capture the system resolver, and cleared when that tunnel goes away.
pub fn set_servers(servers: Vec<SocketAddr>) {
    let mut deduped: Vec<SocketAddr> = Vec::new();
    for server in servers {
        if server.port() != 0 && !deduped.contains(&server) {
            deduped.push(server);
        }
        if deduped.len() == MAX_SERVERS {
            break;
        }
    }
    if deduped.is_empty() {
        info!("trusted DNS: disarmed");
    } else {
        info!(
            ?deduped,
            "trusted DNS: armed for the duration of the tunnel"
        );
    }
    *TRUSTED_SERVERS.lock() = deduped;
    *ANSWER_CACHE.lock() = None;
}

/// Disarm the fallback; the system resolver becomes the last word again.
pub fn clear() {
    set_servers(Vec::new());
}

/// Whether the fallback is armed.
pub fn is_active() -> bool {
    !TRUSTED_SERVERS.lock().is_empty()
}

/// The armed servers, for logging and tests.
pub fn servers() -> Vec<SocketAddr> {
    TRUSTED_SERVERS.lock().clone()
}

/// Resolve `domain` through the captured servers, asking for one family.
///
/// `want_v6` selects the question type; a name with no record of that family
/// answers with an empty list, which is a name-level fact, not an error. An
/// I/O error means every attempted server failed to answer usefully.
pub fn resolve(domain: &str, want_v6: bool) -> io::Result<Vec<IpAddr>> {
    let key = format!(
        "{}|{}",
        if want_v6 { "6" } else { "4" },
        domain.to_lowercase()
    );
    resolve_cached(&key, || resolve_uncached(domain, want_v6))
}

/// Resolve `domain` for both families, IPv4 first.
///
/// Used by the dial path, which wants addresses rather than a family: a name
/// with only a AAAA record must still dial, and one with both must prefer the
/// order the rest of the engine uses.
pub fn resolve_any(domain: &str) -> io::Result<Vec<IpAddr>> {
    if let Ok(ip) = domain.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let key = format!("a|{}", domain.to_lowercase());
    resolve_cached(&key, || {
        let v4 = resolve_uncached(domain, false)?;
        if !v4.is_empty() {
            return Ok(v4);
        }
        resolve_uncached(domain, true)
    })
}

fn resolve_cached(
    key: &str,
    work: impl FnOnce() -> io::Result<Vec<IpAddr>>,
) -> io::Result<Vec<IpAddr>> {
    {
        let mut guard = ANSWER_CACHE.lock();
        if let Some(cache) = guard.as_mut() {
            if let Some(entry) = cache.get(key) {
                if Instant::now() < entry.expires {
                    return Ok(entry.addresses.clone());
                }
            }
            cache.retain(|_, entry| Instant::now() < entry.expires);
        }
    }

    let addresses = work()?;

    let ttl = if addresses.is_empty() {
        NEGATIVE_TTL
    } else {
        POSITIVE_TTL
    };
    let mut guard = ANSWER_CACHE.lock();
    let cache = guard.get_or_insert_with(HashMap::new);
    if cache.len() >= MAX_CACHE_ENTRIES {
        cache.clear();
    }
    cache.insert(
        key.to_string(),
        CacheEntry {
            expires: Instant::now() + ttl,
            addresses: addresses.clone(),
        },
    );
    Ok(addresses)
}

fn resolve_uncached(domain: &str, want_v6: bool) -> io::Result<Vec<IpAddr>> {
    let servers = servers();
    if servers.is_empty() {
        return Err(io::Error::other(
            "trusted DNS is not armed; install the physical servers before relying on it",
        ));
    }
    let name = Name::from_ascii(domain.trim_end_matches('.'))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{domain}: {e}")))?;
    let rr_type = if want_v6 { RrType::AAAA } else { RrType::A };

    let start = NEXT_SERVER.fetch_add(1, Ordering::Relaxed) % servers.len();
    let attempts = MAX_ATTEMPTS.min(servers.len());
    let mut last_error: Option<io::Error> = None;
    for index in 0..attempts {
        let server = servers[(start + index) % servers.len()];
        match exchange(server, &name, rr_type) {
            Ok(addresses) => return Ok(addresses),
            Err(error) => {
                debug!(%server, domain, "trusted DNS attempt failed: {error}");
                last_error = Some(error);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::other("no trusted DNS server answered")))
}

/// One question to one server, over a pinned one-shot UDP socket.
fn exchange(server: SocketAddr, name: &Name, rr_type: RrType) -> io::Result<Vec<IpAddr>> {
    let query_id = next_query_id();
    let query = Message::query(query_id, name.clone(), rr_type, true)
        .to_bytes()
        .map_err(|e| io::Error::other(format!("encode query: {e}")))?;
    let reply = crate::common::socket::udp_exchange(&server, &query, ATTEMPT_TIMEOUT, None)?;
    let response =
        Message::parse(&reply).map_err(|e| io::Error::other(format!("parse reply: {e}")))?;
    if !response.flags.qr {
        return Err(io::Error::other("reply is a query, not a response"));
    }
    // Answer only *this* question. Anything else is a stray, a race or an
    // injection, and taking its addresses would be exactly the race the
    // query id exists to prevent.
    if response.id != query_id {
        return Err(io::Error::other(format!(
            "reply id {} does not match the query id {query_id}",
            response.id
        )));
    }
    match response.question() {
        Some(question)
            if question.qname == *name
                && question.qtype == rr_type
                && question.qclass == RrClass::IN => {}
        _ => {
            return Err(io::Error::other(
                "reply does not echo the question that was asked",
            ))
        }
    }
    if response.flags.tc {
        // Truncated: this path has no TCP retry, so the partial answer is
        // not usable — report it and let the next server try.
        return Err(io::Error::other("reply is truncated (TC set)"));
    }
    let mut addresses = Vec::new();
    for record in &response.answers {
        match record.rdata {
            RData::A(address) => addresses.push(IpAddr::V4(address)),
            RData::Aaaa(address) => addresses.push(IpAddr::V6(address)),
            _ => {}
        }
    }
    Ok(addresses)
}

/// A transaction id that is random when the OS can supply randomness and
/// merely unlikely to repeat when it cannot.
fn next_query_id() -> u16 {
    let mut bytes = [0u8; 2];
    if getrandom::fill(&mut bytes).is_ok() {
        return u16::from_be_bytes(bytes);
    }
    let tick = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.subsec_nanos() >> 16) as u16)
        .unwrap_or(0);
    NEXT_QUERY_ID.fetch_add(0x9E37, Ordering::Relaxed) ^ tick
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::engine_resolver::testing::spawn_udp_server;
    use std::net::Ipv4Addr;

    /// The module's state is process-wide, so the tests that move it take
    /// turns instead of racing each other's `set_servers`/`clear`.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn exclusive() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Arms the fallback for one test and disarms it on drop, so a panicking
    /// assertion cannot leak the global state into the next test.
    struct Armed;

    impl Armed {
        fn new(servers: Vec<SocketAddr>) -> Self {
            set_servers(servers);
            Self
        }
    }

    impl Drop for Armed {
        fn drop(&mut self) {
            clear();
        }
    }

    #[test]
    fn arming_dedupes_and_caps_the_server_list() {
        let _exclusive = exclusive();
        let mut pinned = Vec::new();
        for index in 0..12u16 {
            pinned.push(SocketAddr::from(([127, 0, 0, 1], 5300 + index)));
        }
        pinned.push(SocketAddr::from(([127, 0, 0, 1], 5300)));
        set_servers(pinned);
        let armed = servers();
        assert_eq!(armed.len(), MAX_SERVERS);
        assert_eq!(armed[0], SocketAddr::from(([127, 0, 0, 1], 5300)));
        clear();
        assert!(!is_active());
        assert!(resolve("example.test", false).is_err());
    }

    #[test]
    fn a_query_round_trips_through_an_armed_server() {
        let _exclusive = exclusive();
        let wanted = Name::from_ascii("example.test").expect("a query name");
        let (port, _thread) =
            spawn_udp_server(move |name| (name == &wanted).then(|| Ipv4Addr::new(203, 0, 113, 7)));
        let _armed = Armed::new(vec![SocketAddr::from(([127, 0, 0, 1], port))]);

        let found = resolve("example.test", false).expect("the armed server answers");
        assert_eq!(found, vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))]);

        // The second call is answered from the cache, which must agree.
        let again = resolve("example.test", false).expect("cached answer");
        assert_eq!(again, found);
    }

    /// A loopback server that answers with whatever the closure builds from
    /// the query — the tool for proving that replies which do not belong to
    /// the question are thrown away rather than trusted.
    fn spawn_responder(respond: impl Fn(&Message) -> Option<Message> + Send + 'static) -> u16 {
        let server = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a loopback socket");
        server
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("a read timeout, so the thread cannot outlive the test forever");
        let port = server.local_addr().expect("bound address").port();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 4096];
            while let Ok((len, peer)) = server.recv_from(&mut buf) {
                let Ok(query) = Message::parse(&buf[..len]) else {
                    continue;
                };
                if let Some(response) = respond(&query) {
                    if let Ok(bytes) = response.to_bytes() {
                        let _ = server.send_to(&bytes, peer);
                    }
                }
            }
        });
        port
    }

    fn poisoned_answer() -> recurse_x::Record {
        recurse_x::Record {
            name: Name::from_ascii("example.test").expect("a record name"),
            rr_type: RrType::A,
            class: RrClass::IN,
            ttl: 60,
            rdata: RData::A(Ipv4Addr::new(203, 0, 113, 9)),
        }
    }

    /// A raced or injected reply with the wrong transaction id is discarded,
    /// addresses and all — accepting it is exactly what the random id exists
    /// to prevent.
    #[test]
    fn a_reply_with_the_wrong_transaction_id_is_discarded() {
        let _exclusive = exclusive();
        let port = spawn_responder(|query| {
            let mut response = Message::new(query.id.wrapping_add(1));
            response.flags.qr = true;
            response.questions.clone_from(&query.questions);
            response.answers.push(poisoned_answer());
            Some(response)
        });
        let _armed = Armed::new(vec![SocketAddr::from(([127, 0, 0, 1], port))]);
        assert!(resolve("example.test", false).is_err());
    }

    /// A reply that does not echo the question is discarded even when it
    /// carries syntactically valid answers.
    #[test]
    fn a_reply_to_another_question_is_discarded() {
        let _exclusive = exclusive();
        let port = spawn_responder(|query| {
            let mut response = Message::new(query.id);
            response.flags.qr = true;
            response.questions.push(recurse_x::Question {
                qname: Name::from_ascii("evil.test").expect("a question name"),
                qtype: RrType::A,
                qclass: RrClass::IN,
            });
            response.answers.push(poisoned_answer());
            Some(response)
        });
        let _armed = Armed::new(vec![SocketAddr::from(([127, 0, 0, 1], port))]);
        assert!(resolve("example.test", false).is_err());
    }

    /// A truncated reply is not an answer: this path cannot retry over TCP,
    /// so it must move on to the next server instead of caching the gap.
    #[test]
    fn a_truncated_reply_is_discarded() {
        let _exclusive = exclusive();
        let port = spawn_responder(|query| {
            let mut response = Message::new(query.id);
            response.flags.qr = true;
            response.flags.tc = true;
            response.questions.clone_from(&query.questions);
            response.answers.push(poisoned_answer());
            Some(response)
        });
        let _armed = Armed::new(vec![SocketAddr::from(([127, 0, 0, 1], port))]);
        assert!(resolve("example.test", false).is_err());
    }

    #[test]
    fn a_name_without_a_record_is_an_empty_answer_not_an_error() {
        let _exclusive = exclusive();
        let (port, _thread) = spawn_udp_server(|_| None);
        let _armed = Armed::new(vec![SocketAddr::from(([127, 0, 0, 1], port))]);
        let found = resolve("nothing.test", false).expect("an empty answer is still an answer");
        assert!(found.is_empty());
    }

    #[test]
    fn a_literal_needs_no_server() {
        let _exclusive = exclusive();
        clear();
        let found = resolve_any("198.51.100.9").expect("a literal resolves itself");
        assert_eq!(found, vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))]);
    }
}
