//! Blocking socket primitives for the Corduit synchronous engine.
//!
//! Every socket in Corduit is a plain `std` socket configured with explicit
//! read/write timeouts. A timeout surfaces as `io::ErrorKind::WouldBlock` or
//! `TimedOut` from the read/write call, which the caller treats as "nothing
//! happened yet" — exactly how a synchronous engine bounds blocking
//! operations without an async reactor.
//!
//! * [`connect`] performs a timeout-bounded TCP connect on every platform
//!   (via `socket2`'s `connect_timeout`, which polls the socket internally).
//! * [`connect_host`] resolves a hostname and tries each candidate address
//!   in turn, or all at once when `tcp-concurrent` is enabled.
//! * [`configure`] applies nodelay / keepalive / read / write timeouts.
//! * [`udp_exchange`] performs a one-shot UDP request/reply on a fresh
//!   socket, immune to Windows ICMP poisoning.

use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

/// Whether a name's addresses are dialled at once instead of one after another.
///
/// A process-wide switch rather than a parameter, because `connect_host` sits on
/// every outbound's dial path: threading a flag through fifteen call sites to
/// reach one decision would leave the setting further from where it is read than
/// from where it is set. The engine resolver is installed the same way.
static TCP_CONCURRENT: AtomicBool = AtomicBool::new(false);

/// Ceiling on how many addresses are dialled concurrently.
///
/// A name with eight addresses should not open eight sockets to answer one
/// connect; the first few candidates carry almost all of the benefit, and the
/// rest are the ones most likely to look alike anyway.
const MAX_CONCURRENT_DIALS: usize = 4;

/// Install the profile's `tcp-concurrent` setting.
pub fn set_tcp_concurrent(enabled: bool) {
    TCP_CONCURRENT.store(enabled, Ordering::Relaxed);
}

/// Whether `tcp-concurrent` is in effect.
pub fn tcp_concurrent() -> bool {
    TCP_CONCURRENT.load(Ordering::Relaxed)
}

/// Exempt an outbound socket from the engine's own tunnel (Android).
///
/// The engine **is** the VPN. On the OEM builds that route the VPN app's
/// own traffic into its own TUN, an unprotected outbound socket loops
/// straight back into the netstack — `VpnService.protect` must be called
/// before `connect`/`bind` for the routing decision to stick. A no-op on
/// every other platform.
#[cfg(target_os = "android")]
pub fn protect_outbound_fd(fd: i32) {
    if crate::netstack::has_protect_callback() && !crate::netstack::protect_socket(fd) {
        tracing::warn!(
            "failed to protect outbound socket fd={fd}; it may be routed into the tunnel"
        );
    }
}

/// See [`protect_outbound_fd`]; this variant is a no-op.
#[cfg(not(target_os = "android"))]
pub fn protect_outbound_fd(_fd: i32) {}

/// Exempt a `socket2` socket from the engine's own tunnel.
fn protect_socket2(sock: &socket2::Socket) {
    #[cfg(target_os = "android")]
    {
        use std::os::fd::AsRawFd;
        protect_outbound_fd(sock.as_raw_fd());
    }
    #[cfg(not(target_os = "android"))]
    let _ = sock;
}

/// Establish a TCP connection to `addr` within `timeout`.
///
/// Uses a non-blocking connect polled by the OS (`socket2`'s
/// `connect_timeout`), so a black-holed peer cannot hang the caller past
/// the budget — the classic failure mode of a plain blocking `connect`.
pub fn connect(addr: &SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let sock = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    // The tunnel exemption must precede `connect` for the OS to honour it.
    protect_socket2(&sock);
    sock.set_nonblocking(true)?;
    sock.connect_timeout(&(*addr).into(), timeout)?;
    // `connect_timeout` requires a non-blocking socket but leaves it that
    // way; the synchronous engine needs a plain blocking stream (read/write
    // timeouts via SO_RCVTIMEO/SO_SNDTIMEO only behave as intended on
    // blocking sockets — on Linux a leftover O_NONBLOCK makes relay reads
    // return WouldBlock instantly and stalls bidirectional copies).
    sock.set_nonblocking(false)?;
    let stream: TcpStream = sock.into();
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// Resolve `host:port` and connect to the first reachable address within
/// `timeout`. Resolution itself is bounded via [`resolve_host`].
///
/// The engine's own DNS settings win over the system resolver: subscription
/// profiles frequently make their node domains resolvable only through a
/// private `nameserver-policy` resolver, and the system resolver would
/// answer NXDOMAIN — or worse, a decoy address — for them.
pub fn connect_host(host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    let addrs = match crate::dns::engine_resolver::resolve(host, port) {
        Some(Ok(addrs)) => addrs,
        Some(Err(e)) => {
            tracing::debug!("engine DNS could not resolve {host}: {e}; trying the system resolver");
            resolve_host(host, port, timeout)?
        }
        None => resolve_host(host, port, timeout)?,
    };
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no addresses for {host}:{port}"),
        ));
    }

    // Racing changes the shape of the budget: the attempts no longer take turns,
    // so each one may use the whole timeout rather than a divided share.
    if tcp_concurrent() && addrs.len() > 1 {
        return connect_first(&addrs, timeout);
    }

    // Give each candidate a fair share of the budget so a dead first
    // address (e.g. a stale AAAA record) cannot consume it all.
    let per = (timeout / addrs.len().max(1) as u32).max(Duration::from_millis(250));
    let mut last = None;
    for addr in addrs {
        match connect(&addr, per) {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses")))
}

/// Dial every candidate at once and keep the first one that answers.
///
/// The losing sockets are abandoned rather than waited for: their threads end
/// when their own connect completes or times out, which is bounded by `timeout`.
/// Waiting for them would give back exactly the latency this exists to remove.
fn connect_first(addrs: &[SocketAddr], timeout: Duration) -> io::Result<TcpStream> {
    let candidates: Vec<SocketAddr> = addrs.iter().copied().take(MAX_CONCURRENT_DIALS).collect();
    let (tx, rx) = mpsc::channel();
    let attempts = candidates.len();

    for addr in candidates {
        let tx = tx.clone();
        std::thread::spawn(move || {
            // A send error means the caller already took an answer.
            let _ = tx.send(connect(&addr, timeout));
        });
    }
    // The clone kept in `tx` would hold the channel open forever.
    drop(tx);

    let mut last: Option<io::Error> = None;
    for _ in 0..attempts {
        match rx.recv_timeout(timeout) {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => last = Some(error),
            // Every attempt is accounted for by the loop bound, so a timeout here
            // means the last one is still running; stop rather than wait again.
            Err(_) => break,
        }
    }

    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "no address answered")))
}

/// Run a blocking lookup on a thread of its own and wait at most `timeout`.
///
/// The system resolver is a blocking call that cannot be interrupted, and the
/// engine's resolver is blocking by construction too, so both need the same
/// bound: a lookup that stalls produces `TimedOut` instead of pinning the
/// calling worker for the resolver's whole retry budget. The lookup thread is
/// detached — whatever it finds after the caller gave up is dropped with the
/// channel.
///
/// One helper rather than one copy per caller, because "bounded blocking
/// lookup" is a rule and not a coincidence.
fn bounded_lookup<T, F>(label: &str, timeout: Duration, work: F) -> io::Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> io::Result<T> + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("corduit-resolve".into())
        .spawn(move || {
            let _ = tx.send(work());
        })
        .map_err(|e| io::Error::other(format!("failed to spawn the resolver thread: {e}")))?;

    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("resolving {label} timed out"),
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(io::Error::other("resolver thread panicked"))
        }
    }
}

/// Resolve a hostname to socket addresses with a bounded wait.
pub fn resolve_host(host: &str, port: u16, timeout: Duration) -> io::Result<Vec<SocketAddr>> {
    let host_owned = host.to_owned();
    bounded_lookup(&format!("{host}:{port}"), timeout, move || {
        (host_owned.as_str(), port)
            .to_socket_addrs()
            .map(|iter| iter.collect::<Vec<SocketAddr>>())
    })
}

/// Resolve a hostname to addresses of **both** families, with a bounded wait.
///
/// The engine's own DNS answers first, for the same reason [`connect_host`]
/// prefers it — and here the reason is sharper than convenience: a rule that
/// matches on a resolved address must see the addresses the connection will
/// actually use. Resolving through the system resolver while the dial goes
/// through a profile-configured one lets a `geoip` or `ip-cidr` rule decide on
/// one answer and the connection use another, and the two disagree exactly when
/// the profile's DNS was configured to make them.
///
/// Both families are asked for because a rule matches against all of them. The
/// system resolver is the fallback, exactly as in [`connect_host`].
pub fn resolve_host_all(host: &str, timeout: Duration) -> io::Result<Vec<IpAddr>> {
    resolve_host_all_with(host, timeout, crate::dns::engine_resolver::resolve_ips)
}

/// The engine lookup, as a value.
///
/// A function pointer rather than a direct call, so the ordering rule below can
/// be tested without installing a process-wide resolver — and so that the rule
/// reads as a parameter instead of being buried in a call.
type EngineLookup = fn(&str, bool) -> Option<io::Result<Vec<IpAddr>>>;

fn resolve_host_all_with(
    host: &str,
    timeout: Duration,
    engine: EngineLookup,
) -> io::Result<Vec<IpAddr>> {
    // A literal needs no lookup and no thread, and asking the engine for the
    // other family of a literal is an error by definition.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let host_owned = host.to_owned();
    bounded_lookup(host, timeout, move || {
        engine_then_system(&host_owned, engine)
    })
}

/// The engine resolver first, the system resolver as the documented fallback.
fn engine_then_system(host: &str, engine: EngineLookup) -> io::Result<Vec<IpAddr>> {
    let mut found: Vec<IpAddr> = Vec::new();
    let mut configured = false;

    for want_v6 in [false, true] {
        match engine(host, want_v6) {
            Some(Ok(addresses)) => {
                configured = true;
                extend_unique(&mut found, addresses);
            }
            Some(Err(error)) => {
                configured = true;
                tracing::debug!("engine DNS could not resolve {host}: {error}");
            }
            // No engine DNS at all: nothing to prefer, and asking for the other
            // family would learn nothing.
            None => break,
        }
    }
    if !found.is_empty() {
        return Ok(found);
    }
    if configured {
        tracing::debug!("engine DNS found no address for {host}; trying the system resolver");
    }

    let mut addresses: Vec<IpAddr> = Vec::new();
    for address in (host, 0u16).to_socket_addrs()? {
        extend_unique(&mut addresses, [address.ip()]);
    }
    Ok(addresses)
}

/// Append `items`, skipping anything already present.
///
/// Order is preserved on purpose: the engine resolver hands back IPv4 first,
/// and that is the order the caller dials in.
fn extend_unique(into: &mut Vec<IpAddr>, items: impl IntoIterator<Item = IpAddr>) {
    for item in items {
        if !into.contains(&item) {
            into.push(item);
        }
    }
}

/// Apply TCP options: nodelay and read/write timeouts.
pub fn configure(
    stream: &TcpStream,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
) -> io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(read_timeout)?;
    stream.set_write_timeout(write_timeout)?;
    Ok(())
}

/// Bind a UDP socket to `bind` and set its read timeout.
pub fn udp_bind(bind: SocketAddr, read_timeout: Duration) -> io::Result<UdpSocket> {
    let domain = if bind.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    // Outbound DNS and relay datagrams bypass the tunnel as well.
    protect_socket2(&sock);
    sock.set_reuse_address(true)?;
    sock.bind(&bind.into())?;
    let udp: UdpSocket = sock.into();
    udp.set_read_timeout(Some(read_timeout))?;
    Ok(udp)
}

/// Send `data` to `target` over a *fresh* connected UDP socket and wait for
/// a reply within `timeout`.
///
/// A fresh socket per exchange sidesteps ICMP-port-unreachable poisoning of
/// a long-lived socket: a "connected" UDP socket on Windows turns an ICMP
/// error into `ConnectionReset` on the *next* read, which would kill a
/// reused socket. One-shot sockets are immune.
pub fn udp_exchange(
    target: &SocketAddr,
    data: &[u8],
    timeout: Duration,
    local_bind: Option<SocketAddr>,
) -> io::Result<Vec<u8>> {
    let bind = local_bind.unwrap_or_else(|| match target {
        SocketAddr::V4(_) => SocketAddr::from((IpAddr::V4([0, 0, 0, 0].into()), 0)),
        SocketAddr::V6(_) => SocketAddr::from((IpAddr::V6([0, 0, 0, 0, 0, 0, 0, 0].into()), 0)),
    });
    let sock = udp_bind(bind, timeout)?;
    sock.connect(target)?;
    sock.send(data)?;
    let mut buf = [0u8; 65536];
    let n = recv_udp_timeout(&sock, &mut buf, timeout)?;
    Ok(buf[..n].to_vec())
}

/// Receive one UDP datagram, mapping `WouldBlock`/`TimedOut` into
/// [`io::ErrorKind::TimedOut`] and treating `ConnectionReset` (the Windows
/// ICMP artifact on connected sockets) as "keep waiting".
pub fn recv_udp_timeout(sock: &UdpSocket, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match sock.recv(buf) {
            Ok(n) => return Ok(n),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::ConnectionReset
                ) =>
            {
                if std::time::Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "udp recv timed out",
                    ));
                }
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_timeout_fails_fast() {
        // 192.0.2.0/24 is TEST-NET-1, guaranteed unroutable. A blocking
        // connect would hang; connect_timeout must return within the budget.
        let addr: SocketAddr = "192.0.2.1:65000".parse().unwrap();
        let start = std::time::Instant::now();
        let res = connect(&addr, Duration::from_millis(300));
        assert!(res.is_err());
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    /// A listener that counts what it accepts, so a dial can be observed rather
    /// than timed.
    fn counting_listener() -> (SocketAddr, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&hits);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stream.is_err() {
                    break;
                }
                counter.fetch_add(1, Ordering::SeqCst);
            }
        });
        (addr, hits)
    }

    /// Wait for `counter` to reach at least `expected`, then return what it reads.
    ///
    /// A connect is complete once the kernel finishes the handshake, which can be
    /// before the accepting thread has returned from `accept`. The count is
    /// therefore not readable the instant a dial returns, and asserting on it
    /// immediately is a race rather than a check.
    fn wait_for(
        counter: &std::sync::Arc<std::sync::atomic::AtomicUsize>,
        expected: usize,
    ) -> usize {
        for _ in 0..300 {
            let seen = counter.load(Ordering::SeqCst);
            if seen >= expected {
                return seen;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        counter.load(Ordering::SeqCst)
    }

    /// Racing dials every candidate; dialling in order stops at the first one
    /// that answers.
    ///
    /// Counted on the listeners rather than timed: the difference is which
    /// sockets get opened, and a timing assertion would depend on how fast an
    /// unreachable address happens to fail on the machine running the test.
    #[test]
    fn racing_dials_every_candidate() {
        let (first, first_hits) = counting_listener();
        let (second, second_hits) = counting_listener();

        let stream = connect(&first, Duration::from_secs(2)).expect("the first listener accepts");
        drop(stream);
        assert_eq!(wait_for(&first_hits, 1), 1);

        // Give a stray dial the time it would need to show up, so "did not
        // reach the second address" is an observation and not just a fast read.
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            second_hits.load(Ordering::SeqCst),
            0,
            "one-at-a-time dialling must not reach the second address"
        );

        let stream = connect_first(&[first, second], Duration::from_secs(2))
            .expect("at least one candidate answers");
        drop(stream);

        assert_eq!(wait_for(&first_hits, 2), 2);
        assert_eq!(
            wait_for(&second_hits, 1),
            1,
            "racing must also dial the address that lost"
        );
    }

    /// The switch the engine installs from `tcp-concurrent` reaches the dial path.
    ///
    /// A process-wide flag, so this test leaves it as it found it: another test
    /// dialling a host would otherwise race the setting rather than the addresses.
    #[test]
    fn the_concurrent_switch_round_trips() {
        let original = tcp_concurrent();
        set_tcp_concurrent(true);
        assert!(tcp_concurrent());
        set_tcp_concurrent(false);
        assert!(!tcp_concurrent());
        set_tcp_concurrent(original);
    }

    #[test]
    fn connect_host_rejects_unresolvable() {
        // A host that cannot resolve must surface as an error, not hang.
        let res = connect_host(
            "this-host-does-not-exist.invalid",
            80,
            Duration::from_secs(5),
        );
        assert!(res.is_err());
    }

    #[test]
    fn resolve_host_resolves_localhost() {
        let addrs = resolve_host("localhost", 8080, Duration::from_secs(5)).expect("localhost");
        assert!(
            !addrs.is_empty(),
            "localhost must resolve to at least one address"
        );
        assert!(addrs.iter().all(|addr| addr.port() == 8080));
    }

    #[test]
    fn udp_exchange_times_out() {
        // 192.0.2.1 is unroutable; no reply will come within 200ms.
        let target: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let start = std::time::Instant::now();
        let res = udp_exchange(&target, b"ping", Duration::from_millis(200), None);
        assert!(res.is_err());
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    // -- which resolver answers, in which order ----------------------------

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("ip literal")
    }

    /// How many times the stub engine was consulted.
    ///
    /// A `fn` pointer cannot capture, so the stub records through a static. Only
    /// one test below reads it, and it resets before use.
    static ENGINE_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn engine_answers(_host: &str, want_v6: bool) -> Option<io::Result<Vec<IpAddr>>> {
        ENGINE_CALLS.fetch_add(1, Ordering::SeqCst);
        Some(Ok(if want_v6 {
            vec![ip("2001:db8::7")]
        } else {
            vec![ip("10.9.8.7")]
        }))
    }

    fn engine_absent(_host: &str, _want_v6: bool) -> Option<io::Result<Vec<IpAddr>>> {
        None
    }

    fn engine_must_not_be_asked(_host: &str, _want_v6: bool) -> Option<io::Result<Vec<IpAddr>>> {
        panic!("a literal must never reach a resolver")
    }

    /// The engine's answer wins, both families are asked for, and the system
    /// resolver is not consulted — `node.invalid` cannot resolve, so a fallback
    /// would show up as an error instead of an answer.
    #[test]
    fn the_engine_answers_first_and_for_both_families() {
        ENGINE_CALLS.store(0, Ordering::SeqCst);
        let addresses =
            resolve_host_all_with("node.invalid", Duration::from_secs(2), engine_answers)
                .expect("the engine answered");
        assert_eq!(
            addresses,
            vec![ip("10.9.8.7"), ip("2001:db8::7")],
            "IPv4 must stay first: the caller dials in the order it is handed"
        );
        assert_eq!(
            ENGINE_CALLS.load(Ordering::SeqCst),
            2,
            "an IPv6 address the rule could have matched must not be skipped"
        );
    }

    #[test]
    fn a_literal_needs_no_resolver() {
        let addresses =
            resolve_host_all_with("10.1.2.3", Duration::from_secs(1), engine_must_not_be_asked)
                .expect("a literal resolves to itself");
        assert_eq!(addresses, vec![ip("10.1.2.3")]);
    }

    /// With no engine DNS configured, the system resolver is the path — which is
    /// what every caller had before the engine had a resolver at all.
    #[test]
    fn without_engine_dns_the_system_resolver_answers() {
        let addresses = resolve_host_all_with("localhost", Duration::from_secs(5), engine_absent)
            .expect("localhost resolves");
        assert!(!addresses.is_empty());
        assert!(addresses.iter().all(|address| address.is_loopback()));
    }

    /// A name nothing can resolve is an error, not an empty success: the router
    /// distinguishes the two when it decides whether a rule saw an address.
    #[test]
    fn a_name_nothing_can_resolve_is_an_error() {
        assert!(resolve_host_all_with(
            "nothing-can-resolve-this.invalid",
            Duration::from_secs(5),
            engine_absent
        )
        .is_err());
    }
}
