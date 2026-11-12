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
use std::time::{Duration, Instant};

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

/// Exempt an outbound socket from the engine's own tunnel (Android, OHOS).
///
/// The engine **is** the VPN. On the OEM builds that route the VPN app's
/// own traffic into its own TUN, an unprotected outbound socket loops
/// straight back into the netstack — `VpnService.protect` (Android) and the
/// `vpnConnection.protect` callback behind `set_protect_callback` (OHOS) must be
/// invoked before `connect`/`bind` for the routing decision to stick. A no-op on
/// every other platform.
///
/// Returns `PermissionDenied` when protection fails, including a missing callback
/// while a VPN descriptor is installed. Callers must propagate this error before
/// connecting or sending data. OHOS may instead protect the entire process.
#[cfg(any(target_os = "android", target_env = "ohos"))]
pub fn protect_outbound_fd(fd: i32) -> io::Result<()> {
    #[cfg(target_os = "android")]
    let vpn_active = crate::netstack::get_android_vpn_fd() >= 0;
    #[cfg(target_env = "ohos")]
    let vpn_active =
        crate::netstack::get_ohos_vpn_fd() >= 0 && !crate::netstack::is_ohos_process_protected();

    if (vpn_active || crate::netstack::has_protect_callback())
        && !crate::netstack::protect_socket(fd)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VPN refused outbound socket protection",
        ));
    }
    Ok(())
}

/// See [`protect_outbound_fd`]; this variant is a no-op.
#[cfg(not(any(target_os = "android", target_env = "ohos")))]
pub fn protect_outbound_fd(_fd: i32) -> io::Result<()> {
    Ok(())
}

/// Interface the engine's own sockets are pinned to while a TUN route table
/// is in place.
///
/// The Windows data path captures every route into the Wintun adapter, which
/// includes the engine's own dials: a DIRECT connection would enter the TUN,
/// be routed back to the engine and dial again, forever. Pinning each outbound
/// socket to the physical interface — the same mechanism sing-box and mihomo
/// use — is what lets the engine's traffic bypass the tunnel it installed.
/// `0` means "not pinned", which is the state outside TUN mode.
#[cfg(windows)]
static OUTBOUND_INTERFACE_INDEX: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(0);

/// Pin (or unpin) outbound sockets to one interface index.
///
/// Called by the Windows route manager right before it installs capture
/// routes and right after it removes them, so the pin exists exactly while
/// the tunnel does. A no-op elsewhere.
#[cfg(windows)]
pub fn set_outbound_interface_index(index: Option<u32>) {
    let index = index.unwrap_or(0);
    if OUTBOUND_INTERFACE_INDEX.swap(index, std::sync::atomic::Ordering::SeqCst) != index {
        courierust::courierust_net::outbound::network_changed();
    }
}

/// See [`set_outbound_interface_index`]; no-op on non-Windows platforms.
#[cfg(not(windows))]
pub fn set_outbound_interface_index(_index: Option<u32>) {}

#[cfg(windows)]
fn outbound_interface_index() -> Option<u32> {
    let index = OUTBOUND_INTERFACE_INDEX.load(std::sync::atomic::Ordering::SeqCst);
    (index != 0).then_some(index)
}

/// Apply `IP_UNICAST_IF` / `IPV6_UNICAST_IF` to a freshly created socket.
///
/// The option only affects unicast route selection for the address family it
/// is set on, IPv4 carries the index in network byte order; IPv6 uses host byte order (per the
/// WinSock documentation). A loopback destination never needs the pin and is
/// left alone, so loopback traffic keeps taking the loopback route.
///
/// # Safety
///
/// The crate denies `unsafe` in this module tree; this is the single audited
/// exception, because `setsockopt` has no safe wrapper and there is no other
/// way to pin a socket to an interface on Windows. The unsafe surface is one
/// call: a scalar option written from a stack value that outlives the call,
/// against a socket this function owns, with the result checked.
#[cfg(windows)]
#[allow(unsafe_code)]
fn apply_outbound_interface_raw(
    raw: std::os::windows::io::RawSocket,
    destination: std::net::IpAddr,
) -> io::Result<()> {
    const UNICAST_IF: libc::c_int = 31;
    const IPPROTO_IP: libc::c_int = 0;
    const IPPROTO_IPV6: libc::c_int = 41;

    let Some(index) = outbound_interface_index() else {
        return Ok(());
    };
    if destination.is_loopback() {
        return Ok(());
    }

    let ipv6 = destination.is_ipv6();
    let value = if ipv6 { index } else { index.to_be() };
    let level = if ipv6 { IPPROTO_IPV6 } else { IPPROTO_IP };
    let result = unsafe {
        libc::setsockopt(
            raw as libc::SOCKET,
            level,
            UNICAST_IF,
            &value as *const u32 as *const libc::c_char,
            std::mem::size_of::<u32>() as libc::c_int,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// See [`apply_outbound_interface_raw`]; the `socket2` spelling.
#[cfg(windows)]
fn apply_outbound_interface(
    sock: &socket2::Socket,
    destination: std::net::IpAddr,
) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    apply_outbound_interface_raw(sock.as_raw_socket(), destination)
}

/// See [`apply_outbound_interface_raw`]; no-op on non-Windows platforms.
#[cfg(not(windows))]
fn apply_outbound_interface(
    _sock: &socket2::Socket,
    _destination: std::net::IpAddr,
) -> io::Result<()> {
    Ok(())
}

/// Pin a `std` UDP socket to the engine's physical interface (Windows).
///
/// Sockets that the engine builds through [`udp_bind_for`] are pinned there;
/// this is for the ones a transport builds itself — the QUIC client's socket
/// is the caller — whose datagrams would otherwise follow the TUN capture
/// route and re-enter the engine's own netstack.
#[cfg(windows)]
pub fn pin_outbound_udp_socket(udp: &std::net::UdpSocket, destination: std::net::IpAddr) {
    use std::os::windows::io::AsRawSocket;
    if let Err(error) = apply_outbound_interface_raw(udp.as_raw_socket(), destination) {
        tracing::warn!("Cannot pin outbound UDP socket: {error}");
    }
}

/// See [`pin_outbound_udp_socket`]; a no-op off Windows.
#[cfg(not(windows))]
pub fn pin_outbound_udp_socket(_udp: &std::net::UdpSocket, _destination: std::net::IpAddr) {}

/// Exempt a `socket2` socket from the engine's own tunnel.
fn protect_socket2(sock: &socket2::Socket) -> io::Result<()> {
    #[cfg(any(target_os = "android", target_env = "ohos"))]
    {
        use std::os::fd::AsRawFd;
        protect_outbound_fd(sock.as_raw_fd())?;
    }
    #[cfg(not(any(target_os = "android", target_env = "ohos")))]
    let _ = sock;
    Ok(())
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
    protect_socket2(&sock)?;
    apply_outbound_interface(&sock, addr.ip())?;
    sock.connect_timeout(&(*addr).into(), timeout)?;
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
    connect_host_with(host, port, timeout, resolve_host)
}

fn connect_host_with(
    host: &str,
    port: u16,
    timeout: Duration,
    resolve: impl FnOnce(&str, u16, Duration) -> io::Result<Vec<SocketAddr>>,
) -> io::Result<TcpStream> {
    let started = Instant::now();
    let addrs = resolve(host, port, timeout)?;
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no addresses for {host}:{port}"),
        ));
    }

    let remaining = timeout.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "DNS exhausted the connection deadline",
        ));
    }
    if tcp_concurrent() && addrs.len() > 1 {
        return connect_first(&addrs, remaining);
    }

    let mut last = None;
    for (index, addr) in addrs.iter().enumerate() {
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "connection deadline exhausted",
            ));
        }
        let per = remaining / (addrs.len() - index) as u32;
        if per.is_zero() {
            break;
        }
        match connect(addr, per) {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses")))
}

/// Race the first `MAX_CONCURRENT_DIALS` candidates and keep the first success.
///
/// The losing sockets are abandoned rather than waited for: their threads end
/// when their own connect completes or times out, which is bounded by `timeout`.
/// Waiting for them would give back exactly the latency this exists to remove.
fn connect_first(addrs: &[SocketAddr], timeout: Duration) -> io::Result<TcpStream> {
    if addrs.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no addresses"));
    }
    if timeout.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TCP connect timeout must be nonzero",
        ));
    }

    let started = Instant::now();
    let (tx, rx) = mpsc::channel();
    let attempts = addrs.len().min(MAX_CONCURRENT_DIALS);

    for addr in addrs.iter().copied().take(attempts) {
        let result_tx = tx.clone();
        let spawned = std::thread::Builder::new()
            .name("corduit-connect".into())
            .spawn(move || {
                let remaining = timeout.saturating_sub(started.elapsed());
                let result = if remaining.is_zero() {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "TCP dial timed out",
                    ))
                } else {
                    connect(&addr, remaining)
                };
                let _ = result_tx.send(result);
            });
        if let Err(error) = spawned {
            let _ = tx.send(Err(error));
        }
    }
    drop(tx);
    collect_dials(rx, attempts, started, timeout)
}

/// Collect dial results against one shared budget. An earlier failure must not
/// hide a later success, extend the deadline, or mask an unfinished attempt.
fn collect_dials(
    rx: mpsc::Receiver<io::Result<TcpStream>>,
    attempts: usize,
    started: Instant,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let mut last: Option<io::Error> = None;
    for _ in 0..attempts {
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TCP dial timed out",
            ));
        }
        match rx.recv_timeout(remaining) {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => last = Some(error),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TCP dial timed out",
                ));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(io::Error::other("TCP dial worker exited without a result"));
            }
        }
    }

    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses")))
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

/// Resolve within a bounded wait, honoring configured DNS for TCP, UDP and UI.
/// System DNS is permitted only when there is no engine DNS configuration.
pub fn resolve_host(host: &str, port: u16, timeout: Duration) -> io::Result<Vec<SocketAddr>> {
    resolve_host_with(host, port, timeout, crate::dns::engine_resolver::resolve)
}

type AddressLookup = fn(&str, u16) -> Option<io::Result<Vec<SocketAddr>>>;

fn resolve_host_with(
    host: &str,
    port: u16,
    timeout: Duration,
    engine: AddressLookup,
) -> io::Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let host_owned = host.to_owned();
    bounded_lookup(&format!("{host}:{port}"), timeout, move || {
        let addresses = match engine(&host_owned, port) {
            Some(result) => result?,
            None => resolve_system(&host_owned, port)?,
        };
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "DNS returned no addresses",
            ));
        }
        Ok(addresses)
    })
}

/// The last resort for a dial, with the TUN in mind.
///
/// While a TUN's DNS capture is installed, the OS resolver is pointed at the
/// tunnel — which is this process — so asking it routes the query back into
/// the engine and answers with a fake address the dial can only re-enter.
/// The physical servers captured before the capture was installed answer
/// instead, queried directly from a pinned socket so the exchange never
/// touches the tunnel. With no tunnel up this is plain `to_socket_addrs`.
fn resolve_system(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    if crate::dns::trusted::is_active() {
        let addresses = crate::dns::trusted::resolve_any(host)?;
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no addresses for {host}"),
            ));
        }
        return Ok(addresses
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect());
    }
    (host, port)
        .to_socket_addrs()
        .map(|iter| iter.collect::<Vec<SocketAddr>>())
}

/// As [`resolve_system`], without a port: the address list a rule matches on.
fn resolve_system_ips(host: &str) -> io::Result<Vec<IpAddr>> {
    if crate::dns::trusted::is_active() {
        return crate::dns::trusted::resolve_any(host);
    }
    let mut addresses: Vec<IpAddr> = Vec::new();
    for address in (host, 0u16).to_socket_addrs()? {
        extend_unique(&mut addresses, [address.ip()]);
    }
    Ok(addresses)
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
/// system resolver is used only when no engine resolver is configured.
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
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let host_owned = host.to_owned();
    bounded_lookup(host, timeout, move || {
        engine_then_system(&host_owned, engine)
    })
}

/// Use engine DNS exclusively when configured; use OS DNS only without it.
///
/// The two families are asked for at the same time. They are independent
/// queries, each with its own budget inside the resolver, and probing them
/// one after the other would double the worst-case latency of every
/// dual-stack name — which is the common case.
fn engine_then_system(host: &str, engine: EngineLookup) -> io::Result<Vec<IpAddr>> {
    let (v4, v6) = std::thread::scope(|scope| {
        let v4 = scope.spawn(|| engine(host, false));
        let v6 = scope.spawn(|| engine(host, true));
        (
            v4.join()
                .unwrap_or_else(|_| Some(Err(io::Error::other("IPv4 DNS worker panicked")))),
            v6.join()
                .unwrap_or_else(|_| Some(Err(io::Error::other("IPv6 DNS worker panicked")))),
        )
    });

    let mut found: Vec<IpAddr> = Vec::new();
    let mut configured = false;
    for outcome in [v4, v6] {
        match outcome {
            Some(Ok(addresses)) => {
                configured = true;
                extend_unique(&mut found, addresses);
            }
            Some(Err(error)) => {
                configured = true;
                tracing::debug!("engine DNS could not resolve {host}: {error}");
            }
            None => {}
        }
    }
    if !found.is_empty() {
        return Ok(found);
    }
    if configured {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "configured DNS returned no acceptable address for '{host}'; system fallback is disabled"
            ),
        ));
    }

    let mut addresses: Vec<IpAddr> = Vec::new();
    for address in resolve_system_ips(host)? {
        extend_unique(&mut addresses, [address]);
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
///
/// No interface pin is applied here: the bind address of a wildcard socket
/// says nothing about where its datagrams will go, and pinning a socket that
/// answers a local client would push loopback traffic onto the physical
/// interface. Callers that dial a known unicast destination use
/// [`udp_bind_for`].
pub fn udp_bind(bind: SocketAddr, read_timeout: Duration) -> io::Result<UdpSocket> {
    udp_bind_for(bind, read_timeout, None)
}

/// As [`udp_bind`], pinning the socket to the engine's physical interface
/// when `destination` is a known, non-loopback unicast address.
///
/// This is the UDP half of the TUN bypass: without the pin, a datagram sent
/// by the engine's own outbound takes the capture route, re-enters the TUN
/// and loops. The pin must be decided *per destination*, which is why it is a
/// parameter rather than a property of the bind address.
pub fn udp_bind_for(
    bind: SocketAddr,
    read_timeout: Duration,
    destination: Option<IpAddr>,
) -> io::Result<UdpSocket> {
    let domain = if bind.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    protect_socket2(&sock)?;
    if let Some(addr) = destination {
        apply_outbound_interface(&sock, addr)?;
    }
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
    let sock = udp_bind_for(bind, timeout, Some(target.ip()))?;
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
    #[test]
    fn dns_time_is_charged_to_the_connection_deadline() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let result = super::connect_host_with(
            "test.invalid",
            address.port(),
            std::time::Duration::from_millis(1),
            |_, _, _| {
                std::thread::sleep(std::time::Duration::from_millis(10));
                Ok(vec![address])
            },
        );
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    const DIAL_TEST_TIMEOUT: Duration = Duration::from_secs(5);

    #[test]
    fn connect_timeout_fails_fast() {
        let addr: SocketAddr = "192.0.2.1:65000".parse().unwrap();
        let start = std::time::Instant::now();
        let res = connect(&addr, Duration::from_millis(300));
        assert!(res.is_err());
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    fn dial_listener() -> TcpListener {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        listener
            .set_nonblocking(true)
            .expect("non-blocking listener");
        listener
    }

    /// Keep listeners and accepted streams owned by the test. Closing an
    /// accepted socket while the client is still polling connect can produce
    /// POLLHUP on Windows. No detached accept thread or early close is needed:
    /// the kernel completes the handshake before the test calls accept.
    fn accept_dial(listener: &TcpListener) -> TcpStream {
        let start = std::time::Instant::now();
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).expect("blocking peer");
                    configure(&stream, Some(DIAL_TEST_TIMEOUT), Some(DIAL_TEST_TIMEOUT))
                        .expect("peer timeouts");
                    return stream;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(start.elapsed() < DIAL_TEST_TIMEOUT, "dial never arrived");
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        }
    }

    fn assert_no_dial(listener: &TcpListener) {
        assert_eq!(
            listener.accept().expect_err("unexpected dial").kind(),
            io::ErrorKind::WouldBlock
        );
    }

    fn assert_round_trip(client: &mut TcpStream, peer: &mut TcpStream) {
        assert!(client.nodelay().expect("TCP_NODELAY"));
        configure(client, Some(DIAL_TEST_TIMEOUT), Some(DIAL_TEST_TIMEOUT))
            .expect("client timeouts");
        client.write_all(b"ping").expect("client write");
        let mut message = [0; 4];
        peer.read_exact(&mut message).expect("peer read");
        assert_eq!(&message, b"ping");
        peer.write_all(b"pong").expect("peer write");
        client.read_exact(&mut message).expect("client read");
        assert_eq!(&message, b"pong");
    }

    /// Racing dials every candidate; dialling in order stops at the first one
    /// that answers.
    ///
    /// Observed on the listeners rather than timed: the difference is which
    /// sockets get opened, and a timing assertion would depend on how fast an
    /// unreachable address happens to fail on the machine running the test.
    #[test]
    fn racing_dials_every_candidate() {
        let first = dial_listener();
        let second = dial_listener();
        let first_addr = first.local_addr().unwrap();
        let second_addr = second.local_addr().unwrap();

        let mut stream =
            connect(&first_addr, DIAL_TEST_TIMEOUT).expect("the first listener accepts");
        let mut peer = accept_dial(&first);
        assert_round_trip(&mut stream, &mut peer);
        assert_no_dial(&second);

        let mut winner = connect_first(&[first_addr, second_addr], DIAL_TEST_TIMEOUT)
            .expect("at least one candidate answers");
        let mut first_peer = accept_dial(&first);
        let mut second_peer = accept_dial(&second);
        let (winner_peer, loser_peer) = if winner.peer_addr().unwrap() == first_addr {
            (&mut first_peer, &mut second_peer)
        } else {
            (&mut second_peer, &mut first_peer)
        };
        assert_round_trip(&mut winner, winner_peer);
        assert_eq!(loser_peer.read(&mut [0]).expect("loser closes"), 0);
        drop(winner);
        assert_eq!(winner_peer.read(&mut [0]).expect("winner closes"), 0);
        assert_no_dial(&first);
        assert_no_dial(&second);
    }

    #[test]
    fn racing_limits_concurrent_dials() {
        let listeners: Vec<_> = (0..MAX_CONCURRENT_DIALS + 1)
            .map(|_| dial_listener())
            .collect();
        let addresses: Vec<_> = listeners.iter().map(|l| l.local_addr().unwrap()).collect();
        let winner = connect_first(&addresses, DIAL_TEST_TIMEOUT).expect("a candidate answers");
        let peers: Vec<_> = listeners[..MAX_CONCURRENT_DIALS]
            .iter()
            .map(accept_dial)
            .collect();
        drop(winner);
        for mut peer in peers {
            assert_eq!(peer.read(&mut [0]).expect("dial closes"), 0);
        }
        assert_no_dial(&listeners[MAX_CONCURRENT_DIALS]);
    }

    #[test]
    fn racing_survives_a_failed_candidate() {
        for kind in [io::ErrorKind::ConnectionRefused, io::ErrorKind::TimedOut] {
            for failure_first in [true, false] {
                let listener = dial_listener();
                let address = listener.local_addr().unwrap();
                let stream = connect(&address, DIAL_TEST_TIMEOUT).unwrap();
                let mut peer = accept_dial(&listener);
                let (tx, rx) = mpsc::channel();
                let failure = Err(io::Error::new(kind, "candidate failed"));
                if failure_first {
                    tx.send(failure).unwrap();
                    tx.send(Ok(stream)).unwrap();
                } else {
                    tx.send(Ok(stream)).unwrap();
                    tx.send(failure).unwrap();
                }
                drop(tx);
                let mut winner = collect_dials(rx, 2, Instant::now(), DIAL_TEST_TIMEOUT)
                    .expect("a failed candidate must not hide a successful one");
                assert_eq!(winner.peer_addr().unwrap(), address);
                assert_round_trip(&mut winner, &mut peer);
            }
        }
    }

    #[test]
    fn racing_preserves_the_last_completed_error() {
        for kind in [io::ErrorKind::ConnectionRefused, io::ErrorKind::TimedOut] {
            let (tx, rx) = mpsc::channel();
            tx.send(Err(io::Error::other("first failure"))).unwrap();
            tx.send(Err(io::Error::new(kind, "last failure"))).unwrap();
            drop(tx);
            let error = collect_dials(rx, 2, Instant::now(), DIAL_TEST_TIMEOUT).unwrap_err();
            assert_eq!(error.kind(), kind);
            assert_eq!(error.to_string(), "last failure");
        }
    }

    #[test]
    fn racing_timeout_does_not_report_an_earlier_refusal() {
        let (tx, rx) = mpsc::channel();
        tx.send(Err(io::ErrorKind::ConnectionRefused.into()))
            .unwrap();
        // Keep the sender alive to represent a second, unfinished attempt.
        let error = collect_dials(rx, 2, Instant::now(), Duration::from_millis(10)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        drop(tx);
    }

    #[test]
    fn racing_does_not_restart_an_expired_budget() {
        let (tx, rx) = mpsc::channel();
        tx.send(Err(io::ErrorKind::ConnectionRefused.into()))
            .unwrap();
        drop(tx);
        let timeout = Duration::from_secs(1);
        let started = Instant::now().checked_sub(timeout).unwrap();
        let error = collect_dials(rx, 1, started, timeout).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn racing_reports_a_worker_that_exits_without_a_result() {
        let (tx, rx) = mpsc::channel();
        tx.send(Err(io::ErrorKind::ConnectionRefused.into()))
            .unwrap();
        drop(tx);
        let error = collect_dials(rx, 2, Instant::now(), DIAL_TEST_TIMEOUT).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.to_string().contains("worker exited without a result"));
    }

    #[test]
    fn racing_rejects_empty_candidates_and_zero_timeout() {
        assert_eq!(
            connect_first(&[], DIAL_TEST_TIMEOUT).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        let listener = dial_listener();
        assert_eq!(
            connect_first(&[listener.local_addr().unwrap()], Duration::ZERO)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_no_dial(&listener);
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
    fn dial_and_display_dns_never_replace_a_configured_failure() {
        let empty: AddressLookup = |_, _| Some(Ok(Vec::new()));
        let failed: AddressLookup = |_, _| {
            Some(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "policy denied",
            )))
        };
        for engine in [empty, failed] {
            assert!(resolve_host_with("localhost", 443, Duration::from_secs(2), engine).is_err());
        }
        let answer: AddressLookup = |_, port| {
            Some(Ok(vec![SocketAddr::new(
                "203.0.113.7".parse().unwrap(),
                port,
            )]))
        };
        assert_eq!(
            resolve_host_with("localhost", 443, Duration::from_secs(2), answer).unwrap(),
            vec!["203.0.113.7:443".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn configured_dns_failures_cannot_escape_via_localhost_os_resolution() {
        let empty: EngineLookup = |_, _| Some(Ok(Vec::new()));
        let failed: EngineLookup = |_, _| Some(Err(io::Error::other("policy denied")));
        let panicked: EngineLookup = |_, _| panic!("resolver worker failed");
        for engine in [empty, failed, panicked] {
            let error = resolve_host_all_with("localhost", Duration::from_secs(2), engine)
                .expect_err("configured DNS must not be bypassed by the OS resolver");
            assert!(error.to_string().contains("system fallback is disabled"));
        }
    }

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
        assert!(
            resolve_host_all_with(
                "nothing-can-resolve-this.invalid",
                Duration::from_secs(5),
                engine_absent
            )
            .is_err()
        );
    }
}
