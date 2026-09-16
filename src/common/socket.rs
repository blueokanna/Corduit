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
//!   with the same per-attempt budget.
//! * [`configure`] applies nodelay / keepalive / read / write timeouts.
//! * [`udp_exchange`] performs a one-shot UDP request/reply on a fresh
//!   socket, immune to Windows ICMP poisoning.

use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

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

/// Resolve a hostname to socket addresses with a bounded wait.
///
/// The system resolver is a blocking call that cannot be interrupted, so the
/// lookup runs on a thread of its own and the caller waits at most `timeout`:
/// a resolver that stalls (a dead DNS server, retried a few times) produces
/// `TimedOut` instead of pinning the calling worker for the resolver's whole
/// retry budget. The lookup thread is detached — whatever it finds after the
/// caller gave up is dropped with the channel.
pub fn resolve_host(host: &str, port: u16, timeout: Duration) -> io::Result<Vec<SocketAddr>> {
    let (tx, rx) = std::sync::mpsc::channel();
    let host_owned = host.to_owned();
    std::thread::Builder::new()
        .name("corduit-resolve".into())
        .spawn(move || {
            let result = (host_owned.as_str(), port)
                .to_socket_addrs()
                .map(|iter| iter.collect::<Vec<SocketAddr>>());
            let _ = tx.send(result);
        })
        .map_err(|e| io::Error::other(format!("failed to spawn the resolver thread: {e}")))?;

    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("resolving {host}:{port} timed out"),
        )),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err(io::Error::other("resolver thread panicked"))
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
}
