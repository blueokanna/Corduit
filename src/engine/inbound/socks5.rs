//! SOCKS5 inbound (RFC 1928, RFC 1929 authentication), synchronous.
//!
//! This module owns the workspace's **only** SOCKS5 implementation:
//! [`serve_connection`] is the whole protocol path for one accepted socket —
//! greeting and authentication, the request, then either a `CONNECT` relay
//! through the matched outbound or a `UDP ASSOCIATE` relay — and two callers
//! share it:
//!
//! * [`Socks5Inbound`] (the `socks5` inbound) wraps it in a listener;
//! * [`MixedInbound`](super::mixed::MixedInbound) sniffs the first byte of
//!   every connection and forwards SOCKS5 traffic here.
//!
//! Relays run on the connection's own thread (bounded by the listener's
//! connection budget), because a relay blocks for as long as the session
//! lives — the UDP relay gets a thread of its own for the same reason.
//!
//! `UDP ASSOCIATE` forwards each datagram as a one-shot request/reply through
//! the matched outbound and rebuilds the SOCKS5 UDP envelope on the way back.
//! Only the client that owns the TCP control connection may use its relay
//! socket (source-IP check), so the bound UDP port is never an open relay.

use crate::common::listener::ConnectionListener;
use crate::engine::config::InboundConfig;
use crate::engine::connection_tracker::{global_tracker, TrackedConnection};
use crate::engine::error::{Error, Result};
use crate::engine::inbound::auth::{socks5_userpass, InboundAuth, SOCKS5_AUTH_USERPASS};
use crate::engine::inbound::{bind_tcp_listener, InboundListener};
use crate::engine::outbound::{OutboundManager, TargetAddr};
use crate::engine::routing::Router;
use parking_lot::Mutex;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// UDP ASSOCIATE lifetime: the relay socket gives up after this much
/// silence, so a client that vanishes without closing its control
/// connection cannot hold a UDP port forever.
const UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(300);
/// Handshake read/write timeout (a silent client is dropped after this).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Read/write timeout applied once a connection enters the relay phase.
const RELAY_TIMEOUT: Duration = Duration::from_secs(60);
/// Upper bound on concurrently served SOCKS5 connections.
const MAX_CONNECTIONS: usize = 2048;

/// SOCKS5 protocol version byte.
const SOCKS5_VERSION: u8 = 0x05;
/// SOCKS5 `CONNECT` command.
const SOCKS5_CMD_CONNECT: u8 = 0x01;
/// SOCKS5 `UDP ASSOCIATE` command.
const SOCKS5_CMD_UDP_ASSOCIATE: u8 = 0x03;
/// SOCKS5 "no authentication required" method.
const SOCKS5_AUTH_NONE: u8 = 0x00;
/// SOCKS5 reply: succeeded.
const SOCKS5_REPLY_SUCCESS: u8 = 0x00;
/// SOCKS5 reply: general failure.
const SOCKS5_REPLY_FAILURE: u8 = 0x01;
/// SOCKS5 reply: command not supported.
const SOCKS5_REPLY_UNSUPPORTED: u8 = 0x07;
/// SOCKS5 reply: address type not supported.
const SOCKS5_REPLY_BAD_ADDRESS: u8 = 0x08;

/// Address forms of a SOCKS5 request.
#[derive(Debug)]
enum Socks5Addr {
    Domain(String),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

/// Serve one accepted SOCKS5 connection.
///
/// `kind` labels the connection in the traffic tracker (`socks5` / `mixed`).
/// Returns after the relay finishes; the caller owns the socket until then.
pub(crate) fn serve_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    router: Arc<Router>,
    outbound_manager: Arc<OutboundManager>,
    auth: Arc<InboundAuth>,
    kind: &'static str,
) -> Result<()> {
    let _ = stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
    let _ = stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT));

    if !perform_handshake(&mut stream, &auth)? {
        return Err(Error::protocol_with_info(
            "SOCKS5 handshake failed",
            "SOCKS5",
        ));
    }
    let (target_addr, target_port, command) = read_request(&mut stream)?;

    match command {
        SOCKS5_CMD_CONNECT => handle_connect(
            stream,
            peer_addr,
            target_addr,
            target_port,
            router,
            outbound_manager,
            kind,
        ),
        SOCKS5_CMD_UDP_ASSOCIATE => {
            handle_udp_associate(stream, peer_addr, router, outbound_manager)
        }
        _ => {
            send_reply(&mut stream, SOCKS5_REPLY_UNSUPPORTED)?;
            Err(Error::protocol_with_info(
                "Unsupported SOCKS5 command",
                "SOCKS5",
            ))
        }
    }
}

/// RFC 1928 §3: greeting, method selection, optional RFC 1929 credentials.
///
/// Returns `Ok(false)` when the connection is not (or cannot be) a SOCKS5
/// session; the caller closes it.
fn perform_handshake(stream: &mut TcpStream, auth: &InboundAuth) -> Result<bool> {
    let mut header = [0u8; 2];
    stream
        .read_exact(&mut header)
        .map_err(|e| Error::network(format!("Failed to read SOCKS5 greeting: {e}")))?;
    if header[0] != SOCKS5_VERSION {
        return Ok(false);
    }

    let mut methods = vec![0u8; header[1] as usize];
    stream
        .read_exact(&mut methods)
        .map_err(|e| Error::network(format!("Failed to read SOCKS5 methods: {e}")))?;

    if auth.required() {
        if !methods.contains(&SOCKS5_AUTH_USERPASS) {
            let _ = stream.write_all(&[SOCKS5_VERSION, 0xFF]);
            return Ok(false);
        }
        stream
            .write_all(&[SOCKS5_VERSION, SOCKS5_AUTH_USERPASS])
            .map_err(|e| Error::network(format!("Failed to send method selection: {e}")))?;
        return socks5_userpass(stream, auth);
    }

    if !methods.contains(&SOCKS5_AUTH_NONE) {
        let _ = stream.write_all(&[SOCKS5_VERSION, 0xFF]);
        return Ok(false);
    }
    stream
        .write_all(&[SOCKS5_VERSION, SOCKS5_AUTH_NONE])
        .map_err(|e| Error::network(format!("Failed to send method selection: {e}")))?;
    Ok(true)
}

/// RFC 1928 §4: `VER CMD RSV ATYP DST.ADDR DST.PORT`.
///
/// Every field is length-prefixed or fixed-width, so a request is read with a
/// bounded number of bytes and no allocation the client can steer.
fn read_request(stream: &mut TcpStream) -> Result<(Socks5Addr, u16, u8)> {
    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .map_err(|e| Error::network(format!("Failed to read SOCKS5 request: {e}")))?;
    if head[0] != SOCKS5_VERSION {
        return Err(Error::protocol("Invalid SOCKS5 version in request"));
    }
    if head[2] != 0x00 {
        return Err(Error::protocol("Non-zero reserved byte in SOCKS5 request"));
    }
    let command = head[1];

    let (addr, port) = match head[3] {
        0x01 => {
            let mut addr = [0u8; 4];
            stream
                .read_exact(&mut addr)
                .map_err(|e| Error::network(format!("Failed to read IPv4 address: {e}")))?;
            (Socks5Addr::Ipv4(Ipv4Addr::from(addr)), read_port(stream)?)
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .map_err(|e| Error::network(format!("Failed to read domain length: {e}")))?;
            let mut domain = vec![0u8; len[0] as usize];
            stream
                .read_exact(&mut domain)
                .map_err(|e| Error::network(format!("Failed to read domain: {e}")))?;
            let domain = String::from_utf8(domain)
                .map_err(|_| Error::protocol("Invalid domain encoding"))?;
            (Socks5Addr::Domain(domain), read_port(stream)?)
        }
        0x04 => {
            let mut addr = [0u8; 16];
            stream
                .read_exact(&mut addr)
                .map_err(|e| Error::network(format!("Failed to read IPv6 address: {e}")))?;
            (Socks5Addr::Ipv6(Ipv6Addr::from(addr)), read_port(stream)?)
        }
        _ => {
            send_reply(stream, SOCKS5_REPLY_BAD_ADDRESS)?;
            return Err(Error::protocol("Unsupported SOCKS5 address type"));
        }
    };
    Ok((addr, port, command))
}

/// The two-byte big-endian port of a SOCKS5 request.
fn read_port(stream: &mut TcpStream) -> Result<u16> {
    let mut port = [0u8; 2];
    stream
        .read_exact(&mut port)
        .map_err(|e| Error::network(format!("Failed to read port: {e}")))?;
    Ok(u16::from_be_bytes(port))
}

/// Relay a `CONNECT` request through the matched outbound.
fn handle_connect(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    target_addr: Socks5Addr,
    target_port: u16,
    router: Arc<Router>,
    outbound_manager: Arc<OutboundManager>,
    kind: &'static str,
) -> Result<()> {
    let (domain, ip) = match &target_addr {
        Socks5Addr::Domain(domain) => (Some(domain.clone()), None),
        Socks5Addr::Ipv4(ip) => (None, Some(IpAddr::V4(*ip))),
        Socks5Addr::Ipv6(ip) => (None, Some(IpAddr::V6(*ip))),
    };
    let target = match &target_addr {
        Socks5Addr::Domain(domain) => TargetAddr::new_domain(domain.clone(), target_port),
        Socks5Addr::Ipv4(ip) => TargetAddr::new_ip(SocketAddr::new(IpAddr::V4(*ip), target_port)),
        Socks5Addr::Ipv6(ip) => TargetAddr::new_ip(SocketAddr::new(IpAddr::V6(*ip), target_port)),
    };

    let outbound_tag = router.match_outbound(domain.as_deref(), ip, Some(target_port), None);
    tracing::info!("SOCKS5 CONNECT {target} -> {outbound_tag} (from {peer_addr})");

    let Some(outbound) = outbound_manager.get_proxy(&outbound_tag) else {
        tracing::error!("Outbound '{}' not found", outbound_tag);
        send_reply(&mut stream, SOCKS5_REPLY_FAILURE)?;
        return Err(Error::config(format!(
            "Outbound '{outbound_tag}' not found"
        )));
    };

    let unspecified = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    send_reply_with_addr(&mut stream, SOCKS5_REPLY_SUCCESS, unspecified)?;

    let destination_ip = match &target {
        TargetAddr::Ip(addr) => Some(addr.ip().to_string()),
        TargetAddr::Domain(domain, _) => {
            crate::common::socket::resolve_host(domain, target.port(), Duration::from_secs(3))
                .ok()
                .and_then(|addrs| addrs.into_iter().next())
                .map(|addr| addr.ip().to_string())
        }
    };

    let tracker = global_tracker();
    let tracked = tracker.track(TrackedConnection::new_with_ip(
        kind.to_string(),
        outbound_tag.clone(),
        target.host(),
        destination_ip,
        target.port(),
        "SOCKS5".to_string(),
        "tcp".to_string(),
        "SOCKS5".to_string(),
        target.to_string(),
    ));

    let _ = stream.set_read_timeout(Some(RELAY_TIMEOUT));
    let _ = stream.set_write_timeout(Some(RELAY_TIMEOUT));

    let result = outbound.relay_tcp_with_connection(
        Box::new(stream),
        target.clone(),
        Some(Arc::clone(&tracked)),
    );
    tracker.untrack(&tracked.id);
    if let Err(e) = result {
        if e.to_string().contains("cancel") {
            tracing::debug!(
                "SOCKS5 relay cancelled via '{}' to {}",
                outbound.tag(),
                target
            );
        } else {
            tracing::warn!(
                "SOCKS5 relay via '{}' to {} failed: {}",
                outbound.tag(),
                target,
                e
            );
        }
    }
    Ok(())
}

/// `UDP ASSOCIATE`: bind a relay socket, tell the client where it is, and
/// keep the association alive for as long as the TCP control connection is.
fn handle_udp_associate(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    router: Arc<Router>,
    outbound_manager: Arc<OutboundManager>,
) -> Result<()> {
    tracing::info!("SOCKS5 UDP ASSOCIATE from {peer_addr}");

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let udp_socket = crate::common::socket::udp_bind(bind_addr, UDP_SESSION_TIMEOUT)
        .map_err(|e| Error::network(format!("Failed to bind UDP relay socket: {e}")))?;
    let _ = udp_socket.set_write_timeout(Some(UDP_SESSION_TIMEOUT));
    let local_addr = udp_socket
        .local_addr()
        .map_err(|e| Error::network(format!("Failed to read UDP relay address: {e}")))?;

    tracing::info!("UDP relay listening on {local_addr} for {peer_addr}");
    send_reply_with_addr(&mut stream, SOCKS5_REPLY_SUCCESS, local_addr)?;

    let cancel = crate::common::cancel::CancellationToken::new();
    let relay_cancel = cancel.clone();
    let relay_thread = std::thread::Builder::new()
        .name("corduit-socks5-udp".into())
        .spawn(move || {
            if let Err(e) = run_udp_relay(
                udp_socket,
                peer_addr,
                router,
                outbound_manager,
                relay_cancel,
            ) {
                tracing::debug!("UDP relay error for {peer_addr}: {e}");
            }
        })
        .map_err(|e| Error::network(format!("Failed to spawn UDP relay thread: {e}")))?;

    let _ = stream.set_read_timeout(Some(RELAY_TIMEOUT));
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => break,    // client closed
            Ok(_) => continue, // nothing defined on this half
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(e) => {
                tracing::debug!("UDP ASSOCIATE control connection from {peer_addr} failed: {e}");
                break;
            }
        }
    }

    cancel.cancel();
    let _ = relay_thread.join();
    tracing::info!("UDP ASSOCIATE with {peer_addr} ended");
    Ok(())
}

/// Forward datagrams between the client and the matched outbound.
///
/// Only datagrams whose source IP matches the association's client are
/// relayed: without that check the bound UDP port would be an open relay for
/// anyone who can reach it.
fn run_udp_relay(
    udp_socket: UdpSocket,
    client_addr: SocketAddr,
    router: Arc<Router>,
    outbound_manager: Arc<OutboundManager>,
    cancel: crate::common::cancel::CancellationToken,
) -> Result<()> {
    let mut buf = vec![0u8; 65535];

    while !cancel.is_cancelled() {
        let (len, src_addr) = match udp_socket.recv_from(&mut buf) {
            Ok(result) => result,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                continue;
            }
            Err(e) => {
                tracing::debug!("UDP relay receive error: {e}");
                continue;
            }
        };

        if src_addr.ip() != client_addr.ip() {
            tracing::debug!(
                "Dropping UDP datagram from {src_addr} (association client is {client_addr})"
            );
            continue;
        }

        if len < 10 {
            continue;
        }
        if buf[2] != 0 {
            tracing::debug!("Dropping fragmented SOCKS5 UDP datagram");
            continue;
        }

        let (target, header_len) = match buf[3] {
            0x01 if len >= 10 => {
                let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                let port = u16::from_be_bytes([buf[8], buf[9]]);
                (
                    TargetAddr::new_ip(SocketAddr::new(IpAddr::V4(ip), port)),
                    10,
                )
            }
            0x03 => {
                let domain_len = buf[4] as usize;
                if len < 7 + domain_len {
                    continue;
                }
                let Ok(domain) = String::from_utf8(buf[5..5 + domain_len].to_vec()) else {
                    continue;
                };
                let port = u16::from_be_bytes([buf[5 + domain_len], buf[6 + domain_len]]);
                (TargetAddr::new_domain(domain, port), 7 + domain_len)
            }
            0x04 if len >= 22 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[4..20]);
                let port = u16::from_be_bytes([buf[20], buf[21]]);
                (
                    TargetAddr::new_ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)),
                    22,
                )
            }
            _ => continue,
        };

        let payload = &buf[header_len..len];
        if payload.is_empty() {
            continue;
        }

        let (domain, ip) = match &target {
            TargetAddr::Domain(domain, _) => (Some(domain.clone()), None),
            TargetAddr::Ip(addr) => (None, Some(addr.ip())),
        };
        let outbound_tag = router.match_outbound(domain.as_deref(), ip, Some(target.port()), None);
        let Some(outbound) = outbound_manager.get_proxy(&outbound_tag) else {
            tracing::warn!("Outbound '{}' not found for UDP", outbound_tag);
            continue;
        };
        if !outbound.supports_udp() {
            tracing::debug!("Outbound '{}' does not support UDP", outbound_tag);
            continue;
        }

        match outbound.relay_udp_packet(&target, payload) {
            Ok(response) if !response.is_empty() => {
                let packet = build_udp_reply(&target, &response);
                if let Err(e) = udp_socket.send_to(&packet, src_addr) {
                    tracing::debug!("Failed to send UDP reply: {e}");
                }
            }
            Ok(_) => {}
            Err(e) => tracing::debug!("UDP relay error via '{}': {}", outbound.tag(), e),
        }
    }
    Ok(())
}

/// Wrap an outbound reply in the SOCKS5 UDP response envelope.
fn build_udp_reply(target: &TargetAddr, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(payload.len() + 22);
    packet.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV, FRAG
    match target {
        TargetAddr::Ip(addr) => {
            match addr.ip() {
                IpAddr::V4(ip) => {
                    packet.push(0x01);
                    packet.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    packet.push(0x04);
                    packet.extend_from_slice(&ip.octets());
                }
            }
            packet.extend_from_slice(&addr.port().to_be_bytes());
        }
        TargetAddr::Domain(domain, port) => {
            let len = domain.len().min(u8::MAX as usize);
            packet.push(0x03);
            packet.push(len as u8);
            packet.extend_from_slice(&domain.as_bytes()[..len]);
            packet.extend_from_slice(&port.to_be_bytes());
        }
    }
    packet.extend_from_slice(payload);
    packet
}

/// Send a reply with the unspecified IPv4 address.
fn send_reply(stream: &mut TcpStream, reply: u8) -> Result<()> {
    let unspecified = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    send_reply_with_addr(stream, reply, unspecified)
}

/// Send a reply carrying `addr` as `BND.ADDR` / `BND.PORT`.
fn send_reply_with_addr(stream: &mut TcpStream, reply: u8, addr: SocketAddr) -> Result<()> {
    let mut packet = Vec::with_capacity(22);
    packet.extend_from_slice(&[SOCKS5_VERSION, reply, 0x00]);
    match addr.ip() {
        IpAddr::V4(ip) => {
            packet.push(0x01);
            packet.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            packet.push(0x04);
            packet.extend_from_slice(&ip.octets());
        }
    }
    packet.extend_from_slice(&addr.port().to_be_bytes());
    stream
        .write_all(&packet)
        .map_err(|e| Error::network(format!("Failed to write SOCKS5 reply: {e}")))
}

/// SOCKS5 proxy inbound listener.
pub struct Socks5Inbound {
    config: InboundConfig,
    router: Arc<Router>,
    outbound_manager: Arc<OutboundManager>,
    auth: Arc<InboundAuth>,
    running: Arc<AtomicBool>,
    server: Mutex<Option<ConnectionListener>>,
}

impl InboundListener for Socks5Inbound {
    fn start(&self) -> Result<()> {
        self.start_listener()
    }

    fn stop(&self) -> Result<()> {
        self.stop_listener()
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }
}

impl Socks5Inbound {
    /// Build the inbound. No socket is bound until [`start`](Self::start).
    pub fn new(
        config: InboundConfig,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
        auth: Arc<InboundAuth>,
    ) -> Self {
        Self {
            config,
            router,
            outbound_manager,
            auth,
            running: Arc::new(AtomicBool::new(false)),
            server: Mutex::new(None),
        }
    }

    fn start_listener(&self) -> Result<()> {
        if self.running.load(Ordering::Relaxed) {
            tracing::warn!(
                "SOCKS5 inbound already running on {}:{}",
                self.config.listen,
                self.config.port
            );
            return Ok(());
        }

        let (listener, addr) = bind_tcp_listener(&self.config.listen, self.config.port, "SOCKS5")?;
        let router = Arc::clone(&self.router);
        let outbound_manager = Arc::clone(&self.outbound_manager);
        let auth = Arc::clone(&self.auth);

        let mut server = ConnectionListener::new(listener, addr, MAX_CONNECTIONS);
        server
            .start("corduit-socks5-conn", move |stream, peer| {
                if let Err(e) = serve_connection(
                    stream,
                    peer,
                    Arc::clone(&router),
                    Arc::clone(&outbound_manager),
                    Arc::clone(&auth),
                    "socks5",
                ) {
                    tracing::debug!("SOCKS5 connection error from {peer}: {e}");
                }
            })
            .map_err(|e| {
                Error::network(format!("Failed to serve SOCKS5 inbound on {addr}: {e}"))
            })?;

        *self.server.lock() = Some(server);
        self.running.store(true, Ordering::Relaxed);
        tracing::info!("SOCKS5 inbound listening on {addr}");
        Ok(())
    }

    fn stop_listener(&self) -> Result<()> {
        tracing::info!(
            "Stopping SOCKS5 inbound on {}:{}",
            self.config.listen,
            self.config.port
        );

        let mut server = self.server.lock().take();
        if let Some(server) = server.as_mut() {
            server.stop();
        }
        self.running.store(false, Ordering::Relaxed);
        tracing::info!("SOCKS5 inbound stopped");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::config::AuthenticationConfig;
    use std::net::TcpListener;

    /// Run `f` against a connected socket pair: the returned handle is the
    /// server side, the caller drives the client side.
    fn socket_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let client = TcpStream::connect(addr).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        (server, client)
    }

    fn auth_with(user: &str, pass: &str) -> InboundAuth {
        InboundAuth::new(Some(&[AuthenticationConfig {
            username: user.to_string(),
            password: pass.to_string(),
        }]))
    }

    #[test]
    fn no_auth_handshake_is_accepted_when_open() {
        let (mut server, mut client) = socket_pair();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        assert!(perform_handshake(&mut server, &InboundAuth::default()).unwrap());
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply, [0x05, 0x00]);
    }

    #[test]
    fn no_auth_only_client_is_refused_when_credentials_are_configured() {
        let (mut server, mut client) = socket_pair();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        assert!(!perform_handshake(&mut server, &auth_with("user", "pass")).unwrap());
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(reply, [0x05, 0xFF], "no acceptable methods");
    }

    #[test]
    fn userpass_handshake_validates_the_credentials() {
        let (mut server, mut client) = socket_pair();
        client
            .write_all(&[0x05, 0x01, SOCKS5_AUTH_USERPASS])
            .unwrap();
        let mut selection = [0u8; 2];
        let auth = auth_with("user", "pass");
        let handle = std::thread::spawn(move || perform_handshake(&mut server, &auth));
        client.read_exact(&mut selection).unwrap();
        assert_eq!(selection, [0x05, SOCKS5_AUTH_USERPASS]);
        client
            .write_all(&[0x01, 4, b'u', b's', b'e', b'r', 4, b'p', b'a', b's', b's'])
            .unwrap();
        let mut status = [0u8; 2];
        client.read_exact(&mut status).unwrap();
        assert_eq!(status, [0x01, 0x00]);
        assert!(handle.join().unwrap().unwrap());
    }

    #[test]
    fn a_non_zero_reserved_byte_is_refused() {
        let (mut server, mut client) = socket_pair();
        client
            .write_all(&[0x05, SOCKS5_CMD_CONNECT, 0x01, 0x01])
            .unwrap();
        assert!(read_request(&mut server).is_err());
    }

    #[test]
    fn replies_carry_the_announced_address() {
        let (mut server, mut client) = socket_pair();
        let relay: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        send_reply_with_addr(&mut server, SOCKS5_REPLY_SUCCESS, relay).unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(&reply[..4], &[0x05, 0x00, 0x00, 0x01]);
        assert_eq!(&reply[4..8], &[127, 0, 0, 1]);
        assert_eq!(u16::from_be_bytes([reply[8], reply[9]]), 1080);
    }

    #[test]
    fn udp_reply_envelope_round_trips_ipv4() {
        let target = TargetAddr::new_ip("127.0.0.1:53".parse().unwrap());
        let packet = build_udp_reply(&target, b"dns");
        assert_eq!(&packet[..4], &[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(&packet[4..8], &[127, 0, 0, 1]);
        assert_eq!(u16::from_be_bytes([packet[8], packet[9]]), 53);
        assert_eq!(&packet[10..], b"dns");
    }

    #[test]
    fn udp_reply_envelope_round_trips_a_domain() {
        let target = TargetAddr::new_domain("example.com".to_string(), 443);
        let packet = build_udp_reply(&target, b"x");
        assert_eq!(packet[3], 0x03);
        assert_eq!(packet[4], 11);
        assert_eq!(&packet[5..16], b"example.com");
        assert_eq!(u16::from_be_bytes([packet[16], packet[17]]), 443);
        assert_eq!(&packet[18..], b"x");
    }
}
