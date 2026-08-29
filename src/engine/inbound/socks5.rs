use crate::common::cancel::CancellationToken;
use crate::engine::config::InboundConfig;
use crate::engine::connection_tracker::{global_tracker, TrackedConnection};
use crate::engine::error::{Error, Result};
use crate::engine::inbound::auth::{socks5_userpass, InboundAuth, SOCKS5_AUTH_USERPASS};
use crate::engine::inbound::{bind_tcp_listener, InboundListener};
use crate::engine::outbound::{OutboundManager, TargetAddr};
use crate::engine::routing::Router;
use dashmap::DashMap;
use parking_lot::Mutex;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// UDP session timeout for QUIC/gRPC long-lived connections
const UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes
/// Handshake read/write timeout (a silent client is dropped after this).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Read/write timeout applied once a connection enters the relay phase. The
/// relay treats `WouldBlock`/`TimedOut` as "idle" and keeps the connection
/// alive, so this only bounds each blocking read/write call.
const RELAY_TIMEOUT: Duration = Duration::from_secs(60);
/// Accept-loop poll interval while the listener is idle.
const ACCEPT_POLL: Duration = Duration::from_millis(10);

/// UDP session for tracking UDP ASSOCIATE connections
#[allow(dead_code)]
struct UdpSession {
    client_addr: SocketAddr,
    last_activity: Instant,
}

/// SOCKS5 proxy inbound listener with UDP ASSOCIATE support (synchronous).
pub struct Socks5Inbound {
    config: InboundConfig,
    router: Arc<Router>,
    outbound_manager: Arc<OutboundManager>,
    auth: Arc<InboundAuth>,
    cancel_token: CancellationToken,
    running: Arc<AtomicBool>,
    /// Handle of the dedicated accept thread; joined by `stop()`.
    accept_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// UDP sessions for UDP ASSOCIATE
    #[allow(dead_code)]
    udp_sessions: Arc<DashMap<u16, UdpSession>>,
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
            cancel_token: CancellationToken::new(),
            running: Arc::new(AtomicBool::new(false)),
            accept_thread: Mutex::new(None),
            udp_sessions: Arc::new(DashMap::new()),
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
        let cancel_token = self.cancel_token.clone();
        let running = Arc::clone(&self.running);

        running.store(true, Ordering::Relaxed);

        let handle = std::thread::Builder::new()
            .name("corduit-socks5-accept".into())
            .spawn(move || {
                accept_loop(
                    listener,
                    addr,
                    cancel_token,
                    running,
                    router,
                    outbound_manager,
                    auth,
                );
            })
            .map_err(|e| Error::network(format!("Failed to spawn SOCKS5 accept thread: {e}")))?;

        *self.accept_thread.lock() = Some(handle);

        tracing::info!("SOCKS5 inbound listening on {}", addr);
        Ok(())
    }

    fn stop_listener(&self) -> Result<()> {
        tracing::info!(
            "Stopping SOCKS5 inbound on {}:{}",
            self.config.listen,
            self.config.port
        );
        self.cancel_token.cancel();

        // The accept thread polls the token and exits promptly; joining it
        // also drops the listener (releasing the bound port). Take the handle
        // first so the lock is released before the (potentially blocking) join.
        let handle = self.accept_thread.lock().take();
        if let Some(handle) = handle {
            let _ = handle.join();
        }

        self.running.store(false, Ordering::Relaxed);
        tracing::info!("SOCKS5 inbound stopped");
        Ok(())
    }

    fn handle_connection(
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
        auth: Arc<InboundAuth>,
    ) -> Result<()> {
        // The handshake is bounded by the socket read timeout
        // (HANDSHAKE_TIMEOUT) applied in the accept loop.
        if !Self::perform_handshake(&mut stream, &auth)? {
            return Err(Error::protocol_with_info(
                "SOCKS5 handshake failed",
                "SOCKS5",
            ));
        }
        let (target_addr, target_port, command) = Self::read_request(&mut stream)?;

        // Handle different SOCKS5 commands
        match command {
            0x01 => {
                // CONNECT command - TCP proxy
                Self::handle_connect(
                    stream,
                    peer_addr,
                    target_addr,
                    target_port,
                    router,
                    outbound_manager,
                )
            }
            0x03 => {
                // UDP ASSOCIATE command - UDP proxy for QUIC/gRPC
                Self::handle_udp_associate(stream, peer_addr, router, outbound_manager)
            }
            _ => {
                Self::send_reply(&mut stream, 0x07)?; // Command not supported
                Err(Error::protocol_with_info(
                    "Unsupported SOCKS5 command",
                    "SOCKS5",
                ))
            }
        }
    }

    /// Handle SOCKS5 CONNECT command (TCP proxy)
    fn handle_connect(
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        target_addr: Socks5Addr,
        target_port: u16,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Result<()> {
        // Extract domain/IP and port for routing
        let (domain, ip) = match &target_addr {
            Socks5Addr::Domain(domain) => (Some(domain.clone()), None),
            Socks5Addr::Ipv4(ip) => (None, Some(IpAddr::V4(*ip))),
            Socks5Addr::Ipv6(ip) => (None, Some(IpAddr::V6(*ip))),
        };

        // Match outbound using router
        let outbound_tag = router.match_outbound(domain.as_deref(), ip, Some(target_port), None);

        // Build target address
        let target = match &target_addr {
            Socks5Addr::Domain(d) => TargetAddr::new_domain(d.clone(), target_port),
            Socks5Addr::Ipv4(ip) => {
                TargetAddr::new_ip(SocketAddr::new(IpAddr::V4(*ip), target_port))
            }
            Socks5Addr::Ipv6(ip) => {
                TargetAddr::new_ip(SocketAddr::new(IpAddr::V6(*ip), target_port))
            }
        };

        tracing::info!(
            "SOCKS5 CONNECT {} -> {} from {}",
            target,
            outbound_tag,
            peer_addr
        );

        // Get the outbound proxy
        let outbound = match outbound_manager.get_proxy(&outbound_tag) {
            Some(proxy) => proxy,
            None => {
                tracing::error!("Outbound '{}' not found", outbound_tag);
                Self::send_reply(&mut stream, 0x01)?; // General failure
                return Err(Error::config(format!(
                    "Outbound '{}' not found",
                    outbound_tag
                )));
            }
        };

        // Send success reply with dummy bound address (we don't know the actual bind address)
        let dummy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        Self::send_reply_with_addr(&mut stream, 0x00, dummy_addr)?;

        // Try to resolve the destination IP for display
        let destination_ip = match &target {
            TargetAddr::Ip(addr) => Some(addr.ip().to_string()),
            TargetAddr::Domain(domain, _) => {
                crate::common::socket::resolve_host(domain, target.port(), Duration::from_secs(3))
                    .ok()
                    .and_then(|addrs| addrs.into_iter().next())
                    .map(|addr| addr.ip().to_string())
            }
        };

        // Track the connection with IP address
        let tracked_conn = TrackedConnection::new_with_ip(
            "socks5".to_string(),
            outbound_tag.clone(),
            target.host(),
            destination_ip,
            target.port(),
            "SOCKS5".to_string(),
            "tcp".to_string(),
            "SOCKS5".to_string(),
            target.to_string(),
        );
        let tracker = global_tracker();
        let tracked = tracker.track(tracked_conn);
        let conn_arc = Arc::clone(&tracked);

        // The relay phase uses longer read/write timeouts.
        let _ = stream.set_read_timeout(Some(RELAY_TIMEOUT));
        let _ = stream.set_write_timeout(Some(RELAY_TIMEOUT));

        // Relay data through the outbound proxy with connection tracking
        if let Err(e) =
            outbound.relay_tcp_with_connection(Box::new(stream), target.clone(), Some(conn_arc))
        {
            tracing::debug!(
                "SOCKS5 relay error via '{}' to {}: {}",
                outbound.tag(),
                target,
                e
            );
        }

        // Untrack the connection
        tracker.untrack(&tracked.id);

        Ok(())
    }

    /// Handle SOCKS5 UDP ASSOCIATE command for QUIC/gRPC protocols
    fn handle_udp_associate(
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Result<()> {
        tracing::info!("SOCKS5 UDP ASSOCIATE request from {}", peer_addr);

        // Bind a UDP socket for the client
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let udp_socket = crate::common::socket::udp_bind(bind_addr, UDP_SESSION_TIMEOUT)
            .map_err(|e| Error::network(format!("Failed to bind UDP socket: {}", e)))?;
        let _ = udp_socket.set_write_timeout(Some(UDP_SESSION_TIMEOUT));

        let local_addr = udp_socket
            .local_addr()
            .map_err(|e| Error::network(format!("Failed to get UDP socket address: {}", e)))?;

        tracing::info!(
            "UDP relay socket bound to {} for client {}",
            local_addr,
            peer_addr
        );

        // Send success reply with the UDP relay address
        Self::send_reply_with_addr(&mut stream, 0x00, local_addr)?;

        // Start the UDP relay on a pool worker; it is stopped when the TCP
        // control connection below ends.
        let token = CancellationToken::new();
        let relay_token = token.clone();
        let router_clone = Arc::clone(&router);
        let outbound_manager_clone = Arc::clone(&outbound_manager);
        crate::common::exec::spawn(move || {
            if let Err(e) = Self::run_udp_relay(
                udp_socket,
                peer_addr,
                router_clone,
                outbound_manager_clone,
                relay_token,
            ) {
                tracing::debug!("UDP relay error for {}: {}", peer_addr, e);
            }
        });

        // Keep TCP connection alive - UDP ASSOCIATE is valid while TCP
        // connection is open. Read from TCP stream to detect when the client
        // disconnects; the read timeout acts as a keep-alive poll.
        let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
        let mut buf = [0u8; 1];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => {
                    // Client disconnected
                    tracing::info!("UDP ASSOCIATE client {} disconnected", peer_addr);
                    break;
                }
                Ok(_) => {
                    // Unexpected data, ignore
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    // Timeout, check if still connected
                    continue;
                }
                Err(e) => {
                    tracing::debug!("UDP ASSOCIATE TCP error for {}: {}", peer_addr, e);
                    break;
                }
            }
        }
        token.cancel();

        Ok(())
    }

    /// Run UDP relay for SOCKS5 UDP ASSOCIATE
    ///
    /// Only the client that established the TCP UDP-ASSOCIATE connection may
    /// use this relay socket. Datagrams from any other source IP are dropped;
    /// otherwise any host that can reach the bound UDP port would get a free
    /// open proxy (a classic SOCKS5 amplification / open-proxy vector).
    fn run_udp_relay(
        udp_socket: std::net::UdpSocket,
        client_addr: SocketAddr,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
        token: CancellationToken,
    ) -> Result<()> {
        let mut buf = vec![0u8; 65535];

        while !token.is_cancelled() {
            let (n, src_addr) = match udp_socket.recv_from(&mut buf) {
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
                    tracing::debug!("UDP recv error: {}", e);
                    continue;
                }
            };

            // Reject datagrams that do not originate from the authenticated
            // UDP-ASSOCIATE client (same source IP). This prevents third
            // parties from abusing the relay as an open proxy.
            if src_addr.ip() != client_addr.ip() {
                tracing::debug!(
                    "Dropping UDP datagram from unexpected source {} (associate client {})",
                    src_addr,
                    client_addr
                );
                continue;
            }

            if n < 10 {
                continue; // Too short for SOCKS5 UDP header
            }

            // Parse SOCKS5 UDP request header
            // +----+------+------+----------+----------+----------+
            // |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
            // +----+------+------+----------+----------+----------+
            // | 2  |  1   |  1   | Variable |    2     | Variable |
            // +----+------+------+----------+----------+----------+

            let frag = buf[2];
            if frag != 0 {
                // Fragmentation not supported
                tracing::debug!("UDP fragmentation not supported");
                continue;
            }

            let atyp = buf[3];
            let (target_addr, target_port, header_len) = match atyp {
                0x01 => {
                    // IPv4
                    if n < 10 {
                        continue;
                    }
                    let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                    let port = u16::from_be_bytes([buf[8], buf[9]]);
                    (
                        TargetAddr::new_ip(SocketAddr::new(IpAddr::V4(ip), port)),
                        port,
                        10,
                    )
                }
                0x03 => {
                    // Domain
                    let domain_len = buf[4] as usize;
                    if n < 7 + domain_len {
                        continue;
                    }
                    let domain = match String::from_utf8(buf[5..5 + domain_len].to_vec()) {
                        Ok(d) => d,
                        Err(_) => continue,
                    };
                    let port = u16::from_be_bytes([buf[5 + domain_len], buf[6 + domain_len]]);
                    (TargetAddr::new_domain(domain, port), port, 7 + domain_len)
                }
                0x04 => {
                    // IPv6
                    if n < 22 {
                        continue;
                    }
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&buf[4..20]);
                    let ip = Ipv6Addr::from(octets);
                    let port = u16::from_be_bytes([buf[20], buf[21]]);
                    (
                        TargetAddr::new_ip(SocketAddr::new(IpAddr::V6(ip), port)),
                        port,
                        22,
                    )
                }
                _ => continue,
            };

            let payload = &buf[header_len..n];
            if payload.is_empty() {
                continue;
            }

            // Route the UDP packet
            let (domain, ip) = match &target_addr {
                TargetAddr::Domain(d, _) => (Some(d.clone()), None),
                TargetAddr::Ip(addr) => (None, Some(addr.ip())),
            };

            let outbound_tag =
                router.match_outbound(domain.as_deref(), ip, Some(target_port), None);

            tracing::debug!(
                "UDP relay: {} -> {} via {} ({} bytes)",
                src_addr,
                target_addr,
                outbound_tag,
                payload.len()
            );

            // Get the outbound proxy
            let outbound = match outbound_manager.get_proxy(&outbound_tag) {
                Some(proxy) => proxy,
                None => {
                    tracing::warn!("Outbound '{}' not found for UDP", outbound_tag);
                    continue;
                }
            };

            // Check if outbound supports UDP
            if !outbound.supports_udp() {
                tracing::debug!("Outbound '{}' does not support UDP, skipping", outbound_tag);
                continue;
            }

            // Forward the UDP packet (one-shot request/reply, blocking).
            let payload_vec = payload.to_vec();
            match outbound.relay_udp_packet(&target_addr, &payload_vec) {
                Ok(response) => {
                    if !response.is_empty() {
                        // Build SOCKS5 UDP response
                        let mut response_packet = Vec::with_capacity(response.len() + 22);
                        response_packet.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV, FRAG

                        match &target_addr {
                            TargetAddr::Ip(addr) => {
                                match addr.ip() {
                                    IpAddr::V4(ip) => {
                                        response_packet.push(0x01);
                                        response_packet.extend_from_slice(&ip.octets());
                                    }
                                    IpAddr::V6(ip) => {
                                        response_packet.push(0x04);
                                        response_packet.extend_from_slice(&ip.octets());
                                    }
                                }
                                response_packet.extend_from_slice(&addr.port().to_be_bytes());
                            }
                            TargetAddr::Domain(domain, port) => {
                                response_packet.push(0x03);
                                response_packet.push(domain.len() as u8);
                                response_packet.extend_from_slice(domain.as_bytes());
                                response_packet.extend_from_slice(&port.to_be_bytes());
                            }
                        }
                        response_packet.extend_from_slice(&response);

                        if let Err(e) = udp_socket.send_to(&response_packet, src_addr) {
                            tracing::debug!("Failed to send UDP response: {}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("UDP relay error via '{}': {}", outbound.tag(), e);
                }
            }
        }

        Ok(())
    }

    fn perform_handshake(stream: &mut TcpStream, auth: &InboundAuth) -> Result<bool> {
        let mut buf = [0u8; 2];
        stream
            .read_exact(&mut buf)
            .map_err(|e| Error::network(format!("Failed to read SOCKS5 handshake: {}", e)))?;

        if buf[0] != 0x05 {
            return Ok(false); // Not SOCKS5
        }

        let num_methods = buf[1] as usize;
        let mut methods = vec![0u8; num_methods];
        stream
            .read_exact(&mut methods)
            .map_err(|e| Error::network(format!("Failed to read SOCKS5 methods: {}", e)))?;

        if auth.required() {
            // Credentials configured: only RFC 1929 user/pass is acceptable.
            if !methods.contains(&SOCKS5_AUTH_USERPASS) {
                stream.write_all(&[0x05, 0xFF]).map_err(|e| {
                    Error::network(format!("Failed to write SOCKS5 response: {}", e))
                })?;
                return Ok(false);
            }
            stream
                .write_all(&[0x05, SOCKS5_AUTH_USERPASS])
                .map_err(|e| Error::network(format!("Failed to write SOCKS5 response: {}", e)))?;
            if !socks5_userpass(stream, auth)? {
                return Ok(false);
            }
            return Ok(true);
        }

        // Check if no authentication is supported
        let supports_no_auth = methods.contains(&0x00);
        if !supports_no_auth {
            // Send "no acceptable methods" reply
            stream
                .write_all(&[0x05, 0xFF])
                .map_err(|e| Error::network(format!("Failed to write SOCKS5 response: {}", e)))?;
            return Ok(false);
        }

        // Send response: version 5, no authentication
        stream
            .write_all(&[0x05, 0x00])
            .map_err(|e| Error::network(format!("Failed to write SOCKS5 response: {}", e)))?;

        Ok(true)
    }

    fn read_request(stream: &mut TcpStream) -> Result<(Socks5Addr, u16, u8)> {
        let mut buf = [0u8; 4];
        stream
            .read_exact(&mut buf)
            .map_err(|e| Error::network(format!("Failed to read SOCKS5 request: {}", e)))?;

        if buf[0] != 0x05 {
            return Err(Error::protocol("Invalid SOCKS5 version"));
        }

        let command = buf[1];
        let addr_type = buf[3];

        let (addr, port) = match addr_type {
            0x01 => {
                // IPv4
                let mut addr_buf = [0u8; 4];
                stream.read_exact(&mut addr_buf)?;
                let ipv4 = Ipv4Addr::from(addr_buf);
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf)?;
                let port = u16::from_be_bytes(port_buf);
                (Socks5Addr::Ipv4(ipv4), port)
            }
            0x03 => {
                // Domain
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf)?;
                let len = len_buf[0] as usize;
                let mut domain_buf = vec![0u8; len];
                stream.read_exact(&mut domain_buf)?;
                let domain = String::from_utf8(domain_buf)
                    .map_err(|_| Error::protocol("Invalid domain encoding"))?;
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf)?;
                let port = u16::from_be_bytes(port_buf);
                (Socks5Addr::Domain(domain), port)
            }
            0x04 => {
                // IPv6
                let mut addr_buf = [0u8; 16];
                stream.read_exact(&mut addr_buf)?;
                let ipv6 = Ipv6Addr::from(addr_buf);
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf)?;
                let port = u16::from_be_bytes(port_buf);
                (Socks5Addr::Ipv6(ipv6), port)
            }
            _ => return Err(Error::protocol("Unsupported address type")),
        };

        Ok((addr, port, command))
    }

    fn send_reply(stream: &mut TcpStream, reply: u8) -> Result<()> {
        let reply_packet = [
            0x05,  // Version
            reply, // Reply code
            0x00,  // Reserved
            0x01,  // IPv4 address type
            0x00, 0x00, 0x00, 0x00, // IPv4 address (0.0.0.0)
            0x00, 0x00, // Port (0)
        ];

        stream
            .write_all(&reply_packet)
            .map_err(|e| Error::network(format!("Failed to write SOCKS5 reply: {}", e)))?;

        Ok(())
    }

    fn send_reply_with_addr(stream: &mut TcpStream, reply: u8, addr: SocketAddr) -> Result<()> {
        let mut reply_packet = Vec::with_capacity(22);
        reply_packet.push(0x05); // Version
        reply_packet.push(reply); // Reply code
        reply_packet.push(0x00); // Reserved

        match addr.ip() {
            IpAddr::V4(ipv4) => {
                reply_packet.push(0x01); // IPv4
                reply_packet.extend_from_slice(&ipv4.octets());
            }
            IpAddr::V6(ipv6) => {
                reply_packet.push(0x04); // IPv6
                reply_packet.extend_from_slice(&ipv6.octets());
            }
        }

        reply_packet.extend_from_slice(&addr.port().to_be_bytes());

        stream
            .write_all(&reply_packet)
            .map_err(|e| Error::network(format!("Failed to write SOCKS5 reply: {}", e)))?;

        Ok(())
    }
}

/// Dedicated accept loop: polls a non-blocking listener for connections and
/// dispatches each to the work-stealing pool. Exits on cancellation (which
/// also drops the listener and releases the bound port).
fn accept_loop(
    listener: std::net::TcpListener,
    addr: SocketAddr,
    cancel_token: CancellationToken,
    running: Arc<AtomicBool>,
    router: Arc<Router>,
    outbound_manager: Arc<OutboundManager>,
    auth: Arc<InboundAuth>,
) {
    loop {
        if cancel_token.is_cancelled() {
            tracing::info!("SOCKS5 inbound on {} shutting down", addr);
            break;
        }
        match listener.accept() {
            Ok((stream, peer_addr)) => {
                // Windows: accepted sockets inherit the listener's
                // non-blocking mode; force blocking so the read/write
                // timeouts below actually bound each operation.
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
                let _ = stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT));
                let router = Arc::clone(&router);
                let outbound_manager = Arc::clone(&outbound_manager);
                let auth = Arc::clone(&auth);
                crate::common::exec::spawn(move || {
                    if let Err(err) = Socks5Inbound::handle_connection(
                        stream,
                        peer_addr,
                        router,
                        outbound_manager,
                        auth,
                    ) {
                        tracing::debug!("SOCKS5 connection error from {}: {}", peer_addr, err);
                    }
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL);
            }
            Err(e) => {
                if !cancel_token.is_cancelled() {
                    tracing::error!("SOCKS5 accept error: {}", e);
                }
                break;
            }
        }
    }
    running.store(false, Ordering::Relaxed);
    tracing::info!("SOCKS5 inbound on {} stopped", addr);
}

#[derive(Debug)]
enum Socks5Addr {
    Domain(String),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}
