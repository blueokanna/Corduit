//! Main TCP/IP stack coordinator

use crate::common::LogThrottle;
use crate::netstack::solidtcp::device::DeviceConfig;
use crate::netstack::solidtcp::dns::{ClientDnsSettings, DnsHandler, DnsVerdict, FakeIpPool};
use crate::netstack::solidtcp::error::{Result, SolidTcpError};
use crate::netstack::solidtcp::nat::{NatConfig, NatTable};
use crate::netstack::solidtcp::packet::{
    build_ipv4_tcp, build_ipv4_udp, parse_packet, ParsedPacket, TcpFlags, TcpInfo, TransportInfo,
};
use crate::netstack::solidtcp::stats::StackStats;
use crate::netstack::solidtcp::tcp::{
    TcpAction, TcpConfig, TcpConnection, TcpManager, MAX_RECV_WINDOW,
};
use crate::netstack::solidtcp::udp::{UdpConfig, UdpManager};
use bytes::BytesMut;
use parking_lot::{Mutex, RwLock};
use smoltcp::wire::IpProtocol;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream, UdpSocket as StdUdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

const PROXY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const PROXY_POLL_TIMEOUT: Duration = Duration::from_millis(100);

/// How long a UDP association may sit idle before it closes.
///
/// A flow that resumes after this pays one local handshake; leaving the
/// association open forever would hold a server-side socket and thread for a
/// flow that is already gone.
const UDP_ASSOCIATION_IDLE: Duration = Duration::from_secs(120);

/// Bound on a single datagram hand-off to the relay socket.
const UDP_SEND_TIMEOUT: Duration = Duration::from_secs(30);

/// Associations opened between sweeps of the table.
const UDP_ASSOCIATION_SWEEP_EVERY: u64 = 256;

/// A live SOCKS5 UDP association.
///
/// A `UDP ASSOCIATE` relays to any destination — every datagram carries its
/// own target — so one association can serve a whole flow. That is the point
/// of holding one: the path this replaced opened a TCP connection, ran the
/// handshake and spawned three threads for *each datagram*, which made QUIC
/// traffic create and destroy threads faster than anything else in the stack.
struct UdpAssociation {
    relay_addr: SocketAddr,
    socket: StdUdpSocket,
    /// Held only so the server keeps the relay in place; dropped when the
    /// association is replaced or swept away.
    _control: TcpStream,
    /// Cleared by the reply pump when the association ends, so the packet path
    /// builds a new one instead of writing into a socket nobody is reading.
    alive: Arc<AtomicBool>,
}

impl UdpAssociation {
    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    /// Frame one datagram for the relay and hand it to the socket.
    fn send(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        domain: Option<&str>,
        payload: &[u8],
    ) -> Result<()> {
        let mut framed = Vec::with_capacity(payload.len() + 262);
        framed.extend_from_slice(&[0x00, 0x00, 0x00]);

        // A domain that cannot be expressed in the wire form is not worth
        // dropping the datagram over: fall back to the address the flow
        // resolved to.
        match domain.filter(|domain| domain.len() <= u8::MAX as usize) {
            Some(domain) => {
                framed.push(0x03);
                framed.push(domain.len() as u8);
                framed.extend_from_slice(domain.as_bytes());
            }
            None => match dst_addr.ip() {
                IpAddr::V4(ip) => {
                    framed.push(0x01);
                    framed.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    framed.push(0x04);
                    framed.extend_from_slice(&ip.octets());
                }
            },
        }
        framed.extend_from_slice(&dst_addr.port().to_be_bytes());
        framed.extend_from_slice(payload);

        self.socket
            .send_to(&framed, self.relay_addr)
            .map_err(|e| SolidTcpError::ProxyError(format!("UDP send failed: {}", e)))?;

        debug!(
            "UDP forwarded: {} -> {} ({} bytes)",
            src_addr,
            dst_addr,
            payload.len()
        );
        Ok(())
    }
}

/// Length of the SOCKS5 UDP request header at the front of `datagram`.
///
/// `None` when the datagram is too short or carries an address type the relay
/// cannot have produced.
fn socks5_udp_header_len(datagram: &[u8]) -> Option<usize> {
    match *datagram.get(3)? {
        0x01 => Some(10),
        0x03 => Some(7 + *datagram.get(4)? as usize),
        0x04 => Some(22),
        _ => None,
    }
}

/// Read replies from an association's relay socket and hand them to the TUN.
///
/// One thread per flow rather than one per datagram. It ends when the flow has
/// been quiet for [`UDP_ASSOCIATION_IDLE`] or the relay fails, and it closes
/// the control connection on the way out so the server drops its half of the
/// association immediately.
fn pump_udp_replies(
    socket: StdUdpSocket,
    control: TcpStream,
    client: SocketAddr,
    remote: SocketAddr,
    tun_tx: Option<mpsc::Sender<BytesMut>>,
    stats: Arc<StackStats>,
    alive: Arc<AtomicBool>,
) {
    let mut buf = vec![0u8; 65535];

    loop {
        match socket.recv_from(&mut buf) {
            Ok((n, _)) => {
                let Some(header_len) = socks5_udp_header_len(&buf[..n]) else {
                    debug!("UDP reply with an unusable header ({} bytes)", n);
                    continue;
                };
                if n <= header_len {
                    continue;
                }
                let (IpAddr::V4(remote_ip), IpAddr::V4(client_ip)) = (remote.ip(), client.ip())
                else {
                    continue;
                };
                let Some(ref tx) = tun_tx else {
                    continue;
                };

                let packet = build_ipv4_udp(
                    remote_ip,
                    client_ip,
                    remote.port(),
                    client.port(),
                    &buf[header_len..n],
                );
                stats.record_sent(packet.len());
                if tx.send(BytesMut::from(&packet[..])).is_err() {
                    break;
                }
            }
            // Nothing arrived within the idle budget: the flow is done with
            // this association. The packet path builds another one if it
            // comes back.
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                debug!("UDP association {client} -> {remote} went idle");
                break;
            }
            Err(e) if is_transient(&e) => continue,
            Err(e) => {
                debug!("UDP relay recv error {client} -> {remote}: {e}");
                break;
            }
        }
    }

    alive.store(false, Ordering::Release);
    // Closing the control connection is what makes the server drop its half of
    // the association — including the thread serving it — instead of holding it
    // until the listener stops.
    let _ = control.shutdown(Shutdown::Both);
}
const PROXY_WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(60);
const FAKE_IP_MISS_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// Whether a socket error just means "nothing happened yet".
///
/// A socket read/write timeout surfaces as `EAGAIN` on Unix (Android, Linux,
/// macOS — decoded as [`io::ErrorKind::WouldBlock`], textually "Try again")
/// and as `WSAETIMEDOUT` ([`io::ErrorKind::TimedOut`]) on Windows, so a relay
/// that only tolerates one of the two drops healthy connections the moment they
/// go quiet. `Interrupted` belongs here as well: `EINTR` is a signal artefact,
/// not a failure.
fn is_transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

/// Whether the peer is simply gone. Relays end quietly on these instead of
/// warning, because browsers abort half of their connections on purpose.
fn is_peer_gone(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
    )
}

#[cfg(target_os = "android")]
use std::os::unix::io::AsRawFd;

#[cfg(target_os = "android")]
static PROTECT_CALLBACK: parking_lot::RwLock<Option<Box<dyn Fn(i32) -> bool + Send + Sync>>> =
    parking_lot::RwLock::new(None);

#[cfg(target_os = "android")]
pub fn set_protect_callback<F>(callback: F)
where
    F: Fn(i32) -> bool + Send + Sync + 'static,
{
    let mut guard = PROTECT_CALLBACK.write();
    *guard = Some(Box::new(callback));
    info!("SolidStack: Socket protect callback registered");
}

#[cfg(target_os = "android")]
pub fn clear_protect_callback() {
    let mut guard = PROTECT_CALLBACK.write();
    *guard = None;
    info!("SolidStack: Socket protect callback cleared");
}

#[cfg(target_os = "android")]
pub fn protect_socket(fd: i32) -> bool {
    debug!("protect_socket called for fd={}", fd);
    let guard = PROTECT_CALLBACK.read();
    if let Some(ref callback) = *guard {
        let result = callback(fd);
        if result {
            debug!("Socket fd={} protected successfully", fd);
        } else {
            warn!("Socket fd={} protection FAILED", fd);
        }
        result
    } else {
        warn!(
            "No protect callback set for socket fd={} - this will cause routing loop!",
            fd
        );
        false
    }
}

#[cfg(target_os = "android")]
pub fn has_protect_callback() -> bool {
    PROTECT_CALLBACK.read().is_some()
}

#[derive(Debug, Clone)]
pub struct StackConfig {
    pub device: DeviceConfig,
    pub tcp: TcpConfig,
    pub udp: UdpConfig,
    pub nat: NatConfig,
    pub dns: ClientDnsSettings,
    pub proxy_addr: SocketAddr,
    pub dns_intercept: bool,
    pub cleanup_interval: Duration,
}

impl Default for StackConfig {
    fn default() -> Self {
        Self {
            device: DeviceConfig::default(),
            tcp: TcpConfig::default(),
            udp: UdpConfig::default(),
            nat: NatConfig::default(),
            dns: ClientDnsSettings::default(),
            proxy_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7890),
            dns_intercept: true,
            cleanup_interval: Duration::from_secs(30),
        }
    }
}

pub struct StackBuilder {
    config: StackConfig,
}

impl StackBuilder {
    pub fn new() -> Self {
        Self {
            config: StackConfig::default(),
        }
    }

    pub fn proxy_port(mut self, port: u16) -> Self {
        self.config.proxy_addr.set_port(port);
        self
    }

    pub fn proxy_addr(mut self, addr: SocketAddr) -> Self {
        self.config.proxy_addr = addr;
        self
    }

    pub fn mtu(mut self, mtu: usize) -> Self {
        self.config.device.mtu = mtu;
        self
    }

    pub fn dns_intercept(mut self, enable: bool) -> Self {
        self.config.dns_intercept = enable;
        self
    }

    /// How the intercepted DNS is answered.
    ///
    /// Replaces the old `fake_ip_range(start, size)` setter: the range, the mode
    /// and the filter are one decision, and splitting them across two setters is
    /// how a stack ends up in `normal` mode while still holding a fake pool.
    pub fn client_dns(mut self, settings: ClientDnsSettings) -> Self {
        self.config.dns = settings;
        self
    }

    pub fn tcp_timeout(mut self, timeout: Duration) -> Self {
        self.config.tcp.idle_timeout = timeout;
        self
    }

    pub fn udp_timeout(mut self, timeout: Duration) -> Self {
        self.config.udp.session_timeout = timeout;
        self
    }

    pub fn build(self) -> SolidStack {
        SolidStack::new(self.config)
    }
}

impl Default for StackBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Main TCP/IP stack
pub struct SolidStack {
    config: StackConfig,
    tcp_manager: Arc<TcpManager>,
    udp_manager: Arc<UdpManager>,
    nat_table: Arc<NatTable>,
    fake_ip_pool: Arc<FakeIpPool>,
    dns_handler: Arc<DnsHandler>,
    stats: Arc<StackStats>,
    running: Arc<AtomicBool>,
    tun_tx: Option<mpsc::Sender<BytesMut>>,
    fake_ip_miss_log: Arc<LogThrottle>,
    /// One reusable SOCKS5 UDP association per flow, keyed by the client and
    /// destination addresses.
    udp_associations: Mutex<HashMap<(SocketAddr, SocketAddr), Arc<UdpAssociation>>>,
    /// Associations opened, used only to pace sweeping the tombstones of dead
    /// ones out of the table. The server side of a dead association is already
    /// gone — the reply pump closes its control connection as it ends — so a
    /// tombstone costs nothing but its table entry.
    udp_associations_opened: AtomicU64,
}

impl SolidStack {
    pub fn new(config: StackConfig) -> Self {
        let fake_ip_pool = Arc::new(FakeIpPool::with_config(config.dns.fake_ip.clone()));
        let dns_handler = Arc::new(DnsHandler::new(fake_ip_pool.clone(), &config.dns));

        Self {
            tcp_manager: Arc::new(TcpManager::with_config(config.tcp.clone())),
            udp_manager: Arc::new(UdpManager::with_config(config.udp.clone())),
            nat_table: Arc::new(NatTable::with_config(config.nat.clone())),
            fake_ip_pool,
            dns_handler,
            stats: Arc::new(StackStats::new()),
            running: Arc::new(AtomicBool::new(false)),
            tun_tx: None,
            fake_ip_miss_log: Arc::new(LogThrottle::new(FAKE_IP_MISS_LOG_INTERVAL)),
            udp_associations: Mutex::new(HashMap::new()),
            udp_associations_opened: AtomicU64::new(0),
            config,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(StackConfig::default())
    }
    pub fn builder() -> StackBuilder {
        StackBuilder::new()
    }

    pub fn set_tun_tx(&mut self, tx: mpsc::Sender<BytesMut>) {
        self.tun_tx = Some(tx);
    }
    pub fn tun_tx(&self) -> Option<&mpsc::Sender<BytesMut>> {
        self.tun_tx.as_ref()
    }

    pub fn start(&self) {
        self.running.store(true, Ordering::Relaxed);
        info!("SolidStack started");
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        self.tcp_manager.cleanup();
        self.udp_manager.cleanup();
        self.nat_table.clear();
        info!("SolidStack stopped");
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
    pub fn stats(&self) -> &Arc<StackStats> {
        &self.stats
    }
    pub fn tcp_manager(&self) -> &Arc<TcpManager> {
        &self.tcp_manager
    }
    pub fn udp_manager(&self) -> &Arc<UdpManager> {
        &self.udp_manager
    }
    pub fn nat_table(&self) -> &Arc<NatTable> {
        &self.nat_table
    }
    pub fn fake_ip_pool(&self) -> &Arc<FakeIpPool> {
        &self.fake_ip_pool
    }
    pub fn dns_handler(&self) -> &Arc<DnsHandler> {
        &self.dns_handler
    }
    pub fn proxy_port(&self) -> u16 {
        self.config.proxy_addr.port()
    }
    pub fn proxy_addr(&self) -> SocketAddr {
        self.config.proxy_addr
    }

    pub fn connection_count(&self) -> usize {
        self.tcp_manager.connection_count() + self.udp_manager.session_count()
    }

    pub fn process_packet(&self, packet: &[u8]) -> Result<()> {
        if !self.is_running() {
            return Ok(());
        }

        self.stats.record_received(packet.len());

        let parsed = match parse_packet(packet) {
            Ok(p) => p,
            Err(e) => {
                self.stats.record_parse_error();
                debug!("Packet parse error: {}", e);
                return Ok(());
            }
        };

        debug!(
            "Packet: {:?} {} -> {} proto={:?}",
            parsed.version, parsed.src_addr, parsed.dst_addr, parsed.protocol
        );

        match parsed.protocol {
            IpProtocol::Tcp => {
                self.stats.record_tcp();
                self.handle_tcp_packet(&parsed, packet)
            }
            IpProtocol::Udp => {
                self.stats.record_udp();
                self.handle_udp_packet(&parsed, packet)
            }
            IpProtocol::Icmp => {
                self.stats.record_icmp();
                Ok(())
            }
            _ => {
                self.stats.record_other();
                Ok(())
            }
        }
    }

    fn handle_tcp_packet(&self, parsed: &ParsedPacket, raw: &[u8]) -> Result<()> {
        let tcp_info = match &parsed.transport {
            TransportInfo::Tcp(info) => info,
            _ => return Ok(()),
        };

        let src_addr = parsed
            .src_socket()
            .ok_or_else(|| SolidTcpError::InvalidPacket("Missing source address".to_string()))?;
        let dst_addr = parsed.dst_socket().ok_or_else(|| {
            SolidTcpError::InvalidPacket("Missing destination address".to_string())
        })?;

        let ip_header_len = parsed.payload_offset;
        let tcp_data_offset = if ip_header_len + 12 < raw.len() {
            ((raw[ip_header_len + 12] >> 4) as usize) * 4
        } else {
            20
        };

        let payload_start = ip_header_len + tcp_data_offset;
        let ip_total_len = if raw.len() >= 4 {
            u16::from_be_bytes([raw[2], raw[3]]) as usize
        } else {
            raw.len()
        };

        let payload_end = ip_total_len.min(raw.len());
        let payload = if payload_start < payload_end {
            &raw[payload_start..payload_end]
        } else {
            &[]
        };

        debug!(
            "TCP: {} -> {} flags={:?} seq={} ack={} payload_len={}",
            src_addr,
            dst_addr,
            tcp_info.flags,
            tcp_info.seq,
            tcp_info.ack,
            payload.len()
        );

        if tcp_info.flags.syn && !tcp_info.flags.ack {
            return self.handle_tcp_syn(src_addr, dst_addr, tcp_info, parsed);
        }

        if let Some(conn) = self.tcp_manager.get_connection(src_addr, dst_addr) {
            let action = {
                let mut conn = conn.write();
                conn.process(tcp_info, payload)?
            };

            self.execute_tcp_action(src_addr, dst_addr, &conn, action)?;
        } else if !tcp_info.flags.rst {
            debug!(
                "No connection for packet, sending RST: {} -> {}",
                src_addr, dst_addr
            );
            self.send_tcp_packet(
                dst_addr,
                src_addr,
                tcp_info.ack,
                tcp_info.seq.wrapping_add(1),
                TcpFlags::rst_ack(),
                MAX_RECV_WINDOW,
                &[],
                None,
            )?;
        }

        Ok(())
    }

    fn handle_tcp_syn(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        tcp_info: &TcpInfo,
        _parsed: &ParsedPacket,
    ) -> Result<()> {
        let fake_ip = match dst_addr.ip() {
            IpAddr::V4(ip) if self.fake_ip_pool.is_fake_ip(ip) => Some(ip),
            _ => None,
        };
        let domain = fake_ip.and_then(|ip| self.fake_ip_pool.lookup(ip));

        info!(
            "=== TCP SYN received: {} -> {} (domain: {:?}, is_fake_ip: {}) ===",
            src_addr,
            dst_addr,
            domain,
            fake_ip.is_some()
        );

        if let (Some(ip), None) = (fake_ip, &domain) {
            if let Some(suppressed) = self.fake_ip_miss_log.admit() {
                warn!(
                    address = %ip,
                    suppressed,
                    "fake-IP address has no domain mapping; resetting connection \
                     (client holds a stale DNS answer and should re-resolve)"
                );
            }
            self.send_tcp_packet(
                dst_addr,
                src_addr,
                0,
                tcp_info.seq.wrapping_add(1),
                TcpFlags::rst_ack(),
                MAX_RECV_WINDOW,
                &[],
                None,
            )?;
            return Ok(());
        }

        let conn = self
            .tcp_manager
            .handle_syn(src_addr, dst_addr, tcp_info, domain.clone())?;
        self.stats.record_tcp_connection();

        let (our_seq, their_seq, mss, window) = {
            let conn = conn.read();
            (
                conn.snd_nxt().wrapping_sub(1),
                conn.rcv_nxt(),
                conn.mss(),
                conn.recv_window() as u16,
            )
        };

        info!(
            "Sending SYN-ACK to {} for connection to {:?}",
            src_addr,
            domain.as_ref().unwrap_or(&dst_addr.to_string())
        );

        self.send_tcp_packet(
            dst_addr,
            src_addr,
            our_seq,
            their_seq,
            TcpFlags::syn_ack(),
            window,
            &[],
            Some(mss),
        )?;

        let stack = self.clone_for_proxy();
        let conn_clone = conn.clone();

        if let Err(e) = std::thread::Builder::new()
            .name("tun-proxy-tcp".into())
            .spawn(move || {
                if let Err(e) =
                    stack.establish_proxy_connection(src_addr, dst_addr, domain, conn_clone)
                {
                    warn!(
                        "Proxy connection failed: {} -> {}: {}",
                        src_addr, dst_addr, e
                    );
                }
            })
        {
            warn!("Failed to spawn proxy connection thread: {}", e);
        }

        Ok(())
    }

    fn clone_for_proxy(&self) -> StackProxy {
        StackProxy {
            proxy_addr: self.config.proxy_addr,
            tun_tx: self.tun_tx.clone(),
            tcp_manager: self.tcp_manager.clone(),
            stats: self.stats.clone(),
            running: self.running.clone(),
        }
    }

    /// The association serving `src_addr -> dst_addr`, created on first use.
    ///
    /// A datagram for a flow that already has a live association costs one map
    /// lookup and a `send_to`; everything else — a new flow, or one whose
    /// association has since gone idle — builds a fresh one.
    fn udp_association(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
    ) -> Result<Arc<UdpAssociation>> {
        let key = (src_addr, dst_addr);

        {
            let table = self.udp_associations.lock();
            if let Some(existing) = table.get(&key) {
                if existing.is_alive() {
                    return Ok(Arc::clone(existing));
                }
            }
        }

        let association = Arc::new(
            self.clone_for_proxy()
                .open_udp_association(src_addr, dst_addr)?,
        );

        let mut table = self.udp_associations.lock();
        let replaced = table.insert(key, Arc::clone(&association));
        let opened = self.udp_associations_opened.fetch_add(1, Ordering::Relaxed);
        if opened % UDP_ASSOCIATION_SWEEP_EVERY == 0 {
            table.retain(|_, entry| entry.is_alive());
        }
        drop(table);
        // Dropping the association the sweep just replaced closes its control
        // connection, which is what tells the server to release the relay.
        drop(replaced);

        Ok(association)
    }

    fn execute_tcp_action(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        conn: &Arc<RwLock<TcpConnection>>,
        action: TcpAction,
    ) -> Result<()> {
        // Every segment sent to the client carries the connection's current
        // receive window, so a sender that is being throttled finds out as
        // soon as it hears from us.
        match action {
            TcpAction::SendAck => {
                let (seq, ack, window) = {
                    let conn = conn.read();
                    (conn.snd_nxt(), conn.rcv_nxt(), conn.recv_window() as u16)
                };
                self.send_tcp_packet(
                    dst_addr,
                    src_addr,
                    seq,
                    ack,
                    TcpFlags::ack_only(),
                    window,
                    &[],
                    None,
                )?;
            }
            TcpAction::SendFinAck => {
                let (seq, ack, window) = {
                    let conn = conn.read();
                    (conn.snd_nxt(), conn.rcv_nxt(), conn.recv_window() as u16)
                };
                self.send_tcp_packet(
                    dst_addr,
                    src_addr,
                    seq,
                    ack,
                    TcpFlags::fin_ack(),
                    window,
                    &[],
                    None,
                )?;
                let close_action = conn.write().close();
                if close_action == TcpAction::SendFin {}
            }
            TcpAction::SendFin => {
                let (seq, ack, window) = {
                    let conn = conn.read();
                    (conn.snd_nxt(), conn.rcv_nxt(), conn.recv_window() as u16)
                };
                self.send_tcp_packet(
                    dst_addr,
                    src_addr,
                    seq,
                    ack,
                    TcpFlags::fin_ack(),
                    window,
                    &[],
                    None,
                )?;
            }
            TcpAction::SendRst => {
                let seq = conn.read().snd_nxt();
                self.send_tcp_packet(
                    dst_addr,
                    src_addr,
                    seq,
                    0,
                    TcpFlags::rst_only(),
                    MAX_RECV_WINDOW,
                    &[],
                    None,
                )?;
            }
            TcpAction::Established => {
                debug!("TCP connection established: {} -> {}", src_addr, dst_addr);
            }
            TcpAction::Close => {
                self.tcp_manager.remove_connection(src_addr, dst_addr);
                self.stats.record_tcp_closed();
                debug!("TCP connection closed: {} -> {}", src_addr, dst_addr);
            }
            TcpAction::SendData(data) => {
                let (seq, ack, window) = {
                    let mut conn = conn.write();
                    let seq = conn.snd_nxt();
                    let ack = conn.rcv_nxt();
                    let window = conn.recv_window() as u16;
                    conn.advance_snd_nxt(data.len() as u32);
                    (seq, ack, window)
                };
                self.send_tcp_packet(
                    dst_addr,
                    src_addr,
                    seq,
                    ack,
                    TcpFlags::psh_ack(),
                    window,
                    &data,
                    None,
                )?;
            }
            TcpAction::None => {}
        }
        Ok(())
    }

    fn handle_udp_packet(&self, parsed: &ParsedPacket, raw: &[u8]) -> Result<()> {
        let udp_info = match &parsed.transport {
            TransportInfo::Udp(info) => info,
            _ => return Ok(()),
        };

        let src_addr = parsed
            .src_socket()
            .ok_or_else(|| SolidTcpError::InvalidPacket("Missing source address".to_string()))?;
        let dst_addr = parsed.dst_socket().ok_or_else(|| {
            SolidTcpError::InvalidPacket("Missing destination address".to_string())
        })?;

        let payload_start = parsed.payload_offset + 8;
        let payload = if udp_info.payload_len > 0 && payload_start < raw.len() {
            &raw[payload_start..raw.len().min(payload_start + udp_info.payload_len)]
        } else {
            return Ok(());
        };

        info!(
            "UDP packet: {} -> {} ({} bytes payload)",
            src_addr,
            dst_addr,
            payload.len()
        );

        if dst_addr.port() == 53 && self.config.dns_intercept {
            info!(
                "=== DNS query intercepted: {} -> {} ({} bytes) ===",
                src_addr,
                dst_addr,
                payload.len()
            );
            return self.handle_dns_query(src_addr, dst_addr, payload);
        }

        self.handle_udp_data(src_addr, dst_addr, payload)
    }

    fn handle_dns_query(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        payload: &[u8],
    ) -> Result<()> {
        self.stats.record_dns_query();
        info!(
            "=== Processing DNS query: {} -> {} ({} bytes) ===",
            src_addr,
            dst_addr,
            payload.len()
        );

        match self.dns_handler.handle_query(payload) {
            Ok(DnsVerdict::Answer {
                bytes,
                faked_domain,
            }) => {
                if let Some(domain) = faked_domain {
                    info!("DNS query for domain: {domain} - Fake-IP allocated");
                    self.stats.record_fake_ip();
                }
                self.stats.record_dns_response();
                info!(
                    "DNS response ready: {} bytes, sending back to {} from {}",
                    bytes.len(),
                    src_addr,
                    dst_addr
                );

                match self.send_udp_packet(dst_addr, src_addr, &bytes) {
                    Ok(()) => {
                        info!("=== DNS response sent successfully to {} ===", src_addr);
                    }
                    Err(e) => {
                        warn!("Failed to send DNS response to {}: {}", src_addr, e);
                        return Err(e);
                    }
                }
            }
            // Not a record the pool can stand in for. Letting it travel as
            // ordinary UDP reaches a real resolver and supports every record
            // type, which beats inventing an answer the client would act on.
            Ok(DnsVerdict::Forward) => {
                debug!(
                    "DNS query {} -> {} is not pool-answerable; forwarding as UDP",
                    src_addr, dst_addr
                );
                return self.handle_udp_data(src_addr, dst_addr, payload);
            }
            Err(e) => {
                warn!("DNS query handling failed: {}", e);
                return Err(e);
            }
        }

        Ok(())
    }

    fn handle_udp_data(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        payload: &[u8],
    ) -> Result<()> {
        let domain = match dst_addr.ip() {
            IpAddr::V4(ip) if self.fake_ip_pool.is_fake_ip(ip) => {
                match self.fake_ip_pool.lookup(ip) {
                    Some(domain) => Some(domain),
                    None => {
                        if let Some(suppressed) = self.fake_ip_miss_log.admit() {
                            warn!(
                                address = %dst_addr,
                                suppressed,
                                "dropping UDP to a fake-IP address with no domain mapping \
                                 (client holds a stale DNS answer and should re-resolve)"
                            );
                        }
                        return Ok(());
                    }
                }
            }
            _ => None,
        };

        debug!(
            "UDP data: {} -> {} ({} bytes, domain: {:?})",
            src_addr,
            dst_addr,
            payload.len(),
            domain
        );

        let _session =
            self.udp_manager
                .get_or_create_session(src_addr, dst_addr, domain.clone())?;
        self.udp_manager
            .record_sent(src_addr, dst_addr, payload.len());

        // Straight into the flow's association: no thread, no TCP connect and
        // no handshake per packet. Only a missing or dead association pays for
        // the setup below, and that runs on the packet thread because a
        // handshake against the engine's own local listener takes microseconds.
        match self.udp_association(src_addr, dst_addr) {
            Ok(association) => {
                if let Err(e) = association.send(src_addr, dst_addr, domain.as_deref(), payload) {
                    debug!("UDP send error: {} -> {}: {}", src_addr, dst_addr, e);
                }
            }
            Err(e) => {
                debug!("UDP association error: {} -> {}: {}", src_addr, dst_addr, e);
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn send_tcp_packet(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        seq: u32,
        ack: u32,
        flags: TcpFlags,
        window: u16,
        payload: &[u8],
        mss: Option<u16>,
    ) -> Result<()> {
        let tun_tx = self.tun_tx.as_ref().ok_or(SolidTcpError::DeviceNotReady)?;

        let (src_ip, dst_ip) = match (src_addr.ip(), dst_addr.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => (s, d),
            _ => return Err(SolidTcpError::Unsupported("IPv6 not supported".to_string())),
        };

        let packet = build_ipv4_tcp(
            src_ip,
            dst_ip,
            src_addr.port(),
            dst_addr.port(),
            seq,
            ack,
            flags,
            window,
            payload,
            mss,
        );

        self.stats.record_sent(packet.len());
        tun_tx
            .send(BytesMut::from(&packet[..]))
            .map_err(|_| SolidTcpError::ChannelClosed)?;

        Ok(())
    }

    fn send_udp_packet(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        payload: &[u8],
    ) -> Result<()> {
        let tun_tx = self.tun_tx.as_ref().ok_or_else(|| {
            warn!("TUN TX channel not available!");
            SolidTcpError::DeviceNotReady
        })?;

        let (src_ip, dst_ip) = match (src_addr.ip(), dst_addr.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => (s, d),
            _ => return Err(SolidTcpError::Unsupported("IPv6 not supported".to_string())),
        };

        info!(
            "Building UDP packet: {}:{} -> {}:{} ({} bytes payload)",
            src_ip,
            src_addr.port(),
            dst_ip,
            dst_addr.port(),
            payload.len()
        );

        let packet = build_ipv4_udp(src_ip, dst_ip, src_addr.port(), dst_addr.port(), payload);

        info!("Sending UDP packet to TUN: {} bytes total", packet.len());
        self.stats.record_sent(packet.len());

        match tun_tx.send(BytesMut::from(&packet[..])) {
            Ok(()) => {
                info!("UDP packet sent to TUN successfully");
                Ok(())
            }
            Err(e) => {
                warn!("Failed to send UDP packet to TUN: {}", e);
                Err(SolidTcpError::ChannelClosed)
            }
        }
    }

    pub fn run_cleanup(&self) {
        let interval = self.config.cleanup_interval;

        while self.is_running() {
            std::thread::sleep(interval);
            self.tcp_manager.cleanup();
            self.udp_manager.cleanup();
            self.nat_table.cleanup();
            self.fake_ip_pool.cleanup_expired();
        }
    }
}

struct StackProxy {
    proxy_addr: SocketAddr,
    tun_tx: Option<mpsc::Sender<BytesMut>>,
    tcp_manager: Arc<TcpManager>,
    stats: Arc<StackStats>,
    running: Arc<AtomicBool>,
}

impl StackProxy {
    /// Write the entire buffer to the shared TCP stream, looping on partial
    /// writes. `Write` is implemented for `&TcpStream`, so the same stream
    /// can be shared between the reader and writer threads.
    ///
    /// Transient errors (an expired write timeout, `EINTR`) are retried instead
    /// of failing the connection — a peer that is merely slow to drain its
    /// socket is not a broken peer. Only when no byte at all has been accepted
    /// for [`PROXY_WRITE_STALL_TIMEOUT`] does the write give up.
    fn write_all_sync(mut stream: &TcpStream, mut data: &[u8]) -> io::Result<()> {
        let mut stalled_since: Option<Instant> = None;
        while !data.is_empty() {
            match stream.write(data) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write whole buffer",
                    ));
                }
                Ok(n) => {
                    data = &data[n..];
                    stalled_since = None;
                }
                Err(e) if is_transient(&e) => {
                    let since = *stalled_since.get_or_insert_with(Instant::now);
                    if since.elapsed() >= PROXY_WRITE_STALL_TIMEOUT {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "peer stopped reading",
                        ));
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Open a fresh `UDP ASSOCIATE` and start the reply pump for it.
    ///
    /// Callers go through `SolidStack::udp_association`, which is what keeps
    /// one association per flow instead of one per datagram.
    fn open_udp_association(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
    ) -> Result<UdpAssociation> {
        // Connect to the proxy and perform the SOCKS5 UDP ASSOCIATE handshake.
        let tcp_stream = crate::common::socket::connect(&self.proxy_addr, PROXY_HANDSHAKE_TIMEOUT)
            .map_err(|e| {
                SolidTcpError::ProxyError(format!("UDP associate connect failed: {}", e))
            })?;

        #[cfg(target_os = "android")]
        {
            let fd = tcp_stream.as_raw_fd();
            if !protect_socket(fd) {
                warn!("Failed to protect UDP associate TCP socket fd={}", fd);
            } else {
                debug!("Protected UDP associate TCP socket fd={}", fd);
            }
        }

        let mut tcp_stream = tcp_stream;
        let _ = tcp_stream.set_read_timeout(Some(PROXY_HANDSHAKE_TIMEOUT));
        let _ = tcp_stream.set_write_timeout(Some(PROXY_HANDSHAKE_TIMEOUT));

        tcp_stream
            .write_all(&[0x05, 0x01, 0x00])
            .map_err(|e| SolidTcpError::ProxyError(format!("UDP greeting failed: {}", e)))?;

        let mut response = [0u8; 2];
        tcp_stream
            .read_exact(&mut response)
            .map_err(|e| SolidTcpError::ProxyError(format!("UDP response failed: {}", e)))?;

        if response[0] != 0x05 || response[1] != 0x00 {
            return Err(SolidTcpError::ProxyAuthFailed);
        }

        let request = [0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        tcp_stream.write_all(&request).map_err(|e| {
            SolidTcpError::ProxyError(format!("UDP associate request failed: {}", e))
        })?;

        let mut assoc_response = [0u8; 10];
        tcp_stream.read_exact(&mut assoc_response).map_err(|e| {
            SolidTcpError::ProxyError(format!("UDP associate response failed: {}", e))
        })?;

        if assoc_response[1] != 0x00 {
            return Err(SolidTcpError::ProxyError(format!(
                "UDP ASSOCIATE failed: {}",
                assoc_response[1]
            )));
        }

        let relay_addr = match assoc_response[3] {
            0x01 => {
                let ip = Ipv4Addr::new(
                    assoc_response[4],
                    assoc_response[5],
                    assoc_response[6],
                    assoc_response[7],
                );
                let port = u16::from_be_bytes([assoc_response[8], assoc_response[9]]);
                let ip = if ip.is_unspecified() {
                    Ipv4Addr::new(127, 0, 0, 1)
                } else {
                    ip
                };
                SocketAddr::new(IpAddr::V4(ip), port)
            }
            _ => {
                return Err(SolidTcpError::ProxyError(
                    "Unsupported relay address type".to_string(),
                ));
            }
        };

        debug!("UDP relay address: {}", relay_addr);

        let udp_socket = StdUdpSocket::bind("0.0.0.0:0")
            .map_err(|e| SolidTcpError::ProxyError(format!("UDP socket bind failed: {}", e)))?;

        #[cfg(target_os = "android")]
        {
            let fd = udp_socket.as_raw_fd();
            if !protect_socket(fd) {
                warn!("Failed to protect UDP relay socket fd={}", fd);
            } else {
                debug!("Protected UDP relay socket fd={}", fd);
            }
        }

        // The association outlives this call: the control connection is held
        // open (and dropped with the association) so the server keeps the
        // relay in place, and the pump is the only reader of the socket.
        let _ = udp_socket.set_read_timeout(Some(UDP_ASSOCIATION_IDLE));
        let _ = udp_socket.set_write_timeout(Some(UDP_SEND_TIMEOUT));

        let alive = Arc::new(AtomicBool::new(true));
        let pump_socket = udp_socket
            .try_clone()
            .map_err(|e| SolidTcpError::ProxyError(format!("UDP socket clone failed: {}", e)))?;
        let pump_control = tcp_stream
            .try_clone()
            .map_err(|e| SolidTcpError::ProxyError(format!("UDP control clone failed: {}", e)))?;
        let pump_alive = Arc::clone(&alive);
        let pump_tun_tx = self.tun_tx.clone();
        let pump_stats = self.stats.clone();

        std::thread::Builder::new()
            .name("tun-udp-relay".into())
            .spawn(move || {
                pump_udp_replies(
                    pump_socket,
                    pump_control,
                    src_addr,
                    dst_addr,
                    pump_tun_tx,
                    pump_stats,
                    pump_alive,
                );
            })
            .map_err(|e| {
                SolidTcpError::ProxyError(format!("Failed to spawn UDP reply pump: {}", e))
            })?;

        debug!(
            "UDP association ready: {} -> {} via {}",
            src_addr, dst_addr, relay_addr
        );

        Ok(UdpAssociation {
            relay_addr,
            socket: udp_socket,
            _control: tcp_stream,
            alive,
        })
    }

    fn establish_proxy_connection(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        domain: Option<String>,
        conn: Arc<RwLock<TcpConnection>>,
    ) -> Result<()> {
        info!(
            "=== Establishing proxy connection: {} -> {} (domain: {:?}) ===",
            src_addr, dst_addr, domain
        );

        let mut stream = crate::common::socket::connect(&self.proxy_addr, PROXY_HANDSHAKE_TIMEOUT)
            .map_err(|e| SolidTcpError::ProxyError(format!("Connect failed: {}", e)))?;

        #[cfg(target_os = "android")]
        {
            let fd = stream.as_raw_fd();
            if !protect_socket(fd) {
                warn!("Failed to protect proxy TCP socket fd={}", fd);
            }
        }

        let _ = stream.set_nodelay(true);
        let _ = stream.set_read_timeout(Some(PROXY_HANDSHAKE_TIMEOUT));
        let _ = stream.set_write_timeout(Some(PROXY_HANDSHAKE_TIMEOUT));

        self.socks5_handshake(&mut stream, dst_addr, domain.as_deref())?;

        info!("SOCKS5 handshake complete: {} -> {}", src_addr, dst_addr);

        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        // The writer owns this handle: it releases each chunk back to the
        // connection's receive window as it drains, and clears the liveness
        // flag when it leaves — see `ProxyWriter`.
        let proxy_writer = conn.write().set_proxy_tx(tx);

        let stream = Arc::new(stream);

        // Writer thread: drain the app->proxy channel and write to the proxy.
        let running = self.running.clone();
        let src_clone = src_addr;
        let dst_clone = dst_addr;
        // Weak, not a clone. The connection owns the channel's sender, so a
        // strong reference here would keep that sender alive for as long as
        // this thread runs — and this thread only ends when the sender is
        // dropped. Teardown (the reader removing the connection from the
        // manager) is what has to end it, so the writer must not be part of
        // what keeps it alive: with a clone here every finished flow left a
        // writer parked in `recv_timeout` for the life of the engine.
        let conn_for_ws = Arc::downgrade(&conn);
        let write_stream = stream.clone();
        let rx = rx;
        std::thread::Builder::new()
            .name("tun-proxy-write".into())
            .spawn(move || {
                let mut first_data = true;
                let mut write_buffer = Vec::with_capacity(65536);
                // Releases bytes back to the receive window as they reach the
                // proxy, and gives back anything still held if this thread
                // leaves early.
                let mut flow = proxy_writer;

                loop {
                    if !running.load(Ordering::Relaxed) {
                        break;
                    }

                    match rx.recv_timeout(PROXY_POLL_TIMEOUT) {
                        Ok(data) => {
                            if first_data && data.len() > 20 {
                                first_data = false;
                                if let Ok(text) = std::str::from_utf8(&data[..data.len().min(512)])
                                {
                                    let text_lower = text.to_lowercase();
                                    if text_lower.contains("upgrade: websocket")
                                        || text_lower.contains("connection: upgrade")
                                    {
                                        info!(
                                            "WebSocket upgrade detected for {} -> {}",
                                            src_clone, dst_clone
                                        );
                                        // The flow may already be gone; the
                                        // flag matters only while it is not.
                                        if let Some(conn) = conn_for_ws.upgrade() {
                                            conn.write().set_websocket(true);
                                        }
                                    }
                                }
                            }

                            flow.take(data.len());
                            write_buffer.extend_from_slice(&data);

                            let mut has_pending = false;
                            while let Ok(more) = rx.try_recv() {
                                flow.take(more.len());
                                write_buffer.extend_from_slice(&more);
                                has_pending = true;
                            }
                            if write_buffer.len() >= 16384 || !has_pending {
                                if let Err(e) = Self::write_all_sync(&write_stream, &write_buffer) {
                                    if is_peer_gone(&e) {
                                        debug!(
                                            "App->Proxy: peer closed ({}) for {} -> {}",
                                            e, src_clone, dst_clone
                                        );
                                    } else {
                                        warn!(
                                            "App->Proxy write error: {} for {} -> {}",
                                            e, src_clone, dst_clone
                                        );
                                    }
                                    break;
                                }
                                // On the wire now, so no longer occupying the
                                // receive window.
                                flow.written();
                                write_buffer.clear();
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            if !write_buffer.is_empty() {
                                if let Err(e) = Self::write_all_sync(&write_stream, &write_buffer) {
                                    if is_peer_gone(&e) {
                                        debug!(
                                            "App->Proxy: peer closed on flush ({}) for {} -> {}",
                                            e, src_clone, dst_clone
                                        );
                                    } else {
                                        warn!(
                                            "App->Proxy flush error: {} for {} -> {}",
                                            e, src_clone, dst_clone
                                        );
                                    }
                                    break;
                                }
                                flow.written();
                                write_buffer.clear();
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }

                if !write_buffer.is_empty() {
                    let _ = Self::write_all_sync(&write_stream, &write_buffer);
                }
            })
            .map_err(|e| SolidTcpError::ProxyError(format!("Failed to spawn writer: {}", e)))?;

        // Reader thread: read proxy->app data and emit TCP segments to TUN.
        let tun_tx = self.tun_tx.clone();
        let stats = self.stats.clone();
        let tcp_manager = self.tcp_manager.clone();
        let running = self.running.clone();
        let conn_clone = conn.clone();
        let read_stream = stream.clone();
        std::thread::Builder::new()
            .name("tun-proxy-read".into())
            .spawn(move || {
                let mut buf = vec![0u8; 65536];

                loop {
                    if !running.load(Ordering::Relaxed) {
                        break;
                    }

                    match (&*read_stream).read(&mut buf) {
                        Ok(0) => {
                            debug!("Proxy->App: EOF for {} -> {}", src_addr, dst_addr);
                            break;
                        }
                        Ok(n) => {
                            let send_info = {
                                let mut conn_guard = conn_clone.write();
                                let base_seq = conn_guard.snd_nxt();
                                let ack = conn_guard.rcv_nxt();
                                let mss = conn_guard.mss() as usize;

                                let ips = match (dst_addr.ip(), src_addr.ip()) {
                                    (IpAddr::V4(s), IpAddr::V4(d)) => Some((s, d)),
                                    _ => None,
                                };

                                if let Some((src_ip, dst_ip)) = ips {
                                    conn_guard.advance_snd_nxt(n as u32);
                                    // The window rides on every segment we emit,
                                    // so a sender that is being throttled on the
                                    // uplink learns about it here too.
                                    let window = conn_guard.recv_window() as u16;
                                    Some((base_seq, ack, mss, window, src_ip, dst_ip))
                                } else {
                                    warn!("IPv6 not supported");
                                    None
                                }
                            };

                            let (base_seq, ack, mss, window, src_ip, dst_ip) = match send_info {
                                Some(info) => info,
                                None => break,
                            };

                            let effective_mss = mss.min(1360);
                            let data = &buf[..n];
                            let mut offset = 0;
                            let mut seq = base_seq;
                            let mut packets_to_send = Vec::new();

                            while offset < data.len() {
                                let chunk_end = (offset + effective_mss).min(data.len());
                                let chunk = &data[offset..chunk_end];
                                let is_last = chunk_end == data.len();

                                let flags = if is_last || data.len() <= effective_mss {
                                    TcpFlags::psh_ack()
                                } else {
                                    TcpFlags::ack_only()
                                };

                                let packet = build_ipv4_tcp(
                                    src_ip,
                                    dst_ip,
                                    dst_addr.port(),
                                    src_addr.port(),
                                    seq,
                                    ack,
                                    flags,
                                    window,
                                    chunk,
                                    None,
                                );

                                packets_to_send.push(packet);

                                seq = seq.wrapping_add(chunk.len() as u32);
                                offset = chunk_end;
                            }

                            if let Some(ref tx) = tun_tx {
                                for packet in packets_to_send {
                                    stats.record_sent(packet.len());
                                    if tx.send(BytesMut::from(&packet[..])).is_err() {
                                        warn!("Failed to send to TUN");
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) if is_transient(&e) => {
                            continue;
                        }
                        Err(e) if is_peer_gone(&e) => {
                            debug!(
                                "Proxy->App: peer closed ({}) for {} -> {}",
                                e, src_addr, dst_addr
                            );
                            break;
                        }
                        Err(e) => {
                            warn!("Proxy read error: {} for {} -> {}", e, src_addr, dst_addr);
                            break;
                        }
                    }
                }

                let fin_info = {
                    let conn_guard = conn_clone.read();
                    let ips = match (dst_addr.ip(), src_addr.ip()) {
                        (IpAddr::V4(s), IpAddr::V4(d)) => Some((s, d)),
                        _ => None,
                    };
                    ips.map(|(src_ip, dst_ip)| {
                        (
                            conn_guard.snd_nxt(),
                            conn_guard.rcv_nxt(),
                            conn_guard.recv_window() as u16,
                            src_ip,
                            dst_ip,
                        )
                    })
                };

                if let Some((seq, ack, window, src_ip, dst_ip)) = fin_info {
                    if let Some(ref tx) = tun_tx {
                        let packet = build_ipv4_tcp(
                            src_ip,
                            dst_ip,
                            dst_addr.port(),
                            src_addr.port(),
                            seq,
                            ack,
                            TcpFlags::fin_ack(),
                            window,
                            &[],
                            None,
                        );
                        let _ = tx.send(BytesMut::from(&packet[..]));
                    }
                }

                tcp_manager.remove_connection(src_addr, dst_addr);
            })
            .map_err(|e| SolidTcpError::ProxyError(format!("Failed to spawn reader: {}", e)))?;

        Ok(())
    }

    fn socks5_handshake(
        &self,
        stream: &mut TcpStream,
        target: SocketAddr,
        domain: Option<&str>,
    ) -> Result<()> {
        stream
            .write_all(&[0x05, 0x01, 0x00])
            .map_err(|e| SolidTcpError::ProxyError(format!("Greeting failed: {}", e)))?;

        let mut response = [0u8; 2];
        stream
            .read_exact(&mut response)
            .map_err(|e| SolidTcpError::ProxyError(format!("Response failed: {}", e)))?;

        if response[0] != 0x05 || response[1] != 0x00 {
            return Err(SolidTcpError::ProxyAuthFailed);
        }

        let mut request = vec![0x05, 0x01, 0x00];

        if let Some(domain) = domain {
            request.push(0x03);
            request.push(domain.len() as u8);
            request.extend_from_slice(domain.as_bytes());
        } else {
            match target.ip() {
                IpAddr::V4(ip) => {
                    request.push(0x01);
                    request.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    request.push(0x04);
                    request.extend_from_slice(&ip.octets());
                }
            }
        }
        request.extend_from_slice(&target.port().to_be_bytes());

        stream
            .write_all(&request)
            .map_err(|e| SolidTcpError::ProxyError(format!("Connect request failed: {}", e)))?;

        let mut connect_response = [0u8; 10];
        stream
            .read_exact(&mut connect_response)
            .map_err(|e| SolidTcpError::ProxyError(format!("Connect response failed: {}", e)))?;

        if connect_response[1] != 0x00 {
            let error_msg = match connect_response[1] {
                0x01 => "General SOCKS server failure",
                0x02 => "Connection not allowed by ruleset",
                0x03 => "Network unreachable",
                0x04 => "Host unreachable",
                0x05 => "Connection refused",
                0x06 => "TTL expired",
                0x07 => "Command not supported",
                0x08 => "Address type not supported",
                _ => "Unknown error",
            };
            return Err(SolidTcpError::ProxyError(format!(
                "SOCKS5 connect failed: {} ({})",
                error_msg, connect_response[1]
            )));
        }

        match connect_response[3] {
            0x01 => {
                // IPv4 - already read enough
            }
            0x03 => {
                let domain_len = connect_response[4] as usize;
                let mut skip = vec![0u8; domain_len + 2 - 6];
                if !skip.is_empty() {
                    let _ = stream.read_exact(&mut skip);
                }
            }
            0x04 => {
                let mut skip = [0u8; 12];
                let _ = stream.read_exact(&mut skip);
            }
            _ => {}
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn transient_socket_errors_are_recognized() {
        // A stale timeout is not a broken connection: Unix reports `EAGAIN`
        // ("Try again", `WouldBlock`), Windows `WSAETIMEDOUT` (`TimedOut`).
        assert!(is_transient(&io::Error::from(io::ErrorKind::WouldBlock)));
        assert!(is_transient(&io::Error::from(io::ErrorKind::TimedOut)));
        assert!(is_transient(&io::Error::from(io::ErrorKind::Interrupted)));
        assert!(!is_transient(&io::Error::from(
            io::ErrorKind::ConnectionReset
        )));
        assert!(!is_transient(&io::Error::from(io::ErrorKind::BrokenPipe)));

        assert!(is_peer_gone(&io::Error::from(
            io::ErrorKind::ConnectionReset
        )));
        assert!(is_peer_gone(&io::Error::from(io::ErrorKind::BrokenPipe)));
        assert!(!is_peer_gone(&io::Error::from(io::ErrorKind::WouldBlock)));
        assert!(!is_peer_gone(&io::Error::from(io::ErrorKind::TimedOut)));
    }

    /// Regression for the relay killing live connections: a peer that stops
    /// reading fills the send window, so the write timeout expires and the
    /// error arrives as `WouldBlock`. The write must survive that and finish
    /// once the peer drains again.
    #[test]
    fn write_all_sync_waits_out_a_stalled_peer() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let writer = TcpStream::connect(addr).expect("connect loopback");
        let (reader, _) = listener.accept().expect("accept loopback");

        writer
            .set_write_timeout(Some(Duration::from_millis(50)))
            .expect("write timeout");

        // Far beyond any default send buffer, so the write has to stall.
        let payload = vec![0x5au8; 16 * 1024 * 1024];
        let expected = payload.len();
        let writer_thread =
            std::thread::spawn(move || StackProxy::write_all_sync(&writer, &payload));

        std::thread::sleep(Duration::from_millis(500));

        let mut sink = vec![0u8; 256 * 1024];
        let mut reader_ref = &reader;
        let mut received = 0usize;
        while received < expected {
            match reader_ref.read(&mut sink) {
                Ok(0) => break,
                Ok(n) => received += n,
                Err(_) => break,
            }
        }

        assert_eq!(
            received, expected,
            "draining the peer sees the whole payload"
        );
        assert!(
            writer_thread.join().expect("writer thread").is_ok(),
            "a stalled peer must delay the write, not fail it"
        );
    }

    fn start_stack_with_tun() -> (SolidStack, mpsc::Receiver<BytesMut>) {
        let mut stack = SolidStack::with_defaults();
        let (tx, rx) = mpsc::channel();
        stack.set_tun_tx(tx);
        stack.start();
        (stack, rx)
    }

    /// A client dialling a fake address the pool never issued — or issued in a
    /// previous session — must be reset at once. Ignoring the SYN leaves the app
    /// hanging and retrying instead of re-resolving, which is what the log spam
    /// in the field came from.
    #[test]
    fn a_fake_ip_without_a_mapping_is_reset() {
        let (stack, rx) = start_stack_with_tun();
        let client = Ipv4Addr::new(198, 18, 0, 1);
        let stale = Ipv4Addr::new(198, 18, 0, 29);
        let syn = build_ipv4_tcp(
            client,
            stale,
            40000,
            13861,
            1000,
            0,
            TcpFlags::syn_only(),
            64240,
            &[],
            Some(1460),
        );

        stack.process_packet(&syn).expect("the SYN is processed");

        let reply = rx
            .try_recv()
            .expect("an unmapped fake address is answered, not ignored");
        let parsed = parse_packet(&reply).expect("the reply parses");
        assert_eq!(parsed.src_addr, IpAddr::V4(stale));
        assert_eq!(parsed.dst_addr, IpAddr::V4(client));
        match parsed.transport {
            TransportInfo::Tcp(tcp) => {
                assert!(tcp.flags.rst, "a stale fake address must be reset");
                assert!(tcp.flags.ack);
                assert_eq!((tcp.src_port, tcp.dst_port), (13861, 40000));
            }
            other => panic!("expected a TCP answer, got {other:?}"),
        }
    }

    /// The mapped path still handshakes: an address that *is* in the pool gets a
    /// SYN-ACK and a session keyed by the domain it stands for.
    #[test]
    fn a_mapped_fake_ip_is_answered_with_syn_ack() {
        let (stack, rx) = start_stack_with_tun();
        let fake = stack
            .fake_ip_pool()
            .allocate("example.com")
            .expect("the pool has room");
        let client = Ipv4Addr::new(198, 18, 0, 1);
        let syn = build_ipv4_tcp(
            client,
            fake,
            40001,
            443,
            2000,
            0,
            TcpFlags::syn_only(),
            64240,
            &[],
            Some(1460),
        );

        stack.process_packet(&syn).expect("the SYN is processed");

        let reply = rx.try_recv().expect("a mapped fake address is answered");
        let parsed = parse_packet(&reply).expect("the reply parses");
        match parsed.transport {
            TransportInfo::Tcp(tcp) => assert!(
                tcp.flags.syn && tcp.flags.ack,
                "expected a SYN-ACK, got flags {:?}",
                tcp.flags
            ),
            other => panic!("expected a TCP answer, got {other:?}"),
        }
        assert_eq!(stack.tcp_manager().connection_count(), 1);
    }

    /// UDP to an unmapped fake address is dropped: the destination cannot be
    /// named, and forwarding it would ask a real proxy hop to dial a padding
    /// address from 198.18.0.0/16.
    #[test]
    fn udp_to_an_unmapped_fake_ip_is_dropped() {
        let (stack, rx) = start_stack_with_tun();
        let client = Ipv4Addr::new(198, 18, 0, 1);
        let stale = Ipv4Addr::new(198, 18, 0, 29);
        let datagram = build_ipv4_udp(client, stale, 50000, 443, &[0u8; 32]);

        stack
            .process_packet(&datagram)
            .expect("the datagram is processed");

        assert_eq!(
            stack.udp_manager().session_count(),
            0,
            "no UDP session is created for an unmapped fake address"
        );
        assert!(
            rx.try_recv().is_err(),
            "a dropped datagram emits nothing towards the TUN"
        );
    }
}
