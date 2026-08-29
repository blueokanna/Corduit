//! Main TCP/IP stack coordinator

use crate::netstack::solidtcp::device::DeviceConfig;
use crate::netstack::solidtcp::dns::{DnsHandler, FakeIpConfig, FakeIpPool};
use crate::netstack::solidtcp::error::{Result, SolidTcpError};
use crate::netstack::solidtcp::nat::{NatConfig, NatTable};
use crate::netstack::solidtcp::packet::{
    build_ipv4_tcp, build_ipv4_udp, parse_packet, ParsedPacket, TcpFlags, TcpInfo, TransportInfo,
};
use crate::netstack::solidtcp::stats::StackStats;
use crate::netstack::solidtcp::tcp::{TcpAction, TcpConfig, TcpConnection, TcpManager};
use crate::netstack::solidtcp::udp::{UdpConfig, UdpManager};
use bytes::BytesMut;
use parking_lot::RwLock;
use smoltcp::wire::IpProtocol;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket as StdUdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;
use tracing::{debug, info, warn};

/// Timeout used for SOCKS5 handshake / UDP associate reads.
const PROXY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long proxy worker threads poll their queues between checks.
const PROXY_POLL_TIMEOUT: Duration = Duration::from_millis(100);

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
    info!("=== protect_socket called for fd={} ===", fd);
    let guard = PROTECT_CALLBACK.read();
    if let Some(ref callback) = *guard {
        info!("Calling protect callback for fd={}", fd);
        let result = callback(fd);
        if result {
            info!("Socket fd={} protected successfully", fd);
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
    pub fake_ip: FakeIpConfig,
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
            fake_ip: FakeIpConfig::default(),
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

    pub fn fake_ip_range(mut self, start: Ipv4Addr, size: u32) -> Self {
        self.config.fake_ip.range_start = start;
        self.config.fake_ip.pool_size = size;
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
}

impl SolidStack {
    pub fn new(config: StackConfig) -> Self {
        let fake_ip_pool = Arc::new(FakeIpPool::with_config(config.fake_ip.clone()));
        let dns_handler = Arc::new(DnsHandler::new(fake_ip_pool.clone()));

        Self {
            tcp_manager: Arc::new(TcpManager::with_config(config.tcp.clone())),
            udp_manager: Arc::new(UdpManager::with_config(config.udp.clone())),
            nat_table: Arc::new(NatTable::with_config(config.nat.clone())),
            fake_ip_pool,
            dns_handler,
            stats: Arc::new(StackStats::new()),
            running: Arc::new(AtomicBool::new(false)),
            tun_tx: None,
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
        let domain = if let IpAddr::V4(ip) = dst_addr.ip() {
            let d = self.fake_ip_pool.lookup(ip);
            if d.is_none() && self.fake_ip_pool.is_fake_ip(ip) {
                warn!("TCP SYN to Fake-IP {} but no domain mapping found!", ip);
            }
            d
        } else {
            None
        };

        info!(
            "=== TCP SYN received: {} -> {} (domain: {:?}, is_fake_ip: {}) ===",
            src_addr,
            dst_addr,
            domain,
            if let IpAddr::V4(ip) = dst_addr.ip() {
                self.fake_ip_pool.is_fake_ip(ip)
            } else {
                false
            }
        );

        if domain.is_none() {
            if let IpAddr::V4(ip) = dst_addr.ip() {
                if self.fake_ip_pool.is_fake_ip(ip) {
                    warn!(
                        "Cannot proxy connection to Fake-IP {} without domain mapping",
                        ip
                    );
                    self.send_tcp_packet(
                        dst_addr,
                        src_addr,
                        0,
                        tcp_info.seq.wrapping_add(1),
                        TcpFlags::rst_ack(),
                        &[],
                        None,
                    )?;
                    return Ok(());
                }
            }
        }

        let conn = self
            .tcp_manager
            .handle_syn(src_addr, dst_addr, tcp_info, domain.clone())?;
        self.stats.record_tcp_connection();

        let (our_seq, their_seq, mss) = {
            let conn = conn.read();
            (conn.snd_nxt().wrapping_sub(1), conn.rcv_nxt(), conn.mss())
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
            &[],
            Some(mss),
        )?;

        let stack = self.clone_for_proxy();
        let conn_clone = conn.clone();

        // Long-lived per-connection relay runs on a dedicated thread.
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
            nat_table: self.nat_table.clone(),
            stats: self.stats.clone(),
            running: self.running.clone(),
        }
    }

    fn execute_tcp_action(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        conn: &Arc<RwLock<TcpConnection>>,
        action: TcpAction,
    ) -> Result<()> {
        match action {
            TcpAction::SendAck => {
                let (seq, ack) = {
                    let conn = conn.read();
                    (conn.snd_nxt(), conn.rcv_nxt())
                };
                self.send_tcp_packet(
                    dst_addr,
                    src_addr,
                    seq,
                    ack,
                    TcpFlags::ack_only(),
                    &[],
                    None,
                )?;
            }
            TcpAction::SendFinAck => {
                let (seq, ack) = {
                    let conn = conn.read();
                    (conn.snd_nxt(), conn.rcv_nxt())
                };
                self.send_tcp_packet(dst_addr, src_addr, seq, ack, TcpFlags::fin_ack(), &[], None)?;
                let close_action = conn.write().close();
                if close_action == TcpAction::SendFin {}
            }
            TcpAction::SendFin => {
                let (seq, ack) = {
                    let conn = conn.read();
                    (conn.snd_nxt(), conn.rcv_nxt())
                };
                self.send_tcp_packet(dst_addr, src_addr, seq, ack, TcpFlags::fin_ack(), &[], None)?;
            }
            TcpAction::SendRst => {
                let seq = conn.read().snd_nxt();
                self.send_tcp_packet(dst_addr, src_addr, seq, 0, TcpFlags::rst_only(), &[], None)?;
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
                let (seq, ack) = {
                    let mut conn = conn.write();
                    let seq = conn.snd_nxt();
                    let ack = conn.rcv_nxt();
                    conn.advance_snd_nxt(data.len() as u32);
                    (seq, ack)
                };
                self.send_tcp_packet(
                    dst_addr,
                    src_addr,
                    seq,
                    ack,
                    TcpFlags::psh_ack(),
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
            Ok((response, domain)) => {
                if let Some(ref d) = domain {
                    info!("DNS query for domain: {} - Fake-IP allocated", d);
                    self.stats.record_fake_ip();
                }
                self.stats.record_dns_response();
                info!(
                    "DNS response ready: {} bytes, sending back to {} from {}",
                    response.len(),
                    src_addr,
                    dst_addr
                );

                match self.send_udp_packet(dst_addr, src_addr, &response) {
                    Ok(()) => {
                        info!("=== DNS response sent successfully to {} ===", src_addr);
                    }
                    Err(e) => {
                        warn!("Failed to send DNS response to {}: {}", src_addr, e);
                        return Err(e);
                    }
                }
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
        let domain = if let IpAddr::V4(ip) = dst_addr.ip() {
            self.fake_ip_pool.lookup(ip)
        } else {
            None
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

        let stack = self.clone_for_proxy();
        let payload_vec = payload.to_vec();

        // The UDP relay performs a single exchange with a timeout; run it on
        // a dedicated thread so packet processing never blocks on the proxy.
        if let Err(e) = std::thread::Builder::new()
            .name("tun-proxy-udp".into())
            .spawn(move || {
                if let Err(e) = stack.forward_udp(src_addr, dst_addr, domain, &payload_vec) {
                    debug!("UDP forward error: {} -> {}: {}", src_addr, dst_addr, e);
                }
            })
        {
            warn!("Failed to spawn UDP forward thread: {}", e);
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
            65535,
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

    #[allow(dead_code)]
    fn establish_proxy_connection(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        domain: Option<String>,
        conn: Arc<RwLock<TcpConnection>>,
    ) -> Result<()> {
        let proxy = self.clone_for_proxy();
        proxy.establish_proxy_connection(src_addr, dst_addr, domain, conn)
    }
}

struct StackProxy {
    proxy_addr: SocketAddr,
    tun_tx: Option<mpsc::Sender<BytesMut>>,
    tcp_manager: Arc<TcpManager>,
    #[allow(dead_code)]
    nat_table: Arc<NatTable>,
    stats: Arc<StackStats>,
    running: Arc<AtomicBool>,
}

impl StackProxy {
    /// Write the entire buffer to the shared TCP stream, looping on partial
    /// writes. `Write` is implemented for `&TcpStream`, so the same stream
    /// can be shared between the reader and writer threads.
    fn write_all_sync(mut stream: &TcpStream, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            match stream.write(data) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write whole buffer",
                    ));
                }
                Ok(n) => data = &data[n..],
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn forward_udp(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        domain: Option<String>,
        payload: &[u8],
    ) -> Result<()> {
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

        // 30s window for the single UDP response.
        let _ = udp_socket.set_read_timeout(Some(Duration::from_secs(30)));
        let _ = udp_socket.set_write_timeout(Some(Duration::from_secs(30)));

        let mut udp_request = Vec::with_capacity(payload.len() + 262);
        udp_request.extend_from_slice(&[0x00, 0x00, 0x00]);

        if let Some(ref domain) = domain {
            udp_request.push(0x03);
            udp_request.push(domain.len() as u8);
            udp_request.extend_from_slice(domain.as_bytes());
        } else {
            match dst_addr.ip() {
                IpAddr::V4(ip) => {
                    udp_request.push(0x01);
                    udp_request.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    udp_request.push(0x04);
                    udp_request.extend_from_slice(&ip.octets());
                }
            }
        }
        udp_request.extend_from_slice(&dst_addr.port().to_be_bytes());
        udp_request.extend_from_slice(payload);

        udp_socket
            .send_to(&udp_request, relay_addr)
            .map_err(|e| SolidTcpError::ProxyError(format!("UDP send failed: {}", e)))?;

        debug!(
            "UDP forwarded: {} -> {} ({} bytes)",
            src_addr,
            dst_addr,
            payload.len()
        );

        // Wait for the single response with the socket read timeout, then
        // send it back to the TUN device. Dropping the TCP control stream
        // afterwards closes the UDP association.
        let mut buf = vec![0u8; 65535];
        match udp_socket.recv_from(&mut buf) {
            Ok((n, _)) => {
                if n > 10 {
                    let atyp = buf[3];
                    let header_len = match atyp {
                        0x01 => 10,
                        0x03 => 7 + buf[4] as usize,
                        0x04 => 22,
                        _ => return Ok(()),
                    };

                    if n > header_len {
                        let response_payload = &buf[header_len..n];

                        if let Some(ref tx) = self.tun_tx {
                            let (src_ip, dst_ip) = match (dst_addr.ip(), src_addr.ip()) {
                                (IpAddr::V4(s), IpAddr::V4(d)) => (s, d),
                                _ => return Ok(()),
                            };

                            let packet = build_ipv4_udp(
                                src_ip,
                                dst_ip,
                                dst_addr.port(),
                                src_addr.port(),
                                response_payload,
                            );

                            self.stats.record_sent(packet.len());
                            let _ = tx.send(BytesMut::from(&packet[..]));
                        }
                    }
                }
            }
            Err(e) => {
                debug!("UDP recv error: {}", e);
            }
        }

        drop(tcp_stream);
        Ok(())
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
        conn.write().set_proxy_tx(tx);

        let stream = Arc::new(stream);

        // Writer thread: drain the app->proxy channel and write to the proxy.
        let running = self.running.clone();
        let src_clone = src_addr;
        let dst_clone = dst_addr;
        let conn_for_ws = conn.clone();
        let write_stream = stream.clone();
        let rx = rx;
        std::thread::Builder::new()
            .name("tun-proxy-write".into())
            .spawn(move || {
                let mut first_data = true;
                let mut write_buffer = Vec::with_capacity(65536);

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
                                        conn_for_ws.write().set_websocket(true);
                                    }
                                }
                            }

                            write_buffer.extend_from_slice(&data);

                            // std mpsc has no `is_empty`; probe for
                            // immediately-available data with `try_recv` and
                            // batch it in, then flush when the buffer is
                            // large or nothing more is queued.
                            let mut has_pending = false;
                            while let Ok(more) = rx.try_recv() {
                                write_buffer.extend_from_slice(&more);
                                has_pending = true;
                            }
                            if write_buffer.len() >= 16384 || !has_pending {
                                if let Err(e) = Self::write_all_sync(&write_stream, &write_buffer) {
                                    warn!(
                                        "App->Proxy write error: {} for {} -> {}",
                                        e, src_clone, dst_clone
                                    );
                                    break;
                                }
                                write_buffer.clear();
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            // Idle: flush any partial buffer so data is not
                            // held back indefinitely.
                            if !write_buffer.is_empty() {
                                if let Err(e) = Self::write_all_sync(&write_stream, &write_buffer) {
                                    warn!(
                                        "App->Proxy flush error: {} for {} -> {}",
                                        e, src_clone, dst_clone
                                    );
                                    break;
                                }
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
                            info!("Proxy->App: EOF for {} -> {}", src_addr, dst_addr);
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
                                    Some((base_seq, ack, mss, src_ip, dst_ip))
                                } else {
                                    warn!("IPv6 not supported");
                                    None
                                }
                            };

                            let (base_seq, ack, mss, src_ip, dst_ip) = match send_info {
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
                                    65535,
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
                        Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                            // Idle: re-check liveness and keep polling.
                            continue;
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
                        (conn_guard.snd_nxt(), conn_guard.rcv_nxt(), src_ip, dst_ip)
                    })
                };

                if let Some((seq, ack, src_ip, dst_ip)) = fin_info {
                    if let Some(ref tx) = tun_tx {
                        let packet = build_ipv4_tcp(
                            src_ip,
                            dst_ip,
                            dst_addr.port(),
                            src_addr.port(),
                            seq,
                            ack,
                            TcpFlags::fin_ack(),
                            65535,
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
