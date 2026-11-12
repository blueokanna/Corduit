//! Platform-neutral TUN packet processing runtime.

use crate::netstack::error::{NetStackError, Result};
use crate::netstack::packet_queue::PacketSender;
use crate::netstack::solidtcp::packet::{TransportInfo, parse_packet};
use crate::netstack::solidtcp::{ClientDnsSettings, SolidStack, StackBuilder, StackStats};
#[cfg(test)]
use bytes::BytesMut;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::{net::Ipv4Addr, net::SocketAddr};
use tracing::{debug, info, warn};

const DNS_WORKERS: usize = 4;
const DNS_QUEUE_CAPACITY: usize = 64;

/// DNS may wait on upstream sockets. Its fixed worker and queue limits keep
/// those waits off the TUN reader without turning a DNS burst into unbounded
/// threads or packet retention. A full UDP queue drops packets for client retry.
struct DnsDispatch {
    sender: Mutex<Option<mpsc::SyncSender<Vec<u8>>>>,
    accepting: Arc<AtomicBool>,
}

impl DnsDispatch {
    fn new(work: impl Fn(&[u8]) + Send + Sync + 'static) -> std::io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Vec<u8>>(DNS_QUEUE_CAPACITY);
        let receiver = Arc::new(Mutex::new(receiver));
        let work = Arc::new(work);
        let accepting = Arc::new(AtomicBool::new(true));
        for index in 0..DNS_WORKERS {
            let receiver = Arc::clone(&receiver);
            let work = Arc::clone(&work);
            let accepting = Arc::clone(&accepting);
            std::thread::Builder::new()
                .name(format!("tun-dns-{index}"))
                .spawn(move || {
                    loop {
                        // Release the receiver lock before resolving; only dequeue
                        // is serialized, so independent queries run concurrently.
                        let packet = { receiver.lock().recv() };
                        let Ok(packet) = packet else { break };
                        if !accepting.load(Ordering::Acquire) {
                            break;
                        }
                        work(&packet);
                    }
                })?;
        }
        Ok(Self {
            sender: Mutex::new(Some(sender)),
            accepting,
        })
    }

    fn submit(&self, packet: &[u8]) -> Result<bool> {
        let sender = self.sender.lock();
        let sender = sender.as_ref().ok_or(NetStackError::NotRunning)?;
        match sender.try_send(packet.to_vec()) {
            Ok(()) => Ok(true),
            Err(mpsc::TrySendError::Full(_)) => Ok(false),
            Err(mpsc::TrySendError::Disconnected(_)) => Err(NetStackError::ChannelClosed),
        }
    }

    fn stop(&self) {
        self.accepting.store(false, Ordering::Release);
        self.sender.lock().take();
        // In-flight resolutions finish within their resolver deadlines. They
        // may not send or forward packets after the owning stack has stopped.
    }
}

impl Drop for DnsDispatch {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Traffic counters exposed to platform bridges.
#[derive(Debug, Clone, Default)]
pub struct TunTrafficStats {
    pub packets_received: u64,
    pub packets_sent: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub tcp_connections: usize,
    pub udp_sessions: usize,
    pub dns_queries: u64,
}

/// Owns the userspace TCP/IP stack that translates TUN packets to the local
/// SOCKS inbound. Platform code only owns the TUN descriptor and lifecycle.
pub struct TunPacketProcessor {
    stack: Arc<SolidStack>,
    running: AtomicBool,
    packet_count: AtomicU64,
    dns: DnsDispatch,
}

impl TunPacketProcessor {
    pub fn new(proxy_port: u16, mtu: u16, tun_tx: impl Into<PacketSender>) -> Self {
        Self::new_with_proxy_addr(
            SocketAddr::from((Ipv4Addr::LOCALHOST, proxy_port)),
            mtu,
            tun_tx,
        )
    }

    pub fn new_with_proxy_addr(
        proxy_addr: SocketAddr,
        mtu: u16,
        tun_tx: impl Into<PacketSender>,
    ) -> Self {
        Self::new_with_dns(proxy_addr, mtu, tun_tx, ClientDnsSettings::default())
    }

    /// Build a processor whose intercepted DNS follows the profile.
    ///
    /// The settings decide whether a query gets a fake address, a real answer,
    /// or is forwarded. Without them the responder applies its own default,
    /// which is how every `A` query ended up faked no matter what the profile
    /// asked for.
    pub fn new_with_dns(
        proxy_addr: SocketAddr,
        mtu: u16,
        tun_tx: impl Into<PacketSender>,
        dns: ClientDnsSettings,
    ) -> Self {
        Self::new_with_dns_and_auth(proxy_addr, mtu, tun_tx, dns, None)
    }

    /// As [`Self::new_with_dns`], with credentials for the local SOCKS5
    /// inbound when the profile configures `general.authentication`.
    pub fn new_with_dns_and_auth(
        proxy_addr: SocketAddr,
        mtu: u16,
        tun_tx: impl Into<PacketSender>,
        dns: ClientDnsSettings,
        credentials: Option<(String, String)>,
    ) -> Self {
        let mut builder = StackBuilder::new()
            .proxy_addr(proxy_addr)
            .mtu(usize::from(mtu))
            .dns_intercept(true)
            .client_dns(dns);
        if let Some((username, password)) = credentials {
            builder = builder.proxy_auth(username, password);
        }
        let mut stack = builder.build();
        stack.set_tun_tx(tun_tx);
        stack.start();

        let stack = Arc::new(stack);
        let dns_stack = Arc::clone(&stack);
        let dns = DnsDispatch::new(move |packet| {
            if let Err(error) = dns_stack.process_packet(packet) {
                warn!("DNS packet processing failed: {error}");
            }
        })
        .expect("failed to spawn TUN DNS workers");
        let cleanup_stack = Arc::clone(&stack);
        std::thread::Builder::new()
            .name("tun-cleanup".into())
            .spawn(move || {
                cleanup_stack.run_cleanup();
            })
            .expect("failed to spawn TUN cleanup thread");

        info!(%proxy_addr, mtu, "TUN packet processor started");
        Self {
            stack,
            running: AtomicBool::new(true),
            packet_count: AtomicU64::new(0),
            dns,
        }
    }

    pub fn process_packet(&self, packet: &[u8]) -> Result<()> {
        if !self.is_running() {
            return Err(NetStackError::NotRunning);
        }
        if packet.is_empty() {
            return Err(NetStackError::InvalidPacket("empty TUN packet".to_string()));
        }

        let packet_number = self.packet_count.fetch_add(1, Ordering::Relaxed) + 1;
        if packet_number <= 10 || packet_number.is_multiple_of(500) {
            debug!(packet_number, bytes = packet.len(), "processing TUN packet");
        }

        if parse_packet(packet).is_ok_and(
            |parsed| matches!(parsed.transport, TransportInfo::Udp(ref udp) if udp.dst_port == 53),
        ) {
            if !self.dns.submit(packet)? {
                self.stack.stats().record_dropped();
            }
            return Ok(());
        }

        self.stack
            .process_packet(packet)
            .map_err(|error| NetStackError::InvalidPacket(error.to_string()))
    }

    pub fn connection_count(&self) -> usize {
        self.stack.connection_count()
    }

    pub fn stats(&self) -> &Arc<StackStats> {
        self.stack.stats()
    }

    pub fn traffic_stats(&self) -> TunTrafficStats {
        let snapshot = self.stack.stats().snapshot();
        TunTrafficStats {
            packets_received: snapshot.packets_received,
            packets_sent: snapshot.packets_sent,
            bytes_received: snapshot.bytes_received,
            bytes_sent: snapshot.bytes_sent,
            tcp_connections: self.stack.tcp_manager().connection_count(),
            udp_sessions: self.stack.udp_manager().session_count(),
            dns_queries: snapshot.dns_queries,
        }
    }

    pub fn get_traffic_stats(&self) -> TunTrafficStats {
        self.traffic_stats()
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    pub fn stop(&self) {
        if self.running.swap(false, Ordering::AcqRel) {
            self.stack.stop();
            self.dns.stop();
            info!(
                packets = self.packet_count.load(Ordering::Relaxed),
                "TUN packet processor stopped"
            );
        }
    }

    pub fn reset(&self) {
        self.stack.fake_ip_pool().clear();
        self.stack.nat_table().clear();
        self.stack.tcp_manager().cleanup();
        self.stack.udp_manager().cleanup();
        self.packet_count.store(0, Ordering::Relaxed);
    }

    pub fn reset_fake_ip_pool(&self) {
        self.stack.fake_ip_pool().clear();
    }
}

impl Drop for TunPacketProcessor {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netstack::solidtcp::packet::{TcpFlags, build_ipv4_tcp, build_ipv4_udp};
    use std::net::{IpAddr, Ipv6Addr};
    use std::time::Duration;

    #[test]
    fn slow_dns_does_not_block_tcp_packets() {
        let (tx, replies) = mpsc::channel::<BytesMut>();
        let mut processor = TunPacketProcessor::new(7890, 1500, tx);
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let release_rx = Mutex::new(release_rx);
        processor.dns = DnsDispatch::new(move |_| {
            started_tx.send(()).unwrap();
            let _ = release_rx.lock().recv_timeout(Duration::from_secs(5));
        })
        .unwrap();

        let client = Ipv4Addr::new(198, 18, 0, 1);
        let dns = build_ipv4_udp(client, Ipv4Addr::new(198, 18, 0, 2), 50000, 53, &[0; 12]);
        processor.process_packet(&dns).unwrap();
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        // A stale fake address is answered with RST immediately. That TCP
        // response must arrive while the DNS worker is still blocked.
        let syn = build_ipv4_tcp(
            client,
            Ipv4Addr::new(198, 18, 0, 29),
            40000,
            443,
            1000,
            0,
            TcpFlags::syn_only(),
            64240,
            &[],
            Some(1460),
        );
        processor.process_packet(&syn).unwrap();
        let response = replies.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(matches!(parse_packet(&response).unwrap().transport,
            TransportInfo::Tcp(tcp) if tcp.flags.rst));
        processor.stop();
        drop(release_tx);
    }

    #[test]
    fn dns_queue_is_bounded_and_stop_discards_pending_queries() {
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let release_rx = Mutex::new(release_rx);
        let dispatch = DnsDispatch::new(move |_| {
            started_tx.send(()).unwrap();
            let _ = release_rx.lock().recv_timeout(Duration::from_secs(5));
        })
        .unwrap();
        for _ in 0..DNS_WORKERS {
            assert!(dispatch.submit(&[0]).unwrap());
        }
        for _ in 0..DNS_WORKERS {
            started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        }
        for _ in 0..DNS_QUEUE_CAPACITY {
            assert!(dispatch.submit(&[0]).unwrap());
        }
        assert!(!dispatch.submit(&[0]).unwrap());
        dispatch.stop();
        assert!(matches!(
            dispatch.submit(&[0]),
            Err(NetStackError::NotRunning)
        ));
        drop(release_tx);
        assert!(matches!(
            started_rx.recv_timeout(Duration::from_secs(1)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));
    }

    #[test]
    fn processor_rejects_packets_after_stop() {
        let (tx, _rx) = mpsc::channel::<BytesMut>();
        let processor = TunPacketProcessor::new(7890, 1500, tx);
        processor.stop();
        assert!(matches!(
            processor.process_packet(&[0x45]),
            Err(NetStackError::NotRunning)
        ));
    }

    #[test]
    fn processor_rejects_empty_packets() {
        let (tx, _rx) = mpsc::channel::<BytesMut>();
        let processor = TunPacketProcessor::new(7890, 1500, tx);
        assert!(matches!(
            processor.process_packet(&[]),
            Err(NetStackError::InvalidPacket(_))
        ));
    }

    #[test]
    fn processor_preserves_ipv6_proxy_endpoint() {
        let (tx, _rx) = mpsc::channel::<BytesMut>();
        let proxy_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 7890);
        let processor = TunPacketProcessor::new_with_proxy_addr(proxy_addr, 1500, tx);

        assert_eq!(processor.stack.proxy_addr(), proxy_addr);
        processor.stop();
    }
}
