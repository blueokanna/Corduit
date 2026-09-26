//! Packet parsing and building using smoltcp wire types

use crate::netstack::solidtcp::error::{Result, SolidTcpError};
use smoltcp::wire::{IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const DEFAULT_MTU: usize = 1500;
pub const DEFAULT_MSS_V4: u16 = 1360;
pub const DEFAULT_MSS_V6: u16 = 1340;

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
}

impl TcpFlags {
    pub fn syn_only() -> Self {
        Self {
            syn: true,
            ..Default::default()
        }
    }
    pub fn syn_ack() -> Self {
        Self {
            syn: true,
            ack: true,
            ..Default::default()
        }
    }
    pub fn ack_only() -> Self {
        Self {
            ack: true,
            ..Default::default()
        }
    }
    pub fn fin_ack() -> Self {
        Self {
            fin: true,
            ack: true,
            ..Default::default()
        }
    }
    pub fn rst_ack() -> Self {
        Self {
            rst: true,
            ack: true,
            ..Default::default()
        }
    }
    pub fn rst_only() -> Self {
        Self {
            rst: true,
            ..Default::default()
        }
    }
    pub fn psh_ack() -> Self {
        Self {
            psh: true,
            ack: true,
            ..Default::default()
        }
    }

    pub fn to_byte(&self) -> u8 {
        let mut flags = 0u8;
        if self.fin {
            flags |= 0x01;
        }
        if self.syn {
            flags |= 0x02;
        }
        if self.rst {
            flags |= 0x04;
        }
        if self.psh {
            flags |= 0x08;
        }
        if self.ack {
            flags |= 0x10;
        }
        flags
    }
}

#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub version: IpVersion,
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub protocol: IpProtocol,
    pub payload_offset: usize,
    pub payload_len: usize,
    pub transport: TransportInfo,
}

#[derive(Debug, Clone)]
pub enum TransportInfo {
    Tcp(TcpInfo),
    Udp(UdpInfo),
    Icmp,
    Other(u8),
}

#[derive(Debug, Clone)]
pub struct TcpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub mss: Option<u16>,
    pub payload_len: usize,
}

#[derive(Debug, Clone)]
pub struct UdpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload_len: usize,
}

impl ParsedPacket {
    pub fn src_socket(&self) -> Option<SocketAddr> {
        match &self.transport {
            TransportInfo::Tcp(t) => Some(SocketAddr::new(self.src_addr, t.src_port)),
            TransportInfo::Udp(u) => Some(SocketAddr::new(self.src_addr, u.src_port)),
            _ => None,
        }
    }

    pub fn dst_socket(&self) -> Option<SocketAddr> {
        match &self.transport {
            TransportInfo::Tcp(t) => Some(SocketAddr::new(self.dst_addr, t.dst_port)),
            TransportInfo::Udp(u) => Some(SocketAddr::new(self.dst_addr, u.dst_port)),
            _ => None,
        }
    }

    pub fn is_tcp_syn(&self) -> bool {
        matches!(&self.transport, TransportInfo::Tcp(t) if t.flags.syn && !t.flags.ack)
    }

    pub fn is_dns(&self) -> bool {
        matches!(&self.transport, TransportInfo::Udp(u) if u.dst_port == 53)
    }
}

/// Parse an IP packet
pub fn parse_packet(data: &[u8]) -> Result<ParsedPacket> {
    if data.is_empty() {
        return Err(SolidTcpError::PacketTooShort {
            expected: 1,
            actual: 0,
        });
    }

    let version = (data[0] >> 4) & 0x0F;
    match version {
        4 => parse_ipv4(data),
        6 => parse_ipv6(data),
        _ => Err(SolidTcpError::InvalidIpVersion(version)),
    }
}

fn parse_ipv4(data: &[u8]) -> Result<ParsedPacket> {
    let pkt = Ipv4Packet::new_checked(data)
        .map_err(|e| SolidTcpError::InvalidPacket(format!("IPv4: {}", e)))?;

    let ihl = ((data[0] & 0x0F) as usize) * 4;
    let payload = pkt.payload();
    let protocol = pkt.next_header();

    let src = pkt.src_addr();
    let dst = pkt.dst_addr();

    let transport = parse_transport(protocol, payload)?;

    Ok(ParsedPacket {
        version: IpVersion::Ipv4,
        src_addr: IpAddr::V4(src.into()),
        dst_addr: IpAddr::V4(dst.into()),
        protocol,
        payload_offset: ihl,
        payload_len: payload.len(),
        transport,
    })
}

fn parse_ipv6(data: &[u8]) -> Result<ParsedPacket> {
    let pkt = Ipv6Packet::new_checked(data)
        .map_err(|e| SolidTcpError::InvalidPacket(format!("IPv6: {}", e)))?;

    let payload = pkt.payload();
    let protocol = pkt.next_header();

    let src = pkt.src_addr();
    let dst = pkt.dst_addr();

    let transport = parse_transport(protocol, payload)?;

    Ok(ParsedPacket {
        version: IpVersion::Ipv6,
        src_addr: IpAddr::V6(src.into()),
        dst_addr: IpAddr::V6(dst.into()),
        protocol,
        payload_offset: 40,
        payload_len: payload.len(),
        transport,
    })
}

fn parse_transport(protocol: IpProtocol, payload: &[u8]) -> Result<TransportInfo> {
    match protocol {
        IpProtocol::Tcp => parse_tcp(payload),
        IpProtocol::Udp => parse_udp(payload),
        IpProtocol::Icmp | IpProtocol::Icmpv6 => Ok(TransportInfo::Icmp),
        _ => Ok(TransportInfo::Other(protocol.into())),
    }
}

fn parse_tcp(data: &[u8]) -> Result<TransportInfo> {
    let pkt = TcpPacket::new_checked(data)
        .map_err(|e| SolidTcpError::InvalidPacket(format!("TCP: {}", e)))?;

    let header_len = pkt.header_len() as usize;
    let mut mss = None;

    // Parse options for MSS
    if header_len > 20 && data.len() >= header_len {
        let opts = &data[20..header_len];
        let mut i = 0;
        while i < opts.len() {
            match opts[i] {
                0 => break,
                1 => i += 1,
                2 if i + 4 <= opts.len() => {
                    mss = Some(u16::from_be_bytes([opts[i + 2], opts[i + 3]]));
                    i += 4;
                }
                _ => {
                    if i + 1 < opts.len() && opts[i + 1] > 0 {
                        i += opts[i + 1] as usize;
                    } else {
                        break;
                    }
                }
            }
        }
    }

    Ok(TransportInfo::Tcp(TcpInfo {
        src_port: pkt.src_port(),
        dst_port: pkt.dst_port(),
        seq: pkt.seq_number().0 as u32,
        ack: pkt.ack_number().0 as u32,
        flags: TcpFlags {
            fin: pkt.fin(),
            syn: pkt.syn(),
            rst: pkt.rst(),
            psh: pkt.psh(),
            ack: pkt.ack(),
        },
        window: pkt.window_len(),
        mss,
        payload_len: data.len().saturating_sub(header_len),
    }))
}

fn parse_udp(data: &[u8]) -> Result<TransportInfo> {
    let pkt = UdpPacket::new_checked(data)
        .map_err(|e| SolidTcpError::InvalidPacket(format!("UDP: {}", e)))?;

    Ok(TransportInfo::Udp(UdpInfo {
        src_port: pkt.src_port(),
        dst_port: pkt.dst_port(),
        payload_len: pkt.payload().len(),
    }))
}

/// Build IPv4 TCP packet
#[allow(clippy::too_many_arguments)]
pub fn build_ipv4_tcp(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: TcpFlags,
    window: u16,
    payload: &[u8],
    mss: Option<u16>,
) -> Vec<u8> {
    use std::sync::atomic::{AtomicU16, Ordering};
    static IP_ID: AtomicU16 = AtomicU16::new(1);

    let tcp_opts_len = if flags.syn && mss.is_some() { 4 } else { 0 };
    let tcp_hdr_len = 20 + tcp_opts_len;
    let total_len = 20 + tcp_hdr_len + payload.len();

    let mut pkt = vec![0u8; total_len];

    // IPv4 header
    pkt[0] = 0x45;
    pkt[1] = 0x00;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());

    let ip_id = IP_ID.fetch_add(1, Ordering::Relaxed);
    pkt[4..6].copy_from_slice(&ip_id.to_be_bytes());

    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());

    let ip_cksum = checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    // TCP header
    let tcp_start = 20;
    pkt[tcp_start..tcp_start + 2].copy_from_slice(&src_port.to_be_bytes());
    pkt[tcp_start + 2..tcp_start + 4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[tcp_start + 4..tcp_start + 8].copy_from_slice(&seq.to_be_bytes());
    pkt[tcp_start + 8..tcp_start + 12].copy_from_slice(&ack.to_be_bytes());
    pkt[tcp_start + 12] = ((tcp_hdr_len / 4) as u8) << 4;
    pkt[tcp_start + 13] = flags.to_byte();
    pkt[tcp_start + 14..tcp_start + 16].copy_from_slice(&window.to_be_bytes());

    if flags.syn {
        if let Some(mss_val) = mss {
            pkt[tcp_start + 20] = 2;
            pkt[tcp_start + 21] = 4;
            pkt[tcp_start + 22..tcp_start + 24].copy_from_slice(&mss_val.to_be_bytes());
        }
    }

    let payload_start = tcp_start + tcp_hdr_len;
    if !payload.is_empty() {
        pkt[payload_start..payload_start + payload.len()].copy_from_slice(payload);
    }

    let tcp_cksum = tcp_checksum(&src_ip.octets(), &dst_ip.octets(), &pkt[tcp_start..]);
    pkt[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_cksum.to_be_bytes());

    pkt
}

/// Build an IPv6 TCP packet.
///
/// The IPv6 header carries no checksum of its own, so the only thing that
/// differs from the IPv4 builder is the 40-byte header and the pseudo-header
/// the TCP checksum is computed over.
#[allow(clippy::too_many_arguments)]
pub fn build_ipv6_tcp(
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: TcpFlags,
    window: u16,
    payload: &[u8],
    mss: Option<u16>,
) -> Vec<u8> {
    let tcp_opts_len = if flags.syn && mss.is_some() { 4 } else { 0 };
    let tcp_hdr_len = 20 + tcp_opts_len;
    let total_len = 40 + tcp_hdr_len + payload.len();

    let mut pkt = vec![0u8; total_len];

    // IPv6 header
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&((tcp_hdr_len + payload.len()) as u16).to_be_bytes());
    pkt[6] = 6;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src_ip.octets());
    pkt[24..40].copy_from_slice(&dst_ip.octets());

    // TCP header
    let tcp_start = 40;
    pkt[tcp_start..tcp_start + 2].copy_from_slice(&src_port.to_be_bytes());
    pkt[tcp_start + 2..tcp_start + 4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[tcp_start + 4..tcp_start + 8].copy_from_slice(&seq.to_be_bytes());
    pkt[tcp_start + 8..tcp_start + 12].copy_from_slice(&ack.to_be_bytes());
    pkt[tcp_start + 12] = ((tcp_hdr_len / 4) as u8) << 4;
    pkt[tcp_start + 13] = flags.to_byte();
    pkt[tcp_start + 14..tcp_start + 16].copy_from_slice(&window.to_be_bytes());

    if flags.syn {
        if let Some(mss_val) = mss {
            pkt[tcp_start + 20] = 2;
            pkt[tcp_start + 21] = 4;
            pkt[tcp_start + 22..tcp_start + 24].copy_from_slice(&mss_val.to_be_bytes());
        }
    }

    let payload_start = tcp_start + tcp_hdr_len;
    if !payload.is_empty() {
        pkt[payload_start..payload_start + payload.len()].copy_from_slice(payload);
    }

    let tcp_cksum = transport_checksum(&src_ip.octets(), &dst_ip.octets(), 6, &pkt[tcp_start..]);
    pkt[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_cksum.to_be_bytes());

    pkt
}

/// Build an IPv6 UDP packet. The UDP checksum is mandatory on IPv6.
pub fn build_ipv6_udp(
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 40 + 8 + payload.len();
    let mut pkt = vec![0u8; total_len];

    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    pkt[6] = 17;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src_ip.octets());
    pkt[24..40].copy_from_slice(&dst_ip.octets());

    let udp_len = (8 + payload.len()) as u16;
    pkt[40..42].copy_from_slice(&src_port.to_be_bytes());
    pkt[42..44].copy_from_slice(&dst_port.to_be_bytes());
    pkt[44..46].copy_from_slice(&udp_len.to_be_bytes());

    if !payload.is_empty() {
        pkt[48..].copy_from_slice(payload);
    }

    let udp_cksum = transport_checksum(&src_ip.octets(), &dst_ip.octets(), 17, &pkt[40..]);
    // A computed zero is transmitted as all ones: zero means "no checksum",
    // which IPv6 does not allow.
    let udp_cksum = if udp_cksum == 0 { 0xFFFF } else { udp_cksum };
    pkt[46..48].copy_from_slice(&udp_cksum.to_be_bytes());

    pkt
}

/// Build a TCP packet for either address family.
///
/// Mixed families cannot describe a real flow, so they are rejected instead
/// of being silently coerced into a v4 packet.
#[allow(clippy::too_many_arguments)]
pub fn build_tcp(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: TcpFlags,
    window: u16,
    payload: &[u8],
    mss: Option<u16>,
) -> Result<Vec<u8>> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => Ok(build_ipv4_tcp(
            src, dst, src_port, dst_port, seq, ack, flags, window, payload, mss,
        )),
        (IpAddr::V6(src), IpAddr::V6(dst)) => Ok(build_ipv6_tcp(
            src, dst, src_port, dst_port, seq, ack, flags, window, payload, mss,
        )),
        _ => Err(SolidTcpError::Unsupported(
            "mixed address families".to_string(),
        )),
    }
}

/// Build a UDP packet for either address family.
pub fn build_udp(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            Ok(build_ipv4_udp(src, dst, src_port, dst_port, payload))
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            Ok(build_ipv6_udp(src, dst, src_port, dst_port, payload))
        }
        _ => Err(SolidTcpError::Unsupported(
            "mixed address families".to_string(),
        )),
    }
}

/// Build IPv4 UDP packet
pub fn build_ipv4_udp(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
    let mut pkt = vec![0u8; total_len];

    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());

    let ip_cksum = checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    let udp_len = (8 + payload.len()) as u16;
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..26].copy_from_slice(&udp_len.to_be_bytes());

    if !payload.is_empty() {
        pkt[28..].copy_from_slice(payload);
    }

    let udp_cksum = udp_checksum(&src_ip.octets(), &dst_ip.octets(), &pkt[20..]);
    pkt[26..28].copy_from_slice(&udp_cksum.to_be_bytes());

    pkt
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = sum_words(data);
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

fn tcp_checksum(src: &[u8; 4], dst: &[u8; 4], tcp: &[u8]) -> u16 {
    transport_checksum(src, dst, 6, tcp)
}

fn udp_checksum(src: &[u8; 4], dst: &[u8; 4], udp: &[u8]) -> u16 {
    let cksum = transport_checksum(src, dst, 17, udp);
    if cksum == 0 {
        0xFFFF
    } else {
        cksum
    }
}

/// Ones-complement sum over arbitrary bytes, odd trailing byte padded.
fn sum_words(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    for i in (0..data.len()).step_by(2) {
        let word = if i + 1 < data.len() {
            ((data[i] as u32) << 8) | (data[i + 1] as u32)
        } else {
            (data[i] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }
    sum
}

/// Transport checksum over a v4 or v6 pseudo-header.
///
/// Both families sum the source address, the destination address, the
/// protocol and the upper-layer length; the v6 pseudo-header's zero padding
/// contributes nothing, so the same accumulation serves both.
fn transport_checksum(src: &[u8], dst: &[u8], proto: u8, data: &[u8]) -> u16 {
    let mut sum = sum_words(src);
    sum = sum.wrapping_add(sum_words(dst));
    sum = sum.wrapping_add(proto as u32);
    sum = sum.wrapping_add(data.len() as u32);
    sum = sum.wrapping_add(sum_words(data));
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Packet parser utility struct
pub struct PacketParser;

impl PacketParser {
    pub fn parse(data: &[u8]) -> Result<ParsedPacket> {
        parse_packet(data)
    }
}

/// Packet builder utility struct
pub struct PacketBuilder;

impl PacketBuilder {
    #[allow(clippy::too_many_arguments)]
    pub fn build_ipv4_tcp(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: TcpFlags,
        window: u16,
        payload: &[u8],
        mss: Option<u16>,
    ) -> Vec<u8> {
        build_ipv4_tcp(
            src_ip, dst_ip, src_port, dst_port, seq, ack, flags, window, payload, mss,
        )
    }

    pub fn build_ipv4_udp(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        build_ipv4_udp(src_ip, dst_ip, src_port, dst_port, payload)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_ipv6_tcp(
        src_ip: Ipv6Addr,
        dst_ip: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: TcpFlags,
        window: u16,
        payload: &[u8],
        mss: Option<u16>,
    ) -> Vec<u8> {
        build_ipv6_tcp(
            src_ip, dst_ip, src_port, dst_port, seq, ack, flags, window, payload, mss,
        )
    }

    pub fn build_ipv6_udp(
        src_ip: Ipv6Addr,
        dst_ip: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        build_ipv6_udp(src_ip, dst_ip, src_port, dst_port, payload)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_tcp(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: TcpFlags,
        window: u16,
        payload: &[u8],
        mss: Option<u16>,
    ) -> Result<Vec<u8>> {
        build_tcp(
            src_ip, dst_ip, src_port, dst_port, seq, ack, flags, window, payload, mss,
        )
    }

    pub fn build_udp(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        build_udp(src_ip, dst_ip, src_port, dst_port, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::{IpAddress, Ipv4Address, Ipv6Address, UdpPacket};

    fn v6(addr: &str) -> Ipv6Addr {
        addr.parse().expect("a literal v6 address")
    }

    fn v4_src_dst() -> (IpAddr, IpAddr) {
        (
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)),
        )
    }

    fn v6_src_dst() -> (IpAddr, IpAddr) {
        (
            IpAddr::V6(v6("2001:db8::1")),
            IpAddr::V6(v6("fd7a:115c:a1e0::1")),
        )
    }

    /// A v6 SYN-ACK must parse back with the right addresses, ports, flag and
    /// a checksum smoltcp accepts — the receiver is a real host's stack, not
    /// our parser.
    #[test]
    fn ipv6_tcp_round_trips_with_a_valid_checksum() {
        let (src, dst) = v6_src_dst();
        let payload = b"MSS probe";
        let packet = build_ipv6_tcp(
            v6("2001:db8::1"),
            v6("fd7a:115c:a1e0::1"),
            443,
            40000,
            1000,
            2000,
            TcpFlags::syn_ack(),
            64240,
            payload,
            Some(DEFAULT_MSS_V6),
        );

        let parsed = parse_packet(&packet).expect("the built packet parses");
        assert_eq!(parsed.src_addr, src);
        assert_eq!(parsed.dst_addr, dst);
        match parsed.transport {
            TransportInfo::Tcp(tcp) => {
                assert!(
                    tcp.flags.syn && tcp.flags.ack,
                    "SYN-ACK flags survive the build"
                );
                assert_eq!((tcp.src_port, tcp.dst_port), (443, 40000));
                assert_eq!(tcp.seq, 1000);
                assert_eq!(tcp.ack, 2000);
                assert_eq!(tcp.payload_len, payload.len());
                assert_eq!(tcp.mss, Some(DEFAULT_MSS_V6));
            }
            other => panic!("expected TCP, got {other:?}"),
        }

        let tcp = TcpPacket::new_checked(&packet[40..]).expect("the TCP header is well formed");
        assert!(
            tcp.verify_checksum(
                &IpAddress::Ipv6(Ipv6Address::from_bytes(&v6("2001:db8::1").octets())),
                &IpAddress::Ipv6(Ipv6Address::from_bytes(&v6("fd7a:115c:a1e0::1").octets())),
            ),
            "the TCP checksum must verify against the v6 pseudo-header"
        );
    }

    /// IPv6 forbids a zero UDP checksum, so a datagram whose sum lands on zero
    /// has to be transmitted as all ones.
    #[test]
    fn ipv6_udp_checksum_is_never_zero() {
        let packet = build_ipv6_udp(
            v6("2001:db8::1"),
            v6("fd7a:115c:a1e0::2"),
            53,
            40001,
            b"\x12\x34query",
        );

        let parsed = parse_packet(&packet).expect("the built packet parses");
        assert_eq!(parsed.dst_addr, IpAddr::V6(v6("fd7a:115c:a1e0::2")));

        let stored = u16::from_be_bytes([packet[46], packet[47]]);
        assert_ne!(stored, 0, "zero means 'no checksum' and is illegal on v6");

        let udp = UdpPacket::new_checked(&packet[40..]).expect("the UDP header is well formed");
        assert!(
            udp.verify_checksum(
                &IpAddress::Ipv6(Ipv6Address::from_bytes(&v6("2001:db8::1").octets())),
                &IpAddress::Ipv6(Ipv6Address::from_bytes(&v6("fd7a:115c:a1e0::2").octets())),
            ),
            "the UDP checksum must verify against the v6 pseudo-header"
        );
    }

    /// The checksum refactor has to leave v4 exactly as it was.
    #[test]
    fn ipv4_checksums_still_verify() {
        let tcp = build_ipv4_tcp(
            Ipv4Addr::new(203, 0, 113, 7),
            Ipv4Addr::new(198, 18, 0, 1),
            443,
            40000,
            5,
            6,
            TcpFlags::psh_ack(),
            64240,
            b"payload",
            None,
        );
        let packet = TcpPacket::new_checked(&tcp[20..]).expect("well formed");
        assert!(packet.verify_checksum(
            &IpAddress::Ipv4(Ipv4Address::new(203, 0, 113, 7)),
            &IpAddress::Ipv4(Ipv4Address::new(198, 18, 0, 1)),
        ));

        let udp = build_ipv4_udp(
            Ipv4Addr::new(203, 0, 113, 7),
            Ipv4Addr::new(198, 18, 0, 1),
            53,
            40001,
            b"dns",
        );
        let packet = UdpPacket::new_checked(&udp[20..]).expect("well formed");
        assert!(packet.verify_checksum(
            &IpAddress::Ipv4(Ipv4Address::new(203, 0, 113, 7)),
            &IpAddress::Ipv4(Ipv4Address::new(198, 18, 0, 1)),
        ));
    }

    /// The dispatchers pick the family from the addresses; a mixed pair is a
    /// caller bug and must not be silently turned into a v4 packet.
    #[test]
    fn family_dispatch_and_mixed_pairs() {
        let (v4_src, v4_dst) = v4_src_dst();
        let (v6_src, v6_dst) = v6_src_dst();

        let v4_packet = build_tcp(
            v4_src,
            v4_dst,
            1,
            2,
            0,
            0,
            TcpFlags::ack_only(),
            100,
            &[],
            None,
        )
        .expect("v4 dispatch");
        assert_eq!(v4_packet[0] >> 4, 4);

        let v6_packet = build_tcp(
            v6_src,
            v6_dst,
            1,
            2,
            0,
            0,
            TcpFlags::ack_only(),
            100,
            &[],
            None,
        )
        .expect("v6 dispatch");
        assert_eq!(v6_packet[0] >> 4, 6);

        assert!(build_tcp(
            v4_src,
            v6_dst,
            1,
            2,
            0,
            0,
            TcpFlags::ack_only(),
            100,
            &[],
            None
        )
        .is_err());
        assert!(build_udp(v6_src, v4_dst, 1, 2, &[]).is_err());
    }
}
