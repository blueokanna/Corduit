//! Hysteria2 outbound on the in-repo QUIC transport, following the official
//! Hysteria 2 protocol specification (hysteria.network/docs/developers/Protocol).
//!
//! This is **not** the legacy Hysteria v1 handshake: authentication is an
//! HTTP/3 request (`POST /auth`) carried on a QUIC bidirectional stream:
//!
//! ```text
//! HEADERS frame (QPACK block):
//!   :method       POST
//!   :scheme       https
//!   :authority    hysteria
//!   :path         /auth
//!   hysteria-auth <password>
//!   hysteria-cc-rx <rx bytes/sec>
//!   hysteria-padding <random>
//! response: :status 233 on success (anything else = auth failure)
//! ```
//!
//! Then per-connection proxy requests:
//!
//! ```text
//! TCP  bi-stream  [varint 0x401][varint addr_len][addr "host:port"][varint pad_len][pad]
//!      response   [u8 status][varint msg_len][msg][varint pad_len][pad]
//! UDP  datagram   [u32 session_id][u16 packet_id][u8 frag_id][u8 frag_count]
//!                 [varint addr_len][addr][payload]
//! ```
//!
//! UDP packets larger than a QUIC datagram are fragmented (same packet id,
//! `frag_count > 1`) and reassembled on receive, per the spec. Optional
//! "Salamander" obfuscation wraps every QUIC datagram at the socket layer via
//! [`crate::protocol::quic::Salamander`].
//!
//! Honest scope notes: `fingerprint` (TLS fingerprint mimicry) and `ports` /
//! `hop-interval` (source-port hopping) are parsed for config compatibility
//! but not applied — the courierust TLS stack cannot mimic a JA3 fingerprint
//! and the transport binds a single UDP socket. Both are logged loudly when
//! configured. Congestion control is the transport's NewReno-style AIMD
//! (Hysteria's TCP-Brutal controller is not reimplemented); the configured
//! `up`/`down` Mbps only feeds the `hysteria-cc-rx` rate hint.

use crate::common::stream::BoxStream;
use crate::engine::config::OutboundConfig;
use crate::engine::connection_tracker::TrackedConnection;
use crate::engine::error::{Error, Result};
use crate::engine::outbound::{OutboundProxy, TargetAddr};
use crate::engine::tls::yaml_value_to_string;
use crate::protocol::qpack::{decode_block, encode_literal_fields};
use crate::protocol::quic::{
    ClientConfig as QuicClientConfig, ClientConnection, QuicClient, QuicRecvStream, QuicSendStream,
    Salamander,
};
use bytes::Buf;
use parking_lot::{Mutex, RwLock};
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// TCP request frame id (Hysteria 2 protocol spec).
const HY2_TCP_REQUEST_ID: u64 = 0x401;
/// HTTP/3 frame / stream type constants used by the auth exchange.
const H3_FRAME_HEADERS: u64 = 0x01;
const H3_CONTROL_STREAM: u64 = 0x00;
const H3_SETTINGS_FRAME: u64 = 0x04;
/// Max UDP relay payload per QUIC datagram (conservative; the transport caps
/// a datagram at ~1200 bytes including headers).
const MAX_DATAGRAM_PAYLOAD: usize = 1100;
/// Reassembly TTL for fragmented UDP packets.
const FRAGMENT_TTL: Duration = Duration::from_secs(10);
/// Cap for auth / TCP response strings.
const MAX_RESPONSE_STRING: usize = 4096;

/// Obfuscation configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ObfsType {
    #[default]
    None,
    /// Salamander with a pre-shared string key (`obfs-password`).
    Salamander(String),
}

/// Hysteria2 outbound settings (kept for `hy2_config()` introspection and tests).
#[derive(Debug, Clone)]
pub struct Hysteria2Config {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub obfs: ObfsType,
    pub sni: Option<String>,
    pub skip_cert_verify: bool,
    pub alpn: Vec<String>,
    pub up_mbps: Option<u32>,
    pub down_mbps: Option<u32>,
    pub fingerprint: Option<String>,
    pub ports: Option<String>,
    pub hop_interval: Option<u32>,
    pub disable_mtu_discovery: bool,
}

impl Default for Hysteria2Config {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 443,
            password: String::new(),
            obfs: ObfsType::None,
            sni: None,
            skip_cert_verify: false,
            alpn: vec!["h3".to_string()],
            up_mbps: None,
            down_mbps: None,
            fingerprint: None,
            ports: None,
            hop_interval: None,
            disable_mtu_discovery: false,
        }
    }
}

/// A live, authenticated Hysteria2 session over one QUIC connection.
pub struct Hysteria2Connection {
    connection: Arc<ClientConnection>,
    password: String,
    authenticated: RwLock<bool>,
    down_mbps: Option<u32>,
    /// Fragmented UDP reassembly state (keyed by session id + packet id).
    assembler: Mutex<FragAssembler>,
}

impl Hysteria2Connection {
    pub fn new(
        connection: Arc<ClientConnection>,
        password: String,
        down_mbps: Option<u32>,
    ) -> Self {
        Self {
            connection,
            password,
            authenticated: RwLock::new(false),
            down_mbps,
            assembler: Mutex::new(FragAssembler::new()),
        }
    }

    /// Authenticate over HTTP/3 (`POST /auth`), waiting for `:status 233`.
    pub fn authenticate(&self) -> Result<()> {
        if *self.authenticated.read() {
            return Ok(());
        }

        // HTTP/3 setup streams (kept open, no FIN). A real client opens the
        // control stream, the QPACK encoder stream and the QPACK decoder
        // stream before issuing requests; some servers wait for them.
        for stream_type in [H3_CONTROL_STREAM, 0x02, 0x03] {
            if let Ok(mut s) = self.connection.open_uni() {
                let mut setup = Vec::with_capacity(6);
                write_varint(&mut setup, stream_type);
                if stream_type == H3_CONTROL_STREAM {
                    write_varint(&mut setup, H3_SETTINGS_FRAME);
                    write_varint(&mut setup, 0);
                }
                let _ = s.write_all(&setup);
            }
        }

        let (mut send, mut recv) = self
            .connection
            .open_bi()
            .map_err(|e| Error::network(format!("Failed to open auth stream: {e}")))?;

        let padding = random_padding();
        let rx_bps = self
            .down_mbps
            .map(|m| (m as u64) * 1024 * 1024 / 8)
            .unwrap_or(0);

        let fields: Vec<(&[u8], Vec<u8>)> = vec![
            (b":method", b"POST".to_vec()),
            (b":scheme", b"https".to_vec()),
            (b":authority", b"hysteria".to_vec()),
            (b":path", b"/auth".to_vec()),
            (b"hysteria-auth", self.password.as_bytes().to_vec()),
            (b"hysteria-cc-rx", rx_bps.to_string().into_bytes()),
            (b"hysteria-padding", padding),
        ];
        let field_refs: Vec<(&[u8], &[u8])> =
            fields.iter().map(|(n, v)| (*n, v.as_slice())).collect();
        let qpack = encode_literal_fields(&field_refs);

        let mut msg = Vec::with_capacity(qpack.len() + 8);
        write_varint(&mut msg, H3_FRAME_HEADERS);
        write_varint(&mut msg, qpack.len() as u64);
        msg.extend_from_slice(&qpack);

        send.write_all(&msg)
            .map_err(|e| Error::network(format!("Failed to send auth request: {e}")))?;
        send.finish()
            .map_err(|e| Error::network(format!("Failed to finish auth stream: {e}")))?;

        // Read response frames until the HEADERS frame arrives (bounded by
        // the 15s deadline: QUIC reads block, so retry on transient stalls).
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let (frame_type, payload) = read_h3_frame(&mut recv, 16384, deadline)
                .map_err(|e| Error::network(format!("Failed to read auth response: {e}")))?;
            if frame_type == H3_FRAME_HEADERS {
                let fields = decode_block(&payload)
                    .map_err(|e| Error::protocol(format!("QPACK decode failed: {e}")))?;
                let mut status_ok = false;
                for (name, value) in &fields {
                    if name.eq_ignore_ascii_case(b":status") {
                        status_ok = value == b"233";
                    }
                }
                if !status_ok {
                    let detail: Vec<String> = fields
                        .iter()
                        .map(|(n, v)| {
                            format!(
                                "{}: {}",
                                String::from_utf8_lossy(n),
                                String::from_utf8_lossy(v)
                            )
                        })
                        .collect();
                    return Err(Error::protocol(format!(
                        "Hysteria2 authentication rejected (status != 233): {}",
                        detail.join(", ")
                    )));
                }
                break;
            }
            // Ignore DATA / SETTINGS / other frames on the auth stream.
        }

        *self.authenticated.write() = true;
        debug!("Hysteria2 authentication completed");
        Ok(())
    }

    /// Open a TCP relay: send the `0x401` request and read the status byte.
    pub fn open_tcp_stream(&self, target: &TargetAddr) -> Result<(QuicSendStream, QuicRecvStream)> {
        self.authenticate()?;

        let (mut send, mut recv) = self
            .connection
            .open_bi()
            .map_err(|e| Error::network(format!("Failed to open bi stream: {e}")))?;

        let addr = encode_address(target);
        let mut msg = Vec::with_capacity(addr.len() + 8);
        write_varint(&mut msg, HY2_TCP_REQUEST_ID);
        write_varint(&mut msg, addr.len() as u64);
        msg.extend_from_slice(addr.as_bytes());
        write_varint(&mut msg, 0); // no padding

        send.write_all(&msg)
            .map_err(|e| Error::network(format!("Failed to send TCP request: {e}")))?;

        let status = read_tcp_response(&mut recv)?;
        if status != 0 {
            return Err(Error::protocol(format!(
                "Hysteria2 TCP connect failed (status {status})"
            )));
        }

        debug!("Hysteria2 TCP stream opened for target: {target}");
        Ok((send, recv))
    }

    /// Send one UDP payload as (possibly fragmented) QUIC datagrams.
    pub fn send_udp_packet(&self, session_id: u32, target: &TargetAddr, data: &[u8]) -> Result<()> {
        self.authenticate()?;

        let addr = encode_address(target);
        let header_len = 4 + 2 + 1 + 1 + varint_len(addr.len() as u64) + addr.len();
        let max_chunk = MAX_DATAGRAM_PAYLOAD.saturating_sub(header_len);
        let packet_id: u16 = crate::engine::random::u16();
        if data.len() <= max_chunk {
            let msg = write_udp_message(session_id, packet_id, 0, 1, &addr, data);
            self.connection
                .send_datagram(msg)
                .map_err(|e| Error::network(format!("Failed to send UDP datagram: {e}")))?;
            debug!(
                "Hysteria2 UDP packet sent to {target} ({} bytes)",
                data.len()
            );
            return Ok(());
        }

        let frag_count = data.len().div_ceil(max_chunk);
        if frag_count > 255 {
            return Err(Error::protocol(format!(
                "UDP payload too large to fragment ({} fragments)",
                frag_count
            )));
        }
        for (i, chunk) in data.chunks(max_chunk).enumerate() {
            let msg = write_udp_message(
                session_id,
                packet_id,
                i as u8,
                frag_count as u8,
                &addr,
                chunk,
            );
            self.connection
                .send_datagram(msg)
                .map_err(|e| Error::network(format!("Failed to send UDP fragment: {e}")))?;
        }
        debug!(
            "Hysteria2 UDP packet sent to {target} ({} bytes, {} fragments)",
            data.len(),
            frag_count
        );
        Ok(())
    }

    /// Receive the next complete UDP payload (reassembling fragments).
    pub fn recv_udp_packet(&self) -> Result<(u32, TargetAddr, Vec<u8>)> {
        loop {
            let datagram = self
                .connection
                .read_datagram()
                .map_err(|e| Error::network(format!("Failed to receive UDP datagram: {e}")))?;

            let (session_id, packet_id, frag_id, frag_count, target, payload) =
                parse_udp_message(&datagram)?;

            if frag_count == 1 {
                return Ok((session_id, target, payload));
            }

            let mut assembler = self.assembler.lock();
            if let Some(full) =
                assembler.add(session_id, packet_id, frag_id, frag_count, target, payload)
            {
                return Ok((session_id, full.0, full.1));
            }
        }
    }

    pub fn is_closed(&self) -> bool {
        self.connection.is_closed()
    }

    pub fn close(&self) {
        self.connection.close();
    }

    #[allow(dead_code)]
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }
}

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

/// QUIC varint (RFC 9000 §16) — length is implied by the top two bits.
fn write_varint(out: &mut Vec<u8>, value: u64) {
    match value {
        0..=63 => out.push(value as u8),
        64..=16_383 => {
            out.push(0x40 | ((value >> 8) as u8));
            out.push((value & 0xff) as u8);
        }
        16_384..=1_073_741_823 => {
            out.push(0x80 | ((value >> 24) as u8));
            out.push(((value >> 16) & 0xff) as u8);
            out.push(((value >> 8) & 0xff) as u8);
            out.push((value & 0xff) as u8);
        }
        _ => {
            out.push(0xc0 | ((value >> 56) as u8));
            for i in (0..7).rev() {
                out.push(((value >> (i * 8)) & 0xff) as u8);
            }
        }
    }
}

fn varint_len(value: u64) -> usize {
    match value {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    }
}

fn read_varint<R: Read>(r: &mut R, deadline: Instant) -> std::io::Result<u64> {
    let mut b = [0u8; 1];
    read_exact_deadline(r, &mut b, deadline)?;
    let first = b[0];
    let len = 1usize << (first >> 6);
    let mut value = (first & 0x3f) as u64;
    for _ in 1..len {
        read_exact_deadline(r, &mut b, deadline)?;
        value = (value << 8) | b[0] as u64;
    }
    Ok(value)
}

/// Read one HTTP/3 frame: `[frame_type varint][length varint][payload]`.
fn read_h3_frame<R: Read>(
    r: &mut R,
    max_len: usize,
    deadline: Instant,
) -> std::io::Result<(u64, Vec<u8>)> {
    let frame_type = read_varint(r, deadline)?;
    let len = read_varint(r, deadline)? as usize;
    if len > max_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("HTTP/3 frame too large ({len} bytes)"),
        ));
    }
    let mut payload = vec![0u8; len];
    read_exact_deadline(r, &mut payload, deadline)?;
    Ok((frame_type, payload))
}

/// Read the Hysteria2 TCP response header; returns the status byte.
///
/// The message and padding are drained best-effort with a hard cap so a
/// peer claiming a huge length field cannot make us block forever. Only the
/// status byte matters for the relay decision.
fn read_tcp_response<R: Read>(r: &mut R) -> Result<u8> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut b = [0u8; 1];
    read_exact_deadline(r, &mut b, deadline)
        .map_err(|e| Error::network(format!("Failed to read TCP response: {e}")))?;
    let status = b[0];

    if let Ok(msg_len) = read_varint(r, deadline) {
        let _ = skip_bounded(r, msg_len as usize, deadline);
        if let Ok(pad_len) = read_varint(r, deadline) {
            let _ = skip_bounded(r, pad_len as usize, deadline);
        }
    }
    Ok(status)
}

/// Read and discard up to `total` bytes, but never more than a bounded cap.
fn skip_bounded<R: Read>(r: &mut R, total: usize, deadline: Instant) -> std::io::Result<()> {
    let mut remaining = total.min(MAX_RESPONSE_STRING);
    let mut buf = [0u8; 512];
    while remaining > 0 {
        let take = remaining.min(buf.len());
        read_exact_deadline(r, &mut buf[..take], deadline)?;
        remaining -= take;
    }
    Ok(())
}

/// Read exactly `buf.len()` bytes, retrying transient stalls until
/// `deadline`. QUIC reads block with a bounded park, so a `read` returning
/// `WouldBlock`/`TimedOut` consumes nothing and can be safely retried.
fn read_exact_deadline(
    stream: &mut dyn Read,
    buf: &mut [u8],
    deadline: Instant,
) -> std::io::Result<()> {
    let mut pos = 0usize;
    while pos < buf.len() {
        match stream.read(&mut buf[pos..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected EOF",
                ))
            }
            Ok(n) => pos += n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "read timed out",
                    ));
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// `host:port` (bracketed IPv6), matching `net.JoinHostPort`.
fn encode_address(target: &TargetAddr) -> String {
    match target {
        TargetAddr::Domain(domain, port) => format!("{domain}:{port}"),
        TargetAddr::Ip(addr) => addr.to_string(),
    }
}

fn parse_address(s: &str) -> Result<TargetAddr> {
    if let Some(rest) = s.strip_prefix('[') {
        // [v6]:port
        let (ip, port_part) = rest
            .split_once(']')
            .ok_or_else(|| Error::protocol("Malformed bracketed address"))?;
        let port = port_part
            .strip_prefix(':')
            .ok_or_else(|| Error::protocol("Malformed bracketed address"))?;
        let ip: std::net::Ipv6Addr = ip
            .parse()
            .map_err(|_| Error::protocol("Invalid IPv6 address"))?;
        let port: u16 = port.parse().map_err(|_| Error::protocol("Invalid port"))?;
        Ok(TargetAddr::Ip(SocketAddr::V6(std::net::SocketAddrV6::new(
            ip, port, 0, 0,
        ))))
    } else {
        let (host, port) = s
            .rsplit_once(':')
            .ok_or_else(|| Error::protocol("Address has no port"))?;
        let port: u16 = port.parse().map_err(|_| Error::protocol("Invalid port"))?;
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            Ok(TargetAddr::Ip(SocketAddr::V4(std::net::SocketAddrV4::new(
                ip, port,
            ))))
        } else {
            Ok(TargetAddr::Domain(host.to_string(), port))
        }
    }
}

/// Encode one UDP relay message (Hysteria 2 spec).
fn write_udp_message(
    session_id: u32,
    packet_id: u16,
    frag_id: u8,
    frag_count: u8,
    addr: &str,
    payload: &[u8],
) -> Vec<u8> {
    let mut full = Vec::with_capacity(addr.len() + payload.len() + 16);
    full.extend_from_slice(&session_id.to_be_bytes());
    full.extend_from_slice(&packet_id.to_be_bytes());
    full.push(frag_id);
    full.push(frag_count);
    write_varint(&mut full, addr.len() as u64);
    full.extend_from_slice(addr.as_bytes());
    full.extend_from_slice(payload);
    full
}

fn parse_udp_message(data: &[u8]) -> Result<(u32, u16, u8, u8, TargetAddr, Vec<u8>)> {
    if data.len() < 8 {
        return Err(Error::protocol("UDP message too short"));
    }
    let mut buf = data;
    let session_id = buf.get_u32();
    let packet_id = buf.get_u16();
    let frag_id = buf.get_u8();
    let frag_count = buf.get_u8();

    // Address length is a varint; parse by hand since `Buf` gives no varint.
    let (addr_len, addr_bytes) = read_varint_slice(buf)?;
    if addr_len as usize > addr_bytes.len() {
        return Err(Error::protocol("UDP address truncated"));
    }
    let addr_str = std::str::from_utf8(&addr_bytes[..addr_len as usize])
        .map_err(|_| Error::protocol("UDP address not UTF-8"))?;
    let target = parse_address(addr_str)?;
    let payload = addr_bytes[addr_len as usize..].to_vec();
    Ok((session_id, packet_id, frag_id, frag_count, target, payload))
}

/// Parse a QUIC varint from a byte slice, returning `(value, rest)`.
fn read_varint_slice(data: &[u8]) -> Result<(u64, &[u8])> {
    let first = *data
        .first()
        .ok_or_else(|| Error::protocol("Empty varint"))?;
    let len = 1usize << (first >> 6);
    if data.len() < len {
        return Err(Error::protocol("Truncated varint"));
    }
    let mut value = (first & 0x3f) as u64;
    for &b in &data[1..len] {
        value = (value << 8) | b as u64;
    }
    Ok((value, &data[len..]))
}

/// One in-flight fragmented UDP packet.
type PendingFragment = (u8, BTreeMap<u8, Vec<u8>>, TargetAddr, Instant);

/// Reassembly buffer for fragmented UDP relay messages.
struct FragAssembler {
    /// (session_id, packet_id) -> pending fragment state.
    pending: HashMap<(u32, u16), PendingFragment>,
}

impl FragAssembler {
    fn new() -> Self {
        Self {
            pending: HashMap::new(),
        }
    }

    /// Insert a fragment; returns `(target, reassembled payload)` when the
    /// whole packet has arrived.
    fn add(
        &mut self,
        session_id: u32,
        packet_id: u16,
        frag_id: u8,
        frag_count: u8,
        target: TargetAddr,
        payload: Vec<u8>,
    ) -> Option<(TargetAddr, Vec<u8>)> {
        let now = Instant::now();
        // Prune expired entries (bounded memory).
        if self.pending.len() > 64 {
            let cutoff = now - FRAGMENT_TTL;
            self.pending.retain(|_, (_, _, _, at)| *at > cutoff);
        }

        let key = (session_id, packet_id);
        let entry = self
            .pending
            .entry(key)
            .or_insert_with(|| (frag_count, BTreeMap::new(), target.clone(), now));
        entry.1.insert(frag_id, payload);
        entry.3 = now;

        if entry.1.len() as u8 >= entry.0 {
            let (_, map, tgt, _) = self.pending.remove(&key)?;
            let mut full = Vec::new();
            for (_, chunk) in map {
                full.extend_from_slice(&chunk);
            }
            Some((tgt, full))
        } else {
            None
        }
    }
}

/// Random alphanumeric padding for the auth request.
fn random_padding() -> Vec<u8> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let len = 8 + (crate::engine::random::u8() as usize % 16);
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(ALPHABET[crate::engine::random::u8() as usize % ALPHABET.len()]);
    }
    out
}

// ---------------------------------------------------------------------------
// Outbound
// ---------------------------------------------------------------------------

pub struct Hysteria2Outbound {
    config: OutboundConfig,
    hy2_config: Hysteria2Config,
    connection: Mutex<Option<Arc<Hysteria2Connection>>>,
}

impl Hysteria2Outbound {
    pub fn new(config: OutboundConfig) -> Result<Self> {
        let server = config
            .server
            .as_ref()
            .ok_or_else(|| Error::config("Missing server address for Hysteria2"))?
            .clone();

        let port = config
            .port
            .ok_or_else(|| Error::config("Missing port for Hysteria2"))?;

        let password = config
            .options
            .get("password")
            .or_else(|| config.options.get("auth"))
            .map(yaml_value_to_string)
            .ok_or_else(|| Error::config("Missing password for Hysteria2"))?;

        let obfs = if let Some(obfs_type) = config.options.get("obfs").map(yaml_value_to_string) {
            if obfs_type.eq_ignore_ascii_case("salamander") {
                let obfs_password = config
                    .options
                    .get("obfs-password")
                    .map(yaml_value_to_string)
                    .unwrap_or_default();
                ObfsType::Salamander(obfs_password)
            } else {
                ObfsType::None
            }
        } else {
            ObfsType::None
        };

        let sni = config
            .options
            .get("sni")
            .map(yaml_value_to_string)
            .filter(|s| !s.is_empty());

        let skip_cert_verify = config
            .options
            .get("skip-cert-verify")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let alpn = config
            .options
            .get("alpn")
            .and_then(|v| v.as_array())
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_else(|| vec!["h3".to_string()]);

        let up_mbps = config
            .options
            .get("up")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        let down_mbps = config
            .options
            .get("down")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        let fingerprint = config
            .options
            .get("fingerprint")
            .map(yaml_value_to_string)
            .filter(|s| !s.is_empty());

        let ports = config
            .options
            .get("ports")
            .map(yaml_value_to_string)
            .filter(|s| !s.is_empty());

        let hop_interval = config
            .options
            .get("hop-interval")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        let disable_mtu_discovery = config
            .options
            .get("disable-mtu-discovery")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if fingerprint.is_some() {
            warn!(
                "Hysteria2 '{}': 'fingerprint' (TLS fingerprint mimicry) is not supported \
                 by the courierust TLS stack; ignoring",
                config.tag
            );
        }
        if ports.is_some() || hop_interval.is_some() {
            warn!(
                "Hysteria2 '{}': 'ports' / 'hop-interval' (source-port hopping) is not \
                 supported by the in-repo QUIC transport; ignoring",
                config.tag
            );
        }

        let hy2_config = Hysteria2Config {
            server,
            port,
            password,
            obfs,
            sni,
            skip_cert_verify,
            alpn,
            up_mbps,
            down_mbps,
            fingerprint,
            ports,
            hop_interval,
            disable_mtu_discovery,
        };

        debug!(
            "Creating Hysteria2 outbound: server={}:{}, obfs={:?}, up={:?}Mbps, down={:?}Mbps",
            hy2_config.server,
            hy2_config.port,
            hy2_config.obfs,
            hy2_config.up_mbps,
            hy2_config.down_mbps
        );

        Ok(Self {
            config,
            hy2_config,
            connection: Mutex::new(None),
        })
    }

    pub fn hy2_config(&self) -> &Hysteria2Config {
        &self.hy2_config
    }

    fn build_quic_config(&self, socket_addr: SocketAddr) -> Result<QuicClientConfig> {
        let server_name = self
            .hy2_config
            .sni
            .clone()
            .unwrap_or_else(|| self.hy2_config.server.clone());

        let mut cfg = QuicClientConfig::new(socket_addr, server_name);
        cfg.alpn = self.hy2_config.alpn.clone();
        cfg.skip_cert_verify = self.hy2_config.skip_cert_verify;
        cfg.idle_timeout = Duration::from_secs(30);
        cfg.keep_alive_interval = Some(Duration::from_secs(10));
        cfg.max_concurrent_bidi_streams = 100;
        cfg.max_concurrent_uni_streams = 100;
        if let ObfsType::Salamander(pwd) = &self.hy2_config.obfs {
            cfg.obfs = Some(Arc::new(Salamander::new(pwd.as_bytes())));
        }
        Ok(cfg)
    }

    fn get_or_create_connection(&self) -> Result<Arc<Hysteria2Connection>> {
        let mut conn_guard = self.connection.lock();

        if let Some(ref conn) = *conn_guard {
            if !conn.is_closed() {
                return Ok(conn.clone());
            }
        }

        let socket_addr: SocketAddr = crate::common::socket::resolve_host(
            &self.hy2_config.server,
            self.hy2_config.port,
            Duration::from_secs(30),
        )
        .map_err(|e| {
            Error::network(format!(
                "Failed to resolve Hysteria2 server {}:{}: {e}",
                self.hy2_config.server, self.hy2_config.port
            ))
        })?
        .into_iter()
        .next()
        .ok_or_else(|| {
            Error::network(format!(
                "No addresses found for Hysteria2 server {}:{}",
                self.hy2_config.server, self.hy2_config.port
            ))
        })?;

        let quic_config = self.build_quic_config(socket_addr)?;
        let client = QuicClient::new(quic_config);
        let connection = client
            .connect()
            .map_err(|e| Error::network(format!("QUIC connection failed: {e}")))?;

        debug!("Hysteria2 QUIC connection established to {socket_addr}");

        let hy2_conn = Arc::new(Hysteria2Connection::new(
            connection,
            self.hy2_config.password.clone(),
            self.hy2_config.down_mbps,
        ));

        hy2_conn.authenticate()?;

        *conn_guard = Some(hy2_conn.clone());

        Ok(hy2_conn)
    }

    pub fn relay_udp(&self, target: &TargetAddr, data: &[u8]) -> Result<Vec<u8>> {
        let conn = self.get_or_create_connection()?;
        let session_id: u32 = crate::engine::random::u32();

        conn.send_udp_packet(session_id, target, data)?;

        // QUIC datagram receive blocks until data; bound it with a dedicated
        // thread + channel receive timeout.
        let timeout = Duration::from_secs(30);
        let conn2 = conn.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(conn2.recv_udp_packet());
        });

        let (_recv_session_id, _recv_target, payload) = match rx.recv_timeout(timeout) {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return Err(Error::network(format!("UDP receive failed: {e}"))),
            Err(_) => return Err(Error::network("UDP receive timeout")),
        };
        Ok(payload)
    }
}

impl OutboundProxy for Hysteria2Outbound {
    fn connect(&self) -> Result<()> {
        let _conn = self.get_or_create_connection()?;
        info!(
            "Hysteria2 outbound '{}' connected to {}:{}",
            self.config.tag, self.hy2_config.server, self.hy2_config.port
        );
        Ok(())
    }

    fn disconnect(&self) -> Result<()> {
        let mut conn_guard = self.connection.lock();
        if let Some(conn) = conn_guard.take() {
            conn.close();
        }
        Ok(())
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn server_addr(&self) -> Option<(String, u16)> {
        Some((self.hy2_config.server.clone(), self.hy2_config.port))
    }

    fn supports_udp(&self) -> bool {
        true // Hysteria2 always supports UDP
    }

    fn relay_udp_packet(&self, target: &TargetAddr, data: &[u8]) -> Result<Vec<u8>> {
        self.relay_udp(target, data)
    }

    fn test_http_latency(&self, test_url: &str, timeout: Duration) -> Result<Duration> {
        use std::time::Instant;

        let url = crate::common::url::Url::parse(test_url)
            .map_err(|e| Error::config(format!("Invalid test URL: {e}")))?;

        let host = url
            .host_str()
            .ok_or_else(|| Error::config("Test URL has no host"))?
            .to_string();
        let url_port = url
            .port()
            .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        let path = if url.path().is_empty() {
            "/"
        } else {
            url.path()
        };

        let start = Instant::now();

        let conn = self.get_or_create_connection()?;

        let target = TargetAddr::Domain(host.clone(), url_port);
        let (mut send, mut recv) = conn.open_tcp_stream(&target)?;

        let http_request = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: Corduit/1.0\r\n\r\n"
        );

        send.write_all(http_request.as_bytes())
            .map_err(|e| Error::network(format!("Failed to send HTTP request: {e}")))?;

        // QUIC stream reads block until data; bound them via a thread + channel.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut response = vec![0u8; 1024];
            let r = recv.read(&mut response).map(|n| response[..n].to_vec());
            let _ = tx.send(r);
        });

        let response = match rx.recv_timeout(timeout) {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => return Err(Error::network(format!("Failed to read response: {e}"))),
            Err(_) => return Err(Error::network("Response timeout")),
        };

        let response_str = String::from_utf8_lossy(&response);
        if response_str.starts_with("HTTP/") {
            let elapsed = start.elapsed();
            info!("Hysteria2 latency test success: {}ms", elapsed.as_millis());
            Ok(elapsed)
        } else {
            Err(Error::network("Invalid HTTP response"))
        }
    }

    fn relay_tcp(&self, inbound: BoxStream, target: TargetAddr) -> Result<()> {
        self.relay_tcp_with_connection(inbound, target, None)
    }

    fn relay_tcp_with_connection(
        &self,
        inbound: BoxStream,
        target: TargetAddr,
        connection: Option<Arc<TrackedConnection>>,
    ) -> Result<()> {
        let conn = self.get_or_create_connection()?;
        let (send, recv) = conn.open_tcp_stream(&target)?;

        debug!(
            "Hysteria2: relaying TCP to {target} via {}:{}",
            self.hy2_config.server, self.hy2_config.port
        );

        let pair = QuicStreamPair::new(send, recv);
        relay_streams!(inbound, pair, connection)
    }
}

/// Combines a QUIC stream's send/recv halves into one duplex `SyncStream` so
/// the bidirectional relay can drive both directions concurrently (each half
/// is an independent handle to the same QUIC stream).
struct QuicStreamPair {
    send: Mutex<QuicSendStream>,
    recv: Mutex<QuicRecvStream>,
}

impl QuicStreamPair {
    fn new(send: QuicSendStream, recv: QuicRecvStream) -> Self {
        Self {
            send: Mutex::new(send),
            recv: Mutex::new(recv),
        }
    }
}

impl Read for QuicStreamPair {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.recv.lock().read(buf)
    }
}

impl Write for QuicStreamPair {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.send.lock().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.send.lock().flush()
    }
}

impl crate::common::stream::SyncStream for QuicStreamPair {
    fn shutdown(&self, how: std::net::Shutdown) -> std::io::Result<()> {
        if matches!(how, std::net::Shutdown::Write | std::net::Shutdown::Both) {
            // Half-close: queue the QUIC stream FIN after buffered data.
            self.send.lock().finish()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_obfs_type_default() {
        assert_eq!(ObfsType::default(), ObfsType::None);
    }

    #[test]
    fn test_hysteria2_config_default() {
        let config = Hysteria2Config::default();
        assert_eq!(config.port, 443);
        assert_eq!(config.alpn, vec!["h3".to_string()]);
        assert!(!config.skip_cert_verify);
        assert!(config.up_mbps.is_none());
        assert!(config.down_mbps.is_none());
    }

    #[test]
    fn test_varint_roundtrip() {
        // QUIC varints cap at 2^62 - 1 (the two top bits are the length).
        let max = (1u64 << 62) - 1;
        for value in [
            0u64,
            1,
            63,
            64,
            255,
            16383,
            16384,
            1_073_741_823,
            1_073_741_824,
            max,
        ] {
            let mut out = Vec::new();
            write_varint(&mut out, value);
            assert_eq!(varint_len(value), out.len());
            let (decoded, rest) = read_varint_slice(&out).unwrap();
            assert_eq!(decoded, value);
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn test_encode_address_variants() {
        assert_eq!(
            encode_address(&TargetAddr::Domain("example.com".to_string(), 443)),
            "example.com:443"
        );
        let v4 = SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::new(1, 2, 3, 4),
            80,
        ));
        assert_eq!(encode_address(&TargetAddr::Ip(v4)), "1.2.3.4:80");
        let v6 = SocketAddr::V6(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::LOCALHOST,
            443,
            0,
            0,
        ));
        assert_eq!(encode_address(&TargetAddr::Ip(v6)), "[::1]:443");
    }

    #[test]
    fn test_parse_address_roundtrip() {
        let cases = [
            TargetAddr::Domain("example.com".to_string(), 443),
            TargetAddr::Ip(SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::new(1, 2, 3, 4),
                8080,
            ))),
            TargetAddr::Ip(SocketAddr::V6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::LOCALHOST,
                8443,
                0,
                0,
            ))),
        ];
        for target in cases {
            let s = encode_address(&target);
            let parsed = parse_address(&s).unwrap();
            assert_eq!(parsed, target, "for {s}");
        }
    }

    #[test]
    fn test_parse_address_rejects_garbage() {
        assert!(parse_address("").is_err());
        assert!(parse_address("no-port").is_err());
        assert!(parse_address("host:notaport").is_err());
        assert!(parse_address("[::1]443").is_err());
    }

    #[test]
    fn test_udp_message_roundtrip() {
        let target = TargetAddr::Domain("example.com".to_string(), 443);
        let payload = b"hello hysteria2 udp";
        let msg = write_udp_message(0xdeadbeef, 0x1234, 2, 5, &encode_address(&target), payload);

        let (session, packet, frag_id, frag_count, decoded_target, decoded_payload) =
            parse_udp_message(&msg).unwrap();
        assert_eq!(session, 0xdeadbeef);
        assert_eq!(packet, 0x1234);
        assert_eq!(frag_id, 2);
        assert_eq!(frag_count, 5);
        assert_eq!(decoded_target, target);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn test_udp_message_rejects_short() {
        assert!(parse_udp_message(&[0u8; 7]).is_err());
    }

    #[test]
    fn test_fragment_assembler_reassembles() {
        let mut a = FragAssembler::new();
        let target = TargetAddr::Domain("example.com".to_string(), 443);
        assert!(a.add(1, 2, 0, 3, target.clone(), b"hel".to_vec()).is_none());
        assert!(a.add(1, 2, 2, 3, target.clone(), b"lo".to_vec()).is_none());
        let (t, full) = a
            .add(1, 2, 1, 3, target.clone(), b"lo wor".to_vec())
            .unwrap();
        assert_eq!(t, target);
        assert_eq!(full, b"hello worlo");
    }

    #[test]
    fn test_fragment_assembler_expires() {
        let mut a = FragAssembler::new();
        // Two distinct packets; the assembler keeps them separate.
        a.add(1, 1, 0, 2, TargetAddr::Domain("a".into(), 1), b"x".to_vec());
        let out = a.add(1, 2, 0, 1, TargetAddr::Domain("b".into(), 2), b"y".to_vec());
        assert_eq!(out.unwrap().1, b"y");
    }
}
