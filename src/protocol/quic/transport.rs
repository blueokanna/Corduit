//! QUIC v1 client transport (RFC 9000 + RFC 9002) built on courierust's
//! public packet/frame/protection codecs.
//!
//! A single driver thread owns the connected UDP socket and drives the
//! transport. All outbound datagrams are built under the state lock by
//! [`QuicConn::build_outbound`] and sent *after* the lock is released.
//! Inbound packets are un-protected, parsed, and fed into the shared
//! [`ConnState`]; waiters wake on per-stream / per-connection
//! [`Notify`](crate::common::sync::Notify) handles.
//!
//! The driver is fully synchronous: it blocks on `recv_from` with a short
//! socket read timeout (`DRIVER_POLL`), so it wakes on inbound traffic
//! immediately and otherwise re-checks timers and the writer latch every
//! poll interval. The timeout also bounds how long a stream write waits
//! before its queued bytes hit the wire.
//!
//! Loss recovery follows RFC 9002: per-space sent-packet tracking,
//! time-threshold loss detection, PTO probes with exponential backoff, and a
//! NewReno-style AIMD congestion controller. Flow control implements the
//! `MAX_DATA` / `MAX_STREAM_DATA` / `MAX_STREAMS` credit exchange in both
//! directions, and RFC 9221 datagrams are supported.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use courierust::courierust_quic::frame::Frame;
use courierust::courierust_quic::packet::{self, LongType, Packet as ParsedPacket};
use courierust::courierust_quic::protection::PacketKey;
use courierust::courierust_tls::crypto::rng::{self, ChaChaRng};

use super::config::ClientConfig;
use super::error::{QuicError, Result};
use super::obfs::Salamander;
use super::tls13::{Tls13Client, TransportParameters};
use crate::common::sync::Notify;
use crate::protocol::quic::{INITIAL_CWND, MAX_PACKET, MAX_UDP_PAYLOAD, MIN_CWND};

/// Driver poll interval: bounds both idle wakeup latency and how quickly a
/// queued write reaches the wire. 10 ms is comfortably below QUIC's own
/// timing granularity (PTO / ack delay are tens of ms) while keeping idle
/// syscalls at ~100/s per connection.
const DRIVER_POLL: Duration = Duration::from_millis(10);

/// Maximum in-memory per-stream send buffer before `poll_write` backpressures.
const MAX_SEND_BUFFER: usize = 4 * 1024 * 1024;
/// Maximum buffered receive bytes per stream.
const MAX_RECV_BUFFER: u64 = 16 * 1024 * 1024;
/// Bound on the packet numbers retained for ACK generation. RFC 9000 §19.3.1
/// permits implementations to limit ACK ranges; without a cap a long-lived
/// connection would accumulate every received packet number forever.
const MAX_ACK_QUEUE: usize = 256;
/// Per-packet overhead reserved when sizing a DATAGRAM frame (short header +
/// connection ID + packet number + AEAD tag + frame header). Conservative so
/// an accepted datagram always fits its own packet.
const DATAGRAM_OVERHEAD: u64 = 48;
/// Time-threshold loss factor (RFC 9002 §6.1.2).
const LOSS_REDUCTION: f64 = 9.0 / 8.0;
/// Retry integrity key/nonce (RFC 9001 §5.8; public by design).
const RETRY_KEY: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_NONCE: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0x2b,
];
/// The maximum ACK delay we advertise (ms).
const MAX_ACK_DELAY_MS: u64 = 25;
/// The ack delay exponent we advertise.
const ACK_DELAY_EXPONENT: u64 = 3;
/// Default packet number length used when sending.
const PN_LEN: usize = 2;

/// A QUIC packet-number space.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum PnSpace {
    Initial,
    Handshake,
    Application,
}

impl PnSpace {
    fn index(self) -> usize {
        match self {
            PnSpace::Initial => 0,
            PnSpace::Handshake => 1,
            PnSpace::Application => 2,
        }
    }
}

/// One sent packet, retained for ACK / loss processing.
struct SentPacket {
    pn: u64,
    time: Instant,
    size: usize,
    ack_eliciting: bool,
    in_flight: bool,
    /// Frames carried (for retransmission).
    frames: Vec<Frame>,
}

/// One packet-number space.
struct Space {
    next_pn: u64,
    largest_recv_pn: u64,
    ack_queue: BTreeSet<u64>,
    ack_pending: bool,
    sent: VecDeque<SentPacket>,
    /// CRYPTO bytes received (fed to the TLS layer).
    crypto_recv: Vec<u8>,
    /// CRYPTO bytes queued to send: `[crypto_acked, crypto_written)`.
    crypto_send: Vec<u8>,
    /// Absolute offset of `crypto_send[0]` (acked prefix).
    crypto_acked: u64,
    /// Absolute offset of the first unsent byte.
    crypto_sent: u64,
    /// Absolute offset of the last byte written by the TLS layer.
    crypto_written: u64,
    last_ack_eliciting: Option<Instant>,
    /// Read key (`None` once the space is discarded).
    key: Option<PacketKey>,
    /// Write key.
    write_key: Option<PacketKey>,
}

impl Space {
    fn new() -> Self {
        Self {
            next_pn: 0,
            largest_recv_pn: 0,
            ack_queue: BTreeSet::new(),
            ack_pending: false,
            sent: VecDeque::new(),
            crypto_recv: Vec::new(),
            crypto_send: Vec::new(),
            crypto_acked: 0,
            crypto_sent: 0,
            crypto_written: 0,
            last_ack_eliciting: None,
            key: None,
            write_key: None,
        }
    }

    fn has_crypto_to_send(&self) -> bool {
        self.crypto_sent < self.crypto_written
    }
}

/// Per-stream transport state.
pub(crate) struct StreamState {
    // send side
    send_buf: VecDeque<u8>,
    ack_pos: u64,
    write_pos: u64,
    sent_through: u64,
    /// Highest `sent_through` ever reached. Used for flow-control accounting:
    /// retransmissions rewind `sent_through` but must not consume connection
    /// credit a second time.
    sent_high: u64,
    peer_limit: u64,
    fin_queued: bool,
    fin_sent: bool,
    fin_acked: bool,
    reset_sent: Option<u64>,
    reset_recv: Option<u64>,
    send_notify: Arc<Notify>,
    // recv side
    recv_prefix: VecDeque<u8>,
    recv_contig: u64,
    recv_gaps: BTreeMap<u64, Vec<u8>>,
    peer_send_limit: u64,
    fin_recv: bool,
    fin_recv_offset: u64,
    recv_notify: Arc<Notify>,
}

impl StreamState {
    fn new(peer_limit: u64, peer_send_limit: u64) -> Self {
        Self {
            send_buf: VecDeque::new(),
            ack_pos: 0,
            write_pos: 0,
            sent_through: 0,
            sent_high: 0,
            peer_limit,
            fin_queued: false,
            fin_sent: false,
            fin_acked: false,
            reset_sent: None,
            reset_recv: None,
            send_notify: Arc::new(Notify::new()),
            recv_prefix: VecDeque::new(),
            recv_contig: 0,
            recv_gaps: BTreeMap::new(),
            peer_send_limit,
            fin_recv: false,
            fin_recv_offset: 0,
            recv_notify: Arc::new(Notify::new()),
        }
    }

    fn has_send_data(&self) -> bool {
        !self.fin_acked
            && (self.sent_through < self.write_pos || (self.fin_queued && !self.fin_sent))
    }

    fn buffered_recv(&self) -> u64 {
        self.recv_prefix.len() as u64 + self.recv_gaps.values().map(|v| v.len() as u64).sum::<u64>()
    }
}

/// The outcome of a non-blocking receive attempt.
pub(crate) enum RecvOutcome {
    Data(usize),
    WouldBlock,
    Eof,
    Reset(u64),
}

/// The shared QUIC connection state.
pub(crate) struct ConnState {
    pub(crate) config: ClientConfig,
    pub(crate) tls: Tls13Client,
    pub(crate) scid: Vec<u8>,
    pub(crate) dcid: Vec<u8>,
    retry_token: Vec<u8>,
    spaces: [Space; 3],
    pub(crate) streams: HashMap<u64, StreamState>,
    next_bidi: u64,
    next_uni: u64,
    peer_bidi_limit: u64,
    peer_uni_limit: u64,
    peer_max_data: u64,
    peer_max_stream_data_bidi: u64,
    peer_max_stream_data_uni: u64,
    total_sent: u64,
    total_acked: u64,
    my_max_stream_data_bidi_local: u64,
    my_max_stream_data_bidi_remote: u64,
    my_max_stream_data_uni: u64,
    max_data_advertised: u64,
    total_recv: u64,
    /// MAX_* frames queued to send.
    pending_max_data: Vec<u64>,
    pending_max_stream_data: Vec<(u64, u64)>,
    /// Outbound datagrams waiting to be sent.
    datagram_tx: VecDeque<Vec<u8>>,
    pub(crate) datagram_rx: VecDeque<Vec<u8>>,
    pub(crate) datagram_notify: Arc<Notify>,
    pub(crate) streams_notify: Arc<Notify>,
    pub(crate) handshake_complete: bool,
    handshake_confirmed: bool,
    /// Keep-alive: a PING has been scheduled (sent on the next flush).
    ping_pending: bool,
    pub(crate) closed: Option<QuicError>,
    last_recv: Instant,
    keep_alive_next: Instant,
    // congestion / loss
    cwnd: u64,
    ssthresh: u64,
    bytes_in_flight: u64,
    smoothed_rtt: Duration,
    rttvar: Duration,
    latest_rtt: Duration,
    pto_due: Option<Instant>,
    pto_count: u32,
    recovery_start: Option<Instant>,
}

/// The connection handle shared with streams and the facade.
pub(crate) struct QuicConn {
    pub(crate) udp: Arc<UdpSocket>,
    pub(crate) peer: SocketAddr,
    pub(crate) state: Mutex<ConnState>,
    pub(crate) writer: Notify,
    /// Optional packet obfuscation wrapping every datagram on the wire.
    pub(crate) obfs: Option<Arc<Salamander>>,
    /// Woken whenever the handshake completes or the connection closes (so
    /// waiters wake and re-check the connection state under the lock).
    pub(crate) handshake: Notify,
    pub(crate) shutdown: AtomicBool,
}

impl QuicConn {
    pub(crate) fn lock(&self) -> MutexGuard<'_, ConnState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Build a connection over an already-connected UDP socket and start the
    /// driver thread. The initial ClientHello flight is queued immediately.
    pub(crate) fn start(
        udp: UdpSocket,
        peer: SocketAddr,
        config: ClientConfig,
    ) -> Result<Arc<QuicConn>> {
        // The driver blocks on recv; a short read timeout turns a quiet
        // socket into a periodic wakeup so timers and queued writes get
        // serviced promptly.
        udp.set_read_timeout(Some(DRIVER_POLL))
            .map_err(|e| QuicError::Io(e.to_string()))?;
        let udp = Arc::new(udp);
        let mut rng_seed = [0u8; 44];
        rng::fill_random(&mut rng_seed);
        let mut rng = ChaChaRng::from_seed(&rng_seed);
        let scid = rand_vec(&mut rng, 8);
        let dcid = rand_vec(&mut rng, 8);

        let tp = TransportParameters {
            initial_max_data: config.initial_max_data,
            initial_max_stream_data_bidi_local: config.initial_max_stream_data,
            initial_max_stream_data_bidi_remote: config.initial_max_stream_data,
            initial_max_stream_data_uni: config.initial_max_stream_data,
            initial_max_streams_bidi: config.max_concurrent_bidi_streams,
            initial_max_streams_uni: config.max_concurrent_uni_streams,
            max_udp_payload_size: config.max_udp_payload_size,
            ack_delay_exponent: ACK_DELAY_EXPONENT,
            max_ack_delay: MAX_ACK_DELAY_MS,
            ..Default::default()
        };

        let roots = if config.skip_cert_verify {
            courierust::courierust_tls::RootStore::new()
        } else {
            crate::common::roots::system_root_store().clone()
        };

        let tls = Tls13Client::new(
            config.server_name.clone(),
            config.alpn.clone(),
            config.skip_cert_verify,
            roots,
            unix_now(),
            &tp,
            &scid,
        )
        .map_err(|e| QuicError::Tls(e.to_string()))?;

        // Obfuscation must be captured before `config` is moved into state.
        let config_obfs = config.obfs.clone();

        let mut state = ConnState {
            config,
            tls,
            scid: scid.clone(),
            dcid: dcid.clone(),
            retry_token: Vec::new(),
            spaces: [Space::new(), Space::new(), Space::new()],
            streams: HashMap::new(),
            next_bidi: 0,
            next_uni: 2,
            peer_bidi_limit: 0,
            peer_uni_limit: 0,
            peer_max_data: 0,
            peer_max_stream_data_bidi: 0,
            peer_max_stream_data_uni: 0,
            total_sent: 0,
            total_acked: 0,
            my_max_stream_data_bidi_local: tp.initial_max_stream_data_bidi_local,
            my_max_stream_data_bidi_remote: tp.initial_max_stream_data_bidi_remote,
            my_max_stream_data_uni: tp.initial_max_stream_data_uni,
            max_data_advertised: tp.initial_max_data,
            total_recv: 0,
            pending_max_data: Vec::new(),
            pending_max_stream_data: Vec::new(),
            datagram_tx: VecDeque::new(),
            datagram_rx: VecDeque::new(),
            datagram_notify: Arc::new(Notify::new()),
            streams_notify: Arc::new(Notify::new()),
            handshake_complete: false,
            handshake_confirmed: false,
            ping_pending: false,
            closed: None,
            last_recv: Instant::now(),
            keep_alive_next: Instant::now() + Duration::from_secs(60),
            cwnd: INITIAL_CWND,
            ssthresh: u64::MAX,
            bytes_in_flight: 0,
            smoothed_rtt: Duration::from_millis(333),
            rttvar: Duration::from_millis(333 / 2),
            latest_rtt: Duration::from_millis(333),
            pto_due: None,
            pto_count: 0,
            recovery_start: None,
        };

        // Initial keys + the queued ClientHello.
        state.spaces[0].write_key =
            Some(PacketKey::initial(&dcid, false).map_err(|e| QuicError::Protocol(e.to_string()))?);
        state.spaces[0].key =
            Some(PacketKey::initial(&dcid, true).map_err(|e| QuicError::Protocol(e.to_string()))?);
        state.spaces[0].crypto_send = state.tls.client_hello.clone();
        state.spaces[0].crypto_written = state.tls.client_hello.len() as u64;

        let conn = Arc::new(QuicConn {
            udp,
            peer,
            state: Mutex::new(state),
            writer: Notify::new(),
            obfs: config_obfs,
            handshake: Notify::new(),
            shutdown: AtomicBool::new(false),
        });

        let driver = conn.clone();
        std::thread::Builder::new()
            .name("corduit-quic-driver".into())
            .spawn(move || driver.run())
            .map_err(|e| QuicError::Io(e.to_string()))?;
        conn.writer.notify_one();
        Ok(conn)
    }

    // -------------------------------------------------------------------
    // Driver
    // -------------------------------------------------------------------

    /// The connection's driver loop: receive (bounded by the socket read
    /// timeout), process inbound, run timers, flush outbound, repeat.
    /// Exits when the connection is closed or [`QuicConn::close`] is called.
    fn run(self: Arc<Self>) {
        let mut buf = [0u8; MAX_PACKET];
        loop {
            // 1. Receive one datagram. A quiet socket times out after
            //    DRIVER_POLL and falls through to timer / writer servicing.
            match self.udp.recv_from(&mut buf) {
                Ok((n, _)) => {
                    let out = {
                        let mut st = self.lock();
                        st.last_recv = Instant::now();
                        match &self.obfs {
                            // Salamander: strip the 8-byte salt and XOR the
                            // keystream back out. Packets too short to carry
                            // a salt are invalid and discarded.
                            Some(obfs) => match obfs.deobfuscate_packet(&buf[..n]) {
                                Some(plain) => {
                                    if let Err(e) = self.process_inbound(&mut st, &plain) {
                                        self.process_fatal(&mut st, e);
                                        Vec::new()
                                    } else {
                                        self.build_outbound(&mut st)
                                    }
                                }
                                None => self.build_outbound(&mut st),
                            },
                            None => {
                                if let Err(e) = self.process_inbound(&mut st, &buf[..n]) {
                                    self.process_fatal(&mut st, e);
                                    Vec::new()
                                } else {
                                    self.build_outbound(&mut st)
                                }
                            }
                        }
                    };
                    self.send_all(&out);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::ConnectionReset
                    ) =>
                {
                    // Transient: idle socket, or (on Windows) an ICMP error
                    // surfacing on a connected UDP socket. Both are normal
                    // for QUIC — loss recovery is the activity authority,
                    // not per-recv errors.
                    let _ = self.writer.notified();
                    let out = {
                        let mut st = self.lock();
                        self.on_timer(&mut st);
                        self.build_outbound(&mut st)
                    };
                    self.send_all(&out);
                }
                Err(e) => {
                    let mut st = self.lock();
                    self.process_fatal(&mut st, QuicError::Io(e.to_string()));
                }
            }

            // 2. Exit once the connection is closed or shutdown is requested.
            let closed = {
                let st = self.lock();
                st.closed.is_some() || self.shutdown.load(Ordering::Acquire)
            };
            if closed {
                return;
            }
        }
    }

    fn send_all(&self, datagrams: &[Vec<u8>]) {
        for d in datagrams {
            if let Some(obfs) = &self.obfs {
                let _ = self.udp.send_to(&obfs.obfuscate_packet(d), self.peer);
            } else {
                let _ = self.udp.send_to(d, self.peer);
            }
        }
    }

    fn on_timer(&self, st: &mut ConnState) {
        if !st.handshake_complete && st.last_recv.elapsed() > st.config.handshake_timeout {
            st.closed = Some(QuicError::Timeout);
            self.handshake.notify_waiters();
            return;
        }
        if st.handshake_complete
            && st.config.keep_alive_interval.is_none()
            && st.last_recv.elapsed() > st.config.idle_timeout
        {
            st.closed = Some(QuicError::IdleTimeout);
            self.handshake.notify_waiters();
            return;
        }
        if st.handshake_complete {
            if let Some(_ka) = st.config.keep_alive_interval {
                if Instant::now() >= st.keep_alive_next {
                    // Send an ack-eliciting PING so the peer replies and the
                    // connection stays alive. An ACK frame alone is not
                    // ack-eliciting and would not solicit a response.
                    st.ping_pending = true;
                    st.keep_alive_next = Instant::now() + _ka;
                }
            }
        }
        if let Some(due) = st.pto_due {
            if Instant::now() >= due {
                self.send_probe(st);
            }
        }
    }

    // -------------------------------------------------------------------
    // Inbound
    // -------------------------------------------------------------------

    fn process_inbound(&self, st: &mut ConnState, data: &[u8]) -> Result<()> {
        if st.closed.is_some() || data.is_empty() {
            return Ok(());
        }
        let first = data[0];

        // Long-header packet: verify the version and that it is addressed to
        // our connection ID (RFC 9000 §5.2). Anything unrecognised is
        // discarded, not fatal — stray UDP can hit the socket at any time.
        if first & 0x80 != 0 {
            if data.len() < 5 {
                return Ok(());
            }
            let version = u32::from_be_bytes(data[1..5].try_into().unwrap());
            if version == 0 {
                // Version-negotiation packet: the server does not speak v1.
                return Err(QuicError::Protocol(
                    "server sent a version-negotiation packet".into(),
                ));
            }
            if version != crate::protocol::quic::QUIC_VERSION {
                return Ok(()); // unsupported version: drop
            }
            let ptype = (first >> 4) & 0x03;
            if ptype == 0x03 {
                return self.process_retry(st, data);
            }
            if data.len() < 6 {
                return Ok(());
            }
            let dcid_len = data[5] as usize;
            if dcid_len != st.scid.len()
                || data.len() < 6 + dcid_len
                || &data[6..6 + dcid_len] != st.scid.as_slice()
            {
                return Ok(()); // not addressed to us: drop
            }
            let space = match ptype {
                0x00 => PnSpace::Initial,
                0x01 => return Ok(()), // 0-RTT: not offered
                _ => PnSpace::Handshake,
            };
            let pn_offset = long_pn_offset(data)
                .ok_or_else(|| QuicError::Protocol("malformed long header".into()))?;
            return self.process_packet(st, data, space, pn_offset, true);
        }

        // Short-header packet: destination connection ID must match ours.
        let pn_offset = 1 + st.scid.len();
        if data.len() <= pn_offset || &data[1..pn_offset] != st.scid.as_slice() {
            return Ok(());
        }
        self.process_packet(st, data, PnSpace::Application, pn_offset, false)
    }

    fn process_retry(&self, st: &mut ConnState, data: &[u8]) -> Result<()> {
        let mut pos = 5usize; // first byte + version
        if data.len() < pos + 2 {
            return Err(QuicError::Protocol("truncated Retry".into()));
        }
        let dcid_len = data[pos] as usize;
        pos += 1;
        if data.len() < pos + dcid_len + 1 {
            return Err(QuicError::Protocol("truncated Retry".into()));
        }
        let retry_dcid = &data[pos..pos + dcid_len];
        pos += dcid_len;
        let scid_len = data[pos] as usize;
        pos += 1;
        if data.len() < pos + scid_len + 2 {
            return Err(QuicError::Protocol("truncated Retry".into()));
        }
        let retry_scid = &data[pos..pos + scid_len];
        pos += scid_len;
        let (token_len, used) = courierust::courierust_quic::varint::decode(&data[pos..])
            .map_err(|e| QuicError::Protocol(e.to_string()))?;
        pos += used;
        let token_len = token_len as usize;
        if data.len() < pos + token_len + 16 {
            return Err(QuicError::Protocol("truncated Retry".into()));
        }
        let token = &data[pos..pos + token_len];
        pos += token_len;
        let tag = &data[pos..pos + 16];

        // Integrity tag over the pseudo-packet (RFC 9001 §5.8).
        let mut pseudo = Vec::with_capacity(1 + dcid_len + 6 + scid_len + token_len);
        pseudo.push(dcid_len as u8);
        pseudo.extend_from_slice(retry_dcid);
        pseudo.push(0x40);
        pseudo.extend_from_slice(&crate::protocol::quic::QUIC_VERSION.to_be_bytes());
        pseudo.push(scid_len as u8);
        pseudo.extend_from_slice(retry_scid);
        let mut tok = courierust::courierust_quic::varint::encode(token_len as u64);
        tok.extend_from_slice(token);
        pseudo.extend_from_slice(&tok);

        // RFC 9000 §5.8: a client MUST discard a Retry whose DCID does not
        // match the one it sent or that fails the integrity check — it is a
        // stray/spoofed packet, not a reason to tear the connection down.
        if retry_dcid != st.dcid.as_slice()
            || courierust::courierust_tls::crypto::gcm::open(&RETRY_KEY, &RETRY_NONCE, &pseudo, tag)
                .is_none()
        {
            return Ok(());
        }

        // Restart the Initial space with the new DCID + token.
        st.dcid = retry_scid.to_vec();
        st.retry_token = token.to_vec();
        st.spaces[0] = Space::new();
        st.spaces[0].write_key = Some(
            PacketKey::initial(retry_scid, false)
                .map_err(|e| QuicError::Protocol(e.to_string()))?,
        );
        st.spaces[0].key = Some(
            PacketKey::initial(retry_scid, true).map_err(|e| QuicError::Protocol(e.to_string()))?,
        );
        st.spaces[0].crypto_send = st.tls.client_hello.clone();
        st.spaces[0].crypto_written = st.tls.client_hello.len() as u64;
        st.tls.reset_after_retry();
        Ok(())
    }

    fn process_packet(
        &self,
        st: &mut ConnState,
        data: &[u8],
        space: PnSpace,
        pn_offset: usize,
        long: bool,
    ) -> Result<()> {
        // The sample for header protection must be within the datagram.
        if data.len() < pn_offset + 4 + 16 + 1 {
            return Ok(());
        }
        let key = match &st.spaces[space.index()].key {
            Some(k) => k.clone(),
            None => return Ok(()),
        };

        let mut packet = data.to_vec();
        key.unprotect_header(&mut packet, pn_offset, long)
            .map_err(|e| QuicError::Protocol(e.to_string()))?;

        let parsed = packet::parse(
            &packet,
            st.spaces[space.index()].largest_recv_pn,
            st.scid.len(),
        )
        .map_err(|e| QuicError::Protocol(e.to_string()))?;
        let (pn, pn_len) = match &parsed {
            ParsedPacket::Long(h) => (h.packet_number, h.pn_len),
            ParsedPacket::Short(h) => (h.packet_number, h.pn_len),
        };
        let header_end = pn_offset + pn_len;
        if header_end > packet.len() {
            return Ok(());
        }

        // Duplicate or already-acked packet numbers are dropped.
        let largest = st.spaces[space.index()].largest_recv_pn;
        if pn <= largest && st.spaces[space.index()].ack_queue.contains(&pn) {
            return Ok(());
        }
        if pn <= largest.saturating_sub(1_000_000) {
            return Ok(()); // very old
        }

        // The server's source connection ID becomes our destination ID for
        // all subsequent packets (RFC 9000 §7.2).
        if let ParsedPacket::Long(h) = &parsed {
            if !h.scid.is_empty() {
                st.dcid = h.scid.clone();
            }
        }

        let plain = match key.open(pn, &packet[..header_end], &packet[header_end..]) {
            Ok(p) => p,
            Err(_) => return Ok(()), // auth failure: drop
        };

        let mut pos = 0usize;
        while pos < plain.len() {
            let (frame, used) =
                Frame::decode(&plain[pos..]).map_err(|e| QuicError::Protocol(e.to_string()))?;
            pos += used;
            self.process_frame(st, space, pn, frame)?;
        }

        if st.closed.is_none() {
            if pn > st.spaces[space.index()].largest_recv_pn {
                st.spaces[space.index()].largest_recv_pn = pn;
            }
            st.spaces[space.index()].ack_queue.insert(pn);
            st.spaces[space.index()].ack_pending = true;
            // Bound the ACK queue so a long-lived connection doesn't retain
            // every received packet number forever (RFC 9000 §19.3.1).
            let q = &mut st.spaces[space.index()].ack_queue;
            while q.len() > MAX_ACK_QUEUE {
                let oldest = *q.iter().next().expect("non-empty queue");
                q.remove(&oldest);
            }
        }
        Ok(())
    }

    fn process_frame(
        &self,
        st: &mut ConnState,
        space: PnSpace,
        _pn: u64,
        frame: Frame,
    ) -> Result<()> {
        match frame {
            Frame::Ack {
                largest_acked,
                ack_delay,
                ranges,
                ..
            } => self.on_ack(st, space, largest_acked, ack_delay, ranges),
            Frame::Crypto { offset, data } => self.on_crypto(st, space, offset, data),
            Frame::Stream {
                stream_id,
                offset,
                data,
                fin,
                ..
            } => self.on_stream(st, stream_id, offset.unwrap_or(0), data, fin),
            Frame::MaxData(max) => {
                if max > st.peer_max_data {
                    st.peer_max_data = max;
                    wake_senders(st);
                }
                Ok(())
            }
            Frame::MaxStreamData { stream_id, max } => {
                if let Some(s) = st.streams.get_mut(&stream_id) {
                    if max > s.peer_limit {
                        s.peer_limit = max;
                        s.send_notify.notify_waiters();
                    }
                }
                Ok(())
            }
            Frame::MaxStreams {
                unidirectional,
                max,
            } => {
                if unidirectional {
                    if max > st.peer_uni_limit {
                        st.peer_uni_limit = max;
                    }
                } else if max > st.peer_bidi_limit {
                    st.peer_bidi_limit = max;
                }
                st.streams_notify.notify_waiters();
                Ok(())
            }
            Frame::ResetStream {
                stream_id,
                app_error_code,
                ..
            } => {
                if let Some(s) = st.streams.get_mut(&stream_id) {
                    s.reset_recv = Some(app_error_code);
                    s.recv_notify.notify_waiters();
                }
                Ok(())
            }
            Frame::ConnectionClose {
                error_code, reason, ..
            } => {
                st.closed = Some(QuicError::ClosedByPeer {
                    error_code,
                    reason: String::from_utf8_lossy(&reason).into_owned(),
                });
                self.handshake.notify_waiters();
                wake_all(st);
                st.datagram_notify.notify_waiters();
                Ok(())
            }
            Frame::HandshakeDone => {
                st.handshake_confirmed = true;
                // Discard handshake keys.
                st.spaces[0].key = None;
                st.spaces[0].write_key = None;
                st.spaces[1].key = None;
                st.spaces[1].write_key = None;
                Ok(())
            }
            Frame::Datagram { data, .. } => {
                st.datagram_rx.push_back(data);
                st.datagram_notify.notify_waiters();
                Ok(())
            }
            Frame::StopSending { .. }
            | Frame::NewConnectionId { .. }
            | Frame::RetireConnectionId(_)
            | Frame::NewToken { .. }
            | Frame::PathChallenge(_)
            | Frame::PathResponse(_)
            | Frame::Padding(_)
            | Frame::DataBlocked(_)
            | Frame::StreamDataBlocked { .. }
            | Frame::StreamsBlocked { .. }
            | Frame::Ping => Ok(()),
        }
    }

    fn on_crypto(
        &self,
        st: &mut ConnState,
        space: PnSpace,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<()> {
        let sp = &mut st.spaces[space.index()];
        // Contiguous crypto handling (servers send CRYPTO in order; overlap
        // only occurs on retransmission).
        let expected = sp.crypto_recv.len() as u64;
        if offset == expected {
            sp.crypto_recv.extend_from_slice(&data);
        } else if offset < expected {
            let start = offset as usize;
            let new = (offset + data.len() as u64).min(expected) as usize;
            if new > start {
                sp.crypto_recv[start..new].copy_from_slice(&data[..new - start]);
            }
            if offset + data.len() as u64 > expected {
                let from = (expected - offset) as usize;
                sp.crypto_recv.extend_from_slice(&data[from..]);
            }
        } else {
            return Err(QuicError::Protocol("CRYPTO gap from peer".into()));
        }

        let consumed = st.tls.consume_crypto(&sp.crypto_recv)?;
        sp.crypto_recv.drain(..consumed);

        // The TLS layer may have queued the client Finished into the
        // handshake space's send buffer.
        let pending = st.tls.take_crypto_pending();
        if !pending.is_empty() {
            let hsp = &mut st.spaces[PnSpace::Handshake.index()];
            hsp.crypto_send.extend_from_slice(&pending);
            hsp.crypto_written += pending.len() as u64;
        }
        install_keys(st);
        if st.tls.is_complete() && !st.handshake_complete {
            st.handshake_complete = true;
            self.handshake.notify_waiters();
        }
        Ok(())
    }

    fn on_stream(
        &self,
        st: &mut ConnState,
        stream_id: u64,
        offset: u64,
        data: Vec<u8>,
        fin: bool,
    ) -> Result<()> {
        if !st.streams.contains_key(&stream_id) {
            st.streams.insert(
                stream_id,
                StreamState::new(0, recv_window_for(st, stream_id)),
            );
        }
        let s = st
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| QuicError::Protocol("stream vanished".into()))?;

        // Flow-control enforcement (RFC 9000 §4.1).
        let data_len = data.len() as u64;
        let end = offset + data_len;
        if end > s.peer_send_limit {
            return Err(QuicError::Protocol("stream flow-control violation".into()));
        }
        if s.buffered_recv() + data_len > MAX_RECV_BUFFER {
            return Err(QuicError::Protocol("receive buffer overflow".into()));
        }
        if fin {
            s.fin_recv = true;
            s.fin_recv_offset = end;
        }

        let prefix_end = s.recv_contig + s.recv_prefix.len() as u64;
        if offset <= prefix_end {
            let skip = (prefix_end - offset) as usize;
            if skip < data.len() {
                s.recv_prefix.extend(data[skip..].iter().copied());
            }
            promote_gaps(s);
        } else {
            // Out-of-order: merge into gaps, then promote if contiguous.
            insert_gap(s, offset, data);
            let pend = s.recv_contig + s.recv_prefix.len() as u64;
            if let Some(seg) = s.recv_gaps.remove(&pend) {
                s.recv_prefix.extend(seg);
                promote_gaps(s);
            }
        }

        st.total_recv = st.total_recv.saturating_add(data_len);
        s.recv_notify.notify_waiters();
        bump_recv_credit(st, stream_id);
        Ok(())
    }

    fn on_ack(
        &self,
        st: &mut ConnState,
        space: PnSpace,
        largest_acked: u64,
        ack_delay: u64,
        ranges: Vec<(u64, u64)>,
    ) -> Result<()> {
        let mut acked = BTreeSet::new();
        acked.insert(largest_acked);
        let first_len = ranges.first().map(|(_, l)| *l).unwrap_or(0);
        for i in 1..=first_len {
            acked.insert(largest_acked - i);
        }
        let mut cur = largest_acked - first_len;
        for (gap, len) in ranges.iter().skip(1) {
            cur = cur.saturating_sub(*gap + 1);
            for i in 0..=*len {
                acked.insert(cur.saturating_sub(i));
            }
            cur = cur.saturating_sub(*len);
        }

        // Drain sent packets, classifying into acked / lost / retained.
        let mut acked_frames: Vec<Frame> = Vec::new();
        let mut lost_frames: Vec<Frame> = Vec::new();
        let mut newest_acked_time: Option<(Instant, bool)> = None;
        let now = Instant::now();
        let mut retained: VecDeque<SentPacket> = VecDeque::new();
        let rtt_base = st.smoothed_rtt.max(st.latest_rtt);

        {
            let sp = &mut st.spaces[space.index()];
            for p in sp.sent.drain(..) {
                if acked.contains(&p.pn) {
                    if p.in_flight {
                        st.bytes_in_flight = st.bytes_in_flight.saturating_sub(p.size as u64);
                    }
                    if p.ack_eliciting {
                        newest_acked_time = Some((p.time, true));
                    }
                    acked_frames.extend(p.frames);
                } else if p.in_flight
                    && now.duration_since(p.time)
                        > Duration::from_secs_f64(rtt_base.as_secs_f64() * LOSS_REDUCTION)
                {
                    st.bytes_in_flight = st.bytes_in_flight.saturating_sub(p.size as u64);
                    lost_frames.extend(p.frames);
                } else {
                    retained.push_back(p);
                }
            }
            sp.sent = retained;
        }

        // Apply acked stream / crypto progress.
        for f in acked_frames {
            self.on_acked_frame(st, f);
        }
        for f in lost_frames {
            self.on_lost_frame(st, space, f);
        }

        // Congestion: grow the window per acked ack-eliciting packet.
        if !acked.is_empty() {
            self.on_acks_cc(st, acked.len() as u64);
        }

        if let Some((sent_at, _)) = newest_acked_time {
            let latest = sent_at.elapsed();
            let delay = Duration::from_millis(ack_delay << 3); // exp=3
            let adj = latest.saturating_sub(delay);
            if st.rttvar == Duration::from_millis(333 / 2)
                && st.smoothed_rtt == Duration::from_millis(333)
            {
                st.smoothed_rtt = latest;
                st.rttvar = latest / 2;
            } else {
                // abs_diff (stable 1.81) — hand-rolled for MSRV 1.78.
                let diff = if st.smoothed_rtt >= adj {
                    st.smoothed_rtt - adj
                } else {
                    adj - st.smoothed_rtt
                };
                st.rttvar = (st.rttvar * 3 + diff) / 4;
                st.smoothed_rtt = (st.smoothed_rtt * 7 + adj) / 8;
            }
            st.latest_rtt = latest;
        }
        st.pto_count = 0;
        st.pto_due = None;
        Ok(())
    }

    fn on_acked_frame(&self, st: &mut ConnState, f: Frame) {
        match f {
            Frame::Stream {
                stream_id,
                offset,
                data,
                fin,
                ..
            } => {
                if let Some(s) = st.streams.get_mut(&stream_id) {
                    let end = offset.unwrap_or(0) + data.len() as u64;
                    if end > s.ack_pos {
                        let drain = (end - s.ack_pos) as usize;
                        s.ack_pos = end;
                        let avail = s.send_buf.len();
                        s.send_buf.drain(..drain.min(avail));
                        if s.ack_pos >= s.write_pos {
                            s.send_buf.clear();
                        }
                        st.total_acked = st.total_acked.saturating_add(data.len() as u64);
                    }
                    if fin && end >= s.sent_through {
                        s.fin_acked = true;
                    }
                    s.send_notify.notify_waiters();
                }
            }
            Frame::Crypto { offset, data } => {
                let sp = &mut st.spaces[0];
                let _ = sp;
                // ACK for crypto: advance the acked prefix.
                for space_idx in 0..2 {
                    let sp = &mut st.spaces[space_idx];
                    let end = offset + data.len() as u64;
                    if end > sp.crypto_acked && end <= sp.crypto_written {
                        let drain = (end - sp.crypto_acked) as usize;
                        sp.crypto_acked = end;
                        let avail = sp.crypto_send.len();
                        sp.crypto_send.drain(..drain.min(avail));
                    }
                }
            }
            _ => {}
        }
    }

    fn on_lost_frame(&self, st: &mut ConnState, space: PnSpace, f: Frame) {
        match f {
            Frame::Stream {
                stream_id,
                offset,
                fin,
                ..
            } => {
                if let Some(s) = st.streams.get_mut(&stream_id) {
                    let start = offset.unwrap_or(0);
                    if start < s.sent_through {
                        s.sent_through = start;
                    }
                    if fin {
                        s.fin_sent = false;
                    }
                    s.send_notify.notify_waiters();
                }
            }
            Frame::Crypto { offset, .. } => {
                let sp = &mut st.spaces[space.index()];
                if offset < sp.crypto_sent {
                    sp.crypto_sent = offset;
                }
            }
            _ => {}
        }
        let in_recovery = st
            .recovery_start
            .map(|t| {
                Instant::now().duration_since(t) < st.smoothed_rtt.max(Duration::from_millis(1))
            })
            .unwrap_or(false);
        if !in_recovery {
            st.ssthresh = (st.cwnd / 2).max(MIN_CWND);
            st.cwnd = st.ssthresh;
            st.recovery_start = Some(Instant::now());
        }
    }

    fn on_acks_cc(&self, st: &mut ConnState, num_acked: u64) {
        let mss = 1200u64;
        if st.cwnd < st.ssthresh {
            st.cwnd = st.cwnd.saturating_add(mss * num_acked);
        } else {
            let inc = (mss * mss * num_acked) / st.cwnd.max(mss);
            st.cwnd = st.cwnd.saturating_add(inc);
        }
        if st.bytes_in_flight < st.cwnd / 2 {
            // Fast recovery ended.
            st.recovery_start = None;
        }
    }

    // -------------------------------------------------------------------
    // Outbound
    // -------------------------------------------------------------------

    /// Build all pending outbound datagrams. Must be called with the state
    /// lock held; the returned datagrams are sent by the caller after the
    /// lock is released.
    fn build_outbound(&self, st: &mut ConnState) -> Vec<Vec<u8>> {
        if st.closed.is_some() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let max_datagram = st.peer_max_udp_payload().min(MAX_UDP_PAYLOAD);

        for space in [PnSpace::Initial, PnSpace::Handshake, PnSpace::Application] {
            let idx = space.index();
            if st.spaces[idx].write_key.is_none() {
                continue;
            }

            if st.spaces[idx].ack_pending {
                if let Some(ack) = build_ack(&st.spaces[idx]) {
                    st.spaces[idx].ack_pending = false;
                    let mut frames = vec![ack];
                    let _ = self.send_one(st, space, &mut frames, false, max_datagram, &mut out);
                }
            }

            loop {
                let cwnd_avail = st.cwnd.saturating_sub(st.bytes_in_flight);
                if cwnd_avail < 40 {
                    break;
                }

                if space == PnSpace::Application {
                    if let Some(d) = st.datagram_tx.pop_front() {
                        if d.len() as u64 > max_datagram.saturating_sub(DATAGRAM_OVERHEAD) {
                            st.datagram_tx.push_front(d);
                        } else {
                            let mut frames = vec![Frame::Datagram {
                                data: d,
                                length: None,
                            }];
                            let _ = self.send_one(
                                st,
                                space,
                                &mut frames,
                                false,
                                max_datagram,
                                &mut out,
                            );
                            if out.len() >= 32 {
                                break;
                            }
                            continue;
                        }
                    }
                }

                let mut frames: Vec<Frame> = Vec::new();
                let mut ack_eliciting = false;

                // CRYPTO (Initial / Handshake). Chunked so a single frame
                // always fits inside one QUIC packet.
                if space != PnSpace::Application && st.spaces[idx].has_crypto_to_send() {
                    let sp = &st.spaces[idx];
                    let start = (sp.crypto_sent - sp.crypto_acked) as usize;
                    let take = (max_datagram.saturating_sub(50)) as usize;
                    let data: Vec<u8> = sp
                        .crypto_send
                        .iter()
                        .skip(start)
                        .take(take)
                        .copied()
                        .collect();
                    if !data.is_empty() {
                        frames.push(Frame::Crypto {
                            offset: sp.crypto_sent,
                            data,
                        });
                        ack_eliciting = true;
                    }
                }

                // STREAM + flow-control frames (application space).
                if space == PnSpace::Application {
                    self.collect_stream_frames(st, &mut frames, max_datagram, &mut ack_eliciting);
                }

                // Keep-alive PING (ack-eliciting, so the peer replies).
                if st.ping_pending {
                    frames.push(Frame::Ping);
                    ack_eliciting = true;
                    st.ping_pending = false;
                }

                // PTO probe.
                if space == PnSpace::Application && st.pto_due.is_some() && frames.is_empty() {
                    frames.push(Frame::Ping);
                    ack_eliciting = true;
                }

                if frames.is_empty() {
                    break;
                }

                if !self.send_one(
                    st,
                    space,
                    &mut frames,
                    ack_eliciting,
                    max_datagram,
                    &mut out,
                ) {
                    break;
                }
                if out.len() >= 32 {
                    break;
                }
            }
        }
        out
    }

    /// Encode, protect and enqueue one packet from `frames`. Returns `false`
    /// (rolling back the packet number) if the packet cannot be produced.
    /// Only ack-eliciting packets consume congestion-window credit and are
    /// tracked for loss recovery.
    fn send_one(
        &self,
        st: &mut ConnState,
        space: PnSpace,
        frames: &mut Vec<Frame>,
        ack_eliciting: bool,
        max_datagram: u64,
        out: &mut Vec<Vec<u8>>,
    ) -> bool {
        let idx = space.index();
        let mut payload = Vec::new();
        for f in frames.iter() {
            f.encode(&mut payload);
        }

        let (header, pn_offset, long) = match build_packet_header(st, space) {
            Ok(h) => h,
            Err(_) => return false,
        };
        let pn = st.spaces[idx].next_pn;
        st.spaces[idx].next_pn += 1;
        let key = match &st.spaces[idx].write_key {
            Some(k) => k.clone(),
            None => return false,
        };
        let sealed = match key.seal(pn, &header, &payload) {
            Ok(s) => s,
            Err(_) => {
                st.spaces[idx].next_pn -= 1;
                return false;
            }
        };

        let mut datagram = header;
        datagram.extend_from_slice(&sealed);
        if datagram.len() as u64 > max_datagram {
            st.spaces[idx].next_pn -= 1;
            return false;
        }
        if key.protect_header(&mut datagram, pn_offset, long).is_err() {
            st.spaces[idx].next_pn -= 1;
            return false;
        }

        // Advance CRYPTO sent offset.
        if space != PnSpace::Application {
            let sent_bytes = st.spaces[idx].crypto_sent;
            let data_len = match frames.iter().find(|f| matches!(f, Frame::Crypto { .. })) {
                Some(Frame::Crypto { data, .. }) => data.len() as u64,
                _ => 0,
            };
            st.spaces[idx].crypto_sent = sent_bytes + data_len;
        }

        if ack_eliciting {
            st.bytes_in_flight = st.bytes_in_flight.saturating_add(datagram.len() as u64);
            st.spaces[idx].last_ack_eliciting = Some(Instant::now());
            st.spaces[idx].sent.push_back(SentPacket {
                pn,
                time: Instant::now(),
                size: datagram.len(),
                ack_eliciting: true,
                in_flight: true,
                frames: std::mem::take(frames),
            });
            st.pto_due = Some(Instant::now() + self.pto_period(st));
        }
        out.push(datagram);
        true
    }

    fn collect_stream_frames(
        &self,
        st: &mut ConnState,
        frames: &mut Vec<Frame>,
        max_datagram: u64,
        ack_eliciting: &mut bool,
    ) {
        let mut budget = max_datagram.saturating_sub(50);

        // Flow-control credit updates first.
        for max in st.pending_max_data.drain(..) {
            frames.push(Frame::MaxData(max));
        }
        for (sid, max) in st.pending_max_stream_data.drain(..) {
            frames.push(Frame::MaxStreamData {
                stream_id: sid,
                max,
            });
        }

        let ids: Vec<u64> = st
            .streams
            .iter()
            .filter(|(_, s)| s.has_send_data())
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            if budget < 16 {
                break;
            }
            let send_limit = if id & 1 == 0 {
                st.peer_max_stream_data_bidi
            } else {
                st.peer_max_stream_data_uni
            };
            let s = match st.streams.get_mut(&id) {
                Some(s) => s,
                None => continue,
            };
            if s.reset_sent.is_some() {
                continue;
            }
            let avail = (send_limit.saturating_sub(s.sent_through))
                .min(st.peer_max_data.saturating_sub(st.total_sent));
            if avail == 0 {
                continue;
            }
            let start = (s.sent_through - s.ack_pos) as usize;
            let take = (avail as usize)
                .min(budget as usize)
                .min(s.write_pos.saturating_sub(s.sent_through) as usize);
            if take > 0 {
                let data: Vec<u8> = s.send_buf.iter().skip(start).take(take).copied().collect();
                let new_through = s.sent_through + take as u64;
                st.total_sent = st
                    .total_sent
                    .saturating_add(new_through.saturating_sub(s.sent_high));
                s.sent_high = new_through;
                s.sent_through = new_through;
                budget -= take as u64;
                let fin = s.fin_queued && !s.fin_sent && s.sent_through == s.write_pos;
                if fin {
                    s.fin_sent = true;
                }
                frames.push(Frame::Stream {
                    stream_id: id,
                    offset: Some(s.sent_through - take as u64),
                    data,
                    length: None,
                    fin,
                });
                *ack_eliciting = true;
            } else if s.fin_queued && !s.fin_sent && s.sent_through == s.write_pos {
                s.fin_sent = true;
                frames.push(Frame::Stream {
                    stream_id: id,
                    offset: Some(s.sent_through),
                    data: Vec::new(),
                    length: None,
                    fin: true,
                });
                *ack_eliciting = true;
            }
        }
    }

    fn pto_period(&self, st: &ConnState) -> Duration {
        let base = st.smoothed_rtt
            + (st.rttvar * 4).max(Duration::from_millis(1))
            + Duration::from_millis(MAX_ACK_DELAY_MS);
        base * (1u32 << st.pto_count.min(10))
    }

    fn send_probe(&self, st: &mut ConnState) {
        // Retransmit the oldest unacked ack-eliciting packet's frames.
        for space in [PnSpace::Application, PnSpace::Handshake, PnSpace::Initial] {
            let idx = space.index();
            if st.spaces[idx].write_key.is_none() {
                continue;
            }
            let probe = st.spaces[idx]
                .sent
                .iter()
                .find(|p| p.ack_eliciting && p.in_flight);
            if let Some(p) = probe {
                let frames = p.frames.clone();
                for f in frames {
                    self.on_lost_frame(st, space, f);
                }
                break;
            }
        }
        st.pto_count += 1;
        st.pto_due = Some(Instant::now() + self.pto_period(st));
        self.writer.notify_one();
    }

    fn process_fatal(&self, st: &mut ConnState, err: QuicError) {
        if st.closed.is_none() {
            st.closed = Some(err);
        }
        self.handshake.notify_waiters();
        wake_all(st);
        st.datagram_notify.notify_waiters();
        st.streams_notify.notify_waiters();
    }

    // -------------------------------------------------------------------
    // Public API used by streams / facade
    // -------------------------------------------------------------------

    pub(crate) fn open_bi(&self, st: &mut ConnState) -> Result<u64> {
        self.open_stream(st, false)
    }

    pub(crate) fn open_uni(&self, st: &mut ConnState) -> Result<u64> {
        self.open_stream(st, true)
    }

    fn open_stream(&self, st: &mut ConnState, uni: bool) -> Result<u64> {
        if let Some(e) = &st.closed {
            return Err(e.clone());
        }
        let id = if uni {
            let n = st.next_uni;
            if (n / 4) >= st.peer_uni_limit {
                return Err(QuicError::StreamLimit);
            }
            st.next_uni += 4;
            n
        } else {
            let n = st.next_bidi;
            if (n / 4) >= st.peer_bidi_limit {
                return Err(QuicError::StreamLimit);
            }
            st.next_bidi += 4;
            n
        };
        let peer_limit = if uni {
            st.peer_max_stream_data_uni
        } else {
            st.peer_max_stream_data_bidi
        };
        st.streams.insert(id, StreamState::new(peer_limit, 0));
        Ok(id)
    }

    pub(crate) fn accept_uni_ready(&self, st: &mut ConnState) -> Option<u64> {
        st.streams
            .iter()
            .filter(|(id, s)| *id & 3 == 3 && (!s.recv_prefix.is_empty() || s.fin_recv))
            .map(|(id, _)| *id)
            .next()
    }

    pub(crate) fn streams_notify_handle(&self) -> Arc<Notify> {
        self.lock().streams_notify.clone()
    }

    pub(crate) fn datagram_notify_handle(&self) -> Arc<Notify> {
        self.lock().datagram_notify.clone()
    }

    /// Whether the caller may open another bidi/uni stream (used for async
    /// open_* waiting).
    pub(crate) fn can_open(&self, st: &ConnState, uni: bool) -> bool {
        let n = if uni { st.next_uni } else { st.next_bidi };
        let limit = if uni {
            st.peer_uni_limit
        } else {
            st.peer_bidi_limit
        };
        (n / 4) < limit
    }

    pub(crate) fn send_data(
        &self,
        st: &mut ConnState,
        stream_id: u64,
        data: &[u8],
    ) -> Result<usize> {
        if let Some(e) = &st.closed {
            return Err(e.clone());
        }
        let s = st
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| QuicError::Protocol("unknown stream".into()))?;
        if s.reset_sent.is_some() || s.reset_recv.is_some() {
            return Err(QuicError::StreamReset { error_code: 0 });
        }
        let buffered = (s.write_pos - s.ack_pos) as usize;
        if buffered >= MAX_SEND_BUFFER {
            return Err(QuicError::StreamLimit);
        }
        let take = data.len().min(MAX_SEND_BUFFER - buffered);
        s.send_buf.extend(data[..take].iter().copied());
        s.write_pos += take as u64;
        Ok(take)
    }

    pub(crate) fn send_buffered(&self, st: &ConnState, stream_id: u64) -> usize {
        match st.streams.get(&stream_id) {
            Some(s) => (s.write_pos - s.ack_pos) as usize,
            None => 0,
        }
    }

    pub(crate) fn stream_send_notify(&self, st: &ConnState, stream_id: u64) -> Arc<Notify> {
        st.streams
            .get(&stream_id)
            .map(|s| s.send_notify.clone())
            .unwrap_or_else(|| Arc::new(Notify::new()))
    }

    pub(crate) fn fin_stream(&self, st: &mut ConnState, stream_id: u64) -> Result<()> {
        if let Some(e) = &st.closed {
            return Err(e.clone());
        }
        let s = st
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| QuicError::Protocol("unknown stream".into()))?;
        s.fin_queued = true;
        s.send_notify.notify_waiters();
        Ok(())
    }

    pub(crate) fn recv_into(
        &self,
        st: &mut ConnState,
        stream_id: u64,
        buf: &mut [u8],
    ) -> RecvOutcome {
        let Some(s) = st.streams.get_mut(&stream_id) else {
            return RecvOutcome::Eof;
        };
        if let Some(code) = s.reset_recv {
            return RecvOutcome::Reset(code);
        }
        if !s.recv_prefix.is_empty() {
            let n = buf.len().min(s.recv_prefix.len());
            for (dst, src) in buf[..n].iter_mut().zip(s.recv_prefix.drain(..n)) {
                *dst = src;
            }
            s.recv_contig += n as u64;
            bump_recv_credit(st, stream_id);
            return RecvOutcome::Data(n);
        }
        if s.fin_recv && s.recv_contig >= s.fin_recv_offset {
            return RecvOutcome::Eof;
        }
        RecvOutcome::WouldBlock
    }

    pub(crate) fn stream_recv_notify(&self, st: &ConnState, stream_id: u64) -> Arc<Notify> {
        st.streams
            .get(&stream_id)
            .map(|s| s.recv_notify.clone())
            .unwrap_or_else(|| Arc::new(Notify::new()))
    }

    pub(crate) fn send_datagram(&self, st: &mut ConnState, data: Vec<u8>) -> Result<()> {
        if let Some(e) = &st.closed {
            return Err(e.clone());
        }
        // The same bound the driver applies when building packets, so an
        // accepted datagram is never silently dropped at flush time.
        let max_datagram = st.peer_max_udp_payload().min(MAX_UDP_PAYLOAD);
        if data.len() as u64 > max_datagram.saturating_sub(DATAGRAM_OVERHEAD) {
            return Err(QuicError::DatagramTooLarge);
        }
        st.datagram_tx.push_back(data);
        Ok(())
    }

    pub(crate) fn pop_datagram(&self, st: &mut ConnState) -> Option<Vec<u8>> {
        st.datagram_rx.pop_front()
    }

    pub(crate) fn close(&self, st: &mut ConnState, err: Option<QuicError>) {
        if st.closed.is_none() {
            st.closed = Some(err.unwrap_or(QuicError::Closed));
        }
        self.handshake.notify_waiters();
        wake_all(st);
        st.datagram_notify.notify_waiters();
        st.streams_notify.notify_waiters();
        self.shutdown.store(true, Ordering::Release);
    }

    /// The current smoothed RTT estimate.
    pub(crate) fn smoothed_rtt(&self, st: &ConnState) -> Duration {
        st.smoothed_rtt
    }

    pub(crate) fn remote_address(&self) -> SocketAddr {
        self.peer
    }
}

impl ConnState {
    fn peer_max_udp_payload(&self) -> u64 {
        self.tls
            .peer_tp
            .as_ref()
            .map(|tp| {
                if tp.max_udp_payload_size >= 1200 {
                    tp.max_udp_payload_size
                } else {
                    1200
                }
            })
            .unwrap_or(1200)
    }
}

fn recv_window_for(st: &ConnState, stream_id: u64) -> u64 {
    if stream_id & 1 == 0 {
        st.my_max_stream_data_bidi_local
    } else if stream_id & 2 != 0 {
        st.my_max_stream_data_uni
    } else {
        st.my_max_stream_data_bidi_remote
    }
}

fn wake_all(st: &mut ConnState) {
    for s in st.streams.values() {
        s.send_notify.notify_waiters();
        s.recv_notify.notify_waiters();
    }
}

/// Sync the TLS-layer keys into the packet-number spaces as the handshake
/// progresses.
fn install_keys(st: &mut ConnState) {
    if let Some(k) = &st.tls.hs_write {
        if st.spaces[PnSpace::Handshake.index()].write_key.is_none() {
            st.spaces[PnSpace::Handshake.index()].write_key = Some(k.clone());
        }
    }
    if let Some(k) = &st.tls.hs_read {
        if st.spaces[PnSpace::Handshake.index()].key.is_none() {
            st.spaces[PnSpace::Handshake.index()].key = Some(k.clone());
        }
    }
    if st.tls.is_complete() {
        if let Some(k) = &st.tls.app_write {
            st.spaces[PnSpace::Application.index()].write_key = Some(k.clone());
        }
        if let Some(k) = &st.tls.app_read {
            st.spaces[PnSpace::Application.index()].key = Some(k.clone());
        }
    }
}

fn wake_senders(st: &mut ConnState) {
    for s in st.streams.values() {
        s.send_notify.notify_waiters();
    }
}

/// Promote out-of-order gaps that are now contiguous with the prefix.
fn promote_gaps(s: &mut StreamState) {
    loop {
        let pend = s.recv_contig + s.recv_prefix.len() as u64;
        match s.recv_gaps.first_entry() {
            Some(e) if *e.key() == pend => {
                let (_, seg) = e.remove_entry();
                s.recv_prefix.extend(seg);
            }
            _ => break,
        }
    }
}

/// Insert an out-of-order segment into the gap map, merging overlaps.
fn insert_gap(s: &mut StreamState, offset: u64, data: Vec<u8>) {
    let mut merged_offset = offset;
    let mut merged = data;
    loop {
        // Find any existing segment overlapping [merged_offset, merged_end).
        let merged_end = merged_offset + merged.len() as u64;
        let overlapping: Vec<(u64, Vec<u8>)> = s
            .recv_gaps
            .range(..=merged_end)
            .filter(|(&k, v)| k + v.len() as u64 >= merged_offset)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        if overlapping.is_empty() {
            break;
        }
        for (k, v) in overlapping {
            let v_end = k + v.len() as u64;
            let new_start = merged_offset.min(k);
            let new_end = merged_end.max(v_end);
            let mut buf = Vec::with_capacity((new_end - new_start) as usize);
            if new_start < merged_offset {
                buf.extend_from_slice(&v[..(merged_offset - k) as usize]);
            }
            buf.extend_from_slice(&merged);
            if v_end > merged_end {
                let from = (merged_end - k) as usize;
                buf.extend_from_slice(&v[from..]);
            }
            s.recv_gaps.remove(&k);
            merged = buf;
            merged_offset = new_start;
        }
    }
    s.recv_gaps.insert(merged_offset, merged);
}

/// Bump the peer's send credit for `stream_id` and the global data credit
/// when the advertised windows are more than half consumed.
fn bump_recv_credit(st: &mut ConnState, stream_id: u64) {
    let Some(s) = st.streams.get_mut(&stream_id) else {
        return;
    };
    let consumed = s.recv_contig + s.recv_prefix.len() as u64;
    let window = s.peer_send_limit;
    if window > 0 && consumed + window / 2 > window {
        let new_limit = window + window / 2;
        s.peer_send_limit = new_limit;
        st.pending_max_stream_data.push((stream_id, new_limit));
    }
    if st.total_recv + st.max_data_advertised / 2 > st.max_data_advertised {
        let new_max = st.max_data_advertised + st.max_data_advertised / 2;
        st.max_data_advertised = new_max;
        st.pending_max_data.push(new_max);
    }
}

/// Build an ACK frame from a space's ack queue.
fn build_ack(sp: &Space) -> Option<Frame> {
    if sp.ack_queue.is_empty() {
        return None;
    }
    let largest = *sp.ack_queue.iter().next_back()?;
    let ranges = build_ack_ranges(&sp.ack_queue);
    Some(Frame::Ack {
        largest_acked: largest,
        ack_delay: 0,
        ranges,
        ecn: None,
    })
}

/// Build the `(gap, range_len)` list per RFC 9000 §19.3.1. The first element
/// is `(0, first_range_len)`; subsequent elements are `(gap, range_len)`.
fn build_ack_ranges(acked: &BTreeSet<u64>) -> Vec<(u64, u64)> {
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    let mut iter = acked.iter().rev();
    let largest = match iter.next() {
        Some(&p) => p,
        None => return ranges,
    };
    // First range: consecutive acked packets ending at `largest`.
    let mut first_len = 0u64;
    let mut prev = largest;
    for &pn in iter.by_ref() {
        if pn + 1 == prev {
            first_len += 1;
            prev = pn;
        } else {
            break;
        }
    }
    ranges.push((0, first_len));
    if ranges.len() >= 4 {
        return ranges;
    }
    // Subsequent ranges.
    let mut gap_base = prev; // smallest acked in the first range
    loop {
        let next_acked = acked
            .range(..gap_base.saturating_sub(1))
            .next_back()
            .copied();
        let Some(p) = next_acked else { break };
        let gap = gap_base - p - 1;
        let mut len = 0u64;
        let mut q = p;
        for &pn in acked.range(..p).rev() {
            if pn + 1 == q {
                len += 1;
                q = pn;
            } else {
                break;
            }
        }
        ranges.push((gap, len));
        if ranges.len() >= 4 {
            break;
        }
        gap_base = q;
    }
    ranges
}

/// Compute the packet-number offset for a long-header packet.
fn long_pn_offset(data: &[u8]) -> Option<usize> {
    if data.len() < 7 {
        return None;
    }
    let mut pos = 5usize;
    let dcid_len = data[pos] as usize;
    pos += 1;
    if data.len() < pos + dcid_len + 1 {
        return None;
    }
    pos += dcid_len;
    let scid_len = data[pos] as usize;
    pos += 1;
    if data.len() < pos + scid_len {
        return None;
    }
    pos += scid_len;
    let ptype = (data[0] >> 4) & 0x03;
    if ptype == 0x00 {
        let (token_len, used) = courierust::courierust_quic::varint::decode(&data[pos..]).ok()?;
        pos += used;
        if data.len() < pos + token_len as usize {
            return None;
        }
        pos += token_len as usize;
    }
    let (_plen, used) = courierust::courierust_quic::varint::decode(&data[pos..]).ok()?;
    pos += used;
    Some(pos)
}

/// Build a packet header; returns `(header_with_pn, pn_offset, is_long)`.
fn build_packet_header(st: &ConnState, space: PnSpace) -> Result<(Vec<u8>, usize, bool)> {
    let pn = st.spaces[space.index()].next_pn;
    match space {
        PnSpace::Initial => {
            let header = packet::encode_long(
                LongType::Initial,
                &st.dcid,
                &st.scid,
                pn,
                PN_LEN,
                &st.retry_token,
                0,
            )
            .map_err(|e| QuicError::Protocol(e.to_string()))?;
            let pn_offset = header.len() - PN_LEN;
            Ok((header, pn_offset, true))
        }
        PnSpace::Handshake => {
            let header =
                packet::encode_long(LongType::Handshake, &st.dcid, &st.scid, pn, PN_LEN, &[], 0)
                    .map_err(|e| QuicError::Protocol(e.to_string()))?;
            let pn_offset = header.len() - PN_LEN;
            Ok((header, pn_offset, true))
        }
        PnSpace::Application => {
            let header = packet::encode_short(&st.dcid, pn, PN_LEN, false)
                .map_err(|e| QuicError::Protocol(e.to_string()))?;
            let pn_offset = header.len() - PN_LEN;
            Ok((header, pn_offset, false))
        }
    }
}

fn rand_vec(rng: &mut ChaChaRng, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    rng.fill(&mut out);
    out
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
