//! TCP connection management

use crate::netstack::solidtcp::error::Result;
use crate::netstack::solidtcp::nat::NatKey;
use crate::netstack::solidtcp::packet::{TcpInfo, DEFAULT_MSS_V4, DEFAULT_MSS_V6};
use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};

/// The largest receive window a TCP header can carry.
///
/// No window scaling is negotiated, so a value above this would be silently
/// truncated on the wire: the window we compute and the window the peer acts
/// on would disagree, and nothing would report the difference.
pub const MAX_RECV_WINDOW: u16 = 65535;

/// What the proxy writer owns on a connection's behalf.
///
/// Two things have to travel with the writer thread, and both are about the
/// same hazard: this stack acknowledges a segment when it arrives, not when the
/// proxy has taken it.
///
/// * the in-flight counter, released as the writer drains it, so the receive
///   window reflects what is still queued rather than what is acknowledged;
/// * the liveness flag, cleared on the way out of every path — including an
///   early `break` — because "the channel is closed" is only discoverable by
///   trying to send, and by then the bytes are already acknowledged.
///
/// The release is in `Drop` for that reason: a writer that stops early has to
/// hand its bytes back to the window, or the connection would sit at a window
/// of zero for the rest of its life.
pub struct ProxyWriter {
    inflight: Arc<AtomicUsize>,
    alive: Arc<AtomicBool>,
    held: usize,
}

impl ProxyWriter {
    fn new(inflight: Arc<AtomicUsize>, alive: Arc<AtomicBool>) -> Self {
        Self {
            inflight,
            alive,
            held: 0,
        }
    }

    /// Record bytes taken off the channel that are not on the wire yet.
    pub fn take(&mut self, bytes: usize) {
        self.held += bytes;
    }

    /// The bytes taken so far have been written; they no longer occupy the
    /// window.
    pub fn written(&mut self) {
        self.release_held();
    }

    /// Bytes currently taken but not written.
    pub fn held(&self) -> usize {
        self.held
    }

    fn release_held(&mut self) {
        if self.held > 0 {
            self.inflight.fetch_sub(self.held, Ordering::Relaxed);
            self.held = 0;
        }
    }
}

impl Drop for ProxyWriter {
    fn drop(&mut self) {
        self.release_held();
        self.alive.store(false, Ordering::Release);
    }
}

/// TCP state (RFC 793)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl std::fmt::Display for TcpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// TCP action to take after processing a segment
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpAction {
    None,
    SendAck,
    SendFin,
    SendFinAck,
    SendRst,
    SendData(Vec<u8>),
    Established,
    Close,
}

/// TCP configuration
#[derive(Debug, Clone)]
pub struct TcpConfig {
    pub recv_window: u16,
    pub mss: u16,
    pub idle_timeout: Duration,
    pub connect_timeout: Duration,
    pub time_wait: Duration,
    pub websocket_timeout: Duration,
    pub max_recv_buffer: usize,
    pub max_send_buffer: usize,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            recv_window: 65535,
            mss: 1360,
            idle_timeout: Duration::from_secs(300),
            connect_timeout: Duration::from_secs(30),
            time_wait: Duration::from_secs(10),
            websocket_timeout: Duration::from_secs(3600),
            max_recv_buffer: 1024 * 1024,
            max_send_buffer: 1024 * 1024,
        }
    }
}

/// TCP connection
pub struct TcpConnection {
    pub key: NatKey,
    state: TcpState,
    snd_nxt: u32,
    snd_una: u32,
    rcv_nxt: u32,
    mss: u16,
    config: TcpConfig,
    recv_buf: VecDeque<u8>,
    send_buf: VecDeque<u8>,
    last_active: Instant,
    bytes_tx: u64,
    bytes_rx: u64,
    pub domain: Option<String>,
    proxy_tx: Option<mpsc::Sender<Vec<u8>>>,
    fin_recv: bool,
    pending_data: VecDeque<u8>,
    ooo_segments: BTreeMap<u32, Vec<u8>>,
    max_ooo_size: usize,
    ooo_size: usize,
    is_websocket: bool,
    recv_window: u32,
    /// The window value last put on the wire.
    ///
    /// Kept only to detect the one transition a peer cannot discover by
    /// itself: a window that was advertised as zero and has since opened. A
    /// peer that stopped for a closed window sends nothing but probes, so
    /// without this the flow would resume only when its retransmission timer
    /// expired.
    last_advertised: u32,
    /// Bytes handed to the proxy writer but not yet written to the proxy.
    ///
    /// The relay between this stack and the proxy socket is a queue, and a
    /// queue nobody counts is not flow control. `recv_buf` is drained into the
    /// channel inside the same call that fills it, so it is empty whenever the
    /// window is recomputed — meaning the three buffers above could all read
    /// zero while the proxy was megabytes behind. Shared with the writer
    /// thread, which releases each chunk once it is on the wire.
    proxy_inflight: Arc<AtomicUsize>,
    /// Cleared by the proxy writer as it exits. A connection that is up but
    /// whose writer is gone can neither deliver nor keep what the peer sends,
    /// so it has to stop accepting rather than acknowledge and discard.
    proxy_alive: Arc<AtomicBool>,
    /// Set when a send to the writer's channel fails. Redundant with
    /// `proxy_alive` except for the instant between the channel being dropped
    /// and the writer's guard running, which is exactly the window in which a
    /// segment would otherwise be accepted and thrown away.
    proxy_dead: bool,
    dup_ack_count: u32,
}

impl TcpConnection {
    pub fn new_passive(
        key: NatKey,
        their_seq: u32,
        their_mss: Option<u16>,
        domain: Option<String>,
        config: TcpConfig,
    ) -> Self {
        let mut iss = [0u8; 4];
        getrandom::fill(&mut iss).expect("OS RNG unavailable");
        let iss = u32::from_le_bytes(iss);
        let fallback_mss = match key.dst.ip() {
            IpAddr::V4(_) => DEFAULT_MSS_V4,
            IpAddr::V6(_) => DEFAULT_MSS_V6,
        };
        let mss = their_mss.unwrap_or(fallback_mss).min(config.mss);
        let is_websocket = matches!(key.dst.port(), 80 | 443 | 8080 | 8443 | 9000);

        Self {
            key,
            state: TcpState::SynReceived,
            snd_nxt: iss.wrapping_add(1),
            snd_una: iss,
            rcv_nxt: their_seq.wrapping_add(1),
            mss,
            config,
            recv_buf: VecDeque::new(),
            send_buf: VecDeque::new(),
            last_active: Instant::now(),
            bytes_tx: 0,
            bytes_rx: 0,
            domain,
            proxy_tx: None,
            fin_recv: false,
            pending_data: VecDeque::new(),
            ooo_segments: BTreeMap::new(),
            max_ooo_size: 512 * 1024,
            ooo_size: 0,
            is_websocket,
            recv_window: MAX_RECV_WINDOW as u32,
            last_advertised: MAX_RECV_WINDOW as u32,
            proxy_inflight: Arc::new(AtomicUsize::new(0)),
            proxy_alive: Arc::new(AtomicBool::new(false)),
            proxy_dead: false,
            dup_ack_count: 0,
        }
    }

    pub fn set_websocket(&mut self, is_ws: bool) {
        self.is_websocket = is_ws;
        if is_ws {
            self.max_ooo_size = 1024 * 1024;
            info!("Connection marked as WebSocket: {:?}", self.key);
        }
    }

    pub fn is_websocket(&self) -> bool {
        self.is_websocket
    }
    pub fn recv_window(&self) -> u32 {
        self.recv_window
    }

    /// Everything accepted from the peer that the proxy has not written yet.
    ///
    /// This is the queue the receive window exists to bound: bytes that have
    /// been acknowledged but not consumed. The reassembly buffers count, and
    /// so does what the proxy writer has taken but not written — leaving that
    /// out is what let a slow proxy grow the queue without limit.
    pub fn queued_bytes(&self) -> usize {
        self.recv_buf
            .len()
            .saturating_add(self.pending_data.len())
            .saturating_add(self.ooo_size)
            .saturating_add(self.proxy_inflight.load(Ordering::Relaxed))
    }

    /// Whether the flow can still carry anything.
    ///
    /// A connection with no proxy yet is *not* gone: its bytes are buffered
    /// until the SOCKS5 handshake finishes. A connection whose writer has
    /// exited is, and so is one whose channel rejected a send.
    fn proxy_is_gone(&self) -> bool {
        self.proxy_dead || (self.proxy_tx.is_some() && !self.proxy_alive.load(Ordering::Acquire))
    }

    /// Whether one more segment of `len` bytes fits in the queued-data budget.
    fn has_room_for(&self, len: usize) -> bool {
        !self.proxy_is_gone()
            && self.queued_bytes().saturating_add(len) <= self.config.max_recv_buffer
    }

    /// The segment size to round windows to, never zero.
    fn segment_size(&self) -> usize {
        (self.mss as usize).max(1)
    }

    fn update_recv_window(&mut self) {
        let available = self
            .config
            .max_recv_buffer
            .saturating_sub(self.queued_bytes());
        let segment = self.segment_size();
        let window = (available / segment * segment).min(MAX_RECV_WINDOW as usize);
        self.recv_window = window as u32;
        self.last_advertised = self.recv_window;
    }

    /// Recompute the window and report whether the peer has to be told.
    ///
    /// True only for the transition from "closed" to "open": a peer that ran
    /// out of window has no other way to learn that it may resume, since the
    /// segment that would carry our ACK is the one it is waiting to send.
    fn window_update_due(&mut self) -> bool {
        let was_closed = self.last_advertised == 0;
        self.update_recv_window();
        was_closed && self.recv_window >= self.segment_size() as u32
    }

    pub fn state(&self) -> TcpState {
        self.state
    }
    pub fn is_established(&self) -> bool {
        self.state == TcpState::Established
    }
    pub fn is_closed(&self) -> bool {
        matches!(self.state, TcpState::Closed | TcpState::TimeWait)
    }

    /// Attach the proxy writer's channel, flushing anything buffered while it
    /// was being set up.
    ///
    /// Returns the handle the writer owns: it releases the in-flight counter as
    /// it drains, and clears the liveness flag when it exits, so the receive
    /// window reflects what is still queued rather than what is acknowledged.
    pub fn set_proxy_tx(&mut self, tx: mpsc::Sender<Vec<u8>>) -> ProxyWriter {
        self.proxy_tx = Some(tx.clone());
        if !self.pending_data.is_empty() {
            let data: Vec<u8> = self.pending_data.drain(..).collect();
            let len = data.len();
            info!("Flushing {} bytes of pending data to proxy", len);
            self.proxy_inflight.fetch_add(len, Ordering::Relaxed);
            if tx.send(data).is_err() {
                self.proxy_inflight.fetch_sub(len, Ordering::Relaxed);
                self.proxy_dead = true;
                warn!("Proxy channel closed while flushing {} bytes", len);
            }
        }
        self.proxy_alive.store(true, Ordering::Release);
        ProxyWriter::new(
            Arc::clone(&self.proxy_inflight),
            Arc::clone(&self.proxy_alive),
        )
    }

    pub fn snd_nxt(&self) -> u32 {
        self.snd_nxt
    }
    pub fn rcv_nxt(&self) -> u32 {
        self.rcv_nxt
    }
    pub fn mss(&self) -> u16 {
        self.mss
    }

    pub fn advance_snd_nxt(&mut self, len: u32) {
        self.snd_nxt = self.snd_nxt.wrapping_add(len);
        self.bytes_tx += len as u64;
    }

    pub fn process(&mut self, seg: &TcpInfo, payload: &[u8]) -> Result<TcpAction> {
        self.last_active = Instant::now();
        if seg.flags.rst {
            info!("TCP RST: {:?}", self.key);
            self.state = TcpState::Closed;
            return Ok(TcpAction::Close);
        }
        match self.state {
            TcpState::SynReceived => self.on_syn_recv(seg),
            TcpState::Established => self.on_established(seg, payload),
            TcpState::FinWait1 => self.on_fin_wait1(seg),
            TcpState::FinWait2 => self.on_fin_wait2(seg),
            TcpState::CloseWait => self.on_close_wait(seg),
            TcpState::Closing => self.on_closing(seg),
            TcpState::LastAck => self.on_last_ack(seg),
            TcpState::TimeWait => self.on_time_wait(seg),
            _ => Ok(TcpAction::None),
        }
    }

    fn on_syn_recv(&mut self, seg: &TcpInfo) -> Result<TcpAction> {
        if seg.flags.ack && self.valid_ack(seg.ack) {
            self.snd_una = seg.ack;
            self.state = TcpState::Established;
            info!("TCP ESTABLISHED: {:?}", self.key);
            return Ok(TcpAction::Established);
        }
        Ok(TcpAction::None)
    }

    fn on_established(&mut self, seg: &TcpInfo, payload: &[u8]) -> Result<TcpAction> {
        if seg.flags.ack {
            self.process_ack(seg.ack);
        }
        let mut action = TcpAction::None;
        if !payload.is_empty() {
            action = self.process_data(seg.seq, payload)?;
        }
        if seg.flags.fin {
            self.fin_recv = true;
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.state = TcpState::CloseWait;
            debug!("TCP FIN recv -> CLOSE_WAIT: {:?}", self.key);
            return Ok(TcpAction::SendFinAck);
        }
        if action == TcpAction::None && self.window_update_due() {
            action = TcpAction::SendAck;
        }
        Ok(action)
    }

    fn on_fin_wait1(&mut self, seg: &TcpInfo) -> Result<TcpAction> {
        if seg.flags.ack && self.valid_ack(seg.ack) {
            self.snd_una = seg.ack;
            if seg.flags.fin {
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                self.state = TcpState::TimeWait;
                return Ok(TcpAction::SendAck);
            }
            self.state = TcpState::FinWait2;
        }
        if seg.flags.fin {
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.state = TcpState::Closing;
            return Ok(TcpAction::SendAck);
        }
        Ok(TcpAction::None)
    }

    fn on_fin_wait2(&mut self, seg: &TcpInfo) -> Result<TcpAction> {
        if seg.flags.fin {
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.state = TcpState::TimeWait;
            return Ok(TcpAction::SendAck);
        }
        Ok(TcpAction::None)
    }

    fn on_close_wait(&mut self, seg: &TcpInfo) -> Result<TcpAction> {
        if seg.flags.ack {
            self.process_ack(seg.ack);
        }
        Ok(TcpAction::None)
    }

    fn on_closing(&mut self, seg: &TcpInfo) -> Result<TcpAction> {
        if seg.flags.ack && self.valid_ack(seg.ack) {
            self.state = TcpState::TimeWait;
        }
        Ok(TcpAction::None)
    }

    fn on_last_ack(&mut self, seg: &TcpInfo) -> Result<TcpAction> {
        if seg.flags.ack && self.valid_ack(seg.ack) {
            self.state = TcpState::Closed;
            return Ok(TcpAction::Close);
        }
        Ok(TcpAction::None)
    }

    fn on_time_wait(&mut self, seg: &TcpInfo) -> Result<TcpAction> {
        if seg.flags.fin {
            return Ok(TcpAction::SendAck);
        }
        Ok(TcpAction::None)
    }

    fn valid_ack(&self, ack: u32) -> bool {
        let (una, nxt) = (self.snd_una, self.snd_nxt);
        if una <= nxt {
            ack > una && ack <= nxt
        } else {
            ack > una || ack <= nxt
        }
    }

    fn process_ack(&mut self, ack: u32) {
        if self.valid_ack(ack) {
            self.snd_una = ack;
        }
    }

    fn process_data(&mut self, seq: u32, data: &[u8]) -> Result<TcpAction> {
        if data.is_empty() {
            return Ok(TcpAction::None);
        }
        if self.proxy_is_gone() {
            self.state = TcpState::Closed;
            return Ok(TcpAction::SendRst);
        }

        self.update_recv_window();
        let seq_end = seq.wrapping_add(data.len() as u32);

        if self.seq_before_or_eq(seq_end, self.rcv_nxt) {
            trace!(
                "Complete retransmission detected: seq={}, seq_end={}, rcv_nxt={}",
                seq,
                seq_end,
                self.rcv_nxt
            );
            return Ok(TcpAction::SendAck);
        }

        if seq == self.rcv_nxt {
            if !self.has_room_for(data.len()) {
                trace!(
                    "Refusing {} bytes: queued {} of {} (backpressure)",
                    data.len(),
                    self.queued_bytes(),
                    self.config.max_recv_buffer
                );
                return Ok(TcpAction::SendAck);
            }
            self.dup_ack_count = 0;
            self.recv_buf.extend(data);
            self.rcv_nxt = self.rcv_nxt.wrapping_add(data.len() as u32);
            self.bytes_rx += data.len() as u64;
            self.try_deliver_ooo_segments();
            let d: Vec<u8> = self.recv_buf.drain(..).collect();
            if !d.is_empty() {
                self.deliver_to_proxy(d);
            }
            self.update_recv_window();
            return Ok(TcpAction::SendAck);
        }

        if self.seq_before(seq, self.rcv_nxt) && self.seq_after(seq_end, self.rcv_nxt) {
            let skip = self.rcv_nxt.wrapping_sub(seq) as usize;
            if skip < data.len() {
                let new_data = &data[skip..];
                trace!(
                    "Partial retransmission: seq={}, skip={}, new_len={}",
                    seq,
                    skip,
                    new_data.len()
                );
                if !self.has_room_for(new_data.len()) {
                    return Ok(TcpAction::SendAck);
                }
                self.recv_buf.extend(new_data);
                self.rcv_nxt = self.rcv_nxt.wrapping_add(new_data.len() as u32);
                self.bytes_rx += new_data.len() as u64;
                self.try_deliver_ooo_segments();
                let d: Vec<u8> = self.recv_buf.drain(..).collect();
                if !d.is_empty() {
                    self.deliver_to_proxy(d);
                }
                self.update_recv_window();
            }
            return Ok(TcpAction::SendAck);
        }

        if self.seq_after(seq, self.rcv_nxt) {
            self.dup_ack_count += 1;
            if self.ooo_size + data.len() <= self.max_ooo_size {
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    self.ooo_segments.entry(seq)
                {
                    debug!(
                        "Buffering out-of-order segment: seq={}, len={}, expected={}, gap={}",
                        seq,
                        data.len(),
                        self.rcv_nxt,
                        seq.wrapping_sub(self.rcv_nxt)
                    );
                    entry.insert(data.to_vec());
                    self.ooo_size += data.len();
                }
            } else {
                warn!(
                    "OOO buffer full ({} bytes), dropping segment: seq={}, len={}",
                    self.ooo_size,
                    seq,
                    data.len()
                );
            }
        }

        Ok(TcpAction::SendAck)
    }

    fn try_deliver_ooo_segments(&mut self) {
        loop {
            let next_seq = self.rcv_nxt;
            if let Some(data) = self.ooo_segments.remove(&next_seq) {
                debug!(
                    "Delivering OOO segment: seq={}, len={}",
                    next_seq,
                    data.len()
                );
                self.ooo_size -= data.len();
                self.recv_buf.extend(&data);
                self.rcv_nxt = self.rcv_nxt.wrapping_add(data.len() as u32);
                self.bytes_rx += data.len() as u64;
            } else {
                let mut found = None;
                for (&seg_seq, seg_data) in self.ooo_segments.iter() {
                    let seg_end = seg_seq.wrapping_add(seg_data.len() as u32);
                    if self.seq_before_or_eq(seg_seq, self.rcv_nxt)
                        && self.seq_after(seg_end, self.rcv_nxt)
                    {
                        let skip = self.rcv_nxt.wrapping_sub(seg_seq) as usize;
                        if skip < seg_data.len() {
                            found = Some((seg_seq, skip));
                            break;
                        }
                    }
                }

                if let Some((seg_seq, skip)) = found {
                    if let Some(data) = self.ooo_segments.remove(&seg_seq) {
                        let new_data = &data[skip..];
                        debug!(
                            "Delivering partial OOO segment: seq={}, skip={}, len={}",
                            seg_seq,
                            skip,
                            new_data.len()
                        );
                        self.ooo_size -= data.len();
                        self.recv_buf.extend(new_data);
                        self.rcv_nxt = self.rcv_nxt.wrapping_add(new_data.len() as u32);
                        self.bytes_rx += new_data.len() as u64;
                        continue;
                    }
                }
                break;
            }
        }
    }

    /// Hand data to the proxy writer.
    ///
    /// Infallible by construction: [`has_room_for`](Self::has_room_for) gates
    /// admission, so there is always room, and the bytes stay on the books as
    /// in-flight until the writer reports them written.
    fn deliver_to_proxy(&mut self, data: Vec<u8>) {
        if data.is_empty() {
            return;
        }

        let Some(tx) = self.proxy_tx.clone() else {
            debug!("Buffering {} bytes (proxy not ready)", data.len());
            self.pending_data.extend(data);
            return;
        };

        let data_len = data.len();
        self.proxy_inflight.fetch_add(data_len, Ordering::Relaxed);
        match tx.send(data) {
            Ok(()) => trace!("Sending {} bytes to proxy", data_len),
            Err(_) => {
                self.proxy_inflight.fetch_sub(data_len, Ordering::Relaxed);
                self.proxy_dead = true;
                warn!(
                    "Proxy channel closed, {} bytes cannot be delivered; \
                     resetting {:?}",
                    data_len, self.key
                );
            }
        }
    }

    fn seq_before(&self, seq1: u32, seq2: u32) -> bool {
        (seq1.wrapping_sub(seq2) as i32) < 0
    }

    fn seq_after(&self, seq1: u32, seq2: u32) -> bool {
        (seq1.wrapping_sub(seq2) as i32) > 0
    }

    fn seq_before_or_eq(&self, seq1: u32, seq2: u32) -> bool {
        seq1 == seq2 || self.seq_before(seq1, seq2)
    }

    pub fn send(&mut self, data: &[u8]) {
        self.send_buf.extend(data);
    }

    pub fn get_send_data(&mut self) -> Option<Vec<u8>> {
        if self.send_buf.is_empty() {
            return None;
        }
        let len = self.send_buf.len().min(self.mss as usize);
        let data: Vec<u8> = self.send_buf.drain(..len).collect();
        self.snd_nxt = self.snd_nxt.wrapping_add(data.len() as u32);
        self.bytes_tx += data.len() as u64;
        Some(data)
    }

    pub fn close(&mut self) -> TcpAction {
        match self.state {
            TcpState::Established => {
                self.state = TcpState::FinWait1;
                TcpAction::SendFin
            }
            TcpState::CloseWait => {
                self.state = TcpState::LastAck;
                TcpAction::SendFin
            }
            _ => TcpAction::None,
        }
    }

    pub fn is_timed_out(&self) -> bool {
        let timeout = match self.state {
            TcpState::Established => {
                if self.is_websocket {
                    self.config.websocket_timeout
                } else {
                    self.config.idle_timeout
                }
            }
            TcpState::TimeWait => self.config.time_wait,
            _ => self.config.connect_timeout,
        };
        self.last_active.elapsed() > timeout
    }

    pub fn stats(&self) -> (u64, u64) {
        (self.bytes_tx, self.bytes_rx)
    }
}

/// TCP connection manager
pub struct TcpManager {
    connections: DashMap<NatKey, Arc<RwLock<TcpConnection>>>,
    /// Applied to every connection the manager opens.
    config: TcpConfig,
}

impl TcpManager {
    pub fn new() -> Self {
        Self::with_config(TcpConfig::default())
    }

    pub fn with_config(config: TcpConfig) -> Self {
        Self {
            connections: DashMap::new(),
            config,
        }
    }

    pub fn handle_syn(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        tcp_info: &TcpInfo,
        domain: Option<String>,
    ) -> Result<Arc<RwLock<TcpConnection>>> {
        let key = NatKey::new(src, dst);

        if let Some(conn) = self.connections.get(&key) {
            return Ok(conn.clone());
        }

        let conn = TcpConnection::new_passive(
            key,
            tcp_info.seq,
            tcp_info.mss,
            domain,
            self.config.clone(),
        );
        let conn = Arc::new(RwLock::new(conn));
        self.connections.insert(key, conn.clone());

        trace!("TCP connection created: {} -> {}", src, dst);
        Ok(conn)
    }

    pub fn get_connection(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Option<Arc<RwLock<TcpConnection>>> {
        let key = NatKey::new(src, dst);
        self.connections.get(&key).map(|c| c.clone())
    }

    pub fn remove_connection(&self, src: SocketAddr, dst: SocketAddr) {
        let key = NatKey::new(src, dst);
        self.connections.remove(&key);
        trace!("TCP connection removed: {} -> {}", src, dst);
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    pub fn cleanup(&self) {
        let to_remove: Vec<_> = self
            .connections
            .iter()
            .filter(|entry| {
                let conn = entry.read();
                conn.is_closed() || conn.is_timed_out()
            })
            .map(|entry| *entry.key())
            .collect();

        for key in to_remove {
            self.connections.remove(&key);
            trace!("TCP connection cleaned up: {:?}", key);
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = Arc<RwLock<TcpConnection>>> + '_ {
        self.connections.iter().map(|e| e.clone())
    }
}

impl Default for TcpManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    const SEGMENT: usize = 1024;
    const BUDGET: usize = 4096;
    const THEIR_ISN: u32 = 1000;

    fn addr(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])), port)
    }

    fn key() -> NatKey {
        NatKey::new(addr([10, 0, 0, 2], 40100), addr([1, 1, 1, 1], 443))
    }

    fn config(budget: usize) -> TcpConfig {
        TcpConfig {
            max_recv_buffer: budget,
            ..TcpConfig::default()
        }
    }

    /// A connection whose proxy writer never runs: the channel exists but
    /// nothing drains it, so every accepted byte stays queued.
    fn stalled_proxy(budget: usize) -> (TcpConnection, mpsc::Receiver<Vec<u8>>, ProxyWriter) {
        let mut conn = TcpConnection::new_passive(
            key(),
            THEIR_ISN,
            Some(SEGMENT as u16),
            None,
            config(budget),
        );
        let (tx, rx) = mpsc::channel();
        let writer = conn.set_proxy_tx(tx);
        (conn, rx, writer)
    }

    /// Stand in for the writer thread draining the channel and writing it out.
    fn drain_to_proxy(rx: &mpsc::Receiver<Vec<u8>>, writer: &mut ProxyWriter) -> usize {
        let mut drained = 0;
        while let Ok(chunk) = rx.try_recv() {
            writer.take(chunk.len());
            drained += chunk.len();
        }
        writer.written();
        drained
    }

    /// Feed segments until the connection refuses one, returning how many it
    /// accepted. `process_data` is driven directly: the window and the queue
    /// live there, and the state machine above it only decides when to call it.
    fn fill_until_refused(conn: &mut TcpConnection) -> usize {
        let mut seq = conn.rcv_nxt();
        let mut accepted = 0;
        for _ in 0..64 {
            conn.process_data(seq, &vec![0u8; SEGMENT]).unwrap();
            let now = conn.rcv_nxt();
            if now == seq {
                break;
            }
            accepted += 1;
            seq = now;
        }
        accepted
    }

    #[test]
    fn the_window_shrinks_by_what_the_proxy_has_not_written() {
        let (mut conn, _rx, mut writer) = stalled_proxy(BUDGET);
        conn.update_recv_window();
        assert_eq!(
            conn.recv_window() as usize,
            BUDGET,
            "empty queue: budget is free"
        );

        let mut seq = conn.rcv_nxt();
        for _ in 0..2 {
            assert_eq!(
                conn.process_data(seq, &vec![0u8; SEGMENT]).unwrap(),
                TcpAction::SendAck
            );
            seq = conn.rcv_nxt();
        }

        assert!(conn.recv_buf.is_empty());
        assert_eq!(conn.queued_bytes(), 2 * SEGMENT);
        assert_eq!(conn.recv_window() as usize, BUDGET - 2 * SEGMENT);

        writer.take(2 * SEGMENT);
        writer.written();
        conn.update_recv_window();
        assert_eq!(conn.recv_window() as usize, BUDGET);
    }

    #[test]
    fn a_full_queue_is_refused_rather_than_dropped() {
        let (mut conn, _rx, _counter) = stalled_proxy(BUDGET);

        let accepted = fill_until_refused(&mut conn);
        assert_eq!(accepted, BUDGET / SEGMENT);
        assert_eq!(conn.queued_bytes(), BUDGET);
        assert_eq!(conn.rcv_nxt().wrapping_sub(THEIR_ISN + 1) as usize, BUDGET);
        assert_eq!(conn.recv_window(), 0, "a full queue must close the window");
    }

    #[test]
    fn draining_the_proxy_reopens_the_window_and_asks_for_an_update() {
        let (mut conn, rx, mut writer) = stalled_proxy(BUDGET);
        fill_until_refused(&mut conn);
        assert_eq!(conn.recv_window(), 0);
        assert_eq!(conn.last_advertised, 0);

        assert_eq!(drain_to_proxy(&rx, &mut writer), BUDGET);
        assert!(conn.window_update_due());
        assert_eq!(conn.recv_window() as usize, BUDGET);
        // ...and once only: the value is on the record now.
        assert!(!conn.window_update_due());
    }

    #[test]
    fn data_buffered_before_the_proxy_is_kept_up_to_the_budget() {
        let mut conn = TcpConnection::new_passive(
            key(),
            THEIR_ISN,
            Some(SEGMENT as u16),
            None,
            config(BUDGET),
        );

        let accepted = fill_until_refused(&mut conn);
        assert_eq!(accepted, BUDGET / SEGMENT);
        assert_eq!(conn.pending_data.len(), BUDGET);
        assert_eq!(conn.queued_bytes(), BUDGET);

        let (tx, rx) = mpsc::channel();
        let mut writer = conn.set_proxy_tx(tx);
        assert!(conn.pending_data.is_empty());
        assert_eq!(conn.queued_bytes(), BUDGET);
        assert_eq!(
            writer.held(),
            0,
            "nothing taken yet: the window still holds it"
        );
        assert_eq!(rx.try_recv().unwrap().len(), BUDGET);
        conn.update_recv_window();
        assert_eq!(conn.recv_window(), 0);

        writer.take(BUDGET);
        writer.written();
        conn.update_recv_window();
        assert_eq!(conn.recv_window() as usize, BUDGET);
    }

    #[test]
    fn a_stopped_writer_resets_the_flow_instead_of_acknowledging_into_a_hole() {
        let (mut conn, _rx, writer) = stalled_proxy(BUDGET);
        drop(writer);

        let before = conn.rcv_nxt();
        assert_eq!(
            conn.process_data(before, &vec![0u8; SEGMENT]).unwrap(),
            TcpAction::SendRst
        );
        assert_eq!(conn.rcv_nxt(), before, "nothing was acknowledged");
        assert!(!conn.has_room_for(1));
    }

    #[test]
    fn a_channel_that_rejects_a_send_resets_the_next_segment() {
        let (mut conn, rx, _writer) = stalled_proxy(BUDGET);
        drop(rx);

        assert_eq!(
            conn.process_data(conn.rcv_nxt(), &vec![0u8; SEGMENT])
                .unwrap(),
            TcpAction::SendAck
        );
        assert!(conn.proxy_dead);
        assert_eq!(
            conn.process_data(conn.rcv_nxt(), &vec![0u8; SEGMENT])
                .unwrap(),
            TcpAction::SendRst
        );
    }
}
