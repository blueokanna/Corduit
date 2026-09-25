//! ShadowTLS v3 outbound.
//!
//! ShadowTLS does not encrypt anything. It makes a proxy connection *look* like
//! a TLS session to a real site, and it does that by having the client complete
//! a genuine TLS 1.3 handshake — through the ShadowTLS server, which relays it
//! to a real handshake destination — and then reusing the same socket for its
//! own framing once the camouflage is established. The password never appears on
//! the wire; it authenticates the client by signing a field of a ClientHello
//! that a passive observer sees as ordinary.
//!
//! Three phases, in order:
//!
//! 1. **The `ClientHello`'s session id is signed.** The handshake carries a
//!    32-byte `legacy_session_id`. Twenty-eight random bytes go in front, and
//!    the last four are `HMAC-SHA1(password, hello[..39] || session_id ||
//!    hello[71..])[:4]`, where `hello` is the ClientHello *handshake message*
//!    (no record header) and `session_id` still has its last four bytes zero.
//!    Those offsets are not arbitrary: 39 is where the session id starts
//!    (handshake header + version + random + length byte) and 71 is where it
//!    ends. The server recomputes the same MAC over the bytes it received,
//!    which is how it knows this is not a visitor.
//! 2. **The handshake runs for real.** The server proxies the whole TLS
//!    handshake to its configured destination (`www.bing.com:443` and friends),
//!    so a prober that connects without the password gets a certificate for
//!    that site. The client extracts the `ServerHello`'s 32-byte random from
//!    this flight; everything the server sends back during the handshake is
//!    already ShadowTLS-framed, and is unwrapped on the way in.
//! 3. **The socket switches to ShadowTLS frames.** Both directions are
//!    `17 03 03 || u16 (payload + 4) || tag || payload`, where `tag` is a
//!    rolling `HMAC-SHA1`. The MAC's key is the password; its input is
//!    `server_random || "C"` for the client's direction and `server_random ||
//!    "S"` for the server's, and each frame folds its own four-byte tag back
//!    into the MAC — so frame *n* is authenticated by every tag before it, and
//!    a spliced or reordered frame fails even when its payload is intact.
//!
//! During the handshake phase the server's frames carry a real TLS record that
//! is XORed with `SHA-256(password || server_random)`; the XOR stops at the
//! handshake, because there is no TLS record underneath after it.
//!
//! # Reference
//!
//! `ihciah/shadow-tls`, `src/client.rs` and `src/util.rs`: `generate_session_id`,
//! `StreamWrapper`, `verified_relay`, `copy_add_appdata`, `verify_appdata`; and
//! `src/server.rs`: `verified_extract_sni`, `copy_by_frame_with_modification` for
//! what a frame's payload actually holds.
//!
//! # Deliberate refusals, each with its reason
//!
//! * **v1 and v2.** They sign the handshake with a different construction (a
//!   hash of the whole stream, not a session-id MAC) and v2's framing differs.
//!   `version: 2` is refused by name instead of being spoken with v3's rules.
//! * **The decoy alert.** The reference sends a 31-byte fake alert record when a
//!   teardown happens after a handshake that was not TLS 1.3, so a prober sees a
//!   browser giving up. Our TLS client is 1.3-only, so a successful handshake
//!   always announced 1.3 and that branch is unreachable; it is not written
//!   rather than written and never run.
//! * **A plain-HTTP latency probe.** ShadowTLS's peer is a plain-TLS
//!   pass-through for the handshake and the *inner* proxy's protocol afterwards,
//!   so a raw `GET /` has nothing to answer it. The probe reports that instead
//!   of timing out.
//!
//! # One deviation from the reference, stated
//!
//! While the handshake runs, the server's frame payload is the peer's whole TLS
//! record, and this build hands that record to the TLS client as it is. The
//! reference instead keeps the frame's own five-byte header in front of it and
//! only corrects the length, which leaves a record whose content is another
//! record — readable only by its forked rustls, which unwraps that nesting. The
//! bytes on the wire are identical either way; only the two lines that present
//! them differ, and a conformant TLS stack needs the record, not the nesting.

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use courierust::courierust_tls::crypto::rng::fill_random;
use tracing::debug;

use crate::common::socket::connect_host;
use crate::common::stream::{is_benign_shutdown_error, BoxStream, SyncStream};
use crate::crypto::hash::{Sha1, Sha256};
use crate::crypto::mac::Hmac;
use crate::engine::config::OutboundConfig;
use crate::engine::connection_tracker::TrackedConnection;
use crate::engine::error::{Error, Result};
use crate::engine::outbound::{OutboundProxy, TargetAddr};
use crate::protocol::tls13::{
    connect, fingerprint::Fingerprint, ClientHelloDraft, ClientHelloHook, Tls13ClientConfig,
};

/// TCP connect budget.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Record header: type, major, minor, two length bytes.
const RECORD_HEADER: usize = 5;
/// Length of the truncated MAC every frame carries.
const MAC_LEN: usize = 4;
/// `type || version || length || tag`, i.e. the header a frame's payload starts
/// after.
const FRAME_HEADER: usize = RECORD_HEADER + MAC_LEN;
/// Offset of the session id inside a `ClientHello` handshake message.
const SESSION_ID_OFFSET: usize = 39;
/// Length of the session id a TLS 1.3 `ClientHello` carries.
const SESSION_ID_LEN: usize = 32;
/// Offset of `ServerHello.random` inside its record.
const SERVER_RANDOM_OFFSET: usize = RECORD_HEADER + 1 + 3 + 2;
/// Cap on a record a peer may send, so a length field cannot allocate.
const MAX_RECORD: usize = 64 * 1024;
/// Largest payload one frame carries. The two length bytes cap a frame at
/// 65535 bytes, and a write is framed rather than buffered.
const MAX_FRAME_PAYLOAD: usize = 16 * 1024;

const RECORD_ALERT: u8 = 0x15;
const RECORD_HANDSHAKE: u8 = 0x16;
const RECORD_APP_DATA: u8 = 0x17;
const HANDSHAKE_SERVER_HELLO: u8 = 0x02;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const TLS_1_3: u16 = 0x0304;

// ---------------------------------------------------------------------------
// Rolling MAC
// ---------------------------------------------------------------------------

/// The rolling `HMAC-SHA1` each direction is authenticated with.
///
/// The reference implements this by cloning the MAC state for every tag, and so
/// does this: `tag` never mutates, and `commit` is the only thing that moves the
/// state forward, which keeps the two callers (build a tag outbound, verify a
/// tag inbound) from being able to disagree about what has been folded in.
struct RollingHmac(Hmac<Sha1>);

impl RollingHmac {
    /// A MAC keyed with `password`, fed `prefix` before any frame.
    fn new(password: &[u8], prefix: &[u8]) -> Self {
        let mut mac = Hmac::<Sha1>::new(password);
        mac.update(prefix);
        Self(mac)
    }

    /// The tag `payload` would carry, without moving the state.
    fn tag(&self, payload: &[u8]) -> [u8; MAC_LEN] {
        let mut probe = self.0.clone();
        probe.update(payload);
        let mut digest = [0u8; 64];
        probe.finalize_into(&mut digest);
        let mut tag = [0u8; MAC_LEN];
        tag.copy_from_slice(&digest[..MAC_LEN]);
        tag
    }

    /// Fold a frame's own tag back in, which is what chains the frames.
    fn commit(&mut self, payload: &[u8], tag: &[u8; MAC_LEN]) {
        self.0.update(payload);
        self.0.update(tag);
    }

    /// Feed a payload without folding a tag in: what the *handshake* phase does,
    /// where the server's records are chained on payloads alone.
    fn observe(&mut self, payload: &[u8]) {
        self.0.update(payload);
    }
}

/// Everything derived from the handshake, once the `ServerHello` has been seen.
///
/// The random itself is not kept: every key below is derived from it, and a
/// wrong random fails the first MAC long before anything could compare them.
struct HandshakeState {
    /// The client → server MAC of the frame phase.
    to_server: RollingHmac,
    /// The server → client MAC of the frame phase.
    from_server: RollingHmac,
    /// The handshake phase's own MAC, kept so records the handshake destination
    /// sends after the handshake finished are recognised and dropped instead of
    /// being mistaken for corrupt frames. Dropped the first time a record does
    /// not match it, which is how it stops being consulted.
    stragglers: Option<RollingHmac>,
    /// The handshake phase's XOR keystream: `SHA-256(password || server_random)`.
    keystream: [u8; 32],
}

impl HandshakeState {
    /// Derive every key this connection needs from the password and the
    /// server's random.
    fn derive(password: &[u8], server_random: [u8; 32]) -> Self {
        let mut with_c = Vec::with_capacity(server_random.len() + 1);
        with_c.extend_from_slice(&server_random);
        with_c.push(b'C');
        let mut with_s = with_c.clone();
        *with_s.last_mut().expect("pushed") = b'S';

        let mut keystream_input = password.to_vec();
        keystream_input.extend_from_slice(&server_random);

        Self {
            to_server: RollingHmac::new(password, &with_c),
            from_server: RollingHmac::new(password, &with_s),
            stragglers: Some(RollingHmac::new(password, &server_random)),
            keystream: Sha256::digest(&keystream_input),
        }
    }
}

// ---------------------------------------------------------------------------
// Session id signing
// ---------------------------------------------------------------------------

/// Signs the `ClientHello`'s session id with the password.
///
/// The MAC covers the message with the session id's last four bytes still zero,
/// and only then are the four tag bytes written into it — so a server that
/// recomputes the MAC over what it received, after zeroing those bytes, gets the
/// same value.
struct SessionIdSigner {
    password: Vec<u8>,
}

impl ClientHelloHook for SessionIdSigner {
    fn on_client_hello(
        &mut self,
        draft: &mut ClientHelloDraft<'_>,
    ) -> crate::protocol::tls13::Result<()> {
        let offset = draft.session_id_offset;
        let end = offset + SESSION_ID_LEN;
        if offset != SESSION_ID_OFFSET || draft.raw.len() < end {
            return Err(crate::protocol::tls13::Tls13Error::InvalidConfig(format!(
                "the ClientHello builder put the session id at {offset}, but ShadowTLS signs the \
                 id at {SESSION_ID_OFFSET}: the two would disagree on the wire"
            )));
        }

        let mut session_id = [0u8; SESSION_ID_LEN];
        fill_random(&mut session_id[..SESSION_ID_LEN - MAC_LEN]);

        let mut mac = Hmac::<Sha1>::new(&self.password);
        mac.update(&draft.raw[..offset]);
        mac.update(&session_id);
        mac.update(&draft.raw[end..]);
        let mut digest = [0u8; 64];
        mac.finalize_into(&mut digest);
        session_id[SESSION_ID_LEN - MAC_LEN..].copy_from_slice(&digest[..MAC_LEN]);

        draft.raw[offset..end].copy_from_slice(&session_id);
        Ok(())
    }
}

/// Whether the `ServerHello` record announces TLS 1.3, read from its
/// `supported_versions` extension.
fn announces_tls13(record: &[u8]) -> bool {
    // record(5) || handshake header(4) || version(2) || random(32) || sid len(1)
    let mut pos = SERVER_RANDOM_OFFSET + 32;
    if record.len() <= pos {
        return false;
    }
    let session_id_len = usize::from(record[pos]);
    pos += 1 + session_id_len;
    // cipher suite (2) + compression method (1)
    pos += 3;
    if record.len() < pos + 2 {
        return false;
    }
    let extensions_len = usize::from(u16::from_be_bytes([record[pos], record[pos + 1]]));
    pos += 2;
    let end = (pos + extensions_len).min(record.len());
    while pos + 4 <= end {
        let ext_type = u16::from_be_bytes([record[pos], record[pos + 1]]);
        let ext_len = usize::from(u16::from_be_bytes([record[pos + 2], record[pos + 3]]));
        pos += 4;
        if pos + ext_len > end {
            return false;
        }
        if ext_type == EXT_SUPPORTED_VERSIONS && ext_len == 2 {
            return u16::from_be_bytes([record[pos], record[pos + 1]]) == TLS_1_3;
        }
        pos += ext_len;
    }
    false
}

// ---------------------------------------------------------------------------
// Record reader
// ---------------------------------------------------------------------------

/// A socket plus the bytes that belong to a record the peer has not finished
/// sending.
///
/// A relay bounds its reads (see `RELAY_READ_POLL`), so a record can arrive in
/// pieces and `read_exact` is not usable: a timeout in the middle of one would
/// throw away the bytes it had already taken off the socket. The partial record
/// is kept here instead, and the timeout is handed back to the caller, which is
/// what it asked for.
struct RecordReader {
    sock: TcpStream,
    pending: Vec<u8>,
}

impl RecordReader {
    fn new(sock: TcpStream) -> Self {
        Self {
            sock,
            pending: Vec::new(),
        }
    }

    /// The next whole record, `None` at end of stream.
    fn next(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        loop {
            if self.pending.len() >= RECORD_HEADER {
                let len = usize::from(u16::from_be_bytes([self.pending[3], self.pending[4]]));
                if len > MAX_RECORD {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        format!("ShadowTLS: a {len}-byte record is past the cap"),
                    ));
                }
                if self.pending.len() >= RECORD_HEADER + len {
                    let record = self.pending[..RECORD_HEADER + len].to_vec();
                    self.pending.drain(..RECORD_HEADER + len);
                    return Ok(Some(record));
                }
            }

            let mut chunk = [0u8; 16 * 1024];
            match self.sock.read(&mut chunk) {
                Ok(0) => return Ok(None),
                Ok(n) => self.pending.extend_from_slice(&chunk[..n]),
                // A read timeout is how the relay stays cancellable; the bytes
                // of an unfinished record stay here for the next call.
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    return Err(e)
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// The socket, for the frame phase that takes over from the handshake.
    fn into_inner(self) -> (TcpStream, Vec<u8>) {
        (self.sock, self.pending)
    }
}

// ---------------------------------------------------------------------------
// The handshake-phase wrapper
// ---------------------------------------------------------------------------

/// The transport the TLS client reads the camouflage handshake through.
///
/// Outbound records are passed through untouched: during the handshake the
/// server is relaying them to the handshake destination. Inbound records are
/// unwrapped — the `ServerHello`'s random is lifted out, and the application-data
/// records that follow (which carry the *real* handshake's `EncryptedExtensions`,
/// certificate and `Finished`) are verified, un-XORed and handed to the TLS
/// client as ordinary records.
struct HandshakeReader {
    records: RecordReader,
    password: Vec<u8>,
    state: Option<HandshakeState>,
    /// An unwrapped record waiting for the TLS client to ask for it.
    ready: Vec<u8>,
    ready_pos: usize,
}

impl HandshakeReader {
    fn new(sock: TcpStream, password: Vec<u8>) -> Self {
        Self {
            records: RecordReader::new(sock),
            password,
            state: None,
            ready: Vec::new(),
            ready_pos: 0,
        }
    }

    /// Take the socket and the keys back, once the handshake is done.
    fn into_parts(self) -> (TcpStream, Vec<u8>, Option<HandshakeState>) {
        let (sock, pending) = self.records.into_inner();
        (sock, pending, self.state)
    }

    /// Unwrap one record, leaving the result in `ready`.
    fn prepare(&mut self) -> std::io::Result<()> {
        let record = match self.records.next()? {
            Some(record) => record,
            None => return Ok(()),
        };
        self.ready = record.clone();
        self.ready_pos = 0;

        if record[0] != RECORD_APP_DATA {
            if record[0] == RECORD_HANDSHAKE
                && record.len() >= SERVER_RANDOM_OFFSET + 32
                && record[RECORD_HEADER] == HANDSHAKE_SERVER_HELLO
            {
                let mut server_random = [0u8; 32];
                server_random
                    .copy_from_slice(&record[SERVER_RANDOM_OFFSET..SERVER_RANDOM_OFFSET + 32]);
                debug!(
                    "ShadowTLS: ServerHello seen (TLS 1.3: {}), server random {:02x?}",
                    announces_tls13(&record),
                    server_random
                );
                self.state = Some(HandshakeState::derive(&self.password, server_random));
            }
            return Ok(());
        }

        let state = match self.state.as_mut() {
            Some(state) => state,
            // Application data before the ServerHello cannot be unwrapped; it
            // cannot happen in a TLS handshake either, but passing it through
            // would feed the TLS client garbage, so it is dropped as a record
            // the handshake did not produce.
            None => return Ok(()),
        };

        let payload = &record[FRAME_HEADER..];
        let stragglers = state
            .stragglers
            .as_mut()
            .expect("the handshake phase keeps it");
        let tag = stragglers.tag(payload);
        if tag[..] != record[RECORD_HEADER..FRAME_HEADER] {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "ShadowTLS: a handshake record failed its MAC",
            ));
        }
        stragglers.observe(payload);

        // The payload is a real TLS record XORed with the keystream, so what the
        // TLS client gets back is that record.
        let mut plain = payload.to_vec();
        for (byte, key) in plain.iter_mut().zip(state.keystream.iter().cycle()) {
            *byte ^= key;
        }
        self.ready = present(&record, &plain);
        self.ready_pos = 0;
        Ok(())
    }
}

/// Whether `buf` is a whole TLS record, length field included.
fn is_record(buf: &[u8]) -> bool {
    buf.len() >= RECORD_HEADER
        && matches!(buf[0], 0x14..=0x17)
        && buf[1] == 0x03
        && buf[2] == 0x03
        && usize::from(u16::from_be_bytes([buf[3], buf[4]])) == buf.len() - RECORD_HEADER
}

/// What the TLS client is handed for a record the server wrapped.
///
/// The server's frame payload is the peer's record *whole* — header and all —
/// because that is what its wrapping loop takes off the socket to the handshake
/// destination. So an unwrapped payload is already a record and is passed on as
/// one, which is what keeps the handshake underneath transparent.
///
/// The reference instead keeps its own header in front and rewrites the length,
/// which leaves the receiving TLS stack a record whose content is another
/// record; only its forked rustls, which unwraps the nesting, can read that. A
/// payload that is not a record at all still gets the frame's header, with the
/// length corrected, because there is nothing else to stand in for one.
fn present(outer: &[u8], payload: &[u8]) -> Vec<u8> {
    if is_record(payload) {
        return payload.to_vec();
    }
    let mut record = outer[..RECORD_HEADER].to_vec();
    record[3..RECORD_HEADER].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(payload);
    record
}

impl Read for HandshakeReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.ready_pos < self.ready.len() {
                let take = (self.ready.len() - self.ready_pos).min(buf.len());
                buf[..take].copy_from_slice(&self.ready[self.ready_pos..self.ready_pos + take]);
                self.ready_pos += take;
                if self.ready_pos == self.ready.len() {
                    self.ready.clear();
                    self.ready_pos = 0;
                }
                return Ok(take);
            }
            self.ready.clear();
            self.ready_pos = 0;
            self.prepare()?;
            if self.ready.is_empty() {
                // The peer closed without a full record.
                return Ok(0);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The frame phase
// ---------------------------------------------------------------------------

/// A ShadowTLS v3 connection after the handshake, as a duplex stream.
struct ShadowTlsStream {
    reader: RecordReader,
    writer: TcpStream,
    state: HandshakeState,
    /// Decrypted payload not yet handed to the caller.
    decoded: Vec<u8>,
    decoded_pos: usize,
    /// The peer sent an alert or closed the stream.
    peer_closed: bool,
}

impl ShadowTlsStream {
    fn new(sock: TcpStream, writer: TcpStream, pending: Vec<u8>, state: HandshakeState) -> Self {
        let mut reader = RecordReader::new(sock);
        reader.pending = pending;
        Self {
            reader,
            writer,
            state,
            decoded: Vec::new(),
            decoded_pos: 0,
            peer_closed: false,
        }
    }

    /// Verify a frame and return its payload, or `None` for a record that is not
    /// part of the tunnel.
    fn decode(&mut self, record: &[u8]) -> std::io::Result<Option<Vec<u8>>> {
        match record[0] {
            RECORD_ALERT => {
                // A close_notify is the peer saying goodbye, which is a clean
                // end of stream rather than a broken frame.
                self.peer_closed = true;
                return Ok(None);
            }
            RECORD_APP_DATA => {}
            other => {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "ShadowTLS: unexpected TLS record type 0x{other:02x} in the data phase"
                    ),
                ))
            }
        }
        if record.len() < FRAME_HEADER {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "ShadowTLS: a frame is shorter than its own header",
            ));
        }

        let payload = &record[FRAME_HEADER..];
        if let Some(stragglers) = self.state.stragglers.as_mut() {
            let tag = stragglers.tag(payload);
            if tag[..] == record[RECORD_HEADER..FRAME_HEADER] {
                stragglers.observe(payload);
                debug!("ShadowTLS: dropped a record the handshake destination sent late");
                return Ok(None);
            }
            self.state.stragglers = None;
        }

        let tag = self.state.from_server.tag(payload);
        if tag[..] != record[RECORD_HEADER..FRAME_HEADER] {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "ShadowTLS: a frame failed its MAC, so the connection was not tunnelled by a peer \
                 that knows the password",
            ));
        }
        self.state.from_server.commit(payload, &tag);
        Ok(Some(payload.to_vec()))
    }
}

impl Read for ShadowTlsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.decoded_pos < self.decoded.len() {
                let take = (self.decoded.len() - self.decoded_pos).min(buf.len());
                buf[..take]
                    .copy_from_slice(&self.decoded[self.decoded_pos..self.decoded_pos + take]);
                self.decoded_pos += take;
                if self.decoded_pos == self.decoded.len() {
                    self.decoded.clear();
                    self.decoded_pos = 0;
                }
                return Ok(take);
            }
            self.decoded.clear();
            self.decoded_pos = 0;

            if self.peer_closed {
                return Ok(0);
            }
            let record = match self.reader.next()? {
                Some(record) => record,
                None => {
                    self.peer_closed = true;
                    return Ok(0);
                }
            };
            if let Some(payload) = self.decode(&record)? {
                self.decoded = payload;
            }
        }
    }
}

impl Write for ShadowTlsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let take = buf.len().min(MAX_FRAME_PAYLOAD);
        let payload = &buf[..take];

        let tag = self.state.to_server.tag(payload);
        // The MAC moves even if the socket write fails: a truncated frame has
        // already desynchronised the peer, so the connection is over either way.
        self.state.to_server.commit(payload, &tag);

        let mut record = Vec::with_capacity(FRAME_HEADER + take);
        record.extend_from_slice(&[RECORD_APP_DATA, 0x03, 0x03]);
        record.extend_from_slice(&((take + MAC_LEN) as u16).to_be_bytes());
        record.extend_from_slice(&tag);
        record.extend_from_slice(payload);
        self.writer.write_all(&record)?;
        Ok(take)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

impl SyncStream for ShadowTlsStream {
    fn shutdown(&self, how: Shutdown) -> std::io::Result<()> {
        let first = self.reader.sock.shutdown(how);
        let second = self.writer.shutdown(how);
        let result = first.and(second);
        match result {
            Err(e) if is_benign_shutdown_error(&e) => Ok(()),
            other => other,
        }
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.reader.sock.peer_addr().ok()
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.reader.sock.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.writer.set_write_timeout(timeout)
    }
}

// ---------------------------------------------------------------------------
// Outbound
// ---------------------------------------------------------------------------

/// The first configured spelling of an option that is present.
fn option_string(config: &OutboundConfig, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        config
            .options
            .get(*key)
            .and_then(|value| value.as_str())
            .map(|text| text.to_string())
    })
}

/// A boolean option, with the spellings a profile may use.
///
/// An unparsable value is an error rather than a `false`: `insecure` decides
/// whether the handshake's certificate is checked, and guessing at that is a
/// decision the user did not make.
fn option_bool(config: &OutboundConfig, keys: &[&str]) -> Result<Option<bool>> {
    let Some(raw) = option_string(config, keys) else {
        return Ok(None);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(Some(true)),
        "0" | "false" | "no" | "off" => Ok(Some(false)),
        other => Err(Error::config(format!(
            "ShadowTLS option `{}` must be a boolean, got '{other}'",
            keys[0]
        ))),
    }
}

/// Unix seconds, for the certificate validity window.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// ShadowTLS settings, kept for introspection and tests.
///
/// The password is deliberately absent: it lives in the outbound, next to
/// nothing that formats or logs it.
#[derive(Debug, Clone)]
pub struct ShadowTlsConfig {
    pub server: String,
    pub port: u16,
    /// The handshake destinations the `ClientHello` may present.
    pub sni: Vec<String>,
    pub fingerprint: String,
    pub alpn: Vec<String>,
    pub insecure: bool,
}

pub struct ShadowTlsOutbound {
    config: OutboundConfig,
    settings: ShadowTlsConfig,
    password: Vec<u8>,
    fingerprint: Fingerprint,
}

/// Debug without the password: the one field that must never reach a log line,
/// a panic message or a `{:?}` in a bug report.
impl core::fmt::Debug for ShadowTlsOutbound {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShadowTlsOutbound")
            .field("tag", &self.config.tag)
            .field("server", &self.settings.server)
            .field("port", &self.settings.port)
            .field("sni", &self.settings.sni)
            .field("fingerprint", &self.settings.fingerprint)
            .field("insecure", &self.settings.insecure)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl ShadowTlsOutbound {
    pub fn new(config: OutboundConfig) -> Result<Self> {
        let server = config
            .server
            .clone()
            .ok_or_else(|| Error::config("Missing server address for ShadowTLS"))?;
        let port = config
            .port
            .ok_or_else(|| Error::config("Missing port for ShadowTLS"))?;

        let password = option_string(&config, &["password"])
            .ok_or_else(|| Error::config("ShadowTLS requires a `password`"))?;

        let version = option_string(&config, &["version"]).unwrap_or_else(|| "3".to_string());
        if version.trim() != "3" {
            return Err(Error::config(format!(
                "ShadowTLS version {version} is not implemented: v1 and v2 sign the handshake with \
                 a different construction and v2 frames differently, so speaking v3's rules to them \
                 would fail in a way that looks like a wrong password. Version 3 only."
            )));
        }

        let sni: Vec<String> = option_string(&config, &["sni", "server-name", "tls-host"])
            .unwrap_or_default()
            .split([';', ','])
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty())
            .collect();
        if sni.is_empty() {
            return Err(Error::config(
                "ShadowTLS requires an `sni`: the handshake it hides behind is a real one, so it \
                 has to name the site the server will proxy to",
            ));
        }

        let fingerprint_name = option_string(&config, &["fingerprint", "client-fingerprint"])
            .unwrap_or_else(|| "chrome".to_string());
        let fingerprint = Fingerprint::parse(&fingerprint_name)
            .map_err(|e| Error::config(format!("ShadowTLS `fingerprint`: {e}")))?;

        let alpn: Vec<String> = option_string(&config, &["alpn"])
            .unwrap_or_default()
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect();

        let insecure = option_bool(&config, &["insecure", "skip-cert-verify", "tls-insecure"])?
            .unwrap_or(false);

        debug!(
            "Creating ShadowTLS outbound: server={server}:{port}, sni={sni:?}, fingerprint={:?}, \
             alpn={alpn:?}, certificate verification: {}",
            fingerprint.canonical_name(),
            if insecure { "off" } else { "on" }
        );

        Ok(Self {
            config,
            settings: ShadowTlsConfig {
                server,
                port,
                sni,
                fingerprint: fingerprint_name,
                alpn,
                insecure,
            },
            password: password.into_bytes(),
            fingerprint,
        })
    }

    /// The parsed settings, for introspection and tests.
    pub fn shadowtls_config(&self) -> &ShadowTlsConfig {
        &self.settings
    }

    /// Dial the server and run the camouflage handshake, leaving the socket in
    /// the frame phase.
    fn open(&self, timeout: Duration) -> Result<ShadowTlsStream> {
        let sock =
            connect_host(&self.settings.server, self.settings.port, timeout).map_err(|e| {
                Error::network(format!(
                    "Failed to connect to ShadowTLS server {}:{}: {e}",
                    self.settings.server, self.settings.port
                ))
            })?;
        sock.set_read_timeout(Some(timeout))
            .map_err(|e| Error::network(format!("set read timeout: {e}")))?;
        sock.set_write_timeout(Some(timeout))
            .map_err(|e| Error::network(format!("set write timeout: {e}")))?;
        let writer = sock
            .try_clone()
            .map_err(|e| Error::network(format!("clone ShadowTLS socket: {e}")))?;

        let mut pick = [0u8; 1];
        fill_random(&mut pick);
        let sni = self.settings.sni[usize::from(pick[0]) % self.settings.sni.len()].clone();

        let reader = HandshakeReader::new(sock, self.password.clone());
        let tls_config = Tls13ClientConfig {
            server_name: sni,
            alpn: self.settings.alpn.clone(),
            fingerprint: self.fingerprint.clone(),
            now: unix_now(),
            roots: Some(crate::common::roots::system_root_store().clone()),
            verify: !self.settings.insecure,
            auth: None,
            hello_hook: Some(Box::new(SessionIdSigner {
                password: self.password.clone(),
            })),
            compatibility_ccs: true,
            shutdown_hook: None,
        };

        let tls = connect(reader, writer, tls_config).map_err(|e| {
            Error::protocol(format!(
                "ShadowTLS: the camouflage handshake with {} failed: {e}",
                self.settings.sni.join(", ")
            ))
        })?;
        let (reader, writer) = tls.into_parts();
        let (sock, pending, state) = reader.into_parts();
        let state = state.ok_or_else(|| {
            Error::protocol(
                "ShadowTLS: the peer completed a handshake without a ServerHello in it, so the \
                 random every frame MAC depends on never arrived",
            )
        })?;
        debug!("ShadowTLS: handshake done, switching to frames");
        Ok(ShadowTlsStream::new(sock, writer, pending, state))
    }
}

impl OutboundProxy for ShadowTlsOutbound {
    fn connect(&self) -> Result<()> {
        // A wrong password still completes the handshake — the server proxies it
        // to the real site either way — so the only thing a probe can establish
        // is reachability and that the peer speaks TLS 1.3 here. The first frame
        // is what proves the password, and that only happens with traffic.
        let _probe = self.open(CONNECT_TIMEOUT)?;
        Ok(())
    }

    fn disconnect(&self) -> Result<()> {
        Ok(())
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn server_addr(&self) -> Option<(String, u16)> {
        Some((self.settings.server.clone(), self.settings.port))
    }

    fn supports_udp(&self) -> bool {
        false
    }

    fn relay_udp_packet(&self, _target: &TargetAddr, _data: &[u8]) -> Result<Vec<u8>> {
        Err(Error::config(
            "ShadowTLS carries one TCP stream at a time and has no datagram framing, so UDP \
             cannot be routed through this outbound",
        ))
    }

    fn test_http_latency(&self, test_url: &str, _timeout: Duration) -> Result<Duration> {
        Err(Error::config(format!(
            "testing '{test_url}' through the ShadowTLS outbound '{}' would need an HTTP responder \
             at the far end, but ShadowTLS's peer is a TLS pass-through for the handshake and the \
             inner protocol's own framing afterwards: a raw GET has nothing to answer it",
            self.config.tag
        )))
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
        let stream = self.open(CONNECT_TIMEOUT)?;
        debug!(
            "ShadowTLS: tunnelling to {target} via {}:{}",
            self.settings.server, self.settings.port
        );
        relay_streams!(inbound, stream, connection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::tls13::fingerprint::{build_client_hello, ClientHelloSpec};
    use std::net::TcpListener;

    const PASSWORD: &[u8] = b"a-shadowtls-password";
    const SERVER_RANDOM: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2,
        0xe1, 0xf0,
    ];

    /// A tag computed straight from the specification, with no state: the
    /// `chained` bytes are every frame before this one, payloads and tags
    /// together. The client's rolling MAC has to agree with this, which is what
    /// makes the two independent.
    fn spec_tag(direction: u8, chained: &[u8], payload: &[u8]) -> [u8; MAC_LEN] {
        let mut mac = Hmac::<Sha1>::new(PASSWORD);
        mac.update(&SERVER_RANDOM);
        mac.update(&[direction]);
        mac.update(chained);
        mac.update(payload);
        let mut digest = [0u8; 64];
        mac.finalize_into(&mut digest);
        let mut tag = [0u8; MAC_LEN];
        tag.copy_from_slice(&digest[..MAC_LEN]);
        tag
    }

    /// `17 03 03 || u16 (payload + 4) || tag || payload`.
    fn spec_frame(tag: [u8; MAC_LEN], payload: &[u8]) -> Vec<u8> {
        let mut record = Vec::with_capacity(FRAME_HEADER + payload.len());
        record.extend_from_slice(&[RECORD_APP_DATA, 0x03, 0x03]);
        record.extend_from_slice(&((payload.len() + MAC_LEN) as u16).to_be_bytes());
        record.extend_from_slice(&tag);
        record.extend_from_slice(payload);
        record
    }

    /// Two connected loopback sockets. Every test here drives both ends, so a
    /// real socket is used rather than a pipe: the record framing depends on
    /// what a single `read` returns.
    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let client = TcpStream::connect(addr).expect("connect");
        let (peer, _) = listener.accept().expect("accept");
        for sock in [&client, &peer] {
            sock.set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
        }
        (client, peer)
    }

    fn read_n(sock: &mut TcpStream, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        sock.read_exact(&mut buf).expect("read");
        buf
    }

    /// A TLS 1.3 `ServerHello` record, built here from the RFC's layout.
    fn server_hello_record() -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&SERVER_RANDOM);
        body.push(SESSION_ID_LEN as u8);
        body.extend_from_slice(&[0x5a; SESSION_ID_LEN]);
        body.extend_from_slice(&[0x13, 0x01, 0x00]); // AES-128-GCM, no compression
        body.extend_from_slice(&[0x00, 0x06]); // extension block, 6 bytes
        body.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]); // supported_versions

        let mut handshake = vec![HANDSHAKE_SERVER_HELLO, 0x00];
        handshake.extend_from_slice(&(body.len() as u16).to_be_bytes());
        handshake.extend_from_slice(&body);

        let mut record = vec![RECORD_HANDSHAKE, 0x03, 0x03];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    /// The session id the client signs has to be the id the server recomputes
    /// over: 28 random bytes, then the four that close `HMAC-SHA1` over the
    /// message with those four still zero.
    #[test]
    fn the_session_id_carries_the_password_mac() {
        let mut raw = build_client_hello(&ClientHelloSpec {
            server_name: "www.bing.com",
            alpn: &[],
            fingerprint: Fingerprint::Chrome,
            random: &[0x3c; 32],
            session_id: [0u8; SESSION_ID_LEN],
            key_share: &[0x7f; 32],
        })
        .expect("the builder produces a ClientHello")
        .raw;
        assert_eq!(raw[SESSION_ID_OFFSET - 1], SESSION_ID_LEN as u8);

        let mut draft = ClientHelloDraft {
            session_id_offset: SESSION_ID_OFFSET,
            random: &[0x3c; 32],
            key_share_private: &[0x11; 32],
            key_share_public: &[0x7f; 32],
            raw: &mut raw,
        };
        SessionIdSigner {
            password: PASSWORD.to_vec(),
        }
        .on_client_hello(&mut draft)
        .expect("signing cannot fail on a well-shaped hello");

        let end = SESSION_ID_OFFSET + SESSION_ID_LEN;
        assert_ne!(
            &raw[SESSION_ID_OFFSET..end - MAC_LEN],
            &[0u8; SESSION_ID_LEN - MAC_LEN][..],
            "the leading 28 bytes are fresh entropy"
        );

        let mut mac = Hmac::<Sha1>::new(PASSWORD);
        mac.update(&raw[..SESSION_ID_OFFSET]);
        mac.update(&raw[SESSION_ID_OFFSET..end - MAC_LEN]);
        mac.update(&[0u8; MAC_LEN]);
        mac.update(&raw[end..]);
        let mut digest = [0u8; 64];
        mac.finalize_into(&mut digest);
        assert_eq!(&raw[end - MAC_LEN..end], &digest[..MAC_LEN]);
    }

    /// A hello whose session id sits somewhere else is refused rather than
    /// signed in the wrong place: the peer would reject it either way, but the
    /// reason would be invisible.
    #[test]
    fn a_moved_session_id_is_refused() {
        let mut raw = vec![0u8; 128];
        let mut draft = ClientHelloDraft {
            session_id_offset: 40,
            random: &[0x3c; 32],
            key_share_private: &[0x11; 32],
            key_share_public: &[0x7f; 32],
            raw: &mut raw,
        };
        assert!(SessionIdSigner {
            password: PASSWORD.to_vec()
        }
        .on_client_hello(&mut draft)
        .is_err());
    }

    /// During the handshake the server's records are wrapped: the tag covers the
    /// payload as it arrived, and what the TLS client sees is the record inside.
    #[test]
    fn a_wrapped_handshake_record_is_verified_and_unwrapped() {
        let (client, mut peer) = pair();
        let mut reader = HandshakeReader::new(client, PASSWORD.to_vec());

        let hello = server_hello_record();
        peer.write_all(&hello).expect("write hello");

        // The inner record is a real TLS application-data record; the wire
        // carries it XORed, with the tag over the XORed bytes.
        let inner = {
            let mut record = vec![RECORD_APP_DATA, 0x03, 0x03, 0x00, 0x09];
            record.extend_from_slice(b"ciphertxt");
            record
        };
        let keystream = Sha256::digest(&[PASSWORD, &SERVER_RANDOM].concat());
        let mut xored = inner.clone();
        for (byte, key) in xored.iter_mut().zip(keystream.iter().cycle()) {
            *byte ^= key;
        }
        let mut mac = Hmac::<Sha1>::new(PASSWORD);
        mac.update(&SERVER_RANDOM);
        mac.update(&xored);
        let mut digest = [0u8; 64];
        mac.finalize_into(&mut digest);
        let mut wrapped = vec![RECORD_APP_DATA, 0x03, 0x03];
        wrapped.extend_from_slice(&((xored.len() + MAC_LEN) as u16).to_be_bytes());
        wrapped.extend_from_slice(&digest[..MAC_LEN]);
        wrapped.extend_from_slice(&xored);
        peer.write_all(&wrapped).expect("write wrapped");

        let mut buf = vec![0u8; 4096];
        let n = reader
            .read(&mut buf)
            .expect("the ServerHello is passed through");
        assert_eq!(&buf[..n], &hello[..]);

        let n = reader
            .read(&mut buf)
            .expect("the wrapped record is unwrapped");
        assert_eq!(&buf[..n], &inner[..]);
        assert!(
            reader.state.is_some(),
            "the server random was captured: the wrapper cannot verify anything without it"
        );
    }

    /// A tag that does not check out ends the connection: this is the only place
    /// the peer proves it knows the password.
    #[test]
    fn a_wrapped_record_with_a_bad_tag_is_refused() {
        let (client, mut peer) = pair();
        let mut reader = HandshakeReader::new(client, PASSWORD.to_vec());
        peer.write_all(&server_hello_record()).expect("write hello");

        let mut wrapped = vec![RECORD_APP_DATA, 0x03, 0x03, 0x00, 0x08];
        wrapped.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        wrapped.extend_from_slice(b"payload!");
        peer.write_all(&wrapped).expect("write wrapped");

        let mut buf = vec![0u8; 4096];
        let n = reader
            .read(&mut buf)
            .expect("the ServerHello is passed through");
        assert_eq!(&buf[..n], &server_hello_record()[..]);
        assert!(reader.read(&mut buf).is_err());
    }

    /// The `supported_versions` extension decides whether the handshake was
    /// 1.3, which is what the reference's teardown decoy hangs off.
    #[test]
    fn the_server_hello_says_whether_it_is_tls13() {
        let hello = server_hello_record();
        assert!(announces_tls13(&hello));

        // The same record with version 0x0303 in the extension.
        let mut downgraded = hello.clone();
        let last = downgraded.len();
        downgraded[last - 2..].copy_from_slice(&[0x03, 0x03]);
        assert!(!announces_tls13(&downgraded));

        assert!(!announces_tls13(&hello[..40]));
    }

    /// The frame phase, checked from both ends: the client's frames have to be
    /// the bytes the specification describes, and the tags have to chain.
    #[test]
    fn the_frame_phase_round_trips_against_the_specification() {
        let (client, mut peer) = pair();
        let state = HandshakeState::derive(PASSWORD, SERVER_RANDOM);
        let mut stream = ShadowTlsStream::new(
            client.try_clone().expect("clone"),
            client,
            Vec::new(),
            state,
        );

        // Client → server: two frames, the second chained onto the first.
        assert_eq!(stream.write(b"hello").expect("write"), 5);
        let first = read_n(&mut peer, FRAME_HEADER + 5);
        assert_eq!(&first[..5], &[0x17, 0x03, 0x03, 0x00, 0x09]);
        assert_eq!(&first[FRAME_HEADER..], b"hello");
        assert_eq!(
            &first[RECORD_HEADER..FRAME_HEADER],
            &spec_tag(b'C', &[], b"hello")
        );

        assert_eq!(stream.write(b"world").expect("write"), 5);
        let second = read_n(&mut peer, FRAME_HEADER + 5);
        let mut chain = b"hello".to_vec();
        chain.extend_from_slice(&first[RECORD_HEADER..FRAME_HEADER]);
        assert_eq!(
            &second[RECORD_HEADER..FRAME_HEADER],
            &spec_tag(b'C', &chain, b"world"),
            "the tag of a frame covers every frame before it"
        );

        // Server → client: the same shape, the other direction's key.
        let mut chain = Vec::new();
        for payload in [b"one".as_slice(), b"two".as_slice()] {
            let tag = spec_tag(b'S', &chain, payload);
            let frame = spec_frame(tag, payload);
            chain.extend_from_slice(payload);
            chain.extend_from_slice(&tag);
            peer.write_all(&frame).expect("write frame");
        }
        let mut buf = [0u8; 16];
        assert_eq!(stream.read(&mut buf).expect("read"), 3);
        assert_eq!(&buf[..3], b"one");
        assert_eq!(stream.read(&mut buf).expect("read"), 3);
        assert_eq!(&buf[..3], b"two");
    }

    /// Losing a frame is fatal even when the survivor's own payload is intact,
    /// which is the whole point of chaining the tags.
    #[test]
    fn a_spliced_frame_is_refused() {
        let (client, mut peer) = pair();
        let state = HandshakeState::derive(PASSWORD, SERVER_RANDOM);
        let mut stream = ShadowTlsStream::new(
            client.try_clone().expect("clone"),
            client,
            Vec::new(),
            state,
        );

        // The server sends the second frame of a pair, so the client's MAC is
        // one step behind.
        let first = spec_frame(spec_tag(b'S', &[], b"first"), b"first");
        let mut chain = b"first".to_vec();
        chain.extend_from_slice(&first[RECORD_HEADER..FRAME_HEADER]);
        let second = spec_frame(spec_tag(b'S', &chain, b"second"), b"second");
        peer.write_all(&second).expect("write frame");

        let mut buf = [0u8; 16];
        assert!(stream.read(&mut buf).is_err());
    }

    /// Records the handshake destination sends after the handshake are dropped
    /// rather than reported as corruption — the reference's "useless data"
    /// detector.
    #[test]
    fn a_late_handshake_record_is_dropped() {
        let (client, mut peer) = pair();
        let state = HandshakeState::derive(PASSWORD, SERVER_RANDOM);
        let mut stream = ShadowTlsStream::new(
            client.try_clone().expect("clone"),
            client,
            Vec::new(),
            state,
        );

        // A `NewSessionTicket` the handshake destination sent late: tagged with
        // the handshake MAC and XORed with the keystream.
        let keystream = Sha256::digest(&[PASSWORD, &SERVER_RANDOM].concat());
        let mut late = b"ticket".to_vec();
        for (byte, key) in late.iter_mut().zip(keystream.iter().cycle()) {
            *byte ^= key;
        }
        let mut mac = Hmac::<Sha1>::new(PASSWORD);
        mac.update(&SERVER_RANDOM);
        mac.update(&late);
        let mut digest = [0u8; 64];
        mac.finalize_into(&mut digest);
        let mut wrapped = vec![RECORD_APP_DATA, 0x03, 0x03];
        wrapped.extend_from_slice(&((late.len() + MAC_LEN) as u16).to_be_bytes());
        wrapped.extend_from_slice(&digest[..MAC_LEN]);
        wrapped.extend_from_slice(&late);

        let real = spec_frame(spec_tag(b'S', &[], b"payload"), b"payload");
        peer.write_all(&wrapped).expect("write late");
        peer.write_all(&real).expect("write real");

        let mut buf = [0u8; 16];
        assert_eq!(stream.read(&mut buf).expect("read"), 7);
        assert_eq!(&buf[..7], b"payload");
    }

    /// A close_notify is a clean end of stream, and anything else is a protocol
    /// error rather than data.
    #[test]
    fn an_alert_ends_the_stream_and_a_stray_record_is_an_error() {
        let (client, mut peer) = pair();
        let state = HandshakeState::derive(PASSWORD, SERVER_RANDOM);
        let mut stream = ShadowTlsStream::new(
            client.try_clone().expect("clone"),
            client,
            Vec::new(),
            state,
        );
        peer.write_all(&[RECORD_ALERT, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00])
            .expect("write alert");
        let mut buf = [0u8; 16];
        assert_eq!(stream.read(&mut buf).expect("read"), 0);

        let (client, mut peer) = pair();
        let state = HandshakeState::derive(PASSWORD, SERVER_RANDOM);
        let mut stream = ShadowTlsStream::new(
            client.try_clone().expect("clone"),
            client,
            Vec::new(),
            state,
        );
        peer.write_all(&[RECORD_HANDSHAKE, 0x03, 0x03, 0x00, 0x00])
            .expect("write stray");
        assert!(stream.read(&mut buf).is_err());
    }

    /// The config surface: what is required, what is refused, and why.
    #[test]
    fn the_config_refuses_what_it_cannot_speak() {
        let build = |options: &[(&str, nextjson::Value)]| {
            let mut map = std::collections::HashMap::new();
            for (k, v) in options {
                map.insert((*k).to_string(), v.clone());
            }
            ShadowTlsOutbound::new(OutboundConfig {
                tag: "shadowtls".to_string(),
                outbound_type: crate::engine::config::OutboundType::ShadowTls,
                server: Some("127.0.0.1".to_string()),
                port: Some(443),
                options: map,
            })
        };
        let string = |s: &str| nextjson::Value::String(s.to_string());

        assert!(build(&[("password", string("x"))])
            .unwrap_err()
            .to_string()
            .contains("sni"));
        assert!(build(&[("sni", string("www.bing.com"))])
            .unwrap_err()
            .to_string()
            .contains("password"));
        assert!(build(&[
            ("password", string("x")),
            ("sni", string("www.bing.com")),
            ("version", string("2"))
        ])
        .unwrap_err()
        .to_string()
        .contains("Version 3 only"));
        assert!(build(&[
            ("password", string("x")),
            ("sni", string("www.bing.com")),
            ("insecure", string("maybe"))
        ])
        .unwrap_err()
        .to_string()
        .contains("boolean"));

        let outbound = build(&[
            ("password", string("x")),
            ("sni", string("www.bing.com; www.cloudflare.com")),
            ("fingerprint", string("randomized")),
            ("alpn", string("h2,http/1.1")),
            ("insecure", string("true")),
        ])
        .expect("a complete config builds");
        let settings = outbound.shadowtls_config();
        assert_eq!(settings.sni.len(), 2);
        assert_eq!(settings.alpn, vec!["h2", "http/1.1"]);
        assert!(settings.insecure);
        assert_eq!(outbound.server_addr().unwrap().1, 443);
        assert!(!outbound.supports_udp());
    }
}
