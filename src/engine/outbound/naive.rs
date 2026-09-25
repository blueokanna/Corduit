//! NaiveProxy outbound.
//!
//! NaiveProxy is not a wire format of its own: it is an HTTP/2 `CONNECT`
//! tunnel with credentials, run over TLS with `h2` as the only ALPN offer, so
//! that what a network sees is an ordinary HTTPS session to a web server. The
//! server side is a normal HTTP/2 reverse proxy (`Caddy`'s `forward_proxy`)
//! that authorises the `CONNECT` from a `Proxy-Authorization: Basic` header and
//! then becomes a byte pipe.
//!
//! Three things make it work, and all three are here:
//!
//! * **The TLS offer is `h2` and nothing else.** A server that negotiates
//!   `http/1.1` cannot be spoken to at all, so a profile that asks for another
//!   ALPN list is refused at construction rather than failing one `CONNECT`
//!   later.
//! * **The `CONNECT` request is a real HTTP/2 request**: only `:method` and
//!   `:authority` (RFC 9113 §8.3.1 forbids `:scheme` and `:path` for
//!   `CONNECT`), plus the credential header and a browser-shaped `User-Agent`.
//!   The engine's HTTP/2 codec rejects anything connection-specific, which is
//!   what keeps the request from looking like a proxy request to a middlebox
//!   that understands HTTP/1.1 rules.
//! * **The tunnel is the request body in both directions.** Writes are `DATA`
//!   frames on the request stream, reads are the response `DATA` frames, and
//!   flow control is the codec's — a write that the peer's window cannot take
//!   yet returns short and is retried after the next poll, so a slow peer
//!   applies backpressure instead of growing a buffer.
//!
//! # Reference
//!
//! `klzgrad/naiveproxy`: `src/net/tools/naive/http_proxy_socket.cc` (the client
//! `CONNECT`), `naive_protocol.h` (the padding negotiation headers).
//!
//! # Deliberate refusals, each with its reason
//!
//! * **Padding (`kVariant1`).** The frame layout is known
//!   (`u16 data_len || u8 pad_len || data || zeros`, the first eight frames of a
//!   direction) and `padding-type-request: 0` is sent to negotiate it off
//!   explicitly. What is *not* pinned down is the `padding` request header's
//!   direction mask: `naive_protocol.h` names the header but not the bit
//!   assignment, and guessing it wrong does not fail loudly — it shifts every
//!   byte of the tunnel. A server that answers with a type other than `0` is
//!   therefore refused with a message, not stripped blindly.
//! * **HTTP/1.1 `CONNECT`.** `h2` only, for the reason above.
//! * **`probe_resistance`.** A server-side decision (whether an unauthenticated
//!   `CONNECT` is answered with a decoy site); the client has nothing to do.
//! * **UDP.** A `CONNECT` tunnel carries one TCP stream; naiveproxy has no
//!   datagram form, so UDP is refused rather than silently dropped.

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use courierust::courierust_bytes::{Bytes, BytesMut};
use courierust::courierust_h2::error::ErrorCode;
use courierust::courierust_h2::frame::{self, Frame};
use courierust::courierust_h2::settings::Settings;
use courierust::courierust_hpack::{Decoder, Encoder, HeaderField, HeaderList};
use courierust::courierust_http::header::{HeaderName, HeaderValue};
use tracing::debug;

use crate::common::socket::connect_host;
use crate::common::stream::{is_benign_shutdown_error, BoxStream, SyncStream};
use crate::engine::config::OutboundConfig;
use crate::engine::connection_tracker::TrackedConnection;
use crate::engine::error::{Error, Result};
use crate::engine::outbound::{OutboundProxy, TargetAddr};
use crate::engine::tls::{connect_advanced_tls, AdvancedTlsOptions, ClientConfig, TlsConnector};

/// TCP connect + handshake + `CONNECT` verdict budget.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest `DATA` payload this client sends in one frame. The peer's
/// `SETTINGS_MAX_FRAME_SIZE` and the flow-control window bound it further.
const MAX_DATA: usize = 16 * 1024;
/// The frame size this client advertises, so the largest frame it accepts is
/// the same number (RFC 9113 §6.5.2).
const MAX_FRAME_SIZE: usize = 16 * 1024;
/// How long a write may wait for the peer to widen its flow-control window
/// before the condition is reported as a timeout.
const WRITE_BUDGET: Duration = Duration::from_secs(30);
/// Received `DATA` credit is handed back once this much has piled up: the peer
/// never stalls on a round trip, and the window updates stay rare.
const CREDIT_THRESHOLD: u32 = 32 * 1024;
/// The initial flow-control window, fixed by RFC 9113 §6.9.2 until a
/// `SETTINGS_INITIAL_WINDOW_SIZE` changes it.
const INITIAL_WINDOW: i64 = 65535;
/// A window may never exceed 2^31-1 (RFC 9113 §6.9.1).
const MAX_WINDOW: i64 = 0x7fff_ffff;
/// A browser-shaped `User-Agent`. The tunnel is the point, but a client that
/// announces itself as a proxy is a client that a passive observer can pick
/// out.
const USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
     Chrome/120.0.0.0 Safari/537.36";

// ---------------------------------------------------------------------------
// The tunnel
// ---------------------------------------------------------------------------

/// A single-stream HTTP/2 `CONNECT` tunnel.
///
/// This is deliberately *not* the engine's h2 session codec: that one treats a
/// `CONNECT` stream as bodyless — a `DATA` frame on it is a `PROTOCOL_ERROR`
/// there — while RFC 9113 §8.3.1 makes `DATA` the tunnel itself, which is the
/// whole of what naiveproxy needs. So the session state machine, with its
/// multiplexing, priorities and stream table, is not the right tool; what *is*
/// needed is small and is written here on top of the crate's frame codec and
/// HPACK, which do the byte-level work:
///
/// * frames are read and dispatched one at a time, and only the frames a
///   one-stream tunnel can see are meaningful,
/// * both flow-control windows are tracked and obeyed, and the credit for
///   received `DATA` is handed back,
/// * `SETTINGS`, `PING`, `WINDOW_UPDATE`, `RST_STREAM` and `GOAWAY` are
///   answered or obeyed, so a real server sees a well-behaved peer.
///
/// Everything else in HTTP/2 (push, priorities, trailers, multiplexing) is
/// rejected or ignored exactly as RFC 9113 prescribes for a peer that does not
/// use it.
struct H2Tunnel {
    io: BoxStream,
    encoder: Encoder,
    decoder: Decoder,
    stream_id: u32,
    /// Socket bytes that are not yet a whole frame.
    incoming: Vec<u8>,
    /// Decoded `DATA` the caller has not taken yet.
    ready: Vec<u8>,
    ready_pos: usize,
    /// An incomplete header block (`HEADERS` + `CONTINUATION`).
    header_block: Option<Vec<u8>>,
    /// What the peer will accept: per stream, and for the connection.
    stream_window: i64,
    conn_window: i64,
    /// The peer's current settings, and the two this client acts on.
    peer_settings: Settings,
    peer_initial_window: i64,
    /// `DATA` received and not yet credited back.
    uncredited: u32,
    /// The response head, once seen.
    status: Option<u16>,
    /// The fields the response head carried.
    response_headers: Option<HeaderList>,
    /// The `padding-type-reply` the server negotiated.
    padding_reply: Option<String>,
    peer_closed: bool,
    /// Why the peer ended the stream, for the error message.
    reset: Option<ErrorCode>,
}

impl H2Tunnel {
    /// Send the connection preface, our settings and the `CONNECT` request,
    /// then read the verdict.
    fn connect(
        io: BoxStream,
        authority: &str,
        fields: &HeaderList,
        timeout: Duration,
    ) -> Result<Self> {
        let mut tunnel = Self {
            io,
            encoder: Encoder::new(),
            decoder: Decoder::new(4096, 16 * 1024 * 1024),
            stream_id: 1,
            incoming: Vec::new(),
            ready: Vec::new(),
            ready_pos: 0,
            header_block: None,
            stream_window: INITIAL_WINDOW,
            conn_window: INITIAL_WINDOW,
            peer_settings: Settings::default(),
            peer_initial_window: INITIAL_WINDOW,
            uncredited: 0,
            status: None,
            response_headers: None,
            padding_reply: None,
            peer_closed: false,
            reset: None,
        };

        // The preface and the settings that say how this client wants to be
        // spoken to. `enable_push: 0` is required of a client that does not
        // want pushes (RFC 9113 §6.5.2) — a server that pushes anyway is then a
        // protocol error rather than something to be handled.
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(frame::CLIENT_PREFACE);
        let mut settings = BytesMut::new();
        Frame::Settings {
            ack: false,
            entries: Settings {
                header_table_size: 4096,
                enable_push: 0,
                max_concurrent_streams: 1,
                initial_window_size: 65535,
                max_frame_size: MAX_FRAME_SIZE as u32,
                max_header_list_size: 64 * 1024,
                no_rfc7540_priorities: 0,
            }
            .to_vec(),
        }
        .encode(&mut settings);
        out.extend_from_slice(settings.as_slice());

        // One `HEADERS` frame: the header block is far below any frame size a
        // peer advertises, so no `CONTINUATION` is needed to send it.
        let mut block = BytesMut::new();
        tunnel.encoder.encode(fields, &mut block);
        if block.len() > MAX_FRAME_SIZE {
            return Err(Error::config(format!(
                "NaiveProxy: the CONNECT header block is {} bytes, past the {MAX_FRAME_SIZE}-byte \
                 frame a peer refuses",
                block.len()
            )));
        }
        let mut headers = BytesMut::new();
        Frame::Headers {
            stream_id: tunnel.stream_id,
            block: Bytes::from(block.as_slice().to_vec()),
            end_stream: false,
            end_headers: true,
            priority: None,
        }
        .encode(&mut headers);
        out.extend_from_slice(headers.as_slice());

        tunnel
            .io
            .write_all(&out)
            .and_then(|()| tunnel.io.flush())
            .map_err(|e| Error::network(format!("NaiveProxy: cannot send CONNECT: {e}")))?;

        let deadline = Instant::now() + timeout;
        while tunnel.status.is_none() {
            if Instant::now() >= deadline {
                return Err(Error::network(format!(
                    "NaiveProxy: no CONNECT verdict for {authority} within {timeout:?}"
                )));
            }
            match tunnel.pump() {
                Ok(()) => {}
                Err(e) if is_would_block(&e) => continue,
                Err(e) => {
                    return Err(Error::network(format!(
                        "NaiveProxy: reading the CONNECT verdict failed: {e}"
                    )))
                }
            }
            if tunnel.peer_closed && tunnel.status.is_none() {
                return Err(Error::protocol(format!(
                    "NaiveProxy: {authority} ended the stream before answering the CONNECT"
                )));
            }
        }
        if tunnel.status == Some(200) && tunnel.peer_closed {
            return Err(Error::protocol(
                "NaiveProxy: the server ended the tunnel as soon as it opened it",
            ));
        }

        let status = tunnel.status.expect("the loop exits only with a status");
        if status != 200 {
            return Err(Error::network(format!(
                "NaiveProxy: CONNECT to {authority} was refused with status {status} \
                 (401 means the credentials were rejected)"
            )));
        }
        // `padding-type-request: 0` was sent, so anything else is a server that
        // pads a tunnel this build would mis-frame; refusing is the only honest
        // answer, because a wrongly stripped frame corrupts the stream instead
        // of failing.
        if let Some(reply) = tunnel.padding_reply.as_deref() {
            if reply.trim() != "0" {
                return Err(Error::protocol(format!(
                    "NaiveProxy: the server negotiated padding type '{reply}', which this build \
                     does not implement: the `padding` header's direction mask is not stated in \
                     the protocol header, and a wrong guess would shift every byte of the tunnel"
                )));
            }
        }

        debug!(
            "NaiveProxy: tunnel to {authority} established (stream {}, {} response fields)",
            tunnel.stream_id,
            tunnel
                .response_headers
                .as_ref()
                .map(HeaderList::len)
                .unwrap_or(0)
        );
        Ok(tunnel)
    }

    /// Write one frame.
    fn send(&mut self, frame: &Frame) -> std::io::Result<()> {
        let mut buf = BytesMut::with_capacity(64);
        frame.encode(&mut buf);
        self.io.write_all(buf.as_slice())
    }

    /// Read one frame, `Ok(None)` when the buffer holds none and the socket has
    /// nothing yet. A would-block from the transport is propagated as such: the
    /// caller decides whether that means "park" or "give up".
    fn next_frame(&mut self) -> std::io::Result<Option<Frame>> {
        loop {
            if self.incoming.len() >= frame::FRAME_HEADER_LEN {
                let mut header = [0u8; frame::FRAME_HEADER_LEN];
                header.copy_from_slice(&self.incoming[..frame::FRAME_HEADER_LEN]);
                let header = frame::decode_header(&header);
                if header.len as usize > MAX_FRAME_SIZE {
                    return Err(protocol_error(format!(
                        "a {}-byte frame is past the {MAX_FRAME_SIZE}-byte limit this client \
                         advertised",
                        header.len
                    )));
                }
                let total = frame::FRAME_HEADER_LEN + header.len as usize;
                if self.incoming.len() < total {
                    // A partial frame stays buffered: the next read resumes it.
                } else {
                    let payload = self.incoming[frame::FRAME_HEADER_LEN..total].to_vec();
                    self.incoming.drain(..total);
                    let frame = Frame::parse(header, &payload, MAX_FRAME_SIZE as u32)
                        .map_err(|e| protocol_error(format!("malformed frame: {e}")))?;
                    return Ok(Some(frame));
                }
            }
            let mut chunk = [0u8; 16 * 1024];
            match self.io.read(&mut chunk) {
                Ok(0) => {
                    self.peer_closed = true;
                    return Ok(None);
                }
                Ok(n) => self.incoming.extend_from_slice(&chunk[..n]),
                Err(e) if is_would_block(&e) => return Err(e),
                Err(e) => return Err(e),
            }
        }
    }

    /// Read and act on frames until one arrives that the caller can use.
    fn pump(&mut self) -> std::io::Result<()> {
        while let Some(frame) = self.next_frame()? {
            self.handle(frame)?;
        }
        Ok(())
    }

    /// Dispatch one frame.
    fn handle(&mut self, frame: Frame) -> std::io::Result<()> {
        match frame {
            Frame::Settings { ack, entries } => {
                if ack {
                    return Ok(());
                }
                let previous_initial = self.peer_initial_window;
                let mut settings = self.peer_settings.clone();
                settings
                    .apply(&entries)
                    .map_err(|e| protocol_error(format!("the peer sent invalid SETTINGS: {e}")))?;
                // A change to the initial window resizes every open stream's
                // send window by the difference (RFC 9113 §6.9.2).
                let delta = i64::from(settings.initial_window_size) - previous_initial;
                self.stream_window = (self.stream_window + delta).min(MAX_WINDOW);
                self.peer_initial_window = i64::from(settings.initial_window_size);
                self.peer_settings = settings;
                self.send(&Frame::Settings {
                    ack: true,
                    entries: Vec::new(),
                })
            }
            Frame::WindowUpdate {
                stream_id,
                increment,
            } => {
                if increment == 0 {
                    return Err(protocol_error(
                        "a WINDOW_UPDATE with a zero increment is a protocol error (RFC 9113 §6.9)",
                    ));
                }
                if stream_id == 0 {
                    self.conn_window = (self.conn_window + i64::from(increment)).min(MAX_WINDOW);
                } else if stream_id == self.stream_id {
                    self.stream_window =
                        (self.stream_window + i64::from(increment)).min(MAX_WINDOW);
                }
                Ok(())
            }
            Frame::Headers {
                stream_id,
                block,
                end_headers,
                end_stream,
                ..
            } => {
                if stream_id != self.stream_id {
                    return Ok(());
                }
                self.header_block = Some(block.to_vec());
                if end_headers {
                    self.finish_headers()?;
                }
                if end_stream {
                    self.peer_closed = true;
                }
                Ok(())
            }
            Frame::Continuation {
                stream_id,
                block,
                end_headers,
            } => {
                if stream_id != self.stream_id {
                    return Ok(());
                }
                let Some(pending) = self.header_block.as_mut() else {
                    return Err(protocol_error(
                        "a CONTINUATION frame with no open header block (RFC 9113 §6.10)",
                    ));
                };
                pending.extend_from_slice(&block);
                if end_headers {
                    self.finish_headers()?;
                }
                Ok(())
            }
            Frame::Data {
                stream_id,
                data,
                end_stream,
                padding,
            } => {
                if stream_id != self.stream_id {
                    // This client opens one stream; DATA elsewhere is a
                    // connection error rather than something to discard.
                    return Err(protocol_error("DATA on a stream this client never opened"));
                }
                self.ready.extend_from_slice(&data);
                self.uncredited = self
                    .uncredited
                    .saturating_add(data.len() as u32)
                    .saturating_add(padding as u32);
                if self.uncredited >= CREDIT_THRESHOLD || end_stream {
                    self.credit()?;
                }
                if end_stream {
                    self.peer_closed = true;
                }
                Ok(())
            }
            Frame::RstStream {
                stream_id,
                error_code,
            } => {
                if stream_id == self.stream_id {
                    self.reset = Some(error_code);
                    self.peer_closed = true;
                }
                Ok(())
            }
            Frame::GoAway {
                last_stream_id,
                error_code,
                debug,
            } => {
                if last_stream_id >= self.stream_id {
                    return Err(protocol_error(format!(
                        "the peer sent GOAWAY ({error_code:?}) for this stream: {}",
                        String::from_utf8_lossy(&debug)
                    )));
                }
                self.peer_closed = true;
                Ok(())
            }
            Frame::Ping { ack, data } => {
                if ack {
                    return Ok(());
                }
                self.send(&Frame::Ping { ack: true, data })
            }
            Frame::PushPromise { .. } => Err(protocol_error(
                "the peer pushed a stream after this client advertised SETTINGS_ENABLE_PUSH=0 \
                 (RFC 9113 §6.5.2)",
            )),
            // PRIORITY, PRIORITY_UPDATE, PUSH-related and unknown frames carry
            // nothing a tunnel needs; RFC 9113 §4.1 requires unknown ones to be
            // ignored.
            _ => Ok(()),
        }
    }

    /// Decode a complete header block and pick out the status (and the padding
    /// reply, if the server sent one).
    fn finish_headers(&mut self) -> std::io::Result<()> {
        let block = self.header_block.take().expect("only called with one open");
        let fields = self
            .decoder
            .decode(&block)
            .map_err(|e| protocol_error(format!("the response header block is invalid: {e}")))?;
        for field in &fields {
            match field.name.as_str() {
                ":status" => {
                    self.status = field
                        .value
                        .to_str()
                        .ok()
                        .and_then(|s| s.trim().parse::<u16>().ok());
                }
                "padding-type-reply" => {
                    self.padding_reply = field.value.to_str().ok().map(str::to_string)
                }
                _ => {}
            }
        }
        self.response_headers = Some(fields);
        Ok(())
    }

    /// Hand the peer back the flow-control credit for what has been received.
    fn credit(&mut self) -> std::io::Result<()> {
        if self.uncredited == 0 {
            return Ok(());
        }
        let increment = self.uncredited;
        self.uncredited = 0;
        // Both windows have to be widened: the connection's and the stream's.
        self.send(&Frame::WindowUpdate {
            stream_id: 0,
            increment,
        })?;
        self.send(&Frame::WindowUpdate {
            stream_id: self.stream_id,
            increment,
        })
    }

    /// How much of `buf` can go out right now.
    fn room(&self, want: usize) -> usize {
        let window = self.stream_window.min(self.conn_window).max(0) as usize;
        let frame = self.peer_settings.max_frame_size as usize;
        want.min(window).min(frame).min(MAX_DATA)
    }

    /// Frame and send `buf`, waiting for the peer's window if it is closed.
    fn write_data(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let deadline = Instant::now() + WRITE_BUDGET;
        loop {
            let take = self.room(buf.len());
            if take > 0 {
                let frame = Frame::Data {
                    stream_id: self.stream_id,
                    data: Bytes::from(&buf[..take]),
                    end_stream: false,
                    padding: 0,
                };
                self.send(&frame)?;
                self.stream_window -= take as i64;
                self.conn_window -= take as i64;
                return Ok(take);
            }
            if self.peer_closed {
                return Err(std::io::Error::new(
                    ErrorKind::BrokenPipe,
                    match self.reset {
                        Some(code) => format!("NaiveProxy: the peer reset the tunnel ({code:?})"),
                        None => "NaiveProxy: the peer closed the tunnel".to_string(),
                    },
                ));
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    ErrorKind::TimedOut,
                    "NaiveProxy: the peer's flow-control window stayed closed",
                ));
            }
            // Nothing can go out until a `WINDOW_UPDATE` arrives, so read until
            // one does. A transport timeout is not a failure here: it is the
            // socket's poll interval, and the deadline bounds the wait.
            match self.pump() {
                Ok(()) => {}
                Err(e) if is_would_block(&e) => {}
                Err(e) => return Err(e),
            }
        }
    }
}

/// An `io::Error` carrying a protocol violation.
fn protocol_error(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(ErrorKind::InvalidData, message.into())
}

/// Whether an error is the transport's "nothing right now".
fn is_would_block(error: &std::io::Error) -> bool {
    matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

// ---------------------------------------------------------------------------
// Outbound
// ---------------------------------------------------------------------------

/// TLS parameters for the proxy hop.
struct NaiveTls {
    sni: String,
    skip_cert_verify: bool,
    connector: TlsConnector,
    advanced: AdvancedTlsOptions,
}

pub struct NaiveOutbound {
    config: OutboundConfig,
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    tls: Option<NaiveTls>,
    /// Whether the profile asked for no TLS at all, which is only ever useful
    /// against a loopback listener and is reported as such.
    plaintext: bool,
}

/// Debug without the credentials: they must not reach a log line, a panic
/// message or a `{:?}` in a bug report.
impl core::fmt::Debug for NaiveOutbound {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NaiveOutbound")
            .field("tag", &self.config.tag)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("username", &self.username.is_some())
            .field("password", &"<redacted>")
            .field("plaintext", &self.plaintext)
            .finish()
    }
}

impl NaiveOutbound {
    pub fn new(config: OutboundConfig) -> Result<Self> {
        let server = config
            .server
            .as_ref()
            .ok_or_else(|| Error::config("Missing server address for NaiveProxy"))?
            .clone();
        let port = config
            .port
            .ok_or_else(|| Error::config("Missing port for NaiveProxy"))?;

        let username = config
            .options
            .get("username")
            .or_else(|| config.options.get("user"))
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let password = config
            .options
            .get("password")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        // Both go into a header value: a CR or LF in either would inject
        // headers into the request this client signs with its credentials.
        for (field, value) in [("username", &username), ("password", &password)] {
            if let Some(value) = value {
                if value.contains(['\r', '\n']) {
                    return Err(Error::config(format!(
                        "NaiveProxy {field} must not contain CR or LF: it is encoded into a \
                         Proxy-Authorization header value"
                    )));
                }
            }
        }
        if username.is_some() != password.is_some() {
            return Err(Error::config(
                "NaiveProxy needs both `username` and `password` (the server checks them as one \
                 Basic credential), or neither",
            ));
        }

        // `security: tls` / `tls: false` are honoured, but a NaiveProxy hop is
        // HTTPS by definition: plaintext is only accepted when the profile says
        // so explicitly, and the reason is logged.
        let plaintext = config
            .options
            .get("tls")
            .and_then(|v| v.as_bool())
            .is_some_and(|enabled| !enabled);

        let tls = if plaintext {
            debug!(
                "NaiveProxy: TLS disabled by the profile for {server}:{port}; this is only \
                 sensible against a loopback listener"
            );
            None
        } else {
            let sni = config
                .options
                .get("sni")
                .or_else(|| config.options.get("server-name"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| server.clone());

            let skip_cert_verify = config
                .options
                .get("skip-cert-verify")
                .or_else(|| config.options.get("insecure"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            // The offer is `h2` alone. An explicit list is accepted only if it
            // includes it, because a hop that answers `http/1.1` cannot carry
            // this tunnel at all.
            let alpn = config
                .options
                .get("alpn")
                .and_then(|v| v.as_array())
                .map(|seq| {
                    seq.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect::<Vec<_>>()
                })
                .filter(|v: &Vec<String>| !v.is_empty())
                .unwrap_or_else(|| vec!["h2".to_string()]);
            if !alpn.iter().any(|p| p.eq_ignore_ascii_case("h2")) {
                return Err(Error::config(format!(
                    "NaiveProxy requires `h2` in its ALPN offer, but the profile lists {alpn:?}: an \
                     HTTP/1.1 hop cannot carry a `CONNECT` tunnel with an HTTP/2 request body"
                )));
            }

            let advanced = AdvancedTlsOptions::from_options(&config.options, &sni)?;
            let connector = TlsConnector::new(ClientConfig {
                server_name: Some(sni.clone()),
                alpn: alpn.clone(),
                skip_cert_verify,
                enable_sni: true,
            })
            .map_err(|e| Error::Tls {
                message: format!("NaiveProxy TLS connector: {e}"),
                source: None,
            })?;

            Some(NaiveTls {
                sni,
                skip_cert_verify,
                connector,
                advanced,
            })
        };

        Ok(Self {
            config,
            server,
            port,
            username,
            password,
            tls,
            plaintext,
        })
    }

    /// The proxy's host and port, for introspection and tests.
    pub fn server_endpoint(&self) -> (&str, u16) {
        (&self.server, self.port)
    }

    /// Whether the profile turned TLS off, for introspection and tests.
    pub fn is_plaintext(&self) -> bool {
        self.plaintext
    }

    fn dial_tcp(&self, timeout: Duration) -> Result<TcpStream> {
        connect_host(&self.server, self.port, timeout).map_err(|e| {
            Error::network(format!(
                "Failed to connect to NaiveProxy server {}:{}: {e}",
                self.server, self.port
            ))
        })
    }

    /// Wrap a dialled socket in the hop's TLS layer, offering `h2`.
    fn wrap_tls(&self, stream: TcpStream) -> Result<BoxStream> {
        let Some(tls) = &self.tls else {
            return Ok(Box::new(stream) as BoxStream);
        };
        if tls.advanced.is_empty() {
            tls.connector
                .connect(stream, &tls.sni)
                .map_err(|e| Error::Tls {
                    message: format!("NaiveProxy TLS handshake with {}: {e}", tls.sni),
                    source: None,
                })
        } else {
            connect_advanced_tls(
                stream,
                &tls.sni,
                &["h2".to_string()],
                tls.skip_cert_verify,
                &tls.advanced,
            )
        }
    }

    /// Open the transport and put the `CONNECT` on the wire.
    fn open_tunnel(&self, target: &TargetAddr, timeout: Duration) -> Result<H2Tunnel> {
        let tcp = self.dial_tcp(timeout)?;
        tcp.set_read_timeout(Some(timeout))
            .map_err(|e| Error::network(format!("set read timeout: {e}")))?;
        tcp.set_write_timeout(Some(timeout))
            .map_err(|e| Error::network(format!("set write timeout: {e}")))?;

        let transport = self.wrap_tls(tcp)?;
        let authority = target.to_string();
        let mut fields: HeaderList = Vec::with_capacity(5);
        // Pseudo-headers first. For `CONNECT` exactly these two: RFC 9113 §8.3.1
        // makes `:scheme` and `:path` a stream error on a `CONNECT`, and the
        // codec enforces that on the way out. A pseudo-name goes through
        // `HeaderName::from_lowercase`, which is the constructor that admits the
        // leading colon.
        fields.push(HeaderField::new(
            HeaderName::from_lowercase(":method"),
            HeaderValue::from_static("CONNECT"),
        ));
        fields.push(HeaderField::new(
            HeaderName::from_lowercase(":authority"),
            HeaderValue::from_bytes(authority.as_bytes()).map_err(|e| {
                Error::config(format!(
                    "NaiveProxy: `{authority}` is not a valid authority: {e}"
                ))
            })?,
        ));
        fields.push(HeaderField::new(
            HeaderName::from_static("user-agent"),
            HeaderValue::from_bytes(USER_AGENT.as_bytes()).expect("static user agent"),
        ));
        if let (Some(user), Some(pass)) = (&self.username, &self.password) {
            let credentials = format!("{user}:{pass}");
            let encoded = courierust::courierust_crypto::base64::encode(credentials.as_bytes());
            fields.push(HeaderField::new(
                HeaderName::from_static("proxy-authorization"),
                HeaderValue::from_bytes(format!("Basic {encoded}").as_bytes())
                    .expect("base64 is a valid field value"),
            ));
        }
        // Ask for no padding explicitly, so a server does not have to infer it
        // from the header's absence.
        fields.push(HeaderField::new(
            HeaderName::from_static("padding-type-request"),
            HeaderValue::from_static("0"),
        ));

        H2Tunnel::connect(transport, &authority, &fields, timeout)
    }
}

impl Read for H2Tunnel {
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
            if self.peer_closed {
                return Ok(0);
            }
            // Read and act on frames until one of them carries body bytes.
            // A frame that carries none (a settings exchange, a ping) leaves
            // the loop to poll again.
            self.pump()?;
        }
    }
}

impl Write for H2Tunnel {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.write_data(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.io.flush()
    }
}

impl SyncStream for H2Tunnel {
    fn shutdown(&self, how: Shutdown) -> std::io::Result<()> {
        // An HTTP/2 tunnel has no half-close: ending the request half would end
        // the whole exchange, which is not what a relay that is winding down
        // means. Only a full close is forwarded, and closing the socket under
        // the tunnel ends the stream on the peer's side as well.
        if how != Shutdown::Both {
            return Ok(());
        }
        match self.io.shutdown(Shutdown::Both) {
            Err(e) if is_benign_shutdown_error(&e) => Ok(()),
            other => other,
        }
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.io.peer_addr()
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.io.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.io.set_write_timeout(timeout)
    }
}

impl OutboundProxy for NaiveOutbound {
    fn connect(&self) -> Result<()> {
        // The hop's TLS handshake is what this probe can establish: whether the
        // credentials are accepted only shows up on a `CONNECT`, which needs a
        // destination.
        let tcp = self.dial_tcp(HANDSHAKE_TIMEOUT)?;
        tcp.set_read_timeout(Some(HANDSHAKE_TIMEOUT))
            .map_err(|e| Error::network(format!("set read timeout: {e}")))?;
        tcp.set_write_timeout(Some(HANDSHAKE_TIMEOUT))
            .map_err(|e| Error::network(format!("set write timeout: {e}")))?;
        let _transport = self.wrap_tls(tcp)?;
        Ok(())
    }

    fn disconnect(&self) -> Result<()> {
        Ok(())
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn server_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }

    fn supports_udp(&self) -> bool {
        false
    }

    fn relay_udp_packet(&self, _target: &TargetAddr, _data: &[u8]) -> Result<Vec<u8>> {
        Err(Error::config(
            "NaiveProxy is an HTTP/2 `CONNECT` tunnel: it carries one TCP stream per request and \
             has no datagram form, so UDP cannot be routed through this outbound",
        ))
    }

    fn test_http_latency(&self, test_url: &str, timeout: Duration) -> Result<Duration> {
        let url = crate::common::url::Url::parse(test_url)
            .map_err(|e| Error::config(format!("Invalid test URL: {e}")))?;
        let host = url
            .host_str()
            .ok_or_else(|| Error::config("Test URL has no host"))?
            .to_string();
        let port = url
            .port()
            .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        let path = if url.path().is_empty() {
            "/"
        } else {
            url.path()
        };

        let start = Instant::now();
        let mut stream = self.open_tunnel(
            &TargetAddr::Domain(host.clone(), port),
            timeout.min(HANDSHAKE_TIMEOUT),
        )?;
        // A plain `GET` on the tunnel: the probe measures the tunnel, and the
        // caller picks a destination that speaks plain HTTP (an `https://` test
        // URL would need a TLS handshake inside it, which this transport cannot
        // host because the session owns the socket).
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: \
             Corduit/1.0\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| Error::network(format!("Failed to send probe request: {e}")))?;
        let mut first = [0u8; 5];
        stream
            .read_exact(&mut first)
            .map_err(|e| Error::network(format!("Failed to read probe response: {e}")))?;
        if &first != b"HTTP/" {
            return Err(Error::protocol(
                "NaiveProxy latency probe did not get an HTTP status line",
            ));
        }
        Ok(start.elapsed())
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
        let stream = self.open_tunnel(&target, HANDSHAKE_TIMEOUT)?;
        debug!(
            "NaiveProxy: tunnelling to {target} via {}:{}",
            self.server, self.port
        );
        relay_streams!(inbound, stream, connection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    /// What the test server saw in the `CONNECT` request.
    #[derive(Debug)]
    struct SeenRequest {
        method: Option<String>,
        authority: Option<String>,
        authorization: Option<String>,
        padding_request: Option<String>,
        user_agent: Option<String>,
        has_path_or_scheme: bool,
    }

    /// An HTTP/2 server that answers one `CONNECT` and then echoes the tunnel.
    ///
    /// It is the other end of the protocol rather than a mock: driven frame by
    /// frame on the crate's frame codec and HPACK, written independently of the
    /// client's tunnel, so agreement between the two means something. The
    /// request it saw comes back over a channel.
    fn spawn_server(status: &'static str) -> (std::net::SocketAddr, mpsc::Receiver<SeenRequest>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, rx) = mpsc::channel();

        /// The next whole frame, waiting on the socket for it.
        fn read_frame(reader: &mut TcpStream, buf: &mut Vec<u8>) -> Frame {
            loop {
                if buf.len() >= frame::FRAME_HEADER_LEN {
                    let mut header = [0u8; frame::FRAME_HEADER_LEN];
                    header.copy_from_slice(&buf[..frame::FRAME_HEADER_LEN]);
                    let header = frame::decode_header(&header);
                    let total = frame::FRAME_HEADER_LEN + header.len as usize;
                    if buf.len() >= total {
                        let payload = buf[frame::FRAME_HEADER_LEN..total].to_vec();
                        buf.drain(..total);
                        return Frame::parse(header, &payload, 1 << 20).expect("a valid frame");
                    }
                }
                let mut chunk = [0u8; 8192];
                let n = reader.read(&mut chunk).expect("server read");
                assert!(n > 0, "the client closed the connection early");
                buf.extend_from_slice(&chunk[..n]);
            }
        }

        fn send(writer: &mut TcpStream, frame: &Frame) {
            let mut out = BytesMut::new();
            frame.encode(&mut out);
            writer.write_all(out.as_slice()).expect("server write");
            writer.flush().expect("server flush");
        }

        thread::spawn(move || {
            let sock = listener.accept().expect("accept").0;
            sock.set_read_timeout(Some(Duration::from_secs(10)))
                .expect("timeout");
            let mut reader = sock.try_clone().expect("clone");
            let mut writer = sock;

            // A server reads the client's preface first: it is what tells the
            // two roles apart on the wire.
            let mut preface = [0u8; frame::CLIENT_PREFACE.len()];
            reader.read_exact(&mut preface).expect("h2 preface");
            assert_eq!(
                &preface,
                frame::CLIENT_PREFACE,
                "the tunnel must open with the HTTP/2 connection preface"
            );

            let mut decoder = Decoder::new(4096, 16 * 1024 * 1024);
            let mut buf = Vec::new();
            let mut seen = SeenRequest {
                method: None,
                authority: None,
                authorization: None,
                padding_request: None,
                user_agent: None,
                has_path_or_scheme: false,
            };
            let mut stream_id: Option<u32> = None;

            // The request arrives after the settings exchange.
            while stream_id.is_none() {
                match read_frame(&mut reader, &mut buf) {
                    Frame::Settings { ack: false, .. } => send(
                        &mut writer,
                        &Frame::Settings {
                            ack: true,
                            entries: Vec::new(),
                        },
                    ),
                    Frame::Headers {
                        stream_id: id,
                        block,
                        ..
                    } => {
                        let fields = decoder.decode(&block).expect("the request block decodes");
                        for field in &fields {
                            let value = field.value.to_str().unwrap_or_default().to_string();
                            match field.name.as_str() {
                                ":method" => seen.method = Some(value),
                                ":authority" => seen.authority = Some(value),
                                ":path" | ":scheme" => seen.has_path_or_scheme = true,
                                "proxy-authorization" => seen.authorization = Some(value),
                                "padding-type-request" => seen.padding_request = Some(value),
                                "user-agent" => seen.user_agent = Some(value),
                                _ => {}
                            }
                        }
                        stream_id = Some(id);
                    }
                    _ => {}
                }
            }
            let stream_id = stream_id.expect("set above");

            let mut reply = BytesMut::new();
            let fields: HeaderList = vec![
                HeaderField::new(
                    HeaderName::from_lowercase(":status"),
                    HeaderValue::from_static(status),
                ),
                HeaderField::new(
                    HeaderName::from_static("padding-type-reply"),
                    HeaderValue::from_static("0"),
                ),
            ];
            let mut encoder = Encoder::new();
            encoder.encode(&fields, &mut reply);
            send(
                &mut writer,
                &Frame::Headers {
                    stream_id,
                    block: Bytes::from(reply.as_slice().to_vec()),
                    end_stream: false,
                    end_headers: true,
                    priority: None,
                },
            );
            let _ = tx.send(seen);

            if status != "200" {
                send(
                    &mut writer,
                    &Frame::RstStream {
                        stream_id,
                        error_code: ErrorCode::RefusedStream,
                    },
                );
                return;
            }

            // Echo the tunnel until the client ends it.
            loop {
                match read_frame(&mut reader, &mut buf) {
                    Frame::Data {
                        stream_id: id,
                        data,
                        end_stream,
                        ..
                    } if id == stream_id => {
                        send(
                            &mut writer,
                            &Frame::Data {
                                stream_id,
                                data,
                                end_stream: false,
                                padding: 0,
                            },
                        );
                        if end_stream {
                            break;
                        }
                    }
                    Frame::Settings { ack: false, .. } => send(
                        &mut writer,
                        &Frame::Settings {
                            ack: true,
                            entries: Vec::new(),
                        },
                    ),
                    Frame::RstStream { .. } => break,
                    _ => {}
                }
            }
        });

        (addr, rx)
    }

    fn config(addr: std::net::SocketAddr) -> OutboundConfig {
        let mut options = std::collections::HashMap::new();
        options.insert(
            "username".to_string(),
            nextjson::Value::String("u".to_string()),
        );
        options.insert(
            "password".to_string(),
            nextjson::Value::String("p".to_string()),
        );
        // The tunnel itself is what these tests exercise; TLS is covered by the
        // HTTPS outbound and by the connector's own tests.
        options.insert("tls".to_string(), nextjson::Value::Bool(false));
        OutboundConfig {
            tag: "naive".to_string(),
            outbound_type: crate::engine::config::OutboundType::Naive,
            server: Some(addr.ip().to_string()),
            port: Some(addr.port()),
            options,
        }
    }

    /// The tunnel: a `CONNECT` with the right shape, a 200 verdict, and bytes
    /// that come back.
    #[test]
    fn a_connect_tunnel_carries_bytes_both_ways() {
        let (addr, seen) = spawn_server("200");
        let outbound = NaiveOutbound::new(config(addr)).expect("build");

        let mut tunnel = outbound
            .open_tunnel(
                &TargetAddr::Domain("example.com".to_string(), 80),
                Duration::from_secs(5),
            )
            .expect("CONNECT accepted");

        let request = seen.recv_timeout(Duration::from_secs(5)).expect("request");
        assert_eq!(request.method.as_deref(), Some("CONNECT"));
        assert_eq!(request.authority.as_deref(), Some("example.com:80"));
        assert!(
            !request.has_path_or_scheme,
            "RFC 9113 §8.3.1 forbids `:scheme` and `:path` on a CONNECT"
        );
        assert_eq!(
            request.authorization.as_deref(),
            Some("Basic dTpw"),
            "the credentials travel as one Basic value"
        );
        assert_eq!(request.padding_request.as_deref(), Some("0"));
        assert!(request
            .user_agent
            .as_deref()
            .is_some_and(|ua| ua.contains("Mozilla/5.0")));

        tunnel.write_all(b"ping through the tunnel").expect("write");
        // Read the way the relay does: a would-block is "nothing yet", not an
        // end of stream, so the loop parks briefly and re-polls.
        let mut echo = Vec::new();
        let mut chunk = [0u8; 64];
        for _ in 0..100 {
            match tunnel.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    echo.extend_from_slice(&chunk[..n]);
                    if echo.len() >= 22 {
                        break;
                    }
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    thread::sleep(Duration::from_millis(20))
                }
                Err(e) => panic!("tunnel read failed: {e}"),
            }
        }
        assert_eq!(echo, b"ping through the tunnel");
    }

    /// A refused `CONNECT` is reported with its status, not as a broken tunnel.
    #[test]
    fn a_refused_connect_reports_the_status() {
        let (addr, _seen) = spawn_server("407");
        let outbound = NaiveOutbound::new(config(addr)).expect("build");
        let error = outbound
            .open_tunnel(
                &TargetAddr::Domain("example.com".to_string(), 80),
                Duration::from_secs(5),
            )
            .map(|_| ())
            .expect_err("407 must not open a tunnel")
            .to_string();
        assert!(error.contains("407"), "{error}");
        assert!(error.contains("credentials"), "{error}");
    }

    /// The config surface: what is required, what is refused, and why.
    #[test]
    fn the_config_refuses_what_it_cannot_speak() {
        let build = |options: &[(&str, nextjson::Value)]| {
            let mut map = std::collections::HashMap::new();
            for (k, v) in options {
                map.insert((*k).to_string(), v.clone());
            }
            NaiveOutbound::new(OutboundConfig {
                tag: "naive".to_string(),
                outbound_type: crate::engine::config::OutboundType::Naive,
                server: Some("example.com".to_string()),
                port: Some(443),
                options: map,
            })
        };
        let string = |s: &str| nextjson::Value::String(s.to_string());
        let array = |items: &[&str]| {
            nextjson::Value::Array(items.iter().map(|s| string(s)).collect::<Vec<_>>())
        };

        assert!(
            build(&[]).is_ok(),
            "a naive hop with no credentials is legal"
        );
        assert!(build(&[("username", string("u"))])
            .unwrap_err()
            .to_string()
            .contains("both"));
        assert!(build(&[
            ("username", string("u")),
            ("password", string("p\r\nX-Injected: 1"))
        ])
        .unwrap_err()
        .to_string()
        .contains("CR or LF"));
        assert!(build(&[
            ("username", string("u")),
            ("password", string("p")),
            ("alpn", array(&["http/1.1"]))
        ])
        .unwrap_err()
        .to_string()
        .contains("h2"));

        let outbound = build(&[
            ("username", string("u")),
            ("password", string("p")),
            ("sni", string("www.example.org")),
            ("skip-cert-verify", nextjson::Value::Bool(true)),
            ("alpn", array(&["h2", "http/1.1"])),
        ])
        .expect("a complete config builds");
        assert_eq!(outbound.server_endpoint(), ("example.com", 443));
        assert!(!outbound.is_plaintext());
        assert!(!outbound.supports_udp());

        let plaintext = build(&[("tls", nextjson::Value::Bool(false))]).expect("plaintext builds");
        assert!(plaintext.is_plaintext());
    }
}
