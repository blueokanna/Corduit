//! Bounded HTTP/1.1 connection driver for the control-plane servers.
//!
//! The engine's proxy inbounds run on [`courierust_server::serve_connection`],
//! which is the right call for them: tunneled traffic is long-lived by
//! definition and its framing policy belongs to the server. The control plane
//! is the opposite kind of workload — 64 connection slots are its entire
//! budget, a request is a few hundred bytes, and there is no legitimate reason
//! for one to take minutes — yet the blocking `serve_connection` path bounds a
//! request only by a *per-read* socket timeout. A peer that sends one byte per
//! timeout therefore holds a slot forever: the classic slowloris, with the
//! request-head phase (which a normal client finishes instantly) as the
//! cheapest attack surface.
//!
//! This module is the fix, and only the fix. Every protocol primitive is
//! public and reused unchanged, so this is a driver — timing and framing
//! policy — and never a second HTTP implementation:
//!
//! * the codec is [`courierust_h1`] (request line, headers, body framing,
//!   serialization) — the same parser and writer the server uses;
//! * an upgrade is validated by [`courierust_server::ws::plan`], the same
//!   RFC 6455 policy walk (`Upgrade`/`Connection` tokens, version 13, key
//!   shape, origin), and its refusal carries the server's own response;
//! * the WebSocket session is [`crate::protocol::ws::WebSocket`] in its
//!   server role, i.e. the [`courierust_ws`] state machine the engine's own
//!   transports run on.
//!
//! [`serve_connection`]: courierust::courierust_server::serve_connection
//!
//! # Deadlines
//!
//! All bounds live in [`Limits`], are configured per server, and are enforced
//! by [`BoundedIo`], a reader in front of the transport: the deadline is
//! checked at every read the codec performs, so a drip-feeding peer is cut
//! off *mid-line*, not between requests. Concretely:
//!
//! | phase                          | absolute budget        | idle cap between reads |
//! |--------------------------------|------------------------|------------------------|
//! | waiting for the next request   | `idle_timeout`         | `idle_timeout`         |
//! | request head (from 1st byte)   | `head_deadline`        | `head_read_timeout`    |
//! | request body (after the head)  | `body_deadline`        | `body_read_timeout`    |
//! | one response write             | socket write timeout   | —                      |
//!
//! The head clock starts at the head's *first byte*: an idle keep-alive
//! connection is not penalized, a slowly-delivered head is. When a phase
//! expires with bytes already on the wire the client is told (`408`); when it
//! expires with nothing received (an idle keep-alive connection) the socket is
//! simply closed, because there is nothing to report.
//!
//! # Framing and refusals
//!
//! Responses are framed once, here: hop-by-hop fields are dropped, a
//! `content-length` is derived from the materialized body (streaming bodies
//! are out of scope for the control plane and are refused), and `connection`
//! is set from the keep-alive decision — the same rule the blocking server
//! driver applies. A malformed request line, a bad `Host`, an oversized or
//! unparsable body and a head over the codec's caps are answered with
//! `400`/`431`/`413` and the connection closed (after a bounded linger, so the
//! answer survives a peer that is still uploading). At most
//! `max_requests` requests are served per connection.
//!
//! # WebSocket
//!
//! The caller's [`Handler::websocket`] owns the policy *and* the upgrade
//! decision (token check, then `plan` + `WsPlan::accept_headers`); this driver
//! writes the `101`, hands any bytes already read past the head to the session
//! ([`PrefixedStream`] — a client is allowed to pipeline its first frame with
//! the handshake), and then runs the session:
//!
//! * one inbound text/binary message at a time is dispatched to
//!   [`Endpoint::on_message`]; the reply (if any) is sent as one message of
//!   the same kind;
//! * after `ws_ping_interval` of inbound silence a Ping goes out; a peer that
//!   stays silent for twice as long is dropped (`1001`), and a failed reply
//!   closes with `1011` — the close codes the previous driver used;
//! * the peer's closing frame is answered by the session itself (RFC 6455
//!   §5.5.1), after which the driver stops.

use std::cell::Cell;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use courierust::courierust_body::Body;
use courierust::courierust_error::{Error as CourierError, ErrorKind as CourierErrorKind};
use courierust::courierust_h1 as h1;
use courierust::courierust_http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version,
};
use courierust::courierust_io::{BufReader, Read as CourierRead, Scratch};
use courierust::courierust_ws::handshake::is_websocket_upgrade;

use crate::common::stream::{BoxStream, PrefixedStream};
use crate::protocol::ws::{Message, WebSocket};

/// Read buffer in front of the transport. Sized like the server driver's:
/// one syscall per request (a head is a few hundred bytes).
const READ_BUFFER: usize = 16 * 1024;

/// Longest request line accepted. The same bound courierust's own blocking
/// H/1 loop passes; the header block itself is capped by the codec (64 KiB
/// per line, 1 MiB per block, 1024 fields).
const MAX_REQUEST_LINE: usize = 16 * 1024;

/// How long a refusal lingers before the socket closes. Long enough for the
/// answer to be read by a peer that is mid-upload, short enough that it
/// cannot be used to sit on a connection slot.
const LINGER: Duration = Duration::from_millis(250);

/// The smallest socket timeout we will arm, so a deadline that is
/// microseconds away does not turn into a zero timeout (invalid on some
/// platforms).
const MIN_WAIT: Duration = Duration::from_millis(1);

/// The per-connection budgets of one control-plane server.
///
/// The absolute budgets are deliberately generous for a real client (a head
/// in 30 s, 16 MiB of body in 5 min, a keep-alive socket that may sit idle
/// for 10 min) and fatal for the drip-feed pattern the per-read timeouts
/// cannot catch.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Largest request body accepted (the codec enforces it too).
    pub max_body: usize,
    /// Requests served on one connection before it is closed.
    pub max_requests: usize,
    /// How long a keep-alive connection may wait for its next request.
    pub idle_timeout: Duration,
    /// Absolute budget for a request head, from its first byte.
    pub head_deadline: Duration,
    /// Longest single read may idle inside a request head.
    pub head_read_timeout: Duration,
    /// Absolute budget for a declared request body, from the end of the head.
    pub body_deadline: Duration,
    /// Longest single read may idle inside a request body.
    pub body_read_timeout: Duration,
    /// Socket write timeout: one non-reading peer cannot pin the thread.
    pub write_timeout: Duration,
    /// WebSocket budgets; `None` forbids upgrades (any `Accept` is a bug).
    pub ws: Option<WsLimits>,
}

/// WebSocket budgets of one server.
#[derive(Clone, Copy, Debug)]
pub struct WsLimits {
    /// Largest accepted message (framing caps come from the session).
    pub max_message: usize,
    /// Ping after this much inbound silence; drop at twice this.
    pub ping_interval: Duration,
}

/// One WebSocket message, text or binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// A UTF-8 text message.
    Text(String),
    /// A binary message.
    Binary(Vec<u8>),
}

/// The application side of an accepted WebSocket connection.
///
/// One call per inbound data message, on the connection's own thread, so a
/// blocking call delays only this connection.
pub trait Endpoint: Send + Sync + 'static {
    /// Handle one message; `Some` reply is sent back as one message of the
    /// same kind (`None` sends nothing).
    fn on_message(&self, message: Payload) -> Option<Payload>;
}

/// The handler's answer to a syntactically valid RFC 6455 upgrade.
pub enum Upgrade {
    /// Not an upgrade for this handler: fall through to [`Handler::handle`].
    Pass,
    /// Refuse with this response (written like any other, then the
    /// connection closes).
    Refuse(Response<Body>),
    /// Accept: the driver writes `101` with these headers and drives the
    /// session with `endpoint`.
    Accept {
        /// The `101` head, from the server's upgrade policy.
        headers: HeaderMap,
        /// The application side of the session.
        endpoint: Arc<dyn Endpoint>,
    },
}

/// One control-plane server's request logic.
pub trait Handler: Send + Sync + 'static {
    /// Answer one request. The body has been fully read by the time this
    /// runs, including chunked bodies.
    fn handle(&self, req: Request<Body>) -> Response<Body>;

    /// Decide an upgrade request (RFC 6455). Called only when the request
    /// carries a syntactically valid upgrade; the default passes it to
    /// [`Handler::handle`] unchanged.
    fn websocket(&self, _req: &Request<Body>, _peer: SocketAddr) -> Upgrade {
        Upgrade::Pass
    }
}

/// Serve one accepted connection to completion.
///
/// Returns when the connection is done (clean close, refusal, upgrade
/// session, or any transport failure); errors are the transport's and are
/// logged by the caller.
pub fn serve(
    stream: TcpStream,
    peer: SocketAddr,
    handler: &dyn Handler,
    limits: &Limits,
) -> io::Result<()> {
    // Control plane: small messages, interactive latency, so Nagle would
    // only add delay. Writes are bounded so a stalled reader cannot park
    // the connection thread.
    let _ = stream.set_nodelay(true);
    stream.set_write_timeout(Some(limits.write_timeout))?;

    let state = BoundState::default();
    let mut reader = BufReader::new(
        BoundedIo {
            stream: &stream,
            state: &state,
        },
        READ_BUFFER,
    );
    let mut scratch = Scratch::new();
    let mut served = 0usize;

    loop {
        // Waiting for the next request: the whole wait is the idle timeout.
        // Bytes already in the buffer mean the client pipelined its request,
        // so the head clock starts now instead of on the next syscall.
        let mark = state.bytes();
        state.enter_idle(limits);
        if reader.buffered() > 0 {
            state.enter_head(limits);
        }

        let line = scratch.line();
        match reader.read_until_into(b'\n', MAX_REQUEST_LINE, line) {
            Ok(()) => {}
            // A peer that left between responses is normal keep-alive
            // behaviour, not an error.
            Err(e) if e.kind == CourierErrorKind::UnexpectedEof => return Ok(()),
            Err(e) if e.kind == CourierErrorKind::Timeout => {
                if state.bytes() != mark {
                    // Mid-head: the absolute deadline (not the per-read
                    // timeout) just fired on a client that is dribbling.
                    write_refusal(&stream, StatusCode::REQUEST_TIMEOUT, "request timeout")?;
                    linger(&stream);
                }
                return Ok(());
            }
            Err(e) => {
                refuse(&stream, &e)?;
                return Ok(());
            }
        }
        let request_line = match h1::parse_request_line(line) {
            Ok(request_line) => request_line,
            Err(e) => {
                refuse(&stream, &e)?;
                return Ok(());
            }
        };
        let headers = match h1::read_headers_scratch(&mut reader, &mut scratch) {
            Ok(headers) => headers,
            Err(e) => {
                refuse(&stream, &e)?;
                return Ok(());
            }
        };
        if let Some(reason) = h1::host_header_error(request_line.version, &headers) {
            write_refusal(&stream, StatusCode::BAD_REQUEST, reason)?;
            linger(&stream);
            return Ok(());
        }
        let framed = match h1::body_length(&headers, Some(&request_line.method), None) {
            Ok(framed) => framed,
            Err(e) => {
                refuse(&stream, &e)?;
                return Ok(());
            }
        };
        // An oversized declared body is answered before a byte of it is
        // read: the client is told, not drained.
        if let h1::BodyLen::Length(len) = framed {
            if len > limits.max_body {
                write_refusal(
                    &stream,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body too large",
                )?;
                linger(&stream);
                return Ok(());
            }
        }

        state.enter_body(limits);
        let body = match framed {
            h1::BodyLen::None => Body::Empty,
            h1::BodyLen::Length(len) => {
                match h1::read_body_fixed_scratch(&mut reader, len, limits.max_body, &mut scratch) {
                    Ok(body) => Body::Bytes(body),
                    Err(e) if is_disconnect(&e) => return Ok(()),
                    Err(e) => {
                        refuse(&stream, &e)?;
                        return Ok(());
                    }
                }
            }
            h1::BodyLen::Chunked => {
                match h1::read_body_chunked_scratch(&mut reader, limits.max_body, &mut scratch) {
                    Ok(body) => Body::Bytes(body),
                    Err(e) if is_disconnect(&e) => return Ok(()),
                    Err(e) => {
                        refuse(&stream, &e)?;
                        return Ok(());
                    }
                }
            }
        };

        let request_close = h1::wants_close(&headers);
        let method = request_line.method.clone();
        let req = Request {
            method: request_line.method,
            uri: request_line.target,
            version: request_line.version,
            headers,
            body,
        };

        if is_websocket_upgrade(&req.headers) {
            match handler.websocket(&req, peer) {
                Upgrade::Pass => {}
                Upgrade::Refuse(resp) => {
                    // A refused upgrade is an ordinary response: whether the
                    // connection survives is decided like any other, so a
                    // refusal that names `close` (the upgrade policy's own
                    // refusals do) ends it and a bare `401` does not.
                    served += 1;
                    let keep_alive = !request_close
                        && h1::keep_alive_requested(resp.version, &resp.headers)
                        && resp.version != Version::HTTP_10
                        && served < limits.max_requests;
                    write_response(&stream, &resp, keep_alive, false)?;
                    if keep_alive {
                        continue;
                    }
                    linger_if_buffered(&stream, &mut reader);
                    return Ok(());
                }
                Upgrade::Accept { headers, endpoint } => {
                    let Some(ws) = limits.ws else {
                        // A handler accepted an upgrade a server without
                        // WebSocket budgets cannot drive: a wiring bug, so
                        // fail closed instead of inventing limits.
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "websocket upgrade accepted but no WebSocket limits are configured",
                        ));
                    };
                    let mut head = Vec::with_capacity(256);
                    h1::write_response_head(
                        &mut head,
                        StatusCode::SWITCHING_PROTOCOLS,
                        Version::HTTP_11,
                        &headers,
                    )
                    .map_err(courier_to_io)?;
                    write_all(&stream, &head)?;
                    // Bytes the head parser already read past the request
                    // (a pipelined first frame) belong to the session.
                    let pending = if reader.buffered() > 0 {
                        reader.fill_buf().map_err(courier_to_io)?.to_vec()
                    } else {
                        Vec::new()
                    };
                    drop(reader);
                    return serve_websocket(stream, pending, endpoint.as_ref(), ws);
                }
            }
        }

        let is_head = method == Method::HEAD;
        let resp = handler.handle(req);
        served += 1;
        let keep_alive = !request_close
            && h1::keep_alive_requested(resp.version, &resp.headers)
            && resp.version != Version::HTTP_10
            && served < limits.max_requests;
        write_response(&stream, &resp, keep_alive, is_head)?;
        if !keep_alive {
            linger_if_buffered(&stream, &mut reader);
            return Ok(());
        }
    }
}

/// Drive one accepted WebSocket session until either side closes it.
fn serve_websocket(
    stream: TcpStream,
    pending: Vec<u8>,
    endpoint: &dyn Endpoint,
    limits: WsLimits,
) -> io::Result<()> {
    // Idle reads are how the keepalive notices a silent peer; a read timeout
    // is expected, not an error.
    let poll = limits
        .ping_interval
        .min(Duration::from_secs(1))
        .max(Duration::from_millis(50));
    stream.set_read_timeout(Some(poll))?;

    let transport = PrefixedStream::new(pending, Box::new(stream) as BoxStream);
    let mut ws = WebSocket::accepted(transport, limits.max_message);
    let mut last_rx = Instant::now();
    let mut ping_sent = false;

    loop {
        match ws.read_message() {
            Ok(Message::Text(text)) => {
                last_rx = Instant::now();
                ping_sent = false;
                if let Some(reply) = endpoint.on_message(Payload::Text(text)) {
                    if send(&mut ws, reply).is_err() {
                        let _ = ws.close_with(1011, "send failed");
                        return Ok(());
                    }
                }
            }
            Ok(Message::Binary(data)) => {
                last_rx = Instant::now();
                ping_sent = false;
                if let Some(reply) = endpoint.on_message(Payload::Binary(data)) {
                    if send(&mut ws, reply).is_err() {
                        let _ = ws.close_with(1011, "send failed");
                        return Ok(());
                    }
                }
            }
            // The peer started the closing handshake; the session has
            // already answered it.
            Ok(Message::Close) => return Ok(()),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                let idle = last_rx.elapsed();
                if idle >= limits.ping_interval * 2 {
                    let _ = ws.close_with(1001, "peer silent");
                    return Ok(());
                }
                if idle >= limits.ping_interval && !ping_sent {
                    if ws.send_ping(b"").is_err() {
                        return Ok(());
                    }
                    ping_sent = true;
                }
            }
            // Transport failure or protocol violation (the session already
            // sent the violating close frame where one applies).
            Err(_) => return Ok(()),
        }
    }
}

/// Send one reply message of the same kind as the request.
fn send(ws: &mut WebSocket<PrefixedStream>, reply: Payload) -> io::Result<()> {
    match reply {
        Payload::Text(text) => ws.send_text(&text),
        Payload::Binary(data) => ws.send_binary(&data),
    }
}

// ---------------------------------------------------------------------------
// The deadline reader
// ---------------------------------------------------------------------------

/// One request phase's budgets.
#[derive(Clone, Copy)]
struct Phase {
    /// Absolute end of the phase.
    deadline: Instant,
    /// Longest a single read may block inside the phase.
    max_gap: Duration,
    /// For the wait-for-the-next-request phase: the pair of budgets that
    /// begins at the head's first byte (see [`BoundState::enter_idle`]).
    head_window: Option<(Duration, Duration)>,
}

/// The mutable state of one connection's reader, shared between the driver
/// (which configures phases) and the [`BoundedIo`] the codec reads through.
///
/// `Cell` rather than atomics: a connection is single-threaded by
/// construction — its own thread runs this loop from first byte to close.
#[derive(Default)]
struct BoundState {
    phase: Cell<Option<Phase>>,
    armed: Cell<Option<Duration>>,
    bytes: Cell<u64>,
}

impl BoundState {
    /// Wait for the next request: an idle keep-alive socket is bounded only
    /// by `idle_timeout`, but the head's own clock (`head_deadline`) starts
    /// at its first byte, because a client that has begun sending must not
    /// be allowed to stretch that moment forever.
    fn enter_idle(&self, limits: &Limits) {
        let now = Instant::now();
        self.phase.set(Some(Phase {
            deadline: now + limits.idle_timeout,
            max_gap: limits.idle_timeout,
            head_window: Some((limits.head_deadline, limits.head_read_timeout)),
        }));
        self.armed.set(None);
    }

    /// A head whose first byte is already in hand (pipelined, or the
    /// automatic switch from [`Self::enter_idle`] just happened).
    fn enter_head(&self, limits: &Limits) {
        let now = Instant::now();
        self.phase.set(Some(Phase {
            deadline: now + limits.head_deadline,
            max_gap: limits.head_read_timeout,
            head_window: None,
        }));
        self.armed.set(None);
    }

    /// A declared body, from the end of the head.
    fn enter_body(&self, limits: &Limits) {
        let now = Instant::now();
        self.phase.set(Some(Phase {
            deadline: now + limits.body_deadline,
            max_gap: limits.body_read_timeout,
            head_window: None,
        }));
        self.armed.set(None);
    }

    /// Total bytes read from the transport on this connection.
    fn bytes(&self) -> u64 {
        self.bytes.get()
    }
}

/// A transport reader that enforces the active phase's deadline.
///
/// The deadline is evaluated on every read, so it bites inside the codec's
/// own loops (`read_until_into`, `read_body_fixed_scratch`, ...): a peer that
/// makes progress strictly below every per-read timeout still runs out of
/// total budget.
struct BoundedIo<'a> {
    stream: &'a TcpStream,
    state: &'a BoundState,
}

impl CourierRead for BoundedIo<'_> {
    fn read(&mut self, buf: &mut [u8]) -> courierust::Result<usize> {
        let now = Instant::now();
        let Some(phase) = self.state.phase.get() else {
            return Err(CourierError::with_message(
                CourierErrorKind::Io,
                "connection reader used outside a request phase",
            ));
        };
        if now >= phase.deadline {
            return Err(deadline_error());
        }
        // Arm the socket for the shorter of the phase's idle cap and the
        // time the phase has left: whichever comes first, the loop regains
        // control in time to answer.
        let wait = phase.max_gap.min(phase.deadline - now).max(MIN_WAIT);
        if self.state.armed.get().map_or(true, |armed| wait < armed) {
            self.stream
                .set_read_timeout(Some(wait))
                .map_err(socket_error)?;
            self.state.armed.set(Some(wait));
        }
        match Read::read(&mut &*self.stream, buf) {
            Ok(0) => Ok(0),
            Ok(n) => {
                self.state.bytes.set(self.state.bytes.get() + n as u64);
                if let Some((window, gap)) =
                    self.state.phase.get().and_then(|phase| phase.head_window)
                {
                    // First byte of a request head: its absolute clock
                    // starts at the moment the byte arrived, not at the
                    // moment the read that found it began to block.
                    let arrived = Instant::now();
                    self.state.phase.set(Some(Phase {
                        deadline: arrived + window,
                        max_gap: gap,
                        head_window: None,
                    }));
                    self.state.armed.set(None);
                }
                Ok(n)
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Err(deadline_error())
            }
            Err(e) => Err(socket_error(e)),
        }
    }
}

fn deadline_error() -> CourierError {
    CourierError::with_message(CourierErrorKind::Timeout, "connection deadline exceeded")
}

fn socket_error(e: io::Error) -> CourierError {
    CourierError::with_message(CourierErrorKind::Io, e.to_string())
}

fn courier_to_io(e: CourierError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

/// Whether a codec error means "the peer is gone or ran out of time" (close
/// quietly) rather than "the peer sent something wrong" (answer first).
fn is_disconnect(e: &CourierError) -> bool {
    matches!(
        e.kind,
        CourierErrorKind::Timeout | CourierErrorKind::UnexpectedEof
    )
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// Frame and write one response, then its body.
///
/// The single framing rule, mirroring the blocking server driver: hop-by-hop
/// fields are dropped, `content-length` comes from the materialized body
/// (nobody may smuggle the framing), and `connection` states the keep-alive
/// decision. Bodies of `HEAD` responses are announced but not written.
fn write_response(
    stream: &TcpStream,
    resp: &Response<Body>,
    keep_alive: bool,
    is_head: bool,
) -> io::Result<()> {
    if resp.body.is_stream() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control-plane responses must have buffered bodies",
        ));
    }
    let mut out = HeaderMap::with_capacity(resp.headers.len() + 3);
    for (name, value) in resp.headers.iter() {
        if h1::is_hop_by_hop(name.as_str()) {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    match resp.body.as_bytes() {
        Some(body) => {
            let length = h1::IToA::new(body.len());
            out.insert(
                HeaderName::from_lowercase("content-length"),
                HeaderValue::from_bytes(length.as_slice()).map_err(courier_to_io)?,
            );
        }
        None if resp.status.is_informational()
            || resp.status == StatusCode::NO_CONTENT
            || resp.status == StatusCode::NOT_MODIFIED => {}
        // An empty body still gets `Content-Length: 0`, so the framing is
        // unambiguous for the peer.
        None => {
            out.insert(
                HeaderName::from_lowercase("content-length"),
                HeaderValue::from_static("0"),
            );
        }
    }
    out.insert(
        HeaderName::from_lowercase("connection"),
        HeaderValue::from_static(if keep_alive { "keep-alive" } else { "close" }),
    );

    let mut head = Vec::with_capacity(512);
    h1::write_response_head(&mut head, resp.status, Version::HTTP_11, &out)
        .map_err(courier_to_io)?;
    write_all(stream, &head)?;
    if !is_head {
        if let Some(body) = resp.body.as_bytes() {
            write_all(stream, body)?;
        }
    }
    Ok(())
}

/// Write a whole buffer through a shared reference.
///
/// `std::io::Write` is implemented for `&TcpStream`, which is what lets the
/// response path write while the reader still holds its shared borrow of the
/// socket; a write timeout bounds the call.
fn write_all(stream: &TcpStream, data: &[u8]) -> io::Result<()> {
    let mut out = stream;
    out.write_all(data)
}

/// Answer a request that could not be parsed (or was refused before a
/// handler saw it), then close.
fn refuse(stream: &TcpStream, error: &CourierError) -> io::Result<()> {
    if let Some(status) = refusal_status(error) {
        let message = match status {
            StatusCode::PAYLOAD_TOO_LARGE => "request body too large",
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE => "request head too large",
            _ => "bad request",
        };
        write_refusal(stream, status, message)?;
        linger(stream);
    }
    Ok(())
}

/// The status a malformed request deserves, or `None` when the failure is
/// not the client's to fix (the connection is simply closed).
fn refusal_status(error: &CourierError) -> Option<StatusCode> {
    match error.kind {
        CourierErrorKind::Protocol => Some(StatusCode::BAD_REQUEST),
        CourierErrorKind::Overflow => {
            let header = error
                .message
                .as_deref()
                .map(|m| m.contains("header") || m.contains("line"))
                .unwrap_or(false);
            Some(if header {
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
            } else {
                StatusCode::PAYLOAD_TOO_LARGE
            })
        }
        _ => None,
    }
}

/// A small, fully-framed plain-text answer (always close).
fn write_refusal(stream: &TcpStream, status: StatusCode, message: &str) -> io::Result<()> {
    let mut resp: Response<Body> = Response::with_status(status);
    resp.headers.insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp.body = Body::from(format!("{message}\n").into_bytes());
    write_response(stream, &resp, false, false)
}

/// Half-close the write side and drain briefly, so a peer that is still
/// uploading sees the answer instead of a reset.
fn linger(stream: &TcpStream) {
    let _ = stream.shutdown(Shutdown::Write);
    let _ = stream.set_read_timeout(Some(LINGER));
    let until = Instant::now() + LINGER;
    let mut sink = [0u8; 4096];
    let mut src = stream;
    while Instant::now() < until {
        match std::io::Read::read(&mut src, &mut sink) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

/// Linger only when the peer has bytes we have not read: those are what turn
/// a close into a reset.
fn linger_if_buffered(stream: &TcpStream, reader: &mut BufReader<BoundedIo<'_>>) {
    if reader.buffered() > 0 {
        linger(stream);
    }
}
