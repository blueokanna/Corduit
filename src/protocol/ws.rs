//! WebSocket (RFC 6455) transport over any [`SyncStream`], on the session
//! state machine from [`courierust::courierust_ws`].
//!
//! One implementation serves both directions of the engine:
//!
//! * **client** — [`WebSocket::connect`] performs the opening handshake
//!   (RFC 6455 §4.1) over an already-established stream and then drives a
//!   masking client session. This is the VMess `ws` / `tls+ws` transport;
//! * **server** — [`WebSocket::accepted`] wraps a stream whose HTTP
//!   upgrade has already been answered (the RPC server's connection
//!   thread does that with the H/1 codec).
//!
//! Framing, masking, fragmentation, UTF-8 validation, the close handshake
//! and the per-connection limits all come from `courierust_ws`; this
//! module only adapts it to the engine's synchronous [`SyncStream`] surface:
//!
//! * [`Read`] yields the payload of the next data message (text or binary,
//!   control frames handled transparently);
//! * [`Write`] sends one binary message per call — a proxy tunnel carries
//!   opaque bytes, which is exactly what a binary frame is for;
//! * [`send_text`](WebSocket::send_text) / [`read_message`](WebSocket::read_message)
//!   are the message-level API the JSON-RPC server uses.
//!
//! Idle reads surface as `WouldBlock`/`TimedOut`, so the relay's poll
//! cadence (see [`RELAY_READ_POLL`](crate::common::stream::RELAY_READ_POLL))
//! applies unchanged: a stalled read always releases the stream within one
//! poll interval.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use courierust::courierust_error::ErrorKind as CourierKind;
use courierust::courierust_io::{BufReader, Read as CRead, Write as CWrite};
use courierust::courierust_ws::handshake::{accept_key, generate_key, is_token};
use courierust::courierust_ws::{
    Event, FrameWriter, MaskSource, Role, Session, SessionConfig, StreamSink,
};

use crate::common::stream::{shutdown_lenient, SyncStream};

/// Largest single frame / message accepted from the peer (16 MiB). The
/// wire length field is 64-bit, so an unbounded value would let a peer
/// request an arbitrary allocation.
pub const MAX_MESSAGE: usize = 16 * 1024 * 1024;

/// Read buffer the session keeps in front of the transport.
const READ_BUFFER: usize = 16 * 1024;

/// Upper bound on the opening handshake response (headers only).
const MAX_HANDSHAKE_RESPONSE: usize = 16 * 1024;

/// Budget for the opening handshake, armed as a socket read/write timeout
/// so a peer that accepts the connection and then goes silent cannot park
/// the dialing worker forever.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// One message received from the peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// A complete UTF-8 text message.
    Text(String),
    /// A complete binary message.
    Binary(Vec<u8>),
    /// The peer's closing frame (our reply has already been sent).
    Close,
}

/// The two halves of the session share one transport: the reader must hold
/// the socket while the writer masks and sends into it.
struct SharedIo<S: SyncStream> {
    stream: Arc<Mutex<S>>,
}

impl<S: SyncStream> SharedIo<S> {
    fn with_locked<R>(&self, f: impl FnOnce(&mut S) -> io::Result<R>) -> io::Result<R> {
        let mut guard = self
            .stream
            .lock()
            .map_err(|_| io::Error::other("websocket: transport lock poisoned"))?;
        f(&mut guard)
    }
}

impl<S: SyncStream> CRead for SharedIo<S> {
    fn read(&mut self, buf: &mut [u8]) -> courierust::Result<usize> {
        self.with_locked(|stream| Read::read(stream, buf))
            .map_err(transport_error)
    }
}

impl<S: SyncStream> CWrite for SharedIo<S> {
    fn write(&mut self, buf: &[u8]) -> courierust::Result<usize> {
        self.with_locked(|stream| Write::write(stream, buf))
            .map_err(transport_error)
    }

    fn flush(&mut self) -> courierust::Result<()> {
        self.with_locked(|stream| Write::flush(stream))
            .map_err(transport_error)
    }
}

/// Translate a transport error into courierust's error space, keeping the
/// kinds the session distinguishes (idle vs. dead peer).
fn transport_error(e: io::Error) -> courierust::Error {
    let kind = match e.kind() {
        io::ErrorKind::WouldBlock => CourierKind::WouldBlock,
        io::ErrorKind::TimedOut => CourierKind::Timeout,
        io::ErrorKind::UnexpectedEof => CourierKind::UnexpectedEof,
        _ => CourierKind::Io,
    };
    courierust::Error::with_message(kind, e.to_string())
}

/// A synchronous WebSocket connection over `S`.
///
/// The session is guarded by a mutex because [`SyncStream::shutdown`]
/// takes `&self` (the relay may half-close from the direction that reached
/// EOF while the other thread is between reads). Every lock is held for
/// one bounded operation at most.
pub struct WebSocket<S: SyncStream> {
    stream: Arc<Mutex<S>>,
    session: Mutex<Session<SharedIo<S>, StreamSink<SharedIo<S>>>>,
    /// Payload bytes of the current message not yet handed to the caller.
    pending: Vec<u8>,
    pending_pos: usize,
    close_sent: AtomicBool,
}

impl<S: SyncStream> WebSocket<S> {
    /// Perform the client opening handshake over `stream`.
    ///
    /// `host` is the `Host` header value (the proxy server name, or the
    /// configured `ws-opts.host`), `path` the request target. `headers`
    /// are extra request headers from the outbound configuration; they are
    /// validated (token name, no CR/LF in the value) and may not override
    /// the handshake's own headers.
    pub fn connect(
        mut stream: S,
        host: &str,
        path: &str,
        headers: &HashMap<String, String>,
    ) -> io::Result<Self> {
        validate_host(host)?;
        validate_path(path)?;

        if stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).is_err()
            || stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT)).is_err()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "websocket: the transport cannot arm a handshake timeout",
            ));
        }

        let key = generate_key()
            .map_err(|e| io::Error::other(format!("websocket: no entropy for the key: {e}")))?;
        let mut request = String::with_capacity(256);
        request.push_str("GET ");
        request.push_str(path);
        request.push_str(" HTTP/1.1\r\nHost: ");
        request.push_str(host);
        request.push_str("\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ");
        request.push_str(&key);
        request.push_str("\r\nSec-WebSocket-Version: 13\r\n");
        for (name, value) in headers {
            if name.eq_ignore_ascii_case("host")
                || name.eq_ignore_ascii_case("upgrade")
                || name.eq_ignore_ascii_case("connection")
                || name.eq_ignore_ascii_case("sec-websocket-key")
                || name.eq_ignore_ascii_case("sec-websocket-version")
            {
                continue;
            }
            if !is_token(name) || value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("websocket: illegal request header {name:?}"),
                ));
            }
            request.push_str(name);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");

        stream.write_all(request.as_bytes())?;
        stream.flush()?;

        let response = read_handshake_response(&mut stream)?;
        verify_handshake(&response, &key)?;

        Ok(Self::session(stream, Role::Client, MAX_MESSAGE))
    }

    /// Wrap a stream whose HTTP upgrade this process has already answered.
    ///
    /// `max_message` caps one (possibly fragmented) message; the caller
    /// owns the handshake, exactly as the RPC server's HTTP layer does.
    pub fn accepted(stream: S, max_message: usize) -> Self {
        Self::session(stream, Role::Server, max_message)
    }

    fn session(stream: S, role: Role, max_message: usize) -> Self {
        let stream = Arc::new(Mutex::new(stream));
        let reader = SharedIo {
            stream: stream.clone(),
        };
        let writer = SharedIo {
            stream: stream.clone(),
        };
        let mask = match role {
            Role::Client => MaskSource::Random,
            Role::Server => MaskSource::None,
        };
        let config = SessionConfig {
            role,
            max_frame: max_message,
            max_message,
            max_fragments: 0,
            compression: None,
            auto_pong: true,
        };
        let session = Session::new(
            BufReader::new(reader, READ_BUFFER),
            FrameWriter::new(StreamSink::new(writer), mask, None),
            config,
        );
        Self {
            stream,
            session: Mutex::new(session),
            pending: Vec::new(),
            pending_pos: 0,
            close_sent: AtomicBool::new(false),
        }
    }

    /// Receive the next complete data message, or [`Message::Close`] once
    /// the peer starts the closing handshake.
    ///
    /// Returns `WouldBlock`/`TimedOut` when the transport produced no
    /// complete message within its read timeout; all partial state is
    /// retained, so the next call resumes exactly where this one stopped.
    pub fn read_message(&mut self) -> io::Result<Message> {
        loop {
            let event = {
                let mut session = self
                    .session
                    .lock()
                    .map_err(|_| io::Error::other("websocket: session lock poisoned"))?;
                match session.poll_message() {
                    Ok(Some(event)) => {
                        // A Ping was answered and a Close echoed by the
                        // session; make sure those control frames left.
                        if !matches!(event, Event::Text(_) | Event::Binary(_)) {
                            let _ = session.flush();
                        }
                        Some(event)
                    }
                    Ok(None) => None,
                    Err(e) => return Err(session_error(e)),
                }
            };
            match event {
                Some(Event::Text(text)) => return Ok(Message::Text(text)),
                Some(Event::Binary(bytes)) => return Ok(Message::Binary(bytes.to_vec())),
                Some(Event::Ping(_)) | Some(Event::Pong(_)) => continue,
                Some(Event::Close(_)) => return Ok(Message::Close),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "websocket: no complete message yet",
                    ))
                }
            }
        }
    }

    /// Send one text message.
    pub fn send_text(&mut self, text: &str) -> io::Result<()> {
        self.session_mut(|session| session.send_text(text))
    }

    /// Send one binary message.
    pub fn send_binary(&mut self, data: &[u8]) -> io::Result<()> {
        self.session_mut(|session| session.send_binary(data))
    }

    /// Send a Ping (the peer answers with a Pong carrying the same payload).
    pub fn send_ping(&mut self, payload: &[u8]) -> io::Result<()> {
        self.session_mut(|session| session.send_ping(payload))
    }

    /// Start the closing handshake with code 1000. Idempotent.
    pub fn close(&mut self) -> io::Result<()> {
        if self.close_sent.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.session_mut(|session| session.close(1000, ""))
    }

    fn session_mut<R>(
        &mut self,
        f: impl FnOnce(&mut Session<SharedIo<S>, StreamSink<SharedIo<S>>>) -> courierust::Result<R>,
    ) -> io::Result<R> {
        let mut session = self
            .session
            .lock()
            .map_err(|_| io::Error::other("websocket: session lock poisoned"))?;
        let out = f(&mut session).map_err(session_error)?;
        session.flush().map_err(session_error)?;
        Ok(out)
    }
}

impl<S: SyncStream> Read for WebSocket<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.pending_pos < self.pending.len() {
                let n = (self.pending.len() - self.pending_pos).min(buf.len());
                buf[..n].copy_from_slice(&self.pending[self.pending_pos..self.pending_pos + n]);
                self.pending_pos += n;
                if self.pending_pos == self.pending.len() {
                    self.pending.clear();
                    self.pending_pos = 0;
                }
                return Ok(n);
            }
            match self.read_message() {
                Ok(Message::Binary(data)) => {
                    if data.is_empty() {
                        continue;
                    }
                    self.pending = data;
                }
                Ok(Message::Text(text)) => {
                    if text.is_empty() {
                        continue;
                    }
                    self.pending = text.into_bytes();
                }
                Ok(Message::Close) => return Ok(0),
                // A peer that vanished without a closing handshake is
                // end-of-stream, not a transport failure: the relay
                // finishes this direction and half-closes the other side.
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                Err(e) => return Err(e),
            }
        }
    }
}

impl<S: SyncStream> Write for WebSocket<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.send_binary(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.session_mut(|session| session.flush())
    }
}

impl<S: SyncStream> SyncStream for WebSocket<S> {
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        if matches!(how, Shutdown::Write | Shutdown::Both)
            && !self.close_sent.swap(true, Ordering::AcqRel)
        {
            if let Ok(mut session) = self.session.lock() {
                let _ = session.close(1000, "");
                let _ = session.flush();
            }
        }
        if matches!(how, Shutdown::Read) {
            return self.with_stream(|stream| shutdown_lenient(stream, Shutdown::Read));
        }
        if matches!(how, Shutdown::Both) {
            return self.with_stream(|stream| shutdown_lenient(stream, Shutdown::Both));
        }
        Ok(())
    }

    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.stream.lock().ok().and_then(|s| s.peer_addr())
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.with_stream(|stream| stream.set_read_timeout(timeout))
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.with_stream(|stream| stream.set_write_timeout(timeout))
    }
}

impl<S: SyncStream> WebSocket<S> {
    fn with_stream<R>(&self, f: impl FnOnce(&mut S) -> io::Result<R>) -> io::Result<R> {
        let mut guard = self
            .stream
            .lock()
            .map_err(|_| io::Error::other("websocket: transport lock poisoned"))?;
        f(&mut guard)
    }
}

/// Map a session error onto the engine's `io` error space.
fn session_error(e: courierust::Error) -> io::Error {
    let kind = match e.kind {
        CourierKind::WouldBlock => io::ErrorKind::WouldBlock,
        CourierKind::Timeout => io::ErrorKind::TimedOut,
        CourierKind::UnexpectedEof => return io::Error::new(io::ErrorKind::UnexpectedEof, ""),
        CourierKind::Protocol | CourierKind::InvalidHeader | CourierKind::Overflow => {
            io::ErrorKind::InvalidData
        }
        CourierKind::Canceled => io::ErrorKind::Interrupted,
        CourierKind::Io | CourierKind::Other => io::ErrorKind::Other,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, e.to_string())
}

/// Validate the `Host` header value.
fn validate_host(host: &str) -> io::Result<()> {
    if host.is_empty() || host.bytes().any(|b| b <= b' ' || b == b'\x7f') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "websocket: illegal Host value",
        ));
    }
    Ok(())
}

/// Validate the request target.
fn validate_path(path: &str) -> io::Result<()> {
    if !path.starts_with('/') || path.bytes().any(|b| b <= b' ' || b == b'\x7f') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "websocket: the request path must start with '/' and hold no control byte",
        ));
    }
    Ok(())
}

/// Read the handshake response head, up to and including the terminating
/// empty line. Byte-at-a-time, so no frame byte that follows the headers in
/// the same segment is ever consumed.
fn read_handshake_response<S: SyncStream>(stream: &mut S) -> io::Result<Vec<u8>> {
    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while head.len() < MAX_HANDSHAKE_RESPONSE {
        match stream.read(&mut byte) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "websocket: the peer closed during the handshake",
                ))
            }
            Ok(_) => {
                head.push(byte[0]);
                if head.len() >= 4 && head[head.len() - 4..] == *b"\r\n\r\n" {
                    return Ok(head);
                }
            }
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "websocket: handshake response too large",
    ))
}

/// Validate the status line and the `Sec-WebSocket-Accept` value
/// (RFC 6455 §4.1: any mismatch must fail the connection).
fn verify_handshake(response: &[u8], key: &str) -> io::Result<()> {
    let text = std::str::from_utf8(response).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "websocket: the handshake response is not UTF-8",
        )
    })?;
    let mut lines = text.split("\r\n");
    let status = lines.next().unwrap_or_default();
    if status.split_whitespace().nth(1) != Some("101") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("websocket: the peer refused the upgrade: {status}"),
        ));
    }

    let expected = accept_key(key).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("websocket: cannot derive the accept value: {e}"),
        )
    })?;
    let mut upgrade_ok = false;
    let mut connection_ok = false;
    let mut accept_ok = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("upgrade") {
            upgrade_ok = value.eq_ignore_ascii_case("websocket");
        } else if name.eq_ignore_ascii_case("connection") {
            connection_ok = value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
        } else if name.eq_ignore_ascii_case("sec-websocket-accept") {
            accept_ok = value == expected;
        }
    }
    if !upgrade_ok || !connection_ok || !accept_ok {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "websocket: the handshake response does not match the request",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader as StdBufReader};
    use std::net::{TcpListener, TcpStream};

    /// Answer the opening handshake with the codec's own primitives, then
    /// echo every text message back.
    fn run_echo_server(listener: TcpListener) {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = StdBufReader::new(stream.try_clone().unwrap());
        let mut key = String::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("sec-websocket-key") {
                    key = value.trim().to_string();
                }
            }
        }
        let accept = accept_key(&key).unwrap();
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        Write::write_all(&mut &stream, response.as_bytes()).unwrap();

        let mut ws = WebSocket::accepted(stream, MAX_MESSAGE);
        loop {
            match ws.read_message() {
                Ok(Message::Text(text)) => {
                    let reply = format!("echo:{text}");
                    if ws.send_text(&reply).is_err() {
                        return;
                    }
                }
                Ok(Message::Binary(data)) => {
                    if ws.send_binary(&data).is_err() {
                        return;
                    }
                }
                Ok(Message::Close) => {
                    let _ = ws.close();
                    return;
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue
                }
                Err(_) => return,
            }
        }
    }

    fn echo_pair() -> (WebSocket<TcpStream>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || run_echo_server(listener));
        let client = WebSocket::connect(
            TcpStream::connect(addr).unwrap(),
            "localhost",
            "/ws",
            &HashMap::new(),
        )
        .unwrap();
        (client, server)
    }

    /// Read until `expected` bytes arrived, tolerating idle polls.
    fn read_expected(ws: &mut WebSocket<TcpStream>, expected: &[u8]) -> Vec<u8> {
        let mut total = Vec::new();
        for _ in 0..200 {
            if total.len() >= expected.len() {
                break;
            }
            let mut buf = [0u8; 64];
            match ws.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => total.extend_from_slice(&buf[..n]),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue
                }
                Err(e) => panic!("read failed: {e}"),
            }
        }
        total
    }

    #[test]
    fn client_handshake_and_text_roundtrip() {
        let (mut client, server) = echo_pair();
        client
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        client.send_text("hello").unwrap();
        assert_eq!(read_expected(&mut client, b"echo:hello"), b"echo:hello");
        client.close().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn binary_write_is_one_masked_binary_frame() {
        let (mut client, server) = echo_pair();
        client
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        client.write_all(b"\x00\x01\x02 opaque").unwrap();
        client.flush().unwrap();
        assert_eq!(
            read_expected(&mut client, b"\x00\x01\x02 opaque"),
            b"\x00\x01\x02 opaque"
        );
        client.close().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn handshake_requires_the_matching_accept_value() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                head.push(byte[0]);
            }
            // Correct shape, wrong accept value.
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                      Connection: Upgrade\r\nSec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n",
                )
                .unwrap();
        });
        let err = WebSocket::connect(
            TcpStream::connect(addr).unwrap(),
            "localhost",
            "/ws",
            &HashMap::new(),
        )
        .err()
        .expect("a wrong accept value must fail the handshake");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        server.join().unwrap();
    }

    #[test]
    fn status_other_than_101_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                head.push(byte[0]);
            }
            stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });
        let err = WebSocket::connect(
            TcpStream::connect(addr).unwrap(),
            "localhost",
            "/ws",
            &HashMap::new(),
        )
        .err()
        .expect("a non-101 status must fail the handshake");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        server.join().unwrap();
    }

    #[test]
    fn illegal_request_headers_are_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut headers = HashMap::new();
        headers.insert("X-Evil".to_string(), "a\r\nInjected: 1".to_string());
        let err = WebSocket::connect(
            TcpStream::connect(addr).unwrap(),
            "localhost",
            "/ws",
            &headers,
        )
        .err()
        .expect("CRLF in a header value must be refused before any byte is sent");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn illegal_path_is_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let err = WebSocket::connect(
            TcpStream::connect(addr).unwrap(),
            "localhost",
            "no-leading-slash",
            &HashMap::new(),
        )
        .err()
        .expect("a path without a leading slash must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
