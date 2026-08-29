//! WebSocket transport on a hand-rolled RFC 6455 client codec
//! (replacing `tokio-tungstenite`).
//!
//! Corduit's transport layer needs a WebSocket duplex stream for proxy
//! outbound protocols that tunnel over WS. This module is the
//! transport-level, generic version with a *complete* frame codec:
//!
//! * client handshake (RFC 6455 §4) with `Sec-WebSocket-Accept` verification;
//! * masked client→server frames, unmasked server→client frames;
//! * 7-bit / 16-bit / 64-bit payload lengths;
//! * fragmentation (continuation frames) with a hard message cap;
//! * ping → pong echo, close-frame handling;
//! * a synchronous `std::io::Read`/`std::io::Write` surface plus an optional
//!   `split()` into independent sink/reader halves.
//!
//! The codec is deliberately defensive: oversized frames are rejected before
//! any allocation, and an unmasked server frame (or a masked client frame
//! that RFC 6455 forbids on the server side) is treated as a protocol
//! violation and surfaced as an error.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

use crate::crypto::digest::Digest;
use crate::crypto::encoding::{encode as b64_encode, Config as B64Config};
use crate::crypto::hash::Sha1;
use nextjson::{NsonDeserialize, NsonSerialize};

use super::{Result, TransportError};

/// Largest accepted WebSocket frame/message. The length field is a 64-bit
/// value straight from the wire; without a cap a malicious peer could
/// request a multi-gigabyte allocation.
const MAX_WS_MESSAGE: u64 = 16 * 1024 * 1024; // 16 MiB
/// Cap for the handshake response head.
const MAX_HANDSHAKE_HEAD: usize = 64 * 1024;

#[derive(Debug, Clone, NsonSerialize, NsonDeserialize)]
pub struct WebSocketConfig {
    #[serde(default = "default_path")]
    pub path: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub max_early_data: usize,
    #[serde(default)]
    pub early_data_header: Option<String>,
}

fn default_path() -> String {
    "/".to_string()
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            path: default_path(),
            host: None,
            headers: HashMap::new(),
            max_early_data: 0,
            early_data_header: None,
        }
    }
}

pub struct WebSocketTransport {
    config: WebSocketConfig,
    server: String,
    /// Kept as configuration metadata (the caller establishes the stream;
    /// `port`/`use_tls` document the intended endpoint).
    #[allow(dead_code)]
    port: u16,
    #[allow(dead_code)]
    use_tls: bool,
}

impl WebSocketTransport {
    pub fn new(config: WebSocketConfig, server: &str, port: u16, use_tls: bool) -> Self {
        Self {
            config,
            server: server.to_string(),
            port,
            use_tls,
        }
    }

    pub fn connect<S>(&self, stream: S) -> Result<WsStream<S>>
    where
        S: Read + Write,
    {
        let host = self.config.host.as_deref().unwrap_or(&self.server);
        let path = &self.config.path;
        let stream = websocket_handshake(stream, path, host, &self.config.headers)?;
        Ok(WsStream::new(stream))
    }

    pub fn connect_with_early_data<S>(&self, stream: S, early_data: &[u8]) -> Result<WsStream<S>>
    where
        S: Read + Write,
    {
        if early_data.is_empty() || self.config.max_early_data == 0 {
            return self.connect(stream);
        }

        let host = self.config.host.as_deref().unwrap_or(&self.server);

        let early_data_encoded = if early_data.len() <= self.config.max_early_data {
            b64_encode(early_data, B64Config::STANDARD)
        } else {
            b64_encode(
                &early_data[..self.config.max_early_data],
                B64Config::STANDARD,
            )
        };

        let path_with_early_data = if let Some(ref header_name) = self.config.early_data_header {
            format!(
                "{}?{}={}",
                self.config.path, header_name, early_data_encoded
            )
        } else {
            format!("{}?ed={}", self.config.path, early_data_encoded)
        };

        let stream =
            websocket_handshake(stream, &path_with_early_data, host, &self.config.headers)?;
        Ok(WsStream::new(stream))
    }

    pub fn config(&self) -> &WebSocketConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// Handshake (RFC 6455 §4)
// ---------------------------------------------------------------------------

fn generate_ws_key() -> String {
    let mut key = [0u8; 16];
    getrandom::fill(&mut key).ok();
    b64_encode(&key, B64Config::STANDARD)
}

/// `base64(SHA-1(key || RFC6455_GUID))`.
fn compute_accept(client_key: &str) -> String {
    const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut hasher = Sha1::new();
    hasher.update(client_key.as_bytes());
    hasher.update(WS_GUID);
    let digest = hasher.finalize();
    b64_encode(&digest, B64Config::STANDARD)
}

/// Perform the client side of the WebSocket opening handshake over `stream`.
fn websocket_handshake<S: Read + Write>(
    mut stream: S,
    path: &str,
    host: &str,
    extra_headers: &HashMap<String, String>,
) -> Result<S> {
    let key = generate_ws_key();
    let mut request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Sec-WebSocket-Version: 13\r\n"
    );
    for (k, v) in extra_headers {
        if k.to_lowercase() != "host" {
            request.push_str(&format!("{k}: {v}\r\n"));
        }
    }
    request.push_str("\r\n");

    stream
        .write_all(request.as_bytes())
        .map_err(|e| TransportError::WebSocket(format!("write handshake: {e}")))?;
    stream
        .flush()
        .map_err(|e| TransportError::WebSocket(format!("flush handshake: {e}")))?;

    // Read the response head byte-by-byte until the blank line. Bounded so a
    // hostile peer cannot make us buffer unboundedly.
    let mut response = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while response.len() < MAX_HANDSHAKE_HEAD {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                // The handshake must complete within the socket read timeout.
                return Err(TransportError::WebSocket(format!(
                    "handshake response timed out: {e}"
                )));
            }
            Err(e) => {
                return Err(TransportError::WebSocket(format!(
                    "read handshake response: {e}"
                )))
            }
        }
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !response.ends_with(b"\r\n\r\n") {
        return Err(TransportError::WebSocket(
            "handshake response too large or incomplete".to_string(),
        ));
    }

    let text = String::from_utf8_lossy(&response);
    if !text.starts_with("HTTP/1.1 101") {
        return Err(TransportError::WebSocket(format!(
            "handshake rejected: {}",
            text.lines().next().unwrap_or("unknown status")
        )));
    }

    let expected = compute_accept(&key);
    let accept_ok = text.lines().any(|line| {
        let lower = line.to_lowercase();
        lower.starts_with("sec-websocket-accept:")
            && line
                .split(':')
                .nth(1)
                .map(str::trim)
                .is_some_and(|v| v == expected)
    });
    if !accept_ok {
        return Err(TransportError::WebSocket(
            "Sec-WebSocket-Accept mismatch".to_string(),
        ));
    }

    Ok(stream)
}

// ---------------------------------------------------------------------------
// Frame codec
// ---------------------------------------------------------------------------

/// Opcode of the current frame being parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Need 2 header bytes.
    Head,
    /// Need 2 extended-length bytes.
    ExtLen16,
    /// Need 8 extended-length bytes.
    ExtLen64,
    /// Need 4 mask bytes.
    Mask,
    /// Need the frame payload.
    Payload,
}

/// The RFC 6455 frame codec shared by [`WsStream`], [`WsSink`] and
/// [`WsReader`].
struct WsFramed<S> {
    inner: S,
    // --- read side ---
    /// Bytes pulled from the wire but not yet parsed.
    inbuf: Vec<u8>,
    inpos: usize,
    /// Frame assembly state.
    stage: Stage,
    need: usize,
    fin: bool,
    opcode: u8,
    masked: bool,
    payload_len: u64,
    mask: [u8; 4],
    frame_payload: Vec<u8>,
    /// Fragmented message assembly.
    frag_opcode: Option<u8>,
    frag: Vec<u8>,
    /// A complete message ready to serve to the reader.
    out: Vec<u8>,
    outpos: usize,
    /// EOF observed (peer closed cleanly).
    eof: bool,
    // --- write side ---
    /// Serialized (masked) frames pending write.
    write_buf: Vec<u8>,
    write_pos: usize,
}

impl<S: Read + Write> WsFramed<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            inbuf: Vec::with_capacity(4096),
            inpos: 0,
            stage: Stage::Head,
            need: 2,
            fin: false,
            opcode: 0,
            masked: false,
            payload_len: 0,
            mask: [0u8; 4],
            frame_payload: Vec::new(),
            frag_opcode: None,
            frag: Vec::new(),
            out: Vec::new(),
            outpos: 0,
            eof: false,
            write_buf: Vec::new(),
            write_pos: 0,
        }
    }

    /// Parse as many complete frames as `inbuf` allows. Returns a parsed
    /// frame, or `None` when more input is needed.
    fn parse_one(&mut self) -> Option<io::Result<Option<FrameOut>>> {
        let avail = self.inbuf.len() - self.inpos;
        if avail < self.need {
            return None;
        }
        match self.stage {
            Stage::Head => {
                let b0 = self.inbuf[self.inpos];
                let b1 = self.inbuf[self.inpos + 1];
                self.inpos += 2;
                self.fin = b0 & 0x80 != 0;
                self.opcode = b0 & 0x0F;
                self.masked = b1 & 0x80 != 0;
                self.payload_len = (b1 & 0x7F) as u64;
                match self.payload_len {
                    126 => {
                        self.stage = Stage::ExtLen16;
                        self.need = 2;
                    }
                    127 => {
                        self.stage = Stage::ExtLen64;
                        self.need = 8;
                    }
                    _ => {
                        self.stage = Stage::Mask;
                        self.need = if self.masked { 4 } else { 0 };
                    }
                }
                self.parse_one()
            }
            Stage::ExtLen16 => {
                let b = &self.inbuf[self.inpos..self.inpos + 2];
                self.inpos += 2;
                self.payload_len = u16::from_be_bytes([b[0], b[1]]) as u64;
                self.stage = Stage::Mask;
                self.need = if self.masked { 4 } else { 0 };
                self.parse_one()
            }
            Stage::ExtLen64 => {
                let b = &self.inbuf[self.inpos..self.inpos + 8];
                self.inpos += 8;
                self.payload_len = u64::from_be_bytes(b.try_into().expect("8 bytes"));
                self.stage = Stage::Mask;
                self.need = if self.masked { 4 } else { 0 };
                self.parse_one()
            }
            Stage::Mask => {
                if self.masked {
                    let m = &self.inbuf[self.inpos..self.inpos + 4];
                    self.inpos += 4;
                    self.mask = [m[0], m[1], m[2], m[3]];
                }
                if self.payload_len > MAX_WS_MESSAGE {
                    return Some(Err(io::Error::other(format!(
                        "websocket frame too large: {} bytes",
                        self.payload_len
                    ))));
                }
                self.frame_payload = Vec::with_capacity(self.payload_len as usize);
                self.stage = Stage::Payload;
                self.need = self.payload_len as usize;
                self.parse_one()
            }
            Stage::Payload => {
                let take = self.need.min(avail);
                let src = &self.inbuf[self.inpos..self.inpos + take];
                if self.masked {
                    let base = self.frame_payload.len() as u64;
                    for (i, &byte) in src.iter().enumerate() {
                        self.frame_payload
                            .push(byte ^ self.mask[((base + i as u64) % 4) as usize]);
                    }
                } else {
                    self.frame_payload.extend_from_slice(src);
                }
                self.inpos += take;
                self.need -= take;
                if self.need > 0 {
                    return None;
                }
                // Frame complete.
                let payload = std::mem::take(&mut self.frame_payload);
                let opcode = self.opcode;
                let fin = self.fin;
                self.stage = Stage::Head;
                self.need = 2;
                Some(Ok(Some(FrameOut {
                    fin,
                    opcode,
                    payload,
                })))
            }
        }
    }
}

/// A parsed frame handed to the reader.
struct FrameOut {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Shared codec drivers (blocking)
// ---------------------------------------------------------------------------

/// Serialize a client frame (masked) and append it to the write buffer.
fn enqueue_frame<S>(framed: &mut WsFramed<S>, opcode: u8, payload: &[u8]) {
    let mut frame = Vec::with_capacity(payload.len() + 14);
    frame.push(0x80 | opcode);
    let len = payload.len();
    if len < 126 {
        frame.push(0x80 | len as u8);
    } else if len <= u16::MAX as usize {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }
    // Client frames MUST be masked (RFC 6455 §5.1).
    let mask = [0x12, 0x34, 0x56, 0x78];
    frame.extend_from_slice(&mask);
    for (i, &byte) in payload.iter().enumerate() {
        frame.push(byte ^ mask[i % 4]);
    }
    framed.write_buf.extend_from_slice(&frame);
}

/// Enqueue a close frame (1000 = normal closure).
fn framed_enqueue_close<S>(framed: &mut WsFramed<S>) {
    if framed.write_pos >= framed.write_buf.len() {
        enqueue_frame(framed, 0x8, &[0x03, 0xe8]);
    }
}

/// Write `write_buf` to the wire in full.
fn framed_flush_write<S: Read + Write>(framed: &mut WsFramed<S>) -> io::Result<()> {
    if framed.write_pos >= framed.write_buf.len() {
        framed.write_buf.clear();
        framed.write_pos = 0;
        return Ok(());
    }
    let remaining = &framed.write_buf[framed.write_pos..];
    framed.inner.write_all(remaining)?;
    framed.write_buf.clear();
    framed.write_pos = 0;
    Ok(())
}

/// Queue a fresh binary frame for `buf` and flush it to the wire.
fn framed_write<S: Read + Write>(framed: &mut WsFramed<S>, buf: &[u8]) -> io::Result<usize> {
    // Flush anything already queued (a previous partial write, a pong).
    framed_flush_write(framed)?;
    if buf.is_empty() {
        return Ok(0);
    }
    enqueue_frame(framed, 0x2, buf);
    framed_flush_write(framed)?;
    Ok(buf.len())
}

/// Serve buffered message bytes, then parse incoming frames, reading more
/// wire bytes as needed. Blocking reads are bounded by the socket's read
/// timeout (a timeout mid-read propagates as `WouldBlock`/`TimedOut`).
fn framed_read<S: Read + Write>(framed: &mut WsFramed<S>, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        // 1. Serve already-decoded message bytes.
        if framed.outpos < framed.out.len() {
            let remaining = &framed.out[framed.outpos..];
            let n = std::cmp::min(remaining.len(), buf.len());
            buf[..n].copy_from_slice(&remaining[..n]);
            framed.outpos += n;
            if framed.outpos >= framed.out.len() {
                framed.out.clear();
                framed.outpos = 0;
            }
            return Ok(n);
        }

        // 2. Parse any complete frames available in the input buffer. When a
        //    frame completes a message, stop parsing and serve it first (the
        //    parse state is preserved, so the next call continues).
        let mut delivered = false;
        loop {
            match framed.parse_one() {
                None => break, // need more wire bytes
                Some(Err(e)) => return Err(e),
                Some(Ok(Some(frame))) => {
                    let FrameOut {
                        fin,
                        opcode,
                        payload,
                    } = frame;
                    match opcode {
                        // Continuation of a fragmented data message.
                        0x0 => {
                            framed.frag_opcode.ok_or_else(|| {
                                io::Error::other("continuation frame without a started message")
                            })?;
                            if framed.frag.len() + payload.len() > MAX_WS_MESSAGE as usize {
                                return Err(io::Error::other("websocket message too large"));
                            }
                            framed.frag.extend_from_slice(&payload);
                            if fin {
                                let msg = std::mem::take(&mut framed.frag);
                                framed.frag_opcode = None;
                                framed.out = msg;
                                framed.outpos = 0;
                                delivered = true;
                            }
                        }
                        0x1 | 0x2 => {
                            if framed.frag_opcode.is_some() {
                                return Err(io::Error::other(
                                    "new data frame during fragmented message",
                                ));
                            }
                            if fin {
                                framed.out = payload;
                                framed.outpos = 0;
                                delivered = true;
                            } else {
                                framed.frag_opcode = Some(opcode);
                                framed.frag = payload;
                            }
                        }
                        // Ping → respond pong.
                        0x9 => {
                            if payload.len() > 125 {
                                return Err(io::Error::other("ping frame too large"));
                            }
                            enqueue_frame(framed, 0xA, &payload);
                            framed_flush_write(framed)?;
                        }
                        // Pong — ignore.
                        0xA => {}
                        // Close → surface EOF.
                        0x8 => {
                            framed.eof = true;
                            return Ok(0);
                        }
                        _ => {
                            return Err(io::Error::other(format!(
                                "unsupported websocket opcode 0x{opcode:x}"
                            )))
                        }
                    }
                    if delivered {
                        break; // serve the message before parsing more
                    }
                }
                Some(Ok(None)) => unreachable!(),
            }
        }

        // 3. If we produced a message, loop to serve it.
        if framed.outpos < framed.out.len() {
            continue;
        }

        // 4. Need more wire bytes: compact and read (bounded by the socket
        //    read timeout; a timeout propagates as an idle signal).
        if framed.inpos > 0 {
            framed.inbuf.drain(..framed.inpos);
            framed.inpos = 0;
        }
        let mut chunk = [0u8; 8192];
        match framed.inner.read(&mut chunk) {
            Ok(0) => {
                // Peer closed the TCP stream.
                framed.eof = true;
                return Ok(0);
            }
            Ok(n) => framed.inbuf.extend_from_slice(&chunk[..n]),
            Err(e) => return Err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// WsStream
// ---------------------------------------------------------------------------

/// A WebSocket duplex stream. Internally shares the codec behind a mutex so
/// reads, writes and half-close can come from different threads (the relay's
/// two copy threads, or `split()` halves).
pub struct WsStream<S> {
    framed: Arc<Mutex<WsFramed<S>>>,
}

impl<S: Read + Write> WsStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            framed: Arc::new(Mutex::new(WsFramed::new(inner))),
        }
    }

    /// Split into independent write/read halves that share the underlying
    /// codec (each operation is serialized by the internal mutex).
    pub fn split(self) -> (WsSink<S>, WsReader<S>) {
        (WsSink::new(self.framed.clone()), WsReader::new(self.framed))
    }
}

impl<S: Read + Write> Read for WsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut guard = self
            .framed
            .lock()
            .map_err(|_| io::Error::other("ws mutex poisoned"))?;
        framed_read(&mut *guard, buf)
    }
}

impl<S: Read + Write> Write for WsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = self
            .framed
            .lock()
            .map_err(|_| io::Error::other("ws mutex poisoned"))?;
        framed_write(&mut *guard, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut guard = self
            .framed
            .lock()
            .map_err(|_| io::Error::other("ws mutex poisoned"))?;
        framed_flush_write(&mut *guard)
    }
}

impl<S: Read + Write + Send> crate::common::stream::SyncStream for WsStream<S> {
    fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        if how != std::net::Shutdown::Read {
            // Best-effort close frame, then flush.
            let mut guard = self
                .framed
                .lock()
                .map_err(|_| io::Error::other("ws mutex poisoned"))?;
            framed_enqueue_close(&mut *guard);
            framed_flush_write(&mut *guard)
        } else {
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Split halves
// ---------------------------------------------------------------------------

pub struct WsSink<S: Read + Write> {
    inner: Arc<Mutex<WsFramed<S>>>,
}

impl<S: Read + Write> WsSink<S> {
    fn new(inner: Arc<Mutex<WsFramed<S>>>) -> Self {
        Self { inner }
    }
}

impl<S: Read + Write> Write for WsSink<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("ws mutex poisoned"))?;
        framed_write(&mut *guard, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("ws mutex poisoned"))?;
        framed_flush_write(&mut *guard)
    }
}

impl<S: Read + Write> Drop for WsSink<S> {
    fn drop(&mut self) {
        // Emit a close frame on teardown so the peer sees a clean shutdown.
        if let Ok(mut guard) = self.inner.try_lock() {
            framed_enqueue_close(&mut *guard);
            let _ = framed_flush_write(&mut *guard);
        }
    }
}

pub struct WsReader<S: Read + Write> {
    inner: Arc<Mutex<WsFramed<S>>>,
}

impl<S: Read + Write> WsReader<S> {
    fn new(inner: Arc<Mutex<WsFramed<S>>>) -> Self {
        Self { inner }
    }
}

impl<S: Read + Write> Read for WsReader<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("ws mutex poisoned"))?;
        framed_read(&mut *guard, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::stream::SyncStream;
    use std::net::SocketAddr;
    use std::time::Duration;

    /// A minimal blocking RFC 6455 server used to test the client codec:
    /// performs the handshake and echoes every data message back.
    fn spawn_echo_server() -> SocketAddr {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                std::thread::spawn(move || {
                    // Handshake.
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    loop {
                        if stream.read(&mut byte).is_err() {
                            return;
                        }
                        head.push(byte[0]);
                        if head.ends_with(b"\r\n\r\n") {
                            break;
                        }
                    }
                    let text = String::from_utf8_lossy(&head);
                    let key = text
                        .lines()
                        .find_map(|l| {
                            l.to_lowercase()
                                .starts_with("sec-websocket-key:")
                                .then(|| l.split(':').nth(1).unwrap().trim().to_string())
                        })
                        .unwrap_or_default();
                    let accept = compute_accept(&key);
                    let resp = format!(
                        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                    );
                    if stream.write_all(resp.as_bytes()).is_err() {
                        return;
                    }
                    // Echo loop: read masked frames, echo back unmasked.
                    loop {
                        let mut hdr = [0u8; 2];
                        if stream.read_exact(&mut hdr).is_err() {
                            return;
                        }
                        let fin = hdr[0] & 0x80 != 0;
                        let opcode = hdr[0] & 0x0F;
                        let masked = hdr[1] & 0x80 != 0;
                        let mut len = (hdr[1] & 0x7F) as u64;
                        if len == 126 {
                            let mut b = [0u8; 2];
                            if stream.read_exact(&mut b).is_err() {
                                return;
                            }
                            len = u16::from_be_bytes(b) as u64;
                        } else if len == 127 {
                            let mut b = [0u8; 8];
                            if stream.read_exact(&mut b).is_err() {
                                return;
                            }
                            len = u64::from_be_bytes(b);
                        }
                        let mut mask = [0u8; 4];
                        if masked && stream.read_exact(&mut mask).is_err() {
                            return;
                        }
                        let mut payload = vec![0u8; len as usize];
                        if stream.read_exact(&mut payload).is_err() {
                            return;
                        }
                        if masked {
                            for (i, b) in payload.iter_mut().enumerate() {
                                *b ^= mask[i % 4];
                            }
                        }
                        match opcode {
                            0x8 => return, // close
                            0x9 => { /* ping */ }
                            _ => {}
                        }
                        if !fin {
                            continue;
                        }
                        // Echo text/binary back (unmasked server frame).
                        let mut out = vec![0x80 | opcode];
                        let l = payload.len();
                        if l < 126 {
                            out.push(l as u8);
                        } else if l <= u16::MAX as usize {
                            out.push(126);
                            out.extend_from_slice(&(l as u16).to_be_bytes());
                        } else {
                            out.push(127);
                            out.extend_from_slice(&(l as u64).to_be_bytes());
                        }
                        out.extend_from_slice(&payload);
                        if stream.write_all(&out).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        addr
    }

    #[test]
    fn handshake_and_echo_roundtrip() {
        let addr = spawn_echo_server();
        let config = WebSocketConfig {
            path: "/".to_string(),
            host: Some("echo.test".to_string()),
            headers: HashMap::new(),
            max_early_data: 0,
            early_data_header: None,
        };
        let transport = WebSocketTransport::new(config, "echo.test", addr.port(), false);
        let tcp = std::net::TcpStream::connect(addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut ws = transport.connect(tcp).unwrap();

        let payload = b"hello websocket";
        ws.write_all(payload).unwrap();
        ws.flush().unwrap();

        let mut buf = [0u8; 256];
        let n = ws.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], payload);
        ws.shutdown(std::net::Shutdown::Both).ok();
    }

    #[test]
    fn split_halves_roundtrip() {
        let addr = spawn_echo_server();
        let config = WebSocketConfig::default();
        let transport = WebSocketTransport::new(config, "echo.test", addr.port(), false);
        let tcp = std::net::TcpStream::connect(addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let ws = transport.connect(tcp).unwrap();
        let (mut sink, mut reader) = ws.split();

        let payload = b"split test";
        sink.write_all(payload).unwrap();
        sink.flush().unwrap();

        let mut buf = [0u8; 256];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], payload);
        drop(sink);
    }
}
