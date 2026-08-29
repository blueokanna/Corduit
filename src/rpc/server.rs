//! Localhost HTTP + WebSocket JSON-RPC server for web frontends.
//!
//! This transport exposes the **same** typed dispatch surface as the C ABI
//! ([`crate::rpc::dispatch`]) over a plain JSON wire format, so a browser
//! dashboard, a desktop GUI or any language with an HTTP/WebSocket stack can
//! drive the engine without linking Rust.
//!
//! # Implementation
//!
//! The transport is built entirely on `courierust` — no `hyper`, no
//! `tokio-tungstenite`:
//!
//! * HTTP/1.1 framing comes from [`crate::common::http_server`], a blocking
//!   server over courierust's H/1 codec (one thread per connection);
//! * WebSocket upgrades ride the server's raw-connection handoff: the
//!   handler returns a `101 Switching Protocols` carrying an internal marker
//!   header, and the connection is handed to a blocking RFC 6455 codec
//!   ([`WsServer`]) that speaks the protocol from scratch;
//! * RPC dispatch is synchronous: each WebSocket message (and each `POST
//!   /rpc` request) is handled inline on the connection thread with a direct
//!   call to [`crate::rpc::dispatch`].
//!
//! # Security model
//!
//! * Binds to a loopback address only (never `0.0.0.0`) — the server is not
//!   reachable from other machines.
//! * Every call requires a bearer token:
//!   - HTTP: `Authorization: Bearer <token>` header;
//!   - WebSocket: `?token=<token>` query parameter (browsers cannot set
//!     headers on WebSocket connections).
//! * Token comparison is constant-time ([`ct_eq`]).
//! * Request bodies and WebSocket messages are size-bounded; oversized
//!   payloads are rejected with `413`.
//! * Responses carry permissive CORS headers so a locally-hosted dashboard
//!   served from a different port can talk to the engine.
//!
//! # Endpoints
//!
//! * `GET /health` — `{"ok":true}` (unauthenticated, no sensitive data);
//! * `POST /rpc` — JSON-RPC request `{"method":"...","params":{...}}`;
//! * WebSocket (any path) — same JSON-RPC payload per message.
//!
//! # Wire contract
//!
//! * request:  `{ "method": "<name>", "params": { ... } }`;
//! * success:  `{ "code": 0, "data": <value> }`;
//! * error:    `{ "code": 1, "error": "<message>" }`.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use courierust::courierust_http::{
    Body, HeaderName, HeaderValue, Method, Request, Response, StatusCode,
};
use courierust::courierust_io::{Read as CRead, Write as CWrite};
use courierust::courierust_tls::TlsVersion;

use crate::common::http_server::{HttpServer, HttpServerConfig, RawConnection, TUNNEL_MARKER};
use crate::crypto::util::ct_eq;

/// Maximum accepted JSON-RPC request body (config uploads can be large).
const MAX_REQUEST_BODY: usize = 16 * 1024 * 1024; // 16 MiB
/// Maximum accepted WebSocket message size.
const MAX_WS_MESSAGE: usize = 16 * 1024 * 1024; // 16 MiB
/// Upper bound on a single connection's read idle time. Bounds idle
/// keep-alive / WebSocket connections (resource hygiene); a dashboard never
/// needs longer between requests.
const CONNECTION_LIFETIME: std::time::Duration = std::time::Duration::from_secs(600);

/// Error produced by the RPC server.
#[derive(Debug)]
pub struct ServerError(pub String);

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ServerError {}

impl From<std::io::Error> for ServerError {
    fn from(e: std::io::Error) -> Self {
        ServerError(e.to_string())
    }
}

/// A bound (not yet started) RPC server.
pub struct RpcServer {
    server: HttpServer,
    addr: SocketAddr,
}

/// A running RPC server. Call [`stop`](Self::stop) or [`join`](Self::join) to
/// shut it down gracefully.
pub struct RpcServerHandle {
    addr: SocketAddr,
    token_set: bool,
    server: std::sync::Mutex<Option<HttpServer>>,
}

impl RpcServer {
    /// Bind a TCP listener at `addr`. Use a loopback address (`127.0.0.1`,
    /// `::1`) — the server deliberately never binds to all interfaces.
    pub fn bind(addr: SocketAddr, token: String) -> std::io::Result<Self> {
        let token: Arc<str> = Arc::from(token.as_str());

        // Synchronous HTTP handler: routes /health and /rpc, and converts a
        // WebSocket upgrade into a 101 + raw-connection handoff.
        let handler_token = token.clone();
        let handler = Arc::new(move |req: Request<Body>| -> Response<Body> {
            handle_http_request(req, &handler_token)
        });

        // WebSocket tunnel: runs the RFC 6455 message loop on the blocking
        // raw connection after the 101 has been written.
        let tunnel_handler = Arc::new(move |conn: RawConnection| {
            run_ws_tunnel(conn);
        });

        let config = HttpServerConfig {
            listen: addr,
            tls: None,
            min_version: TlsVersion::Tls12,
            max_version: TlsVersion::Tls13,
            max_head: 64 * 1024,
            max_body: MAX_REQUEST_BODY,
            read_timeout: Some(CONNECTION_LIFETIME),
            tunnel_handler: Some(tunnel_handler),
            handler,
        };

        let server = HttpServer::bind(config)?;
        let addr = server.local_addr()?;
        Ok(Self { server, addr })
    }

    /// The actual bound address (useful when binding to port `0`).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Start the accept loop on a background thread and return a controller
    /// handle.
    pub fn spawn(mut self) -> RpcServerHandle {
        self.server.start().expect("start RPC server accept loop");
        RpcServerHandle {
            addr: self.addr,
            token_set: true,
            server: std::sync::Mutex::new(Some(self.server)),
        }
    }
}

impl RpcServerHandle {
    /// The bound address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Whether a token is required (always true — a token is mandatory).
    pub fn token_set(&self) -> bool {
        self.token_set
    }

    /// Whether the accept loop is currently running.
    pub fn is_running(&self) -> bool {
        self.server
            .lock()
            .unwrap()
            .as_ref()
            .map(HttpServer::is_running)
            .unwrap_or(false)
    }

    /// Request a graceful shutdown of the accept loop.
    pub fn stop(&self) {
        if let Some(server) = self.server.lock().unwrap().as_ref() {
            server.stop();
        }
    }

    /// Stop the accept loop and wait for it to exit.
    pub fn join(self) {
        if let Some(mut server) = self.server.lock().unwrap().take() {
            server.shutdown();
        }
    }
}

/// Route a single HTTP request (or WebSocket upgrade).
fn handle_http_request(req: Request<Body>, token: &str) -> Response<Body> {
    // CORS preflight for browser dashboards served from another origin.
    if req.method == Method::OPTIONS {
        return cors_response(StatusCode::NO_CONTENT);
    }

    let path = req.uri.path().to_string();

    // WebSocket upgrade — the 101 carries the internal handoff marker so the
    // connection thread hands the raw socket to the WS loop.
    if is_websocket_upgrade(&req) {
        return websocket_upgrade_response(&req, token);
    }

    // Unauthenticated health probe (no sensitive data).
    if req.method == Method::GET && path == "/health" {
        return json_response(StatusCode::OK, r#"{"ok":true}"#);
    }

    // Only `POST /rpc` is the JSON-RPC endpoint.
    if req.method != Method::POST || path != "/rpc" {
        return json_response(StatusCode::NOT_FOUND, r#"{"code":1,"error":"not found"}"#);
    }

    // Bearer-token authorization (constant-time comparison).
    let authorized = req
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| ct_eq(t.as_bytes(), token.as_bytes()))
        .unwrap_or(false);
    if !authorized {
        return json_response(
            StatusCode::UNAUTHORIZED,
            r#"{"code":1,"error":"unauthorized"}"#,
        );
    }

    // The blocking server caps the body at `max_body` and answers oversized
    // requests with 413 before the handler runs; the `Some(_)` arm below is
    // defensive only. An empty body flows through and is reported as a
    // logical JSON-RPC error ("missing 'method'").
    let body = match req.body.as_bytes() {
        Some(b) if b.len() <= MAX_REQUEST_BODY => b.to_vec(),
        Some(_) => {
            return json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                r#"{"code":1,"error":"request too large"}"#,
            )
        }
        None => Vec::new(),
    };

    let response = process_payload(&body);
    json_response(StatusCode::OK, &response)
}

/// Handle a WebSocket upgrade request after token validation.
fn websocket_upgrade_response(req: &Request<Body>, token: &str) -> Response<Body> {
    // Browsers cannot set the Authorization header on WebSocket connections,
    // so the token is carried as `?token=...` in the request URI.
    let query_token = req
        .uri
        .query()
        .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("token=")))
        .map(str::to_string);
    let Some(query_token) = query_token else {
        return json_response(
            StatusCode::UNAUTHORIZED,
            r#"{"code":1,"error":"missing token"}"#,
        );
    };
    if !ct_eq(query_token.as_bytes(), token.as_bytes()) {
        return json_response(
            StatusCode::UNAUTHORIZED,
            r#"{"code":1,"error":"unauthorized"}"#,
        );
    }

    // RFC 6455 requires the client key to compute the accept value.
    let ws_key = req
        .headers
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let Some(ws_key) = ws_key else {
        return json_response(
            StatusCode::BAD_REQUEST,
            r#"{"code":1,"error":"missing Sec-WebSocket-Key"}"#,
        );
    };

    let mut resp = Response::new(StatusCode::SWITCHING_PROTOCOLS);
    resp.headers.insert(
        HeaderName::from_static("connection"),
        HeaderValue::from_static("Upgrade"),
    );
    resp.headers.insert(
        HeaderName::from_static("upgrade"),
        HeaderValue::from_static("websocket"),
    );
    resp.headers.insert(
        HeaderName::from_static("sec-websocket-accept"),
        HeaderValue::from(websocket_accept(&ws_key)),
    );
    // Internal marker: after this response is written, the connection thread
    // hands the raw socket to the tunnel handler (the WS message loop).
    resp.headers.insert(
        HeaderName::from_static(TUNNEL_MARKER),
        HeaderValue::from_static("1"),
    );
    resp
}

/// Compute the RFC 6455 `Sec-WebSocket-Accept` value for a client key:
/// `base64(SHA-1(key || "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`.
fn websocket_accept(client_key: &str) -> String {
    use crate::crypto::digest::Digest;
    use crate::crypto::hash::Sha1;

    const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut hasher = Sha1::new();
    hasher.update(client_key.as_bytes());
    hasher.update(WS_GUID);
    let digest = hasher.finalize();
    crate::crypto::encoding::encode(&digest, crate::crypto::encoding::Config::STANDARD)
}

fn is_websocket_upgrade(req: &Request<Body>) -> bool {
    let upgrade = req
        .headers
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    let connection = req
        .headers
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        });
    upgrade && connection
}

// ---------------------------------------------------------------------------
// Blocking RFC 6455 server-side WebSocket codec
// ---------------------------------------------------------------------------

/// A message yielded by the server-side WebSocket codec.
enum WsMsg {
    Text(Vec<u8>),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong,
    Close,
}

/// A blocking RFC 6455 server over a [`RawConnection`].
///
/// Server-to-client frames are unmasked; client-to-server frames MUST be
/// masked (RFC 6455 §5.1) — an unmasked client frame is a protocol
/// violation and closes the connection. Fragmented data messages are
/// reassembled; control frames (ping/pong/close) are never fragmented and
/// are returned to the caller as they arrive.
struct WsServer {
    conn: RawConnection,
    /// Opcode of the in-progress fragmented data message (`None` = idle).
    frag_opcode: Option<u8>,
    /// Payload accumulated so far for the fragmented message.
    frag_payload: Vec<u8>,
    /// Hard cap for a single (possibly fragmented) message.
    max_message: usize,
}

impl WsServer {
    fn new(conn: RawConnection, max_message: usize) -> Self {
        Self {
            conn,
            frag_opcode: None,
            frag_payload: Vec::new(),
            max_message,
        }
    }

    /// Read one complete message. Fragmented data messages are reassembled;
    /// control frames are returned as-is.
    fn read(&mut self) -> Result<WsMsg, String> {
        loop {
            let (fin, opcode, payload) = self.read_frame()?;
            match opcode {
                0x0 => {
                    // Continuation of a fragmented data message.
                    let op = self
                        .frag_opcode
                        .ok_or("continuation frame without a started message")?;
                    if self.frag_payload.len() + payload.len() > self.max_message {
                        return Err("websocket message too large".to_string());
                    }
                    self.frag_payload.extend_from_slice(&payload);
                    if fin {
                        let msg = if op == 0x1 {
                            WsMsg::Text(std::mem::take(&mut self.frag_payload))
                        } else {
                            WsMsg::Binary(std::mem::take(&mut self.frag_payload))
                        };
                        self.frag_opcode = None;
                        return Ok(msg);
                    }
                }
                0x1 | 0x2 => {
                    // New data message. A fresh one while a fragmented
                    // message is in flight is a protocol violation.
                    if self.frag_opcode.is_some() {
                        return Err("new data frame during fragmented message".to_string());
                    }
                    if fin {
                        return Ok(if opcode == 0x1 {
                            WsMsg::Text(payload)
                        } else {
                            WsMsg::Binary(payload)
                        });
                    }
                    self.frag_opcode = Some(opcode);
                    self.frag_payload = payload;
                }
                0x8 => return Ok(WsMsg::Close),
                0x9 => return Ok(WsMsg::Ping(payload)),
                0xA => return Ok(WsMsg::Pong),
                _ => return Err(format!("unsupported websocket opcode 0x{opcode:x}")),
            }
        }
    }

    /// Read one raw frame: header, extended length, mask, unmasked payload.
    fn read_frame(&mut self) -> Result<(bool, u8, Vec<u8>), String> {
        let mut hdr = [0u8; 2];
        read_exact(&mut self.conn, &mut hdr)?;
        let fin = hdr[0] & 0x80 != 0;
        let opcode = hdr[0] & 0x0F;
        let masked = hdr[1] & 0x80 != 0;
        let mut len = (hdr[1] & 0x7F) as u64;
        if len == 126 {
            let mut ext = [0u8; 2];
            read_exact(&mut self.conn, &mut ext)?;
            len = u16::from_be_bytes(ext) as u64;
        } else if len == 127 {
            let mut ext = [0u8; 8];
            read_exact(&mut self.conn, &mut ext)?;
            len = u64::from_be_bytes(ext);
        }
        // Reject oversized frames before allocating any buffer.
        if len > self.max_message as u64 {
            return Err(format!("websocket frame too large: {len} bytes"));
        }
        if !masked {
            return Err("client-to-server frames must be masked".to_string());
        }
        let mut mask = [0u8; 4];
        read_exact(&mut self.conn, &mut mask)?;
        let mut payload = vec![0u8; len as usize];
        read_exact(&mut self.conn, &mut payload)?;
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[i % 4];
        }
        Ok((fin, opcode, payload))
    }

    fn send_text(&mut self, data: &[u8]) -> Result<(), String> {
        self.send_frame(0x1, data)
    }

    fn send_pong(&mut self, data: &[u8]) -> Result<(), String> {
        self.send_frame(0xA, data)
    }

    fn send_close(&mut self) -> Result<(), String> {
        // 1000 = normal closure.
        self.send_frame(0x8, &[0x03, 0xe8])
    }

    /// Write one unmasked server frame (FIN always set — the server never
    /// fragments its own messages here).
    fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<(), String> {
        let mut out = Vec::with_capacity(payload.len() + 10);
        out.push(0x80 | opcode);
        let len = payload.len();
        if len < 126 {
            out.push(len as u8);
        } else if len <= u16::MAX as usize {
            out.push(126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push(127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
        out.extend_from_slice(payload);
        write_all(&mut self.conn, &out)?;
        CWrite::flush(&mut self.conn).map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// Run the WebSocket message loop: every message is one JSON-RPC request.
/// The token was already validated during the upgrade handshake. Runs on
/// the connection thread; dispatch is synchronous.
fn run_ws_tunnel(conn: RawConnection) {
    let mut ws = WsServer::new(conn, MAX_WS_MESSAGE);
    loop {
        match ws.read() {
            Ok(WsMsg::Text(data)) | Ok(WsMsg::Binary(data)) => {
                let resp = process_payload(&data);
                if let Err(e) = ws.send_text(resp.as_bytes()) {
                    tracing::debug!("RPC WebSocket write failed: {e}");
                    break;
                }
            }
            Ok(WsMsg::Ping(payload)) => {
                if ws.send_pong(&payload).is_err() {
                    break;
                }
            }
            Ok(WsMsg::Pong) => {}
            Ok(WsMsg::Close) => {
                let _ = ws.send_close();
                break;
            }
            Err(e) => {
                tracing::debug!("RPC WebSocket closed: {e}");
                break;
            }
        }
    }
}

/// Read a buffer in full over a courierust reader.
fn read_exact<R: CRead>(reader: &mut R, mut buf: &mut [u8]) -> Result<(), String> {
    while !buf.is_empty() {
        match CRead::read(reader, buf) {
            Ok(0) => return Err("connection closed mid-read".to_string()),
            Ok(n) => buf = &mut buf[n..],
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}

/// Write a buffer in full over a courierust writer.
fn write_all<W: CWrite>(writer: &mut W, mut data: &[u8]) -> Result<(), String> {
    while !data.is_empty() {
        match CWrite::write(writer, data) {
            Ok(0) => return Err("write returned 0 bytes".to_string()),
            Ok(n) => data = &data[n..],
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// JSON-RPC payload handling
// ---------------------------------------------------------------------------

/// Parse one JSON-RPC payload and produce the JSON response string.
fn process_payload(body: &[u8]) -> String {
    let text = match std::str::from_utf8(body) {
        Ok(t) => t,
        Err(_) => return encode_response(Err("request body is not valid UTF-8".to_string())),
    };
    let parsed: nextjson::Value = match nextjson::from_str(text) {
        Ok(v) => v,
        Err(e) => return encode_response(Err(format!("invalid request JSON: {e}"))),
    };
    let method = match parsed.get("method").and_then(|v| v.as_str()) {
        Some(m) => m,
        None => return encode_response(Err("missing 'method'".to_string())),
    };
    let params = parsed
        .get("params")
        .cloned()
        .unwrap_or(nextjson::Value::Null);
    let result = crate::rpc::dispatch(method, &params);
    encode_response(result)
}

/// Encode a dispatch result as the canonical `{"code":..,"data":..|"error":..}`
/// JSON object. Errors are escaped by `nextjson` itself, never interpolated.
fn encode_response(result: Result<nextjson::Value, String>) -> String {
    let mut map = nextjson::Map::new();
    match result {
        Ok(data) => {
            map.insert("code".to_string(), nextjson::Value::from(0));
            map.insert("data".to_string(), data);
        }
        Err(e) => {
            map.insert("code".to_string(), nextjson::Value::from(1));
            map.insert("error".to_string(), nextjson::Value::from(e));
        }
    }
    nextjson::to_string(&nextjson::Value::Object(map))
        .unwrap_or_else(|_| r#"{"code":1,"error":"response encode failed"}"#.to_string())
}

/// Build a JSON response with permissive CORS headers (localhost-only
/// service, token-gated).
fn json_response(status: StatusCode, body: &str) -> Response<Body> {
    let mut resp = Response::new(status);
    resp.headers.insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("application/json"),
    );
    add_cors(&mut resp);
    resp.body = Body::from(body.as_bytes().to_vec());
    resp
}

/// Build a CORS preflight response.
fn cors_response(status: StatusCode) -> Response<Body> {
    let mut resp = Response::new(status);
    add_cors(&mut resp);
    resp
}

/// Permissive CORS headers for the locally-hosted dashboard.
fn add_cors(resp: &mut Response<Body>) {
    resp.headers.insert(
        HeaderName::from_static("access-control-allow-origin"),
        HeaderValue::from_static("*"),
    );
    resp.headers.insert(
        HeaderName::from_static("access-control-allow-methods"),
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    resp.headers.insert(
        HeaderName::from_static("access-control-allow-headers"),
        HeaderValue::from_static("Authorization, Content-Type"),
    );
    resp.headers.insert(
        HeaderName::from_static("access-control-max-age"),
        HeaderValue::from_static("86400"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::time::Duration;

    fn spawn_test_server() -> RpcServerHandle {
        let server = RpcServer::bind(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            "test-token-123".to_string(),
        )
        .expect("bind");
        server.spawn()
    }

    /// Raw HTTP/1.1 client (test-only, plain `std` sockets). Sends a single
    /// request with `Connection: close` and returns `(status, body)`.
    fn http_request(
        addr: SocketAddr,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: &str,
    ) -> (u16, String) {
        let mut stream = std::net::TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        if let Some(t) = token {
            req.push_str(&format!("Authorization: Bearer {t}\r\n"));
        }
        req.push_str("\r\n");
        req.push_str(body);
        stream.write_all(req.as_bytes()).unwrap();

        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).unwrap();
        let text = String::from_utf8_lossy(&resp);
        let status: u16 = text
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        (status, body)
    }

    fn post_rpc(addr: SocketAddr, token: Option<&str>, body: &str) -> (u16, String) {
        http_request(addr, "POST", "/rpc", token, body)
    }

    /// Perform the WebSocket upgrade handshake; returns the connected socket
    /// and the HTTP status line's status code.
    fn ws_handshake(addr: SocketAddr, token: &str) -> (std::net::TcpStream, u16) {
        let mut stream = std::net::TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let key = "dGhlIHNhbXBsZSBub25jZQ=="; // RFC 6455 sample key
        let req = format!(
            "GET /ws?token={token} HTTP/1.1\r\n\
             Host: {addr}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).unwrap();

        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            stream.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
            if head.len() > 64 * 1024 {
                panic!("handshake response too large");
            }
        }
        let status: u16 = String::from_utf8_lossy(&head)
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        (stream, status)
    }

    /// Send one masked text frame (client side).
    fn ws_send_text(stream: &mut std::net::TcpStream, data: &[u8]) {
        let mut frame = vec![0x81];
        let len = data.len();
        if len < 126 {
            frame.push(0x80 | len as u8);
        } else if len <= u16::MAX as usize {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        let mask = [0x01, 0x02, 0x03, 0x04];
        frame.extend_from_slice(&mask);
        for (i, byte) in data.iter().enumerate() {
            frame.push(byte ^ mask[i % 4]);
        }
        stream.write_all(&frame).unwrap();
    }

    /// Read one server frame; returns `(opcode, payload)` (server frames are
    /// unmasked).
    fn ws_read_frame(stream: &mut std::net::TcpStream) -> (u8, Vec<u8>) {
        let mut hdr = [0u8; 2];
        stream.read_exact(&mut hdr).unwrap();
        let opcode = hdr[0] & 0x0F;
        let mut len = (hdr[1] & 0x7F) as u64;
        if len == 126 {
            let mut ext = [0u8; 2];
            stream.read_exact(&mut ext).unwrap();
            len = u16::from_be_bytes(ext) as u64;
        } else if len == 127 {
            let mut ext = [0u8; 8];
            stream.read_exact(&mut ext).unwrap();
            len = u64::from_be_bytes(ext);
        }
        let mut payload = vec![0u8; len as usize];
        stream.read_exact(&mut payload).unwrap();
        (opcode, payload)
    }

    /// Send a masked close frame (1000).
    fn ws_send_close(stream: &mut std::net::TcpStream) {
        let mut frame = vec![0x88, 0x80 | 2, 0x01, 0x02, 0x03, 0x04, 0x03, 0xe8];
        // Mask the 2-byte close payload.
        for i in 0..2 {
            frame[6 + i] ^= [0x01, 0x02, 0x03, 0x04][i % 4];
        }
        stream.write_all(&frame).unwrap();
    }

    #[test]
    fn health_endpoint_is_open() {
        let h = spawn_test_server();
        let (status, body) = http_request(h.addr(), "GET", "/health", None, "");
        assert_eq!(status, 200);
        assert!(body.contains("\"ok\":true"));
        h.stop();
        std::thread::sleep(Duration::from_millis(50));
        assert!(!h.is_running());
    }

    #[test]
    fn http_rpc_requires_token() {
        let h = spawn_test_server();
        // No token -> 401
        let (status, body) = post_rpc(h.addr(), None, r#"{"method":"get_version"}"#);
        assert_eq!(status, 401);
        assert!(body.contains("unauthorized"));
        // Wrong token -> 401
        let (status, _) = post_rpc(h.addr(), Some("wrong"), r#"{"method":"get_version"}"#);
        assert_eq!(status, 401);
        h.stop();
    }

    #[test]
    fn http_rpc_dispatch_roundtrip() {
        let h = spawn_test_server();
        let (status, body) = post_rpc(
            h.addr(),
            Some("test-token-123"),
            r#"{"method":"get_version"}"#,
        );
        assert_eq!(status, 200);
        let parsed: nextjson::Value = nextjson::from_str(&body).unwrap();
        assert_eq!(parsed.get("code").and_then(|v| v.as_i64()), Some(0));
        assert!(parsed.get("data").is_some());
        h.stop();
    }

    #[test]
    fn http_rpc_unknown_method_is_error() {
        let h = spawn_test_server();
        let (status, body) = post_rpc(
            h.addr(),
            Some("test-token-123"),
            r#"{"method":"no_such_method"}"#,
        );
        assert_eq!(status, 200); // transport-level OK, logical error
        let parsed: nextjson::Value = nextjson::from_str(&body).unwrap();
        assert_eq!(parsed.get("code").and_then(|v| v.as_i64()), Some(1));
        assert!(parsed.get("error").and_then(|v| v.as_str()).is_some());
        h.stop();
    }

    #[test]
    fn oversize_body_is_rejected() {
        let h = spawn_test_server();
        let big = format!(
            r#"{{"method":"x","params":{{"pad":"{}"}}}}"#,
            "a".repeat(MAX_REQUEST_BODY + 1)
        );
        let (status, _) = post_rpc(h.addr(), Some("test-token-123"), &big);
        assert_eq!(status, 413);
        h.stop();
    }

    #[test]
    fn websocket_roundtrip() {
        let h = spawn_test_server();
        let (mut ws, status) = ws_handshake(h.addr(), "test-token-123");
        assert_eq!(status, 101);

        ws_send_text(&mut ws, r#"{"method":"get_version"}"#.as_bytes());
        let (opcode, payload) = ws_read_frame(&mut ws);
        assert_eq!(opcode, 0x1); // text
        let text = String::from_utf8(payload).unwrap();
        let parsed: nextjson::Value = nextjson::from_str(&text).unwrap();
        assert_eq!(parsed.get("code").and_then(|v| v.as_i64()), Some(0));

        // Graceful close: server replies with a close frame.
        ws_send_close(&mut ws);
        let (opcode, _) = ws_read_frame(&mut ws);
        assert_eq!(opcode, 0x8);
        h.stop();
    }

    #[test]
    fn websocket_rejects_bad_token() {
        let h = spawn_test_server();
        let (_ws, status) = ws_handshake(h.addr(), "wrong");
        assert_eq!(status, 401, "connection with a bad token must be refused");
        h.stop();
    }
}
