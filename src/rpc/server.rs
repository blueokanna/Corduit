//! Localhost HTTP + WebSocket JSON-RPC server for web frontends.
//!
//! This transport exposes the **same** typed dispatch surface as the C ABI
//! ([`crate::rpc::dispatch`]) over a plain JSON wire format, so a browser
//! dashboard, a desktop GUI or any language with an HTTP/WebSocket stack can
//! drive the engine without linking Rust.
//!
//! # Implementation
//!
//! Every connection is driven by [`serve_connection`] — courierust's
//! per-connection engine — on a thread of its own (bounded, see
//! [`crate::common::listener`]). Nothing about HTTP is hand-written:
//!
//! * framing, keep-alive, body caps and the `413` for an oversized request
//!   come from the server;
//! * a WebSocket upgrade is validated by the server's WebSocket policy
//!   (method, `Upgrade`/`Connection` tokens, key shape, version 13, origin)
//!   and then served by the **blocking** WebSocket driver, which owns the
//!   framing, the limits, the keepalive pings and the closing handshake.
//!
//! The dispatch itself is synchronous and may block for as long as an
//! operation takes (`start_proxy`, a config reload); that is why each
//! connection has a thread of its own instead of sharing a scheduler.
//!
//! # Security model
//!
//! * [`RpcServer::bind`] **refuses any address that is not loopback** — the
//!   server is not reachable from other machines even by misconfiguration.
//! * Every call requires a bearer token:
//!   - HTTP: `Authorization: Bearer <token>` header;
//!   - WebSocket: `?token=<token>` query parameter (browsers cannot set
//!     headers on WebSocket connections).
//! * Token comparison is constant-time ([`crate::crypto::util::ct_eq`]).
//! * Request bodies and WebSocket messages are size-bounded; oversized
//!   payloads are rejected with `413`.
//! * Responses carry permissive CORS headers so a locally-hosted dashboard
//!   served from a different port can talk to the engine. That is also why
//!   the WebSocket origin policy is [`OriginPolicy::Any`]: the token in the
//!   URL is the authentication, and `Origin` is not.
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

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;

use courierust::courierust_body::Body;
use courierust::courierust_http::{HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use courierust::courierust_server::ws::{WsConfig, WsConn, WsData, WsService, WsUpgradeReply};
use courierust::courierust_server::{serve_connection, Handler, ServerConfig};
use courierust::courierust_ws::{OriginPolicy, PmDeflatePolicy};

use crate::common::listener::ConnectionListener;
use crate::crypto::util::ct_eq;

/// Maximum accepted JSON-RPC request body (config uploads can be large).
const MAX_REQUEST_BODY: usize = 16 * 1024 * 1024;
/// Maximum accepted WebSocket message size.
const MAX_WS_MESSAGE: usize = 16 * 1024 * 1024;
/// Cap for a request head (status line + header list).
const MAX_REQUEST_HEAD: usize = 64 * 1024;
/// Upper bound on concurrently open connections: a local dashboard needs a
/// handful, and the bound is what keeps a stuck client from pinning threads.
const MAX_CONNECTIONS: usize = 64;
/// Upper bound on a connection's read idle time (keep-alive and WebSocket).
const CONNECTION_LIFETIME: std::time::Duration = std::time::Duration::from_secs(600);
/// Server-side keepalive: a Ping goes out after this much inbound silence,
/// and a peer that stays silent for twice as long is dropped.
const WS_PING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// A bound (not yet serving) RPC server.
pub struct RpcServer {
    listener: Option<TcpListener>,
    addr: SocketAddr,
    token: Arc<str>,
    config: Arc<ServerConfig>,
}

/// A serving RPC server. [`stop`](Self::stop) shuts it down; dropping the
/// handle does the same (the listener is never left behind).
pub struct RpcServerHandle {
    addr: SocketAddr,
    token_set: bool,
    server: parking_lot::Mutex<Option<ConnectionListener>>,
}

impl RpcServer {
    /// Bind a TCP listener at `addr`.
    ///
    /// Only loopback addresses are accepted (`127.0.0.0/8`, `::1`): the
    /// server exposes engine control and must never be reachable from the
    /// network, so a non-loopback address is refused here rather than
    /// documented as a rule.
    pub fn bind(addr: SocketAddr, token: String) -> std::io::Result<Self> {
        if !addr.ip().is_loopback() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("RPC server refuses non-loopback address {addr}"),
            ));
        }

        let listener = TcpListener::bind(addr)?;
        let addr = listener.local_addr()?;
        // The accept loop polls the listener so it can observe a stop
        // request without waiting for a connection.
        listener.set_nonblocking(true)?;

        let config = ServerConfig {
            read_timeout: Some(CONNECTION_LIFETIME),
            max_header_list: MAX_REQUEST_HEAD,
            max_body: MAX_REQUEST_BODY,
            http2: false,
            tls: None,
            handshake_timeout: None,
            max_connections: MAX_CONNECTIONS,
            websocket: ws_config(),
            ..ServerConfig::default()
        };

        Ok(Self {
            listener: Some(listener),
            addr,
            token: Arc::from(token.as_str()),
            config: Arc::new(config),
        })
    }

    /// The actual bound address (useful when binding to port `0`).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Start serving on a background thread and return a controller handle.
    pub fn spawn(mut self) -> RpcServerHandle {
        let listener = self
            .listener
            .take()
            .expect("RPC server listener consumed before spawn");
        let handler = RpcHandler {
            token: Arc::clone(&self.token),
        };
        let config = Arc::clone(&self.config);

        let mut server = ConnectionListener::new(listener, self.addr, MAX_CONNECTIONS);
        server
            .start("corduit-rpc-conn", move |stream, peer| {
                if let Err(e) = serve_connection(stream, &handler, config.as_ref()) {
                    tracing::debug!("RPC connection from {peer} ended: {e}");
                }
            })
            .expect("start RPC server accept loop");

        RpcServerHandle {
            addr: self.addr,
            token_set: true,
            server: parking_lot::Mutex::new(Some(server)),
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

    /// Whether the accept loop is still running.
    pub fn is_running(&self) -> bool {
        self.server
            .lock()
            .as_ref()
            .map(ConnectionListener::is_running)
            .unwrap_or(false)
    }

    /// Request a graceful shutdown and wait for the accept loop to exit.
    /// Idempotent. Connections already being served finish on their own
    /// threads.
    pub fn stop(&self) {
        // Take the listener out first so the lock is released before the
        // (blocking) join of the accept loop.
        let mut server = self.server.lock().take();
        if let Some(server) = server.as_mut() {
            server.stop();
        }
    }

    /// Stop in one call (the handle is consumed).
    pub fn join(self) {
        self.stop();
    }
}

impl Drop for RpcServerHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The HTTP/WebSocket handler behind the server.
struct RpcHandler {
    token: Arc<str>,
}

impl Handler for RpcHandler {
    fn handle(&self, req: Request<Body>) -> Response<Body> {
        handle_http_request(req, &self.token)
    }

    /// Route a WebSocket upgrade: authenticate, then hand the connection to
    /// the JSON-RPC service. The framing, the limits, the keepalive and the
    /// closing handshake are the server's business.
    fn websocket(&self, req: &Request<Body>) -> WsUpgradeReply {
        // Browsers cannot set the Authorization header on a WebSocket
        // connection, so the token travels as `?token=...`.
        let presented = req
            .uri
            .query()
            .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("token=")));
        let Some(presented) = presented else {
            return WsUpgradeReply::Refuse(unauthorized("missing token"));
        };
        if !ct_eq(presented.as_bytes(), self.token.as_bytes()) {
            return WsUpgradeReply::Refuse(unauthorized("unauthorized"));
        }
        WsUpgradeReply::Accept(Arc::new(RpcWsService))
    }
}

/// One WebSocket connection: every message is one JSON-RPC request.
///
/// `on_message` runs on the connection's own thread, so a blocking dispatch
/// call delays only this connection.
struct RpcWsService;

impl WsService for RpcWsService {
    fn on_message(&self, conn: &mut WsConn, message: WsData) {
        let response = match message {
            WsData::Text(text) => process_payload(text.as_bytes()),
            WsData::Binary(data) => process_payload(&data),
        };
        if let Err(e) = conn.send_text(&response) {
            tracing::debug!("RPC WebSocket write failed: {e}");
            let _ = conn.close(1011, "send failed");
        }
    }
}

/// The WebSocket policy the server enforces.
fn ws_config() -> WsConfig {
    WsConfig {
        enabled: true,
        // Token in the URL is the authentication; a dashboard served from
        // another local port presents a foreign `Origin` by design.
        origin: OriginPolicy::Any,
        trusted_proxies: Vec::new(),
        subprotocols: Vec::new(),
        // JSON-RPC payloads are small and the peer is on loopback:
        // `permessage-deflate` would cost CPU and buy nothing.
        compression: PmDeflatePolicy {
            enabled: false,
            ..PmDeflatePolicy::default()
        },
        max_message: MAX_WS_MESSAGE,
        max_frame: MAX_WS_MESSAGE,
        ping_interval: Some(WS_PING_INTERVAL),
        ..WsConfig::default()
    }
}

/// Route a single HTTP request.
fn handle_http_request(req: Request<Body>, token: &str) -> Response<Body> {
    // CORS preflight for browser dashboards served from another origin.
    if req.method == Method::OPTIONS {
        return cors_response(StatusCode::NO_CONTENT);
    }

    let path = req.uri.path().to_string();

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

    // The server caps the body at `MAX_REQUEST_BODY` and answers an
    // oversized request with `413` before the handler runs; the check below
    // is the same bound expressed on the materialized body.
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

    json_response(StatusCode::OK, &process_payload(&body))
}

/// A `401` for a WebSocket upgrade the client is not allowed to make.
fn unauthorized(reason: &str) -> Response<Body> {
    json_response(
        StatusCode::UNAUTHORIZED,
        &format!(r#"{{"code":1,"error":"{reason}"}}"#),
    )
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
    let mut resp = Response::with_status(status);
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
    let mut resp = Response::with_status(status);
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
        // A request the server refuses (an oversized body) is answered and
        // then closed, so a client still streaming may see its connection
        // reset after the response: whatever arrived is what this helper
        // reports.
        let _ = stream.read_to_end(&mut resp);
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

        let status = read_handshake_head(&mut stream);
        (stream, status)
    }

    /// Read an HTTP response head, returning its status code.
    fn read_handshake_head(stream: &mut std::net::TcpStream) -> u16 {
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
        String::from_utf8_lossy(&head)
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    /// Encode one masked client text frame.
    fn masked_text_frame(data: &[u8]) -> Vec<u8> {
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
        frame
    }

    /// Send one masked text frame (client side).
    fn ws_send_text(stream: &mut std::net::TcpStream, data: &[u8]) {
        stream.write_all(&masked_text_frame(data)).unwrap();
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
        assert!(!h.is_running());
    }

    #[test]
    fn non_loopback_bind_is_refused() {
        let err = RpcServer::bind(
            SocketAddr::from(([0, 0, 0, 0], 0)),
            "test-token-123".to_string(),
        )
        .err()
        .expect("a wildcard bind must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
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

    /// A declared body larger than the cap is refused before a byte of it is
    /// read, so the client gets its `413` (and no body is buffered).
    #[test]
    fn oversize_body_is_rejected() {
        let h = spawn_test_server();
        let mut stream = std::net::TcpStream::connect(h.addr()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let head = format!(
            "POST /rpc HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer test-token-123\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            h.addr(),
            MAX_REQUEST_BODY + 1
        );
        stream.write_all(head.as_bytes()).unwrap();

        assert_eq!(read_handshake_head(&mut stream), 413);
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

        // Graceful close: the server completes the handshake.
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

    /// A frame pipelined with the upgrade request (sent in the same write)
    /// must be delivered — the reader keeps the bytes the handshake parser
    /// already buffered.
    #[test]
    fn pipelined_frame_after_upgrade_is_served() {
        let h = spawn_test_server();
        let mut stream = std::net::TcpStream::connect(h.addr()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let head = format!(
            "GET /ws?token=test-token-123 HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n",
            h.addr()
        );

        let mut request = head.into_bytes();
        request.extend_from_slice(&masked_text_frame(br#"{"method":"get_version"}"#));
        stream.write_all(&request).unwrap();

        // Consume the 101 head, then read the response frame.
        assert_eq!(read_handshake_head(&mut stream), 101);
        let (opcode, payload) = ws_read_frame(&mut stream);
        assert_eq!(opcode, 0x1);
        let parsed: nextjson::Value =
            nextjson::from_str(&String::from_utf8(payload).unwrap()).unwrap();
        assert_eq!(parsed.get("code").and_then(|v| v.as_i64()), Some(0));
        h.stop();
    }
}
