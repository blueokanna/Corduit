//! Localhost HTTP + WebSocket JSON-RPC server for web frontends.
//!
//! This transport exposes the **same** typed dispatch surface as the C ABI
//! ([`crate::rpc::dispatch`]) over a plain JSON wire format, so a browser
//! dashboard, a desktop GUI or any language with an HTTP/WebSocket stack can
//! drive the engine without linking Rust.
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::protocol::{Message, Role, WebSocketConfig};
use tokio_tungstenite::WebSocketStream;
use tokio_util::sync::CancellationToken;

use crate::crypto::util::ct_eq;

/// Maximum accepted JSON-RPC request body (config uploads can be large).
const MAX_REQUEST_BODY: usize = 16 * 1024 * 1024; // 16 MiB
/// Maximum accepted WebSocket message size.
const MAX_WS_MESSAGE: usize = 16 * 1024 * 1024; // 16 MiB
/// Upper bound on a single connection's lifetime. Bounds idle keep-alive
/// connections (resource hygiene); a dashboard never needs longer.
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

impl From<hyper::Error> for ServerError {
    fn from(e: hyper::Error) -> Self {
        ServerError(e.to_string())
    }
}

/// A bound (not yet started) RPC server.
pub struct RpcServer {
    listener: TcpListener,
    addr: SocketAddr,
    token: Arc<str>,
}

/// A running RPC server. Drop the task handle or call [`stop`](Self::stop) to
/// shut it down gracefully.
pub struct RpcServerHandle {
    addr: SocketAddr,
    token_set: bool,
    task: tokio::task::JoinHandle<()>,
    shutdown: CancellationToken,
    running: Arc<AtomicBool>,
}

impl RpcServer {
    /// Bind a TCP listener at `addr`. Use a loopback address (`127.0.0.1`,
    /// `::1`) — the server deliberately never binds to all interfaces.
    pub async fn bind(addr: SocketAddr, token: String) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let addr = listener.local_addr()?;
        Ok(Self {
            listener,
            addr,
            token: Arc::from(token.as_str()),
        })
    }

    /// The actual bound address (useful when binding to port `0`).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Spawn the accept loop on the current Tokio runtime and return a
    /// controller handle.
    pub fn spawn(self) -> RpcServerHandle {
        let shutdown = CancellationToken::new();
        let running = Arc::new(AtomicBool::new(false));
        let task_shutdown = shutdown.clone();
        let task_running = running.clone();
        let task = tokio::spawn(async move {
            accept_loop(self.listener, self.token, task_shutdown, task_running).await;
        });
        RpcServerHandle {
            addr: self.addr,
            token_set: true,
            task,
            shutdown,
            running,
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
        self.running.load(Ordering::SeqCst)
    }

    /// Request a graceful shutdown of the accept loop.
    pub fn stop(&self) {
        self.shutdown.cancel();
    }

    /// Wait for the accept loop task to finish.
    pub async fn join(self) {
        let _ = self.task.await;
    }
}

/// Accept loop: accept connections until cancelled, spawning one handler per
/// connection.
async fn accept_loop(
    listener: TcpListener,
    token: Arc<str>,
    shutdown: CancellationToken,
    running: Arc<AtomicBool>,
) {
    running.store(true, Ordering::SeqCst);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            res = listener.accept() => {
                match res {
                    Ok((stream, peer)) => {
                        let token = token.clone();
                        tokio::spawn(async move {
                            if let Err(e) = serve_connection(stream, &token).await {
                                tracing::debug!("RPC connection {peer} ended: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        if shutdown.is_cancelled() {
                            break;
                        }
                        tracing::debug!("RPC accept error: {e}");
                        // Transient accept errors (e.g. EMFILE) — back off and
                        // keep serving instead of spinning.
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
        }
    }
    running.store(false, Ordering::SeqCst);
}

/// Serve one connection: HTTP/1.1 with WebSocket upgrade support.
async fn serve_connection(stream: TcpStream, token: &str) -> Result<(), ServerError> {
    let io = TokioIo::new(stream);
    let token = token.to_string();
    let service = service_fn(move |req: Request<Incoming>| {
        let token = token.clone();
        async move { handle_request(req, &token).await }
    });
    let conn = http1::Builder::new()
        .keep_alive(true)
        .serve_connection(io, service)
        .with_upgrades();
    // Bound the connection lifetime so idle keep-alive sockets cannot pile up.
    match tokio::time::timeout(CONNECTION_LIFETIME, conn).await {
        Ok(result) => Ok(result?),
        Err(_) => Ok(()), // idle for too long — drop the connection
    }
}

/// Route a single HTTP request (or WebSocket upgrade).
async fn handle_request(
    mut req: Request<Incoming>,
    token: &str,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, ServerError> {
    // CORS preflight for browser dashboards served from another origin.
    if req.method() == Method::OPTIONS {
        return Ok(cors_response(StatusCode::NO_CONTENT, Bytes::new()));
    }

    let path = req.uri().path().to_string();

    if is_websocket_upgrade(&req) {
        return handle_websocket_upgrade(&mut req, token).await;
    }

    // Unauthenticated health probe (no sensitive data).
    if req.method() == Method::GET && path == "/health" {
        return Ok(json_response(StatusCode::OK, r#"{"ok":true}"#));
    }

    // Only `POST /rpc` is the JSON-RPC endpoint.
    if req.method() != Method::POST || path != "/rpc" {
        return Ok(json_response(
            StatusCode::NOT_FOUND,
            r#"{"code":1,"error":"not found"}"#,
        ));
    }

    // Bearer-token authorization (constant-time comparison).
    let authorized = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| ct_eq(t.as_bytes(), token.as_bytes()))
        .unwrap_or(false);
    if !authorized {
        return Ok(json_response(
            StatusCode::UNAUTHORIZED,
            r#"{"code":1,"error":"unauthorized"}"#,
        ));
    }

    let body = match read_bounded(req.into_body()).await {
        Ok(b) => b,
        Err(()) => {
            return Ok(json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                r#"{"code":1,"error":"request too large"}"#,
            ))
        }
    };

    let response = process_payload(&body).await;
    Ok(json_response(StatusCode::OK, &response))
}

/// Handle a WebSocket upgrade request after token validation.
async fn handle_websocket_upgrade(
    req: &mut Request<Incoming>,
    token: &str,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, ServerError> {
    // Browsers cannot set the Authorization header on WebSocket connections,
    // so the token is carried as `?token=...` in the request URI.
    let query_token = req.uri().query().and_then(|q| {
        q.split('&')
            .find_map(|kv| kv.strip_prefix("token="))
            .map(|v| v.to_string())
    });
    let Some(query_token) = query_token else {
        return Ok(json_response(
            StatusCode::UNAUTHORIZED,
            r#"{"code":1,"error":"missing token"}"#,
        ));
    };
    if !ct_eq(query_token.as_bytes(), token.as_bytes()) {
        return Ok(json_response(
            StatusCode::UNAUTHORIZED,
            r#"{"code":1,"error":"unauthorized"}"#,
        ));
    }

    // RFC 6455 requires the client key to compute the accept value.
    let ws_key = req
        .headers()
        .get(hyper::header::SEC_WEBSOCKET_KEY)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let Some(ws_key) = ws_key else {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            r#"{"code":1,"error":"missing Sec-WebSocket-Key"}"#,
        ));
    };

    // `hyper::upgrade::on` returns an `OnUpgrade` future that resolves once the
    // upgrade is performed — which happens *after* this service returns the 101
    // response. Awaiting it here would deadlock, so it is spawned instead.
    let on_upgrade = hyper::upgrade::on(req);
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                if let Err(e) = run_websocket(upgraded).await {
                    tracing::debug!("RPC WebSocket closed: {e}");
                }
            }
            Err(e) => tracing::debug!("RPC WebSocket upgrade failed: {e}"),
        }
    });

    let accept = websocket_accept(&ws_key);
    Ok(Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(hyper::header::CONNECTION, "Upgrade")
        .header(hyper::header::UPGRADE, "websocket")
        .header(hyper::header::SEC_WEBSOCKET_ACCEPT, accept)
        .body(empty_body())
        .expect("static response body"))
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

/// Run the WebSocket message loop: every message is one JSON-RPC request.
/// The token was already validated during the upgrade handshake.
async fn run_websocket(upgraded: hyper::upgrade::Upgraded) -> Result<(), ServerError> {
    let ws_config = WebSocketConfig::default()
        .max_message_size(Some(MAX_WS_MESSAGE))
        .max_frame_size(Some(MAX_WS_MESSAGE));
    let mut ws =
        WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, Some(ws_config))
            .await;

    while let Some(msg) = ws.next().await {
        let msg = msg.map_err(|e| ServerError(format!("websocket read: {e}")))?;
        match msg {
            Message::Text(text) => {
                let resp = process_payload(text.as_bytes()).await;
                ws.send(Message::text(resp))
                    .await
                    .map_err(|e| ServerError(format!("websocket write: {e}")))?;
            }
            Message::Binary(bin) => {
                let resp = process_payload(&bin).await;
                ws.send(Message::text(resp))
                    .await
                    .map_err(|e| ServerError(format!("websocket write: {e}")))?;
            }
            Message::Ping(payload) => {
                ws.send(Message::Pong(payload))
                    .await
                    .map_err(|e| ServerError(format!("websocket pong: {e}")))?;
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
    Ok(())
}

/// Parse one JSON-RPC payload and produce the JSON response string.
async fn process_payload(body: &[u8]) -> String {
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
    let result = crate::rpc::dispatch(method, &params).await;
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

/// Read a request body, rejecting anything above [`MAX_REQUEST_BODY`].
async fn read_bounded(body: Incoming) -> Result<Bytes, ()> {
    let limited = Limited::new(body, MAX_REQUEST_BODY);
    match limited.collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(_) => Err(()),
    }
}

fn is_websocket_upgrade(req: &Request<Incoming>) -> bool {
    let upgrade_header = req
        .headers()
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    let connection_header = req
        .headers()
        .get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        });
    // Hyper only performs the upgrade when the request carries both headers;
    // otherwise our 101 response would never be followed by an upgraded IO.
    upgrade_header && connection_header
}

fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// Build a JSON response with permissive CORS headers (localhost-only
/// service, token-gated).
fn json_response(status: StatusCode, body: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        .header(
            "Access-Control-Allow-Headers",
            "Authorization, Content-Type",
        )
        .header("Access-Control-Max-Age", "86400")
        .body(
            Full::new(Bytes::from(body.to_string()))
                .map_err(|never| match never {})
                .boxed(),
        )
        .expect("static response")
}

/// Build a CORS preflight response.
fn cors_response(status: StatusCode, body: Bytes) -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(status)
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        .header(
            "Access-Control-Allow-Headers",
            "Authorization, Content-Type",
        )
        .header("Access-Control-Max-Age", "86400")
        .body(Full::new(body).map_err(|never| match never {}).boxed())
        .expect("static response")
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn spawn_test_server() -> RpcServerHandle {
        let server = RpcServer::bind(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            "test-token-123".to_string(),
        )
        .await
        .expect("bind");
        server.spawn()
    }

    async fn post_rpc(addr: SocketAddr, token: Option<&str>, body: &str) -> (StatusCode, String) {
        let client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build_http();
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(format!("http://{addr}/rpc"))
            .header(CONTENT_TYPE, "application/json");
        if let Some(t) = token {
            builder = builder.header(AUTHORIZATION, format!("Bearer {t}"));
        }
        let req = builder
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap();
        let resp = client.request(req).await.expect("request");
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    #[tokio::test]
    async fn health_endpoint_is_open() {
        let h = spawn_test_server().await;
        let client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build_http();
        let resp = client
            .request(
                Request::builder()
                    .uri(format!("http://{}/health", h.addr()))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&bytes).contains("\"ok\":true"));
        h.stop();
    }

    #[tokio::test]
    async fn http_rpc_requires_token() {
        let h = spawn_test_server().await;
        // No token -> 401
        let (status, body) = post_rpc(h.addr(), None, r#"{"method":"get_version"}"#).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(body.contains("unauthorized"));
        // Wrong token -> 401
        let (status, _) = post_rpc(h.addr(), Some("wrong"), r#"{"method":"get_version"}"#).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        h.stop();
    }

    #[tokio::test]
    async fn http_rpc_dispatch_roundtrip() {
        let h = spawn_test_server().await;
        let (status, body) = post_rpc(
            h.addr(),
            Some("test-token-123"),
            r#"{"method":"get_version"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let parsed: nextjson::Value = nextjson::from_str(&body).unwrap();
        assert_eq!(parsed.get("code").and_then(|v| v.as_i64()), Some(0));
        assert!(parsed.get("data").is_some());
        h.stop();
    }

    #[tokio::test]
    async fn http_rpc_unknown_method_is_error() {
        let h = spawn_test_server().await;
        let (status, body) = post_rpc(
            h.addr(),
            Some("test-token-123"),
            r#"{"method":"no_such_method"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK); // transport-level OK, logical error
        let parsed: nextjson::Value = nextjson::from_str(&body).unwrap();
        assert_eq!(parsed.get("code").and_then(|v| v.as_i64()), Some(1));
        assert!(parsed.get("error").and_then(|v| v.as_str()).is_some());
        h.stop();
    }

    #[tokio::test]
    async fn oversize_body_is_rejected() {
        let h = spawn_test_server().await;
        let big = format!(
            r#"{{"method":"x","params":{{"pad":"{}"}}}}"#,
            "a".repeat(MAX_REQUEST_BODY + 1)
        );
        let (status, _) = post_rpc(h.addr(), Some("test-token-123"), &big).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        h.stop();
    }

    #[tokio::test]
    async fn websocket_roundtrip() {
        let h = spawn_test_server().await;
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let uri = format!("ws://{}/ws?token=test-token-123", h.addr());
        let req = uri.into_client_request().unwrap();
        let (mut ws, _) = tokio_tungstenite::connect_async(req)
            .await
            .expect("connect");
        ws.send(Message::text(r#"{"method":"get_version"}"#))
            .await
            .unwrap();
        let msg = ws.next().await.unwrap().unwrap();
        let text = msg.into_text().unwrap();
        let parsed: nextjson::Value = nextjson::from_str(&text).unwrap();
        assert_eq!(parsed.get("code").and_then(|v| v.as_i64()), Some(0));
        ws.send(Message::Close(None)).await.unwrap();
        h.stop();
    }

    #[tokio::test]
    async fn websocket_rejects_bad_token() {
        let h = spawn_test_server().await;
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let uri = format!("ws://{}/ws?token=wrong", h.addr());
        let req = uri.into_client_request().unwrap();
        let res = tokio_tungstenite::connect_async(req).await;
        assert!(res.is_err(), "connection with a bad token must be refused");
        h.stop();
    }
}
