//! HTTP proxy inbound on courierust's server engine.
//!
//! This module owns the **single** HTTP proxy implementation of the
//! workspace: [`HttpProxyHandler`] is a [`Handler`], so both listeners in the
//! engine — [`HttpInbound`] (the `http` inbound) and
//! [`MixedInbound`](super::mixed::MixedInbound) (the `mixed` inbound, which
//! owns its accept loop to sniff SOCKS5) — run exactly the same request path
//! through [`serve_proxy_connection`]:
//!
//! * a plain proxy request (absolute-form URI, or origin-form with `Host`)
//!   reaches [`Handler::handle`] through courierust's HTTP/1.1 (and h2c)
//!   engine and is forwarded with correct re-framing ([`super::forward`]);
//! * a `CONNECT` request is answered `200` and the connection is relayed
//!   through the matched outbound.
//!
//! Framing, keep-alive, chunked bodies, the oversized-body `413` and the
//! hop-by-hop handling all come from courierust's server — there is no
//! hand-written HTTP parser here.
//!
//! # Why `CONNECT` is answered before the server engine sees it
//!
//! RFC 9110 §9.3.6 gives `CONNECT` an *authority-form* request target
//! (`host:port`). courierust's request-line parser accepts origin-form,
//! asterisk-form and absolute-form only, and answers `400` to anything else,
//! so the engine never reaches a handler for a `CONNECT` request. The
//! listener therefore peeks the first bytes of every connection without
//! consuming them: a `CONNECT` prologue is served by the bounded path below
//! (head parsed with courierust's own H/1 codec, then a raw relay), and
//! everything else is handed to [`serve_connection`] with the peeked bytes
//! untouched.
//!
//! Inbound authentication is enforced on every request **and** every
//! `CONNECT` tunnel (CWE-306) before anything is proxied.

use crate::common::listener::ConnectionListener;
use crate::common::stream::{BoxStream, SyncStream};
use crate::engine::config::InboundConfig;
use crate::engine::connection_tracker::{global_tracker, TrackedConnection};
use crate::engine::error::{Error, Result};
use crate::engine::inbound::auth::{check_proxy_authorization, InboundAuth};
use crate::engine::inbound::forward;
use crate::engine::inbound::{bind_tcp_listener, InboundListener};
use crate::engine::outbound::{OutboundManager, OutboundProxy, TargetAddr};
use crate::engine::routing::Router;
use courierust::courierust_body::Body;
use courierust::courierust_h1 as h1;
use courierust::courierust_http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version,
};
use courierust::courierust_io::{BufReader, SliceReader};
use courierust::courierust_server::{serve_connection, Handler, ServerConfig};
use parking_lot::Mutex;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Cap for a single request head (status line + header list).
pub(crate) const PROXY_MAX_HEAD: usize = 64 * 1024;
/// Cap for a single request body: what a proxy must be able to carry. A
/// larger body is answered `413` by the server before the handler runs.
pub(crate) const PROXY_MAX_BODY: usize = 64 * 1024 * 1024;
/// Read timeout for a proxy connection (request head and body).
pub(crate) const PROXY_READ_TIMEOUT: Duration = Duration::from_secs(300);
/// Budget for the first bytes of a connection (the protocol prologue).
pub(crate) const PROXY_PROLOGUE_TIMEOUT: Duration = Duration::from_secs(30);
/// Upper bound on concurrently open proxy connections: every `CONNECT`
/// tunnel occupies a thread of its own, so this bound is what keeps a herd
/// of idle clients from exhausting the process.
pub(crate) const PROXY_MAX_CONNECTIONS: usize = 2048;

/// The server configuration both proxy listeners run with.
pub(crate) fn proxy_server_config() -> ServerConfig {
    ServerConfig {
        read_timeout: Some(PROXY_READ_TIMEOUT),
        max_header_list: PROXY_MAX_HEAD,
        max_body: PROXY_MAX_BODY,
        http2: true,
        tls: None,
        handshake_timeout: None,
        idle_timeout: Some(Duration::from_secs(120)),
        max_connections: PROXY_MAX_CONNECTIONS,
        ..ServerConfig::default()
    }
}

/// Serve one accepted proxy connection.
///
/// The first bytes decide which engine runs: `CONNECT` needs the proxy to
/// answer a request form courierust's parser refuses, everything else is the
/// server's business.
pub(crate) fn serve_proxy_connection(
    stream: TcpStream,
    handler: &HttpProxyHandler,
    config: &ServerConfig,
) -> std::result::Result<(), String> {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(PROXY_PROLOGUE_TIMEOUT));
    let _ = stream.set_write_timeout(Some(PROXY_PROLOGUE_TIMEOUT));

    match peek_connect_head(&stream)? {
        Some(head_len) => {
            let _ = stream.set_read_timeout(Some(PROXY_READ_TIMEOUT));
            let _ = stream.set_write_timeout(Some(PROXY_READ_TIMEOUT));
            serve_connect(stream, handler, head_len)
        }
        None => serve_connection(stream, handler, config).map_err(|e| e.to_string()),
    }
}

/// The `CONNECT` method with its separating space — the shortest prologue
/// that identifies one.
const CONNECT_PREFIX: &[u8] = b"CONNECT ";

/// Peek the connection's head without consuming a byte.
///
/// Returns the head length (through the blank line) when the request is a
/// `CONNECT`, or `None` as soon as the prologue proves it is something else
/// — the server engine then reads the same bytes from the start, including
/// anything the client pipelined behind them.
fn peek_connect_head(stream: &TcpStream) -> std::result::Result<Option<usize>, String> {
    let mut probe = vec![0u8; PROXY_MAX_HEAD];
    let deadline = Instant::now() + PROXY_PROLOGUE_TIMEOUT;
    loop {
        let available = match stream.peek(&mut probe) {
            Ok(0) => return Ok(None), // the peer closed before saying anything
            Ok(n) => n,
            Err(e) => return Err(format!("failed to peek the request head: {e}")),
        };
        let prefix = &probe[..available];
        if prefix.starts_with(CONNECT_PREFIX) {
            if let Some(end) = find_subsequence(prefix, b"\r\n\r\n") {
                return Ok(Some(end + 4));
            }
        } else if available >= CONNECT_PREFIX.len() {
            return Ok(None);
        }
        if Instant::now() > deadline {
            return Err("timed out waiting for the request head".to_string());
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// Answer a `CONNECT` request and relay the connection.
///
/// The head is the only thing consumed, so payload the client pipelined
/// behind it (a TLS `ClientHello`, typically) reaches the relay untouched.
fn serve_connect(
    mut stream: TcpStream,
    handler: &HttpProxyHandler,
    head_len: usize,
) -> std::result::Result<(), String> {
    let mut head = vec![0u8; head_len];
    stream
        .read_exact(&mut head)
        .map_err(|e| format!("failed to read the CONNECT head: {e}"))?;
    let (authority, headers) = match parse_connect_head(&head) {
        Ok(parsed) => parsed,
        Err(e) => {
            tracing::warn!("Malformed CONNECT request: {e}");
            return write_text(&mut stream, StatusCode::BAD_REQUEST, "Bad Request");
        }
    };

    if !check_proxy_authorization(&headers, &handler.auth) {
        tracing::info!("Rejecting unauthenticated CONNECT request");
        return write_head(&mut stream, StatusCode::PROXY_AUTHENTICATION_REQUIRED, &[]);
    }
    let Some((host, port)) = parse_authority(authority) else {
        tracing::warn!("Invalid CONNECT target: {authority}");
        return write_text(
            &mut stream,
            StatusCode::BAD_REQUEST,
            "Invalid CONNECT request",
        );
    };

    let outbound_tag = handler
        .router
        .match_outbound(Some(&host), None, Some(port), None);
    let Some(outbound) = handler.outbound_manager.get_proxy(&outbound_tag) else {
        tracing::error!("Outbound '{outbound_tag}' not found");
        return write_text(
            &mut stream,
            StatusCode::BAD_GATEWAY,
            &format!("Outbound '{outbound_tag}' not found"),
        );
    };

    tracing::info!("CONNECT {host}:{port} -> {outbound_tag}");
    // `200 OK` and nothing else: from here on the connection carries opaque
    // bytes (RFC 9110 §9.3.6).
    write_head(&mut stream, StatusCode::OK, &[])?;

    ConnectRelay {
        outbound,
        outbound_tag,
        host,
        port,
        kind: handler.kind,
    }
    .relay(Box::new(stream));
    Ok(())
}

/// Parse a `CONNECT` request head: the authority-form request line plus the
/// header list.
///
/// The request line is split here rather than handed to
/// [`h1::parse_request_line`] because that parser accepts origin-, asterisk-
/// and absolute-form targets only — the reason this fast path exists at all.
/// Everything after the request line (the header block) is courierust's
/// parser.
fn parse_connect_head(head: &[u8]) -> std::result::Result<(&str, HeaderMap), String> {
    let line_end = head
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(|| "malformed request line".to_string())?;
    let line = trim_ows(&head[..line_end]);

    let mut parts = line.split(|&b| b == b' ');
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if method != b"CONNECT" || target.is_empty() || parts.next().is_some() {
        return Err("malformed CONNECT request line".to_string());
    }
    let version = h1::parse_version(version).map_err(|e| format!("malformed version: {e}"))?;
    if version != Version::HTTP_11 && version != Version::HTTP_10 {
        return Err("CONNECT requires HTTP/1.x".to_string());
    }
    let authority =
        std::str::from_utf8(target).map_err(|_| "non-ASCII CONNECT target".to_string())?;
    if authority.bytes().any(|b| b < 0x21 || b == 0x7f) {
        return Err("control character in the CONNECT target".to_string());
    }

    let mut reader = BufReader::new(SliceReader::new(&head[line_end + 1..]), head.len());
    let headers = h1::read_headers(&mut reader).map_err(|e| format!("malformed headers: {e}"))?;
    Ok((authority, headers))
}

/// Trim trailing CR/LF and optional whitespace from a line.
fn trim_ows(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && matches!(line[end - 1], b'\r' | b'\n' | b' ' | b'\t') {
        end -= 1;
    }
    &line[..end]
}

/// Write a response head (no body).
fn write_head(
    stream: &mut TcpStream,
    status: StatusCode,
    headers: &[(&'static str, &str)],
) -> std::result::Result<(), String> {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        map.append(
            HeaderName::from_static(name),
            HeaderValue::from_bytes(value.as_bytes())
                .map_err(|e| format!("invalid response header: {e}"))?,
        );
    }
    let mut out = Vec::with_capacity(128);
    h1::write_response_head(&mut out, status, Version::HTTP_11, &map)
        .map_err(|e| format!("failed to serialize the response head: {e}"))?;
    stream
        .write_all(&out)
        .and_then(|()| stream.flush())
        .map_err(|e| format!("failed to write the response head: {e}"))
}

/// Answer with a plain-text body and close.
fn write_text(
    stream: &mut TcpStream,
    status: StatusCode,
    message: &str,
) -> std::result::Result<(), String> {
    let length = message.len().to_string();
    write_head(
        stream,
        status,
        &[
            ("content-type", "text/plain; charset=utf-8"),
            ("content-length", &length),
            ("connection", "close"),
        ],
    )?;
    stream
        .write_all(message.as_bytes())
        .map_err(|e| format!("failed to write the response body: {e}"))
}

/// Relay one `CONNECT` tunnel through its outbound.
///
/// The blocking relay is the tunnel's whole lifetime on this thread.
struct ConnectRelay {
    outbound: Arc<dyn OutboundProxy>,
    outbound_tag: String,
    host: String,
    port: u16,
    kind: &'static str,
}

impl ConnectRelay {
    fn relay(&self, client: BoxStream) {
        let destination_ip =
            crate::common::socket::resolve_host(&self.host, self.port, Duration::from_secs(3))
                .ok()
                .and_then(|addrs| addrs.into_iter().next())
                .map(|addr| addr.ip().to_string());

        let tracker = global_tracker();
        let tracked = tracker.track(TrackedConnection::new_with_ip(
            self.kind.to_string(),
            self.outbound_tag.clone(),
            self.host.clone(),
            destination_ip,
            self.port,
            "HTTPS".to_string(),
            "tcp".to_string(),
            "HTTP-CONNECT".to_string(),
            format!("{}:{}", self.host, self.port),
        ));

        let result = self.outbound.relay_tcp_with_connection(
            client,
            TargetAddr::new_domain(self.host.clone(), self.port),
            Some(Arc::clone(&tracked)),
        );
        tracker.untrack(&tracked.id);
        if let Err(e) = result {
            tracing::warn!(
                "CONNECT relay via '{}' to {}:{} failed: {}",
                self.outbound_tag,
                self.host,
                self.port,
                e
            );
        }
    }
}

/// The HTTP proxy surface: authenticate, route, then forward.
///
/// Shared by the `http` and `mixed` inbounds; `kind` only labels the
/// connections they report to the tracker (`http` / `mixed`).
pub(crate) struct HttpProxyHandler {
    kind: &'static str,
    router: Arc<Router>,
    outbound_manager: Arc<OutboundManager>,
    auth: Arc<InboundAuth>,
}

impl HttpProxyHandler {
    /// Build the handler for one listener.
    pub(crate) fn new(
        kind: &'static str,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
        auth: Arc<InboundAuth>,
    ) -> Self {
        Self {
            kind,
            router,
            outbound_manager,
            auth,
        }
    }

    /// Forward a plain proxy request and return the origin's response.
    fn forward(&self, req: Request<Body>) -> Result<Response<Body>> {
        let (host, port) = parse_http_target(&req)
            .ok_or_else(|| Error::protocol("Invalid HTTP proxy request: missing host"))?;

        let outbound_tag = self
            .router
            .match_outbound(Some(&host), None, Some(port), None);
        tracing::info!("HTTP {} -> {}", req.uri.as_str(), outbound_tag);

        let outbound = self
            .outbound_manager
            .get_proxy(&outbound_tag)
            .ok_or_else(|| Error::config(format!("Outbound '{outbound_tag}' not found")))?;

        let method = req.method.clone();
        let path = req.uri.as_str().to_string();
        let is_head = method == Method::HEAD;

        let target = TargetAddr::new_domain(host.clone(), port);
        let (mut client_side, server_side) = forward::mem_duplex(64 * 1024);
        let relay_handle = std::thread::Builder::new()
            .name("corduit-http-relay".into())
            .spawn(move || outbound.relay_tcp(Box::new(server_side) as BoxStream, target))
            .map_err(|e| Error::network(format!("Failed to spawn relay thread: {e}")))?;
        let body = req.body.as_bytes().map(|b| b.to_vec()).unwrap_or_default();

        forward::send_request(
            &mut client_side,
            &method,
            &path,
            &req.headers,
            &host,
            port,
            &body,
        )?;

        client_side
            .shutdown(Shutdown::Write)
            .map_err(|e| Error::network(format!("Failed to shutdown write: {e}")))?;

        let response = forward::read_http_response(&mut client_side, is_head)?;
        let _ = relay_handle.join();
        Ok(response)
    }
}

impl Handler for HttpProxyHandler {
    fn handle(&self, req: Request<Body>) -> Response<Body> {
        if !check_proxy_authorization(&req.headers, &self.auth) {
            tracing::info!("Rejecting unauthenticated HTTP request");
            return proxy_auth_required();
        }

        match self.forward(req) {
            Ok(resp) => resp,
            Err(e) => {
                tracing::error!("HTTP proxy error: {}", e);
                error_response(StatusCode::BAD_GATEWAY, &format!("Proxy error: {e}"))
            }
        }
    }
}

/// HTTP proxy inbound listener.
pub struct HttpInbound {
    config: InboundConfig,
    router: Arc<Router>,
    outbound_manager: Arc<OutboundManager>,
    auth: Arc<InboundAuth>,
    running: Arc<AtomicBool>,
    server: Mutex<Option<ConnectionListener>>,
}

impl InboundListener for HttpInbound {
    fn start(&self) -> Result<()> {
        self.start_listener()
    }

    fn stop(&self) -> Result<()> {
        self.stop_listener()
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }
}

impl HttpInbound {
    /// Build the inbound. No socket is bound until [`start`](Self::start).
    pub fn new(
        config: InboundConfig,
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
        auth: Arc<InboundAuth>,
    ) -> Self {
        Self {
            config,
            router,
            outbound_manager,
            auth,
            running: Arc::new(AtomicBool::new(false)),
            server: Mutex::new(None),
        }
    }

    fn start_listener(&self) -> Result<()> {
        if self.running.load(Ordering::Relaxed) {
            tracing::warn!(
                "HTTP inbound already running on {}:{}",
                self.config.listen,
                self.config.port
            );
            return Ok(());
        }

        let (listener, addr) = bind_tcp_listener(&self.config.listen, self.config.port, "HTTP")?;
        let handler = Arc::new(HttpProxyHandler::new(
            "http",
            Arc::clone(&self.router),
            Arc::clone(&self.outbound_manager),
            Arc::clone(&self.auth),
        ));
        let server_config = Arc::new(proxy_server_config());

        let mut server = ConnectionListener::new(listener, addr, PROXY_MAX_CONNECTIONS);
        server
            .start("corduit-http-conn", move |stream, peer| {
                if let Err(e) = serve_proxy_connection(stream, &handler, &server_config) {
                    tracing::debug!("HTTP connection from {peer} ended: {e}");
                }
            })
            .map_err(|e| Error::network(format!("Failed to serve HTTP inbound on {addr}: {e}")))?;

        *self.server.lock() = Some(server);
        self.running.store(true, Ordering::Relaxed);
        tracing::info!("HTTP inbound listening on {addr}");
        Ok(())
    }

    fn stop_listener(&self) -> Result<()> {
        tracing::info!(
            "Stopping HTTP inbound on {}:{}",
            self.config.listen,
            self.config.port
        );
        let mut server = self.server.lock().take();
        if let Some(server) = server.as_mut() {
            server.stop();
        }
        self.running.store(false, Ordering::Relaxed);
        Ok(())
    }
}

/// `407 Proxy Authentication Required`, with the challenge a client needs to
/// retry with credentials.
fn proxy_auth_required() -> Response<Body> {
    let mut resp = Response::with_status(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    resp.headers.insert(
        HeaderName::from_static("proxy-authenticate"),
        HeaderValue::from_static("Basic realm=\"corduit\""),
    );
    resp.headers.insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp.body = Body::from(b"Proxy authentication required".to_vec());
    resp
}

/// Build a plain-text response.
pub(crate) fn error_response(status: StatusCode, message: &str) -> Response<Body> {
    let mut resp = Response::with_status(status);
    resp.headers.insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp.body = Body::from(message.as_bytes().to_vec());
    resp
}

/// Parse a CONNECT authority (`host:port` or `[v6]:port`).
pub(crate) fn parse_authority(authority: &str) -> Option<(String, u16)> {
    let authority = authority.trim_start_matches('/');
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some((host, suffix)) = rest.split_once(']') {
            let port = if let Some(p) = suffix.strip_prefix(':') {
                p.parse::<u16>().ok()?
            } else {
                443
            };
            return Some((host.to_string(), port));
        }
    }
    if let Some((host, port_str)) = authority.rsplit_once(':') {
        if !host.is_empty() && !host.contains(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return Some((host.to_string(), port));
            }
        }
        // A bare IPv6 address without brackets is invalid.
        return None;
    }
    if !authority.is_empty() {
        return Some((authority.to_string(), 443));
    }
    None
}

/// Parse an absolute-form proxy request target (`scheme://host[:port]/path`)
/// or fall back to the `Host` header of an origin-form request.
fn parse_http_target(req: &Request<Body>) -> Option<(String, u16)> {
    let target = req.uri.as_str();
    if let Some(rest) = target.strip_prefix("http://") {
        let (authority, _path) = split_authority_path(rest);
        return split_host_port(authority, 80);
    }
    if let Some(rest) = target.strip_prefix("https://") {
        let (authority, _path) = split_authority_path(rest);
        return split_host_port(authority, 443);
    }
    if let Some(host_header) = req.headers.get("host").and_then(|v| v.to_str().ok()) {
        return split_host_port(host_header.trim(), 80);
    }
    None
}

fn split_authority_path(rest: &str) -> (&str, &str) {
    match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    }
}

fn split_host_port(authority: &str, default_port: u16) -> Option<(String, u16)> {
    let authority = authority.trim();
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, suffix) = rest.split_once(']')?;
        let port = if let Some(p) = suffix.strip_prefix(':') {
            p.parse::<u16>().ok()?
        } else {
            default_port
        };
        return Some((host.to_string(), port));
    }
    if let Some((host, port_str)) = authority.rsplit_once(':') {
        if !host.contains(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return Some((host.to_string(), port));
            }
        }
        return None;
    }
    if authority.is_empty() {
        return None;
    }
    Some((authority.to_string(), default_port))
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_authority_forms() {
        assert_eq!(
            parse_authority("example.com:443"),
            Some(("example.com".to_string(), 443))
        );
        assert_eq!(
            parse_authority("example.com"),
            Some(("example.com".to_string(), 443))
        );
        assert_eq!(
            parse_authority("[2001:db8::1]:8443"),
            Some(("2001:db8::1".to_string(), 8443))
        );
        assert_eq!(
            parse_authority("[2001:db8::1]"),
            Some(("2001:db8::1".to_string(), 443))
        );
        assert_eq!(parse_authority("2001:db8::1"), None);
        assert_eq!(parse_authority(""), None);
    }

    #[test]
    fn parses_absolute_and_origin_form_targets() {
        let abs = Request::new(Method::GET, "http://example.com:8080/a?b=1");
        assert_eq!(
            parse_http_target(&abs),
            Some(("example.com".to_string(), 8080))
        );

        let mut origin = Request::new(Method::GET, "/a?b=1");
        origin.headers.insert(
            HeaderName::from_static("host"),
            HeaderValue::from_static("example.com"),
        );
        assert_eq!(
            parse_http_target(&origin),
            Some(("example.com".to_string(), 80))
        );

        let bare = Request::new(Method::GET, "/a");
        assert_eq!(parse_http_target(&bare), None);
    }

    #[test]
    fn parses_a_connect_head_with_the_codec() {
        let head = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic x\r\n\r\n";
        let (authority, headers) = parse_connect_head(head).expect("head parses");
        assert_eq!(authority, "example.com:443");
        assert_eq!(
            headers.get("host").and_then(|v| v.to_str().ok()),
            Some("example.com:443")
        );
        assert!(headers.contains_key("proxy-authorization"));
    }

    #[test]
    fn refuses_malformed_connect_heads() {
        assert!(parse_connect_head(b"GET / HTTP/1.1\r\n\r\n").is_err());
        assert!(parse_connect_head(b"CONNECT a:1 HTTP/1.1 extra\r\n\r\n").is_err());
        assert!(parse_connect_head(b"CONNECT a:1 HTTP/1.1\r\n\r\n").is_ok());
        assert!(parse_connect_head(b"CONNECT a:1 HTTP/1.1\r\n").is_err());
        assert!(parse_connect_head(b"CONNECT \x00a HTTP/1.1\r\n\r\n").is_err());
    }

    #[test]
    fn finds_the_head_terminator() {
        // "CONNECT a:443 HTTP/1.1" is 22 bytes: the blank line starts at 22.
        assert_eq!(
            find_subsequence(b"CONNECT a:443 HTTP/1.1\r\n\r\n", b"\r\n\r\n"),
            Some(22)
        );
        assert_eq!(find_subsequence(b"partial", b"\r\n\r\n"), None);
    }
}
