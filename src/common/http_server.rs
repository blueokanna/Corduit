//! A small blocking HTTP/1.1 server built on courierust's H/1 codec and TLS.
//!
//! courierust ships a complete [`Server`](courierust::courierust_server::Server),
//! but Corduit's own servers (DoH, DoT, RPC, proxy inbound) need three things
//! the built-in server does not expose:
//!
//! * **graceful stop** — close the accept loop on demand (a long-lived
//!   library must be able to tear its listeners down);
//! * **a synchronous handler** that bridges into the tokio engine (the
//!   handler runs on a dedicated thread and `block_on`s the engine);
//! * **predictable per-connection threads** — long-lived connections (a
//!   proxy CONNECT tunnel, a WebSocket) occupy one thread each, which is a
//!   deliberate, documented trade of the blocking model.
//!
//! So this module owns a tiny accept loop and speaks HTTP/1.1 through
//! courierust's public building blocks: [`courierust_h1`] for framing and
//! [`courierust_tls::TlsAcceptor`] for TLS. Keep-alive is honoured (a
//! `Connection: close` from either side ends the connection); bodies are
//! materialized in memory with a hard cap, matching the engine's other
//! bounded-buffer guarantees.

use courierust::courierust_error::{Error as CourierError, ErrorKind as CourierErrorKind};
use courierust::courierust_h1 as h1;
use courierust::courierust_http::{
    Body, HeaderName, HeaderValue, Request, Response, StatusCode, Version,
};
use courierust::courierust_io::{BufReader, Read as CRead, Write as CWrite};
use courierust::courierust_tls::{TlsAcceptor, TlsStream, TlsVersion};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::common::roots::{base64_decode, parse_pem_bundle};

/// Default cap for a single request head (status line + headers).
pub const DEFAULT_MAX_HEAD: usize = 64 * 1024;
/// Default cap for a single request body.
pub const DEFAULT_MAX_BODY: usize = 64 * 1024 * 1024;
/// Default read timeout for connections.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(120);
/// Default accept-loop poll interval (only used while idle).
const ACCEPT_POLL: Duration = Duration::from_millis(5);
/// Read idle bound while draining a rejected (oversized) body.
const DRAIN_TIMEOUT: Duration = Duration::from_millis(200);
/// Hard wall-clock bound for a reject-drain (a misbehaving client that
/// keeps streaming is dropped after this).
const DRAIN_DEADLINE: Duration = Duration::from_secs(5);

/// A server TLS identity (certificate chain + private key).
#[derive(Debug, Clone)]
pub struct TlsIdentity {
    /// DER-encoded certificate chain, leaf first.
    pub cert_chain: Vec<Vec<u8>>,
    /// PKCS#8 or PKCS#1 DER private key.
    pub private_key: Vec<u8>,
    /// Whether the private key is an RSA key.
    pub is_rsa: bool,
}

impl TlsIdentity {
    /// Load an identity from PEM files (`cert` may contain a chain; `key` is
    /// a PKCS#8 / PKCS#1 / SEC1 private key).
    pub fn from_pem_files(cert_path: &str, key_path: &str) -> std::io::Result<Self> {
        let cert_pem = std::fs::read_to_string(cert_path)?;
        let key_pem = std::fs::read_to_string(key_path)?;
        Self::from_pem(&cert_pem, &key_pem)
    }

    /// Parse a PEM certificate chain and a PEM private key.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> std::io::Result<Self> {
        let cert_chain = parse_pem_bundle(cert_pem)?;
        if cert_chain.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "no certificates found in PEM input",
            ));
        }
        let (private_key, is_rsa) = parse_private_key_pem(key_pem)?;
        Ok(Self {
            cert_chain,
            private_key,
            is_rsa,
        })
    }
}

/// The RSA OID (`1.2.840.113549.1.1.1`) as it appears in a PKCS#8
/// AlgorithmIdentifier.
const RSA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// Parse a PEM private key, returning `(der, is_rsa)`.
fn parse_private_key_pem(pem: &str) -> std::io::Result<(Vec<u8>, bool)> {
    const PKCS8: &str = "-----BEGIN PRIVATE KEY-----";
    const PKCS8_END: &str = "-----END PRIVATE KEY-----";
    const RSA1: &str = "-----BEGIN RSA PRIVATE KEY-----";
    const RSA1_END: &str = "-----END RSA PRIVATE KEY-----";
    const EC1: &str = "-----BEGIN EC PRIVATE KEY-----";
    const EC1_END: &str = "-----END EC PRIVATE KEY-----";

    if let Some(block) = extract_block(pem, PKCS8, PKCS8_END) {
        let der = base64_decode(&block)?;
        // PKCS#8 wraps an algorithm identifier; sniff the RSA OID.
        let is_rsa = contains_oid(&der, RSA_OID);
        return Ok((der, is_rsa));
    }
    if let Some(block) = extract_block(pem, RSA1, RSA1_END) {
        return Ok((base64_decode(&block)?, true));
    }
    if let Some(block) = extract_block(pem, EC1, EC1_END) {
        return Ok((base64_decode(&block)?, false));
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "no supported private key (PKCS#8 / PKCS#1 RSA / SEC1 EC) found in PEM input",
    ))
}

/// Extract the base64 body of a PEM block between `begin` and `end`.
fn extract_block(pem: &str, begin: &str, end: &str) -> Option<String> {
    let start = pem.find(begin)?;
    let after = &pem[start + begin.len()..];
    let finish = after.find(end)?;
    Some(after[..finish].to_string())
}

/// Scan `der` for the exact OID byte sequence (used to sniff the PKCS#8
/// key algorithm; RSA is `is_rsa = true`, everything else is not).
fn contains_oid(der: &[u8], oid: &[u8]) -> bool {
    if oid.is_empty() || der.len() < oid.len() {
        return false;
    }
    der.windows(oid.len()).any(|w| w == oid)
}

/// A transport that is either a plain TCP socket or a TLS stream, shared
/// between the reader and writer via `Arc` (the same shape the blocking-IO
/// bridge and the client use). Public so a CONNECT-tunnel handler can wrap
/// it in a [`crate::common::BlockingStream`].
#[allow(clippy::large_enum_variant)] // the TLS variant legitimately owns a handshake object
pub enum RawConnection {
    /// A plain TCP socket.
    Plain(Arc<TcpStream>),
    /// A TLS stream over the same socket.
    Tls(TlsStream<Arc<TcpStream>, Arc<TcpStream>>),
}

impl CRead for RawConnection {
    fn read(&mut self, buf: &mut [u8]) -> courierust::Result<usize> {
        match self {
            RawConnection::Plain(s) => CRead::read(s, buf),
            RawConnection::Tls(t) => CRead::read(t, buf),
        }
    }
}

impl CWrite for RawConnection {
    fn write(&mut self, buf: &[u8]) -> courierust::Result<usize> {
        match self {
            RawConnection::Plain(s) => CWrite::write(s, buf),
            RawConnection::Tls(t) => CWrite::write(t, buf),
        }
    }

    fn flush(&mut self) -> courierust::Result<()> {
        match self {
            RawConnection::Plain(s) => CWrite::flush(s),
            RawConnection::Tls(t) => CWrite::flush(t),
        }
    }
}

/// A synchronous HTTP request handler.
pub trait Handler: Send + Sync + 'static {
    /// Handle one request and produce a response.
    fn handle(&self, req: Request<Body>) -> Response<Body>;
}

impl<F> Handler for F
where
    F: Fn(Request<Body>) -> Response<Body> + Send + Sync + 'static,
{
    fn handle(&self, req: Request<Body>) -> Response<Body> {
        self(req)
    }
}

/// Marker header set by a handler to hand the raw connection to the
/// [`TunnelHandler`] after the response is written (proxy CONNECT). The
/// header is stripped before the response reaches the client.
pub(crate) const TUNNEL_MARKER: &str = "x-corduit-raw-upgrade";

/// Handles a raw connection handed off after an HTTP response (used for
/// proxy CONNECT tunnels). The connection is blocking; wrap it in a
/// [`crate::common::BlockingStream`] to relay it through the async engine.
pub trait TunnelHandler: Send + Sync + 'static {
    /// Take ownership of the raw connection and relay it.
    fn handle_tunnel(&self, conn: RawConnection);
}

impl<F> TunnelHandler for F
where
    F: Fn(RawConnection) + Send + Sync + 'static,
{
    fn handle_tunnel(&self, conn: RawConnection) {
        self(conn)
    }
}

/// Server configuration.
#[derive(Clone)]
pub struct HttpServerConfig {
    /// Address to bind.
    pub listen: SocketAddr,
    /// Optional TLS identity; when set the server accepts HTTPS.
    pub tls: Option<TlsIdentity>,
    /// TLS versions to negotiate (server).
    pub min_version: TlsVersion,
    pub max_version: TlsVersion,
    /// Maximum request head size.
    pub max_head: usize,
    /// Maximum request body size.
    pub max_body: usize,
    /// Per-connection read timeout (also bounds the TLS handshake).
    pub read_timeout: Option<Duration>,
    /// The synchronous handler.
    pub handler: Arc<dyn Handler>,
    /// Optional raw-tunnel handler (proxy CONNECT).
    pub tunnel_handler: Option<Arc<dyn TunnelHandler>>,
}

impl HttpServerConfig {
    /// Build a shared acceptor (the ticket key is fixed at construction, so
    /// resumption sessions survive across connections on this server).
    fn server_tls_acceptor(&self) -> Option<Arc<TlsAcceptor>> {
        self.tls.as_ref().map(|id| {
            Arc::new(TlsAcceptor::new(courierust::courierust_tls::ServerConfig {
                identity: courierust::courierust_tls::Identity {
                    cert_chain: id.cert_chain.clone(),
                    private_key: id.private_key.clone(),
                    is_rsa: id.is_rsa,
                },
                alpn: Vec::new(),
                min_version: self.min_version,
                max_version: self.max_version,
                session_ticket_key: None,
            }))
        })
    }
}

/// A runnable HTTP server with graceful stop.
pub struct HttpServer {
    config: HttpServerConfig,
    listener: Option<TcpListener>,
    shutdown: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl HttpServer {
    /// Bind (but do not yet serve) a server on `config.listen`.
    pub fn bind(config: HttpServerConfig) -> std::io::Result<Self> {
        let listener = TcpListener::bind(config.listen)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            config,
            listener: Some(listener),
            shutdown: Arc::new(AtomicBool::new(false)),
            running: Arc::new(AtomicBool::new(false)),
            handle: None,
        })
    }

    /// Whether the accept loop is currently running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// The bound address (useful when `listen` port was 0).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener
            .as_ref()
            .ok_or_else(|| std::io::Error::other("server not bound"))?
            .local_addr()
    }

    /// Start the accept loop on a background thread.
    pub fn start(&mut self) -> std::io::Result<()> {
        if self.handle.is_some() {
            return Ok(()); // already running
        }
        let listener = self
            .listener
            .take()
            .ok_or_else(|| std::io::Error::other("server already started"))?;
        let shutdown = self.shutdown.clone();
        let running = self.running.clone();
        let config = self.config.clone();
        running.store(true, Ordering::SeqCst);
        let handle = std::thread::Builder::new()
            .name("corduit-http-accept".into())
            .spawn(move || accept_loop(listener, config, shutdown, running))
            .expect("spawn corduit-http-accept");
        self.handle = Some(handle);
        Ok(())
    }

    /// Request a graceful stop. In-flight connections finish their current
    /// request; the accept loop exits.
    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Block until the accept loop has exited.
    pub fn join(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }

    /// Stop and join in one call.
    pub fn shutdown(&mut self) {
        self.stop();
        self.join();
    }
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn accept_loop(
    listener: TcpListener,
    config: HttpServerConfig,
    shutdown: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
) {
    let tls_acceptor = config.server_tls_acceptor();
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                let handler = config.handler.clone();
                let tls_acceptor = tls_acceptor.clone();
                let read_timeout = config.read_timeout;
                let max_head = config.max_head;
                let max_body = config.max_body;
                let tunnel_handler = config.tunnel_handler.clone();
                // One thread per connection: connections may live for the
                // whole duration of a tunnel / WebSocket.
                std::thread::Builder::new()
                    .name("corduit-http-conn".into())
                    .spawn(move || {
                        let _ = handle_connection(
                            stream,
                            handler.as_ref(),
                            tunnel_handler.as_deref(),
                            tls_acceptor.as_deref(),
                            read_timeout,
                            max_head,
                            max_body,
                        );
                    })
                    .ok();
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL);
            }
            Err(_) => break,
        }
    }
    running.store(false, Ordering::SeqCst);
}

fn handle_connection(
    stream: TcpStream,
    handler: &dyn Handler,
    tunnel_handler: Option<&dyn TunnelHandler>,
    tls_acceptor: Option<&TlsAcceptor>,
    read_timeout: Option<Duration>,
    max_head: usize,
    max_body: usize,
) -> Result<(), String> {
    // Accepted sockets inherit the listener's non-blocking mode on Windows,
    // which would make `SO_RCVTIMEO` ineffective (reads return WouldBlock
    // the instant no data is buffered). Force blocking so the timeouts below
    // actually bound each read.
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(read_timeout);
    let _ = stream.set_write_timeout(read_timeout);

    let stream = Arc::new(stream);
    let mut conn = match tls_acceptor {
        Some(acceptor) => {
            let tls = acceptor
                .accept(stream.clone(), stream.clone())
                .map_err(|e| format!("TLS handshake: {e}"))?;
            RawConnection::Tls(tls)
        }
        None => RawConnection::Plain(stream),
    };

    // Keep-alive loop. A response carrying the raw-upgrade marker ends the
    // HTTP exchange and hands the connection to the tunnel handler.
    loop {
        let req = match read_request(&mut conn, max_head, max_body) {
            Ok(Some(req)) => req,
            Ok(None) => return Ok(()), // clean close
            Err(ReadError::Oversized) => {
                // Reject an oversized body explicitly instead of silently
                // truncating it — the 413 lets clients distinguish "too big"
                // from "malformed".
                let resp = error_response(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
                let _ = write_response(&mut conn, &resp);
                // Drain the unread remainder before closing. Closing with
                // unread receive data makes the stack emit RST instead of
                // FIN, which can abort a client still streaming the body
                // before it has read the 413. Only plain sockets can have
                // their read timeout adjusted cheaply; for TLS the 413 is
                // sent and the socket is closed as-is (real HTTP/2+ clients
                // handle a post-response close fine).
                let drain_socket = match &conn {
                    RawConnection::Plain(s) => Some(s.clone()),
                    RawConnection::Tls(_) => None,
                };
                if let Some(socket) = drain_socket {
                    let _ = socket.set_read_timeout(Some(DRAIN_TIMEOUT));
                    let mut buf = [0u8; 8192];
                    let deadline = std::time::Instant::now() + DRAIN_DEADLINE;
                    while std::time::Instant::now() < deadline {
                        match CRead::read(&mut conn, &mut buf) {
                            Ok(0) => break,    // client closed
                            Ok(_) => continue, // keep discarding
                            Err(_) => break,   // idle => client stopped
                        }
                    }
                }
                return Ok(());
            }
        };
        let keep_alive = request_keeps_alive(&req);
        let resp = handler.handle(req);

        let wants_tunnel = resp.headers.contains_key(TUNNEL_MARKER) && tunnel_handler.is_some();
        // Strip the marker so it never reaches the client.
        let mut resp = resp;
        resp.headers.remove(TUNNEL_MARKER);
        write_response(&mut conn, &resp).map_err(|e| format!("write response: {e}"))?;

        if wants_tunnel {
            tunnel_handler.expect("checked above").handle_tunnel(conn);
            return Ok(());
        }
        if !keep_alive || response_wants_close(&resp) {
            break;
        }
    }
    Ok(())
}

/// A request-head/body read failure that the connection loop must act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadError {
    /// The declared body length exceeded the configured cap.
    Oversized,
}

/// Read one request.
///
/// Returns `Ok(None)` on a clean connection close before any byte (and on
/// any malformed/unreadable request, which is treated as a close), or
/// `Err(ReadError::Oversized)` when the declared body length exceeds
/// `max_body`.
fn read_request<S: CRead + CWrite>(
    conn: &mut S,
    max_head: usize,
    max_body: usize,
) -> Result<Option<Request<Body>>, ReadError> {
    let mut reader = BufReader::new(conn, 8192);
    let line = match reader.read_until(b'\n', max_head) {
        Ok(line) => line,
        Err(_) => return Ok(None),
    };
    if line.is_empty() {
        return Ok(None); // clean close
    }
    let line = trim_crlf(&line);
    let req_line = match h1::parse_request_line(line) {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };

    let headers = match h1::read_headers(&mut reader) {
        Ok(h) => h,
        Err(_) => return Ok(None),
    };

    let body = match h1::body_length(&headers, Some(&req_line.method), None) {
        Ok(h1::BodyLen::Length(n)) => {
            if n > max_body {
                return Err(ReadError::Oversized);
            }
            match reader.read_exact(n) {
                Ok(b) => b,
                Err(_) => return Ok(None),
            }
        }
        Ok(h1::BodyLen::Chunked) => match h1::read_body_chunked(&mut reader, max_body) {
            Ok(b) => b.to_vec(),
            Err(_) => return Ok(None),
        },
        Ok(h1::BodyLen::None) => Vec::new(),
        Err(_) => return Ok(None),
    };

    Ok(Some(Request {
        method: req_line.method,
        uri: req_line.target,
        version: req_line.version,
        headers,
        body: Body::from(body),
    }))
}

/// Write a response head + body over the connection.
fn write_response<S: CRead + CWrite>(
    conn: &mut S,
    resp: &Response<Body>,
) -> Result<(), CourierError> {
    let mut out = Vec::new();
    let mut headers = resp.headers.clone();
    // Ensure a framing header exists for a materialized body (keep-alive
    // depends on it). Handlers may set their own Content-Length.
    if !headers.contains_key("content-length") && !headers.contains_key("transfer-encoding") {
        match &resp.body {
            Body::Bytes(b) => {
                headers.insert(
                    HeaderName::from_static("content-length"),
                    HeaderValue::from(b.len().to_string()),
                );
            }
            Body::Empty => {}
        }
    }
    h1::write_response_head(&mut out, resp.status, resp.version, &headers)?;
    match &resp.body {
        Body::Bytes(b) => out.extend_from_slice(b),
        Body::Empty => {}
    }
    write_all_bytes(conn, &out)?;
    CWrite::flush(conn)
}

/// Whether the request asks to keep the connection alive.
fn request_keeps_alive(req: &Request<Body>) -> bool {
    match req.headers.get("connection").and_then(|v| v.to_str().ok()) {
        Some(v) if v.eq_ignore_ascii_case("close") => false,
        Some(v) if v.eq_ignore_ascii_case("keep-alive") => true,
        _ => req.version == Version::HTTP_11,
    }
}

/// Whether the response asks to close the connection.
fn response_wants_close(resp: &Response<Body>) -> bool {
    resp.headers
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("close"))
        .unwrap_or(false)
}

fn write_all_bytes<W: CWrite>(writer: &mut W, mut data: &[u8]) -> Result<(), CourierError> {
    while !data.is_empty() {
        match CWrite::write(writer, data) {
            Ok(0) => return Err(CourierError::new(CourierErrorKind::Io)),
            Ok(n) => data = &data[n..],
            Err(e) if matches!(e.kind, CourierErrorKind::WouldBlock) => {
                std::thread::yield_now();
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn trim_crlf(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// Build a minimal error response (used by the DNS/RPC layers).
pub fn error_response(status: StatusCode, message: &str) -> Response<Body> {
    let mut resp = Response::new(status);
    resp.headers.insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp.body = Body::from(message.as_bytes().to_vec());
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use courierust::courierust_http::Method;
    use std::io::{Read as _, Write as _};

    #[test]
    fn parses_private_key_pem() {
        // A structurally valid PKCS#8 RSA key (version + AlgorithmIdentifier
        // carrying the rsaEncryption OID + an empty key blob). DER:
        //   30 14 02 01 00 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 04 00
        let der: &[u8] = &[
            0x30, 0x14, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
            0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x00,
        ];
        let b64 = test_b64(der);
        let pkcs8 = format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n");
        let (parsed_der, is_rsa) = parse_private_key_pem(&pkcs8).unwrap();
        assert!(is_rsa);
        assert_eq!(parsed_der, der);

        // A non-RSA PKCS#8 (EC OID 1.2.840.10045.2.1) is not flagged RSA.
        let ec_der: &[u8] = &[
            0x30, 0x14, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
            0x02, 0x01, 0x06, 0x00, 0x04, 0x00, 0x00, 0x00,
        ];
        let ec_b64 = test_b64(ec_der);
        let ec_pem = format!("-----BEGIN PRIVATE KEY-----\n{ec_b64}\n-----END PRIVATE KEY-----\n");
        let (_d, is_rsa) = parse_private_key_pem(&ec_pem).unwrap();
        assert!(!is_rsa);

        // Unknown block → error.
        assert!(
            parse_private_key_pem("-----BEGIN GARBAGE-----\nAAA=\n-----END GARBAGE-----\n")
                .is_err()
        );
    }

    /// Tiny base64 encoder for test fixtures.
    fn test_b64(data: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
            out.push(T[(n >> 18) as usize & 63] as char);
            out.push(T[(n >> 12) as usize & 63] as char);
            if chunk.len() > 1 {
                out.push(T[(n >> 6) as usize & 63] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(T[n as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
        out
    }

    #[test]
    fn sniffs_rsa_oid() {
        assert!(contains_oid(
            &[0x30, 0x00, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
            RSA_OID
        ));
        assert!(!contains_oid(
            &[0x30, 0x00, 0x2a, 0x86, 0x48, 0xce, 0x3d],
            RSA_OID
        ));
    }

    #[test]
    fn keep_alive_detection() {
        let mut req = Request::new(Method::GET, "/");
        assert!(request_keeps_alive(&req)); // HTTP/1.1 default
        req.headers.insert(
            HeaderName::from_static("connection"),
            HeaderValue::from_static("close"),
        );
        assert!(!request_keeps_alive(&req));
    }

    #[test]
    fn round_trip_through_plain_server() {
        // Bind a server with an echo-ish handler, then drive it with a raw
        // socket and verify the request line + body round-trip.
        let cfg = HttpServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            min_version: TlsVersion::Tls12,
            max_version: TlsVersion::Tls13,
            max_head: DEFAULT_MAX_HEAD,
            max_body: DEFAULT_MAX_BODY,
            read_timeout: Some(Duration::from_secs(5)),
            tunnel_handler: None,
            handler: Arc::new(|req: Request<Body>| {
                let mut resp = Response::new(StatusCode::OK);
                let body = format!("echo:{}", req.uri.as_str());
                resp.headers.insert(
                    HeaderName::from_static("content-length"),
                    HeaderValue::from(body.len().to_string()),
                );
                resp.body = Body::from(body);
                resp
            }),
        };
        let mut server = HttpServer::bind(cfg).unwrap();
        let addr = server.local_addr().unwrap();
        server.start().unwrap();

        let mut sock = TcpStream::connect(addr).unwrap();
        sock.write_all(
            b"POST /hello?q=1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nworld",
        )
        .unwrap();
        let mut buf = Vec::new();
        sock.read_to_end(&mut buf).unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
        assert!(text.contains("echo:/hello?q=1"), "{text}");
        assert!(text.ends_with("echo:/hello?q=1"), "{text}");

        server.shutdown();
    }

    #[test]
    fn stop_unblocks_accept_loop() {
        let cfg = HttpServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            min_version: TlsVersion::Tls12,
            max_version: TlsVersion::Tls13,
            max_head: DEFAULT_MAX_HEAD,
            max_body: DEFAULT_MAX_BODY,
            read_timeout: Some(Duration::from_secs(5)),
            tunnel_handler: None,
            handler: Arc::new(|_req: Request<Body>| Response::new(StatusCode::OK)),
        };
        let mut server = HttpServer::bind(cfg).unwrap();
        server.start().unwrap();
        server.shutdown();
        // Reaching here without hanging proves the accept loop exited.
    }
}
