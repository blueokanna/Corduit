//! HTTP client built on `courierust` (replacing `hyper` + `rustls`).
//!
//! Corduit's HTTP needs are deliberately small — fetch a whole body with a
//! timeout, follow redirects, optionally route through a plain HTTP proxy
//! (CONNECT tunnel) — and courierust covers them natively:
//!
//! * The direct path uses [`courierust::courierust_client::Client`], a
//!   synchronous, self-contained HTTP/1.1 + HTTP/2 client with its own
//!   connection pool, redirect handling, bounded bodies and TLS 1.2/1.3
//!   (system roots loaded by [`crate::common::roots`]).
//! * The proxy path establishes a CONNECT tunnel through the proxy with raw
//!   bytes, then speaks HTTP/1.1 over it using courierust's public H/1 codec
//!   ([`courierust::courierust_h1`]) — TLS on top of the tunnel uses
//!   [`courierust::courierust_tls::TlsConnector`].
//!
//! The whole client is synchronous: callers run it on the work-stealing
//! pool (or a relay thread) and the per-request timeout bounds the call.

use courierust::courierust_client::{Client, ClientConfig, TlsSettings};
use courierust::courierust_error::{Error as CourierError, ErrorKind as CourierErrorKind};
use courierust::courierust_h1 as h1;
use courierust::courierust_http::uri::Url;
use courierust::courierust_http::{
    HeaderMap, HeaderName, HeaderValue, Method, PathAndQuery, StatusCode, Version,
};
use courierust::courierust_io::{BufReader, Read as CRead, Write as CWrite};
use courierust::courierust_tls::{TlsConnector, TlsVersion};
use std::fmt;
use std::net::{SocketAddr, TcpStream};
use std::sync::OnceLock;
use std::time::Duration;

use crate::common::roots::system_root_store;

/// Upper bound for a single response body (64 MiB). Subscription files and
/// rule sets are small; this only guards against a hostile server streaming
/// unbounded data.
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Maximum redirect hops before giving up.
const MAX_REDIRECTS: u8 = 8;

/// Cap for an HTTP response head (status line + headers).
const MAX_HEAD_BYTES: usize = 64 * 1024;

/// Cap for a CONNECT response head from a proxy.
const MAX_CONNECT_HEAD_BYTES: usize = 8192;

/// Error type for the HTTP client.
#[derive(Debug)]
pub enum HttpError {
    /// The URL could not be parsed or uses an unsupported scheme.
    InvalidUrl(String),
    /// Host resolution failed.
    Dns(String),
    /// TCP connection failed.
    Connect(String),
    /// TLS handshake failed.
    Tls(String),
    /// The proxy CONNECT tunnel could not be established.
    Proxy(String),
    /// The HTTP request could not be sent.
    Request(String),
    /// The response was malformed or could not be read.
    InvalidResponse(String),
    /// The server did not respond within the configured timeout.
    Timeout,
    /// The response body exceeded the configured limit.
    BodyTooLarge,
    /// Too many redirects were encountered.
    TooManyRedirects,
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpError::InvalidUrl(e) => write!(f, "invalid URL: {e}"),
            HttpError::Dns(e) => write!(f, "DNS resolution failed: {e}"),
            HttpError::Connect(e) => write!(f, "connection failed: {e}"),
            HttpError::Tls(e) => write!(f, "TLS handshake failed: {e}"),
            HttpError::Proxy(e) => write!(f, "proxy error: {e}"),
            HttpError::Request(e) => write!(f, "request failed: {e}"),
            HttpError::InvalidResponse(e) => write!(f, "invalid response: {e}"),
            HttpError::Timeout => write!(f, "request timed out"),
            HttpError::BodyTooLarge => write!(f, "response body too large"),
            HttpError::TooManyRedirects => write!(f, "too many redirects"),
        }
    }
}

impl std::error::Error for HttpError {}

impl From<CourierError> for HttpError {
    fn from(e: CourierError) -> Self {
        match e.kind {
            CourierErrorKind::Timeout => HttpError::Timeout,
            CourierErrorKind::UnexpectedEof => {
                HttpError::InvalidResponse(format!("connection closed: {e}"))
            }
            CourierErrorKind::Overflow => HttpError::BodyTooLarge,
            other => HttpError::Request(format!("{other:?}: {e}")),
        }
    }
}

/// A fully-read HTTP response.
#[derive(Debug)]
pub struct HttpResponse {
    status: u16,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl HttpResponse {
    /// The numeric status code.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// `true` for 2xx status codes.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Response headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Raw response body bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.body
    }

    /// Consume the response and return the body as `String`.
    pub fn text(self) -> Result<String, HttpError> {
        String::from_utf8(self.body)
            .map_err(|e| HttpError::InvalidResponse(format!("body is not UTF-8: {e}")))
    }
}

/// A minimal HTTP client.
///
/// `Debug` is hand-written because courierust's `Client` does not implement
/// it (it is an `Arc` wrapper around pool state).
pub struct HttpClient {
    timeout: Duration,
    proxy: Option<SocketAddr>,
    client: Client,
}

impl fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpClient")
            .field("timeout", &self.timeout)
            .field("proxy", &self.proxy)
            .finish_non_exhaustive()
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpClient {
    /// Create a client with a 30 second timeout, TLS from the system root
    /// store, and no proxy.
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            proxy: None,
            client: build_client(Duration::from_secs(30)),
        }
    }

    /// Set the per-request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.client = build_client(timeout);
        self.timeout = timeout;
        self
    }

    /// Route requests through a plain HTTP proxy (CONNECT tunneling).
    pub fn with_proxy(mut self, proxy: SocketAddr) -> Self {
        self.proxy = Some(proxy);
        self
    }

    /// Perform a GET request, following up to `MAX_REDIRECTS` redirects.
    pub fn get(&self, url: &str) -> Result<HttpResponse, HttpError> {
        self.get_bytes(url)
    }

    /// Perform a GET request, following up to `MAX_REDIRECTS` redirects.
    pub fn get_bytes(&self, url: &str) -> Result<HttpResponse, HttpError> {
        let url = url.to_string();
        let proxy = self.proxy;
        let client = self.client.clone();
        let timeout = self.timeout;
        match proxy {
            Some(proxy) => proxy_get(&client, &url, proxy, timeout),
            None => direct_get(&client, &url, timeout),
        }
    }
}

fn validate_scheme(scheme: &str) -> Result<(), HttpError> {
    match scheme {
        "http" | "https" => Ok(()),
        other => Err(HttpError::InvalidUrl(format!(
            "unsupported scheme '{other}'"
        ))),
    }
}

/// Unix seconds for certificate validity checks.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Build the courierust client used for direct requests. TLS trusts the
/// system root store and prefers HTTP/2 (ALPN `h2`, falling back to
/// `http/1.1`).
fn build_client(timeout: Duration) -> Client {
    let tls = TlsSettings {
        roots: system_root_store().clone(),
        verify: true,
        alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        now: unix_now(),
        min_version: TlsVersion::Tls12,
        max_version: TlsVersion::Tls13,
    };
    Client::with_config(ClientConfig {
        http2: true,
        max_redirects: MAX_REDIRECTS as usize,
        max_body: MAX_BODY_BYTES,
        max_header_list: MAX_HEAD_BYTES,
        connect_timeout: Some(timeout),
        read_timeout: Some(timeout),
        handshake_timeout: Some(timeout),
        tls: Some(tls),
        ..Default::default()
    })
}

/// Shared TLS connector for the proxy path (its resumption-session store
/// survives across requests, so repeat visits to the same host resume).
fn shared_tls_connector() -> &'static TlsConnector {
    static CONNECTOR: OnceLock<TlsConnector> = OnceLock::new();
    CONNECTOR.get_or_init(|| {
        TlsConnector::new(courierust::courierust_tls::ClientConfig {
            roots: system_root_store().clone(),
            verify: true,
            alpn: vec![b"http/1.1".to_vec()],
            now: unix_now(),
            min_version: TlsVersion::Tls12,
            max_version: TlsVersion::Tls13,
        })
    })
}

/// Direct path: courierust handles connect, TLS, HTTP/1.1+HTTP/2 and
/// redirects. The whole body is materialized with a hard cap.
fn direct_get(client: &Client, url: &str, _timeout: Duration) -> Result<HttpResponse, HttpError> {
    let parsed = Url::parse(url).map_err(|e| HttpError::InvalidUrl(e.to_string()))?;
    validate_scheme(&parsed.scheme)?;

    let req = courierust::courierust_http::Request::new(Method::GET, "/");
    let resp = client.execute(url, req).map_err(HttpError::from)?;

    let status = resp.status.as_u16();
    let body = resp
        .body
        .collect_limited(MAX_BODY_BYTES)
        .map_err(HttpError::from)?;

    Ok(HttpResponse {
        status,
        headers: resp.headers,
        body: body.to_vec(),
    })
}

/// Proxy path: CONNECT tunnel, optional TLS, then a single HTTP/1.1 GET
/// spoken with courierust's public codec.
fn proxy_get(
    _client: &Client,
    url: &str,
    proxy: SocketAddr,
    timeout: Duration,
) -> Result<HttpResponse, HttpError> {
    let parsed = Url::parse(url).map_err(|e| HttpError::InvalidUrl(e.to_string()))?;
    validate_scheme(&parsed.scheme)?;

    let mut tcp = TcpStream::connect_timeout(&proxy, timeout)
        .map_err(|e| HttpError::Proxy(format!("connect to {proxy}: {e}")))?;
    let _ = tcp.set_read_timeout(Some(timeout));
    let _ = tcp.set_write_timeout(Some(timeout));
    establish_connect_tunnel(&mut tcp, &parsed.host, parsed.port)?;

    if parsed.scheme == "https" {
        let mut tls = shared_tls_connector()
            .connect(&parsed.host, &tcp, &tcp)
            .map_err(|e| HttpError::Tls(e.to_string()))?;
        h1_get_once(&mut tls, &parsed, timeout)
    } else {
        // `&TcpStream` (not the owned stream) implements courierust's
        // transport traits, so hand a reborrow to the codec.
        h1_get_once(&mut &tcp, &parsed, timeout)
    }
}

/// Perform a single HTTP/1.1 GET over an established (possibly TLS) stream,
/// reading the response with courierust's H/1 codec and enforcing the body
/// and head caps. The request asks for `Connection: close`, so a server that
/// answers without `Content-Length` delimits the body by closing.
fn h1_get_once<S: CRead + CWrite>(
    stream: &mut S,
    url: &Url,
    _timeout: Duration,
) -> Result<HttpResponse, HttpError> {
    // Build the request head.
    let target = PathAndQuery::from_bytes(url.path_and_query.as_str().as_bytes())
        .map_err(|e| HttpError::Request(format!("bad request target: {e}")))?;
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("host"),
        HeaderValue::from(url.authority()),
    );
    headers.insert(
        HeaderName::from_static("accept"),
        HeaderValue::from_static("*/*"),
    );
    headers.insert(
        HeaderName::from_static("connection"),
        HeaderValue::from_static("close"),
    );
    let mut head = Vec::new();
    h1::write_request_head(&mut head, &Method::GET, &target, Version::HTTP_11, &headers)
        .map_err(|e| HttpError::Request(format!("encode request head: {e}")))?;
    write_all_bytes(stream, &head).map_err(|e| HttpError::Request(format!("send request: {e}")))?;
    CWrite::flush(stream).map_err(|e| HttpError::Request(format!("flush request: {e}")))?;

    // Read the response head.
    let mut reader = BufReader::new(stream, 8192);
    let status_line = reader
        .read_until(b'\n', MAX_HEAD_BYTES)
        .map_err(|e| HttpError::InvalidResponse(format!("read status line: {e}")))?;
    let status_line = trim_crlf(&status_line);
    let (status, _version) = h1::parse_status_line(status_line)
        .map_err(|e| HttpError::InvalidResponse(format!("malformed status line: {e}")))?;
    let resp_headers = h1::read_headers(&mut reader)
        .map_err(|e| HttpError::InvalidResponse(format!("malformed headers: {e}")))?;

    let framing = h1::body_length(&resp_headers, None, Some(status))
        .map_err(|e| HttpError::InvalidResponse(format!("bad body framing: {e}")))?;

    let body: Vec<u8> = match framing {
        h1::BodyLen::Length(n) => {
            if n > MAX_BODY_BYTES {
                return Err(HttpError::BodyTooLarge);
            }
            reader
                .read_exact(n)
                .map_err(|e| HttpError::InvalidResponse(format!("read body: {e}")))?
        }
        h1::BodyLen::Chunked => h1::read_body_chunked(&mut reader, MAX_BODY_BYTES)
            .map_err(|e| HttpError::InvalidResponse(format!("read chunked body: {e}")))?
            .to_vec(),
        h1::BodyLen::None => {
            // No Content-Length / Transfer-Encoding. For a status that
            // cannot carry a body this is the end; otherwise the body is
            // close-delimited (we asked for Connection: close).
            if status.is_informational()
                || status == StatusCode::NO_CONTENT
                || status == StatusCode::NOT_MODIFIED
            {
                Vec::new()
            } else {
                read_to_eof_capped(&mut reader, MAX_BODY_BYTES)?
            }
        }
    };

    Ok(HttpResponse {
        status: status.as_u16(),
        headers: resp_headers,
        body,
    })
}

/// Read until EOF (the peer closing the connection) with a hard cap.
fn read_to_eof_capped<R: CRead>(
    reader: &mut BufReader<R>,
    max: usize,
) -> Result<Vec<u8>, HttpError> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read_more(&mut chunk) {
            Ok(0) => return Ok(out),
            Ok(n) => {
                if out.len() + n > max {
                    return Err(HttpError::BodyTooLarge);
                }
                out.extend_from_slice(&chunk[..n]);
            }
            Err(e) if matches!(e.kind, CourierErrorKind::Timeout) => {
                // For a `Connection: close` exchange the server closes right
                // after the body, so a quiet connection after data is the
                // normal completion path.
                return Ok(out);
            }
            Err(e) if matches!(e.kind, CourierErrorKind::WouldBlock) => continue,
            Err(e) if matches!(e.kind, CourierErrorKind::UnexpectedEof) => return Ok(out),
            Err(e) => return Err(HttpError::InvalidResponse(format!("read body: {e}"))),
        }
    }
}

/// Write a buffer in full, retrying partial writes (courierust's `Write`
/// trait has no `write_all`).
fn write_all_bytes<W: CWrite>(writer: &mut W, mut data: &[u8]) -> Result<(), CourierError> {
    while !data.is_empty() {
        match CWrite::write(writer, data) {
            Ok(0) => {
                return Err(CourierError::new(CourierErrorKind::Io));
            }
            Ok(n) => data = &data[n..],
            Err(e) if matches!(e.kind, CourierErrorKind::WouldBlock) => {
                std::thread::yield_now();
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Trim a trailing `\r\n` (or lone `\n`) from a read line.
fn trim_crlf(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// Establish a CONNECT tunnel through a plain HTTP proxy. On success the
/// socket is connected to `host:port` through the proxy.
fn establish_connect_tunnel(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
) -> Result<(), HttpError> {
    use std::io::{Read as _, Write as _};

    let target = format!("{host}:{port}");
    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|e| HttpError::Proxy(format!("send CONNECT: {e}")))?;

    // Read the response head (up to the blank line), capped to avoid
    // unbounded buffering from a misbehaving proxy.
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    loop {
        let n = stream
            .read(&mut chunk)
            .map_err(|e| HttpError::Proxy(format!("read CONNECT response: {e}")))?;
        if n == 0 {
            return Err(HttpError::Proxy(
                "proxy closed connection during CONNECT".into(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > MAX_CONNECT_HEAD_BYTES {
            return Err(HttpError::Proxy("oversized CONNECT response head".into()));
        }
    }

    let status_line = buf
        .split(|b| *b == b'\n')
        .next()
        .ok_or_else(|| HttpError::Proxy("empty CONNECT response".into()))?;
    let status_line = String::from_utf8_lossy(status_line);
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| HttpError::Proxy(format!("malformed CONNECT response: {status_line}")))?;
    if status_code != 200 {
        return Err(HttpError::Proxy(format!(
            "CONNECT failed with status {status_code}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_redirect_codes() {
        // Redirect following is owned by courierust's client; this test pins
        // the HTTP status predicates the H/1 path relies on.
        assert!(StatusCode::MOVED_PERMANENTLY.is_redirection());
        assert!(StatusCode::FOUND.is_redirection());
        assert!(StatusCode::TEMPORARY_REDIRECT.is_redirection());
        assert!(!StatusCode::OK.is_redirection());
        assert!(!StatusCode::NOT_FOUND.is_redirection());
    }

    #[test]
    fn rejects_unsupported_schemes() {
        assert!(validate_scheme("http").is_ok());
        assert!(validate_scheme("https").is_ok());
        assert!(validate_scheme("ftp").is_err());
        assert!(validate_scheme("ws").is_err());
    }

    #[test]
    fn trims_crlf_lines() {
        assert_eq!(trim_crlf(b"HTTP/1.1 200 OK\r\n"), b"HTTP/1.1 200 OK");
        assert_eq!(trim_crlf(b"HTTP/1.1 200 OK\n"), b"HTTP/1.1 200 OK");
        assert_eq!(trim_crlf(b"HTTP/1.1 200 OK"), b"HTTP/1.1 200 OK");
    }

    #[test]
    fn http_response_helpers() {
        // 204 is a 2xx status (success) with no body.
        let resp = HttpResponse {
            status: 204,
            headers: HeaderMap::new(),
            body: Vec::new(),
        };
        assert!(resp.is_success());
        let resp = HttpResponse {
            status: 404,
            headers: HeaderMap::new(),
            body: b"missing".to_vec(),
        };
        assert!(!resp.is_success());
        assert_eq!(resp.bytes(), b"missing");
        assert_eq!(resp.text().unwrap(), "missing");
    }

    #[test]
    fn courier_url_is_used_for_parsing() {
        // The client parses URLs with courierust's own strict Url type; pin
        // the behaviors the client depends on (default ports, IPv6, path).
        let u = Url::parse("https://example.com/a/b?q=1").unwrap();
        assert_eq!(u.host, "example.com");
        assert_eq!(u.port, 443);
        assert_eq!(u.path_and_query.as_str(), "/a/b?q=1");
        assert_eq!(u.authority(), "example.com:443");
    }

    #[test]
    fn proxy_rejects_bad_connect_responses() {
        // Drive the CONNECT parser against a real listener.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                use std::io::Write as _;
                let _ = sock.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");
                let _ = sock.flush();
            }
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        let err = establish_connect_tunnel(&mut stream, "example.com", 443).unwrap_err();
        assert!(matches!(err, HttpError::Proxy(_)));
    }
}
