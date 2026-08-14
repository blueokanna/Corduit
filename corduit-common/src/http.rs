//! Minimal self-implemented HTTP/1.1 client built directly on `hyper`.
//!
//! This replaces `reqwest` for Corduit's needs: GET requests with a timeout,
//! redirect following, an optional plain HTTP proxy (via CONNECT tunneling)
//! and a bounded response body. TLS is handled with `rustls` using the system
//! root store with a `webpki-roots` fallback, so no global crypto-provider
//! installation is required before first use.
//!
//! The API is deliberately small: [`HttpClient`] (builder-style constructor
//! methods) plus the returned [`HttpResponse`]. No streaming, no cookies, no
//! connection pooling — the engine's consumers only fetch whole bodies.

use crate::url::Url;
use bytes::Bytes;
use http::HeaderMap;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::header::{HOST, LOCATION};
use hyper::Request;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::RootCertStore;
use std::fmt;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Upper bound for a single response body (64 MiB). Subscription files and
/// rule sets are small; this only guards against a hostile server streaming
/// unbounded data.
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Maximum redirect hops before giving up.
const MAX_REDIRECTS: u8 = 8;

/// A unified read/write stream handed to hyper: either a plain TCP socket or a
/// TLS socket. A concrete enum (rather than a trait object) lets hyper's
/// blanket `rt::Read`/`rt::Write` impls for `tokio::io` traits apply.
enum Conn {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for Conn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Conn::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Conn::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            Conn::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Conn::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Conn::Plain(s) => Pin::new(s).poll_flush(cx),
            Conn::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Conn::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Conn::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

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

/// A fully-read HTTP response.
#[derive(Debug)]
pub struct HttpResponse {
    status: u16,
    headers: HeaderMap,
    body: Bytes,
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
        String::from_utf8(self.body.to_vec())
            .map_err(|e| HttpError::InvalidResponse(format!("body is not UTF-8: {e}")))
    }
}

/// A minimal HTTP client.
#[derive(Debug, Clone)]
pub struct HttpClient {
    timeout: Duration,
    proxy: Option<SocketAddr>,
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpClient {
    /// Create a client with a 30 second timeout and no proxy.
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            proxy: None,
        }
    }

    /// Set the per-request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Route requests through a plain HTTP proxy (CONNECT tunneling).
    pub fn with_proxy(mut self, proxy: SocketAddr) -> Self {
        self.proxy = Some(proxy);
        self
    }

    /// Perform a GET request, following up to `MAX_REDIRECTS` redirects.
    pub async fn get(&self, url: &str) -> Result<HttpResponse, HttpError> {
        self.get_bytes(url).await
    }

    /// Perform a GET request, following up to `MAX_REDIRECTS` redirects.
    pub async fn get_bytes(&self, url: &str) -> Result<HttpResponse, HttpError> {
        let mut current = Url::parse(url).map_err(|e| HttpError::InvalidUrl(e.to_string()))?;
        validate_scheme(&current)?;

        for _ in 0..=MAX_REDIRECTS {
            let response = tokio::time::timeout(self.timeout, self.request_once(&current))
                .await
                .map_err(|_| HttpError::Timeout)??;

            if is_redirect(response.status()) {
                let location = response
                    .headers()
                    .get(LOCATION)
                    .ok_or_else(|| HttpError::InvalidResponse("redirect without Location".into()))?
                    .to_str()
                    .map_err(|e| HttpError::InvalidResponse(format!("bad Location header: {e}")))?;
                current = resolve_redirect(&current, location)?;
                continue;
            }

            return Ok(response);
        }

        Err(HttpError::TooManyRedirects)
    }

    /// Execute a single request without redirect handling.
    async fn request_once(&self, url: &Url) -> Result<HttpResponse, HttpError> {
        let host = url
            .host_str()
            .ok_or_else(|| HttpError::InvalidUrl("URL has no host".into()))?;
        let is_https = url.scheme() == "https";
        let port = url.port_or_known_default().ok_or_else(|| {
            HttpError::InvalidUrl(format!("unknown default port for '{}'", url.scheme()))
        })?;

        let stream: Conn = if let Some(proxy) = self.proxy {
            let mut tcp = TcpStream::connect(proxy)
                .await
                .map_err(|e| HttpError::Proxy(format!("connect to {proxy}: {e}")))?;
            establish_connect_tunnel(&mut tcp, host, port).await?;
            if is_https {
                Conn::Tls(Box::new(upgrade_tls(tcp, host).await?))
            } else {
                Conn::Plain(tcp)
            }
        } else {
            let addr = format!("{host}:{port}");
            let tcp = TcpStream::connect(&addr)
                .await
                .map_err(|e| HttpError::Connect(format!("{addr}: {e}")))?;
            if is_https {
                Conn::Tls(Box::new(upgrade_tls(tcp, host).await?))
            } else {
                Conn::Plain(tcp)
            }
        };

        let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| HttpError::Request(format!("HTTP handshake: {e}")))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });

        // Build the request in origin-form (path only) with an explicit Host
        // header; this works for both direct connections and CONNECT tunnels.
        let path = if url.path().is_empty() {
            "/".to_string()
        } else {
            url.path().to_string()
        };
        let path_and_query = match url.query() {
            Some(q) => format!("{path}?{q}"),
            None => path,
        };
        let host_header = match url.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.to_string(),
        };

        let request = Request::builder()
            .method("GET")
            .uri(&path_and_query)
            .header(HOST, host_header)
            .body(Full::new(Bytes::new()))
            .map_err(|e| HttpError::Request(format!("build request: {e}")))?;

        let response = sender
            .send_request(request)
            .await
            .map_err(|e| HttpError::Request(format!("send request: {e}")))?;

        let (parts, body) = response.into_parts();
        let body_bytes = read_bounded(body).await?;

        Ok(HttpResponse {
            status: parts.status.as_u16(),
            headers: parts.headers,
            body: body_bytes,
        })
    }
}

fn validate_scheme(url: &Url) -> Result<(), HttpError> {
    match url.scheme() {
        "http" | "https" => Ok(()),
        other => Err(HttpError::InvalidUrl(format!(
            "unsupported scheme '{other}'"
        ))),
    }
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// Resolve a `Location` header against the current URL.
fn resolve_redirect(base: &Url, location: &str) -> Result<Url, HttpError> {
    let location = location.trim();
    if location.is_empty() {
        return Err(HttpError::InvalidResponse("empty Location header".into()));
    }
    if location.starts_with("http://") || location.starts_with("https://") {
        return Url::parse(location).map_err(|e| HttpError::InvalidUrl(e.to_string()));
    }
    if let Some(rest) = location.strip_prefix("//") {
        // protocol-relative
        let joined = format!("{}://{rest}", base.scheme());
        return Url::parse(&joined).map_err(|e| HttpError::InvalidUrl(e.to_string()));
    }
    if let Some(rest) = location.strip_prefix('/') {
        // absolute path
        let joined = format!("{}://{}/{}", base.scheme(), base.host_with_port(), rest);
        return Url::parse(&joined).map_err(|e| HttpError::InvalidUrl(e.to_string()));
    }
    // relative path: resolve against the base directory
    let base_path = base.path();
    let dir = match base_path.rfind('/') {
        Some(i) => &base_path[..=i],
        None => "/",
    };
    let joined = format!(
        "{}://{}{dir}{location}",
        base.scheme(),
        base.host_with_port()
    );
    Url::parse(&joined).map_err(|e| HttpError::InvalidUrl(e.to_string()))
}

/// Read a response body, enforcing the size limit.
async fn read_bounded(body: Incoming) -> Result<Bytes, HttpError> {
    let limited = Limited::new(body, MAX_BODY_BYTES);
    let collected = limited
        .collect()
        .await
        .map_err(|_| HttpError::BodyTooLarge)?;
    Ok(collected.to_bytes())
}

/// Establish a CONNECT tunnel through a plain HTTP proxy. On success the
/// socket is connected to `host:port` through the proxy.
async fn establish_connect_tunnel(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
) -> Result<(), HttpError> {
    let target = format!("{host}:{port}");
    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| HttpError::Proxy(format!("send CONNECT: {e}")))?;

    // Read the response head (up to the blank line), capped to avoid unbounded
    // buffering from a misbehaving proxy.
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
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
        if buf.len() > 8192 {
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

/// Wrap a TCP stream in TLS for the given server name.
async fn upgrade_tls(
    stream: TcpStream,
    host: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, HttpError> {
    let connector = tls_connector()?;
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| HttpError::Tls(format!("invalid server name '{host}': {e}")))?;
    connector
        .connect(server_name, stream)
        .await
        .map_err(|e| HttpError::Tls(e.to_string()))
}

/// Lazily build a TLS connector from the system root store plus webpki roots.
fn tls_connector() -> Result<TlsConnector, HttpError> {
    static CONNECTOR: OnceLock<TlsConnector> = OnceLock::new();
    let connector = CONNECTOR.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            let _ = roots.add(cert);
        }
        // Fallback / supplement: Mozilla roots bundled with the binary.
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("rustls: valid protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        TlsConnector::from(Arc::new(config))
    });
    Ok(connector.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_redirect_codes() {
        assert!(is_redirect(301));
        assert!(is_redirect(302));
        assert!(is_redirect(303));
        assert!(is_redirect(307));
        assert!(is_redirect(308));
        assert!(!is_redirect(200));
        assert!(!is_redirect(404));
    }

    #[test]
    fn resolves_absolute_redirects() {
        let base = Url::parse("https://a.example/path").unwrap();
        let next = resolve_redirect(&base, "https://b.example/new").unwrap();
        assert_eq!(next.host_str(), Some("b.example"));
        assert_eq!(next.path(), "/new");
    }

    #[test]
    fn resolves_protocol_relative_redirects() {
        let base = Url::parse("https://a.example/path").unwrap();
        let next = resolve_redirect(&base, "//cdn.example/x").unwrap();
        assert_eq!(next.scheme(), "https");
        assert_eq!(next.host_str(), Some("cdn.example"));
        assert_eq!(next.path(), "/x");
    }

    #[test]
    fn resolves_absolute_path_redirects() {
        let base = Url::parse("https://a.example/sub/path").unwrap();
        let next = resolve_redirect(&base, "/root").unwrap();
        assert_eq!(next.host_str(), Some("a.example"));
        assert_eq!(next.path(), "/root");
    }

    #[test]
    fn resolves_relative_path_redirects() {
        let base = Url::parse("https://a.example/sub/path").unwrap();
        let next = resolve_redirect(&base, "other").unwrap();
        assert_eq!(next.path(), "/sub/other");

        let base2 = Url::parse("https://a.example").unwrap();
        let next2 = resolve_redirect(&base2, "other").unwrap();
        assert_eq!(next2.path(), "/other");
    }

    #[test]
    fn rejects_unsupported_schemes() {
        let url = Url::parse("ftp://example.com/file").unwrap();
        assert!(validate_scheme(&url).is_err());
    }
}
