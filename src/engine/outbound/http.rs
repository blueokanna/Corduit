//! HTTP proxy outbound: `CONNECT` tunnelling, optionally over TLS (an
//! "HTTPS proxy").
//!
//! ```text
//! CONNECT host:port HTTP/1.1
//! Host: host:port
//! Proxy-Authorization: Basic <base64(user:pass)>
//!                                  -> HTTP/1.1 200 Connection Established
//! ```
//!
//! # One outbound, two transports
//!
//! An `https://` proxy is a TLS-wrapped HTTP/1.1 proxy: the proxy hop is
//! authenticated and encrypted while the tunnel stays opaque byte relay.
//! `tls: true` (or `security: tls`) selects it. The request, the auth header
//! and the relay are identical either way, so this is one type with an
//! optional transport rather than two files that would drift apart.
//!
//! # Why HTTP/1.1 and not h2
//!
//! A proxy that offers `h2` over ALPN expects `CONNECT` as an HTTP/2 request
//! and is entitled to treat HTTP/1.1 framing as a protocol error. The default
//! ALPN offer is therefore `http/1.1` alone — narrow on purpose. A profile that
//! overrides `alpn` to include `h2` can negotiate a connection this outbound
//! cannot speak, and the failure will look like a malformed response.
//!
//! # The over-read
//!
//! The response head ends at a blank line, and no read can stop exactly there.
//! Whatever the last read took past the delimiter already belongs to the
//! tunnel: the peer has sent it and will not send it again. Dropping it —
//! which `BufReader::into_inner` does — is invisible for request/response
//! protocols and fatal for greeting-first ones, where the server speaks before
//! the client does (MySQL, SMTP, SSH, FTP). The bytes are carried into a
//! [`PrefixedStream`](crate::common::stream::PrefixedStream) instead.
//!
//! # The latency probe and a second TLS layer
//!
//! `test_http_latency` measures the whole path: `CONNECT`, then a real HTTP
//! request through the tunnel, which for an `https://` test URL means a second
//! TLS handshake *inside* the tunnel. That handshake needs to own the socket,
//! so it is available only when the proxy hop is plaintext. Through an HTTPS
//! proxy the request fails with a config error naming the fix (use an `http://`
//! test URL for that outbound) instead of quietly reporting the time to
//! `CONNECT` and calling it latency.

use crate::common::stream::{BoxStream, PrefixedStream};
use crate::engine::config::OutboundConfig;
use crate::engine::error::{Error, Result};
use crate::engine::outbound::{OutboundProxy, TargetAddr};
use crate::engine::tls::{AdvancedTlsOptions, ClientConfig, TlsConnector};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// TCP connect + `CONNECT` exchange budget.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest response head accepted: status line plus headers. The head is
/// entirely peer-controlled and a proxy has no reason to send more.
const MAX_HEAD: usize = 16 * 1024;

/// TLS parameters for an HTTPS proxy hop.
struct HttpTls {
    sni: String,
    skip_cert_verify: bool,
    alpn: Vec<String>,
    connector: TlsConnector,
    advanced: AdvancedTlsOptions,
}

/// HTTP outbound proxy (HTTP `CONNECT` tunnel), plain or TLS-wrapped.
pub struct HttpOutbound {
    config: OutboundConfig,
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    tls: Option<HttpTls>,
}

impl HttpOutbound {
    pub fn new(config: OutboundConfig) -> Result<Self> {
        let server = config
            .server
            .as_ref()
            .ok_or_else(|| Error::config("Missing server address for HTTP proxy"))?
            .clone();
        let port = config
            .port
            .ok_or_else(|| Error::config("Missing port for HTTP proxy"))?;

        let username = config
            .options
            .get("username")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let password = config
            .options
            .get("password")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        // Credentials go into a header value, so a CR or LF in one of them
        // would let a profile inject arbitrary headers into the request we
        // send to the proxy.
        for (field, value) in [("username", &username), ("password", &password)] {
            if let Some(value) = value {
                if value.contains(['\r', '\n']) {
                    return Err(Error::config(format!(
                        "HTTP proxy {field} must not contain CR or LF: it is encoded into a \
                         Proxy-Authorization header value"
                    )));
                }
            }
        }

        let tls = if wants_tls(&config) {
            let sni = config
                .options
                .get("sni")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| server.clone());
            let skip_cert_verify = config
                .options
                .get("skip-cert-verify")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let alpn = config
                .options
                .get("alpn")
                .and_then(|v| v.as_array())
                .map(|seq| {
                    seq.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect::<Vec<_>>()
                })
                .filter(|v: &Vec<String>| !v.is_empty())
                .unwrap_or_else(|| vec!["http/1.1".to_string()]);

            let advanced = AdvancedTlsOptions::from_options(&config.options, &sni)?;
            let connector = TlsConnector::new(ClientConfig {
                server_name: Some(sni.clone()),
                alpn: alpn.clone(),
                skip_cert_verify,
                enable_sni: true,
            })
            .map_err(|e| Error::Tls {
                message: format!("HTTP proxy TLS connector: {e}"),
                source: None,
            })?;

            Some(HttpTls {
                sni,
                skip_cert_verify,
                alpn,
                connector,
                advanced,
            })
        } else {
            None
        };

        Ok(Self {
            config,
            server,
            port,
            username,
            password,
            tls,
        })
    }

    fn dial_tcp(&self, timeout: Duration) -> Result<TcpStream> {
        crate::common::socket::connect_host(&self.server, self.port, timeout).map_err(|e| {
            Error::network(format!(
                "Failed to connect to HTTP proxy {}:{}: {e}",
                self.server, self.port
            ))
        })
    }

    /// Wrap a dialled socket in the proxy hop's TLS layer.
    fn wrap_tls(&self, stream: TcpStream) -> Result<BoxStream> {
        let Some(tls) = &self.tls else {
            return Ok(Box::new(stream) as BoxStream);
        };
        if tls.advanced.is_empty() {
            tls.connector
                .connect(stream, &tls.sni)
                .map_err(|e| Error::Tls {
                    message: format!("HTTP proxy TLS handshake with {}: {e}", tls.sni),
                    source: None,
                })
        } else {
            crate::engine::tls::connect_advanced_tls(
                stream,
                &tls.sni,
                &tls.alpn,
                tls.skip_cert_verify,
                &tls.advanced,
            )
        }
    }

    /// Send `CONNECT` for `target` and read the verdict, returning the bytes
    /// that were read past the response head.
    ///
    /// `deadline` bounds the read loop, not the transport: TLS streams install
    /// a short relay poll interval, and treating that poll as a failed
    /// handshake would break a proxy that takes two seconds to answer.
    fn connect_over<S: Read + Write>(
        &self,
        stream: &mut S,
        target: &TargetAddr,
        deadline: Instant,
    ) -> Result<Vec<u8>> {
        let target_str = target.to_string();
        let mut request = format!("CONNECT {target_str} HTTP/1.1\r\nHost: {target_str}\r\n");
        request.push_str("Proxy-Connection: keep-alive\r\n");
        if let (Some(user), Some(pass)) = (&self.username, &self.password) {
            let credentials = format!("{user}:{pass}");
            let encoded = courierust::courierust_crypto::base64::encode(credentials.as_bytes());
            request.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
        }
        request.push_str("\r\n");

        stream
            .write_all(request.as_bytes())
            .map_err(|e| Error::network(format!("Failed to send CONNECT request: {e}")))?;

        let (head, leftover) = read_head(stream, deadline)?;
        let status = parse_status_line(&head)?;
        if status != 200 {
            return Err(Error::network(format!(
                "HTTP CONNECT to {target_str} failed with status {status}"
            )));
        }
        Ok(leftover)
    }

    /// Establish a tunnel and return a stream positioned at the first
    /// tunnelled byte.
    fn open_tunnel(&self, target: &TargetAddr, timeout: Duration) -> Result<BoxStream> {
        let deadline = Instant::now() + timeout;
        let tcp = self.dial_tcp(timeout)?;
        let _ = tcp.set_read_timeout(Some(timeout));
        let _ = tcp.set_write_timeout(Some(timeout));

        tracing::debug!(
            "HTTP proxy: connected to {}:{} for target {}",
            self.server,
            self.port,
            target
        );

        let tunnel: BoxStream = if self.tls.is_some() {
            let mut stream = self.wrap_tls(tcp)?;
            let leftover = self.connect_over(&mut stream, target, deadline)?;
            Box::new(PrefixedStream::new(leftover, stream))
        } else {
            let mut stream = tcp;
            let leftover = self.connect_over(&mut stream, target, deadline)?;
            Box::new(PrefixedStream::new(leftover, Box::new(stream)))
        };

        tracing::debug!("HTTP proxy: tunnel established to {target}");
        Ok(tunnel)
    }
}

fn wants_tls(config: &OutboundConfig) -> bool {
    if let Some(explicit) = config.options.get("tls").and_then(|v| v.as_bool()) {
        return explicit;
    }
    config
        .options
        .get("security")
        .and_then(|v| v.as_str())
        .is_some_and(|s| s.trim().eq_ignore_ascii_case("tls"))
}

impl OutboundProxy for HttpOutbound {
    fn connect(&self) -> Result<()> {
        // Dial the hop, and when TLS is configured complete the handshake.
        // That is the part of the path this outbound owns; whether the proxy
        // can reach a *destination* is what `test_http_latency` measures.
        let tcp = self.dial_tcp(HANDSHAKE_TIMEOUT)?;
        let _ = tcp.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
        let _ = tcp.set_write_timeout(Some(HANDSHAKE_TIMEOUT));
        let _stream = self.wrap_tls(tcp)?;
        Ok(())
    }

    fn disconnect(&self) -> Result<()> {
        Ok(())
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn server_addr(&self) -> Option<(String, u16)> {
        Some((self.server.clone(), self.port))
    }

    fn test_http_latency(&self, test_url: &str, timeout: Duration) -> Result<Duration> {
        let url = crate::common::url::Url::parse(test_url)
            .map_err(|e| Error::config(format!("Invalid test URL: {e}")))?;
        let host = url
            .host_str()
            .ok_or_else(|| Error::config("Test URL has no host"))?
            .to_string();
        let https = url.scheme() == "https";
        let url_port = url.port().unwrap_or(if https { 443 } else { 80 });
        let path = if url.path().is_empty() {
            "/"
        } else {
            url.path()
        };
        let target = TargetAddr::Domain(host.clone(), url_port);

        let budget = timeout.min(HANDSHAKE_TIMEOUT);
        let deadline = Instant::now() + budget;
        let start = Instant::now();

        if self.tls.is_some() && https {
            // The socket is owned by the proxy hop's TLS stream, and the TLS
            // client needs a socket it can own for the *second* layer.
            return Err(Error::config(format!(
                "testing '{}' through the HTTPS proxy '{}' needs a second TLS handshake \
                 inside the tunnel, which this build cannot do on a wrapped transport; \
                 give this outbound an `http://` test URL",
                test_url, self.config.tag
            )));
        }

        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: Corduit/1.0\r\n\r\n"
        );

        if self.tls.is_some() {
            let mut stream = self.wrap_tls(self.dial_tcp(budget)?)?;
            self.connect_over(&mut stream, &target, deadline)?;
            stream
                .write_all(request.as_bytes())
                .map_err(|e| Error::network(format!("Failed to send probe request: {e}")))?;
            read_status_line(&mut stream)?;
            return Ok(start.elapsed());
        }

        let mut tcp = self.dial_tcp(budget)?;
        let _ = tcp.set_read_timeout(Some(budget));
        let _ = tcp.set_write_timeout(Some(budget));
        let leftover = self.connect_over(&mut tcp, &target, deadline)?;

        if https {
            // Nothing was read past the head, because the target cannot speak
            // before it sees a ClientHello. If that ever stops holding the
            // handshake would silently start at the wrong offset, so it is
            // checked rather than assumed.
            if !leftover.is_empty() {
                return Err(Error::protocol(
                    "the target sent bytes before the probe's TLS handshake; the socket \
                     cannot be handed over without reordering the stream",
                ));
            }
            let connector = TlsConnector::new(ClientConfig {
                server_name: Some(host.clone()),
                alpn: vec!["http/1.1".to_string()],
                skip_cert_verify: false,
                enable_sni: true,
            })
            .map_err(|e| Error::Tls {
                message: format!("latency probe TLS connector: {e}"),
                source: None,
            })?;
            let mut stream = connector.connect(tcp, &host).map_err(|e| Error::Tls {
                message: format!("latency probe TLS handshake with {host}: {e}"),
                source: None,
            })?;
            stream
                .write_all(request.as_bytes())
                .map_err(|e| Error::network(format!("Failed to send probe request: {e}")))?;
            read_status_line(&mut stream)?;
        } else {
            tcp.write_all(request.as_bytes())
                .map_err(|e| Error::network(format!("Failed to send probe request: {e}")))?;
            read_status_line(&mut tcp)?;
        }

        Ok(start.elapsed())
    }

    fn relay_tcp(&self, inbound: BoxStream, target: TargetAddr) -> Result<()> {
        self.relay_tcp_with_connection(inbound, target, None)
    }

    fn relay_tcp_with_connection(
        &self,
        inbound: BoxStream,
        target: TargetAddr,
        connection: Option<std::sync::Arc<crate::engine::connection_tracker::TrackedConnection>>,
    ) -> Result<()> {
        let outbound = self.open_tunnel(&target, HANDSHAKE_TIMEOUT)?;
        relay_streams!(inbound, outbound, connection)
    }
}

// ---------------------------------------------------------------------------
// Response head
// ---------------------------------------------------------------------------

/// Read a response head (status line + headers) and return it together with
/// every byte read past it.
///
/// An idle poll is retried until `deadline` rather than reported as a failure:
/// the transport under a TLS stream carries a short read timeout so the relay
/// can poll, and that timeout is not a statement about this handshake.
fn read_head(stream: &mut dyn Read, deadline: Instant) -> Result<(String, Vec<u8>)> {
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = find_head_end(&buf) {
            let head = String::from_utf8_lossy(&buf[..end]).into_owned();
            let leftover = buf.split_off(end);
            return Ok((head, leftover));
        }
        if buf.len() >= MAX_HEAD {
            return Err(Error::network(format!(
                "HTTP proxy response head exceeded {MAX_HEAD} bytes without a blank line"
            )));
        }
        match stream.read(&mut chunk) {
            Ok(0) => {
                return Err(Error::network(
                    "HTTP proxy closed the connection before finishing its response head",
                ))
            }
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if is_idle_poll(&e) => {
                if Instant::now() >= deadline {
                    return Err(Error::network(
                        "timed out waiting for the HTTP proxy response head",
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(Error::network(format!(
                    "Failed to read HTTP proxy response: {e}"
                )))
            }
        }
    }
}

/// Read the first token of the response body far enough to know it is HTTP.
fn read_status_line<S: Read>(stream: &mut S) -> Result<()> {
    let mut first = [0u8; 5];
    stream
        .read_exact(&mut first)
        .map_err(|e| Error::network(format!("Failed to read probe response: {e}")))?;
    if &first != b"HTTP/" {
        return Err(Error::protocol(
            "HTTP latency probe did not get an HTTP status line",
        ));
    }
    Ok(())
}

/// Index just past the blank line that ends a head, if one is present.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Parse `HTTP/1.x <status>` and reject anything that is not an HTTP response.
fn parse_status_line(head: &str) -> Result<u16> {
    let line = head
        .split("\r\n")
        .next()
        .ok_or_else(|| Error::protocol("HTTP proxy sent an empty response"))?;
    let mut parts = line.split_whitespace();
    let version = parts
        .next()
        .ok_or_else(|| Error::protocol("HTTP proxy response has no status line"))?;
    if !version.starts_with("HTTP/") {
        return Err(Error::protocol(format!(
            "the proxy's response does not start with an HTTP version: `{}`",
            truncate_for_log(line)
        )));
    }
    let code = parts
        .next()
        .ok_or_else(|| Error::protocol("HTTP proxy response has no status code"))?;
    code.parse::<u16>()
        .map_err(|_| Error::protocol(format!("HTTP proxy status code `{code}` is not a number")))
}

/// Whether the error is a socket timeout meaning "no bytes yet" rather than a
/// failure.
fn is_idle_poll(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// Keep a peer-controlled string short enough to log on one line.
fn truncate_for_log(s: &str) -> String {
    const MAX: usize = 120;
    if s.len() <= MAX {
        return s.to_string();
    }
    let mut end = MAX;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::net::TcpListener;

    fn config(options: &[(&str, nextjson::Value)]) -> OutboundConfig {
        let mut map = HashMap::new();
        for (k, v) in options {
            map.insert((*k).to_string(), v.clone());
        }
        OutboundConfig {
            tag: "http-test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Http,
            server: Some("127.0.0.1".to_string()),
            port: Some(8080),
            options: map,
        }
    }

    fn local(port: u16, options: &[(&str, nextjson::Value)]) -> OutboundConfig {
        let mut c = config(options);
        c.port = Some(port);
        c
    }

    fn string(value: &str) -> nextjson::Value {
        nextjson::Value::String(value.to_string())
    }

    #[test]
    fn a_plain_profile_stays_plaintext() {
        assert!(HttpOutbound::new(config(&[])).unwrap().tls.is_none());
    }

    #[test]
    fn tls_can_be_asked_for_by_flag_or_by_security() {
        for options in [
            vec![("tls", nextjson::Value::Bool(true))],
            vec![("security", string("TLS"))],
        ] {
            assert!(
                HttpOutbound::new(config(&options)).unwrap().tls.is_some(),
                "{options:?}"
            );
        }
    }

    #[test]
    fn an_explicit_false_wins_over_security_tls() {
        let out = HttpOutbound::new(config(&[
            ("tls", nextjson::Value::Bool(false)),
            ("security", string("tls")),
        ]))
        .unwrap();
        assert!(out.tls.is_none());
    }

    #[test]
    fn the_default_alpn_offer_is_http11_only() {
        let out = HttpOutbound::new(config(&[("tls", nextjson::Value::Bool(true))])).unwrap();
        let tls = out.tls.expect("tls");
        // Offering `h2` would let the peer answer CONNECT with HTTP/2 framing,
        // which this outbound does not speak.
        assert_eq!(tls.alpn, vec!["http/1.1".to_string()]);
        assert_eq!(tls.sni, "127.0.0.1", "SNI defaults to the server address");
    }

    #[test]
    fn sni_and_alpn_overrides_are_honoured() {
        let out = HttpOutbound::new(config(&[
            ("tls", nextjson::Value::Bool(true)),
            ("sni", string("proxy.example")),
            (
                "alpn",
                nextjson::Value::Array(vec![string("http/1.1"), string("h2")]),
            ),
        ]))
        .unwrap();
        let tls = out.tls.expect("tls");
        assert_eq!(tls.sni, "proxy.example");
        assert_eq!(tls.alpn, vec!["http/1.1".to_string(), "h2".to_string()]);
    }

    #[test]
    fn credentials_that_could_inject_a_header_are_refused() {
        let err = HttpOutbound::new(config(&[("username", string("a\r\nX-Evil: 1"))]))
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(err.contains("CR or LF"), "{err}");
        assert!(HttpOutbound::new(config(&[
            ("username", string("a")),
            ("password", string("b\nc")),
        ]))
        .is_err());
    }

    #[test]
    fn a_head_is_split_at_the_blank_line_and_the_rest_kept() {
        let raw = b"HTTP/1.1 200 Connection established\r\nServer: p\r\n\r\n\x16\x03\x01payload";
        let mut cursor = Cursor::new(raw.to_vec());
        let (head, leftover) =
            read_head(&mut cursor, Instant::now() + Duration::from_secs(1)).unwrap();
        assert!(head.starts_with("HTTP/1.1 200"));
        assert_eq!(parse_status_line(&head).unwrap(), 200);
        assert_eq!(leftover, b"\x16\x03\x01payload");
    }

    #[test]
    fn a_head_that_never_ends_is_capped_rather_than_grown() {
        struct Endless;
        impl Read for Endless {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                buf.fill(b'A');
                Ok(buf.len())
            }
        }
        let err = read_head(&mut Endless, Instant::now() + Duration::from_secs(1))
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(err.contains("exceeded"), "{err}");
    }

    #[test]
    fn an_idle_poll_is_retried_until_the_deadline() {
        struct Idle;
        impl Read for Idle {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "poll"))
            }
        }
        let start = Instant::now();
        let err = read_head(&mut Idle, start + Duration::from_millis(30))
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(start.elapsed() >= Duration::from_millis(25), "it must wait");
        assert!(err.contains("timed out"), "{err}");
    }

    #[test]
    fn a_connection_closed_before_the_head_is_an_error() {
        let mut empty = Cursor::new(Vec::new());
        let err = read_head(&mut empty, Instant::now() + Duration::from_secs(1))
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(err.contains("closed the connection"), "{err}");
    }

    #[test]
    fn a_non_http_response_names_what_the_peer_actually_sent() {
        let err = parse_status_line("SSH-2.0-OpenSSH_9.6\r\n\r\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not start with an HTTP version"), "{err}");
        assert!(parse_status_line("HTTP/1.1 abc").is_err());
        assert!(parse_status_line("").is_err());
        assert_eq!(parse_status_line("HTTP/1.1 200 OK").unwrap(), 200);
    }

    #[test]
    fn a_long_status_line_is_truncated_before_it_reaches_a_log() {
        let line = format!("SSH-2.0-{}", "x".repeat(400));
        let msg = truncate_for_log(&line);
        assert!(msg.len() <= 124, "{}", msg.len());
        assert!(msg.ends_with('…'));
        assert!(line.len() > msg.len());
    }

    /// The full path over a real socket, including the over-read: the fake
    /// proxy answers the CONNECT and *immediately* pushes a greeting, exactly
    /// as a MySQL or SSH server behind it would.
    #[test]
    fn a_tunnel_keeps_the_bytes_read_past_the_connect_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            let mut b = [0u8; 1];
            while sock.read_exact(&mut b).is_ok() {
                seen.push(b[0]);
                if seen.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&seen).to_string();
            assert!(head.starts_with("CONNECT nickname:3306 HTTP/1.1"), "{head}");
            assert!(head.contains("Proxy-Authorization: Basic "), "{head}");
            sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n\x4a\x00\x00\x00GREETING")
                .unwrap();
        });

        let out = HttpOutbound::new(local(
            port,
            &[("username", string("u")), ("password", string("p"))],
        ))
        .unwrap();

        let mut tunnel = out
            .open_tunnel(
                &TargetAddr::Domain("nickname".to_string(), 3306),
                Duration::from_secs(5),
            )
            .unwrap();
        let mut greeting = [0u8; 12];
        tunnel.read_exact(&mut greeting).unwrap();
        assert_eq!(&greeting, b"\x4a\x00\x00\x00GREETING");
    }

    /// A greeting-first service reached over an **HTTP/1.1** tunnel, where the
    /// probe can wrap the socket: the CONNECT head is already consumed, and
    /// the GET on top of it is what gets measured.
    #[test]
    fn an_http_probe_reports_an_http_status() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            let mut b = [0u8; 1];
            while sock.read_exact(&mut b).is_ok() {
                seen.push(b[0]);
                if seen.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\n\r\n");
            // Then read the tunnelled GET and answer 204.
            let mut get = Vec::new();
            let mut b = [0u8; 1];
            while sock.read_exact(&mut b).is_ok() {
                get.push(b[0]);
                if get.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&get).to_string();
            assert!(text.starts_with("GET /generate_204 HTTP/1.1"), "{text}");
            let _ = sock.write_all(b"HTTP/1.1 204 No Content\r\n\r\n");
        });

        let out = HttpOutbound::new(local(port, &[])).unwrap();
        let elapsed = out
            .test_http_latency(
                "http://cp.cloudflare.com/generate_204",
                Duration::from_secs(5),
            )
            .unwrap();
        assert!(elapsed < Duration::from_secs(5));
    }

    #[test]
    fn an_https_probe_through_an_https_proxy_says_why_it_cannot() {
        let out = HttpOutbound::new(config(&[("tls", nextjson::Value::Bool(true))])).unwrap();
        let err = out
            .test_http_latency("https://example.com/", Duration::from_secs(1))
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(err.contains("http://` test URL"), "{err}");
    }

    #[test]
    fn a_rejected_connect_names_the_status() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            let mut b = [0u8; 1];
            while sock.read_exact(&mut b).is_ok() {
                seen.push(b[0]);
                if seen.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let _ = sock.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");
        });

        let out = HttpOutbound::new(local(port, &[])).unwrap();
        let err = out
            .open_tunnel(
                &TargetAddr::Ip("1.2.3.4:80".parse().unwrap()),
                Duration::from_secs(5),
            )
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(err.contains("407"), "{err}");
    }
}
