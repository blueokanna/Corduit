//! Hysteria 1 outbound on the in-repo QUIC v1 transport.
//!
//! Hysteria 1 is not Hysteria 2 with a smaller version number: they are
//! different protocols sharing a name, a port convention and an author. v1
//! authenticates on a dedicated **control stream** with a struct-encoded
//! hello, opens one bi-stream per TCP connection, and relays UDP with
//! struct-encoded datagrams. v2 authenticates with an HTTP/3 `POST /auth` and
//! frames requests differently. Only the QUIC layer is common.
//!
//! Wire format (as implemented by `apernet/hysteria` v1.3.5, package
//! `core/cs`). Every integer is big-endian and every struct is packed with no
//! alignment padding, which is what Go's `struc` produces:
//!
//! ```text
//! control stream (the first bi-stream, opened by the client)
//!   [u8 version = 3]
//!   [u64 send_bps][u64 recv_bps][u16 auth_len][auth]        client hello
//!   <- [u8 ok][u64 send_bps][u64 recv_bps][u16 msg_len][msg]
//!
//! TCP (one bi-stream per connection)
//!   [u8 udp = 0][u16 host_len][host][u16 port]              client request
//!   <- [u8 ok][u32 udp_session_id][u16 msg_len][msg]        server response
//!   then raw bytes both ways on the same stream
//!
//! UDP (one long-lived bi-stream per session, QUIC datagrams for the data)
//!   session stream: [u8 udp = 1][u16 host_len = 0][u16 port = 0]
//!                   <- [u8 ok][u32 udp_session_id][u16 msg_len][msg]
//!   datagram:       [u32 session_id][u16 host_len][host][u16 port]
//!                   [u16 msg_id][u8 frag_id][u8 frag_count]
//!                   [u16 data_len][data]
//!   frag_count is 1 for an unfragmented message; fragments share msg_id.
//! ```
//!
//! # Honest scope
//!
//! * ALPN is `hysteria` — v1's own value. Offering v2's `h3` fails the
//!   handshake, because the server selects the protocol by name.
//! * `up`/`down` are advisory. The server uses them for its own accounting;
//!   this client does not shape to them, and Hysteria's Brutal congestion
//!   controller is not reimplemented (the transport runs its own AIMD).
//! * **UDP is not implemented.** v1 needs a long-lived session stream per
//!   association plus a reader that filters datagrams by the server-assigned
//!   session id and reassembles fragments. The engine's `relay_udp_packet` is
//!   one-shot and stateless, so there is nowhere to keep that association;
//!   [`OutboundProxy::relay_udp_packet`] reports exactly this instead of
//!   dropping packets. TCP is unaffected.
//! * **`faketcp` and `wechat` obfs are refused**, not ignored. They are
//!   alternative encapsulations of the UDP socket underneath (a fake TCP
//!   stream, WeChat's UDP shape). A server expecting one drops plain QUIC in
//!   silence, so a config naming one is a hard error carrying the reason.
//! * `disable-mtu-discovery` has no equivalent here and warns.

use crate::common::stream::BoxStream;
use crate::engine::config::OutboundConfig;
use crate::engine::connection_tracker::TrackedConnection;
use crate::engine::error::{Error, Result};
use crate::engine::outbound::{OutboundProxy, TargetAddr};
use crate::engine::tls::yaml_value_to_string;
use crate::protocol::quic::{
    ClientConfig as QuicClientConfig, ClientConnection, PacketObfs, QuicClient, QuicRecvStream,
    QuicSendStream, QuicStreamPair, XPlus,
};
use parking_lot::Mutex;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// First byte of the control stream.
const PROTOCOL_VERSION: u8 = 3;
/// Default ALPN.
const DEFAULT_ALPN: &str = "hysteria";
/// Bound on any length-prefixed string a server can ask us to allocate.
const MAX_MESSAGE: usize = 8192;

/// Hysteria 1 outbound settings (kept for introspection and tests).
#[derive(Debug, Clone)]
pub struct HysteriaConfig {
    pub server: String,
    pub port: u16,
    pub auth: String,
    pub alpn: String,
    pub sni: Option<String>,
    pub skip_cert_verify: bool,
    pub up_mbps: Option<u64>,
    pub down_mbps: Option<u64>,
    pub obfs: Option<String>,
    pub fingerprint: Option<String>,
}

impl Default for HysteriaConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 443,
            auth: String::new(),
            alpn: DEFAULT_ALPN.to_string(),
            sni: None,
            skip_cert_verify: false,
            up_mbps: None,
            down_mbps: None,
            obfs: None,
            fingerprint: None,
        }
    }
}

pub struct HysteriaOutbound {
    config: OutboundConfig,
    hy_config: HysteriaConfig,
    connection: Mutex<Option<Arc<HysteriaConnection>>>,
}

/// An authenticated Hysteria 1 connection plus the control stream that keeps
/// it alive. Every `relay_tcp` opens a fresh bi-stream on it.
struct HysteriaConnection {
    conn: Arc<ClientConnection>,
    /// The control stream's receive half. The server sends nothing after its
    /// hello, but the stream has to stay open: a server that watches the
    /// control stream treats a reset one as the client leaving.
    #[allow(dead_code)]
    control: Mutex<QuicRecvStream>,
}

impl HysteriaOutbound {
    pub fn new(config: OutboundConfig) -> Result<Self> {
        let server = config
            .server
            .clone()
            .ok_or_else(|| Error::config("Missing server address for Hysteria"))?;
        let port = config
            .port
            .ok_or_else(|| Error::config("Missing port for Hysteria"))?;

        let auth = config
            .options
            .get("auth")
            .or_else(|| config.options.get("auth-str"))
            .or_else(|| config.options.get("password"))
            .map(yaml_value_to_string)
            .unwrap_or_default();
        if auth.is_empty() {
            return Err(Error::config(
                "Hysteria 1 requires an `auth` string (the server's password-mode credential)",
            ));
        }

        let obfs = config
            .options
            .get("obfs")
            .map(yaml_value_to_string)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        // A non-default encapsulation is a different wire shape, not a tuning
        // knob: a server expecting FakeTCP drops plain QUIC in silence, so a
        // config naming one fails here rather than timing out later.
        if let Some(mode) = obfs.as_deref() {
            if mode.eq_ignore_ascii_case("faketcp") || mode.eq_ignore_ascii_case("wechat") {
                return Err(Error::config(format!(
                    "Hysteria 1 obfs `{mode}` is a UDP packet encapsulation this build does not \
                     implement; only the default (XPlus) is available"
                )));
            }
        }

        if config
            .options
            .get("disable-mtu-discovery")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            warn!(
                "Hysteria outbound '{}': `disable-mtu-discovery` is a QUIC-internal knob with no \
                 equivalent in this transport; ignoring",
                config.tag
            );
        }

        let hy_config = HysteriaConfig {
            server,
            port,
            auth,
            alpn: config
                .options
                .get("alpn")
                .map(yaml_value_to_string)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| DEFAULT_ALPN.to_string()),
            sni: config
                .options
                .get("sni")
                .map(yaml_value_to_string)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            skip_cert_verify: config
                .options
                .get("skip-cert-verify")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            up_mbps: config
                .options
                .get("up")
                .or_else(|| config.options.get("up-mbps"))
                .and_then(|v| v.as_u64()),
            down_mbps: config
                .options
                .get("down")
                .or_else(|| config.options.get("down-mbps"))
                .and_then(|v| v.as_u64()),
            obfs,
            fingerprint: config
                .options
                .get("fingerprint")
                .map(yaml_value_to_string)
                .filter(|s| !s.trim().is_empty()),
        };

        debug!(
            "Creating Hysteria outbound: server={}:{}, alpn={}, obfs={:?}, up={:?}, down={:?}",
            hy_config.server,
            hy_config.port,
            hy_config.alpn,
            hy_config.obfs,
            hy_config.up_mbps,
            hy_config.down_mbps
        );

        Ok(Self {
            config,
            hy_config,
            connection: Mutex::new(None),
        })
    }

    /// The parsed settings, for introspection and tests.
    pub fn hy_config(&self) -> &HysteriaConfig {
        &self.hy_config
    }

    fn build_quic_config(&self, socket_addr: SocketAddr) -> QuicClientConfig {
        let server_name = self
            .hy_config
            .sni
            .clone()
            .unwrap_or_else(|| self.hy_config.server.clone());

        let mut cfg = QuicClientConfig::new(socket_addr, server_name);
        cfg.alpn = vec![self.hy_config.alpn.clone()];
        cfg.skip_cert_verify = self.hy_config.skip_cert_verify;
        cfg.idle_timeout = Duration::from_secs(30);
        // The reference client keeps the connection alive at two fifths of the
        // idle timeout. Ten seconds holds a NAT mapping open with no
        // measurable traffic.
        cfg.keep_alive_interval = Some(Duration::from_secs(10));
        cfg.max_concurrent_bidi_streams = 100;
        cfg.max_concurrent_uni_streams = 100;
        if let Some(password) = &self.hy_config.obfs {
            cfg.obfs = Some(Arc::new(PacketObfs::XPlus(XPlus::new(password.as_bytes()))));
        }
        cfg
    }

    fn get_or_create_connection(&self) -> Result<Arc<HysteriaConnection>> {
        let mut guard = self.connection.lock();
        if let Some(conn) = guard.as_ref() {
            if !conn.conn.is_closed() {
                return Ok(conn.clone());
            }
        }

        let socket_addr = crate::common::socket::resolve_host(
            &self.hy_config.server,
            self.hy_config.port,
            Duration::from_secs(30),
        )
        .map_err(|e| {
            Error::network(format!(
                "Failed to resolve Hysteria server {}:{}: {e}",
                self.hy_config.server, self.hy_config.port
            ))
        })?
        .into_iter()
        .next()
        .ok_or_else(|| {
            Error::network(format!(
                "No addresses found for Hysteria server {}:{}",
                self.hy_config.server, self.hy_config.port
            ))
        })?;

        let client = QuicClient::new(self.build_quic_config(socket_addr));
        let conn = client
            .connect()
            .map_err(|e| Error::network(format!("QUIC handshake failed: {e}")))?;
        debug!("Hysteria QUIC connection established to {socket_addr}");

        let (mut send, mut recv) = conn
            .open_bi()
            .map_err(|e| Error::network(format!("Failed to open the control stream: {e}")))?;

        // The control stream is where the server decides whether we may enter.
        // Its verdict is read before any request stream is opened, so a
        // rejected credential fails once with the server's own reason instead
        // of every stream failing in turn.
        let hello = encode_client_hello(
            self.hy_config.up_mbps.unwrap_or(0),
            self.hy_config.down_mbps.unwrap_or(0),
            self.hy_config.auth.as_bytes(),
        );
        send.write_all(&hello)
            .map_err(|e| Error::network(format!("Failed to send the client hello: {e}")))?;
        send.flush()
            .map_err(|e| Error::network(format!("Failed to flush the client hello: {e}")))?;

        let (ok, send_bps, recv_bps, message) = read_server_hello(&mut recv)?;
        if !ok {
            return Err(Error::network(format!(
                "Hysteria server rejected the auth string: {}",
                display_or(&message, "no reason given")
            )));
        }
        debug!("Hysteria auth accepted (server send={send_bps} B/s recv={recv_bps} B/s)");

        let hy = Arc::new(HysteriaConnection {
            conn,
            control: Mutex::new(recv),
        });
        *guard = Some(hy.clone());
        Ok(hy)
    }
}

impl OutboundProxy for HysteriaOutbound {
    fn connect(&self) -> Result<()> {
        let _conn = self.get_or_create_connection()?;
        info!(
            "Hysteria outbound '{}' connected to {}:{}",
            self.config.tag, self.hy_config.server, self.hy_config.port
        );
        Ok(())
    }

    fn disconnect(&self) -> Result<()> {
        if let Some(conn) = self.connection.lock().take() {
            conn.conn.close();
        }
        Ok(())
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn server_addr(&self) -> Option<(String, u16)> {
        Some((self.hy_config.server.clone(), self.hy_config.port))
    }

    fn supports_udp(&self) -> bool {
        // Reported as unsupported rather than accepted and dropped: see
        // `relay_udp_packet`.
        false
    }

    fn relay_udp_packet(&self, _target: &TargetAddr, _data: &[u8]) -> Result<Vec<u8>> {
        Err(Error::config(
            "Hysteria 1 UDP needs a long-lived session stream per association plus a datagram \
             reader keyed by the server-assigned session id; this engine's one-shot UDP path \
             has nowhere to keep that state, so UDP is not routed through this outbound",
        ))
    }

    fn test_http_latency(&self, test_url: &str, timeout: Duration) -> Result<Duration> {
        let url = crate::common::url::Url::parse(test_url)
            .map_err(|e| Error::config(format!("Invalid test URL: {e}")))?;
        let host = url
            .host_str()
            .ok_or_else(|| Error::config("Test URL has no host"))?
            .to_string();
        let url_port = url
            .port()
            .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        let path = if url.path().is_empty() {
            "/"
        } else {
            url.path()
        };

        let start = std::time::Instant::now();
        let conn = self.get_or_create_connection()?;
        let (mut send, mut recv) =
            conn.open_tcp_stream(&TargetAddr::Domain(host.clone(), url_port))?;

        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: Corduit/1.0\r\n\r\n"
        );
        send.write_all(request.as_bytes())
            .map_err(|e| Error::network(format!("Failed to send probe request: {e}")))?;
        send.flush()
            .map_err(|e| Error::network(format!("Failed to flush probe request: {e}")))?;

        // A QUIC stream read parks until data arrives, and the stream API does
        // not take a deadline. Reading on a worker thread and waiting on a
        // channel keeps the bound at the caller's timeout, at the cost of one
        // parked thread when the peer is silent.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut first = [0u8; 5];
            let _ = tx.send(recv.read_exact(&mut first).map(|_| first));
        });
        match rx.recv_timeout(timeout) {
            Ok(Ok(first)) if &first == b"HTTP/" => Ok(start.elapsed()),
            Ok(Ok(_)) => Err(Error::protocol(
                "Hysteria latency probe did not get an HTTP status line",
            )),
            Ok(Err(e)) => Err(Error::network(format!(
                "Failed to read probe response: {e}"
            ))),
            Err(_) => Err(Error::network("Hysteria latency probe timed out")),
        }
    }

    fn relay_tcp(&self, inbound: BoxStream, target: TargetAddr) -> Result<()> {
        self.relay_tcp_with_connection(inbound, target, None)
    }

    fn relay_tcp_with_connection(
        &self,
        inbound: BoxStream,
        target: TargetAddr,
        connection: Option<Arc<TrackedConnection>>,
    ) -> Result<()> {
        let conn = self.get_or_create_connection()?;
        let (send, recv) = conn.open_tcp_stream(&target)?;
        debug!(
            "Hysteria: relaying TCP to {target} via {}:{}",
            self.hy_config.server, self.hy_config.port
        );
        relay_streams!(inbound, QuicStreamPair::new(send, recv), connection)
    }
}

impl HysteriaConnection {
    /// Open one bi-stream and negotiate a TCP target on it.
    fn open_tcp_stream(&self, target: &TargetAddr) -> Result<(QuicSendStream, QuicRecvStream)> {
        let (mut send, mut recv) = self
            .conn
            .open_bi()
            .map_err(|e| Error::network(format!("Failed to open a TCP stream: {e}")))?;

        let request = encode_client_request(false, &target.host(), target.port());
        send.write_all(&request)
            .map_err(|e| Error::network(format!("Failed to send the TCP request: {e}")))?;
        send.flush()
            .map_err(|e| Error::network(format!("Failed to flush the TCP request: {e}")))?;

        let response = read_server_response(&mut recv)?;
        if !response.ok {
            return Err(Error::network(format!(
                "Hysteria server refused {target}: {}",
                display_or(&response.message, "no reason given")
            )));
        }
        Ok((send, recv))
    }
}

// ---------------------------------------------------------------------------
// Codecs
//
// Go's `struc` packs these structs with no padding, so every field lands at the
// offset its size implies: `bool` is one byte, a `string`/`[]byte` is preceded
// by the `u16` length its `sizeof=` tag names, and all integers are big-endian.
//
// Written by hand rather than derived, because the failure mode of a wrong
// layout is a silent server-side drop, and a hand-written codec is the only
// version a byte-exact test can pin down.
// ---------------------------------------------------------------------------

/// A `u16`-length-prefixed field's length.
///
/// The wire field is 16 bits, so a longer value cannot be expressed. Encoding
/// truncates at the ceiling rather than wrapping the length: a wrapped length
/// would place every following field at an offset the receiver does not
/// expect, while a truncated credential simply fails auth with a clear reason.
fn u16_len(len: usize) -> u16 {
    u16::try_from(len).unwrap_or(u16::MAX)
}

/// `[u8 version][u64 send_bps][u64 recv_bps][u16 auth_len][auth]`
pub(crate) fn encode_client_hello(send_bps: u64, recv_bps: u64, auth: &[u8]) -> Vec<u8> {
    let auth = &auth[..auth.len().min(usize::from(u16::MAX))];
    let mut out = Vec::with_capacity(1 + 20 + auth.len());
    out.push(PROTOCOL_VERSION);
    out.extend_from_slice(&send_bps.to_be_bytes());
    out.extend_from_slice(&recv_bps.to_be_bytes());
    out.extend_from_slice(&u16_len(auth.len()).to_be_bytes());
    out.extend_from_slice(auth);
    out
}

/// `[u8 udp][u16 host_len][host][u16 port]`
pub(crate) fn encode_client_request(udp: bool, host: &str, port: u16) -> Vec<u8> {
    let host = host.as_bytes();
    let host = &host[..host.len().min(usize::from(u16::MAX))];
    let mut out = Vec::with_capacity(5 + host.len());
    out.push(u8::from(udp));
    out.extend_from_slice(&u16_len(host.len()).to_be_bytes());
    out.extend_from_slice(host);
    out.extend_from_slice(&port.to_be_bytes());
    out
}

/// Read the control stream's hello.
///
/// Returns `(ok, send_bps, recv_bps, message)` and borrows the stream only for
/// the duration of the read, so the caller keeps ownership of it — the stream
/// outlives the handshake.
fn read_server_hello(stream: &mut QuicRecvStream) -> Result<(bool, u64, u64, String)> {
    let ok = read_u8(stream)? != 0;
    let send_bps = read_u64(stream)?;
    let recv_bps = read_u64(stream)?;
    let message = read_string(stream)?;
    Ok((ok, send_bps, recv_bps, message))
}

struct ServerResponse {
    ok: bool,
    /// Present on every response; only a UDP session uses it, and UDP is not
    /// implemented, so it is parsed (to keep the frame consumed) but unused.
    #[allow(dead_code)]
    udp_session_id: u32,
    message: String,
}

/// `[u8 ok][u32 udp_session_id][u16 msg_len][msg]`
fn read_server_response(stream: &mut QuicRecvStream) -> Result<ServerResponse> {
    let ok = read_u8(stream)? != 0;
    let udp_session_id = read_u32(stream)?;
    let message = read_string(stream)?;
    Ok(ServerResponse {
        ok,
        udp_session_id,
        message,
    })
}

fn read_exactly(stream: &mut QuicRecvStream, n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    stream
        .read_exact(&mut buf)
        .map_err(|e| Error::network(format!("Failed to read {n} bytes from the stream: {e}")))?;
    Ok(buf)
}

fn read_u8(stream: &mut QuicRecvStream) -> Result<u8> {
    Ok(read_exactly(stream, 1)?[0])
}

fn read_u32(stream: &mut QuicRecvStream) -> Result<u32> {
    let b = read_exactly(stream, 4)?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64(stream: &mut QuicRecvStream) -> Result<u64> {
    let b = read_exactly(stream, 8)?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&b);
    Ok(u64::from_be_bytes(arr))
}

/// A `u16`-length-prefixed string, with the length checked before allocating:
/// a hostile length field must not be able to reserve memory the frame cannot
/// fill.
fn read_string(stream: &mut QuicRecvStream) -> Result<String> {
    let len = usize::from(u16::from_be_bytes([read_u8(stream)?, read_u8(stream)?]));
    if len > MAX_MESSAGE {
        return Err(Error::protocol(format!(
            "Hysteria string of {len} bytes exceeds the {MAX_MESSAGE}-byte cap"
        )));
    }
    let bytes = read_exactly(stream, len)?;
    String::from_utf8(bytes)
        .map_err(|e| Error::protocol(format!("Hysteria string is not UTF-8: {e}")))
}

/// The text to show for a server message that may be empty.
fn display_or(message: &str, fallback: &str) -> String {
    if message.is_empty() {
        fallback.to_string()
    } else {
        message.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(options: &[(&str, nextjson::Value)]) -> OutboundConfig {
        let mut map = HashMap::new();
        for (k, v) in options {
            map.insert((*k).to_string(), v.clone());
        }
        OutboundConfig {
            tag: "hy-test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Hysteria,
            server: Some("hy.example".to_string()),
            port: Some(443),
            options: map,
        }
    }

    fn string(value: &str) -> nextjson::Value {
        nextjson::Value::String(value.to_string())
    }

    fn build(options: &[(&str, nextjson::Value)]) -> Result<HysteriaConfig> {
        HysteriaOutbound::new(config(options)).map(|o| o.hy_config().clone())
    }

    fn number(value: u64) -> nextjson::Value {
        nextjson::Value::Number(nextjson::Number::from(value))
    }

    #[test]
    fn the_client_hello_is_the_documented_byte_layout() {
        let hello = encode_client_hello(1_000_000, 2_000_000, b"secret");
        assert_eq!(hello[0], PROTOCOL_VERSION);
        assert_eq!(&hello[1..9], &1_000_000u64.to_be_bytes());
        assert_eq!(&hello[9..17], &2_000_000u64.to_be_bytes());
        assert_eq!(&hello[17..19], &6u16.to_be_bytes(), "auth length");
        assert_eq!(&hello[19..], b"secret");
        assert_eq!(hello.len(), 1 + 8 + 8 + 2 + 6);
    }

    #[test]
    fn an_over_long_auth_is_truncated_to_the_length_field_not_wrapped() {
        let auth = vec![b'a'; usize::from(u16::MAX) + 10];
        let hello = encode_client_hello(0, 0, &auth);
        // The declared length and the bytes actually written must agree: a
        // wrapped length would misplace every following field.
        assert_eq!(&hello[17..19], &u16::MAX.to_be_bytes());
        assert_eq!(hello.len(), 19 + usize::from(u16::MAX));
    }

    #[test]
    fn a_tcp_request_carries_the_target_verbatim() {
        let request = encode_client_request(false, "example.com", 443);
        assert_eq!(request[0], 0, "udp = false");
        assert_eq!(&request[1..3], &11u16.to_be_bytes());
        assert_eq!(&request[3..14], b"example.com");
        assert_eq!(&request[14..16], &443u16.to_be_bytes());
        assert_eq!(request.len(), 16);

        // An address literal goes out as text, exactly as the reference client
        // writes it: the host field has no type tag.
        let literal = encode_client_request(false, "1.2.3.4", 53);
        assert_eq!(&literal[3..10], b"1.2.3.4");
        assert_eq!(&literal[10..12], &53u16.to_be_bytes());
    }

    #[test]
    fn a_udp_session_request_has_no_target() {
        // The session stream only establishes the association; the address
        // travels in the datagrams.
        assert_eq!(encode_client_request(true, "", 0), vec![1, 0, 0, 0, 0]);
    }

    #[test]
    fn the_auth_string_is_required_and_named_in_the_error() {
        let err = build(&[]).unwrap_err().to_string();
        assert!(err.contains("auth"), "{err}");
        assert!(build(&[("auth", string(""))]).is_err());
        assert!(build(&[("auth", string("x"))]).is_ok());
    }

    #[test]
    fn the_password_spelling_is_accepted_as_auth() {
        let cfg = build(&[("password", string("hunter2"))]).unwrap();
        assert_eq!(cfg.auth, "hunter2");
        // `auth` wins when both are present: it is v1's own name.
        let cfg = build(&[("password", string("ignored")), ("auth", string("chosen"))]).unwrap();
        assert_eq!(cfg.auth, "chosen");
    }

    #[test]
    fn the_default_alpn_is_hysteria_ones_own_not_hysteria_twos() {
        let cfg = build(&[("auth", string("x"))]).unwrap();
        assert_eq!(cfg.alpn, "hysteria");
        assert_ne!(cfg.alpn, "h3", "h3 is Hysteria 2's ALPN");
    }

    #[test]
    fn non_default_udp_encapsulations_are_refused_with_the_reason() {
        for mode in ["faketcp", "FakeTCP", "wechat"] {
            let err = build(&[("auth", string("x")), ("obfs", string(mode))])
                .unwrap_err()
                .to_string();
            assert!(err.contains("encapsulation"), "{mode}: {err}");
        }
        // The default obfuscator is accepted and kept as the XPlus key.
        let cfg = build(&[("auth", string("x")), ("obfs", string("secret"))]).unwrap();
        assert_eq!(cfg.obfs.as_deref(), Some("secret"));
        // An empty obfs means "none", not "an empty password".
        let cfg = build(&[("auth", string("x")), ("obfs", string(""))]).unwrap();
        assert!(cfg.obfs.is_none());
    }

    #[test]
    fn up_and_down_accept_both_spellings() {
        let cfg = build(&[
            ("auth", string("x")),
            ("up", number(50)),
            ("down-mbps", number(200)),
        ])
        .unwrap();
        assert_eq!(cfg.up_mbps, Some(50));
        assert_eq!(cfg.down_mbps, Some(200));
        assert_eq!(build(&[("auth", string("x"))]).unwrap().up_mbps, None);
    }

    #[test]
    fn a_missing_endpoint_is_a_config_error() {
        let mut c = config(&[("auth", string("x"))]);
        c.server = None;
        assert!(HysteriaOutbound::new(c).is_err());
        let mut c = config(&[("auth", string("x"))]);
        c.port = None;
        assert!(HysteriaOutbound::new(c).is_err());
    }

    #[test]
    fn the_string_cap_is_lower_than_anything_the_length_field_could_describe() {
        // If the cap were at or above the u16 ceiling it would never bite, and
        // a 64 KiB server string would be allocated on request.
        assert!(MAX_MESSAGE < usize::from(u16::MAX));
    }

    #[test]
    fn an_empty_server_message_falls_back_to_a_readable_phrase() {
        assert_eq!(display_or("", "no reason given"), "no reason given");
        assert_eq!(display_or("ACL rejected", "x"), "ACL rejected");
    }

    #[test]
    fn udp_is_reported_as_unsupported_rather_than_accepted() {
        let out = HysteriaOutbound::new(config(&[("auth", string("x"))])).unwrap();
        assert!(!out.supports_udp());
        let err = out
            .relay_udp_packet(&TargetAddr::Domain("dns.test".to_string(), 53), b"\x00")
            .unwrap_err()
            .to_string();
        assert!(err.contains("session stream"), "{err}");
    }
}
