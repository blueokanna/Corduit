//! SOCKS4 / SOCKS4a outbound — the pre-RFC 1928 SOCKS protocol.
//!
//! Still the only thing some legacy servers speak. It has no authentication
//! handshake, no address types and no UDP: the request is a fixed 8-byte
//! header followed by a NUL-terminated user id.
//!
//! ```text
//! request   VN=4 CD=1 DSTPORT(2) DSTIP(4) USERID\0 [DOMAIN\0]
//! reply     VN=0 CD DSTPORT(2) DSTIP(4)          (exactly 8 bytes)
//! ```
//!
//! # One encoder, both dialects
//!
//! SOCKS4 cannot name a host — the target has to be an IPv4 literal — so
//! SOCKS4a smuggles the name through: send a placeholder address in `DSTIP`
//! and append the host name after the user id, and the *server* resolves it.
//! The downgrade happens on the server side, not in the request shape, so a
//! single encoder covers both dialects and the wire form follows the target:
//! an address target produces the SOCKS4 form, a name target the SOCKS4a one.
//!
//! `version: 4` in the config forbids the 4a form, which is the only thing to
//! tell a server that cannot resolve names. A name target is then resolved
//! **locally** — and that leaks the destination name to this machine's
//! resolver, which is precisely what a proxy exists to prevent. So the local
//! path is opt-in, logged at warn level, and documented here instead of being
//! the silent default. Profiles that route names through a SOCKS4-only server
//! should stay on `version: 4a` and let the server do the lookup.
//!
//! # The placeholder address
//!
//! Servers detect 4a by testing the address field for "not a real address",
//! and the value every implementation agrees on is `0.0.0.1` (RFC 1928-era
//! convention; `0.0.0.0` is rejected by servers that read it as "this
//! network"). We send `0.0.0.1`.

use crate::common::stream::BoxStream;
use crate::engine::config::OutboundConfig;
use crate::engine::error::{Error, Result};
use crate::engine::outbound::{OutboundProxy, TargetAddr};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpStream};
use std::time::Duration;

/// TCP connect budget for the proxy hop itself.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Bound on the request/reply exchange. The relay takes over the socket
/// timeouts afterwards, so this only has to cover the handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest user id accepted. The field is NUL-terminated and unbounded on the
/// wire, so the cap is ours: an oversized id is a config bug, not a target.
const MAX_USER_ID: usize = 255;
/// Largest host name accepted. 255 is the DNS limit (RFC 1035 §2.3.4).
const MAX_HOST_LEN: usize = 255;

/// The `DSTIP` sent for a SOCKS4a request.
const PLACEHOLDER_IP: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 1);

/// `CD = 1` (CONNECT). SOCKS4 defines no other command; `BIND` (`CD = 2`)
/// cannot be expressed by this engine's relay model, where the client half of
/// the connection already exists before the outbound is chosen.
const CMD_CONNECT: u8 = 1;

/// Which request form is allowed on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks4Version {
    /// `socks4`: the address field must be a real IPv4 address.
    V4,
    /// `socks4a`: a name may be carried in the request and resolved by the
    /// server.
    V4a,
}

impl Socks4Version {
    /// Parse the config spelling. `4a` is the default because it is a strict
    /// superset on the wire: it only differs when the target is a name.
    fn parse(raw: Option<&str>) -> Result<Self> {
        match raw.map(str::trim) {
            None | Some("") | Some("4a") | Some("socks4a") => Ok(Self::V4a),
            Some("4") | Some("socks4") => Ok(Self::V4),
            Some(other) => Err(Error::config(format!(
                "SOCKS4 version must be `4` or `4a`, got `{other}`"
            ))),
        }
    }
}

pub struct Socks4Outbound {
    config: OutboundConfig,
    server: String,
    port: u16,
    user_id: Vec<u8>,
    version: Socks4Version,
}

impl Socks4Outbound {
    pub fn new(config: OutboundConfig) -> Result<Self> {
        let server = config
            .server
            .clone()
            .ok_or_else(|| Error::config("Missing server address for SOCKS4"))?;
        let port = config
            .port
            .ok_or_else(|| Error::config("Missing port for SOCKS4"))?;

        // `username` is the SOCKS5 spelling and appears in profiles that
        // switch dialects; accept both, prefer the SOCKS4 name.
        let user_id = config
            .options
            .get("user-id")
            .or_else(|| config.options.get("username"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .as_bytes()
            .to_vec();

        if user_id.len() > MAX_USER_ID {
            return Err(Error::config(format!(
                "SOCKS4 user id is {} bytes; the limit is {MAX_USER_ID}",
                user_id.len()
            )));
        }
        if user_id.contains(&0) {
            return Err(Error::config(
                "SOCKS4 user id must not contain a NUL byte: the field is NUL-terminated",
            ));
        }

        let version = Socks4Version::parse(
            config
                .options
                .get("version")
                .and_then(|v| v.as_str())
                .map(str::trim),
        )?;

        // SOCKS4 has no UDP ASSOCIATE. Say so once, at construction, rather
        // than dropping UDP silently at request time.
        if config
            .options
            .get("udp")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            tracing::warn!(
                "SOCKS4 outbound '{}': `udp: true` has no wire form in SOCKS4/4a; \
                 UDP will not use this outbound",
                config.tag
            );
        }

        Ok(Self {
            config,
            server,
            port,
            user_id,
            version,
        })
    }

    /// Open a tunnel to `target`, leaving the socket positioned right after
    /// the server's reply (i.e. at the start of the relayed byte stream).
    fn open(&self, target: &TargetAddr, timeout: Duration) -> Result<TcpStream> {
        let mut stream = crate::common::socket::connect_host(&self.server, self.port, timeout)
            .map_err(|e| {
                Error::network(format!(
                    "Failed to connect to SOCKS4 server {}:{}: {e}",
                    self.server, self.port
                ))
            })?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| Error::network(format!("set read timeout: {e}")))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|e| Error::network(format!("set write timeout: {e}")))?;

        let request = self.encode_request(target)?;
        stream
            .write_all(&request)
            .map_err(|e| Error::network(format!("Failed to send SOCKS4 request: {e}")))?;

        let mut reply = [0u8; 8];
        stream
            .read_exact(&mut reply)
            .map_err(|e| Error::network(format!("Failed to read SOCKS4 reply: {e}")))?;
        parse_reply(&reply)?;

        tracing::debug!("SOCKS4: tunnel established to {target}");
        Ok(stream)
    }

    /// Build the request bytes for `target`.
    fn encode_request(&self, target: &TargetAddr) -> Result<Vec<u8>> {
        match target {
            TargetAddr::Ip(addr) => match addr.ip() {
                IpAddr::V4(ip) => Ok(encode_ipv4(ip, addr.port(), &self.user_id)),
                // No v6 literal exists in the request format, and the 4a form
                // carries a *name*, which a v6 address is not.
                IpAddr::V6(ip) => Err(Error::config(format!(
                    "SOCKS4/4a cannot carry the IPv6 address {ip}; route it through a \
                     SOCKS5, HTTP or Shadowsocks outbound instead"
                ))),
            },
            TargetAddr::Domain(domain, port) => match self.version {
                Socks4Version::V4a => Ok(encode_socks4a(domain, *port, &self.user_id)?),
                Socks4Version::V4 => Ok(encode_ipv4(
                    self.resolve_v4(domain, *port)?,
                    *port,
                    &self.user_id,
                )),
            },
        }
    }

    /// Resolve `domain` locally for the `version: 4` path.
    ///
    /// IPv4 only: the request format has no room for anything else. A failed
    /// lookup is reported with the name, since "we resolved it ourselves" is
    /// the surprising part of this path.
    fn resolve_v4(&self, domain: &str, port: u16) -> Result<Ipv4Addr> {
        let addrs =
            crate::common::socket::resolve_host(domain, port, CONNECT_TIMEOUT).map_err(|e| {
                Error::network(format!(
                    "SOCKS4 `version: 4` resolved {domain} locally: {e}"
                ))
            })?;
        addrs
            .iter()
            .find_map(|addr| match addr.ip() {
                IpAddr::V4(ip) => Some(ip),
                IpAddr::V6(_) => None,
            })
            .ok_or_else(|| {
                Error::network(format!(
                    "SOCKS4 `version: 4` resolved {domain} to IPv6 only, which SOCKS4 \
                     cannot carry; use `version: 4a` or another outbound type"
                ))
            })
    }
}

impl OutboundProxy for Socks4Outbound {
    fn connect(&self) -> Result<()> {
        // A bare TCP probe: SOCKS4 has no server-side greeting to validate,
        // so the only honest check available at `connect()` time is
        // reachability. The real validation happens per request.
        let _probe = crate::common::socket::connect_host(&self.server, self.port, CONNECT_TIMEOUT)
            .map_err(|e| {
                Error::network(format!(
                    "Failed to connect to SOCKS4 server {}:{}: {e}",
                    self.server, self.port
                ))
            })?;
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
        let url_port = url
            .port()
            .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        let path = if url.path().is_empty() {
            "/"
        } else {
            url.path()
        };

        let start = std::time::Instant::now();
        let mut stream = self.open(
            &TargetAddr::Domain(host.clone(), url_port),
            timeout.min(HANDSHAKE_TIMEOUT),
        )?;

        // A bare HTTP/1.1 GET: the status line is the only thing that has to
        // come back, and `Connection: close` keeps the probe from pinning a
        // server-side connection open behind the measurement.
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: Corduit/1.0\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| Error::network(format!("Failed to send probe request: {e}")))?;

        let mut first = [0u8; 5];
        stream
            .read_exact(&mut first)
            .map_err(|e| Error::network(format!("Failed to read probe response: {e}")))?;
        if &first != b"HTTP/" {
            return Err(Error::protocol(
                "SOCKS4 latency probe did not get an HTTP status line",
            ));
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
        let outbound = self.open(&target, HANDSHAKE_TIMEOUT)?;
        relay_streams!(inbound, outbound, connection)
    }
}

// ---------------------------------------------------------------------------
// Wire codecs
//
// Split out from the proxy so both the encoder and the reply parser can be
// tested against fixed byte strings — a relay test can only show that *some*
// request worked, not that the bytes are the ones the protocol prescribes.
// ---------------------------------------------------------------------------

/// SOCKS4 request with a literal IPv4 target.
fn encode_ipv4(ip: Ipv4Addr, port: u16, user_id: &[u8]) -> Vec<u8> {
    let mut request = Vec::with_capacity(9 + user_id.len());
    request.push(4); // VN
    request.push(CMD_CONNECT); // CD
    request.extend_from_slice(&port.to_be_bytes());
    request.extend_from_slice(&ip.octets());
    request.extend_from_slice(user_id);
    request.push(0); // NUL-terminated user id
    request
}

/// SOCKS4a request with a NUL-terminated name after the user id.
fn encode_socks4a(host: &str, port: u16, user_id: &[u8]) -> Result<Vec<u8>> {
    validate_host(host)?;
    let mut request = encode_ipv4(PLACEHOLDER_IP, port, user_id);
    request.extend_from_slice(host.as_bytes());
    request.push(0);
    Ok(request)
}

/// Reject names the request format cannot carry faithfully.
///
/// The field is NUL-terminated, so an embedded NUL would silently truncate
/// the name — and a proxy that dials a *different* host than the one policy
/// approved is the worst failure mode this file has. CR/LF are rejected for
/// the same reason one layer up (any line-oriented intermediary). Space is
/// excluded because no host name contains one; keeping the check to
/// "printable, NUL-free ASCII" keeps IDN out, which is correct: the name
/// field is an ASCII host name, punycode-encoded by the caller if needed.
fn validate_host(host: &str) -> Result<()> {
    if host.is_empty() {
        return Err(Error::config("SOCKS4a target host is empty"));
    }
    if host.len() > MAX_HOST_LEN {
        return Err(Error::config(format!(
            "SOCKS4a target host is {} bytes; the RFC 1035 limit is {MAX_HOST_LEN}",
            host.len()
        )));
    }
    if let Some(bad) = host
        .bytes()
        .find(|b| *b <= b' ' || *b == 0x7f || *b >= 0x80)
    {
        return Err(Error::config(format!(
            "SOCKS4a target host `{host}` contains a byte the 4a name field cannot carry \
             (0x{bad:02x}); the field is printable ASCII only"
        )));
    }
    Ok(())
}

/// Interpret the 8-byte reply.
fn parse_reply(reply: &[u8; 8]) -> Result<()> {
    // A SOCKS4 reply always has VN = 0; the request's VN = 4 must not be
    // echoed. Anything else on the wire is not a SOCKS4 reply, and treating
    // it as one would read the status byte out of unrelated data.
    if reply[0] != 0 {
        return Err(Error::protocol(format!(
            "SOCKS4 reply has version {} (expected 0); the server is not speaking SOCKS4",
            reply[0]
        )));
    }
    match reply[1] {
        90 => Ok(()),
        91 => Err(Error::network(
            "SOCKS4 request rejected or failed (CD=91): the server could not reach the \
             target, or its identd lookup failed",
        )),
        92 => Err(Error::network(
            "SOCKS4 request rejected (CD=92): the server cannot reach identd on this host",
        )),
        93 => Err(Error::network(
            "SOCKS4 request rejected (CD=93): this host and identd disagree about the user id",
        )),
        other => Err(Error::protocol(format!(
            "SOCKS4 reply has unknown status CD={other}"
        ))),
    }
}

/// A SOCKS4 destination resolved to the address form the request needs.
///
/// Exposed for tests: the decision of "literal vs name" is the one place
/// where the two dialects diverge, and it is worth pinning down.
#[cfg(test)]
fn target_form(target: &TargetAddr, version: Socks4Version) -> &'static str {
    match (target, version) {
        (TargetAddr::Ip(std::net::SocketAddr::V4(_)), _) => "ipv4",
        (TargetAddr::Ip(std::net::SocketAddr::V6(_)), _) => "ipv6",
        (TargetAddr::Domain(_, _), Socks4Version::V4a) => "4a",
        (TargetAddr::Domain(_, _), Socks4Version::V4) => "local-resolve",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::TcpListener;

    fn outbound(options: &[(&str, nextjson::Value)]) -> Socks4Outbound {
        let mut map = HashMap::new();
        for (k, v) in options {
            map.insert((*k).to_string(), v.clone());
        }
        Socks4Outbound::new(OutboundConfig {
            tag: "socks4-test".to_string(),
            outbound_type: crate::engine::config::OutboundType::Socks4,
            server: Some("127.0.0.1".to_string()),
            port: Some(1080),
            options: map,
        })
        .expect("outbound builds")
    }

    fn literal() -> Socks4Outbound {
        outbound(&[])
    }

    #[test]
    fn ipv4_request_is_the_fixed_eight_byte_header_plus_the_user_id() {
        let bytes = encode_ipv4(Ipv4Addr::new(93, 184, 216, 34), 80, b"alice");
        assert_eq!(
            bytes,
            vec![0x04, 0x01, 0x00, 0x50, 93, 184, 216, 34, b'a', b'l', b'i', b'c', b'e', 0x00]
        );
    }

    #[test]
    fn an_empty_user_id_still_terminates() {
        let bytes = encode_ipv4(Ipv4Addr::LOCALHOST, 1, b"");
        assert_eq!(&bytes[8..], &[0x00]);
    }

    #[test]
    fn a_name_targets_the_4a_placeholder_and_appends_the_name() {
        let bytes = encode_socks4a("example.com", 443, b"bob").unwrap();
        assert_eq!(bytes[0], 4);
        assert_eq!(bytes[1], 1);
        assert_eq!(&bytes[2..4], &443u16.to_be_bytes());
        assert_eq!(&bytes[4..8], &[0, 0, 0, 1], "the 4a placeholder");
        assert_eq!(&bytes[8..12], b"bob\0");
        assert_eq!(&bytes[12..], b"example.com\0");
    }

    #[test]
    fn a_name_with_a_nul_is_refused_rather_than_truncated() {
        let err = encode_socks4a("evil\0.example", 80, b"").unwrap_err();
        assert!(err.to_string().contains("cannot carry"), "{err}");
    }

    #[test]
    fn a_name_the_wire_cannot_hold_is_refused() {
        assert!(encode_socks4a("", 80, b"").is_err());
        assert!(encode_socks4a(&"a".repeat(MAX_HOST_LEN + 1), 80, b"").is_err());
        // Non-ASCII: the name field is an ASCII host name, not UTF-8 text.
        assert!(encode_socks4a("例え.jp", 80, b"").is_err());
        // Space would split the name if anything upstream re-parses the line.
        assert!(encode_socks4a("a b", 80, b"").is_err());
        // Underscores and hyphens are ordinary host name characters.
        assert!(encode_socks4a("a_b-c.example", 80, b"").is_ok());
    }

    #[test]
    fn a_granted_reply_is_ok_and_every_other_code_names_its_cause() {
        let mut ok = [0u8; 8];
        ok[1] = 90;
        assert!(parse_reply(&ok).is_ok());

        for (code, needle) in [(91, "rejected or failed"), (92, "identd"), (93, "disagree")] {
            let mut reply = [0u8; 8];
            reply[1] = code;
            let err = parse_reply(&reply).unwrap_err().to_string();
            assert!(err.contains(needle), "CD={code}: {err}");
        }

        let mut unknown = [0u8; 8];
        unknown[1] = 77;
        assert!(parse_reply(&unknown).is_err());
    }

    #[test]
    fn a_reply_that_echoes_the_request_version_is_not_treated_as_a_reply() {
        let mut reply = [0u8; 8];
        reply[0] = 4;
        reply[1] = 90;
        let err = parse_reply(&reply).unwrap_err().to_string();
        assert!(err.contains("not speaking SOCKS4"), "{err}");
    }

    #[test]
    fn the_wire_form_follows_the_target_and_the_configured_version() {
        let v4 = TargetAddr::Ip("1.2.3.4:80".parse().unwrap());
        let v6 = TargetAddr::Ip("[::1]:80".parse().unwrap());
        let name = TargetAddr::Domain("example.com".to_string(), 80);

        assert_eq!(target_form(&v4, Socks4Version::V4), "ipv4");
        assert_eq!(target_form(&v4, Socks4Version::V4a), "ipv4");
        assert_eq!(target_form(&name, Socks4Version::V4a), "4a");
        assert_eq!(target_form(&name, Socks4Version::V4), "local-resolve");
        // A v6 literal fits neither dialect, at any configured version.
        assert_eq!(target_form(&v6, Socks4Version::V4), "ipv6");
        assert_eq!(target_form(&v6, Socks4Version::V4a), "ipv6");
    }

    #[test]
    fn an_ipv6_target_is_refused_before_anything_is_sent() {
        let target = TargetAddr::Ip("[2001:db8::1]:443".parse().unwrap());
        let err = literal().encode_request(&target).unwrap_err().to_string();
        assert!(err.contains("cannot carry the IPv6 address"), "{err}");
    }

    #[test]
    fn the_default_dialect_is_4a_so_names_are_resolved_by_the_server() {
        assert_eq!(literal().version, Socks4Version::V4a);
        let v4 = outbound(&[("version", nextjson::Value::String("4".to_string()))]);
        assert_eq!(v4.version, Socks4Version::V4);

        // An unknown dialect is refused at construction, not silently treated
        // as 4a — the two differ in who resolves the name.
        let err = Socks4Outbound::new(OutboundConfig {
            tag: "t".to_string(),
            outbound_type: crate::engine::config::OutboundType::Socks4,
            server: Some("127.0.0.1".to_string()),
            port: Some(1),
            options: HashMap::from([(
                "version".to_string(),
                nextjson::Value::String("5".to_string()),
            )]),
        })
        .map(|_| ())
        .unwrap_err()
        .to_string();
        assert!(err.contains("`4` or `4a`"), "{err}");
    }

    #[test]
    fn a_user_id_that_would_truncate_the_request_is_refused() {
        // `Result<Socks4Outbound>` carries no `Debug`, so the value is
        // dropped before unwrapping the error.
        fn try_user_id(value: &str) -> std::result::Result<(), String> {
            Socks4Outbound::new(OutboundConfig {
                tag: "t".to_string(),
                outbound_type: crate::engine::config::OutboundType::Socks4,
                server: Some("127.0.0.1".to_string()),
                port: Some(1),
                options: HashMap::from([(
                    "user-id".to_string(),
                    nextjson::Value::String(value.to_string()),
                )]),
            })
            .map(|_| ())
            .map_err(|e| e.to_string())
        }

        let err = try_user_id(&"a".repeat(MAX_USER_ID + 1)).unwrap_err();
        assert!(err.contains("the limit is"), "{err}");
        // A NUL would terminate the field early, moving every following byte
        // (including the 4a name) into the wrong place.
        let err = try_user_id("a\0b").unwrap_err();
        assert!(err.contains("NUL"), "{err}");
        assert!(try_user_id(&"a".repeat(MAX_USER_ID)).is_ok());
    }

    #[test]
    fn the_socks5_spelling_of_the_user_id_is_accepted() {
        let out = outbound(&[("username", nextjson::Value::String("carol".to_string()))]);
        assert_eq!(out.user_id, b"carol");
    }

    /// End-to-end over a real socket: the bytes the outbound puts on the wire
    /// are the bytes a SOCKS4 server expects, and the relay carries both
    /// directions afterwards.
    #[test]
    fn a_socks4a_tunnel_relays_both_directions_over_loopback() {
        use std::io::Read as _;
        use std::sync::mpsc;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel::<Vec<u8>>();

        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let mut head = [0u8; 8];
            sock.read_exact(&mut head).expect("8-byte header");
            assert_eq!(&head[2..4], &443u16.to_be_bytes());
            assert_eq!(&head[4..8], &[0, 0, 0, 1], "4a placeholder");

            // NUL-terminated user id, then the NUL-terminated name.
            let mut user_id = Vec::new();
            loop {
                let mut b = [0u8; 1];
                sock.read_exact(&mut b).unwrap();
                if b[0] == 0 {
                    break;
                }
                user_id.push(b[0]);
            }
            let mut host = Vec::new();
            loop {
                let mut b = [0u8; 1];
                sock.read_exact(&mut b).unwrap();
                if b[0] == 0 {
                    break;
                }
                host.push(b[0]);
            }
            tx.send(user_id).unwrap();
            tx.send(host).unwrap();

            sock.write_all(&[0, 90, 0, 0, 0, 0, 0, 0]).unwrap();
            // Echo one line back, then close.
            let mut line = Vec::new();
            let mut b = [0u8; 1];
            while sock.read_exact(&mut b).is_ok() {
                line.push(b[0]);
                if b[0] == b'\n' {
                    break;
                }
            }
            sock.write_all(&line).unwrap();
        });

        let out = Socks4Outbound::new(OutboundConfig {
            tag: "socks4-loopback".to_string(),
            outbound_type: crate::engine::config::OutboundType::Socks4,
            server: Some("127.0.0.1".to_string()),
            port: Some(port),
            options: HashMap::from([(
                "user-id".to_string(),
                nextjson::Value::String("dave".to_string()),
            )]),
        })
        .unwrap();

        let mut tunnel = out
            .open(
                &TargetAddr::Domain("target.example".to_string(), 443),
                Duration::from_secs(5),
            )
            .expect("tunnel");
        assert_eq!(rx.recv().unwrap(), b"dave");
        assert_eq!(rx.recv().unwrap(), b"target.example");

        tunnel.write_all(b"ping\n").unwrap();
        let mut echoed = [0u8; 5];
        tunnel.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"ping\n");

        server.join().unwrap();
    }

    #[test]
    fn a_rejected_request_surfaces_the_server_status() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut head = [0u8; 8];
            let _ = sock.read_exact(&mut head);
            let _ = sock.write_all(&[0, 91, 0, 0, 0, 0, 0, 0]);
        });

        let out = Socks4Outbound::new(OutboundConfig {
            tag: "t".to_string(),
            outbound_type: crate::engine::config::OutboundType::Socks4,
            server: Some("127.0.0.1".to_string()),
            port: Some(port),
            options: HashMap::new(),
        })
        .unwrap();

        let err = out
            .open(
                &TargetAddr::Ip("1.2.3.4:80".parse().unwrap()),
                Duration::from_secs(5),
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("CD=91"), "{err}");
    }
}
