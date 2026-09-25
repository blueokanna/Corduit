//! Upstream server strings: what an operator writes, and what RecurseX needs.
//!
//! A profile names its resolvers with a scheme and an optional port:
//!
//! | Spelling | Transport |
//! |---|---|
//! | `8.8.8.8`, `8.8.8.8:53`, `8.8.8.8@53` | UDP |
//! | `udp://8.8.8.8`, `tcp://8.8.8.8:53` | UDP / TCP |
//! | `tls://dns.google`, `tls://8.8.8.8:853#dns.google` | DoT |
//! | `https://dns.google/dns-query` | DoH |
//! | `h3://dns.google/dns-query` | DoH3 |
//! | `quic://dns.adguard.com` | DoQ |
//!
//! RecurseX accepts almost the same grammar, with two differences that this
//! module exists to bridge:
//!
//! 1. **The address must be an IP literal.** `https://dns.google/dns-query`
//!    cannot be handed over as written, because RecurseX refuses to depend on
//!    whatever `/etc/resolv.conf` happens to say — and it is right to, since it
//!    is the thing that is supposed to work when that file does not. Corduit
//!    resolves the hostname first (see [`crate::dns::engine_resolver`]) and
//!    renders `https://8.8.8.8:443/dns-query#dns.google`.
//! 2. **The encrypted transports need a name.** Verifying a certificate
//!    against an address is not an identity check, so RecurseX demands an
//!    explicit `#name`. A profile that omits it gets the host back as the name
//!    — which is what the previous implementation sent as SNI, so nothing that
//!    used to work stops working, but the operator should write the name.
//!
//! Nothing here does I/O. Parsing and rendering are pure, so the whole grammar
//! is testable without a socket.

use std::fmt;
use std::net::IpAddr;

use recurse_x::Error;

/// The transport an upstream string names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpstreamProtocol {
    /// Plain DNS over UDP.
    Udp,
    /// Plain DNS over TCP (length-prefixed).
    Tcp,
    /// DNS over TLS (RFC 7858).
    Tls,
    /// DNS over HTTPS (RFC 8484), over HTTP/1.1 or HTTP/2.
    Https,
    /// DNS over HTTPS over HTTP/3.
    Http3,
    /// DNS over QUIC (RFC 9250).
    Quic,
}

impl UpstreamProtocol {
    /// The scheme as it is written in a profile.
    pub fn scheme(self) -> &'static str {
        match self {
            UpstreamProtocol::Udp => "udp",
            UpstreamProtocol::Tcp => "tcp",
            UpstreamProtocol::Tls => "tls",
            UpstreamProtocol::Https => "https",
            UpstreamProtocol::Http3 => "h3",
            UpstreamProtocol::Quic => "quic",
        }
    }

    /// The port used when the string names none.
    pub fn default_port(self) -> u16 {
        match self {
            UpstreamProtocol::Udp | UpstreamProtocol::Tcp => 53,
            UpstreamProtocol::Tls | UpstreamProtocol::Quic => 853,
            UpstreamProtocol::Https | UpstreamProtocol::Http3 => 443,
        }
    }

    /// Whether the transport is encrypted, and therefore needs an identity to
    /// verify the peer against.
    pub fn is_encrypted(self) -> bool {
        !matches!(self, UpstreamProtocol::Udp | UpstreamProtocol::Tcp)
    }

    /// Whether the scheme carries a URI path.
    pub fn takes_path(self) -> bool {
        matches!(self, UpstreamProtocol::Https | UpstreamProtocol::Http3)
    }

    fn from_scheme(scheme: &str) -> Option<Self> {
        Some(match scheme {
            "udp" => UpstreamProtocol::Udp,
            "tcp" => UpstreamProtocol::Tcp,
            "tls" => UpstreamProtocol::Tls,
            "https" => UpstreamProtocol::Https,
            "h3" => UpstreamProtocol::Http3,
            "quic" => UpstreamProtocol::Quic,
            _ => return None,
        })
    }
}

impl fmt::Display for UpstreamProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.scheme())
    }
}

/// One upstream server, split into the pieces this crate reasons about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    protocol: UpstreamProtocol,
    host: String,
    port: u16,
    path: Option<String>,
    tls_name: Option<String>,
}

impl Upstream {
    /// Parse one upstream string.
    ///
    /// The address is *not* required to be an IP literal here — resolving that
    /// is the caller's job, because only the caller knows where to get an
    /// address from. Use [`Upstream::needs_bootstrap`] to find out.
    pub fn parse(s: &str) -> recurse_x::Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Err(Error::config("empty upstream string"));
        }

        let (rest, tls_name) = match s.split_once('#') {
            Some((rest, name)) => {
                let name = name.trim();
                if name.is_empty() {
                    return Err(Error::config(format!(
                        "upstream {s:?}: the '#' fragment is empty; remove the '#' or name \
                         the TLS identity"
                    )));
                }
                (rest.trim(), Some(name.to_string()))
            }
            None => (s, None),
        };

        let (scheme, rest) = match rest.split_once("://") {
            Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
            None => ("udp".to_string(), rest),
        };
        let protocol = UpstreamProtocol::from_scheme(&scheme).ok_or_else(|| {
            Error::config(format!(
                "upstream {s:?}: unknown scheme {scheme:?} (expected udp, tcp, tls, https, \
                 h3 or quic)"
            ))
        })?;

        let (authority, path) = match rest.split_once('/') {
            Some((authority, path)) => {
                if !protocol.takes_path() {
                    return Err(Error::config(format!(
                        "upstream {s:?}: {scheme}:// takes no path"
                    )));
                }
                (authority, Some(format!("/{path}")))
            }
            None => (rest, None),
        };

        let (host, port) = split_authority(authority).ok_or_else(|| {
            Error::config(format!("upstream {s:?}: {authority:?} is not an address"))
        })?;
        if !is_plausible_host(&host) {
            return Err(Error::config(format!(
                "upstream {s:?}: {host:?} is neither an IP literal nor a hostname"
            )));
        }
        let port = port.unwrap_or_else(|| protocol.default_port());
        if port == 0 {
            return Err(Error::config(format!(
                "upstream {s:?}: port 0 is not a port"
            )));
        }
        if !protocol.is_encrypted() && tls_name.is_some() {
            return Err(Error::config(format!(
                "upstream {s:?}: a plain {scheme}:// upstream carries no TLS identity"
            )));
        }

        Ok(Self {
            protocol,
            host,
            port,
            path,
            tls_name,
        })
    }

    /// The transport.
    pub fn protocol(&self) -> UpstreamProtocol {
        self.protocol
    }

    /// The configured host: an IP literal or a name.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The configured port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The URI path, for the schemes that carry one.
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// The identity a certificate is verified against — `Some` exactly when the
    /// transport is encrypted.
    ///
    /// Falls back to the configured host when the profile wrote no `#name`.
    /// That is the previous behaviour (the host *was* the SNI), so a profile
    /// that predates this field keeps working; it is not an endorsement of
    /// verifying a certificate against an address.
    pub fn tls_name(&self) -> Option<&str> {
        if self.protocol.is_encrypted() {
            Some(self.tls_name.as_deref().unwrap_or(&self.host))
        } else {
            None
        }
    }

    /// Whether the host is already an address, so no lookup stands between this
    /// resolver and its first query.
    pub fn is_literal(&self) -> bool {
        self.host.parse::<IpAddr>().is_ok()
    }

    /// Whether reaching this server requires resolving its own name first.
    ///
    /// A `true` here is not a problem to report, it is a dependency to break:
    /// `default-nameserver` exists to break it, and the system resolver is the
    /// documented last resort when the profile names none.
    pub fn needs_bootstrap(&self) -> bool {
        !self.is_literal()
    }

    /// Render the string RecurseX's config parser accepts, with the host
    /// replaced by `address`.
    ///
    /// `address` must be supplied exactly when [`Upstream::needs_bootstrap`]
    /// is `true`; it is ignored otherwise, so a literal host can be rendered
    /// without a lookup having happened.
    pub fn render(&self, address: Option<IpAddr>) -> String {
        match address {
            Some(ip) => self.render_host(&bracket(ip)),
            None => self.render_host(&bracket_or_host(&self.host)),
        }
    }

    fn render_host(&self, host: &str) -> String {
        let mut out = String::with_capacity(64);
        out.push_str(self.protocol.scheme());
        out.push_str("://");
        out.push_str(host);
        out.push(':');
        out.push_str(&self.port.to_string());
        if let Some(path) = &self.path {
            out.push_str(path);
        }
        if let Some(name) = self.tls_name() {
            out.push('#');
            out.push_str(name);
        }
        out
    }
}

/// An IPv6 literal must be bracketed, or its last colon reads as a port
/// separator — so an unbracketed one is not a cosmetic problem but a different
/// server: `2001:db8::1` with the default port renders as
/// `2001:db8::1:853`, and every parser in this stack would read port `853`
/// from it, which happens to be right for `tls://` and wrong for everything
/// else.
fn bracket(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    }
}

/// [`bracket`] for a host that is still a string, leaving names untouched.
fn bracket_or_host(host: &str) -> String {
    match host.parse::<IpAddr>() {
        Ok(ip) => bracket(ip),
        Err(_) => host.to_string(),
    }
}

impl fmt::Display for Upstream {
    /// The upstream in the spelling RecurseX accepts.
    ///
    /// Safe to put in a log line even when the host is a name that has not been
    /// resolved yet, which is the case this is mostly used in.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render_host(&bracket_or_host(&self.host)))
    }
}

/// Whether `host` could name a server at all.
///
/// An address is an IP literal or a hostname; anything else — a space, a
/// control character, a stray `%` — is a typo, and reporting it as "a hostname
/// that could not be resolved" would send the operator to the wrong layer.
/// The accepted set is deliberately narrow: the characters a hostname may
/// carry in practice.
fn is_plausible_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

/// Split `host[:port]` or `host@port`, tolerating a bracketed IPv6 literal.
///
/// Returns `None` only when there is no host at all — an unparseable host is
/// returned as written, because deciding whether it is a name or a typo is the
/// caller's job.
fn split_authority(authority: &str) -> Option<(String, Option<u16>)> {
    let authority = authority.trim();
    if authority.is_empty() {
        return None;
    }

    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = match tail {
            "" => None,
            tail => Some(
                tail.strip_prefix(':')
                    .or_else(|| tail.strip_prefix('@'))?
                    .parse()
                    .ok()?,
            ),
        };
        return Some((host.to_string(), port));
    }

    // Unbound's spelling (`1.1.1.1@853`). `@` cannot appear inside an address,
    // so unlike a bare colon it is unambiguous.
    if let Some((host, port)) = authority.rsplit_once('@') {
        return Some((host.to_string(), Some(port.parse().ok()?)));
    }

    // A bare IPv6 literal has more than one colon; none of them is a port.
    if authority.matches(':').count() > 1 {
        return Some((authority.to_string(), None));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => match port.parse::<u16>() {
            Ok(port) => Some((host.to_string(), Some(port))),
            Err(_) => Some((authority.to_string(), None)),
        },
        None => Some((authority.to_string(), None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(s: &str) -> Upstream {
        Upstream::parse(s).unwrap_or_else(|e| panic!("{s:?} should parse: {e}"))
    }

    fn render_of(s: &str, address: Option<&str>) -> String {
        parsed(s).render(address.map(|a| a.parse().expect("address literal")))
    }

    #[test]
    fn a_bare_address_is_plain_udp() {
        let u = parsed("8.8.8.8");
        assert_eq!(u.protocol(), UpstreamProtocol::Udp);
        assert_eq!(u.host(), "8.8.8.8");
        assert_eq!(u.port(), 53);
        assert!(u.is_literal());
        assert!(!u.needs_bootstrap());
        assert_eq!(u.render(None), "udp://8.8.8.8:53");
    }

    #[test]
    fn ports_are_accepted_after_a_colon_or_an_at() {
        assert_eq!(parsed("8.8.8.8:5353").port(), 5353);
        assert_eq!(parsed("8.8.8.8@5353").port(), 5353);
        assert_eq!(parsed("udp://8.8.8.8:5353").port(), 5353);
        assert_eq!(parsed("tcp://8.8.8.8").port(), 53);
        assert_eq!(parsed("tls://8.8.8.8").port(), 853);
        assert_eq!(parsed("quic://8.8.8.8").port(), 853);
        assert_eq!(parsed("https://8.8.8.8/dns-query").port(), 443);
        assert_eq!(parsed("h3://8.8.8.8/dns-query").port(), 443);
    }

    /// The previous parser split on the last colon and could not read an IPv6
    /// literal at all; `::1` became host `::` port `1`.
    #[test]
    fn ipv6_literals_are_read_and_rendered_in_brackets() {
        let u = parsed("tls://[2001:db8::1]:853#dns.example");
        assert_eq!(u.host(), "2001:db8::1");
        assert_eq!(u.port(), 853);
        assert_eq!(u.tls_name(), Some("dns.example"));
        assert_eq!(u.render(None), "tls://[2001:db8::1]:853#dns.example");

        let bare = parsed("2606:4700:4700::1111");
        assert_eq!(bare.host(), "2606:4700:4700::1111");
        assert_eq!(bare.port(), 53);
        assert_eq!(bare.render(None), "udp://[2606:4700:4700::1111]:53");
        assert_eq!(bare.to_string(), "udp://[2606:4700:4700::1111]:53");

        let unbracketed = Upstream::parse("udp://2606:4700:4700::1111:53").expect("parses");
        assert_eq!(unbracketed.host(), "2606:4700:4700::1111:53");
        assert_eq!(unbracketed.port(), 53);
    }

    #[test]
    fn a_hostname_upstream_needs_a_bootstrap_and_renders_with_one() {
        let u = parsed("https://dns.google/dns-query");
        assert_eq!(u.protocol(), UpstreamProtocol::Https);
        assert_eq!(u.host(), "dns.google");
        assert_eq!(u.path(), Some("/dns-query"));
        assert!(u.needs_bootstrap());
        assert_eq!(u.tls_name(), Some("dns.google"));
        assert_eq!(
            u.render(Some("8.8.8.8".parse().unwrap())),
            "https://8.8.8.8:443/dns-query#dns.google"
        );
    }

    /// The rendered form must be exactly what RecurseX's own parser accepts —
    /// that round trip is the whole contract of this module.
    #[test]
    fn every_rendering_round_trips_through_recursex() {
        let cases: &[(&str, Option<&str>)] = &[
            ("8.8.8.8", None),
            ("1.1.1.1:5353", None),
            ("udp://1.1.1.1@5353", None),
            ("tcp://1.1.1.1:53", None),
            ("tls://dns.google", Some("8.8.8.8")),
            ("tls://1.1.1.1#one.one.one.one", None),
            ("https://dns.google/dns-query", Some("8.8.8.8")),
            ("https://1.1.1.1/dns-query#one.one.one.one", None),
            ("https://dns.google", Some("8.8.8.8")),
            ("h3://dns.google/dns-query", Some("8.8.8.8")),
            ("quic://dns.adguard.com", Some("94.140.14.14")),
            ("tls://[2001:db8::1]:853#dns.example", None),
            ("https://[2001:db8::1]/dns-query#dns.example", None),
        ];

        for (input, address) in cases {
            let upstream = parsed(input);
            let rendered = render_of(input, *address);
            assert_eq!(
                upstream.render(address.map(|a| a.parse().unwrap())),
                rendered
            );
            recurse_x::config::parse_upstream(&rendered).unwrap_or_else(|e| {
                panic!("{input:?} rendered as {rendered:?}, which RecurseX rejects: {e}")
            });
        }
    }

    #[test]
    fn a_path_on_a_scheme_that_has_none_is_rejected() {
        for input in [
            "udp://8.8.8.8/dns-query",
            "tcp://8.8.8.8/x",
            "tls://8.8.8.8/dns-query",
        ] {
            assert!(
                Upstream::parse(input).is_err(),
                "{input} should be rejected"
            );
        }
    }

    #[test]
    fn a_tls_identity_on_a_plain_transport_is_rejected() {
        assert!(Upstream::parse("udp://8.8.8.8#dns.google").is_err());
        assert!(Upstream::parse("tcp://8.8.8.8#dns.google").is_err());
    }

    #[test]
    fn malformed_strings_are_rejected_with_a_reason() {
        assert!(Upstream::parse("").is_err());
        assert!(Upstream::parse("   ").is_err());
        assert!(Upstream::parse("https://8.8.8.8#").is_err());
        assert!(Upstream::parse("ftp://8.8.8.8").is_err());
        assert!(Upstream::parse("https://").is_err());
        assert!(Upstream::parse("udp://8.8.8.8:0").is_err());
        // A space can appear in neither an address nor a hostname; reporting it
        // as an unresolvable hostname would send the operator to the wrong
        // layer.
        assert!(Upstream::parse("not a dns server").is_err());
        assert!(Upstream::parse("dns.google/").is_err());
    }

    /// A profile that omits `#name` still gets a usable string: the host
    /// becomes the identity, which is what the previous implementation sent.
    #[test]
    fn a_missing_tls_name_falls_back_to_the_host() {
        assert_eq!(parsed("tls://1.1.1.1").tls_name(), Some("1.1.1.1"));
        assert_eq!(
            parsed("quic://dns.adguard.com").tls_name(),
            Some("dns.adguard.com")
        );
        // ...and a plain transport has no identity at all.
        assert_eq!(parsed("1.1.1.1").tls_name(), None);
        assert_eq!(parsed("tcp://1.1.1.1").tls_name(), None);
    }

    #[test]
    fn the_scheme_is_case_insensitive() {
        assert_eq!(parsed("TLS://dns.google").protocol(), UpstreamProtocol::Tls);
        assert_eq!(
            parsed("HTTPS://dns.google/dns-query").protocol(),
            UpstreamProtocol::Https
        );
    }

    #[test]
    fn display_is_the_config_as_written() {
        assert_eq!(
            parsed("tls://1.1.1.1#one.one.one.one").to_string(),
            "tls://1.1.1.1:853#one.one.one.one"
        );
        // A hostname cannot be rendered for RecurseX yet, so `Display` shows it
        // as configured rather than inventing an address for it.
        assert_eq!(
            parsed("https://dns.google/dns-query").to_string(),
            "https://dns.google:443/dns-query#dns.google"
        );
    }
}
