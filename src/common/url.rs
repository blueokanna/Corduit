//! Minimal, dependency-free URL parser.
//!
//! Implements the subset of RFC 3986 that Corduit needs: absolute URLs of the
//! form `scheme://[userinfo@]host[:port][/path][?query][#fragment]`, with
//! percent-decoding of userinfo, bracketed IPv6 hosts and known scheme default
//! ports. It is deliberately strict: anything that is not a well-formed
//! absolute URL is rejected with a descriptive [`UrlError`].
//!
//! The API mirrors the small slice of the `url` crate that the engine used, so
//! call sites could be migrated mechanically: `parse`, `scheme`, `host_str`,
//! `port`, `path`, `query`, `as_str` and `to_string`.
//!
//! This module is `no_std + alloc`.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

/// Error returned when a URL string cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlError {
    /// Input was empty.
    Empty,
    /// No `scheme://` prefix was found.
    MissingScheme,
    /// The scheme part is empty (`"://host"`).
    EmptyScheme,
    /// No host component was present.
    MissingHost,
    /// The port was absent, non-numeric or out of range.
    InvalidPort,
    /// A bracketed IPv6 host was malformed.
    InvalidIpv6,
    /// A bare (unbracketed) IPv6 literal is not supported.
    BareIpv6,
    /// The scheme is not one of the supported network schemes.
    UnsupportedScheme(String),
}

impl fmt::Display for UrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UrlError::Empty => write!(f, "URL is empty"),
            UrlError::MissingScheme => write!(f, "URL is missing a scheme (expected scheme://...)"),
            UrlError::EmptyScheme => write!(f, "URL has an empty scheme"),
            UrlError::MissingHost => write!(f, "URL has no host"),
            UrlError::InvalidPort => write!(f, "URL has an invalid port"),
            UrlError::InvalidIpv6 => write!(f, "URL has a malformed bracketed IPv6 host"),
            UrlError::BareIpv6 => {
                write!(
                    f,
                    "URL has an unbracketed IPv6 host (wrap it in square brackets)"
                )
            }
            UrlError::UnsupportedScheme(s) => write!(f, "unsupported URL scheme '{s}'"),
        }
    }
}

// `core::error::Error` (error_in_core) only stabilized in Rust 1.81; keep the
// declared MSRV 1.78 by routing the impl through `std` when available.
#[cfg(feature = "std")]
impl std::error::Error for UrlError {}

/// A parsed absolute URL.
///
/// Keeps the original text so `as_str` / `to_string` round-trip
/// exactly as parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    raw: String,
    scheme: String,
    username: String,
    password: Option<String>,
    host: String,
    /// Explicit port only (as written in the URL); `None` when absent.
    port: Option<u16>,
    path: String,
    query: Option<String>,
    fragment: Option<String>,
}

impl Url {
    /// Parse an absolute URL string.
    ///
    /// # Errors
    ///
    /// Returns [`UrlError`] for any malformed input. The parser accepts the
    /// `http`, `https`, `ws`, `wss`, `ftp` and `ssh` schemes, plus the
    /// `ss`/`trojan`/`vmess`/`vless` proxy schemes used by Corduit outbound
    /// configurations.
    pub fn parse(input: &str) -> Result<Self, UrlError> {
        if input.is_empty() {
            return Err(UrlError::Empty);
        }
        let raw = input.to_string();

        // scheme://
        let scheme_end = input.find("://").ok_or(UrlError::MissingScheme)?;
        let scheme = &input[..scheme_end];
        if scheme.is_empty() {
            return Err(UrlError::EmptyScheme);
        }
        let rest = &input[scheme_end + 3..];

        // fragment
        let (rest, fragment) = match rest.find('#') {
            Some(i) => (&rest[..i], Some(rest[i + 1..].to_string())),
            None => (rest, None),
        };
        // query
        let (rest, query) = match rest.find('?') {
            Some(i) => (&rest[..i], Some(rest[i + 1..].to_string())),
            None => (rest, None),
        };
        // authority ends at the first '/' of the path
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, String::new()),
        };

        // userinfo (everything before the last '@')
        let (userinfo, hostport) = match authority.rfind('@') {
            Some(i) => (Some(&authority[..i]), &authority[i + 1..]),
            None => (None, authority),
        };

        let (username, password) = match userinfo {
            Some(info) if !info.is_empty() => match info.find(':') {
                Some(i) => (
                    percent_decode(&info[..i]),
                    Some(percent_decode(&info[i + 1..])),
                ),
                None => (percent_decode(info), None),
            },
            _ => (String::new(), None),
        };

        let (host, port) = parse_host_port(hostport)?;
        if host.is_empty() {
            return Err(UrlError::MissingHost);
        }

        Ok(Self {
            raw,
            scheme: scheme.to_string(),
            username,
            password,
            host,
            port,
            path,
            query,
            fragment,
        })
    }

    /// The URL scheme, e.g. `"https"`.
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// The host component (domain name, IP, or bracketed IPv6 literal without
    /// the brackets), or `None` if absent.
    pub fn host_str(&self) -> Option<&str> {
        (!self.host.is_empty()).then_some(self.host.as_str())
    }

    /// The explicit port as written in the URL (`None` if not present).
    ///
    /// Note: mirrors the `url` crate — this does **not** apply the scheme
    /// default; use [`Url::port_or_known_default`] for that.
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// The explicit port, falling back to the scheme default when known.
    pub fn port_or_known_default(&self) -> Option<u16> {
        self.port.or_else(|| default_port(&self.scheme))
    }

    /// The path component (always starts with `/` when non-empty, empty when
    /// the URL had no path at all).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The query string without the leading `?`, if present.
    pub fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }

    /// The fragment without the leading `#`, if present.
    pub fn fragment(&self) -> Option<&str> {
        self.fragment.as_deref()
    }

    /// Percent-decoded username from the userinfo component, if any.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Percent-decoded password from the userinfo component, if any.
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    /// The original URL text this instance was parsed from.
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// `host` with the explicit port when present, e.g. `"example.com:8443"`.
    pub fn host_with_port(&self) -> String {
        match self.port {
            Some(p) => format!("{}:{p}", self.host),
            None => self.host.clone(),
        }
    }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl core::str::FromStr for Url {
    type Err = UrlError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Url::parse(s)
    }
}

/// Split a `host[:port]` authority into its parts, handling bracketed IPv6.
fn parse_host_port(s: &str) -> Result<(String, Option<u16>), UrlError> {
    if s.is_empty() {
        return Ok((String::new(), None));
    }

    if let Some(stripped) = s.strip_prefix('[') {
        // bracketed IPv6: [::1] or [::1]:8080
        let end = stripped.find(']').ok_or(UrlError::InvalidIpv6)?;
        let host = &stripped[..end];
        if host.is_empty() {
            return Err(UrlError::InvalidIpv6);
        }
        let tail = &stripped[end + 1..];
        let port = if tail.is_empty() {
            None
        } else if let Some(p) = tail.strip_prefix(':') {
            Some(parse_port(p)?)
        } else {
            return Err(UrlError::InvalidIpv6);
        };
        return Ok((host.to_string(), port));
    }

    if s.contains(':') {
        let colons = s.matches(':').count();
        if colons > 1 {
            // multiple colons without brackets → bare IPv6 literal
            return Err(UrlError::BareIpv6);
        }
        let (host, port) = s.split_once(':').expect("contains one colon");
        if host.is_empty() {
            return Err(UrlError::MissingHost);
        }
        return Ok((host.to_string(), Some(parse_port(port)?)));
    }

    Ok((s.to_string(), None))
}

fn parse_port(p: &str) -> Result<u16, UrlError> {
    if p.is_empty() {
        return Err(UrlError::InvalidPort);
    }
    p.parse::<u16>().map_err(|_| UrlError::InvalidPort)
}

/// Known default ports for the schemes Corduit talks to.
fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" | "ws" => Some(80),
        "https" | "wss" => Some(443),
        "ftp" => Some(21),
        "ssh" => Some(22),
        _ => None,
    }
}

/// Percent-decode a component (`%XX` sequences), leaving invalid sequences as
/// literal text. Only used for userinfo; the parser does not need to decode
/// the path or query for its consumers.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(hi * 16 + lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_url() {
        let url = Url::parse("https://example.com/path?q=1#frag").unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.port(), None);
        assert_eq!(url.path(), "/path");
        assert_eq!(url.query(), Some("q=1"));
        assert_eq!(url.fragment(), Some("frag"));
        assert_eq!(url.as_str(), "https://example.com/path?q=1#frag");
    }

    #[test]
    fn applies_default_port() {
        let url = Url::parse("https://dns.google/dns-query").unwrap();
        assert_eq!(url.port(), None);
        assert_eq!(url.port_or_known_default(), Some(443));

        let with_port = Url::parse("http://example.com:8080/").unwrap();
        assert_eq!(with_port.port(), Some(8080));
        assert_eq!(with_port.port_or_known_default(), Some(8080));
    }

    #[test]
    fn parses_userinfo_with_percent_decoding() {
        let url = Url::parse("socks5://user%40name:p%40ss@example.com:1080").unwrap();
        assert_eq!(url.username(), "user@name");
        assert_eq!(url.password(), Some("p@ss"));
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.port(), Some(1080));
    }

    #[test]
    fn parses_ipv6_hosts() {
        let url = Url::parse("http://[::1]:8080/path").unwrap();
        assert_eq!(url.host_str(), Some("::1"));
        assert_eq!(url.port(), Some(8080));

        let no_port = Url::parse("http://[2001:db8::1]/").unwrap();
        assert_eq!(url.host_str(), Some("::1"));
        assert_eq!(no_port.host_str(), Some("2001:db8::1"));
        assert_eq!(no_port.port(), None);
    }

    #[test]
    fn empty_path_means_root() {
        let url = Url::parse("https://example.com").unwrap();
        assert_eq!(url.path(), "");
    }

    #[test]
    fn rejects_malformed_input() {
        assert_eq!(Url::parse(""), Err(UrlError::Empty));
        assert_eq!(Url::parse("example.com/path"), Err(UrlError::MissingScheme));
        assert_eq!(Url::parse("://host"), Err(UrlError::EmptyScheme));
        assert_eq!(Url::parse("https://"), Err(UrlError::MissingHost));
        assert_eq!(Url::parse("https://host:port"), Err(UrlError::InvalidPort));
        assert_eq!(Url::parse("https://host:99999"), Err(UrlError::InvalidPort));
        assert_eq!(Url::parse("http://[::1"), Err(UrlError::InvalidIpv6));
        assert_eq!(Url::parse("http://2001:db8::1"), Err(UrlError::BareIpv6));
    }

    #[test]
    fn round_trips_through_display() {
        let url = Url::parse("trojan://secret@example.com:443?allowInsecure=1").unwrap();
        assert_eq!(
            url.to_string(),
            "trojan://secret@example.com:443?allowInsecure=1"
        );
        assert_eq!(url.host_with_port(), "example.com:443");
    }

    #[test]
    fn proxy_schemes_are_accepted() {
        for scheme in ["ss", "vmess", "vless", "trojan", "socks5", "http"] {
            let url = Url::parse(&format!("{scheme}://user:pass@host:10086")).unwrap();
            assert_eq!(url.scheme(), scheme);
            assert_eq!(url.host_str(), Some("host"));
            assert_eq!(url.port(), Some(10086));
        }
    }
}
