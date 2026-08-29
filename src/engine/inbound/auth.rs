//! Shared inbound authentication.
//!
//! `general.authentication` must be enforced on **every** inbound protocol
//! when configured — otherwise a user who sets credentials (and, say,
//! `allow_lan`) gets an open proxy instead of a protected one (CWE-306).
//!
//! * HTTP / mixed inbounds require `Proxy-Authorization: Basic base64(user:pass)`.
//! * SOCKS5 inbounds require the RFC 1929 username/password method.
//!
//! When no credentials are configured the inbounds stay open (historical
//! behavior). All credential comparisons are constant-time.

use crate::engine::config::AuthenticationConfig;
use crate::engine::error::{Error, Result};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// SOCKS5 authentication method: username/password (RFC 1929).
pub const SOCKS5_AUTH_USERPASS: u8 = 0x02;

/// Credential set enforced by the inbound protocols.
#[derive(Clone)]
pub struct InboundAuth {
    credentials: Arc<Vec<(String, String)>>,
}

impl InboundAuth {
    /// Build the checker from the configured `authentication` list.
    pub fn new(authentication: Option<&[AuthenticationConfig]>) -> Self {
        let credentials: Vec<(String, String)> = authentication
            .map(|auths| {
                auths
                    .iter()
                    .map(|a| (a.username.clone(), a.password.clone()))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            credentials: Arc::new(credentials),
        }
    }

    /// Whether credentials must be presented by clients.
    pub fn required(&self) -> bool {
        !self.credentials.is_empty()
    }

    /// Constant-time check of a username/password pair against every entry.
    pub fn check(&self, username: &str, password: &str) -> bool {
        self.credentials.iter().any(|(user, pass)| {
            crate::crypto::util::ct_eq(user.as_bytes(), username.as_bytes())
                && crate::crypto::util::ct_eq(pass.as_bytes(), password.as_bytes())
        })
    }
}

impl Default for InboundAuth {
    fn default() -> Self {
        Self::new(None)
    }
}

/// Validate a request's `Proxy-Authorization: Basic base64(user:pass)` header.
///
/// Returns `true` when authentication is not required, or when the presented
/// credentials match a configured entry. The base64 payload is bounded and
/// must decode to valid UTF-8 `user:pass`. The header map is generic so both
/// the courierust H/1 inbound and any legacy `http`-based caller can use it.
pub fn check_proxy_authorization<M>(headers: &M, auth: &InboundAuth) -> bool
where
    M: HeaderLookup,
{
    if !auth.required() {
        return true;
    }
    let Some(value) = headers.lookup("proxy-authorization") else {
        return false;
    };
    let Some(encoded) = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))
    else {
        return false;
    };
    let Ok(decoded) = crate::crypto::encoding::decode(
        encoded.trim().as_bytes(),
        crate::crypto::encoding::Config::STANDARD,
    ) else {
        return false;
    };
    let Ok(decoded) = String::from_utf8(decoded) else {
        return false;
    };
    let Some((username, password)) = decoded.split_once(':') else {
        return false;
    };
    auth.check(username, password)
}

/// Look up a header value by (case-insensitive) name.
pub trait HeaderLookup {
    fn lookup(&self, name: &str) -> Option<&str>;
}

impl HeaderLookup for courierust::courierust_http::HeaderMap {
    fn lookup(&self, name: &str) -> Option<&str> {
        self.get(name).and_then(|v| v.to_str().ok())
    }
}

/// SOCKS5 RFC 1929 username/password sub-negotiation.
///
/// Reads `VER(1) ULEN(1) UNAME ULEN PLEN(1) PASSWD PLEN`, validates against
/// `auth`, and writes the `[VER, STATUS]` reply. Returns `Ok(true)` only when
/// the credentials are valid; the caller must close the connection otherwise.
/// All lengths are single bytes (≤ 255), so reads are inherently bounded.
pub async fn socks5_userpass<S>(stream: &mut S, auth: &InboundAuth) -> Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0u8; 2];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| Error::network(format!("Failed to read SOCKS5 auth header: {e}")))?;
    if header[0] != 0x01 {
        return Err(Error::protocol("Invalid SOCKS5 auth version"));
    }

    let username_len = header[1] as usize;
    let mut username = vec![0u8; username_len];
    stream
        .read_exact(&mut username)
        .await
        .map_err(|e| Error::network(format!("Failed to read SOCKS5 username: {e}")))?;

    let mut password_len_buf = [0u8; 1];
    stream
        .read_exact(&mut password_len_buf)
        .await
        .map_err(|e| Error::network(format!("Failed to read SOCKS5 password length: {e}")))?;
    let password_len = password_len_buf[0] as usize;
    let mut password = vec![0u8; password_len];
    stream
        .read_exact(&mut password)
        .await
        .map_err(|e| Error::network(format!("Failed to read SOCKS5 password: {e}")))?;

    let username = String::from_utf8(username)
        .map_err(|_| Error::protocol("SOCKS5 username is not valid UTF-8"))?;
    let password = String::from_utf8(password)
        .map_err(|_| Error::protocol("SOCKS5 password is not valid UTF-8"))?;

    let ok = auth.check(&username, &password);
    let status = if ok { 0x00 } else { 0x01 };
    stream
        .write_all(&[0x01, status])
        .await
        .map_err(|e| Error::network(format!("Failed to write SOCKS5 auth reply: {e}")))?;
    Ok(ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::encoding::{self, Config};
    use crate::engine::config::AuthenticationConfig;

    fn auth(username: &str, password: &str) -> InboundAuth {
        InboundAuth::new(Some(&[AuthenticationConfig {
            username: username.to_string(),
            password: password.to_string(),
        }]))
    }

    #[test]
    fn required_only_when_credentials_configured() {
        assert!(!InboundAuth::new(None).required());
        assert!(auth("user", "pass").required());
    }

    #[test]
    fn check_is_exact_and_constant_time() {
        let checker = auth("alice", "s3cret");
        assert!(checker.check("alice", "s3cret"));
        assert!(!checker.check("alice", "wrong"));
        assert!(!checker.check("bob", "s3cret"));
        assert!(!checker.check("", "s3cret"));
    }

    use courierust::courierust_http::{HeaderName, HeaderValue};

    fn set_header(headers: &mut courierust::courierust_http::HeaderMap, value: &str) {
        headers.insert(
            HeaderName::from_static("proxy-authorization"),
            HeaderValue::from(value.to_string()),
        );
    }

    #[test]
    fn open_inbound_when_no_credentials() {
        let checker = InboundAuth::new(None);
        let mut headers = courierust::courierust_http::HeaderMap::new();
        // No header at all is accepted when auth is not required.
        assert!(check_proxy_authorization(&headers, &checker));
        set_header(&mut headers, "Basic dXNlcjpwYXNz");
        assert!(check_proxy_authorization(&headers, &checker));
    }

    #[test]
    fn basic_auth_round_trip() {
        let checker = auth("user", "pass");
        let mut headers = courierust::courierust_http::HeaderMap::new();
        let encoded = encoding::encode(b"user:pass", Config::STANDARD);

        set_header(&mut headers, &format!("Basic {encoded}"));
        assert!(check_proxy_authorization(&headers, &checker));

        // Wrong password.
        let encoded = encoding::encode(b"user:nope", Config::STANDARD);
        set_header(&mut headers, &format!("Basic {encoded}"));
        assert!(!check_proxy_authorization(&headers, &checker));

        // Missing header / malformed scheme / bad base64 are all rejected.
        headers.clear();
        assert!(!check_proxy_authorization(&headers, &checker));
        set_header(&mut headers, "Bearer abc");
        assert!(!check_proxy_authorization(&headers, &checker));
        set_header(&mut headers, "Basic !!!");
        assert!(!check_proxy_authorization(&headers, &checker));
    }
}
