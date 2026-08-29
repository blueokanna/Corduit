//! Correct HTTP/1.1 forwarding helpers shared by the HTTP and mixed inbounds.
//!
//! The courierust-based inbound hands us a fully *materialized* request: the
//! H/1 codec has already de-framed `Transfer-Encoding: chunked` and
//! `Content-Length` bodies into a bounded byte buffer. When we re-serialize
//! the request for the origin (through the outbound relay chain) we must
//! therefore **not** copy the client's original framing headers. Doing so
//! would make the origin re-interpret the decoded bytes as chunked data —
//! HTTP request smuggling (CWE-444) / protocol desync.
//!
//! What this module does:
//! - strips hop-by-hop headers (RFC 7230 §6.1) plus any header named by the
//!   client's `Connection` header,
//! - guarantees a `Host` header,
//! - re-frames a materialized body with an explicit `Content-Length`,
//! - parses the origin's raw response into a `courierust` `Response` (status
//!   line + headers + de-chunked, size-bounded body) so the inbound re-frames
//!   it correctly for the client instead of wrapping the raw upstream bytes
//!   as a nested HTTP response.
//!
//! The synchronous engine bounds every read through the stream read timeout;
//! `WouldBlock`/`TimedOut` mean "idle" and the loops below retry until the
//! overall deadline instead of treating a transient timeout as fatal.

use crate::engine::error::{Error, Result};
use courierust::courierust_http::{
    Body, HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode, Version,
};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

/// Upper bound for a single forwarded response body (64 MiB). Prevents a
/// hostile origin from exhausting memory with an unbounded download.
const MAX_RESPONSE_BODY_BYTES: usize = 64 * 1024 * 1024;
/// Upper bound for a forwarded response header block.
const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
/// Overall deadline for reading one response.
const RESPONSE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(120);

/// Standard hop-by-hop headers (RFC 7230 §6.1) that must never be forwarded.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-authorization",
];

/// Serialize and send one HTTP/1.1 request over a raw relay stream.
///
/// `body` is the fully materialized request body (may be empty). The caller
/// is responsible for `shutdown()`-ing the write half afterwards so the
/// outbound relay knows the request is complete.
pub(crate) fn send_request<W: Write>(
    write: &mut W,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    host: &str,
    port: u16,
    body: &[u8],
) -> Result<()> {
    let head = build_request_head(method, path, headers, host, port, body.len());
    write
        .write_all(&head)
        .map_err(|e| Error::network(format!("Failed to write request head: {e}")))?;
    if !body.is_empty() {
        write
            .write_all(body)
            .map_err(|e| Error::network(format!("Failed to write request body: {e}")))?;
    }
    Ok(())
}

/// Build the raw request head (request line + filtered headers + explicit
/// `Content-Length` when a body is present). No body bytes are included.
pub(crate) fn build_request_head(
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    host: &str,
    port: u16,
    body_len: usize,
) -> Vec<u8> {
    // Header names named by the client's `Connection` header are also
    // hop-by-hop and must be stripped.
    let mut connection_named: Vec<String> = Vec::new();
    if let Some(value) = headers.get("connection").and_then(|v| v.to_str().ok()) {
        for token in value.split(',') {
            let token = token.trim();
            if !token.is_empty() {
                connection_named.push(token.to_ascii_lowercase());
            }
        }
    }

    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(method.as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(path.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");

    let mut has_host = false;
    let mut has_content_length = false;
    for (name, value) in headers.iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lower.as_str()) || connection_named.contains(&lower) {
            continue;
        }
        if lower == "host" {
            has_host = true;
        }
        if lower == "content-length" {
            has_content_length = true;
        }
        // courierust's parser validated values (no CR/LF injection); drop
        // non-visible ASCII values defensively.
        if let Ok(value) = value.to_str() {
            out.extend_from_slice(name.as_str().as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
    }

    if !has_host {
        out.extend_from_slice(b"Host: ");
        out.extend_from_slice(host.as_bytes());
        out.extend_from_slice(format!(":{port}").as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    if body_len > 0 && !has_content_length {
        out.extend_from_slice(b"Content-Length: ");
        out.extend_from_slice(body_len.to_string().as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    out.extend_from_slice(b"\r\n");
    out
}

/// Read and parse the origin's raw HTTP/1.x response into a courierust
/// `Response`. The body is fully buffered (bounded by
/// [`MAX_RESPONSE_BODY_BYTES`]) and de-chunked when the origin used
/// `Transfer-Encoding: chunked`. `is_head` must be true for HEAD requests
/// (responses to HEAD carry no body).
pub(crate) fn read_http_response<R: Read>(read: &mut R, is_head: bool) -> Result<Response<Body>> {
    let mut pending: Vec<u8> = Vec::new();
    let mut eof = false;

    let deadline = Instant::now() + RESPONSE_DEADLINE;

    let (status, headers, chunked, content_length) =
        read_head(read, &mut pending, &mut eof, deadline)?;

    let no_body = is_head
        || status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED;

    let body: Vec<u8> = if no_body {
        Vec::new()
    } else if chunked {
        read_chunked(read, &mut pending, &mut eof, deadline)?
    } else if let Some(length) = content_length {
        read_exact(read, &mut pending, &mut eof, deadline, length)?
    } else {
        // No framing: the origin is expected to close the connection.
        read_until_eof(read, &mut pending, &mut eof, deadline)?
    };

    // Re-frame for the client: drop framing/hop-by-hop headers; the inbound
    // emits its own Content-Length based on the buffered body.
    let mut resp_headers = HeaderMap::new();
    for (name, value) in headers.iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lower.as_str()) || lower == "content-length" {
            continue;
        }
        resp_headers.append(name.clone(), value.clone());
    }

    Ok(Response {
        status,
        version: Version::HTTP_11,
        headers: resp_headers,
        body: Body::from(body),
        trailers: None,
    })
}

/// Read the response head (status line + headers) and return the parsed
/// status, header map, chunked flag and content-length.
fn read_head<R: Read>(
    read: &mut R,
    pending: &mut Vec<u8>,
    eof: &mut bool,
    deadline: Instant,
) -> Result<(StatusCode, HeaderMap, bool, Option<u64>)> {
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 2048];

    // Locate the end of the header block. The status line and headers are
    // scanned from `buf` (the accumulated head), which may contain a few
    // body bytes after the `\r\n\r\n` separator.
    let parsed = loop {
        if buf.len() > MAX_RESPONSE_HEADER_BYTES {
            return Err(Error::network(format!(
                "Response headers exceeded {} bytes",
                MAX_RESPONSE_HEADER_BYTES
            )));
        }
        if let Some(end) = find_subsequence(&buf, b"\r\n\r\n") {
            let head = &buf[..end];
            let rest = &buf[end + 4..];
            let parsed = parse_head(head)?;
            break (parsed.0, parsed.1, parsed.2, parsed.3, rest.to_vec());
        }

        if Instant::now() > deadline {
            return Err(Error::network("Timed out waiting for response headers"));
        }
        let n = match read.read(&mut tmp) {
            Ok(0) => {
                *eof = true;
                if buf.is_empty() {
                    return Err(Error::network("No response received from server"));
                }
                return Err(Error::network(
                    "Malformed response: missing header terminator",
                ));
            }
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(e) => return Err(Error::network(format!("Failed to read response: {e}"))),
        };
        buf.extend_from_slice(&tmp[..n]);
    };

    let (status, headers, chunked, content_length, body_pending) = parsed;
    // Preserve any bytes already read past the header block.
    pending.clear();
    pending.extend_from_slice(&body_pending);
    Ok((status, headers, chunked, content_length))
}

/// Parse a response head block (status line + header lines) into
/// `(status, headers, chunked, content_length)`.
fn parse_head(head: &[u8]) -> Result<(StatusCode, HeaderMap, bool, Option<u64>)> {
    let lines: Vec<&[u8]> = head.split(|b| *b == b'\n').collect();
    let status_line = lines
        .first()
        .ok_or_else(|| Error::network("Empty response head"))?;
    let status_line = status_line.strip_suffix(b"\r").unwrap_or(status_line);

    // HTTP/1.x <code> <reason>
    let status = parse_status(status_line)?;

    let mut headers = HeaderMap::new();
    let mut chunked = false;
    let mut content_length: Option<u64> = None;

    for line in lines.iter().skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        // Split on the first `:` (slice::split_once is unstable).
        let colon = line
            .iter()
            .position(|&b| b == b':')
            .ok_or_else(|| Error::network("Malformed response header line"))?;
        let (name, value) = (&line[..colon], &line[colon + 1..]);
        let name = std::str::from_utf8(name)
            .map_err(|_| Error::network("Malformed response header name"))?
            .trim();
        let value = std::str::from_utf8(value)
            .map_err(|_| Error::network("Malformed response header value"))?
            .trim();
        if name.is_empty() {
            return Err(Error::network("Malformed response header name"));
        }
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|e| Error::network(format!("Invalid response header name: {e}")))?;
        let header_value = HeaderValue::from_bytes(value.as_bytes())
            .map_err(|e| Error::network(format!("Invalid response header value: {e}")))?;

        match name.to_ascii_lowercase().as_str() {
            "transfer-encoding" => {
                // Multiple TE values are not expected from a well-behaved
                // origin; the only encoding we support is chunked.
                let has_chunked = value
                    .split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("chunked"));
                if has_chunked {
                    chunked = true;
                }
            }
            "content-length" => {
                let len = value
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| Error::network("Malformed Content-Length"))?;
                // Conflicting Content-Length values are a smuggling vector.
                if let Some(existing) = content_length {
                    if existing != len {
                        return Err(Error::network("Conflicting Content-Length values"));
                    }
                } else {
                    content_length = Some(len);
                }
            }
            _ => {}
        }
        headers.append(header_name, header_value);
    }

    if chunked && content_length.is_some() {
        return Err(Error::network(
            "Response has both Transfer-Encoding and Content-Length",
        ));
    }

    Ok((status, headers, chunked, content_length))
}

/// Parse an HTTP status line (`HTTP/1.x <code> <reason>`).
fn parse_status(line: &[u8]) -> Result<StatusCode> {
    let mut parts = line.splitn(3, |b| *b == b' ');
    let _version = parts
        .next()
        .ok_or_else(|| Error::network("Missing version"))?;
    let code = parts
        .next()
        .ok_or_else(|| Error::network("Missing status code"))?;
    let code = std::str::from_utf8(code)
        .map_err(|_| Error::network("Invalid status code"))?
        .parse::<u16>()
        .map_err(|_| Error::network("Invalid status code"))?;
    Ok(StatusCode::from_u16(code))
}

/// Read a chunked response body (RFC 7230 §4.1), returning decoded bytes.
fn read_chunked<R: Read>(
    read: &mut R,
    pending: &mut Vec<u8>,
    eof: &mut bool,
    deadline: Instant,
) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let mut buf = std::mem::take(pending);

    loop {
        // Read a chunk-size line.
        let size_line = loop {
            if let Some(pos) = find_subsequence(&buf, b"\r\n") {
                let line = buf.drain(..pos + 2).collect::<Vec<_>>();
                break line;
            }
            if buf.len() > 1024 {
                return Err(Error::network("Chunk size line too long"));
            }
            if Instant::now() > deadline {
                return Err(Error::network("Timed out reading chunk size"));
            }
            // Read into a growing buffer.
            let mut tmp = [0u8; 2048];
            let n = match read.read(&mut tmp) {
                Ok(0) => {
                    *eof = true;
                    return Err(Error::network("EOF in chunk size line"));
                }
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(e) => return Err(Error::network(format!("Failed to read chunk size: {e}"))),
            };
            buf.extend_from_slice(&tmp[..n]);
        };

        let size_str = std::str::from_utf8(
            size_line
                .strip_suffix(b"\r\n")
                .unwrap_or(&size_line)
                .split(|b| *b == b';')
                .next()
                .unwrap_or_default(),
        )
        .map_err(|_| Error::network("Invalid chunk size"))?;
        let size = usize::from_str_radix(size_str.trim(), 16)
            .map_err(|_| Error::network("Invalid chunk size"))?;

        if size == 0 {
            // Trailer section up to the final CRLF.
            loop {
                if buf.starts_with(b"\r\n") {
                    buf.drain(..2);
                    break;
                }
                if let Some(pos) = find_subsequence(&buf, b"\r\n") {
                    buf.drain(..pos + 2);
                    break;
                }
                let mut tmp = [0u8; 2048];
                let n = match read.read(&mut tmp) {
                    Ok(0) => {
                        *eof = true;
                        return Err(Error::network("EOF in trailers"));
                    }
                    Ok(n) => n,
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(e) => return Err(Error::network(format!("Failed to read trailers: {e}"))),
                };
                buf.extend_from_slice(&tmp[..n]);
            }
            break;
        }

        if out.len().saturating_add(size) > MAX_RESPONSE_BODY_BYTES {
            return Err(Error::network("Response body exceeds limit"));
        }

        // Read exactly `size` data bytes + CRLF.
        let target = out.len() + size;
        while out.len() < target {
            let need = target - out.len();
            if !buf.is_empty() {
                let take = std::cmp::min(need, buf.len());
                out.extend_from_slice(&buf.drain(..take).collect::<Vec<_>>());
                continue;
            }
            let mut tmp = [0u8; 2048];
            let n = match read.read(&mut tmp) {
                Ok(0) => {
                    *eof = true;
                    return Err(Error::network("EOF in chunk data"));
                }
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(e) => return Err(Error::network(format!("Failed to read chunk data: {e}"))),
            };
            buf.extend_from_slice(&tmp[..n]);
        }
        // Consume the trailing CRLF after the chunk data.
        if buf.is_empty() {
            let mut crlf = [0u8; 2];
            let n = match read.read(&mut crlf) {
                Ok(0) => {
                    *eof = true;
                    return Err(Error::network("EOF in chunk CRLF"));
                }
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(e) => return Err(Error::network(format!("Failed to read chunk CRLF: {e}"))),
            };
            let _ = n;
        } else {
            buf.drain(..std::cmp::min(2, buf.len()));
        }
    }

    *pending = buf;
    Ok(out)
}

/// Read exactly `length` bytes (using any already-buffered bytes first).
fn read_exact<R: Read>(
    read: &mut R,
    pending: &mut Vec<u8>,
    eof: &mut bool,
    deadline: Instant,
    length: u64,
) -> Result<Vec<u8>> {
    if length > MAX_RESPONSE_BODY_BYTES as u64 {
        return Err(Error::network("Response body exceeds limit"));
    }
    let mut out: Vec<u8> = Vec::with_capacity(length as usize);
    let mut buf = std::mem::take(pending);

    while (out.len() as u64) < length {
        if Instant::now() > deadline {
            return Err(Error::network("Timed out reading response body"));
        }
        let need = (length as usize) - out.len();
        if !buf.is_empty() {
            let take = std::cmp::min(need, buf.len());
            out.extend_from_slice(&buf.drain(..take).collect::<Vec<_>>());
            continue;
        }
        let mut tmp = [0u8; 2048];
        let n = match read.read(&mut tmp) {
            Ok(0) => {
                *eof = true;
                return Err(Error::network("Connection closed before body was complete"));
            }
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(e) => return Err(Error::network(format!("Failed to read response body: {e}"))),
        };
        buf.extend_from_slice(&tmp[..n]);
    }

    *pending = buf;
    Ok(out)
}

/// Read until EOF (close-delimited body), bounded by the size limit.
fn read_until_eof<R: Read>(
    read: &mut R,
    pending: &mut Vec<u8>,
    eof: &mut bool,
    deadline: Instant,
) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let mut buf = std::mem::take(pending);

    loop {
        if out.len() > MAX_RESPONSE_BODY_BYTES {
            return Err(Error::network("Response body exceeds limit"));
        }
        if Instant::now() > deadline {
            return Err(Error::network("Timed out reading response body"));
        }
        if !buf.is_empty() {
            let take = std::cmp::min(MAX_RESPONSE_BODY_BYTES - out.len(), buf.len());
            out.extend_from_slice(&buf.drain(..take).collect::<Vec<_>>());
            continue;
        }
        let mut tmp = [0u8; 2048];
        let n = match read.read(&mut tmp) {
            Ok(0) => {
                *eof = true;
                break;
            }
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(e) => return Err(Error::network(format!("Failed to read response body: {e}"))),
        };
        buf.extend_from_slice(&tmp[..n]);
    }

    *pending = buf;
    Ok(out)
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

// ---------------------------------------------------------------------------
// Synchronous in-memory duplex
// ---------------------------------------------------------------------------

/// Idle wait bound for [`MemDuplex`] reads/writes. Mirrors a socket read
/// timeout: a read that finds no data waits at most this long before
/// reporting `WouldBlock`, releasing the caller's stream lock so the relay
/// loop can proceed with the opposite direction.
const DUPLEX_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(50);
/// Bound for a blocking write when the peer never drains (socket write
/// timeout semantics).
const DUPLEX_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Shared pipe state between the two ends of a [`MemDuplex`].
#[derive(Default)]
struct DuplexState {
    /// Bytes written by end A, read by end B.
    a_to_b: VecDeque<u8>,
    /// Bytes written by end B, read by end A.
    b_to_a: VecDeque<u8>,
    /// A called `shutdown(Write)` — B observes EOF after draining.
    a_write_closed: bool,
    /// B called `shutdown(Write)` — A observes EOF after draining.
    b_write_closed: bool,
    /// A called `shutdown(Both)`.
    a_both: bool,
    /// B called `shutdown(Both)`.
    b_both: bool,
}

struct DuplexInner {
    state: Mutex<DuplexState>,
    cond: Condvar,
    capacity: usize,
}

/// One end of a synchronous bounded in-memory duplex pipe.
///
/// This is the synchronous replacement for `tokio::io::duplex` used by the
/// HTTP proxy path: the server end is handed to the outbound relay (which
/// runs on its own threads and locks it per operation), the client end is
/// used by the calling thread to send the request and read the response.
/// Reads and writes block on a condition variable with socket-style
/// timeouts so neither direction can starve the other's stream lock.
pub(crate) struct MemDuplex {
    inner: Arc<DuplexInner>,
    is_a: bool,
}

/// Create a new in-memory duplex pair with `capacity` bytes of buffering per
/// direction.
pub(crate) fn mem_duplex(capacity: usize) -> (MemDuplex, MemDuplex) {
    let inner = Arc::new(DuplexInner {
        state: Mutex::new(DuplexState::default()),
        cond: Condvar::new(),
        capacity: capacity.max(1),
    });
    (
        MemDuplex {
            inner: inner.clone(),
            is_a: true,
        },
        MemDuplex { inner, is_a: false },
    )
}

impl MemDuplex {
    fn my_read_buf<'a>(&self, state: &'a mut DuplexState) -> &'a mut VecDeque<u8> {
        if self.is_a {
            &mut state.b_to_a
        } else {
            &mut state.a_to_b
        }
    }

    fn my_write_buf<'a>(&self, state: &'a mut DuplexState) -> &'a mut VecDeque<u8> {
        if self.is_a {
            &mut state.a_to_b
        } else {
            &mut state.b_to_a
        }
    }

    fn peer_write_closed(&self, state: &DuplexState) -> bool {
        if self.is_a {
            state.b_write_closed
        } else {
            state.a_write_closed
        }
    }

    fn my_write_closed(&self, state: &DuplexState) -> bool {
        if self.is_a {
            state.a_write_closed
        } else {
            state.b_write_closed
        }
    }

    fn my_both(&self, state: &DuplexState) -> bool {
        if self.is_a {
            state.a_both
        } else {
            state.b_both
        }
    }

    fn peer_both(&self, state: &DuplexState) -> bool {
        if self.is_a {
            state.b_both
        } else {
            state.a_both
        }
    }
}

impl Read for MemDuplex {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let inner = &self.inner;
        let mut state = inner.state.lock().unwrap();
        {
            let mine = self.my_read_buf(&mut state);
            if !mine.is_empty() {
                let n = mine.len().min(buf.len());
                for (dst, src) in buf[..n].iter_mut().zip(mine.drain(..n)) {
                    *dst = src;
                }
                return Ok(n);
            }
        }
        if self.peer_write_closed(&state) {
            return Ok(0); // EOF
        }
        if self.my_both(&state) || self.peer_both(&state) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "duplex closed",
            ));
        }
        // Idle: wait one window for data (a writer notifies), then
        // report `WouldBlock` so the relay releases its stream lock.
        let (guard, _) = inner
            .cond
            .wait_timeout(state, DUPLEX_IDLE_TIMEOUT)
            .unwrap_or_else(|e| e.into_inner());
        state = guard;
        {
            let mine = self.my_read_buf(&mut state);
            if !mine.is_empty() {
                let n = mine.len().min(buf.len());
                for (dst, src) in buf[..n].iter_mut().zip(mine.drain(..n)) {
                    *dst = src;
                }
                return Ok(n);
            }
        }
        if self.peer_write_closed(&state) {
            return Ok(0);
        }
        if self.my_both(&state) || self.peer_both(&state) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "duplex closed",
            ));
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "duplex idle",
        ))
    }
}

impl Write for MemDuplex {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let inner = &self.inner;
        let mut state = inner.state.lock().unwrap();
        if self.my_write_closed(&state) || self.my_both(&state) || self.peer_both(&state) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "duplex write closed",
            ));
        }
        {
            let mine = self.my_write_buf(&mut state);
            let space = inner.capacity - mine.len();
            if space > 0 {
                let n = space.min(buf.len());
                mine.extend(buf[..n].iter().copied());
                let _ = mine;
                inner.cond.notify_all();
                return Ok(n);
            }
        }
        // Full: wait for the reader to drain, bounded by a write timeout.
        let (guard, _) = inner
            .cond
            .wait_timeout(state, DUPLEX_WRITE_TIMEOUT)
            .unwrap_or_else(|e| e.into_inner());
        state = guard;
        {
            let mine = self.my_write_buf(&mut state);
            let space = inner.capacity - mine.len();
            if space > 0 {
                let n = space.min(buf.len());
                mine.extend(buf[..n].iter().copied());
                let _ = mine;
                inner.cond.notify_all();
                return Ok(n);
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "duplex write timed out",
        ))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl crate::common::stream::SyncStream for MemDuplex {
    fn shutdown(&self, how: std::net::Shutdown) -> std::io::Result<()> {
        let mut state = self.inner.state.lock().unwrap();
        if self.is_a {
            match how {
                std::net::Shutdown::Write | std::net::Shutdown::Both => state.a_write_closed = true,
                std::net::Shutdown::Read => {}
            }
            if how == std::net::Shutdown::Both {
                state.a_both = true;
            }
        } else {
            match how {
                std::net::Shutdown::Write | std::net::Shutdown::Both => state.b_write_closed = true,
                std::net::Shutdown::Read => {}
            }
            if how == std::net::Shutdown::Both {
                state.b_both = true;
            }
        }
        self.inner.cond.notify_all();
        Ok(())
    }
}
