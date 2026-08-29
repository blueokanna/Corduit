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

use crate::engine::error::{Error, Result};
use courierust::courierust_http::{
    Body, HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode, Version,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Upper bound for a single forwarded response body (64 MiB). Prevents a
/// hostile origin from exhausting memory with an unbounded download.
const MAX_RESPONSE_BODY_BYTES: usize = 64 * 1024 * 1024;
/// Upper bound for a forwarded response header block.
const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
/// Per-read timeout applied while talking to the origin.
const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
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
pub(crate) async fn send_request<W>(
    write: &mut W,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    host: &str,
    port: u16,
    body: &[u8],
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let head = build_request_head(method, path, headers, host, port, body.len());
    write
        .write_all(&head)
        .await
        .map_err(|e| Error::network(format!("Failed to write request head: {e}")))?;
    if !body.is_empty() {
        write
            .write_all(body)
            .await
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
pub(crate) async fn read_http_response<R>(read: &mut R, is_head: bool) -> Result<Response<Body>>
where
    R: AsyncRead + Unpin,
{
    let mut pending: Vec<u8> = Vec::new();
    let mut eof = false;

    let deadline = tokio::time::Instant::now() + RESPONSE_DEADLINE;

    let (status, headers, chunked, content_length) =
        read_head(read, &mut pending, &mut eof, deadline).await?;

    let no_body = is_head
        || status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED;

    let body: Vec<u8> = if no_body {
        Vec::new()
    } else if chunked {
        read_chunked(read, &mut pending, &mut eof, deadline).await?
    } else if let Some(length) = content_length {
        read_exact(read, &mut pending, &mut eof, deadline, length).await?
    } else {
        // No framing: the origin is expected to close the connection.
        read_until_eof(read, &mut pending, &mut eof, deadline).await?
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
async fn read_head<R>(
    read: &mut R,
    pending: &mut Vec<u8>,
    eof: &mut bool,
    deadline: tokio::time::Instant,
) -> Result<(StatusCode, HeaderMap, bool, Option<u64>)>
where
    R: AsyncRead + Unpin,
{
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

        if tokio::time::Instant::now() > deadline {
            return Err(Error::network("Timed out waiting for response headers"));
        }
        let n = tokio::time::timeout(IO_TIMEOUT, read.read(&mut tmp))
            .await
            .map_err(|_| Error::network("Timed out reading response headers"))?
            .map_err(|e| Error::network(format!("Failed to read response: {e}")))?;
        if n == 0 {
            *eof = true;
            if buf.is_empty() {
                return Err(Error::network("No response received from server"));
            }
            return Err(Error::network(
                "Malformed response: missing header terminator",
            ));
        }
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
async fn read_chunked<R>(
    read: &mut R,
    pending: &mut Vec<u8>,
    eof: &mut bool,
    deadline: tokio::time::Instant,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
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
            if tokio::time::Instant::now() > deadline {
                return Err(Error::network("Timed out reading chunk size"));
            }
            // Read into a growing buffer.
            let mut tmp = [0u8; 2048];
            let n = tokio::time::timeout(IO_TIMEOUT, read.read(&mut tmp))
                .await
                .map_err(|_| Error::network("Timed out reading chunk size"))?
                .map_err(|e| Error::network(format!("Failed to read chunk size: {e}")))?;
            if n == 0 {
                *eof = true;
                return Err(Error::network("EOF in chunk size line"));
            }
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
                let n = tokio::time::timeout(IO_TIMEOUT, read.read(&mut tmp))
                    .await
                    .map_err(|_| Error::network("Timed out reading trailers"))?
                    .map_err(|e| Error::network(format!("Failed to read trailers: {e}")))?;
                if n == 0 {
                    *eof = true;
                    return Err(Error::network("EOF in trailers"));
                }
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
            let n = tokio::time::timeout(IO_TIMEOUT, read.read(&mut tmp))
                .await
                .map_err(|_| Error::network("Timed out reading chunk data"))?
                .map_err(|e| Error::network(format!("Failed to read chunk data: {e}")))?;
            if n == 0 {
                *eof = true;
                return Err(Error::network("EOF in chunk data"));
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        // Consume the trailing CRLF after the chunk data.
        let mut crlf = [0u8; 2];
        if buf.is_empty() {
            let n = tokio::time::timeout(IO_TIMEOUT, read.read(&mut crlf))
                .await
                .map_err(|_| Error::network("Timed out reading chunk CRLF"))?
                .map_err(|e| Error::network(format!("Failed to read chunk CRLF: {e}")))?;
            if n == 0 {
                *eof = true;
                return Err(Error::network("EOF in chunk CRLF"));
            }
        } else {
            buf.drain(..std::cmp::min(2, buf.len()));
        }
    }

    *pending = buf;
    Ok(out)
}

/// Read exactly `length` bytes (using any already-buffered bytes first).
async fn read_exact<R>(
    read: &mut R,
    pending: &mut Vec<u8>,
    eof: &mut bool,
    deadline: tokio::time::Instant,
    length: u64,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    if length > MAX_RESPONSE_BODY_BYTES as u64 {
        return Err(Error::network("Response body exceeds limit"));
    }
    let mut out: Vec<u8> = Vec::with_capacity(length as usize);
    let mut buf = std::mem::take(pending);

    while (out.len() as u64) < length {
        if tokio::time::Instant::now() > deadline {
            return Err(Error::network("Timed out reading response body"));
        }
        let need = (length as usize) - out.len();
        if !buf.is_empty() {
            let take = std::cmp::min(need, buf.len());
            out.extend_from_slice(&buf.drain(..take).collect::<Vec<_>>());
            continue;
        }
        let mut tmp = [0u8; 2048];
        let n = tokio::time::timeout(IO_TIMEOUT, read.read(&mut tmp))
            .await
            .map_err(|_| Error::network("Timed out reading response body"))?
            .map_err(|e| Error::network(format!("Failed to read response body: {e}")))?;
        if n == 0 {
            *eof = true;
            return Err(Error::network("Connection closed before body was complete"));
        }
        buf.extend_from_slice(&tmp[..n]);
    }

    *pending = buf;
    Ok(out)
}

/// Read until EOF (close-delimited body), bounded by the size limit.
async fn read_until_eof<R>(
    read: &mut R,
    pending: &mut Vec<u8>,
    eof: &mut bool,
    deadline: tokio::time::Instant,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut out: Vec<u8> = Vec::new();
    let mut buf = std::mem::take(pending);

    loop {
        if out.len() > MAX_RESPONSE_BODY_BYTES {
            return Err(Error::network("Response body exceeds limit"));
        }
        if tokio::time::Instant::now() > deadline {
            return Err(Error::network("Timed out reading response body"));
        }
        if !buf.is_empty() {
            let take = std::cmp::min(MAX_RESPONSE_BODY_BYTES - out.len(), buf.len());
            out.extend_from_slice(&buf.drain(..take).collect::<Vec<_>>());
            continue;
        }
        let mut tmp = [0u8; 2048];
        let n = tokio::time::timeout(IO_TIMEOUT, read.read(&mut tmp))
            .await
            .map_err(|_| Error::network("Timed out reading response body"))?
            .map_err(|e| Error::network(format!("Failed to read response body: {e}")))?;
        if n == 0 {
            *eof = true;
            break;
        }
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
