//! Correct HTTP/1.1 forwarding helpers shared by the HTTP and mixed inbounds.
//!
//! `hyper` hands us a fully *decoded* request: `Transfer-Encoding: chunked`
//! and `Content-Length` bodies have already been de-framed into a body stream.
//! When we re-serialize the request for the origin (through the outbound relay
//! chain) we must therefore **not** copy the client's original framing
//! headers. Doing so would make the origin re-interpret the decoded bytes as
//! chunked data — HTTP request smuggling (CWE-444) / protocol desync.
//!
//! What this module does:
//! - strips hop-by-hop headers (RFC 7230 §6.1) plus any header named by the
//!   client's `Connection` header,
//! - guarantees a `Host` header,
//! - re-encodes a request body as HTTP/1.1 chunked (the length is unknown up
//!   front because the body is streamed),
//! - parses the origin's raw response into a real `hyper::Response` (status
//!   line + headers + de-chunked, size-bounded body) so `hyper` re-frames it
//!   correctly for the client instead of wrapping the raw upstream bytes as a
//!   nested HTTP response.

use crate::engine::error::{Error, Result};
use bytes::Bytes;
use http::header::CONNECTION;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use std::io;
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
/// Per-frame timeout for streaming a request body from the client.
const REQUEST_BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

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
/// The caller is responsible for `shutdown()`-ing the write half afterwards so
/// the outbound relay knows the request is complete.
pub(crate) async fn send_request<W>(
    write: &mut W,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    host: &str,
    port: u16,
    body: Incoming,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    // Peek at the first body frame so we can decide whether the request
    // actually carries a body. Requests without a body (typical GET/HEAD) are
    // forwarded without chunked framing.
    let mut body = body;
    let first = tokio::time::timeout(REQUEST_BODY_TIMEOUT, body.frame())
        .await
        .map_err(|_| Error::network("Request body read timed out"))?
        .transpose()
        .map_err(|e| Error::network(format!("Failed to read request body: {e}")))?;
    let has_body = matches!(&first, Some(frame) if frame.data_ref().is_some());

    let head = build_request_head(method, path, headers, host, port, has_body);
    write
        .write_all(&head)
        .await
        .map_err(|e| Error::network(format!("Failed to write request head: {e}")))?;

    if has_body {
        // The first frame already contains data; write it as the first chunk.
        if let Some(frame) = first {
            if let Some(data) = frame.data_ref() {
                write_chunk(write, data).await?;
            }
        }
        loop {
            let frame = tokio::time::timeout(REQUEST_BODY_TIMEOUT, body.frame())
                .await
                .map_err(|_| Error::network("Request body read timed out"))?
                .transpose()
                .map_err(|e| Error::network(format!("Failed to read request body: {e}")))?;
            let Some(frame) = frame else { break };
            if let Some(data) = frame.data_ref() {
                write_chunk(write, data).await?;
            }
        }
        write
            .write_all(b"0\r\n\r\n")
            .await
            .map_err(|e| Error::network(format!("Failed to terminate request body: {e}")))?;
    }

    Ok(())
}

/// Build the raw request head (request line + filtered headers + optional
/// chunked framing marker). No body bytes are included.
pub(crate) fn build_request_head(
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    host: &str,
    port: u16,
    has_body: bool,
) -> Vec<u8> {
    // Header names named by the client's `Connection` header are also
    // hop-by-hop and must be stripped.
    let mut connection_named: Vec<String> = Vec::new();
    if let Some(value) = headers.get(CONNECTION).and_then(|v| v.to_str().ok()) {
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
    for (name, value) in headers {
        let lower = name.as_str().to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lower.as_str()) || connection_named.contains(&lower) {
            continue;
        }
        if lower == "host" {
            has_host = true;
        }
        // Values were validated by hyper's parser, so no CR/LF injection is
        // possible here; non-visible ASCII values are dropped.
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

    if has_body {
        out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    }

    out.extend_from_slice(b"\r\n");
    out
}

/// Write one HTTP/1.1 chunk.
async fn write_chunk<W>(write: &mut W, data: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if data.is_empty() {
        return Ok(());
    }
    write
        .write_all(format!("{:x}\r\n", data.len()).as_bytes())
        .await
        .map_err(|e| Error::network(format!("Failed to write chunk header: {e}")))?;
    write
        .write_all(data)
        .await
        .map_err(|e| Error::network(format!("Failed to write chunk data: {e}")))?;
    write
        .write_all(b"\r\n")
        .await
        .map_err(|e| Error::network(format!("Failed to write chunk trailer: {e}")))
}

/// Read and parse the origin's raw HTTP/1.x response into a `hyper::Response`.
///
/// The body is fully buffered (bounded by [`MAX_RESPONSE_BODY_BYTES`]) and
/// de-chunked when the origin used `Transfer-Encoding: chunked`. `is_head`
/// must be true for HEAD requests (responses to HEAD carry no body).
pub(crate) async fn read_http_response<R>(
    read: &mut R,
    is_head: bool,
) -> Result<Response<BoxBody<Bytes, io::Error>>>
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

    let body: Bytes = if no_body {
        Bytes::new()
    } else if chunked {
        let data = read_chunked(read, &mut pending, &mut eof, deadline).await?;
        Bytes::from(data)
    } else if let Some(length) = content_length {
        let data = read_exact(read, &mut pending, &mut eof, deadline, length).await?;
        Bytes::from(data)
    } else {
        // No framing: the origin is expected to close the connection.
        let data = read_until_eof(read, &mut pending, &mut eof, deadline).await?;
        Bytes::from(data)
    };

    // Re-frame for the client: drop framing/hop-by-hop headers and let hyper
    // emit its own Content-Length based on the buffered body.
    let mut builder = Response::builder().status(status);
    for (name, value) in headers.iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lower.as_str()) || lower == "content-length" {
            continue;
        }
        builder = builder.header(name, value);
    }

    builder
        .body(Full::new(body).map_err(|never| match never {}).boxed())
        .map_err(|e| Error::network(format!("Failed to build response: {e}")))
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
    let (status, header_map, chunked, content_length, body_pending) = loop {
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
            // Header block without terminator: treat as malformed.
            return Err(Error::network(
                "Malformed response: missing header terminator",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    // Keep any bytes already read past the header block for the body reader.
    pending.extend_from_slice(&body_pending);
    drop(buf);

    Ok((status, header_map, chunked, content_length))
}

/// Parse the status line + header lines (everything before `\r\n\r\n`).
fn parse_head(head: &[u8]) -> Result<(StatusCode, HeaderMap, bool, Option<u64>)> {
    let text = std::str::from_utf8(head)
        .map_err(|_| Error::network("Malformed response: headers are not ASCII"))?;

    let mut lines = text.split("\r\n");

    // Status line: "HTTP/1.1 200 OK"
    let status_line = lines
        .next()
        .ok_or_else(|| Error::network("Malformed response: missing status line"))?;
    let mut parts = status_line.split_whitespace();
    let _version = parts.next();
    let code_str = parts
        .next()
        .ok_or_else(|| Error::network("Malformed response: missing status code"))?;
    let code: u16 = code_str
        .parse()
        .map_err(|_| Error::network("Malformed response: invalid status code"))?;
    if !(100..=999).contains(&code) {
        return Err(Error::network(
            "Malformed response: status code out of range",
        ));
    }
    let status = StatusCode::from_u16(code)
        .map_err(|_| Error::network("Malformed response: unsupported status code"))?;

    let mut headers = HeaderMap::new();
    let mut chunked = false;
    let mut content_length: Option<u64> = None;

    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some(colon) = line.find(':') else {
            return Err(Error::network("Malformed response: header without colon"));
        };
        let name = HeaderName::from_bytes(line[..colon].trim().as_bytes())
            .map_err(|_| Error::network("Malformed response: invalid header name"))?;
        let value = HeaderValue::from_bytes(line[colon + 1..].trim_start().as_bytes())
            .map_err(|_| Error::network("Malformed response: invalid header value"))?;

        let lower = name.as_str().to_ascii_lowercase();
        if lower == "transfer-encoding" {
            chunked = value
                .to_str()
                .map(|v| v.to_ascii_lowercase().contains("chunked"))
                .unwrap_or(false);
        }
        if lower == "content-length" {
            content_length = value.to_str().ok().and_then(|v| v.trim().parse().ok());
        }

        headers.append(name, value);
    }

    Ok((status, headers, chunked, content_length))
}

/// Read exactly `length` body bytes (already-framed Content-Length response).
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
    if length as usize > MAX_RESPONSE_BODY_BYTES {
        return Err(Error::network(format!(
            "Response body exceeded {} bytes",
            MAX_RESPONSE_BODY_BYTES
        )));
    }

    let mut out = Vec::with_capacity(length as usize);
    while (out.len() as u64) < length {
        if tokio::time::Instant::now() > deadline {
            return Err(Error::network("Timed out reading response body"));
        }
        let want = (length as usize - out.len()).min(8192);
        let mut tmp = vec![0u8; want];
        let n = read_into(read, pending, eof, &mut tmp).await?;
        if n == 0 {
            return Err(Error::network(format!(
                "Response body truncated: expected {length} bytes, got {}",
                out.len()
            )));
        }
        out.extend_from_slice(&tmp[..n]);
    }
    Ok(out)
}

/// Read a de-chunked response body.
async fn read_chunked<R>(
    read: &mut R,
    pending: &mut Vec<u8>,
    eof: &mut bool,
    deadline: tokio::time::Instant,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut out = Vec::new();

    loop {
        if out.len() > MAX_RESPONSE_BODY_BYTES {
            return Err(Error::network(format!(
                "Response body exceeded {} bytes",
                MAX_RESPONSE_BODY_BYTES
            )));
        }
        // Read a chunk-size line (hex digits, terminated by CRLF).
        let size_line = read_line(read, pending, eof, deadline, 16).await?;
        if size_line.is_empty() {
            return Err(Error::network(
                "Malformed chunked response: empty size line",
            ));
        }
        let size_str = std::str::from_utf8(&size_line)
            .ok()
            .and_then(|line| line.split(';').next())
            .map(str::trim)
            .unwrap_or("");
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| Error::network("Malformed chunked response: bad chunk size"))?;

        if size == 0 {
            // Consume the trailer block (ends with CRLF CRLF or just CRLF).
            loop {
                if tokio::time::Instant::now() > deadline {
                    return Err(Error::network("Timed out reading response trailers"));
                }
                let line = read_line(read, pending, eof, deadline, 8192).await?;
                if line.is_empty() {
                    break;
                }
            }
            break;
        }

        if out.len() + size > MAX_RESPONSE_BODY_BYTES {
            return Err(Error::network(format!(
                "Response body exceeded {} bytes",
                MAX_RESPONSE_BODY_BYTES
            )));
        }

        let mut remaining = size;
        while remaining > 0 {
            let mut tmp = vec![0u8; remaining.min(8192)];
            let n = read_into(read, pending, eof, &mut tmp).await?;
            if n == 0 {
                return Err(Error::network(
                    "Malformed chunked response: truncated chunk",
                ));
            }
            out.extend_from_slice(&tmp[..n]);
            remaining -= n;
        }

        // Chunk data is followed by CRLF.
        let crlf = read_exact_bytes(read, pending, eof, deadline, 2).await?;
        if crlf != b"\r\n" {
            return Err(Error::network("Malformed chunked response: missing CRLF"));
        }
    }

    Ok(out)
}

/// Read until EOF (connection-close framed response).
async fn read_until_eof<R>(
    read: &mut R,
    pending: &mut Vec<u8>,
    eof: &mut bool,
    deadline: tokio::time::Instant,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut out = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        if out.len() > MAX_RESPONSE_BODY_BYTES {
            return Err(Error::network(format!(
                "Response body exceeded {} bytes",
                MAX_RESPONSE_BODY_BYTES
            )));
        }
        if tokio::time::Instant::now() > deadline {
            return Err(Error::network("Timed out reading response body"));
        }
        let n = read_into(read, pending, eof, &mut tmp).await?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&tmp[..n]);
    }
    Ok(out)
}

/// Read one CRLF-terminated line with a maximum length.
async fn read_line<R>(
    read: &mut R,
    pending: &mut Vec<u8>,
    eof: &mut bool,
    deadline: tokio::time::Instant,
    max_len: usize,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut line = Vec::new();
    loop {
        if tokio::time::Instant::now() > deadline {
            return Err(Error::network("Timed out reading response line"));
        }
        if line.len() > max_len {
            return Err(Error::network("Malformed response: line too long"));
        }
        let mut byte = [0u8; 1];
        let n = read_into(read, pending, eof, &mut byte).await?;
        if n == 0 {
            if line.is_empty() {
                return Err(Error::network("Malformed response: unexpected EOF"));
            }
            return Err(Error::network("Malformed response: unterminated line"));
        }
        if byte[0] == b'\n' {
            // Strip the trailing \r if present.
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(line);
        }
        line.push(byte[0]);
    }
}

/// Read exactly `n` bytes (used for the CRLF after a chunk).
async fn read_exact_bytes<R>(
    read: &mut R,
    pending: &mut Vec<u8>,
    eof: &mut bool,
    deadline: tokio::time::Instant,
    n: usize,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        if tokio::time::Instant::now() > deadline {
            return Err(Error::network("Timed out reading response"));
        }
        let mut tmp = vec![0u8; n - out.len()];
        let got = read_into(read, pending, eof, &mut tmp).await?;
        if got == 0 {
            return Err(Error::network("Malformed response: unexpected EOF"));
        }
        out.extend_from_slice(&tmp[..got]);
    }
    Ok(out)
}

/// Read from the underlying stream, draining the pending buffer first.
async fn read_into<R>(
    read: &mut R,
    pending: &mut Vec<u8>,
    eof: &mut bool,
    buf: &mut [u8],
) -> Result<usize>
where
    R: AsyncRead + Unpin,
{
    if !pending.is_empty() {
        let n = buf.len().min(pending.len());
        buf[..n].copy_from_slice(&pending[..n]);
        pending.drain(..n);
        return Ok(n);
    }
    if *eof {
        return Ok(0);
    }
    let n = tokio::time::timeout(IO_TIMEOUT, read.read(buf))
        .await
        .map_err(|_| Error::network("Timed out reading response"))?
        .map_err(|e| Error::network(format!("Failed to read response: {e}")))?;
    if n == 0 {
        *eof = true;
    }
    Ok(n)
}

/// Find the byte offset of a sub-slice.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_request_head_strips_hop_by_hop() {
        let mut headers = HeaderMap::new();
        headers.insert("Host", HeaderValue::from_static("example.com"));
        headers.insert("Proxy-Connection", HeaderValue::from_static("keep-alive"));
        headers.insert("Transfer-Encoding", HeaderValue::from_static("chunked"));
        headers.insert("X-Custom", HeaderValue::from_static("yes"));
        headers.insert("Connection", HeaderValue::from_static("X-Flow"));
        headers.insert("X-Flow", HeaderValue::from_static("drop-me"));

        let head = build_request_head(&Method::POST, "/api", &headers, "example.com", 80, true);
        let text = String::from_utf8(head).unwrap();

        let lower = text.to_lowercase();
        assert!(lower.starts_with("post /api http/1.1\r\n"));
        // The client-supplied Host is preserved (no default port is appended
        // because the client already provided one).
        assert!(lower.contains("host: example.com\r\n"));
        assert!(lower.contains("x-custom: yes\r\n"));
        assert!(lower.contains("transfer-encoding: chunked\r\n"));
        assert!(!lower.contains("proxy-connection"));
        assert!(!lower.contains("x-flow"));
        assert!(!lower.contains("keep-alive"));
    }

    #[test]
    fn test_build_request_head_adds_host() {
        let headers = HeaderMap::new();
        let head = build_request_head(&Method::GET, "/", &headers, "example.org", 8080, false);
        let text = String::from_utf8(head).unwrap();
        assert!(text.contains("Host: example.org:8080\r\n"));
        assert!(!text.to_lowercase().contains("transfer-encoding"));
    }

    #[test]
    fn test_find_subsequence() {
        assert_eq!(find_subsequence(b"abc\r\n\r\nxyz", b"\r\n\r\n"), Some(3));
        assert_eq!(find_subsequence(b"abc", b"\r\n\r\n"), None);
    }
}
