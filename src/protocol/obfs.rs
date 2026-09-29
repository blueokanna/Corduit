//! The obfuscation stream wrappers Snell and SIP003's `simple-obfs` share.
//!
//! Two protocols, one wire: Snell's `obfs: http` / `obfs: tls` and the
//! Shadowsocks `obfs` plugin (`simple-obfs`) were written from the same
//! lineage — the reference for the TLS form is `simple-obfs`'s
//! `obfs_tls.c`, and `sing-snell`'s `obfs.go` is a byte-exact copy of it.
//! The two clients differ only in the fabricated HTTP request they lead
//! with, so the streams live here once:
//!
//! * `TlsObfsStream` is identical for both protocols. The first write is a
//!   fabricated `ClientHello` carrying up to `0x400` payload bytes in its
//!   session-ticket extension, with the rest (and every later write) sent as
//!   `17 03 03` application-data records of at most `0x4000` bytes; the first
//!   read skips the peer's fabricated handshake by its known `0x69`-byte
//!   prefix and then reads records. Every constant is from the reference, and
//!   unit tests pin the three length fields against them, because a wrong
//!   length on this path is a silent failure against a real server rather
//!   than a parse error.
//! * `HttpObfsStream` differs per protocol in the request's header order,
//!   the user agent, and whether the port is appended to `Host`; those are
//!   exactly the `HttpObfsFlavor` variants. Both write the head and the
//!   first record as one `write`, and both skip the peer's fabricated
//!   response up to and including its first `\r\n\r\n`.
//!
//! The read sides are byte-counting state machines rather than `read_exact`s:
//! a relay read may time out between records, and a partial header must
//! resume where it stopped rather than being mistaken for a new record.

use crate::common::stream::{BoxStream, SyncStream};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::time::Duration;

// ---------------------------------------------------------------------------
// TLS obfs
// ---------------------------------------------------------------------------

/// Payload bytes the fabricated `ClientHello` carries in its session ticket.
pub(crate) const TLS_OBFS_CLIENT_HELLO_PAYLOAD_LEN: usize = 0x400;
/// Largest payload one application-data record carries.
const TLS_OBFS_RECORD_PAYLOAD_LEN: usize = 0x4000;
/// `ClientHello` size beyond hostname and payload (0xd9 with both empty).
const TLS_OBFS_CLIENT_HELLO_OVERHEAD: usize = 0xd9;
/// Where the session-ticket payload starts inside the `ClientHello`.
///
/// Only the tests read it: the client builds the payload at this offset by
/// construction, and the tests assert that the construction and this number
/// still agree. Keeping it named is what makes the assertion readable.
#[cfg(test)]
const TLS_OBFS_CLIENT_HELLO_PAYLOAD_OFFSET: usize = 0x8e;
/// Bytes of the peer's first message before its length field: the fabricated
/// `ServerHello` is skipped by this prefix, not parsed (0x6b - 2).
const TLS_OBFS_SERVER_HELLO_PREFIX: usize = 0x69;
/// Bytes of each later record's five-byte header before its length field.
const TLS_OBFS_RECORD_PREFIX: usize = 3;
/// Record length beyond hostname and payload (0xd4 with both empty).
const TLS_OBFS_CLIENT_RECORD_OVERHEAD: usize = 0xd4;
/// Handshake length beyond hostname and payload (0xd0 with both empty).
const TLS_OBFS_CLIENT_HANDSHAKE_OVERHEAD: usize = 0xd0;
/// Extensions length beyond hostname and payload (0x4f with both empty).
const TLS_OBFS_CLIENT_EXTENSIONS_OVERHEAD: usize = 0x4f;

/// The cipher-suite list the fabricated `ClientHello` advertises, verbatim
/// from the reference (`0x38` bytes).
const TLS_OBFS_CIPHER_SUITES: [u8; 0x38] = [
    0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
    0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
    0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
    0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
];

/// The fixed extension trailer behind the hostname, verbatim from the
/// reference (`0x42` bytes: ec_point_formats, supported_groups,
/// signature_algorithms, encrypt_then_mac, extended_master_secret).
const TLS_OBFS_EXTENSION_TRAILER: [u8; 0x42] = [
    0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02, // ec_point_formats
    0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00,
    0x18, // groups
    0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02,
    0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x02, 0x03, // signature_algorithms
    0x00, 0x16, 0x00, 0x00, // encrypt_then_mac
    0x00, 0x17, 0x00, 0x00, // extended_master_secret
];

/// The TLS-obfs dressing: one fabricated `ClientHello` whose session ticket
/// carries the first `0x400` payload bytes, then application-data records.
///
/// The shapes are the reference's client half (`tlsObfsClientConn` in
/// `sing-snell`, `obfs_tls_request` in `simple-obfs`), including the three
/// length fields of the hello and the `0x69`-byte prefix the first server
/// record is skipped by.
pub(crate) struct TlsObfsStream {
    inner: BoxStream,
    host: String,
    client_hello_sent: bool,
    /// Bytes of the current record's fixed prefix still to discard.
    skip_remaining: usize,
    /// The record's two length bytes, accumulated across partial reads.
    length_bytes: [u8; 2],
    length_filled: usize,
    /// Payload bytes the current record still owes.
    payload_remaining: usize,
    first_record: bool,
}

impl TlsObfsStream {
    pub(crate) fn new(inner: BoxStream, host: String) -> Self {
        Self {
            inner,
            host,
            client_hello_sent: false,
            skip_remaining: TLS_OBFS_SERVER_HELLO_PREFIX,
            length_bytes: [0u8; 2],
            length_filled: 0,
            payload_remaining: 0,
            first_record: true,
        }
    }

    /// Wrap `payload` in one or more application-data records.
    fn append_records(out: &mut Vec<u8>, mut payload: &[u8]) {
        while !payload.is_empty() {
            let take = payload.len().min(TLS_OBFS_RECORD_PAYLOAD_LEN);
            out.extend_from_slice(&[0x17, 0x03, 0x03]);
            out.extend_from_slice(&(take as u16).to_be_bytes());
            out.extend_from_slice(&payload[..take]);
            payload = &payload[take..];
        }
    }

    /// The fabricated `ClientHello`, with `buf`'s first `0x400` bytes in its
    /// session ticket and the rest as records behind it.
    fn client_hello(&self, buf: &[u8]) -> Vec<u8> {
        let payload_len = buf.len().min(TLS_OBFS_CLIENT_HELLO_PAYLOAD_LEN);
        let payload = &buf[..payload_len];
        let host = self.host.as_bytes();

        // The bytes only have to vary, not be unguessable: they are a
        // fabricated handshake, and a fill failure leaves zeros rather than
        // failing a connection over it.
        let mut random_bytes = [0u8; 28];
        let _ = getrandom::fill(&mut random_bytes);
        let mut session_id = [0u8; 32];
        let _ = getrandom::fill(&mut session_id);
        let unix_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);

        let mut out =
            Vec::with_capacity(TLS_OBFS_CLIENT_HELLO_OVERHEAD + host.len() + buf.len() + 5);
        out.extend_from_slice(&[0x16, 0x03, 0x01]);
        out.extend_from_slice(
            &((TLS_OBFS_CLIENT_RECORD_OVERHEAD + host.len() + payload.len()) as u16).to_be_bytes(),
        );
        out.extend_from_slice(&[0x01, 0x00]);
        out.extend_from_slice(
            &((TLS_OBFS_CLIENT_HANDSHAKE_OVERHEAD + host.len() + payload.len()) as u16)
                .to_be_bytes(),
        );
        out.extend_from_slice(&[0x03, 0x03]);
        out.extend_from_slice(&unix_seconds.to_be_bytes());
        out.extend_from_slice(&random_bytes);
        out.push(0x20);
        out.extend_from_slice(&session_id);
        out.extend_from_slice(&(TLS_OBFS_CIPHER_SUITES.len() as u16).to_be_bytes());
        out.extend_from_slice(&TLS_OBFS_CIPHER_SUITES);
        out.extend_from_slice(&[0x01, 0x00]);
        out.extend_from_slice(
            &((TLS_OBFS_CLIENT_EXTENSIONS_OVERHEAD + host.len() + payload.len()) as u16)
                .to_be_bytes(),
        );
        // session_ticket: the first payload bytes travel here.
        out.extend_from_slice(&0x0023u16.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        // server_name: the obfs host.
        out.extend_from_slice(&0x0000u16.to_be_bytes());
        out.extend_from_slice(&((host.len() + 5) as u16).to_be_bytes());
        out.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        out.push(0x00);
        out.extend_from_slice(&(host.len() as u16).to_be_bytes());
        out.extend_from_slice(host);
        out.extend_from_slice(&TLS_OBFS_EXTENSION_TRAILER);
        Self::append_records(&mut out, &buf[payload_len..]);
        out
    }
}

impl Read for TlsObfsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.payload_remaining > 0 {
                let want = buf.len().min(self.payload_remaining);
                let read = self.inner.read(&mut buf[..want])?;
                if read == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "obfs tls: the peer closed inside a record",
                    ));
                }
                self.payload_remaining -= read;
                return Ok(read);
            }

            // The fixed prefix is discarded, not validated: both references
            // skip the fabricated hello by length and never look at the type
            // bytes, and a reader that checked them would reject a peer whose
            // fake header differs in exactly the way nobody promised.
            if self.skip_remaining > 0 {
                let mut scratch = [0u8; 64];
                let want = self.skip_remaining.min(scratch.len());
                let read = self.inner.read(&mut scratch[..want])?;
                if read == 0 {
                    // Between records this is how every connection ends.
                    return Ok(0);
                }
                self.skip_remaining -= read;
                continue;
            }

            if self.length_filled < self.length_bytes.len() {
                let read = self
                    .inner
                    .read(&mut self.length_bytes[self.length_filled..])?;
                if read == 0 {
                    if self.length_filled == 0 {
                        return Ok(0);
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "obfs tls: the peer closed inside a record length",
                    ));
                }
                self.length_filled += read;
                continue;
            }

            let length = usize::from(u16::from_be_bytes(self.length_bytes));
            self.length_filled = 0;
            if self.first_record {
                self.first_record = false;
                self.skip_remaining = TLS_OBFS_RECORD_PREFIX;
            }
            if length == 0 {
                continue;
            }
            self.payload_remaining = length;
        }
    }
}

impl Write for TlsObfsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.client_hello_sent {
            self.client_hello_sent = true;
            let hello = self.client_hello(buf);
            self.inner.write_all(&hello)?;
            return Ok(buf.len());
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let mut out =
            Vec::with_capacity(buf.len() + 5 * buf.len().div_ceil(TLS_OBFS_RECORD_PAYLOAD_LEN));
        Self::append_records(&mut out, buf);
        self.inner.write_all(&out)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl SyncStream for TlsObfsStream {
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.shutdown(how)
    }

    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.peer_addr()
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(timeout)
    }

    /// `None`: the fabricated hello must be the first bytes on the wire, and
    /// a shared handle would let the relay write around it.
    fn shared_handle(&self) -> Option<crate::common::stream::SharedStream> {
        None
    }
}

// ---------------------------------------------------------------------------
// HTTP obfs
// ---------------------------------------------------------------------------

/// Which client's fabricated `GET` to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HttpObfsFlavor {
    /// Snell: a Firefox fingerprint drawn once per process, `Content-Length`
    /// before the WebSocket key, and no port in `Host`.
    Snell,
    /// SIP003 `simple-obfs`: a `curl/7.x.y` fingerprint drawn once per
    /// process, a fresh key per request, `Content-Length` last, and the port
    /// appended to `Host` when it is not 80.
    SimpleObfs { method: String },
}

/// The `obfs: http` dressing: a WebSocket-upgrade request before the first
/// write, and a skipped response before the first read.
pub(crate) struct HttpObfsStream {
    inner: BoxStream,
    host: String,
    uri: String,
    port: u16,
    flavor: HttpObfsFlavor,
    header_sent: bool,
    response_skipped: bool,
}

impl HttpObfsStream {
    pub(crate) fn snell(inner: BoxStream, host: String, uri: String) -> Self {
        Self {
            inner,
            host,
            uri,
            port: 0,
            flavor: HttpObfsFlavor::Snell,
            header_sent: false,
            response_skipped: false,
        }
    }

    pub(crate) fn simple_obfs(
        inner: BoxStream,
        host: String,
        uri: String,
        port: u16,
        method: String,
    ) -> Self {
        Self {
            inner,
            host,
            uri,
            port,
            flavor: HttpObfsFlavor::SimpleObfs { method },
            header_sent: false,
            response_skipped: false,
        }
    }

    /// The fabricated request head, with the flavour's fingerprint rules.
    fn request_head(&self, body_len: usize) -> Vec<u8> {
        match &self.flavor {
            HttpObfsFlavor::Snell => {
                use std::sync::OnceLock;
                static FINGERPRINT: OnceLock<(String, String)> = OnceLock::new();
                let (agent, key) = FINGERPRINT.get_or_init(|| {
                    let mut pick = [0u8; 2];
                    let _ = getrandom::fill(&mut pick);
                    let agent = format!(
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.{}; rv:64.0) \
                         Gecko/20100101 Firefox/{}.0",
                        9 + usize::from(pick[0]) % 6,
                        22 + usize::from(pick[1]) % 43,
                    );
                    let mut key_bytes = [0u8; 16];
                    let _ = getrandom::fill(&mut key_bytes);
                    let key = courierust::courierust_crypto::base64::encode(&key_bytes);
                    (agent, key)
                });
                format!(
                    "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nUpgrade: websocket\r\n\
                     Connection: Upgrade\r\nContent-Length: {}\r\nSec-WebSocket-Key: {}\r\n\r\n",
                    self.uri, self.host, agent, body_len, key
                )
                .into_bytes()
            }
            HttpObfsFlavor::SimpleObfs { method } => {
                use std::sync::OnceLock;
                static VERSIONS: OnceLock<(usize, usize)> = OnceLock::new();
                let (major, minor) = VERSIONS.get_or_init(|| {
                    let mut pick = [0u8; 2];
                    let _ = getrandom::fill(&mut pick);
                    (usize::from(pick[0]) % 51, usize::from(pick[1]) % 2)
                });
                let host_port = if self.port != 0 && self.port != 80 {
                    format!("{}:{}", self.host, self.port)
                } else {
                    self.host.clone()
                };
                let mut key_bytes = [0u8; 16];
                let _ = getrandom::fill(&mut key_bytes);
                let key = courierust::courierust_crypto::base64::encode(&key_bytes);
                format!(
                    "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: curl/7.{}.{}\r\n\
                     Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\n\
                     Content-Length: {}\r\n\r\n",
                    method, self.uri, host_port, major, minor, key, body_len
                )
                .into_bytes()
            }
        }
    }
}

/// Bound for the fabricated response head we skip on the first read.
const MAX_OBFS_HEADER: usize = 16 * 1024;

impl Read for HttpObfsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.response_skipped {
            self.response_skipped = true;
            let mut seen = Vec::new();
            let mut byte = [0u8; 1];
            while !seen.ends_with(b"\r\n\r\n") {
                if seen.len() >= MAX_OBFS_HEADER {
                    return Err(io::Error::other(
                        "http obfs: the peer's response head exceeded the cap",
                    ));
                }
                match self.inner.read(&mut byte)? {
                    0 => break,
                    _ => seen.push(byte[0]),
                }
            }
        }
        self.inner.read(buf)
    }
}

impl Write for HttpObfsStream {
    /// Head and body go out in one `write`, which is what both references do:
    /// the record is the request's body, not a second packet after it.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.header_sent {
            self.header_sent = true;
            let mut out = self.request_head(buf.len());
            out.extend_from_slice(buf);
            self.inner.write_all(&out)?;
            return Ok(buf.len());
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl SyncStream for HttpObfsStream {
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.shutdown(how)
    }

    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.peer_addr()
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(timeout)
    }

    fn shared_handle(&self) -> Option<crate::common::stream::SharedStream> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A stream the test scripts: reads come out of a buffer in `chunk`-sized
    /// pieces (so the state machine is exercised across partial reads), writes
    /// are recorded.
    struct ScriptedStream {
        data: Vec<u8>,
        pos: usize,
        chunk: usize,
        writes: Arc<parking_lot::Mutex<Vec<Vec<u8>>>>,
    }

    impl Read for ScriptedStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            let take = buf.len().min(self.chunk).min(self.data.len() - self.pos);
            buf[..take].copy_from_slice(&self.data[self.pos..self.pos + take]);
            self.pos += take;
            Ok(take)
        }
    }

    impl Write for ScriptedStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writes.lock().push(buf.to_vec());
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl SyncStream for ScriptedStream {
        fn shutdown(&self, _how: Shutdown) -> io::Result<()> {
            Ok(())
        }

        fn peer_addr(&self) -> Option<std::net::SocketAddr> {
            None
        }

        fn set_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        fn set_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        fn shared_handle(&self) -> Option<crate::common::stream::SharedStream> {
            None
        }
    }

    fn scripted_stream(data: Vec<u8>, chunk: usize) -> ScriptedStream {
        ScriptedStream {
            data,
            pos: 0,
            chunk,
            writes: Arc::new(parking_lot::Mutex::new(Vec::new())),
        }
    }

    /// The hello's three length fields, and the payload's position inside it,
    /// are checked against the reference's overhead constants: a wrong length
    /// here is a silent failure against a real server, not a parse error.
    #[test]
    fn the_tls_obfs_hello_matches_the_reference_offsets() {
        let host = "cloudfront.net";
        let payload = vec![0xA7u8; TLS_OBFS_CLIENT_HELLO_PAYLOAD_LEN + 0x100];
        let stream = TlsObfsStream::new(
            Box::new(scripted_stream(Vec::new(), 4096)),
            host.to_string(),
        );
        let hello = stream.client_hello(&payload);

        assert_eq!(&hello[..3], &[0x16, 0x03, 0x01]);
        let record_len = usize::from(u16::from_be_bytes([hello[3], hello[4]]));
        assert_eq!(
            record_len,
            TLS_OBFS_CLIENT_RECORD_OVERHEAD + host.len() + TLS_OBFS_CLIENT_HELLO_PAYLOAD_LEN
        );
        let handshake_len = usize::from(u16::from_be_bytes([hello[7], hello[8]]));
        assert_eq!(
            handshake_len,
            TLS_OBFS_CLIENT_HANDSHAKE_OVERHEAD + host.len() + TLS_OBFS_CLIENT_HELLO_PAYLOAD_LEN
        );
        let extension_len_offset =
            5 + 4 + 2 + 4 + 28 + 1 + 32 + 2 + TLS_OBFS_CIPHER_SUITES.len() + 2;
        let extension_len = usize::from(u16::from_be_bytes([
            hello[extension_len_offset],
            hello[extension_len_offset + 1],
        ]));
        assert_eq!(
            extension_len,
            TLS_OBFS_CLIENT_EXTENSIONS_OVERHEAD + host.len() + TLS_OBFS_CLIENT_HELLO_PAYLOAD_LEN
        );

        // The ticket's payload begins at the documented offset.
        assert_eq!(
            &hello[TLS_OBFS_CLIENT_HELLO_PAYLOAD_OFFSET
                ..TLS_OBFS_CLIENT_HELLO_PAYLOAD_OFFSET + TLS_OBFS_CLIENT_HELLO_PAYLOAD_LEN],
            &payload[..TLS_OBFS_CLIENT_HELLO_PAYLOAD_LEN]
        );

        // The hello ends where the reference's constants say, and the
        // remainder rides behind it as one application-data record.
        let hello_len =
            TLS_OBFS_CLIENT_HELLO_OVERHEAD + host.len() + TLS_OBFS_CLIENT_HELLO_PAYLOAD_LEN;
        assert_eq!(hello.len(), hello_len + 5 + 0x100);
        assert_eq!(&hello[hello_len..hello_len + 3], &[0x17, 0x03, 0x03]);
        assert_eq!(
            u16::from_be_bytes([hello[hello_len + 3], hello[hello_len + 4]]),
            0x100
        );
        assert_eq!(
            &hello[hello_len + 5..],
            &payload[TLS_OBFS_CLIENT_HELLO_PAYLOAD_LEN..]
        );
    }

    #[test]
    fn the_tls_obfs_first_write_is_a_single_hello() {
        let inner = scripted_stream(Vec::new(), 4096);
        let writes = Arc::clone(&inner.writes);
        let mut stream = TlsObfsStream::new(Box::new(inner), "cloudfront.net".to_string());
        stream.write_all(b"first record bytes").unwrap();
        let recorded = writes.lock().clone();
        assert_eq!(recorded.len(), 1, "hello and payload leave in one write");
        assert_eq!(&recorded[0][..3], &[0x16, 0x03, 0x01]);
    }

    #[test]
    fn tls_obfs_reads_skip_the_fabricated_handshake_and_frame_records() {
        let first = b"record one".to_vec();
        let second = vec![0x5Au8; 300];
        let mut wire = vec![0xEEu8; TLS_OBFS_SERVER_HELLO_PREFIX];
        wire.extend_from_slice(&(first.len() as u16).to_be_bytes());
        wire.extend_from_slice(&first);
        wire.extend_from_slice(&[0x17, 0x03, 0x03]);
        wire.extend_from_slice(&(second.len() as u16).to_be_bytes());
        wire.extend_from_slice(&second);

        // One byte per read: every partial-state path is walked.
        let mut stream = TlsObfsStream::new(
            Box::new(scripted_stream(wire, 1)),
            "cloudfront.net".to_string(),
        );
        let mut got = vec![0u8; first.len() + second.len()];
        stream.read_exact(&mut got).unwrap();
        assert_eq!(&got[..first.len()], &first[..]);
        assert_eq!(&got[first.len()..], &second[..]);

        // A clean close between records reads as EOF, not an error.
        let mut tail = [0u8; 16];
        assert_eq!(stream.read(&mut tail).unwrap(), 0);
    }

    #[test]
    fn the_simple_obfs_head_carries_the_port_and_curl_fingerprint() {
        let inner = scripted_stream(Vec::new(), 4096);
        let writes = Arc::clone(&inner.writes);
        let mut stream = HttpObfsStream::simple_obfs(
            Box::new(inner),
            "cdn.example".to_string(),
            "/".to_string(),
            8443,
            "GET".to_string(),
        );
        stream.write_all(b"payload").unwrap();
        let recorded = writes.lock().clone();
        assert_eq!(recorded.len(), 1, "head and body leave in one write");
        let head = String::from_utf8_lossy(&recorded[0]);
        assert!(head.starts_with("GET / HTTP/1.1\r\n"), "{head}");
        assert!(head.contains("Host: cdn.example:8443\r\n"), "{head}");
        assert!(head.contains("User-Agent: curl/7."), "{head}");
        assert!(
            head.contains("Upgrade: websocket\r\nConnection: Upgrade\r\n"),
            "{head}"
        );
        assert!(head.contains("Sec-WebSocket-Key: "), "{head}");
        assert!(head.contains("Content-Length: 7\r\n\r\npayload"), "{head}");
    }

    #[test]
    fn the_snell_head_keeps_its_own_order_and_omits_the_port() {
        let inner = scripted_stream(Vec::new(), 4096);
        let writes = Arc::clone(&inner.writes);
        let mut stream =
            HttpObfsStream::snell(Box::new(inner), "bing.com".to_string(), "/ws".to_string());
        stream.write_all(b"payload").unwrap();
        let recorded = writes.lock().clone();
        let head = String::from_utf8_lossy(&recorded[0]);
        assert!(head.starts_with("GET /ws HTTP/1.1\r\n"), "{head}");
        assert!(head.contains("Host: bing.com\r\n"), "{head}");
        assert!(
            head.contains("Upgrade: websocket\r\nConnection: Upgrade\r\n"),
            "{head}"
        );
        assert!(
            head.contains("Content-Length: 7\r\nSec-WebSocket-Key: "),
            "{head}"
        );
        assert!(head.ends_with("\r\n\r\npayload"), "{head}");
    }
}
