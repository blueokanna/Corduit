//! The `v2ray-plugin` mux session: the framing a reference server expects.
//!
//! v2ray-plugin's server half routes every WebSocket stream into v2ray's mux
//! handler (`v1.mux.cool`). The server does that **by default** — the plugin's
//! own `mux` flag defaults to on, and so does mihomo's client — which means a
//! client that writes raw bytes to such a server connects, completes the
//! WebSocket handshake, and then fails every request, because the server reads
//! the first bytes as a session header. This module speaks the framing instead.
//!
//! The layout is v2ray-core's (`common/mux/frame.go`), mirrored byte for byte
//! by mihomo's `transport/v2ray-plugin/mux.go`:
//!
//! ```text
//! metadata  [len:2 BE][session id:2 BE][status:1][option:1]
//!           (NEW only, inside the length: [network:1][port:2 BE][type:1][addr])
//! data      [size:2 BE][payload] — present when option has 0x01
//! ```
//!
//! One TCP connection carries exactly one session, so the session id is 0 and
//! the NEW frame's target is the placeholder mihomo sends (`127.0.0.1:0`):
//! the server delivers every mux stream through a `freedom` outbound that
//! overrides the destination with the Shadowsocks server's own address, so the
//! frame's target never becomes routeable traffic.
//!
//! Status values are `NEW=1`, `KEEP=2`, `END=3`, `KEEP_ALIVE=4`; options are
//! `DATA=1` and `ERROR=2`. The client sends NEW once (prepended to the first
//! write, exactly where the reference's `writeFirstPayload` puts it) and KEEP
//! for every later write; the server answers with KEEP frames and an END frame
//! when the session closes.
//!
//! The session ends with the connection. When the engine shuts the stream
//! down, the WebSocket close handshake reaches the server as an EOF, and
//! v2ray's mux worker treats a plain EOF as a clean session end (`server.go`:
//! only non-EOF read failures are logged), so no out-of-band END frame is
//! injected behind the caller's back.

use crate::common::stream::SyncStream;
use std::io::{self, Read, Write};
use std::net::Shutdown;

/// The opening NEW frame, byte for byte (19 bytes): metadata length `0x0011`,
/// session 0, NEW, no options, network TCP, port 0, domain `127.0.0.1`.
///
/// This is the exact frame mihomo sends (`MuxOption{ID: {0, 0}, Host:
/// "127.0.0.1", Port: 0}` in `transport/v2ray-plugin/websocket.go`).
const NEW_FRAME: [u8; 19] = [
    0x00, 0x11, // metadata length: 17 bytes
    0x00, 0x00, // session id: 0
    0x01, // status: NEW
    0x00, // options: none
    0x01, // network: TCP
    0x00, 0x00, // port: 0
    0x02, // address type: domain
    b'1', b'2', b'7', b'.', b'0', b'.', b'0', b'.', b'1',
];

const SESSION_STATUS_NEW: u8 = 0x01;
const SESSION_STATUS_KEEP: u8 = 0x02;
const SESSION_STATUS_END: u8 = 0x03;
const SESSION_STATUS_KEEP_ALIVE: u8 = 0x04;

const OPTION_DATA: u8 = 0x01;

/// Largest metadata (the `len` field's value) the reference accepts; anything
/// beyond it is a desynchronised stream, not a frame.
const MAX_METADATA: usize = 512;

/// Largest payload one data frame carries — the reference splits stream
/// writes at 8 KiB (`buf.SplitSize(mb, 8 * 1024)` in the mux writer).
const MAX_FRAME_PAYLOAD: usize = 8 * 1024;

/// A `SyncStream` speaking the mux framing over another stream.
///
/// Read and write drive independent halves of the same connection, so the
/// wrapper claims no concurrency of its own: the relay's serialized path (with
/// its bounded read poll) is the intended model, exactly as for the WebSocket
/// underneath.
pub(crate) struct MuxStream<S: SyncStream> {
    inner: S,
    /// The NEW frame travels at the head of the first write, not before it:
    /// sending it eagerly would put bytes on the wire for a connection that
    /// might never carry any.
    new_pending: bool,
    /// Current read stage: a frame's fixed head `[len][sid][status][option]`.
    head: [u8; 6],
    head_filled: usize,
    /// The `[size]` field of a data-bearing frame, filled across reads.
    size: [u8; 2],
    size_filled: usize,
    /// Set once the head says a data frame is coming: its `[size]` field is
    /// the next thing on the wire.
    size_expected: bool,
    /// Payload bytes of the current KEEP frame still to hand to the caller.
    data_remaining: usize,
    /// Bytes still to discard (skipped keepalives, error payloads, targets).
    skip_remaining: usize,
    /// The peer ended the session; reads answer EOF once the frame drains.
    saw_end: bool,
}

impl<S: SyncStream> MuxStream<S> {
    pub(crate) fn new(inner: S) -> Self {
        Self {
            inner,
            new_pending: true,
            head: [0; 6],
            head_filled: 0,
            size: [0; 2],
            size_filled: 0,
            size_expected: false,
            data_remaining: 0,
            skip_remaining: 0,
            saw_end: false,
        }
    }

    /// Read into `buf` once the head identifies a KEEP frame's payload.
    fn drain_payload(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let take = self.data_remaining.min(buf.len());
        let n = self.inner.read(&mut buf[..take])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "mux: the peer closed mid-frame",
            ));
        }
        self.data_remaining -= n;
        Ok(n)
    }

    /// Discard `n` bytes from the inner stream, resuming across short reads
    /// and idle polls.
    fn drain_skip(&mut self) -> io::Result<()> {
        let mut scratch = [0u8; 4096];
        while self.skip_remaining > 0 {
            let take = self.skip_remaining.min(scratch.len());
            let n = self.inner.read(&mut scratch[..take])?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "mux: the peer closed in the middle of a frame",
                ));
            }
            self.skip_remaining -= n;
        }
        Ok(())
    }
}

impl<S: SyncStream> Read for MuxStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.data_remaining > 0 {
                return self.drain_payload(buf);
            }
            if self.saw_end && self.head_filled == 0 && self.skip_remaining == 0 {
                return Ok(0);
            }
            if self.skip_remaining > 0 {
                self.drain_skip()?;
                continue;
            }
            if self.size_expected {
                while self.size_filled < 2 {
                    match self.inner.read(&mut self.size[self.size_filled..]) {
                        Ok(0) => {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "mux: the peer closed mid-frame",
                            ))
                        }
                        Ok(n) => self.size_filled += n,
                        Err(e) => return Err(e),
                    }
                }
                self.size_expected = false;
                let size = u16::from_be_bytes(self.size) as usize;
                self.size_filled = 0;
                if self.head[4] == SESSION_STATUS_KEEP {
                    self.data_remaining = size;
                } else {
                    self.skip_remaining += size;
                }
                continue;
            }
            while self.head_filled < self.head.len() {
                match self.inner.read(&mut self.head[self.head_filled..]) {
                    Ok(0) => {
                        if self.head_filled == 0 {
                            return Ok(0);
                        }
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "mux: the peer closed mid-frame",
                        ));
                    }
                    Ok(n) => self.head_filled += n,
                    Err(e) => return Err(e),
                }
            }
            self.head_filled = 0;

            let length = u16::from_be_bytes([self.head[0], self.head[1]]) as usize;
            if !(4..=MAX_METADATA).contains(&length) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("mux: metadata length {length} is out of range"),
                ));
            }
            let session = u16::from_be_bytes([self.head[2], self.head[3]]);
            let status = self.head[4];
            let option = self.head[5];
            if session != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("mux: the peer addressed session {session}, not this connection's"),
                ));
            }

            match status {
                SESSION_STATUS_NEW => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "mux: the peer opened a session on a stream that owns one",
                    ));
                }
                SESSION_STATUS_END => self.saw_end = true,
                SESSION_STATUS_KEEP | SESSION_STATUS_KEEP_ALIVE => {}
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("mux: unknown session status {other}"),
                    ));
                }
            }
            if length > 4 {
                self.skip_remaining += length - 4;
            }
            if option & OPTION_DATA != 0 {
                self.size_expected = true;
            }
        }
    }
}

impl<S: SyncStream> Write for MuxStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut out = Vec::with_capacity(buf.len() + NEW_FRAME.len() + 10);
        if self.new_pending {
            self.new_pending = false;
            out.extend_from_slice(&NEW_FRAME);
        }
        for chunk in buf.chunks(MAX_FRAME_PAYLOAD) {
            out.extend_from_slice(&4u16.to_be_bytes()); // metadata length
            out.extend_from_slice(&[0x00, 0x00]); // session id: 0
            out.push(SESSION_STATUS_KEEP);
            out.push(OPTION_DATA);
            out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            out.extend_from_slice(chunk);
        }
        self.inner.write_all(&out)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<S: SyncStream> SyncStream for MuxStream<S> {
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.shutdown(how)
    }

    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.peer_addr()
    }

    fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<std::time::Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// Whether the error is the relay's bounded-read poll passing through —
    /// the shape an empty wire produces in these tests.
    fn idle(e: &io::Error) -> bool {
        matches!(
            e.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        )
    }

    /// A scripted transport: tests push the bytes the "peer" sends and
    /// inspect the bytes the stream wrote.
    #[derive(Default)]
    struct Wire {
        to_read: VecDeque<u8>,
        written: Vec<u8>,
        /// When set, an empty read surfaces as `WouldBlock` instead of EOF.
        idle: bool,
    }

    #[derive(Clone, Default)]
    struct Handle {
        wire: Arc<Mutex<Wire>>,
    }

    impl Handle {
        fn push(&self, bytes: &[u8]) {
            self.wire.lock().unwrap().to_read.extend(bytes);
        }

        fn written(&self) -> Vec<u8> {
            self.wire.lock().unwrap().written.clone()
        }

        fn set_idle(&self, on: bool) {
            self.wire.lock().unwrap().idle = on;
        }
    }

    impl Read for Handle {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            let mut wire = self.wire.lock().unwrap();
            if wire.to_read.is_empty() {
                if wire.idle {
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, "idle"));
                }
                return Ok(0);
            }
            let n = wire.to_read.len().min(buf.len());
            for slot in buf.iter_mut().take(n) {
                *slot = wire.to_read.pop_front().unwrap();
            }
            Ok(n)
        }
    }

    impl Write for Handle {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.wire.lock().unwrap().written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl SyncStream for Handle {
        fn shutdown(&self, _how: Shutdown) -> io::Result<()> {
            Ok(())
        }
    }

    fn keep_frame(payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0x00, 0x04, 0x00, 0x00, SESSION_STATUS_KEEP, OPTION_DATA];
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn keep_alive_frame() -> Vec<u8> {
        vec![0x00, 0x04, 0x00, 0x00, SESSION_STATUS_KEEP_ALIVE, 0x00]
    }

    fn end_frame() -> Vec<u8> {
        vec![0x00, 0x04, 0x00, 0x00, SESSION_STATUS_END, 0x00]
    }

    /// The opening frame is pinned against the reference byte for byte: a
    /// wrong length or a missing target field desynchronises every server.
    #[test]
    fn the_first_write_prepends_the_reference_new_frame() {
        let wire = Handle::default();
        let mut stream = MuxStream::new(wire.clone());
        stream.write_all(b"abc").unwrap();

        let mut expected = NEW_FRAME.to_vec();
        expected.extend_from_slice(&keep_frame(b"abc"));
        assert_eq!(wire.written(), expected);
        // 19-byte frame: length 17, session 0, NEW, TCP, port 0, "127.0.0.1".
        assert_eq!(
            &wire.written()[..6],
            &[0x00u8, 0x11, 0x00, 0x00, 0x01, 0x00][..]
        );
        assert_eq!(wire.written()[9], 0x02);
        assert_eq!(&wire.written()[10..19], &b"127.0.0.1"[..]);

        // Later writes are KEEP frames only.
        stream.write_all(b"def").unwrap();
        let written = wire.written();
        assert_eq!(&written[expected.len()..], &keep_frame(b"def")[..]);
    }

    /// A write larger than one frame is chunked at 8 KiB, like the reference.
    #[test]
    fn large_writes_chunk_at_eight_kib() {
        let wire = Handle::default();
        let mut stream = MuxStream::new(wire.clone());
        let payload = vec![0x5a; 20 * 1024];
        stream.write_all(&payload).unwrap();

        let written = wire.written();
        let mut cursor = NEW_FRAME.len();
        let mut chunks = Vec::new();
        while cursor < written.len() {
            let head = &written[cursor..cursor + 6];
            assert_eq!(
                head,
                &[0x00u8, 0x04, 0x00, 0x00, SESSION_STATUS_KEEP, OPTION_DATA][..]
            );
            let size = u16::from_be_bytes([written[cursor + 6], written[cursor + 7]]) as usize;
            chunks.push(size);
            cursor += 8 + size;
        }
        assert_eq!(chunks, vec![8192, 8192, 4096]);
        assert_eq!(cursor, written.len());
    }

    /// Keepalives and END markers are framing: the payload the caller sees is
    /// the KEEP frames' data, nothing else.
    #[test]
    fn the_reader_serves_data_frames_and_skips_keepalives() {
        let wire = Handle::default();
        wire.push(&keep_alive_frame());
        wire.push(&keep_frame(b"hello "));
        wire.push(&keep_frame(b"world"));
        wire.push(&end_frame());
        let mut stream = MuxStream::new(wire.clone());

        let mut got = Vec::new();
        let mut buf = [0u8; 5];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(e) if idle(&e) => continue,
                Err(e) => panic!("read failed: {e}"),
            }
        }
        assert_eq!(&got, &b"hello world"[..]);
    }

    /// Frames arrive across short reads and idle polls; the reader resumes
    /// exactly where it stopped and never loses a byte of state.
    #[test]
    fn partial_frames_resume_across_idle_polls() {
        let wire = Handle::default();
        wire.set_idle(true);
        let mut stream = MuxStream::new(wire.clone());
        let frame = keep_frame(b"stream");
        let mut got = Vec::new();
        let mut buf = [0u8; 16];
        for byte in frame {
            wire.push(&[byte]);
            match stream.read(&mut buf) {
                Ok(0) => unreachable!("the frame has not ended"),
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(e) if idle(&e) => {}
                Err(e) => panic!("read failed: {e}"),
            }
        }
        assert_eq!(&got, &b"stream"[..]);
    }

    /// EOF mid-frame is a broken peer, not the end of the stream.
    #[test]
    fn a_truncated_frame_is_an_error_not_a_silent_eof() {
        let wire = Handle::default();
        wire.push(&[0x00, 0x04, 0x00]);
        let mut stream = MuxStream::new(wire.clone());
        let mut buf = [0u8; 8];
        let err = stream.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// Lengths outside the reference's window are desynchronised streams.
    #[test]
    fn nonsense_metadata_lengths_are_refused() {
        for length in [3u16, 513] {
            let wire = Handle::default();
            wire.push(&length.to_be_bytes());
            wire.push(&[0x00, 0x00, SESSION_STATUS_KEEP, 0x00]);
            let mut stream = MuxStream::new(wire.clone());
            let mut buf = [0u8; 8];
            let err = stream.read(&mut buf).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }
    }

    /// A NEW frame or a foreign session id on the wire means the peer is
    /// speaking to something else; both are refused rather than misread.
    #[test]
    fn frames_addressed_to_another_session_are_refused() {
        let wire = Handle::default();
        wire.push(&[0x00, 0x04, 0x00, 0x07, SESSION_STATUS_KEEP, OPTION_DATA]);
        wire.push(&[0x00, 0x01, b'x']);
        let mut stream = MuxStream::new(wire.clone());
        let mut buf = [0u8; 8];
        let err = stream.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let wire = Handle::default();
        wire.push(&[0x00, 0x0c, 0x00, 0x00, SESSION_STATUS_NEW, 0x00]);
        wire.push(&[0x01, 0x00, 0x50, 0x02, 0x01, b'a', 0x01, 0x01]);
        let mut stream = MuxStream::new(wire.clone());
        let err = stream.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// An empty write is a no-op: the NEW frame must wait for the first real
    /// payload instead of opening a session with nothing in it.
    #[test]
    fn an_empty_write_leaves_the_new_frame_pending() {
        let wire = Handle::default();
        let mut stream = MuxStream::new(wire.clone());
        stream.write_all(b"").unwrap();
        assert!(wire.written().is_empty());

        stream.write_all(b"x").unwrap();
        let written = wire.written();
        assert_eq!(&written[..NEW_FRAME.len()], &NEW_FRAME[..]);
        assert_eq!(&written[NEW_FRAME.len()..], &keep_frame(b"x")[..]);
    }
}
